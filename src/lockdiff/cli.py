from __future__ import annotations

import argparse
import json
import subprocess
import sys

from . import __version__
from .core import DEFAULT_HOSTS, SEV, LockError, diff_locks, parse_lock, worst


def read(path):
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            return fh.read()
    except OSError as e:
        raise LockError(f"{path}: {e.strerror}") from e


def git_show(rev, path):
    if rev.startswith("-") or path.startswith("-"):
        raise LockError("revision and path must not start with '-'")
    try:
        p = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise LockError(f"git failed: {e}") from e
    if p.returncode != 0:
        raise LockError(f"git show {rev}:{path} failed: {p.stderr.strip() or 'unknown error'}")
    return p.stdout


def to_text(r):
    s = r["summary"]
    out = [f"lockdiff: {s['added']} added, {s['removed']} removed, {s['changed']} version changes, {s['findings']} findings", r["scope"]]
    for n in r["notes"]:
        out.append("Note: " + n)
    for f in r["findings"]:
        out.append(f"{f['severity'].upper():<6} {f['rule']} {f['path']}: {f['title']}")
        out.append(f"       {f['detail']}")
    return "\n".join(out) + "\n"


def to_markdown(r):
    s = r["summary"]
    out = ["## lockdiff", "", f"{s['added']} added, {s['removed']} removed, {s['changed']} version changes, **{s['findings']} findings**.", ""]
    if r["findings"]:
        out += ["| Severity | Rule | Package | Finding |", "| --- | --- | --- | --- |"]
        for f in r["findings"]:
            title = f["title"].replace("|", "\\|")
            out.append(f"| {f['severity']} | {f['rule']} | `{f['path']}` | {title} |")
    else:
        out.append("No tamper signals found. This does not check advisories or release dates.")
    return "\n".join(out) + "\n"


SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_sarif(r, path):
    rules, seen, results = [], set(), []
    for f in r["findings"]:
        if f["rule"] not in seen:
            seen.add(f["rule"])
            rules.append({"id": f["rule"], "name": f["title"], "shortDescription": {"text": f["title"]},
                          "fullDescription": {"text": f["detail"]},
                          "defaultConfiguration": {"level": SARIF_LEVEL.get(f["severity"], "note")}})
        results.append({"ruleId": f["rule"], "level": SARIF_LEVEL.get(f["severity"], "note"),
                        "message": {"text": f"{f['title']} ({f['path']}). {f['detail']}"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}}}]})
    return json.dumps({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
                       "runs": [{"tool": {"driver": {"name": "lockdiff", "version": __version__, "rules": rules}},
                                "results": results}]}, indent=2)


def main(argv=None):
    p = argparse.ArgumentParser(prog="lockdiff", description="Offline package-lock.json diff for tamper signals.")
    p.add_argument("old", nargs="?", help="old lockfile (or the lockfile path when --git is used)")
    p.add_argument("new", nargs="?", help="new lockfile (default with --git: the working copy)")
    p.add_argument("--git", metavar="REV", help="compare the file at REV (via `git show`) with the working copy")
    p.add_argument("--registry-host", action="append", default=[], help="additional trusted registry host (repeatable)")
    p.add_argument("--format", choices=["text", "json", "markdown", "sarif"], default="text")
    p.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="never")
    p.add_argument("--version", action="version", version=f"lockdiff {__version__}")
    a = p.parse_args(argv)
    try:
        if a.git:
            path = a.old or "package-lock.json"
            old_text, new_text = git_show(a.git, path), read(a.new or path)
            labels = (f"{a.git}:{path}", a.new or path)
        else:
            if not a.old or not a.new:
                print("lockdiff: give OLD and NEW lockfiles, or use --git REV [PATH]", file=sys.stderr)
                return 2
            old_text, new_text, labels = read(a.old), read(a.new), (a.old, a.new)
        result = diff_locks(parse_lock(old_text, labels[0]), parse_lock(new_text, labels[1]), tuple(DEFAULT_HOSTS) + tuple(a.registry_host))
    except LockError as e:
        print(f"lockdiff: {e}", file=sys.stderr)
        return 2
    out_path = labels[1]
    sys.stdout.write(
        json.dumps(result, indent=2) + "\n" if a.format == "json" else
        to_markdown(result) if a.format == "markdown" else
        to_sarif(result, out_path) + "\n" if a.format == "sarif" else
        to_text(result)
    )
    w = worst(result)
    return 1 if a.fail_on != "never" and w and SEV[w] <= SEV[a.fail_on] else 0
