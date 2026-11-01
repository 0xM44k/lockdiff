"""Offline diff of two npm package-lock.json files for tamper signals.

Reads lockfiles only. No network, no registry lookups, no code execution.
Supports npm lockfileVersion 2/3 (`packages`) and 1 (`dependencies`), and
Yarn Classic `yarn.lock` (v1). Yarn Berry and pnpm lockfiles are detected and
rejected with a clear message rather than misread.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from urllib.parse import urlparse

from . import __version__

SEV = {"high": 0, "medium": 1, "low": 2, "info": 3}
WEAK_ALGOS = {"sha1": 1, "sha256": 2, "sha384": 3, "sha512": 4}
# registry.yarnpkg.com is the official Yarn mirror of the npm registry and is
# what Yarn Classic writes into yarn.lock by default.
DEFAULT_HOSTS = ("registry.npmjs.org", "registry.yarnpkg.com")


class LockError(Exception):
    pass


def name_from_key(key: str) -> str:
    return key.split("node_modules/")[-1]


_YARN_HEADER = re.compile(r"^\s*#\s*yarn lockfile v1", re.M)


def detect_format(text: str) -> str:
    """Return "npm", "yarn1", "yarn-berry" or "pnpm" from the file contents."""
    head = text.lstrip("\ufeff")[:4000]
    if head.lstrip().startswith("{"):
        return "npm"
    if _YARN_HEADER.search(head):
        return "yarn1"
    if re.search(r"^__metadata:", text, re.M):
        return "yarn-berry"
    if re.match(r"^\s*lockfileVersion:", head):
        return "pnpm"
    return "npm"


def _unquote(tok: str) -> str:
    tok = tok.strip()
    if len(tok) >= 2 and tok[0] == tok[-1] == '"':
        try:
            return json.loads(tok)
        except json.JSONDecodeError:
            return tok[1:-1]
    return tok


def _yarn_name(descriptor: str) -> str:
    """`@scope/name@^1.0.0` -> `@scope/name`; `name@npm:alias@1` -> `name`."""
    at = descriptor.find("@", 1)
    return descriptor[:at] if at > 0 else descriptor


def _sha1_hex_to_integrity(hexdigest: str):
    try:
        return "sha1-" + base64.b64encode(binascii.unhexlify(hexdigest)).decode("ascii")
    except (binascii.Error, ValueError):
        return None


def parse_yarn_lock(text: str, label: str = "yarn.lock"):
    """Parse a Yarn Classic (v1) lockfile.

    Identity is the first (alphabetical) descriptor of an entry, for example
    `lodash@^4.17.0`, so a version bump inside the same range is a version
    change rather than an add plus a remove. Yarn v1 records no install-script
    data and no dev flag, so those stay unknown. When an entry has no
    `integrity` field (older Yarn), the SHA-1 fragment of the resolved URL is
    used as `sha1-...` integrity, which the weak-hash rule then reports.
    """
    pkgs, blocks, cur = {}, [], None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith(" "):
            if not raw.rstrip().endswith(":"):
                raise LockError(f"{label}: unexpected line {raw[:60]!r}; not a Yarn v1 lockfile")
            header = raw.rstrip()[:-1]
            descs = sorted(_unquote(t) for t in re.split(r",\s*(?=(?:\"|[@\w]))", header))
            cur = {"descs": descs, "fields": {}}
            blocks.append(cur)
        elif cur is not None and len(raw) - len(raw.lstrip()) == 2:
            m = re.match(r"^\s{2}(\S+)\s+(.*)$", raw)
            if m:
                cur["fields"][m.group(1).strip('"')] = _unquote(m.group(2))
    for b in blocks:
        f, descs = b["fields"], b["descs"]
        if not descs or "version" not in f:
            continue
        resolved = f.get("resolved")
        integrity = f.get("integrity")
        if not integrity and resolved and "#" in resolved:
            frag = resolved.rsplit("#", 1)[1]
            if re.fullmatch(r"[0-9a-f]{40}", frag):
                integrity = _sha1_hex_to_integrity(frag)
        pkgs[descs[0]] = {"name": _yarn_name(descs[0]), "version": f["version"], "resolved": resolved,
                          "integrity": integrity, "install": False, "install_known": False, "dev": False}
    if not pkgs and blocks:
        raise LockError(f"{label}: no package entries with a version were found")
    return {"lockfileVersion": "yarn1", "packages": pkgs}


def parse_lock(text: str, label: str = "lockfile"):
    fmt = detect_format(text)
    if fmt == "yarn1":
        return parse_yarn_lock(text, label)
    if fmt == "yarn-berry":
        raise LockError(f"{label}: this is a Yarn Berry (v2+) lockfile; only npm package-lock.json and Yarn Classic yarn.lock are supported")
    if fmt == "pnpm":
        raise LockError(f"{label}: pnpm-lock.yaml is not supported yet; only npm package-lock.json and Yarn Classic yarn.lock are supported")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise LockError(f"{label}: not valid JSON ({e.msg} at line {e.lineno})") from e
    if not isinstance(data, dict):
        raise LockError(f"{label}: expected a JSON object")
    version = data.get("lockfileVersion")
    pkgs = {}
    if isinstance(data.get("packages"), dict):
        for key, meta in data["packages"].items():
            if key == "" or not isinstance(meta, dict):
                continue
            if meta.get("link"):
                continue
            pkgs[key] = {"name": meta.get("name") or name_from_key(key), "version": meta.get("version"),
                         "resolved": meta.get("resolved"), "integrity": meta.get("integrity"),
                         "install": bool(meta.get("hasInstallScript")), "install_known": True,
                         "dev": bool(meta.get("dev"))}
    elif isinstance(data.get("dependencies"), dict):
        def walk(deps, prefix):
            for n, meta in deps.items():
                if not isinstance(meta, dict):
                    continue
                key = f"{prefix}node_modules/{n}"
                pkgs[key] = {"name": n, "version": meta.get("version"), "resolved": meta.get("resolved"),
                             "integrity": meta.get("integrity"), "install": False, "install_known": False,
                             "dev": bool(meta.get("dev"))}
                if isinstance(meta.get("dependencies"), dict):
                    walk(meta["dependencies"], key + "/")
        walk(data["dependencies"], "")
    else:
        raise LockError(f"{label}: no `packages` or `dependencies` section; is this an npm package-lock.json?")
    return {"lockfileVersion": version, "packages": pkgs}


def _host(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _algo(integrity):
    m = re.match(r"^(sha\d+)-", integrity or "")
    return m.group(1) if m else None


def _vkey(v):
    parts = re.split(r"[.+-]", v or "")
    out = []
    for p in parts[:3]:
        out.append(int(p) if p.isdigit() else 0)
    return out + [0] * (3 - len(out))


def _f(rule, sev, key, pkg, title, detail):
    return {"rule": rule, "severity": sev, "package": pkg["name"], "path": key,
            "version": pkg.get("version"), "title": title, "detail": detail}


def _registry_tarball_name(url):
    """For https://host/<name>/-/<file>-<ver>.tgz return <name>, else None."""
    path = urlparse(url).path
    m = re.match(r"^/((?:@[^/]+/)?[^/]+)/-/", path)
    return m.group(1).replace("%2f", "/").replace("%2F", "/") if m else None


def static_checks(key, pkg, allowed_hosts, is_new):
    """Checks that apply to a package as it is in the NEW lockfile."""
    out = []
    url = pkg.get("resolved") or ""
    if url:
        scheme = urlparse(url).scheme
        host = _host(url)
        if scheme == "http":
            out.append(_f("LD005", "high", key, pkg, "Package is fetched over plain HTTP", f"resolved URL uses http:// ({host}); contents can be altered in transit."))
        if url.startswith(("git+", "git:", "github:")) or scheme in ("git", "git+ssh", "git+https"):
            pinned = bool(re.search(r"#[0-9a-f]{40}$", url))
            if not pinned:
                out.append(_f("LD005", "medium", key, pkg, "Git dependency is not pinned to a commit", "A branch or tag can move; pin a full commit hash."))
        elif host and host not in allowed_hosts and scheme in ("http", "https"):
            out.append(_f("LD002", "medium", key, pkg, f"Package comes from non-allowlisted host {host}", "Only hosts passed with --registry-host (default registry.npmjs.org and registry.yarnpkg.com) are expected."))
        tname = _registry_tarball_name(url) if host in allowed_hosts else None
        if tname and tname != pkg["name"]:
            out.append(_f("LD009", "high", key, pkg, f"Tarball path names {tname} but the entry is {pkg['name']}", "A registry URL for one package under another package's name can install different code than the name suggests."))
    if pkg.get("resolved") and not pkg.get("integrity") and not url.startswith(("git", "github:")):
        out.append(_f("LD006", "medium", key, pkg, "No integrity hash recorded", "Without an integrity value the download cannot be verified."))
    if pkg.get("integrity") and _algo(pkg["integrity"]) == "sha1":
        out.append(_f("LD004", "medium", key, pkg, "Integrity uses SHA-1", "SHA-1 is weak against deliberate collisions; modern npm records sha512."))
    return out


def diff_locks(old, new, allowed_hosts=DEFAULT_HOSTS):
    allowed = {h.lower() for h in allowed_hosts}
    op, np_ = old["packages"], new["packages"]
    findings, added, removed, changed = [], [], [], []
    for key, pkg in np_.items():
        before = op.get(key)
        if before is None:
            added.append(key)
            findings += static_checks(key, pkg, allowed, True)
            if pkg["install"]:
                findings.append(_f("LD003", "medium", key, pkg, "New package runs install scripts", "It declares hasInstallScript, so npm runs code when installing it (unless --ignore-scripts is set)."))
            continue
        if before["version"] == pkg["version"]:
            if before["integrity"] and pkg["integrity"] and before["integrity"] != pkg["integrity"]:
                findings.append(_f("LD001", "high", key, pkg, "Integrity changed but the version did not",
                                   f"{pkg['name']}@{pkg['version']} now has a different hash. Published versions are meant to be immutable; this can mean a re-publish, a different registry copy, or tampering."))
            if before["integrity"] and not pkg["integrity"]:
                findings.append(_f("LD006", "medium", key, pkg, "Integrity hash was removed", "The previous lockfile had a hash for this exact version."))
        else:
            changed.append(key)
            a, b = _vkey(before["version"]), _vkey(pkg["version"])
            if b < a:
                findings.append(_f("LD007", "medium", key, pkg, f"Downgrade {before['version']} to {pkg['version']}", "Downgrades are unusual in a lockfile update; confirm it is intended."))
            elif b[0] > a[0]:
                findings.append(_f("LD007", "info", key, pkg, f"Major upgrade {before['version']} to {pkg['version']}", "Breaking changes are possible."))
        if before["resolved"] and pkg["resolved"] and _host(before["resolved"]) != _host(pkg["resolved"]):
            nh = _host(pkg["resolved"])
            findings.append(_f("LD002", "medium" if nh in allowed else "high", key, pkg,
                               f"Download host changed from {_host(before['resolved'])} to {nh}",
                               "The same package now comes from a different server." + ("" if nh in allowed else " The new host is not in the allowlist.")))
        wa, wb = WEAK_ALGOS.get(_algo(before["integrity"]) or "", 0), WEAK_ALGOS.get(_algo(pkg["integrity"]) or "", 0)
        if wa and wb and wb < wa:
            findings.append(_f("LD004", "medium", key, pkg, "Integrity algorithm weakened", f"{_algo(before['integrity'])} became {_algo(pkg['integrity'])}."))
        if pkg["install"] and not before["install"] and before["install_known"] and pkg["install_known"]:
            findings.append(_f("LD003", "high" if before["version"] == pkg["version"] else "medium", key, pkg, "Package newly runs install scripts",
                               "It did not declare install scripts before. Only the transition is flagged."))
        if before["version"] != pkg["version"] or before["resolved"] != pkg["resolved"]:
            findings += [f for f in static_checks(key, pkg, allowed, False) if f["rule"] != "LD002"]
    for key in op:
        if key not in np_:
            removed.append(key)
    findings.sort(key=lambda f: (SEV[f["severity"]], f["rule"], f["path"]))
    notes = []
    if not (old["lockfileVersion"] and new["lockfileVersion"]) or {1, "yarn1"} & {old["lockfileVersion"], new["lockfileVersion"]}:
        notes.append("A lockfileVersion 1 or yarn.lock file does not record install scripts, so LD003 cannot be evaluated for it.")
    if "yarn1" in (old["lockfileVersion"], new["lockfileVersion"]) and old["lockfileVersion"] != new["lockfileVersion"]:
        notes.append("The two files use different lockfile formats; package identity is matched by key, so most entries will show as added and removed.")
    return {"tool": "lockdiff", "version": __version__,
            "scope": "Compares two lockfiles offline. It does not check advisories, release dates or registries.",
            "summary": {"added": len(added), "removed": len(removed), "changed": len(changed), "findings": len(findings)},
            "added": sorted(added), "removed": sorted(removed), "changed": sorted(changed),
            "findings": findings, "notes": notes}


def worst(result):
    return min((f["severity"] for f in result["findings"]), key=lambda s: SEV[s], default=None)
