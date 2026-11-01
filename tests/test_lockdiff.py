import json, os, subprocess, sys, tempfile, unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "src"))
from lockdiff.core import LockError, diff_locks, parse_lock

H1 = "sha512-" + "A" * 86 + "=="
H2 = "sha512-" + "B" * 86 + "=="
REG = "https://registry.npmjs.org"


def lock(pkgs, v=3):
    return json.dumps({"lockfileVersion": v, "packages": {"": {"name": "root"}, **pkgs}})


def pkg(name, ver="1.0.0", integ=H1, resolved=None, **kw):
    base = name.split("/")[-1]
    return {"version": ver, "resolved": resolved or f"{REG}/{name}/-/{base}-{ver}.tgz", "integrity": integ, **kw}


def run(old, new, **kw):
    return diff_locks(parse_lock(old), parse_lock(new), **kw)


def rules(r):
    return [f["rule"] for f in r["findings"]]


class T(unittest.TestCase):
    def test_no_change_no_findings(self):
        a = lock({"node_modules/a": pkg("a")})
        self.assertEqual(run(a, a)["findings"], [])

    def test_integrity_change_same_version_is_high(self):
        r = run(lock({"node_modules/a": pkg("a")}), lock({"node_modules/a": pkg("a", integ=H2)}))
        self.assertEqual([(f["rule"], f["severity"]) for f in r["findings"]], [("LD001", "high")])

    def test_integrity_change_with_version_bump_is_normal(self):
        r = run(lock({"node_modules/a": pkg("a")}), lock({"node_modules/a": pkg("a", "1.0.1", H2)}))
        self.assertNotIn("LD001", rules(r))

    def test_host_change_to_unlisted_host_is_high_and_allowlist_downgrades(self):
        new = lock({"node_modules/a": pkg("a", resolved="https://mirror.example.net/a/-/a-1.0.0.tgz")})
        old = lock({"node_modules/a": pkg("a")})
        r = run(old, new)
        self.assertIn(("LD002", "high"), [(f["rule"], f["severity"]) for f in r["findings"]])
        r2 = run(old, new, allowed_hosts=("registry.npmjs.org", "mirror.example.net"))
        self.assertIn(("LD002", "medium"), [(f["rule"], f["severity"]) for f in r2["findings"]])

    def test_plain_http(self):
        r = run(lock({}), lock({"node_modules/a": pkg("a", resolved="http://registry.npmjs.org/a/-/a-1.0.0.tgz")}))
        self.assertIn("LD005", rules(r))

    def test_new_install_script_on_new_and_existing(self):
        r = run(lock({"node_modules/a": pkg("a")}), lock({"node_modules/a": pkg("a", hasInstallScript=True), "node_modules/b": pkg("b", hasInstallScript=True)}))
        self.assertEqual(rules(r).count("LD003"), 2)
        sev = {f["path"]: f["severity"] for f in r["findings"] if f["rule"] == "LD003"}
        self.assertEqual(sev["node_modules/a"], "high")   # same version gained a script

    def test_existing_install_script_not_reflagged(self):
        a = lock({"node_modules/a": pkg("a", hasInstallScript=True)})
        self.assertEqual(run(a, a)["findings"], [])

    def test_sha1_and_weakening(self):
        old = lock({"node_modules/a": pkg("a")})
        new = lock({"node_modules/a": pkg("a", "1.0.1", "sha1-" + "x" * 27 + "=")})
        r = run(old, new)
        self.assertEqual(rules(r).count("LD004"), 2)  # weakened + SHA-1

    def test_tarball_name_mismatch(self):
        bad = pkg("left-pad", resolved=f"{REG}/evil/-/evil-1.0.0.tgz")
        r = run(lock({}), lock({"node_modules/left-pad": bad}))
        self.assertIn("LD009", rules(r))

    def test_scoped_names_match(self):
        ok = {"version": "1.0.0", "resolved": f"{REG}/@s/p/-/p-1.0.0.tgz", "integrity": H1}
        self.assertEqual(run(lock({}), lock({"node_modules/@s/p": ok}))["findings"], [])

    def test_unpinned_git_dependency(self):
        g = {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/y.git#main"}
        self.assertIn("LD005", rules(run(lock({}), lock({"node_modules/y": g}))))
        g2 = {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/y.git#" + "a" * 40}
        self.assertNotIn("LD005", rules(run(lock({}), lock({"node_modules/y": g2}))))

    def test_downgrade_and_major(self):
        r = run(lock({"node_modules/a": pkg("a", "2.0.0")}), lock({"node_modules/a": pkg("a", "1.9.0", H2)}))
        self.assertIn(("LD007", "medium"), [(f["rule"], f["severity"]) for f in r["findings"]])
        r = run(lock({"node_modules/a": pkg("a", "1.0.0")}), lock({"node_modules/a": pkg("a", "2.0.0", H2)}))
        self.assertIn(("LD007", "info"), [(f["rule"], f["severity"]) for f in r["findings"]])

    def test_nested_paths_distinct(self):
        a = lock({"node_modules/a": pkg("a"), "node_modules/x/node_modules/a": pkg("a", "0.9.0")})
        self.assertEqual(run(a, a)["summary"]["added"], 0)

    def test_v1_format_and_note(self):
        v1 = json.dumps({"lockfileVersion": 1, "dependencies": {"a": {"version": "1.0.0", "resolved": f"{REG}/a/-/a-1.0.0.tgz", "integrity": H1, "dependencies": {"b": {"version": "1.0.0", "integrity": H1, "resolved": f"{REG}/b/-/b-1.0.0.tgz"}}}}})
        r = run(v1, v1)
        self.assertTrue(r["notes"])
        self.assertEqual(r["findings"], [])

    def test_bad_inputs(self):
        for bad in ("{nope", "[]", "{}"):
            with self.assertRaises(LockError):
                parse_lock(bad)

    def test_cli_exit_codes_and_git(self):
        d = tempfile.mkdtemp()
        old, new = os.path.join(d, "o.json"), os.path.join(d, "n.json")
        open(old, "w").write(lock({"node_modules/a": pkg("a")}))
        open(new, "w").write(lock({"node_modules/a": pkg("a", integ=H2)}))
        env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"))
        run_ = lambda *a, **k: subprocess.run([sys.executable, "-m", "lockdiff", *a], capture_output=True, text=True, env=env, **k)
        self.assertEqual(run_(old, new).returncode, 0)
        self.assertEqual(run_(old, new, "--fail-on", "high").returncode, 1)
        self.assertEqual(run_().returncode, 2)
        self.assertEqual(run_("--git", "--bad", "x").returncode, 2)
        # real git round trip
        subprocess.run(["git", "init", "-q"], cwd=d, check=True)
        subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "add", "."], cwd=d, check=True)
        os.replace(old, os.path.join(d, "package-lock.json"))
        subprocess.run(["git", "add", "package-lock.json"], cwd=d, check=True)
        subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x"], cwd=d, check=True)
        open(os.path.join(d, "package-lock.json"), "w").write(lock({"node_modules/a": pkg("a", integ=H2)}))
        p = subprocess.run([sys.executable, "-m", "lockdiff", "--git", "HEAD", "package-lock.json", "--fail-on", "high"], cwd=d, capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertIn("LD001", p.stdout)

    def test_sarif_output(self):
        d = tempfile.mkdtemp()
        old, new = os.path.join(d, "o.json"), os.path.join(d, "n.json")
        open(old, "w").write(lock({"node_modules/a": pkg("a")}))
        open(new, "w").write(lock({"node_modules/a": pkg("a", integ=H2)}))
        env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"))
        p = subprocess.run([sys.executable, "-m", "lockdiff", old, new, "--format", "sarif"],
                            capture_output=True, text=True, env=env)
        s = json.loads(p.stdout)
        self.assertEqual(s["version"], "2.1.0")
        run = s["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "lockdiff")
        self.assertTrue(run["results"])
        r0 = run["results"][0]
        self.assertEqual(r0["ruleId"], "LD001")
        self.assertEqual(r0["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], new)
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        self.assertTrue({r["ruleId"] for r in run["results"]} <= rule_ids)


YARN_HEAD = "# yarn lockfile v1\n\n"
YH = "sha512-" + "Q" * 86 + "=="
YH2 = "sha512-" + "R" * 86 + "=="


def ylock(*entries):
    return YARN_HEAD + "\n".join(entries) + "\n"


def yentry(descs, ver, name, integ=YH, host="registry.yarnpkg.com", frag="", extra=""):
    base = name.split("/")[-1]
    head = ", ".join(f'"{d}"' if d.startswith("@") else d for d in descs)
    lines = [f"{head}:", f'  version "{ver}"', f'  resolved "https://{host}/{name}/-/{base}-{ver}.tgz{frag}"']
    if integ:
        lines.append(f"  integrity {integ}")
    return "\n".join(lines) + extra + "\n"


class YarnClassic(unittest.TestCase):
    def test_parse_scoped_multi_descriptor_entry(self):
        lk = parse_lock(ylock(yentry(["@babel/core@^7.1.0", "@babel/core@^7.2.0"], "7.2.2", "@babel/core")))
        self.assertEqual(lk["lockfileVersion"], "yarn1")
        (key, p), = lk["packages"].items()
        self.assertEqual(key, "@babel/core@^7.1.0")
        self.assertEqual((p["name"], p["version"]), ("@babel/core", "7.2.2"))

    def test_identical_lockfiles_have_no_findings(self):
        a = ylock(yentry(["a@^1.0.0"], "1.0.0", "a"))
        self.assertEqual(run(a, a)["findings"], [])

    def test_integrity_change_same_version_is_high(self):
        r = run(ylock(yentry(["a@^1.0.0"], "1.0.0", "a")), ylock(yentry(["a@^1.0.0"], "1.0.0", "a", integ=YH2)))
        self.assertEqual([(f["rule"], f["severity"]) for f in r["findings"]], [("LD001", "high")])

    def test_version_bump_inside_range_is_a_change_not_add_remove(self):
        r = run(ylock(yentry(["a@^1.0.0"], "1.0.0", "a")), ylock(yentry(["a@^1.0.0"], "1.0.1", "a", integ=YH2)))
        self.assertEqual((r["summary"]["added"], r["summary"]["removed"], r["summary"]["changed"]), (0, 0, 1))
        self.assertNotIn("LD001", rules(r))

    def test_yarnpkg_registry_is_allowlisted_but_other_hosts_are_not(self):
        old = ylock()
        ok = run(ylock(yentry(["a@^1.0.0"], "1.0.0", "a")), ylock(yentry(["a@^1.0.0"], "1.0.0", "a"), yentry(["b@^1.0.0"], "1.0.0", "b")))
        self.assertNotIn("LD002", rules(ok))
        bad = run(ylock(yentry(["a@^1.0.0"], "1.0.0", "a")), ylock(yentry(["a@^1.0.0"], "1.0.0", "a"), yentry(["b@^1.0.0"], "1.0.0", "b", host="evil.example.net")))
        self.assertIn("LD002", rules(bad))

    def test_sha1_fragment_becomes_weak_integrity_for_new_package(self):
        frag = "#" + "ab" * 20
        r = run(ylock(), ylock(yentry(["old@^1.0.0"], "1.0.0", "old", integ=None, frag=frag)))
        self.assertIn("LD004", rules(r))
        self.assertNotIn("LD006", rules(r))

    def test_missing_integrity_and_no_fragment_is_ld006(self):
        r = run(ylock(), ylock(yentry(["x@^1.0.0"], "1.0.0", "x", integ=None)))
        self.assertIn("LD006", rules(r))

    def test_downgrade_is_flagged(self):
        r = run(ylock(yentry(["a@^1.0.0"], "1.2.0", "a")), ylock(yentry(["a@^1.0.0"], "1.1.0", "a", integ=YH2)))
        self.assertIn("LD007", rules(r))

    def test_unpinned_git_dependency(self):
        git = 'dep@github:owner/dep:\n  version "1.0.0"\n  resolved "git+https://github.com/owner/dep.git#main"\n'
        r = run(ylock(), ylock(git))
        self.assertIn("LD005", rules(r))

    def test_note_says_install_scripts_unknown(self):
        a = ylock(yentry(["a@^1.0.0"], "1.0.0", "a"))
        self.assertTrue(any("install scripts" in n for n in run(a, a)["notes"]))

    def test_berry_pnpm_and_garbage_are_rejected_clearly(self):
        with self.assertRaises(LockError) as e:
            parse_lock('__metadata:\n  version: 6\n\n"a@npm:^1.0.0":\n  version: 1.0.0\n')
        self.assertIn("Berry", str(e.exception))
        with self.assertRaises(LockError) as e:
            parse_lock("lockfileVersion: '9.0'\n\nimporters:\n  .: {}\n")
        self.assertIn("pnpm", str(e.exception))
        with self.assertRaises(LockError):
            parse_lock(YARN_HEAD + "this is not a lockfile entry\n")


    def test_real_yarn_lockfile_fixture(self):
        """A lockfile generated by Yarn 1 (express, @babel/core, lodash): every entry parses, no false positives."""
        with open(os.path.join(ROOT, "tests", "fixtures", "real-yarn-v1.lock"), encoding="utf-8") as fh:
            text = fh.read()
        lk = parse_lock(text)
        blocks = [l for l in text.splitlines() if l and not l.startswith((" ", "#"))]
        self.assertEqual(len(lk["packages"]), len(blocks))
        self.assertGreater(len(blocks), 100)
        self.assertEqual(run(text, text)["findings"], [])
        everything_new = run(YARN_HEAD, text)
        self.assertEqual(everything_new["summary"]["added"], len(blocks))
        self.assertEqual(everything_new["findings"], [])

    def test_cli_runs_on_yarn_examples(self):
        env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"))
        ex = lambda n: os.path.join(ROOT, "examples", n)
        p = subprocess.run([sys.executable, "-m", "lockdiff", ex("old-yarn.lock"), ex("new-yarn.lock"), "--fail-on", "high", "--format", "json"],
                           capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 1, p.stderr)
        got = {f["rule"] for f in json.loads(p.stdout)["findings"]}
        self.assertEqual(got, {"LD001", "LD002", "LD004", "LD005"})


if __name__ == "__main__":
    unittest.main()
