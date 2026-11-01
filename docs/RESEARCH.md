# Research record (2026-10-26)

Method: web searches plus page fetches by an automated tool. Search result pages gave titles only; claims below come from fetched pages. I did not run any competing tool or read source code.

## Observed

- [lockvet](https://pkg.go.dev/github.com/matteo-sung/lockvet@v0.4.5) (fetched): diffs two lockfiles (including Cargo.lock) and reports version changes, advisories via OSV.dev, release age, deprecations/yanks, licence changes, unlisted versions, typosquat suspects, newly added install scripts, dropped provenance. Its page describes no check for **integrity changing while the version stays the same**, nor for **a package switching registry host**.
- Search results also surfaced lockfile-lint-style tools, an "octoscope" lockfile reader and others; I did not open them, so I make no claim about what they check.

## Gap targeted

An offline, dependency-free reviewer for the structural tamper signals in a lockfile diff, designed to run on every pull request without network access: same-version integrity change, host change, plain-HTTP or unpinned git sources, tarball path naming a different package than the entry, SHA-1 or missing integrity, newly appearing install scripts, downgrades. It is a complement to advisory-based tools, not a replacement, and does not claim to catch anything those tools catch.

## Not verified

- Whether other tools already implement every check here (I only read lockvet's page).
- npm's exact behaviour for every lockfile edge case; supported inputs are lockfileVersion 1, 2 and 3 as I understand them, tested only on fixtures I wrote, not on real-world lockfiles.
