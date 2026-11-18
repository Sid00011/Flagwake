# Security policy

## What this project is

A test harness for security responder agents, built on a fictional company. It contains no real
exploits, scanners, malware or credentials, and it never touches a real system. The
"vulnerabilities" and the intruder are abstract records in invented incidents. A weakness in an
incident's design (for example a command list that always scores well for the wrong reason) is a
design issue: please open a normal issue for it. The threat model of the check itself is in
[docs/SECURITY.md](docs/SECURITY.md).

## What to report privately

- A way to make `report.html` or the report viewer run code it should not, or send a request to
  another site (they have a strict Content-Security-Policy and make no external requests).
- A way to change a report's numbers without `flagwake verify` noticing.
- A way for an agent under test to reach outside its own process through the harness, or to make
  `flagwake serve` or the HTTP adapter talk to anything other than localhost.
- A problem in the GitHub Actions workflows (token permissions, injection through pull-request
  text).
- Anything in the repository that looks like a real secret or real exploit code.

## How to report

Use GitHub's private vulnerability reporting: the repository's **Security** tab →
**Report a vulnerability**. Please include the commit, the steps and what you observed. Do not open
a public issue for these.

This is a one-person project: expect a first answer within about a week. Fixes are credited in
`CHANGELOG.md` if you wish.

## Checking a download

From 0.5.0rc2 on, releases are built and published by the `release` workflow of this repository
with PyPI trusted publishing. On https://pypi.org/project/flagwake/, each file's **Provenance**
names this repository, that workflow and the commit it was built from. The same two files are
attached to the GitHub release, which lists their SHA-256; `pip download flagwake==<version>
--no-deps` and a SHA-256 tool let you compare them. To check the signed provenance itself:

```
pip install pypi-attestations
python -m pypi_attestations verify pypi --repository https://github.com/Sid00011/Flagwake pypi:flagwake-<version>-py3-none-any.whl
```

It prints `OK` for a file built by this repository and fails for any other.

## Fixed security issues

**Signed results, v0.5.0rc4 to v0.5.2 (fixed in 0.5.3, 2026-11-18).** In Flagwake's
signing workflow (`.github/workflows/check.yml`), the calling workflow's `defender-env`
could name one of the job's own variables, such as `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, and
the defender then received it. With that token a defender could obtain the run's signing
identity and sign a report it made itself, so a signature from those releases does not
prove the report came from the run. Unsigned reports, scores and `flagwake verify`
without `--provenance` were not affected.

From 0.5.3, `flagwake verify --provenance` calls such a signature not official and names
the calling workflow file at the signed commit. A result signed by an affected release
can still be judged by hand: if that file's `defender-env` names only your own secrets
(no `ACTIONS_`, `GITHUB_` or `RUNNER_` variable, and no expression that could produce
one), the defender never had the token. To be safe, run it again with 0.5.3 or later.

## Supported versions

Only the latest commit on `main`. A fix that changes scores changes the rules hash or the
generator version, so older reports no longer verify against the new build.
