# Signed results

`flagwake verify` re-derives every number of a report from the commands stored in it, so an edited
report fails. On its own it cannot say what produced those commands. A signed result adds that: the
report is made in a GitHub Actions run and signed with a GitHub artifact attestation (Sigstore), and
anyone can check which repository, commit and run produced it.

## Make one

Add this workflow to the repository of your defender (for example `.github/workflows/flagwake.yml`):

```yaml
name: flagwake
on: [push, workflow_dispatch]
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      id-token: write      # the run's own signing identity
      attestations: write  # to store the signature with the repository
    steps:
      - uses: actions/checkout@v5
      - uses: Sid00011/Flagwake@v0.5.0rc4
        with:
          agent: python my_defender.py   # your program (docs/PROTOCOL.md)
```

The run draws fresh incidents, writes `report.json`, `report.html` and the signature
`report.sigstore.json` into the `flagwake-result` artifact, lists the attestation under the
repository's attestations, and shows the damage index in the run summary. Other inputs: `pack`,
`seeds`, `world`, `fail-under`, `sign` (see `action.yml`). A full example:
[examples/ci/flagwake-signed.yml](../examples/ci/flagwake-signed.yml).

Signing is free in public repositories. For a private repository, check whether your GitHub plan
includes artifact attestations.

## Check one

```bash
pip install "flagwake[provenance]"
flagwake verify report.json --provenance report.sigstore.json --repo ORG/REPO
```

The check runs offline. It accepts the bundle the action wrote, or the file
`gh attestation download report.json --repo ORG/REPO` saves. GitHub's own tool gives an
independent second opinion on the signature: `gh attestation verify report.json --repo ORG/REPO`.

## What a valid signature shows

- The file is exactly the one the run wrote: change one byte and the signature fails.
- It was written by a GitHub Actions run of ORG/REPO, at the commit, run and attempt the report
  names, on a GitHub-hosted runner: a machine the repository's maintainers do not control.
- With `flagwake verify`, every number follows from the commands stored in it.
- The defender could not sign anything itself: Flagwake removes the run's signing tokens from the
  defender's environment.

## What it does not show

- **That the defender is honest.** A workflow can run any program. The signature points to the
  exact commit, so for a public repository you can read the defender and the workflow as they
  were.
- **How many runs came before.** A run can be repeated and the best one shared. Every run draws new
  incidents, the report names its attempt number, and a public repository's run history shows the
  other runs.
- **Anything about a self-hosted runner.** Whoever runs it controls the machine, so verify
  refuses such a signature.
- **That a closed product behaved this way on its own.** For a product you cannot read, run
  Flagwake yourself against it (HTTP, MCP or tools mode) on a fresh pack
  ([FOR_COMPANIES.md](FOR_COMPANIES.md)).
