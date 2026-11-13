# Signed results

`flagwake verify` re-derives every number of a report from the commands stored in it, so an edited
report fails. On its own it cannot say what produced those commands. A signed result adds that:
the report is made by Flagwake's signing workflow in GitHub Actions, and anyone can check, with
cryptography rather than trust in whoever shares it, how it was made.

## Make one

Add this to the repository of your defender (for example `.github/workflows/flagwake.yml`):

```yaml
name: flagwake
on: [push, workflow_dispatch]
permissions:
  contents: read
jobs:
  check:
    permissions:
      contents: read
      id-token: write      # the run's own signing identity
      attestations: write  # to store the signatures with the repository
    uses: Sid00011/Flagwake/.github/workflows/check.yml@v0.5.0rc4
    with:
      agent: python my_defender.py   # your program (docs/PROTOCOL.md)
      setup: pip install --user -r requirements.txt
```

Inputs: `agent`, `setup` (run as the defender's user before the check), `pack`, `seeds`, `world`,
`defender-env` (names of your secrets the defender may read; add `secrets: inherit`),
`defender-vars` (public `NAME=value` lines), `step-timeout`, `fail-under`, `name`. A full example:
[examples/ci/flagwake-signed.yml](../examples/ci/flagwake-signed.yml). The `flagwake-result`
artifact holds `report.json`, `report.html`, `report.sigstore.json`, the attempt ticket and its
signature. Signing is free in public repositories; for a private repository, check whether your
GitHub plan includes artifact attestations.

The Flagwake GitHub Action (`uses: Sid00011/Flagwake@v0.5.0rc4`) runs the same steps inside your
own workflow. Its signature then names your workflow, not Flagwake's, as the signer, so a reader
has to read your workflow to know the steps ran as described.

## What the workflow does, in order

1. It installs Flagwake from the workflow's own commit.
2. It creates a user for the defender, with no sudo and no access to the harness, and gives it a
   copy of your repository.
3. It numbers the run: the next attempt number of your repository, from Sigstore's public log.
4. It signs the attempt ticket. The ticket enters the public log before any incident exists.
5. It runs the check. Flagwake first confirms that this run's ticket is in the log, then draws
   fresh incidents with a key made inside the run. Every defender process runs as the defender's
   user and is stopped when its incident ends; nothing of it may outlive the run.
6. It signs `report.json` exactly as written, and checks the signature before it uploads anything.

## Check one

```bash
pip install "flagwake[provenance]"
flagwake verify report.json --provenance report.sigstore.json --repo ORG/REPO --attempts --require-official
```

```
OK   report.json
     signature: made in GitHub Actions: ORG/REPO at commit 1a2b3c4d5e6f, run 4242 (attempt 1, github-hosted runner)
     harness: Flagwake's signing workflow at release v0.5.0rc4
     defender: python my_defender.py; ran as a separate user flagwake-defender, without sudo
     incidents: drawn in the run
     attempt 3: ticket in the public log at index 912345, logged before the draw (--attempts lists them all)
     attempt 3 of ORG/REPO; 2 earlier attempt(s) are in the public log:
       attempt 1: 4100/attempts/1 (log 900001)
       ...
```

The signature check runs offline. `--attempts` reads Sigstore's public log over the network.
`--require-official` fails unless every guarantee below holds. GitHub's own tool gives a second
opinion on the signature and the signer:
`gh attestation verify report.json --repo ORG/REPO --signer-workflow Sid00011/Flagwake/.github/workflows/check.yml`.

## What a signed result shows

- **The file is the one the run wrote.** Change one byte and the signature fails.
- **Where it was made.** A GitHub Actions run of ORG/REPO, at the commit, run and attempt the report
  names, on a GitHub-hosted runner: a machine the repository's maintainers do not control.
- **That Flagwake's steps ran unmodified.** The signing certificate names Flagwake's signing
  workflow at a release tag as the signer, whatever the calling workflow says.
- **That the defender could not touch the harness.** It ran as its own user without sudo: it could
  not read the harness's memory or environment (the incident key, the run's signing token), write
  the output folder, or leave a process behind. A self-test checks this on every release: a
  defender that tries each of those attacks is blocked every time, and the same attacks work
  without the separate user (`.github/workflows/signed-check.yml`).
- **That nobody chose the incidents.** The key that draws them is made inside the run.
- **How many tries came before.** Every run leaves a ticket in Sigstore's public log before its
  incidents are drawn, and the log cannot be edited. `--attempts` lists them, so a result that was
  the fifth try cannot pass for the first.
- **Which model answered,** for Flagwake's reference model agent: the report records the model id
  and the address the model's own server returned, as relayed by that agent (public code, at the
  harness's version).
- **That the numbers follow from the commands** (verify, as for any report).

## What it does not show

- **That the defender is honest.** A workflow can run any program. The signature points to the
  exact commit, so for a public repository you can read the defender as it was.
- **That a closed product behaved this way on its own.** For a product you cannot read, run
  Flagwake yourself against it (HTTP, MCP or tools mode) on a fresh pack
  ([FOR_COMPANIES.md](FOR_COMPANIES.md)).
- **Runs made elsewhere.** A repository can practise without the workflow; only runs with a ticket
  count as attempts, and a new repository starts at attempt 1.
- **What a model provider did on its side.** The model id is the provider's own word.
- **Anything about a self-hosted runner.** Whoever runs it controls the machine, so verify refuses
  such a signature.
