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
`defender-env` (secrets the defender may read, as `NAME` or `NAME=SECRET`), `defender-vars`
(public `NAME=value` lines), `step-timeout`, `fail-under`, `name`. Secret: `model-key`. A full
example: [examples/ci/flagwake-signed.yml](../examples/ci/flagwake-signed.yml).
The `flagwake-result` artifact holds `report.json`, `report.html`, `report.sigstore.json`, the
attempt ticket and its signature. Signing is free in public repositories; for a private
repository, check whether your GitHub plan includes artifact attestations.

To test a model with Flagwake's own model agent, so that the report can say which model answered:

```yaml
    with:
      agent: reference:model --max-calls 8
      defender-vars: |
        FLAGWAKE_LLM_BASE_URL=https://api.your-provider.example/v1
        FLAGWAKE_LLM_MODEL=the-model-id
      defender-env: FLAGWAKE_LLM_KEY=model-key
    secrets:
      model-key: ${{ secrets.YOUR_PROVIDER_KEY_SECRET }}
```

`model-key` is the one secret the workflow accepts from any repository, and the defender reads it
only under the name `defender-env` gives it. GitHub passes `secrets: inherit` only between
repositories of one organisation or enterprise (GitHub Docs, "Reuse workflows", read 2026-11-13),
so from any other account a key has to come in as `model-key`. Within one organisation,
`defender-env` can also name your own secrets after `secrets: inherit`. Either way the defender
sees only the secrets `defender-env` names.

The Flagwake GitHub Action (`uses: Sid00011/Flagwake@v0.5.0rc4`) runs the same steps inside your
own workflow. Its signature then names your workflow, not Flagwake's, as the signer, so a reader
has to read your workflow to know the steps ran as described; `--require-official` refuses it.

## What the workflow does, in order

1. It installs Flagwake from the workflow's own commit.
2. It creates a user for the defender, with no sudo and no access to the harness, and gives it a
   copy of your repository.
3. It numbers the run: the next attempt number of your repository, from Sigstore's public log.
4. It signs the attempt ticket. The ticket is on public record before any incident exists.
5. It runs the check. Flagwake first verifies the ticket's signature and its place in the public
   log, then draws fresh incidents with a key made inside the run. Every defender process runs as
   the defender's user and is stopped when its incident ends; nothing of it may outlive the run.
6. It signs `report.json` exactly as written, and checks the signature before it uploads anything.

## Check one

```bash
pip install "flagwake[provenance]"
flagwake verify report.json --provenance report.sigstore.json --repo ORG/REPO --attempts --require-official
```

```
OK   report.json
     signature: made in GitHub Actions: ORG/REPO at commit 1a2b3c4d5e6f, run 4242 (attempt 1, github-hosted runner); signed 2026-11-14 09:30 UTC
     harness: Flagwake's signing workflow at release v0.5.0rc4
     defender: python my_defender.py; ran as a separate user flagwake-defender, without sudo
     incidents: drawn in the run; pack fresh, 60 incidents in 20 of 20 families
     world: the default company
     attempt 3: ticket signed and in the public log (index 912345) before the draw; --attempts lists every run
     attempt 3 of ORG/REPO: 2 other attempt ticket(s) of this repository are in the public log
       attempt 1: run 4100/attempts/1 (log index 900001)
       attempt 2: run 4180/attempts/1 (log index 905500)
       attempt 3: run 4242/attempts/1 (log index 912345)  <- this report
```

The signature check runs offline. `--attempts` reads Sigstore's public log over the network.
`--require-official` fails unless Flagwake's workflow at a release signed it, the defender was
isolated, the incidents were fresh ones drawn in the run, every incident family was run and the
run has an attempt ticket. GitHub's own tool gives a second opinion on the signature and the signer:
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
- **That nobody chose the incidents.** The key that draws them is made inside the run. A run on
  the public practice seeds, or with a key or a difficulty given by hand, says so and is not
  official.
- **How many checks came before.** Every check leaves a ticket in Sigstore's public log before its
  incidents are drawn, and the log cannot be edited. `--attempts` lists every ticket, also
  several signed in one run (a matrix of twenty checks is twenty tickets), so a result that was
  the fifth try cannot pass for the first. Tickets are tied to the repository's numeric id, so
  renaming the repository does not start a new count, and a ticket counts only when Sigstore's
  certificate authority issued its certificate to that repository: nobody else can add attempts
  to it.
- **Which model answered,** when the defender is `reference:model`: Flagwake starts its own model
  agent itself, from its installed code, with only the `FLAGWAKE_LLM_*` settings; the report
  records the model id the model's server returned and that server's address. For any other
  defender the model id is the defender's own word, and verify says so.
- **That the numbers follow from the commands** (verify, as for any report).

## What it does not show

- **That the defender is honest.** A workflow can run any program. The signature points to the
  exact commit, so for a public repository you can read the defender as it was.
- **That a closed product behaved this way on its own.** For a product you cannot read, run
  Flagwake yourself against it (HTTP, MCP or tools mode) on a fresh pack
  ([FOR_COMPANIES.md](FOR_COMPANIES.md)).
- **Runs made elsewhere.** A repository can practise without the workflow, and a new repository
  starts at attempt 1; only runs with a ticket count as attempts of a repository.
- **What a model provider did on its side.** The model id is the provider's own word, and the
  address is the one the workflow was given: check that it is the provider's.
- **Anything about a self-hosted runner.** Whoever runs it controls the machine, so verify
  refuses such a signature.
- **More than its own roots of trust.** A signed result rests on GitHub (the runner and the
  identity it gives a run), Sigstore (the certificate authority and the public log) and the
  packages the workflow installs from PyPI. Listing attempts uses the public log's search.
