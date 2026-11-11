# Changelog

All notable changes. Dates are UTC. Incidents are versioned by the generator version, the rules by
the rules hash (see `docs/METHODOLOGY.md`).

## Unreleased

- **On PyPI.** `pip install flagwake` installs the command; the README, the quick starts and the
  CI example (`examples/ci/rc-check.yml`, now pinned to a release) use it.
- **CI.** The page tests install Chromium without apt, so they no longer depend on Ubuntu's
  package mirrors being reachable from the runner.

## 0.5.0rc1 (2026-11-08, first public release candidate)

- **Run key and fresh incidents.** Every run makes a secret key. The incident id a program receives
  is keyed with it, so it cannot be traced back to family and seed, and the default pack, `fresh`,
  draws new seeds for each run from 1,000,000-999,999,999 with it (`--run-key` repeats an earlier
  run's incidents; `--pack heldout` keeps the fixed set). The report records the key once the run
  is over; verify rebuilds the ids and checks that the incidents belong to the pack the report
  names. A report built without a pack name says `custom`.
- **Keys over plain http.** The reference model agent and the tool example refuse to send a key
  over plain http to another machine; the registry and the page refuse to store one for such an
  address.
- **A sounder reference response.** Under a company file the response that fixes the 0 of the
  index is the cheapest of up to four ground-truth command lists; it never acts without approval
  and no shipped program does better than it (it used to act unapproved in every
  `approval-required` incident). Rules hash and rules-2 fingerprint move; the original rules are
  untouched (docs/METHODOLOGY.md, 2026-11-11).
- **Routine log lines fit the machine and the hour** (generator `rc-gen-8`): text only; every
  shipped program behaves and scores as before.
- **Cost breakdown.** `flagwake demo` and the result page show where the damage came from, in
  damage points and as shares, next to what doing nothing and the reference response cost.
- **The demo is a pair.** A careful and a gullible example defender on the same incidents, side
  by side on the page; the home page shows the same comparison, and a test keeps its numbers true.
- **`flagwake mcp --world`.** The MCP server runs in any company (the default one unless told
  otherwise); its transcripts record their company and `flagwake report` scores them in it.
- **A company file with anything in any field gets plain problems.** A list or a mapping where a
  name belongs used to stop the checker with an error; a fuzz test now covers every field of the
  company file and of flagwake.yaml.
- **`flagwake --help` is grouped** (start here, test a defender, read results, your own company,
  other ways in); a program that is not found is named plainly.
- **Checks.** `mypy` and a complexity limit (20) run in CI; the longest functions are split.
  `python scripts/company_checks.py` reproduces the checks of the checker on the shipped
  companies (null programs, the reference response, the leak scan, retest, weights, ties).
- **The mark** is signal flag U cut to a swallowtail, the V of a wake.
- **Your own company.** A strict, documented company-file format (docs/COMPANY_FORMAT.md): zones,
  hosts, people and roles, accounts, partner and supplier links, hosted services, business flows,
  approval policy, log sources with delays and gaps, the business calendar and optional custom
  costs. `flagwake world init|validate|show`; `--world` on check, run, baselines, doctor, replay,
  verify and in the registry and the local page. Two shipped companies (18 and 60 hosts).
  Families bind to what a company contains and are skipped, with the reason, when it lacks it.
- **Rules 2** on company files: 20 families (eight new: privileged-laptop-to-payments,
  supplier-down-spreading, helpdesk-pressure, stolen-sign-in-saas, backup-targeting, admin-misuse,
  credential-in-ticket, signal-in-the-flood), the commands `pause`, `resume`, `notify`, `release`
  and `logs <source>`, early assessments that later evidence revises, and difficulty tiers whose
  effect was fixed in advance. Three damage terms (outflow, pause cost, backup integrity) and four
  decision measures (outflow prevented versus pause cost, anchoring, unsupported claims,
  notification appropriateness), re-derived by verify and in the profile.
- **The environment as tools (mode B):** MCP over HTTP or stdio and a local REST API with an
  OpenAPI document and webhooks; every call maps one to one to a world command, so scores match
  the text protocol (tested on every shipped program). `flagwake tools serve|catalogue|openapi|
  test`, `mode: tools` in the registry and on the page, and a reference tool loop for models with
  tool calls.
- **Fidelity disclosure** in every report: mode, adapter, whether the harness sent instruction
  text, and hashes of everything sent (re-derived by verify).
- **What a score is and is not:** a box in every report and docs/VALIDITY.md.
- **`flagwake demo`:** two shipped example defenders on the practice incidents, the first result
  printed with its cost breakdown, written as report.json and report.html and verified, then an
  edited copy verified and rejected. Offline, no model, about two seconds.
- **The local page:** a demo on the first screen; results open on the damage index, four headline
  figures, the cost breakdown and the findings, with buttons to verify the result and to verify an
  edited copy (in memory; the report stays untouched). The page, report.html and the report viewer
  share one calm dark-blue design and the Flagwake mark.
- **Approvals on company files follow shown evidence:** the duty manager grants a critical action
  when the defender had already been shown an alert or indicator naming the target, and denies it
  otherwise, so asking for approval no longer reveals the hidden state (docs/METHODOLOGY.md,
  2026-11-04). The rules-2 fingerprint moves.
- **Varied wording:** each attacker event appears in several wordings, chosen per incident
  (generator rc-gen-7), so a fixed string per event cannot be memorised.
- The reference model scaffold reads the command after a reasoning block (`</think>`), so a line
  of reasoning never becomes an action, and keeps one line per earlier command with the start of
  what it showed, so a model no longer forgets what it read early in a long incident and reads it
  again until its call cap.
- **License:** the code is under the GNU Affero General Public License v3.0 (AGPL-3.0-only), with
  commercial licenses available from the author (LICENSING.md); the documentation and data are
  under CC BY 4.0.
- Format identifiers: `flagwake-company-1`, `flagwake-rc-report-1` and `flagwake-rc-transcript-1`
  (docs/METHODOLOGY.md, 2026-11-06). The original world keeps rules 1 byte for byte (same rules
  hash and fingerprint), and verify says which version made a report.

## 0.4.0rc1 (2026-10-31, release candidate; not published)

- A critical action taken without the required approval adds a change-control review cost to the
  damage index (`W_UNAPPROVED`, 300). Skipping an approval is never cheaper than asking. The rules
  hash and the golden fingerprint change; earlier reports no longer verify.
- Comparisons with the baselines are paired: the verdict comes from a seeded paired bootstrap of
  the per-incident difference, and the profile says how many incidents tell 10 points apart.
- The local page has its own look and a live incident room (the network with the intruder, the
  defender's commands, the clock) while a check or a run works.

## 0.3.0rc1 (2026-10-31, release candidate; not published)

- `flagwake ui`: a local page that walks through adding a defender (a model on this computer,
  found automatically; a model online; your own service), the connection check with the likely fix
  for each failed check, a run with an estimated time, progress with a Stop button, and a result in
  plain words with downloads. It binds 127.0.0.1, checks the Host header, needs a per-launch token,
  accepts changes only from its own origin as JSON, logs nothing and never writes a key.
  Defenders that start a program are off unless started with `--allow-commands`.
- `Start-Flagwake.bat` and `start-flagwake.sh` set up a private environment and start the page.
- `run_pack` accepts progress and stop callbacks.

## 0.2.0rc1 (2026-10-31, release candidate; not published)

- A defender registry: `flagwake init` writes `flagwake.yaml`; `flagwake defenders add|list|show|
  remove|test` edits and checks it; `flagwake run` runs registered defenders over the held-out pack
  (or `--pack practice`) and writes one report per defender and pack under `flagwake-runs/`;
  `flagwake view` serves the report viewer on 127.0.0.1 and opens it on the newest report. Kinds:
  `command` (any program speaking JSON lines), `http`, `mcp` (the harness calls the defender's
  `act` tool), `model-endpoint` (any chat-completions endpoint through the reference program) and
  `baseline`. The file is read by a strict parser that rejects unknown fields; only the command
  string ever reaches a command line, and keys stay in environment variables.
- Every start message says `"role": "defender"`. A conformance suite (`flagwake defenders test`)
  runs canary incidents and reports seven checks; the report header shows the result, the pack
  label (practice seeds are public, held-out are for claims) and a warning when practice beats
  held-out by far.
- Programs receive an opaque incident id instead of `family:seed`, which named the kind of
  incident and allowed regenerating its ground truth.
- A Defender profile in report.json, report.html and the viewer: failure taxonomy with counts,
  harness problems apart from the defender's own, the damage index and five behaviour scores next
  to two baselines on the same incidents with n and intervals ("too few incidents to conclude"
  where they overlap), the run-to-run spread with `--repeat`, three findings and the cost.
  `flagwake verify` recomputes it.
- Checks of the checker: `scripts/sanity_checks.py` (null programs, oracle consistency, leak scan,
  re-runs, separation) and `scripts/sensitivity.py` (weights), with tests.
- The reference model program's instruction explains each report field and shows a complete
  example with a confidence per host; it maps common report shapes (a single confidence number,
  percentages, low/medium/high, host/confidence pairs) to the documented form before sending.

## 0.1.0rc3 (2026-10-31, release candidate; not published)

- The repository holds the check alone. The earlier prototype and everything that served it
  (its simulator, bots, ratings, data, website, scripts, docs and tests) moved to a separate
  repository with its full history; `flagwake` keeps only `check`, `baselines`, `replay`,
  `doctor`, `mcp`, `serve`, `verify` and `report --mcp-log`. The docs drop their `RC_` prefix.
- A golden determinism check (`scripts/golden_check.py`, `tests/rc/golden.json`) replaces the
  old fingerprint guard; CI runs it on every push and compares it across platforms on tags.
The Responder Check is now only a test of an agent under test, read through `report.json`,
`report.html`, the report viewer and `flagwake replay`.
- Removed: the interactive terminal mode (`--rc`, `--rc-family`, `--rc-seed` and
  `--rc-difficulty`), the browser terminal in `web/rc/` with its
  JavaScript port of the interpreter and incident data, and their tests. `flagwake serve` serves
  the report viewer only.
- Every incident opens with the same plain observation: company name, clock, business status,
  alert queue and command list (it was a scene line per family). Generator `rc-gen-5`, world
  `hp-2`; seeds, ground truth, scoring and the record format are unchanged, and every shipped
  baseline gives the same commands and per-incident outcomes as before. Reports from
  0.1.0rc2 do not verify with this build (observation hashes and versions differ).
- `flagwake replay` prints a plain transcript: the minute of each command, the command, the
  minutes it took, the observation, then the business cost and the ground truth.
- The worst-incident summaries are failure traces (key `traces` in `report.json`, renamed).
- The reference model program lists the `ask` topics and tells the model, with every
  observation, how many of its calls remain (`--max-calls`, 30 by default); extra request fields
  for a local server through `FLAGWAKE_LLM_EXTRA_BODY`.
- The scripted baselines no longer depend on the string hash seed (two of them walked a set of
  planted-text ids unsorted).

## 0.1.0rc2 (2026-10-26, release candidate; not published)

- A restore takes two simulated hours (was 20 minutes); restore and patch times enter the rules
  hash. Generator `rc-gen-4`: in `late-staging` the staging needs the stolen web account, and in
  `misconfig-not-wipe` the open flaw also exposes `db-01`.
- New baseline `thorough` (contain, then evict from what it observed).
- Planted text counts as surfaced only when the responder read it.

## 0.1.0rc1 (2026-10-26, release candidate; not published)

The Responder Check, an offline test of security responder agents.
- `flagwake check | replay | baselines | doctor | mcp | serve`, an interactive terminal mode
  (removed in 0.1.0rc3), and `flagwake verify` / `flagwake report --mcp-log` for its reports. An invented company (18 hosts),
  12 incident families with a scripted adaptive attacker and planted instructions in three tiers,
  generator `rc-gen-3`, practice seeds 120000–120999 and held-out seeds 130000–130999.
- Scoring with intervals: containment, false containment, time to first containment,
  evidence-gated actions, approval compliance, planted-order violations (per tier) and UTAR, a
  business-damage index between an evicting oracle (0) and doing nothing (100), collateral, cost
  of checking, unrecognised commands, calibration and restraint. `flagwake verify` replays every
  transcript and names the first field that does not match.
- Nine shipped scripted programs (six baselines, three metric-validity fixtures) and a calibration
  gate that checks they separate, per family, including command lists built from the ground
  truth that show late and incomplete containment both cost.
- Agents connect over JSON lines, localhost HTTP, MCP (stdio) or the Python API. A misbehaving
  agent ends only its own incident; `flagwake doctor` checks an agent or a model endpoint in about
  a minute. A reference model agent (`python -m cyberarena.rc.model_agent`) for any
  chat-completions endpoint, with call and token caps; it needs no key to exist.
- `report.html`: one file, no script, strict CSP; the five things to read first fit one phone
  screen. A browser terminal (removed in 0.1.0rc3) and a report viewer in `web/rc/`.
- Tests have a per-test time limit; CI actions are pinned to commit hashes and every CI job has a
  time limit.

## 0.0.1 (unreleased)

An earlier prototype, kept in a separate repository with its own history.
