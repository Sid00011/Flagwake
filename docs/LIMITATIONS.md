# Responder Check — limitations

Read this before you trust a number. The Responder Check is a cheap regression test of judgement
and restraint, not a certification and not a substitute for testing an agent in your own
environment.

- **Fictional and abstract.** The company, its 18 hosts, ~40 people and accounts, and every
  "vulnerability" are invented and abstract. Nothing here maps to a real system, a real CVE, or a
  real technique. A good score means an agent did well on this test, nothing more.
- **A scripted attacker.** The attacker follows a fixed script with exactly one adaptive rule per
  incident, reading only world state. It is deterministic and limited by design; it is not a free
  adversary and will not surprise an agent the way a real intruder would. The adaptive rules that
  only re-time the existing moves (`rush`, `lie_low`) change the clock, which the damage index
  normalises away, so widening them would not change scores; richer branching to a different route
  (`branch`) is used by only a few incidents, so the route a defender faces is largely fixed.
- **No real forensics.** Observations are short invented log lines and alerts. There are no files,
  memory, packets or binaries to analyse; "evidence" is text.
- **The text is a bounded vocabulary.** Log lines and alerts are built from phrases, so some of the
  work can be done by matching words. Each attacker event now appears in several wordings (varied
  per incident via `text2.VARIANTS`/`pick`; distinct attacker lines up ~37%), so a fixed string
  cannot be memorised. Indicator words are deliberately kept: a keyword rule is still right ~93% of
  the time it fires but catches only ~37% of attacker lines (measured), and the other 63% — decoys,
  quiet incidents, the revised handover note, cross-source signals — need the situation read. The
  free escalation check of the ground truth is closed on company files (METHODOLOGY, 2026-11-04).
- **Small world.** 18 hosts in 5 zones. Real networks are far larger and messier; behaviours that
  only appear at scale are out of scope.
- **The damage weights are design choices.** The business-damage index depends on weights
  (`W_HOLD`, `W_DOWN`, `W_ISOLATE`, `W_EXPOSURE`, `W_REACH`, the payroll multiplier). The downtime
  weight 2.0 is carried over from an earlier prototype's rules; the rest are ours and debatable. The
  index moves if you change them; it is a comparison within this fixed ruleset, not an absolute.
- **The index is normalised and capped.** When an incident's do-nothing and oracle damage are
  close, the per-incident index can be large for a small absolute mistake, so the headline mean caps
  each incident at 200 (a value below 0, better than the oracle, is kept). The raw mean and the count of incidents worse than doing nothing are also
  reported. See [SCORING.md](SCORING.md).
- **Fixed seed sets can be learned.** The practice seeds are public and the held-out seeds
  (130000–130999) are fixed: both come from the same open code, so a determined reader can
  regenerate them and tune a program to them. The default pack, `fresh`, draws new seeds from
  1,000,000–999,999,999 with a secret key made for each run, so its incidents are unknown until the
  run starts. A program never receives the family or the seed; the incident id it gets is keyed
  with the same secret, so it cannot be traced back to them, and the report records the key only
  once the run is over. A program written to cheat could still try to recognise the incident from
  its text, but it would have to generate a large part of the 999-million-seed space to match it.
  Through `flagwake mcp` the client itself names the family and seed it starts, so a model driving
  that server sees them; use `flagwake run` or `flagwake check` for numbers you quote.
- **Verify proves consistency, not origin.** `flagwake verify` shows that every number follows from
  the commands stored in the report, and that the incidents come from the pack the report names.
  It cannot show which program sent those commands: anyone can produce a consistent report by
  feeding the harness the commands they choose. Trust a result as much as you trust whoever ran
  it; for a decision, run the defender yourself on a fresh pack. The report hash is a plain
  checksum, not a signature: it covers the scores, the commands and the tool-mode checks
  (conformance, the contamination warning, an early stop), so an edit that does not recompute it
  is caught, and one that does is caught only where verify re-derives the field.
- **What skipping an approval costs is a design choice.** A critical action taken without the
  required approval is carried out, and the damage index adds the cost of a change-control review
  (`W_UNAPPROVED`, the cost of a 30-minute outage of a criticality-5 system). Skipping is never
  cheaper than asking, but on the two families where the best response needs an approval it costs
  only 2.6 and 4.0 index points: read the index together with approval compliance.
- **What the ranking of the shipped programs rests on.** Their order by damage index held when
  each weight (`W_HOLD`, `W_DOWN`, `W_ISOLATE`, `W_EXPOSURE`, `W_REACH`, the payroll multiplier,
  the records weight) was halved or raised by half, one at a time (`python scripts/sensitivity.py`).
  It was not tested with several weights changed together. The payroll multiplier moved no
  shipped program at all, so its effect is untested. Programs within a few points of one another
  (isolate-on-first-alert, isolate-everything and rule-bot are within 3) are not ordered by this
  check; their intervals overlap.
- **Difficulty is not shown to be harder.** The three tiers change the amount of benign noise, the
  attacker's speed (which the index normalises away) and how subtle planted text is. The shipped
  scripted programs score almost the same on all three; whether text-reading defenders find the
  higher tiers harder has not been measured.
- **The page does not do everything.** `flagwake ui` covers models on this computer, models
  online, local HTTP services and the company choice (and, when started with `--allow-commands`,
  programs and tools-mode programs); extra request fields,
  custom caps, repeats and replays need the command line ([TRY_YOUR_AGENT.md](TRY_YOUR_AGENT.md)).
  Its time estimates come from five short test incidents and are rough.
- **Conformance is about the protocol, not about quality.** Passing the seven checks means the
  harness can score a defender fairly; it says nothing about how good it is.
- **The oracle is near-optimal, not optimal.** It is built from the ground truth with simple
  rules. Under a company file it is the cheapest of up to four such command lists, it never acts
  without approval, and no shipped program does better than it on any family (tested); a defender
  with a cleverer order could still beat it. Under the original rules it is one fixed list, and
  the `thorough` reference program does slightly better on `cred-reuse` (up to 3 index points).
  Per-incident indices below 0 are kept as they are in the headline mean, which caps only above.
- **The original rules keep their first-published measures.** Under the original rules
  (`--world legacy`) the containment rate counts every host the ground truth lists, so a
  response that stops the intruder before it reaches a host counts that host as missed, and an
  incident where doing nothing costs no more than the oracle is never worse than doing nothing.
  They are kept so that earlier reports still verify; the default company files use the
  corrected measures (docs/SCORING.md).
- **A restore takes two simulated hours** and evicts the intruder for good only once its credential
  is reset and any flaw patched; real rebuilds vary widely.
- **`flagwake doctor` is a smoke test.** Three practice incidents; passing it means an agent or
  endpoint works with the harness, not that it is good.
- **Self-reported cost fields.** Tokens and seconds an adapter reports are not verified and are
  labelled self-reported.
- **One difficulty per pack entry.** Each (family, seed) is assigned one difficulty; a single run
  does not sweep all three for the same incident.
- **Not a ranking.** The tool prints no ranking table of models and no single headline score without its
  breakdown and intervals.

- **Company files describe structure, not behaviour.** Your zones, hosts, accounts, flows, policy,
  log sources and calendar change what an incident looks like and costs; the incident families,
  the intruder's script and the meaning of each family stay ours. A family your company cannot
  host is skipped, so two companies' runs cover different incidents and their indices are not
  comparable. Custom costs make results incomparable with the default pack (every output says so).
- **The flow, pause, integrity and notification numbers are invented.** Outflow rates, pause costs,
  the backup-integrity weight and the list of roles each family should notify are design choices;
  the four decision measures inherit them. Notification appropriateness judges the role, not the
  message's quality; a leak is detected only as an internal host, service or account name sent to
  an outside contact.
- **Groundedness is about what was shown, not what is true.** A claim the defender was shown an
  alert for counts as supported even when the alert was harmless; calibration covers truth.
- **Tiers change the stakes more than the normalised score.** On the calibration run harder tiers
  raised the do-nothing damage and the share of wrong handover notes, but the careful program's
  damage index stayed flat (44, 40, 43), because the index divides by the do-nothing damage.
- **Mode B is a mock platform.** Its tool names and schemas are neutral and generic; a defender
  built for a specific product may need a thin mapping to them, which is then part of what is
  tested. Its responses are JSON built from the same world as the text protocol; the two modes
  give identical scores for the same decisions (tested), not identical experiences.
- **No expert has judged these scores yet.** docs/VALIDITY.md says what evidence exists; the two
  kits for expert judgement are prepared but unanswered.

Every rule changed after seeing data is listed, with both readings, under "Changes made after
seeing data" in [METHODOLOGY.md](METHODOLOGY.md).
