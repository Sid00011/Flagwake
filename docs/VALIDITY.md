# What the scores mean, and what evidence supports them

Every number in a Responder Check report is a design choice: a fictional company, a scripted
intruder, and weights that turn outages, intrusion and exposure into one damage index. This page
says, for each measure, what it claims, what evidence supports the claim today, what does not, and
what would change our mind. It separates four kinds of validity:

- **internal validity**: the measure computes what its definition says, deterministically, and
  cannot be gamed by trivial strategies. **Done** (checks listed below; commands in
  docs/METHODOLOGY.md).
- **face validity**: people who handle incidents for a living agree the scores rank responses
  sensibly. **Not done.** The two kits described below are prepared but no expert has answered yet.
- **known-groups validity**: defenders that should be better score better. **Partly done**: the
  scripted reference programs separate as predicted in advance (the calibration gate), and three
  small local models scored between the reference programs and doing nothing. These groups were
  built by the same people who built the check, so this is weak evidence.
- **external validity**: a defender's score here relates to how it would do in real incidents.
  **Not claimed.** Nothing in this project measures that.

**Current evidence level, in one sentence:** the scores are internally consistent and separate
scripted defenders as designed, but they have not yet been compared with expert judgement or with
real incidents, so read them as a structured, re-checkable test of decisions in one fictional
setting, not as a measure of real-world security performance.

## The damage index

- **Claims:** how much business damage a response caused on the incident, between the oracle's
  list (0) and doing nothing (100), using the weights in docs/SCORING.md.
- **Supported by:** the oracle scores 0 and doing nothing 100 by construction; four null
  agents (do nothing, empty report, all-clear, random valid commands) never score below 100 on the
  held-out pack; the oracle is never worse than doing nothing on any incident; the same commands
  always give the same number (retest); the order of the two best reference programs does not
  change when any one weight is halved or doubled.
- **Not supported:** that the weights match what a real business would pay. Programs within a few
  points of each other (the middle of the reference table) change places under some weight
  changes, so small differences are not meaningful. A company can set its own weights (the
  `cost:` section of a company file); its results are then marked as not comparable.
- **Would change our mind:** expert answers to the weight survey that disagree with the ordering
  the weights imply on more than a few questions, or a fitted weight set under which the reference
  programs reorder.

## Containment, false containment, evidence before action, approval compliance

- **Claims:** counts of what the defender did to hosts and accounts the intruder held or did not
  hold, whether it looked before acting, and whether it asked when the policy says to ask.
- **Supported by:** these are counts over a ledger the interpreter keeps; `flagwake verify`
  re-derives every one from the commands; the fixtures built to fail them (paranoid, gullible,
  slow) fail them.
- **Not supported:** that "looked before acting" means the look was the reason. A defender that
  reads logs of every host and then acts at random still scores well on evidence before action;
  the damage index and false containment catch that case, this measure alone does not.

## Planted orders obeyed

- **Claims:** how often the defender carried out an instruction written into a log line, a
  ticket or a message, at three tiers of plausibility, without independent evidence for it.
- **Supported by:** the gullible fixture obeys most of what it reads and careful obeys none; the
  planted text never names the true target (so following the evidence never looks like obeying).
- **Not supported:** coverage of real manipulation. The sentences are a small fixed set.

## How much a keyword shortcut can do

A reader could try to find compromised hosts by matching words rather than by reading the
situation. Two different shortcuts, handled differently:

- **Memorising a fixed string per event.** Each attacker line now appears in several wordings,
  drawn per incident from its paraphrases (`text2.VARIANTS`, chosen by `pick`), so the same event
  reads one way in one incident and another in the next. Measured on both shipped companies
  (held-out): the number of distinct attacker-line wordings rose about 37% (173→241 on the 18-host
  company, 177→238 on the 60-host one), so a model cannot map one exact string to "compromised".
  The paraphrases keep the same facts, slots and indicator words, so a reasoning defender and the
  scripted baselines are unaffected (the calibration is unchanged); a validator (`check_tables`)
  enforces that.
- **Matching indicator words.** A word-matching rule is still right about 93% of the time when it
  fires, but catches only about 37% of attacker lines (measured, unchanged by the paraphrases — on
  purpose). This is kept: a line with an indicator word and no benign-context word usually is an
  attack, which is realistic, and removing the indicators would break genuine analysis and the
  scripted references. The remaining 63% — the benign decoys, the quiet incidents, the revised
  handover note, the signals split across log sources — still need the situation read, not a word.

The escalation oracle that used to let a defender check the ground truth for free is closed on
company files (see "Approval compliance" and METHODOLOGY).

## The four decision measures (rules 2)

- **Outflow prevented versus pause cost:** value a do-nothing run loses to an intruder or a failed
  supplier through a business flow, minus what this run lost, next to what pausing cost.
  Supported: a run that pauses at once prevents nearly all of it at a small cost; the numbers add
  up to the damage terms. Not supported: the per-minute rates are invented.
- **Anchoring rate:** the share of incidents with a revised early assessment where the final report
  still names the superseded host or misses the revised one. Supported: a fixture that believes
  the handover note keeps the superseded host in every such incident; careful in none. Not
  supported: anything about
  how often real handovers are wrong.
- **Unsupported claims:** the share of hosts and accounts in the report that no alert or indicator
  line ever showed the defender. Supported: computed from what the defender was actually shown.
  Not supported: that a supported claim is a correct one (calibration covers that).
- **Notification appropriateness:** required roles reached, notifications to roles the incident did
  not call for, repeats, and internal details sent to outside contacts. Supported: careful reaches
  most required roles and never leaks; programs that never notify reach none. Not supported: the
  list of required roles is our judgement per family; experts may disagree.

## Difficulty tiers

What each tier changes was fixed in advance (docs/SCENARIOS.md). Checked: harder tiers raise the
damage of doing nothing on the flow families, make a wrong early assessment more frequent, and the
rule bot does no better on harder floods of alerts. Not confirmed: the careful program's
normalised index does not rise with the tier, because the index divides by the do-nothing damage,
which rises too. Tiers change the raw stakes more than the normalised score.

## The two kits for expert judgement (prepared, not yet sent)

1. **Weight survey.** Twelve plain-language pairwise questions, each testing one ratio of the
   weights ("Which is worse: the payroll database offline for 60 minutes, or an intruder holding a
   finance laptop for 4 hours?"). An analysis script checks each answer against the ordering the
   weights imply, fits an alternative weight set to the answers (a Bradley-Terry style logistic
   model on log costs), and reports how often the reference programs reorder under the fitted
   weights. The default weights stay unless the answers support a change; any change would be
   listed in docs/METHODOLOGY.md under "Changes made after seeing data".
2. **Blind transcript ranking.** Twenty pairs of transcripts of the same incident handled by two
   different defenders, with names removed and the score hidden. Experts say which defender
   handled it better and why; a script computes the pairwise agreement between their choices and
   the damage index, with a 95% interval. This is the face-validity test.

Until those answers exist, this page's "not done" stays.
