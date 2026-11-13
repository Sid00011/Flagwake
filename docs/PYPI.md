# Flagwake

A free, offline, re-checkable test of how an AI defender behaves during a security incident,
scored with business cost.

Your defender (a program, a model behind a chat-completions endpoint, or a product with its own
tools) works through simulated incidents in an invented company. Flagwake scores its decisions:
how long the intruder held machines, the downtime the defender caused, data exposed, money lost
through business flows, approvals respected, planted instructions obeyed. Every number can be
re-derived from the stored commands, and an edited report fails.

```bash
pip install flagwake
flagwake demo      # two example defenders, a verified report, an edited copy that fails
flagwake ui        # the local page: add a defender, check it, run it, read the result
```

Test your own defender:

```bash
flagwake init
flagwake defenders add --name mine --kind command --command "python my_defender.py"
flagwake defenders test mine
flagwake run --defender mine
flagwake verify flagwake-runs/mine/fresh/report.json
```

- **Offline and free.** No model or judge inside the check; nothing leaves your computer.
- **Fresh incidents for every run**, so a defender cannot have seen them before.
- **Re-checkable and signable.** `flagwake verify` re-derives every number; the GitHub Action signs
  a report so anyone can check which repository, commit and run produced it.
- **Your own company.** Describe your topology in a file and the incidents run in it.
- **Honest limits.** It is a simulation: a score describes behaviour in this test only.

Screenshots, the method, the scoring and the limits:
[github.com/Sid00011/Flagwake](https://github.com/Sid00011/Flagwake).

Code: AGPL-3.0-only (commercial licences on request). Docs and data: CC BY 4.0.
