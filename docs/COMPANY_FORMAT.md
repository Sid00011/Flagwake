# The company file

A company file describes the organisation incidents happen in: its zones, hosts, people,
accounts, partner and supplier links, hosted services, business flows, approval policy, log
sources and business calendar. The check ships two (an 18-host logistics firm, the default, and a
60-host retailer with depots, an identity layer, a cloud account, a CI host, a payments service,
a hosted support desk and two suppliers); you can write your own.

```bash
flagwake world init                       # writes company.yaml, a commented template that validates
flagwake world validate company.yaml      # every problem as a plain sentence; exit 1 if any
flagwake world show company.yaml          # what it contains and which incident families can run
flagwake check --agent baseline:careful --world company.yaml --pack practice --seeds 1
flagwake verify check-out/report.json --world company.yaml
```

The file is JSON or the strict YAML subset of `flagwake.yaml` (block maps and lists, scalars,
`[a, b]` lists of plain words, JSON for anything else). Unknown fields are rejected. Nothing in it is
run or sent anywhere: every field is data, text fields are capped and stripped of control
characters, and every renderer escapes them. Addresses must come from the ranges reserved for
documentation (192.0.2.x, 198.51.100.x, 203.0.113.x) so nothing in the file routes anywhere; use
invented names if you describe a real organisation.

A report made on a company file records its digest (SHA-256 of the normalised file) in the hashed
part of the report and says "custom company" in its header; `verify` needs the same file. Change
`version` whenever you change the file.

## Top level

| field | required | meaning |
|---|---|---|
| `schema` | yes | `flagwake-company-1` |
| `name`, `version` | yes | short ids (lowercase letters, digits, `.`, `_`, `-`) |
| `company` | yes | `name`, optional `short`, `about`, `fictional` (true or false) |
| `shift` | no | `start`: the clock time (HH:MM) the 480-minute incident window starts (default 02:10) |
| `zones` | yes | list of `id`, `label` |
| `hosts` | yes | see below (at most 200) |
| `people` | yes | see below (at most 400) |
| `accounts` | no | service and admin accounts; people's own accounts are the standard ones |
| `links`, `services`, `flows`, `roles` | no | see below |
| `approval`, `logs`, `calendar`, `cost` | no | see below; defaults apply when absent |

## Hosts

`id`, `role`, `label`, `zone`, `criticality` (1 = minor, 5 = the business stops without it) are
required; `team`, `custodian` (a person's account), `users` (accounts that sign in there), `about`,
`tags`, `records` (0-5: how much customer or payroll data it holds; a data store) are optional.
Roles: workstation, server, web, mail (the ticket gateway), remote-access, identity, database,
backup, files, print, monitoring, app, ci, payments. Tags the families look for: `developer` (a
developer workstation), `remote`, `public`.

## People and accounts

People: `account`, `name`, `title`, `team`; optional `manager`, `exec` (true for executives),
`admin` (their separate admin account), `tags` (`helpdesk` marks help-desk staff). Accounts:
`type: service` with `purpose`, `host` it runs on, optional `contact` and `reaches` (hosts or
services it can sign in to); or `type: admin` with the `person` it belongs to.

## Links, hosted services, flows, roles

- `links`: partners, suppliers and providers. `id`, `kind` (partner, supplier, provider), `label`,
  `address` (documentation range), `host` (where the link lands), optional `flows` it carries and
  `contact_role`. Blocking a link's address cuts it for an hour (an outage on its host).
- `services`: hosted (SaaS or cloud) services. `id`, `kind` (saas, cloud), `label`,
  `criticality`; optional `team`, `users`, `about`. They are reached through the `cloud` log source.
- `flows`: business flows. `id`, `kind` (orders, payroll, payments, support, tracking, other),
  `label`, `value_per_minute` (0-1000), `hosts` (hosts or services that carry it); optional
  `pausable` (it has a manual fallback), `pause_cost_per_minute` (default: its value per minute),
  `contact_role`, `link`, `store` (its data store). A compromised or failing flow loses value every
  minute it is not paused; pausing stops that and costs the pause cost per minute.
- `roles`: who `notify <role>` reaches. Each role names an employee (`person`) or an outside
  contact (`name`, `external: true`), with an optional `title`. Names the families use when present:
  security-lead, it-lead, duty-manager, legal, hr, helpdesk, finance-lead, payments-lead, ops-lead,
  sales-lead, support-lead.

## Approval policy

`decider` (a role), `delay` (minutes until the answer, default 15), `expiry` (an unanswered request is
denied after this, default 30), `valid` (minutes a grant stays usable, default 60) and `rules`, a
list in which each rule has `actions` (from isolate, restore, block, reset, patch, pause, resume)
and exactly one of `criticality_at_least` (hosts and services), `account_types` (service, admin,
executive, standard) or `flows` (a list of flow ids, or `all`). The default policy is the original
one: isolate or restore of criticality 4-5, block or reset of admin accounts.

## Log sources

A list of `source` (endpoint, identity, network, cloud), `zones` (`all` or a list of zone ids; the
`cloud` zone is the hosted services), `delay` (minutes before a line is visible) and `gaps` (clock
spans HH:MM-HH:MM when the source collected nothing). The endpoint source is required. `logs
<host>` shows every source's lines about that host; `logs <source>` shows one source across hosts.

## Calendar

`windows`: `id`, `label`, `start` (HH:MM), `minutes`, `days` (Mon-Sun), optional `flow` and
`multiplier` (1-5): downtime of that flow's hosts and exposure of its store count that many times
during the window (the payroll batch is 3 in the shipped companies).

## Costs

Weights stay in the check by default and are recorded in every report. A `cost:` section sets a
company's own: `weights` (any of hold, down, isolate, exposure, reach, unapproved, outflow, pause,
integrity; whole numbers) and `flows` (a flow id to its value per minute while paused). Every output
of a run with custom costs says "custom costs, not comparable with the default pack".

## What families need

`flagwake world show` prints, for your file, which of the 20 families can run and why the others
are skipped (for example "no pausable payments flow", "no supplier link carrying a pausable flow",
"no hosted service with at least two users", "no cloud log source"). Add what is missing, or accept
that those incidents are not part of your run; skipped families are listed in the report.
