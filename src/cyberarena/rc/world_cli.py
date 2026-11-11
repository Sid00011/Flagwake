"""``flagwake world``: write a company-file template, validate a company file, show a world.

The template is a small invented company that uses every section of the format, with a comment
on each; it validates as written. ``validate`` prints every problem as a plain sentence and exits
1; ``show`` prints what a world contains and which incident families can run in it.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from cyberarena.rc.company import CompanyError

TEMPLATE = """\
# A company file for the Flagwake Responder Check (format: docs/COMPANY_FORMAT.md).
# Describe your own organisation, or keep this invented one. Strict subset of YAML: unknown
# fields are rejected. Nothing in this file is sent anywhere or run; it is data.
schema: flagwake-company-1
name: my-company            # short id: lowercase letters, digits, '.', '_' or '-'
version: v1                 # change it whenever you change the file
company:
  name: Example Freight Ltd
  short: Example Freight
  about: An invented small freight firm with one office and one depot.
  fictional: true           # false for a description of a real organisation
shift:
  start: "02:00"            # the 480-minute incident window starts at this clock time
zones:
  - id: edge
    label: Internet-facing
  - id: office
    label: Office and depot computers
  - id: core
    label: Core systems
  - id: cloud
    label: Hosted services
hosts:                      # role: workstation, server, web, mail, remote-access, identity,
                            # database, backup, files, print, monitoring, app, ci, payments
  - id: web-1
    role: web
    label: public booking site
    zone: edge
    criticality: 3          # 1 (minor) to 5 (the business stops without it)
    team: Sales
    custodian: a.lee
    users: [svc-web]
    tags: [public]
  - id: gw-1
    role: remote-access
    label: remote-access gateway
    zone: edge
    criticality: 4
    team: IT
    custodian: b.khan
  - id: mail-1
    role: mail
    label: mail and ticket gateway
    zone: edge
    criticality: 3
    team: IT
    custodian: b.khan
  - id: pc-1
    role: workstation
    label: dispatch desktop
    zone: office
    criticality: 1
    team: Operations
    custodian: c.ortiz
    users: [c.ortiz, d.wu]
    tags: []
  - id: pc-2
    role: workstation
    label: developer laptop
    zone: office
    criticality: 2
    team: IT
    custodian: e.berg
    users: [e.berg]
    tags: [developer]
  - id: pc-3
    role: workstation
    label: service desk laptop
    zone: office
    criticality: 2
    team: IT
    custodian: f.amadi
    users: [f.amadi]
  - id: files-1
    role: files
    label: shared drives
    zone: core
    criticality: 3
    team: IT
    custodian: b.khan
    users: [svc-backup]
  - id: dir-1
    role: identity
    label: directory server
    zone: core
    criticality: 5
    team: IT
    custodian: b.khan
    users: [adm-khan]
  - id: db-1
    role: database
    label: customer database
    zone: core
    criticality: 5
    team: Sales
    custodian: a.lee
    users: [svc-web, svc-backup]
    records: 3              # 0-5: how much it matters if its records leak
  - id: pay-1
    role: payments
    label: payments service
    zone: core
    criticality: 5
    team: Finance
    custodian: g.novak
    users: [svc-pay]
  - id: backup-1
    role: backup
    label: backup server
    zone: core
    criticality: 4
    team: IT
    custodian: b.khan
    users: [svc-backup]
  - id: mon-1
    role: monitoring
    label: security monitoring (the alert source)
    zone: core
    criticality: 4
    team: IT
    custodian: b.khan
people:
  - account: h.stone
    name: Hal Stone
    title: managing director
    team: Executive
    exec: true
  - account: a.lee
    name: Ana Lee
    title: sales lead
    team: Sales
    manager: h.stone
  - account: b.khan
    name: Bilal Khan
    title: IT manager
    team: IT
    manager: h.stone
    admin: adm-khan
  - account: c.ortiz
    name: Cara Ortiz
    title: dispatcher
    team: Operations
    manager: h.stone
    tags: [remote]
  - account: d.wu
    name: Dan Wu
    title: night dispatcher
    team: Operations
    manager: c.ortiz
    tags: [remote]
  - account: e.berg
    name: Eva Berg
    title: developer
    team: IT
    manager: b.khan
    tags: [developer]
  - account: f.amadi
    name: Femi Amadi
    title: service desk
    team: IT
    manager: b.khan
    tags: [helpdesk]
  - account: g.novak
    name: Gina Novak
    title: finance lead
    team: Finance
    manager: h.stone
  - account: j.ruiz
    name: Jo Ruiz
    title: legal counsel
    team: Executive
    manager: h.stone
accounts:                   # service and admin accounts; people are standard accounts
  - account: svc-web
    type: service
    purpose: booking site access to the customer database
    host: web-1
    contact: a.lee
    reaches: [db-1]
  - account: svc-backup
    type: service
    purpose: nightly backups
    host: backup-1
    contact: b.khan
    reaches: [db-1, files-1]
  - account: svc-pay
    type: service
    purpose: authorises payment submissions
    host: pay-1
    contact: g.novak
    reaches: [pay-1]
  - account: adm-khan
    type: admin
    person: b.khan
links:                      # partners, suppliers and providers (documentation addresses only)
  - id: carrier
    kind: supplier
    label: freight carrier booking system
    address: 198.51.100.30
    host: web-1
    flows: [bookings]
    contact_role: carrier-desk
  - id: bank
    kind: partner
    label: bank payment gateway
    address: 203.0.113.30
    host: pay-1
    flows: [payments]
services:                   # hosted (SaaS) services staff sign in to
  - id: help-saas
    kind: saas
    label: hosted support desk
    criticality: 2
    team: Sales
    users: [a.lee, c.ortiz]
flows:                      # business flows; value_per_minute is in damage points
  - id: bookings
    kind: orders
    label: customer bookings
    value_per_minute: 4
    hosts: [web-1, db-1]
    pausable: true
    pause_cost_per_minute: 2   # less than the value when a manual fallback exists
    link: carrier
    contact_role: sales-lead
    store: db-1
  - id: payments
    kind: payments
    label: supplier payments
    value_per_minute: 3
    hosts: [pay-1]
    pausable: true
    link: bank
    contact_role: finance-lead
roles:                      # who the defender can notify; external roles are outside contacts
  security-lead: {"person": "b.khan"}
  duty-manager: {"person": "h.stone", "title": "duty manager tonight"}
  legal: {"person": "j.ruiz"}
  sales-lead: {"person": "a.lee"}
  finance-lead: {"person": "g.novak"}
  helpdesk: {"person": "f.amadi"}
  carrier-desk: {"name": "Carrier operations desk", "title": "supplier contact", "external": true}
approval:                   # which actions need approval, who decides and how fast
  decider: duty-manager
  delay: 15                 # minutes until the answer
  expiry: 30                # an unanswered request is denied after this
  valid: 60                 # a grant can be used for this long
  rules:
    - actions: [isolate, restore]
      criticality_at_least: 4
    - actions: [block, reset]
      account_types: [admin]
    - actions: [pause]
      flows: [payments]
logs:                       # what each log source covers, its delay and its gaps
  - source: endpoint
    zones: all
    delay: 0
  - source: identity
    zones: all
    delay: 2
  - source: network
    zones: [edge, core]
    delay: 5
    gaps: ["03:00-03:15"]
  - source: cloud
    zones: [cloud]
    delay: 10
calendar:
  windows:
    - id: month-end
      label: month-end payment run
      start: "05:00"
      minutes: 30
      days: [Fri]
      flow: payments
      multiplier: 2
# cost:                     # optional: your own weights; results are then not comparable
#   weights: {"hold": 2, "down": 2, "isolate": 1, "exposure": 300}
#   flows: {"bookings": 6}
"""


def add_subparsers(sub: argparse._SubParsersAction) -> None:
    w = sub.add_parser("world", help="write, check or show a company file (the world)")
    wsub = w.add_subparsers(dest="world_command")
    i = wsub.add_parser("init", help="write a commented company-file template")
    i.add_argument("path", nargs="?", default="company.yaml")
    i.add_argument("--force", action="store_true", help="overwrite an existing file")
    v = wsub.add_parser("validate", help="check a company file and list every problem")
    v.add_argument("path")
    s = wsub.add_parser("show", help="show a world: a shipped name or a company file")
    s.add_argument("world", nargs="?", default=None, help="harlow-pine, fenwick-brae or a file")


def cmd_world(args: argparse.Namespace) -> int:
    which = getattr(args, "world_command", None)
    if which == "init":
        path = Path(args.path)
        if path.exists() and not args.force:
            print(f"{path} already exists; use --force to overwrite it")
            return 1
        path.write_text(TEMPLATE, encoding="utf-8", newline="\n")
        print(f"wrote {path}: edit it, then run flagwake world validate {path}")
        return 0
    if which == "validate":
        from cyberarena.rc.world import world_from_file

        try:
            w = world_from_file(args.path)
        except CompanyError as exc:
            print(f"{args.path}: {len(exc.problems)} problem(s)")
            for p in exc.problems:
                print(f"  - {p}")
            return 1
        print(f"OK {args.path}: {w.name} {w.version}, {len(w.hosts)} hosts, digest {w.digest}")
        return 0
    if which == "show":
        from cyberarena.rc.world import resolve_world

        try:
            w = resolve_world(args.world)
        except CompanyError as exc:
            lines = ["the company file is not valid:", *[f"  - {p}" for p in exc.problems]]
            print("\n".join(lines))
            return 1
        except ValueError as exc:
            print(str(exc))
            return 1
        print(show_text(w))
        return 0
    print("usage: flagwake world {init,validate,show}")
    return 2


def show_text(w) -> str:  # noqa: ANN001 - a World
    """A plain listing of a world, ending with the incident families it can run."""
    lines = [
        f"{w.company['name']} ({w.name} {w.version}; digest {w.digest[:16]})"
        + ("  [custom world]" if w.custom else ""),
        f"rules {w.rules}; {len(w.hosts)} hosts, {len(w.people)} people, "
        f"{len(w.services)} service and {len(w.admins)} admin accounts",
    ]
    for z in w.zones:
        names = [h["name"] for h in w.hosts if h["zone"] == z["id"]]
        if names:
            lines.append(f"  {z['id']:<10} {', '.join(names)}")
    if w.cloud:
        lines.append("Hosted services: " + ", ".join(sorted(w.cloud)))
    if w.flows:
        lines.append(
            "Flows: "
            + "; ".join(
                f"{f['id']} ({f['value_per_minute']}/min{', pausable' if f['pausable'] else ''})"
                for f in w.flows.values()
            )
        )
    if w.links:
        lines.append("Links: " + "; ".join(f"{k} ({v['kind']})" for k, v in w.links.items()))
    if w.roles:
        lines.append("Roles: " + ", ".join(sorted(w.roles)))
    lines.append(
        "Log sources: "
        + "; ".join(f"{s['source']} (delay {s['delay']} min)" for s in w.log_sources)
    )
    if w.cost:
        lines.append("Custom costs: results are not comparable with the default pack.")
    if w.rules >= 2:
        from cyberarena.rc.gen2 import binding_report

        ok, skipped = binding_report(w)
        lines.append(f"Families that can run here: {len(ok)} of {len(ok) + len(skipped)}")
        for fam, why in skipped:
            lines.append(f"  skipped {fam}: {why}")
    return "\n".join(lines)
