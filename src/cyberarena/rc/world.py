"""The company an incident happens in.

Two kinds of world exist. The legacy world ``data/world.json`` (version hp-2, the invented
logistics firm in the original file format) is the only world of rules 1, which stay exactly as
first published. Every other world is a company file (``company.py``; the shipped ones are in
``data/worlds/``) and runs under rules 2. Everything shipped is fictional: the company, its hosts,
people, accounts and addresses (the addresses come from the ranges reserved for documentation, so
they route nowhere). A world is fixed per ``version`` and file digest; incidents change only what
happens in it.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

from cyberarena.rc import company as companylib

DATA = Path(__file__).resolve().parent / "data"
WORLDS_DIR = DATA / "worlds"
SHIPPED = ("harlow-pine", "fenwick-brae")
DEFAULT_NAME = "harlow-pine"

# What people say when an incident has nothing particular for them on a topic.
DEFAULT_ANSWERS = {
    "travelling": "No, I'm at home tonight.",
    "opened-file": "No, I haven't opened anything unusual.",
    "signed-in": "No, I haven't signed in since the end of my shift.",
    "approved": "No, I haven't approved anything tonight.",
    "changed": "No, I haven't changed anything.",
    "expecting": "No, I'm not expecting anything unusual tonight.",
    "called": "No, I haven't called the help desk tonight.",
}

# The roles of the legacy hosts (the old file has no such field; rules 1 read them from here).
LEGACY_KINDS = {
    "web-01": "web", "vpn-01": "remote-access", "mail-01": "mail", "hr-portal": "app",
    "files-01": "files", "print-01": "print", "dc-01": "identity", "db-01": "database",
    "db-02": "database", "backup-01": "backup", "monitor-01": "monitoring",
}  # fmt: skip
LEGACY_RECORDS = {"db-01": 3, "db-02": 3}


class World:
    """Read-only view of a company: hosts, people, accounts, links, flows and policies."""

    def __init__(self, doc: dict[str, Any], rules: int = 1, source: str = "") -> None:
        self.doc = doc
        self.rules = rules
        self.source = source or doc.get("name", "")
        self.version: str = doc["version"]
        self.digest = companylib.digest(doc)
        if rules == 1:
            self._legacy(doc)
        else:
            self._company(doc)
        self.host_names: list[str] = [h["name"] for h in self.hosts]
        self.host: dict[str, dict[str, Any]] = {h["name"]: h for h in self.hosts}
        self.accounts: list[str] = sorted({*self.people, *self.services, *self.admins})
        self.execs: list[str] = sorted(a for a, p in self.people.items() if p["exec"])
        usual: dict[str, list[str]] = {}
        for h in self.hosts:
            for u in h["users"]:
                usual.setdefault(u, []).append(h["name"])
        self.usual_hosts = usual
        kinds = [(h["name"], h["kind"]) for h in self.hosts]
        self.gateways = [n for n, k in kinds if k == "remote-access"]
        self.gateway: str | None = self.gateways[0] if self.gateways else None
        self.monitors = [n for n, k in kinds if k == "monitoring"]
        self.tickets = [n for n, k in kinds if k == "mail"]
        self.stores: dict[str, int] = {h["name"]: h["records"] for h in self.hosts if h["records"]}

    # Two views of the same file are the same world (caches key on this).
    def __hash__(self) -> int:
        return hash((self.rules, self.digest))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, World) and (self.rules, self.digest) == (other.rules, other.digest)

    # ----------------------------------------------------------------------------- loading
    def _legacy(self, doc: dict[str, Any]) -> None:
        self.name = "hp-legacy"
        self.company: dict[str, Any] = doc["company"]
        self.custom = False
        self.shift_start = 130
        self.hosts: list[dict[str, Any]] = [
            {
                **h,
                "kind": LEGACY_KINDS.get(h["name"], "workstation"),
                "tags": [],
                "records": LEGACY_RECORDS.get(h["name"], 0),
            }
            for h in doc["hosts"]
        ]
        self.zones = doc["zones"]
        self.people: dict[str, dict[str, Any]] = {p["account"]: p for p in doc["people"]}
        self.services: dict[str, dict[str, Any]] = {
            s["account"]: {**s, "reaches": []} for s in doc["service_accounts"]
        }
        self.admins: dict[str, dict[str, Any]] = {a["account"]: a for a in doc["admin_accounts"]}
        self.partners: dict[str, dict[str, Any]] = {e["ip"]: e for e in doc["external"]}
        self.links: dict[str, dict[str, Any]] = {}
        self.cloud: dict[str, dict[str, Any]] = {}
        self.flows: dict[str, dict[str, Any]] = {}
        self.roles: dict[str, dict[str, Any]] = {}
        self.approval: dict[str, Any] = companylib.DEFAULT_APPROVAL
        self.log_sources: list[dict[str, Any]] = companylib.DEFAULT_LOGS
        self.windows: list[dict[str, Any]] = []
        self.cost: dict[str, Any] | None = None

    def _company(self, doc: dict[str, Any]) -> None:
        self.name = doc["name"]
        self.company = doc["company"]
        self.custom = self.source not in SHIPPED
        self.shift_start = doc["shift"]["start"]
        self.zones = doc["zones"]
        self.hosts = [
            {
                "name": h["id"],
                "zone": h["zone"],
                "role": h["label"],
                "kind": h["role"],
                "crit": h["criticality"],
                "dept": h["team"],
                "custodian": h["custodian"],
                "users": list(h["users"]),
                "profile": h["about"],
                "tags": list(h["tags"]),
                "records": h["records"],
            }
            for h in doc["hosts"]
        ]
        self.people = {
            p["account"]: {
                "account": p["account"],
                "name": p["name"],
                "role": p["title"],
                "dept": p["team"],
                "manager": p["manager"],
                "exec": p["exec"],
                "tags": list(p["tags"]),
                **({"admin": p["admin"]} if p["admin"] else {}),
            }
            for p in doc["people"]
        }
        self.services = {
            a["account"]: {
                "account": a["account"],
                "purpose": a["purpose"],
                "host": a["host"],
                "contact": a["contact"] or (self._custodian(a["host"], doc)),
                "reaches": list(a["reaches"]),
            }
            for a in doc["accounts"]
            if a["type"] == "service"
        }
        self.admins = {
            a["account"]: {"account": a["account"], "person": a["person"]}
            for a in doc["accounts"]
            if a["type"] == "admin"
        }
        self.links = {ln["id"]: dict(ln) for ln in doc["links"]}
        self.partners = {
            ln["address"]: {"ip": ln["address"], "label": f"{ln['label']} ({ln['kind']})", **ln}
            for ln in doc["links"]
        }
        self.cloud = {s["id"]: dict(s) for s in doc["services"]}
        self.flows = {f["id"]: dict(f) for f in doc["flows"]}
        self.roles = dict(doc["roles"])
        self.approval = doc["approval"]
        self.log_sources = doc["logs"]
        self.windows = doc["calendar"]["windows"]
        self.cost = doc["cost"]

    @staticmethod
    def _custodian(host: str, doc: dict[str, Any]) -> str | None:
        for h in doc["hosts"]:
            if h["id"] == host:
                return h["custodian"]
        return None

    # ----------------------------------------------------------------------------- queries
    def crit(self, host: str) -> int:
        """Criticality 1-5 of a host (or of a hosted service)."""
        if host in self.host:
            return int(self.host[host]["crit"])
        return int(self.cloud[host]["criticality"])

    def zone(self, host: str) -> str:
        """The zone id of a host ("cloud" for a hosted service)."""
        if host in self.host:
            return str(self.host[host]["zone"])
        return "cloud"

    def default_answer(self, person: str, topic: str) -> str:
        """The answer of a person with nothing particular to say on ``topic``."""
        return DEFAULT_ANSWERS[topic]

    def dept_people(self, dept: str) -> list[str]:
        """Accounts of the people of a department, sorted."""
        return sorted(a for a, p in self.people.items() if p["dept"] == dept)

    def by_kind(self, kind: str) -> list[str]:
        """Host names of one role, in file order."""
        return [h["name"] for h in self.hosts if h["kind"] == kind]

    def role_holder(self, role: str) -> dict[str, Any] | None:
        """Who a notify role reaches: {name, title, external, person}; None when undefined."""
        r = self.roles.get(role)
        if r is None:
            return None
        if r.get("person"):
            p = self.people[r["person"]]
            return {"name": p["name"], "title": r.get("title") or p["role"], "external": False,
                    "person": r["person"]}  # fmt: skip
        return {"name": r["name"], "title": r.get("title") or "contact", "external": True,
                "person": None}  # fmt: skip

    def summary(self) -> dict[str, Any]:
        """What a report header records about the world (the digest pins the exact file)."""
        return {
            "name": self.name,
            "version": self.version,
            "digest": self.digest,
            "custom": self.custom,
            "custom_costs": bool(self.cost),
            "hosts": len(self.hosts),
        }


@cache
def load_world(name: str = "world.json") -> World:
    """The legacy world of rules 1 (cached)."""
    return World(json.loads((DATA / name).read_text(encoding="utf-8")), rules=1)


@cache
def shipped_world(name: str = DEFAULT_NAME) -> World:
    """A world shipped with the package (data/worlds/<name>.json), cached."""
    if name not in SHIPPED:
        raise ValueError(f"unknown shipped world {name!r} ({', '.join(SHIPPED)})")
    doc = companylib.validate_company(
        json.loads((WORLDS_DIR / f"{name}.json").read_text(encoding="utf-8"))
    )
    return World(doc, rules=2, source=name)


def world_from_file(path: str | Path) -> World:
    """A world from a company file the user wrote (validated; marked custom in reports)."""
    doc = companylib.load_company(path)
    return World(doc, rules=2, source=str(path))


def resolve_world(arg: str | None) -> World:
    """``--world`` value: None or a shipped name gives a shipped world, otherwise a file path."""
    if arg is None or arg == "":
        return shipped_world(DEFAULT_NAME)
    if arg in SHIPPED:
        return shipped_world(arg)
    if arg in ("legacy", "hp-2"):
        return WORLD
    return world_from_file(arg)


WORLD = load_world()
