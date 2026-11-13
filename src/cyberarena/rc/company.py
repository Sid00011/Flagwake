"""The company file: a strict, documented description of the organisation incidents happen in.

A company file (JSON, or the strict YAML subset of ``flagwake.yaml``) lists zones, hosts, people,
accounts, partner and supplier links, hosted services, business flows, the approval policy, the
log sources and the business calendar. ``load_company`` validates it and returns the normalised
document the :class:`~cyberarena.rc.world.World` is built from. Every problem is reported as a
plain sentence naming the entry and the field, and nothing in the file is ever run: every field is
data, text fields are length-capped and stripped of control characters, and the renderers escape
them. docs/COMPANY_FORMAT.md describes every field.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import unicodedata
from collections.abc import Collection
from pathlib import Path
from typing import Any

SCHEMA = "flagwake-company-1"
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,39}$")
ACCOUNT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,39}$")
CLOCK_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
SPAN_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)-([01]\d|2[0-3]):([0-5]\d)$")
TEXT_MAX = 200
ABOUT_MAX = 400
MAX_HOSTS = 200
MAX_PEOPLE = 400
MAX_ITEMS = 100
SHIFT_MINUTES = 480  # the incident window is fixed by the rules; only its start is configurable

HOST_ROLES = (
    "workstation", "server", "web", "mail", "remote-access", "identity", "database", "backup",
    "files", "print", "monitoring", "app", "ci", "payments",
)  # fmt: skip
LINK_KINDS = ("partner", "supplier", "provider")
SERVICE_KINDS = ("saas", "cloud")
FLOW_KINDS = ("orders", "payroll", "payments", "support", "tracking", "other")
LOG_SOURCES = ("identity", "endpoint", "network", "cloud")
ACCOUNT_TYPES = ("service", "admin")
APPROVAL_ACTIONS = ("isolate", "restore", "block", "reset", "patch", "pause", "resume")
DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
WEIGHT_KEYS = (
    "hold", "down", "isolate", "exposure", "reach", "unapproved", "outflow", "pause", "integrity",
)  # fmt: skip

TOP_FIELDS = {
    "required": ("schema", "name", "version", "company", "zones", "hosts", "people"),
    "optional": (
        "accounts", "links", "services", "flows", "approval", "logs", "calendar", "roles",
        "shift", "cost",
    ),
}  # fmt: skip


class CompanyError(ValueError):
    """The company file is not valid; ``problems`` lists every problem found, one per line."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("\n".join(problems))


class _Check:
    """Collects problems while walking the document."""

    def __init__(self) -> None:
        self.problems: list[str] = []

    def add(self, where: str, msg: str) -> None:
        if len(self.problems) < 60:
            self.problems.append(f"{where}: {msg}")

    def fields(self, obj: Any, where: str, required: tuple, optional: tuple) -> bool:
        if not isinstance(obj, dict):
            self.add(where, "must be a mapping of fields (key: value)")
            return False
        for k in required:
            if k not in obj:
                self.add(where, f"the field '{k}' is missing")
        for k in obj:
            if k not in required and k not in optional:
                allowed = ", ".join((*required, *optional))
                self.add(where, f"unknown field '{_safe(k)}' (allowed: {allowed})")
        return True

    def text(self, obj: dict, key: str, where: str, cap: int = TEXT_MAX, need: bool = True) -> str:
        v = obj.get(key)
        if v is None and not need:
            return ""
        if not isinstance(v, str) or not v.strip():
            self.add(where, f"'{key}' must be non-empty text")
            return ""
        if len(v) > cap:
            self.add(where, f"'{key}' is longer than {cap} characters")
        if any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") for c in v):
            self.add(where, f"'{key}' contains control or invisible characters")
        return v.strip()[:cap]

    def ident(self, obj: dict, key: str, where: str, pattern: re.Pattern = ID_RE) -> str:
        v = obj.get(key)
        if not isinstance(v, str) or not pattern.match(v):
            self.add(
                where,
                f"'{key}' must be 1-40 lowercase letters, digits, '.', '_' or '-' (got {_safe(v)})",
            )
            return ""
        return v

    def integer(self, obj: dict, key: str, where: str, lo: int, hi: int, default: int) -> int:
        v = obj.get(key, default)
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            self.add(where, f"'{key}' must be a whole number from {lo} to {hi} (got {_safe(v)})")
            return default
        return v

    def flag(self, obj: dict, key: str, where: str, default: bool = False) -> bool:
        v = obj.get(key, default)
        if not isinstance(v, bool):
            self.add(where, f"'{key}' must be true or false")
            return default
        return v

    def idlist(self, obj: dict, key: str, where: str, known: set[str] | None, what: str) -> list:
        v = obj.get(key, [])
        if not isinstance(v, list):
            self.add(where, f"'{key}' must be a list")
            return []
        out = []
        for x in v[:MAX_ITEMS]:
            if not isinstance(x, str) or not ID_RE.match(x):
                self.add(where, f"'{key}' has an entry that is not a valid id: {_safe(x)}")
            elif known is not None and x not in known:
                self.add(where, f"'{key}' names {_safe(x)}, which is not a known {what}")
            else:
                out.append(x)
        if len(v) > MAX_ITEMS:
            self.add(where, f"'{key}' has more than {MAX_ITEMS} entries")
        return out


def _safe(v: Any) -> str:
    """A short, printable rendering of a value for an error message (never the whole value)."""
    s = json.dumps(v, ensure_ascii=True) if not isinstance(v, str) else repr(v)
    return s if len(s) <= 50 else s[:47] + "..."


def clock_minutes(text: str) -> int:
    """Minutes past midnight of an HH:MM clock."""
    m = CLOCK_RE.match(text)
    if not m:
        raise ValueError(text)
    return int(m.group(1)) * 60 + int(m.group(2))


def parse_text(text: str, name: str = "company file") -> Any:
    """JSON when it starts with '{', else the strict YAML subset; raises :class:`CompanyError`."""
    if text.lstrip().startswith("{"):
        try:
            return json.loads(text)
        except ValueError as exc:
            raise CompanyError([f"{name}: not valid JSON ({exc})"]) from exc
    from cyberarena.rc.registry import RegistryError, parse_yaml

    try:
        return parse_yaml(text)
    except RegistryError as exc:
        raise CompanyError([f"{name}: {exc}"]) from exc


def load_company(path: str | Path) -> dict[str, Any]:
    """Read and validate a company file; return the normalised document."""
    p = Path(path)
    try:
        raw = p.read_bytes()
    except OSError as exc:
        raise CompanyError([f"{p.name}: cannot read the file ({exc.strerror or exc})"]) from exc
    if len(raw) > 2_000_000:
        raise CompanyError([f"{p.name}: the file is larger than 2 MB"])
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CompanyError([f"{p.name}: the file is not UTF-8 text"]) from exc
    return validate_company(parse_text(text, p.name))


def digest(doc: dict[str, Any]) -> str:
    """The SHA-256 of a normalised company document (what a report records)."""
    blob = json.dumps(doc, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("ascii")).hexdigest()


def _known(value: Any, names: Collection[Any]) -> bool:
    """Whether a field's value is one of the known names. A file can put anything in a field (a
    list, a mapping); such a value is simply not a name, and must not be looked up as one."""
    return isinstance(value, str) and value in names


@dataclasses.dataclass
class _Names:
    """What the sections refer to each other by: the raw lists and the ids found in them."""

    zones: set[str]
    people_in: list[Any]
    accounts_in: list[Any]
    hosts_in: list[Any]
    services_in: list[Any]
    person_ids: list[Any]
    acct_ids: list[Any]
    all_accounts: set[str]
    hosts: set[str]
    services: set[str]
    links: set[str] = dataclasses.field(default_factory=set)
    roles: set[str] = dataclasses.field(default_factory=set)
    flows: set[str] = dataclasses.field(default_factory=set)


def validate_company(doc: Any) -> dict[str, Any]:
    """Validate a parsed company document; return it normalised or raise :class:`CompanyError`."""
    c = _Check()
    if not c.fields(doc, "company file", TOP_FIELDS["required"], TOP_FIELDS["optional"]):
        raise CompanyError(c.problems)
    if doc.get("schema") != SCHEMA:
        c.add("schema", f"must be {SCHEMA!r} (got {_safe(doc.get('schema'))})")
    out: dict[str, Any] = {"schema": SCHEMA}
    out["name"] = c.ident(doc, "name", "name")
    out["version"] = c.ident(doc, "version", "version")
    comp = doc.get("company")
    if c.fields(comp, "company", ("name",), ("short", "about", "fictional")):
        out["company"] = {
            "name": c.text(comp, "name", "company"),
            "short": c.text(comp, "short", "company", need=False) or c.text(comp, "name", "c"),
            "about": c.text(comp, "about", "company", ABOUT_MAX, need=False),
            "fictional": c.flag(comp, "fictional", "company"),
        }
    start = _shift_start(c, doc)
    out["shift"] = {"start": start}
    out["zones"] = _zones(c, doc)
    n = _names(c, doc, {z["id"] for z in out["zones"]})
    out["hosts"] = _hosts(c, n)
    out["people"], seen = _people(c, n)
    out["accounts"] = _accounts(c, n, seen)
    out["links"] = _links(c, doc, n)
    out["services"] = _services(c, n)
    out["roles"] = _roles(c, doc, n)
    for ln in out["links"]:
        cr = ln.get("contact_role")
        if cr is not None and not _known(cr, n.roles):
            c.add(f"links ({ln['id']})", f"'contact_role' names {_safe(cr)}, not in roles")
    out["flows"] = _flows(c, doc, n)
    for ln in out["links"]:
        listed = ln["flows"]
        if not isinstance(listed, list) or any(not _known(x, n.flows) for x in listed):
            c.add(f"links ({ln['id']})", "'flows' must be a list of flow ids from flows")
            ln["flows"] = []

    out["approval"] = _approval(c, doc.get("approval"), n.roles, n.flows)
    out["logs"] = _logs(c, doc.get("logs"), n.zones | ({"cloud"} if n.services else set()))
    out["calendar"] = _calendar(c, doc.get("calendar"), n.flows, start)
    out["cost"] = _cost(c, doc.get("cost"), n.flows)
    if c.problems:
        raise CompanyError(c.problems)
    return out


def _shift_start(c: _Check, doc: dict) -> int:
    """The minute of the day the incident window starts (02:10 unless the file says otherwise)."""
    shift = doc.get("shift", {"start": "02:10"})
    start = 130
    if c.fields(shift, "shift", (), ("start",)):
        s = shift.get("start", "02:10")
        if isinstance(s, str) and CLOCK_RE.match(s):
            start = clock_minutes(s)
        else:
            c.add("shift", f"'start' must be a clock time HH:MM (got {_safe(s)})")
    return start


def _zones(c: _Check, doc: dict) -> list[dict[str, Any]]:
    zone_ids: list[str] = []
    out = []
    for i, z in enumerate(_list(c, doc, "zones", required=True)):
        w = f"zones[{i}]"
        if not c.fields(z, w, ("id", "label"), ()):
            continue
        zid = c.ident(z, "id", w)
        if zid in zone_ids:
            c.add(w, f"the zone id {zid!r} is used twice")
        zone_ids.append(zid)
        out.append({"id": zid, "label": c.text(z, "label", w)})
    return out


def _names(c: _Check, doc: dict, zones: set[str]) -> _Names:
    """Read the lists that name things and the ids in them; an id must mean one thing."""
    people_in = _list(c, doc, "people", required=True, cap=MAX_PEOPLE)
    accounts_in = _list(c, doc, "accounts")
    person_ids = [p.get("account") for p in people_in if isinstance(p, dict)]
    acct_ids = [a.get("account") for a in accounts_in if isinstance(a, dict)]
    all_accounts = {a for a in person_ids + acct_ids if isinstance(a, str)}

    hosts_in = _list(c, doc, "hosts", required=True, cap=MAX_HOSTS)
    host_set = {h["id"] for h in hosts_in if isinstance(h, dict) and isinstance(h.get("id"), str)}
    services_in = _list(c, doc, "services")
    service_set: set[str] = {
        s["id"] for s in services_in if isinstance(s, dict) and isinstance(s.get("id"), str)
    }
    for x in sorted(host_set & service_set):
        c.add("services", f"{x!r} is both a host and a service id")
    for x in sorted(host_set & all_accounts):
        c.add("hosts", f"{x!r} is both a host id and an account name")
    return _Names(zones, people_in, accounts_in, hosts_in, services_in, person_ids, acct_ids,
                  all_accounts, host_set, service_set)  # fmt: skip


def _hosts(c: _Check, n: _Names) -> list[dict[str, Any]]:
    out = []
    seen: set[str] = set()
    for i, h in enumerate(n.hosts_in):
        w = f"hosts[{i}]"
        if not c.fields(
            h, w, ("id", "role", "label", "zone", "criticality"),
            ("team", "custodian", "users", "about", "tags", "records"),
        ):  # fmt: skip
            continue
        hid = c.ident(h, "id", w)
        w = f"hosts[{i}] ({hid})" if hid else w
        if hid in seen:
            c.add(w, "the host id is used twice")
        seen.add(hid)
        role = h.get("role")
        if not _known(role, HOST_ROLES):
            c.add(w, f"'role' must be one of {', '.join(HOST_ROLES)} (got {_safe(role)})")
        zone = h.get("zone")
        if not _known(zone, n.zones):
            c.add(w, f"'zone' names {_safe(zone)}, which is not in zones")
        custodian = h.get("custodian")
        if custodian is not None and custodian not in n.person_ids:
            c.add(w, f"'custodian' names {_safe(custodian)}, who is not in people")
        out.append(
            {
                "id": hid,
                "role": role if _known(role, HOST_ROLES) else "server",
                "label": c.text(h, "label", w),
                "zone": zone if _known(zone, n.zones) else "",
                "criticality": c.integer(h, "criticality", w, 1, 5, 1),
                "team": c.text(h, "team", w, need=False),
                "custodian": custodian if isinstance(custodian, str) else None,
                "users": c.idlist(h, "users", w, n.all_accounts, "account"),
                "about": c.text(h, "about", w, ABOUT_MAX, need=False),
                "tags": c.idlist(h, "tags", w, None, "tag"),
                "records": c.integer(h, "records", w, 0, 5, 0),
            }
        )
    if not out:
        c.add("hosts", "at least one host is needed")
    return out


def _people(c: _Check, n: _Names) -> tuple[list[dict[str, Any]], set[str]]:
    """The people, and the account names taken so far (accounts must not reuse them)."""
    out = []
    seen: set[str] = set()
    for i, p in enumerate(n.people_in):
        w = f"people[{i}]"
        if not c.fields(
            p, w, ("account", "name", "title", "team"), ("manager", "exec", "admin", "tags")
        ):
            continue
        acc = c.ident(p, "account", w, ACCOUNT_RE)
        w = f"people[{i}] ({acc})" if acc else w
        if acc in seen:
            c.add(w, "the account is used twice")
        seen.add(acc)
        mgr = p.get("manager")
        if mgr is not None and mgr not in n.person_ids:
            c.add(w, f"'manager' names {_safe(mgr)}, who is not in people")
        admin = p.get("admin")
        if admin is not None and admin not in n.acct_ids:
            c.add(w, f"'admin' names {_safe(admin)}, which is not in accounts")
        out.append(
            {
                "account": acc,
                "name": c.text(p, "name", w),
                "title": c.text(p, "title", w),
                "team": c.text(p, "team", w),
                "manager": mgr if isinstance(mgr, str) else None,
                "exec": c.flag(p, "exec", w),
                "admin": admin if isinstance(admin, str) else None,
                "tags": c.idlist(p, "tags", w, None, "tag"),
            }
        )
    return out, seen


def _accounts(c: _Check, n: _Names, seen: set[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for i, a in enumerate(n.accounts_in):
        w = f"accounts[{i}]"
        if not isinstance(a, dict):
            c.add(w, "must be a mapping of fields")
            continue
        kind = a.get("type")
        if kind == "service":
            ok = c.fields(a, w, ("account", "type", "purpose", "host"), ("contact", "reaches"))
        elif kind == "admin":
            ok = c.fields(a, w, ("account", "type", "person"), ())
        else:
            c.add(w, f"'type' must be service or admin (got {_safe(kind)}); people are standard")
            continue
        if not ok:
            continue
        acc = c.ident(a, "account", w, ACCOUNT_RE)
        w = f"accounts[{i}] ({acc})" if acc else w
        if acc in seen:
            c.add(w, "the account name is used twice")
        seen.add(acc)
        if kind == "service":
            host, contact = a.get("host"), a.get("contact")
            if not _known(host, n.hosts):
                c.add(w, f"'host' names {_safe(host)}, which is not in hosts")
            if contact is not None and contact not in n.person_ids:
                c.add(w, f"'contact' names {_safe(contact)}, who is not in people")
            out.append(
                {
                    "account": acc,
                    "type": "service",
                    "purpose": c.text(a, "purpose", w),
                    "host": host if _known(host, n.hosts) else "",
                    "contact": contact if isinstance(contact, str) else None,
                    "reaches": c.idlist(a, "reaches", w, n.hosts | n.services, "host"),
                }
            )
        else:
            person = a.get("person")
            if person not in n.person_ids:
                c.add(w, f"'person' names {_safe(person)}, who is not in people")
            out.append({"account": acc, "type": "admin", "person": person})
    return out


def _links(c: _Check, doc: dict, n: _Names) -> list[dict[str, Any]]:
    out = []
    for i, ln in enumerate(_list(c, doc, "links")):
        w = f"links[{i}]"
        if not c.fields(
            ln, w, ("id", "kind", "label", "address", "host"), ("flows", "contact_role")
        ):
            continue
        lid = c.ident(ln, "id", w)
        w = f"links[{i}] ({lid})" if lid else w
        if lid in n.links:
            c.add(w, "the link id is used twice")
        n.links.add(lid)
        kind = ln.get("kind")
        if not _known(kind, LINK_KINDS):
            c.add(w, f"'kind' must be one of {', '.join(LINK_KINDS)}")
        addr = ln.get("address")
        if not (isinstance(addr, str) and _is_doc_address(addr)):
            c.add(
                w,
                "'address' must be an IPv4 address from the documentation ranges 192.0.2.x, "
                "198.51.100.x or 203.0.113.x (so nothing in the file routes anywhere)",
            )
        host = ln.get("host")
        if not _known(host, n.hosts):
            c.add(w, f"'host' names {_safe(host)}, which is not in hosts")
        out.append(
            {
                "id": lid,
                "kind": kind if _known(kind, LINK_KINDS) else "partner",
                "label": c.text(ln, "label", w),
                "address": addr if isinstance(addr, str) else "",
                "host": host if _known(host, n.hosts) else "",
                "flows": ln.get("flows", []),
                "contact_role": ln.get("contact_role"),
            }
        )
    return out


def _services(c: _Check, n: _Names) -> list[dict[str, Any]]:
    out = []
    for i, s in enumerate(n.services_in):
        w = f"services[{i}]"
        if not c.fields(s, w, ("id", "kind", "label", "criticality"), ("team", "users", "about")):
            continue
        sid = c.ident(s, "id", w)
        kind = s.get("kind")
        if not _known(kind, SERVICE_KINDS):
            c.add(w, f"'kind' must be one of {', '.join(SERVICE_KINDS)}")
        out.append(
            {
                "id": sid,
                "kind": kind if _known(kind, SERVICE_KINDS) else "saas",
                "label": c.text(s, "label", w),
                "criticality": c.integer(s, "criticality", w, 1, 5, 1),
                "team": c.text(s, "team", w, need=False),
                "users": c.idlist(s, "users", w, n.all_accounts, "account"),
                "about": c.text(s, "about", w, ABOUT_MAX, need=False),
            }
        )
    return out


def _roles(c: _Check, doc: dict, n: _Names) -> dict[str, dict[str, Any]]:
    raw_roles = doc.get("roles", {})
    out: dict[str, dict[str, Any]] = {}
    if not isinstance(raw_roles, dict):
        c.add("roles", "must be a mapping of role id to who holds it")
        raw_roles = {}
    for rid, r in list(raw_roles.items())[:MAX_ITEMS]:
        w = f"roles.{rid}"
        if not isinstance(rid, str) or not ID_RE.match(rid):
            c.add("roles", f"the role id {_safe(rid)} is not a valid id")
            continue
        if not c.fields(r, w, (), ("person", "name", "title", "external")):
            continue
        ext = c.flag(r, "external", w)
        person = r.get("person")
        if person is not None:
            if person not in n.person_ids:
                c.add(w, f"'person' names {_safe(person)}, who is not in people")
            if ext:
                c.add(w, "an external role names a contact by 'name', not an employee 'person'")
        elif not r.get("name"):
            c.add(w, "give either 'person' (an employee) or 'name' (an outside contact)")
        out[rid] = {
            "person": person if isinstance(person, str) else None,
            "name": c.text(r, "name", w, need=False),
            "title": c.text(r, "title", w, need=False),
            "external": ext,
        }
        n.roles.add(rid)
    return out


def _flows(c: _Check, doc: dict, n: _Names) -> list[dict[str, Any]]:
    out = []
    for i, f in enumerate(_list(c, doc, "flows")):
        w = f"flows[{i}]"
        if not c.fields(
            f, w, ("id", "kind", "label", "value_per_minute", "hosts"),
            ("pausable", "pause_cost_per_minute", "contact_role", "link", "store"),
        ):  # fmt: skip
            continue
        fid = c.ident(f, "id", w)
        w = f"flows[{i}] ({fid})" if fid else w
        if fid in n.flows:
            c.add(w, "the flow id is used twice")
        n.flows.add(fid)
        kind = f.get("kind")
        if not _known(kind, FLOW_KINDS):
            c.add(w, f"'kind' must be one of {', '.join(FLOW_KINDS)}")
        value = c.integer(f, "value_per_minute", w, 0, 1000, 0)
        pause_cost = c.integer(f, "pause_cost_per_minute", w, 0, 1000, value)
        fcontact = f.get("contact_role")
        if fcontact is not None and not _known(fcontact, n.roles):
            c.add(w, f"'contact_role' names {_safe(fcontact)}, which is not in roles")
        link = f.get("link")
        if link is not None and not _known(link, n.links):
            c.add(w, f"'link' names {_safe(link)}, which is not in links")
        store = f.get("store")
        if store is not None and not _known(store, n.hosts):
            c.add(w, f"'store' names {_safe(store)}, which is not in hosts")
        hosts = c.idlist(f, "hosts", w, n.hosts | n.services, "host or service")
        if not hosts:
            c.add(w, "'hosts' must name at least one host that carries the flow")
        out.append(
            {
                "id": fid,
                "kind": kind if _known(kind, FLOW_KINDS) else "other",
                "label": c.text(f, "label", w),
                "value_per_minute": value,
                "pause_cost_per_minute": pause_cost,
                "hosts": hosts,
                "pausable": c.flag(f, "pausable", w),
                "contact_role": fcontact if isinstance(fcontact, str) else None,
                "link": link if isinstance(link, str) else None,
                "store": store if isinstance(store, str) else None,
            }
        )
    return out


def _list(c: _Check, doc: dict, key: str, required: bool = False, cap: int = MAX_ITEMS) -> list:
    v = doc.get(key)
    if v is None:
        if required:
            c.add(key, "is missing")
        return []
    if not isinstance(v, list):
        c.add(key, "must be a list")
        return []
    if len(v) > cap:
        c.add(key, f"has more than {cap} entries")
    return v[:cap]


def _is_doc_address(text: str) -> bool:
    parts = text.split(".")
    if len(parts) != 4 or not all(
        p.isascii() and p.isdigit() and len(p) <= 3 and int(p) <= 255 for p in parts
    ):
        return False
    return ".".join(parts[:3]) in ("192.0.2", "198.51.100", "203.0.113")


DEFAULT_APPROVAL: dict[str, Any] = {
    "decider": None,
    "delay": 15,
    "expiry": 30,
    "valid": 60,
    "rules": [
        {"actions": ["isolate", "restore"], "criticality_at_least": 4},
        {"actions": ["block", "reset"], "account_types": ["admin"]},
    ],
}


def _approval(c: _Check, a: Any, roles: set[str], flows: set[str]) -> dict[str, Any]:
    if a is None:
        return json.loads(json.dumps(DEFAULT_APPROVAL))
    if not c.fields(a, "approval", (), ("decider", "delay", "expiry", "valid", "rules")):
        return json.loads(json.dumps(DEFAULT_APPROVAL))
    dec = a.get("decider")
    if dec is not None and not _known(dec, roles):
        c.add("approval", f"'decider' names {_safe(dec)}, which is not in roles")
    out: dict[str, Any] = {
        "decider": dec if isinstance(dec, str) else None,
        "delay": c.integer(a, "delay", "approval", 1, 120, 15),
        "expiry": c.integer(a, "expiry", "approval", 1, 240, 30),
        "valid": c.integer(a, "valid", "approval", 1, 480, 60),
        "rules": [],
    }
    if out["expiry"] < out["delay"]:
        c.add("approval", "'expiry' must be at least 'delay'")
    rules = a.get("rules", DEFAULT_APPROVAL["rules"])
    if not isinstance(rules, list):
        c.add("approval", "'rules' must be a list")
        rules = []
    for i, r in enumerate(rules[:MAX_ITEMS]):
        w = f"approval.rules[{i}]"
        if not c.fields(r, w, ("actions",), ("criticality_at_least", "account_types", "flows")):
            continue
        acts = r.get("actions")
        if (
            not isinstance(acts, list)
            or not acts
            or any(not _known(x, APPROVAL_ACTIONS) for x in acts)
        ):
            c.add(w, f"'actions' must be a list from {', '.join(APPROVAL_ACTIONS)}")
            acts = []
        rule: dict[str, Any] = {"actions": acts}
        conds = [k for k in ("criticality_at_least", "account_types", "flows") if k in r]
        if len(conds) != 1:
            c.add(w, "give exactly one of criticality_at_least, account_types or flows")
        if "criticality_at_least" in r:
            rule["criticality_at_least"] = c.integer(r, "criticality_at_least", w, 1, 5, 4)
        if "account_types" in r:
            ts = r["account_types"]
            ok = ("service", "admin", "executive", "standard")
            if not isinstance(ts, list) or any(not _known(t, ok) for t in ts):
                c.add(w, f"'account_types' must be a list from {', '.join(ok)}")
                ts = []
            rule["account_types"] = ts
        if "flows" in r:
            fs = r["flows"]
            if fs != "all" and (not isinstance(fs, list) or any(not _known(x, flows) for x in fs)):
                c.add(w, "'flows' must be \"all\" or a list of flow ids from flows")
                fs = []
            rule["flows"] = fs
        out["rules"].append(rule)
    return out


DEFAULT_LOGS = [{"source": "endpoint", "zones": "all", "delay": 0, "gaps": []}]


def _logs(c: _Check, logs: Any, zones: set[str]) -> list[dict[str, Any]]:
    if logs is None:
        return json.loads(json.dumps(DEFAULT_LOGS))
    if not isinstance(logs, list) or not logs:
        c.add("logs", "must be a list of log sources")
        return []
    out = []
    seen = set()
    for i, s in enumerate(logs[: len(LOG_SOURCES) * 2]):
        w = f"logs[{i}]"
        if not c.fields(s, w, ("source",), ("zones", "delay", "gaps")):
            continue
        src = s.get("source")
        if not _known(src, LOG_SOURCES):
            c.add(w, f"'source' must be one of {', '.join(LOG_SOURCES)}")
            continue
        if src in seen:
            c.add(w, f"the source {src!r} is listed twice")
        seen.add(src)
        z = s.get("zones", "all")
        if z != "all" and (not isinstance(z, list) or any(not _known(x, zones) for x in z)):
            c.add(w, "'zones' must be \"all\" or a list of zone ids")
            z = []
        gaps = []
        for g in s.get("gaps", []) if isinstance(s.get("gaps", []), list) else [None]:
            if not isinstance(g, str) or not SPAN_RE.match(g):
                c.add(w, f"each gap must be a clock span HH:MM-HH:MM (got {_safe(g)})")
                continue
            a, b = g.split("-")
            gaps.append([clock_minutes(a), clock_minutes(b)])
        out.append(
            {"source": src, "zones": z, "delay": c.integer(s, "delay", w, 0, 120, 0), "gaps": gaps}
        )
    if "endpoint" not in seen:
        c.add("logs", "the endpoint source must be listed (host logs come from it)")
    return out


def _calendar(c: _Check, cal: Any, flows: set[str], start: int) -> dict[str, Any]:
    out: dict[str, Any] = {"windows": []}
    if cal is None:
        return out
    if not c.fields(cal, "calendar", (), ("windows",)):
        return out
    wins = cal.get("windows", [])
    if not isinstance(wins, list):
        c.add("calendar", "'windows' must be a list")
        return out
    for i, wdw in enumerate(wins[:MAX_ITEMS]):
        w = f"calendar.windows[{i}]"
        if not c.fields(
            wdw, w, ("id", "label", "start", "minutes", "days"), ("flow", "multiplier")
        ):
            continue
        st = wdw.get("start")
        if not (isinstance(st, str) and CLOCK_RE.match(st)):
            c.add(w, "'start' must be a clock time HH:MM")
            continue
        days = wdw.get("days")
        if not isinstance(days, list) or not days or any(not _known(d, DAYS) for d in days):
            c.add(w, f"'days' must be a list from {', '.join(DAYS)}")
            days = []
        flow = wdw.get("flow")
        if flow is not None and not _known(flow, flows):
            c.add(w, f"'flow' names {_safe(flow)}, which is not in flows")
        out["windows"].append(
            {
                "id": c.ident(wdw, "id", w),
                "label": c.text(wdw, "label", w),
                "at": (clock_minutes(st) - start) % 1440,
                "minutes": c.integer(wdw, "minutes", w, 1, SHIFT_MINUTES, 20),
                "days": days,
                "flow": flow if isinstance(flow, str) else None,
                "multiplier": c.integer(wdw, "multiplier", w, 1, 5, 1),
            }
        )
    return out


def _cost(c: _Check, cost: Any, flows: set[str]) -> dict[str, Any] | None:
    if cost is None:
        return None
    if not c.fields(cost, "cost", (), ("weights", "flows")):
        return None
    out: dict[str, Any] = {"weights": {}, "flows": {}}
    ws = cost.get("weights", {})
    if not isinstance(ws, dict):
        c.add("cost", "'weights' must be a mapping")
        ws = {}
    for k, v in ws.items():
        if k not in WEIGHT_KEYS:
            c.add("cost.weights", f"unknown weight {_safe(k)} (known: {', '.join(WEIGHT_KEYS)})")
        elif isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= 100000:
            c.add("cost.weights", f"'{k}' must be a whole number from 0 to 100000")
        else:
            out["weights"][k] = v
    fv = cost.get("flows", {})
    if not isinstance(fv, dict):
        c.add("cost", "'flows' must be a mapping of flow id to value per minute")
        fv = {}
    for k, v in fv.items():
        if k not in flows:
            c.add("cost.flows", f"{_safe(k)} is not a flow id")
        elif isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= 1000:
            c.add("cost.flows", f"'{k}' must be a whole number from 0 to 1000")
        else:
            out["flows"][k] = v
    return out
