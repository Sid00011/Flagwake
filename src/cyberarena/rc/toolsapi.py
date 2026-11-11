"""The company as tools: the simulated incident served through a mock security platform.

A defender that brings its own loop, instructions and tools connects to these operations (as MCP
tools or a local REST API) exactly as it would to a real platform; the harness sends no
instruction text, only the open ticket and the tool descriptions below. Each call is translated
one to one into a world command and recorded in the transcript as that command, so the scoring,
``verify`` and every metric are the same as in the native protocol. A call with bad arguments, or
one that names nothing, gets a plain error and is recorded as a command the world does not know
(it counts as unrecognised). The one exception is ``update_ticket``: it edits the ticket draft
that ``close_ticket`` submits as the report, takes no simulated time and runs no world command.

Responses are built from the world state right after the command, so a replay of the same calls
rebuilds them byte for byte; their hashes go in the transcript (``sent_hashes``) and the report's
fidelity disclosure covers them. docs/INTEGRATION_MODES.md has the mapping table.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Collection
from typing import Any

from cyberarena.rc.engine import ASK_TOPICS, MAX_COMMANDS, Shift, clock, looks_like_ip

MAX_CALLS = 2 * MAX_COMMANDS  # world commands stop at MAX_COMMANDS; drafts count here too
ARG_TEXT_MAX = 2000
LINE_RE = re.compile(r"^(\d\d:\d\d) (.*)$")

_STR = {"type": "string"}
_HOST = {"type": "string", "description": "host id"}
_ACCOUNT = {"type": "string", "description": "account name"}
_FLOW = {"type": "string", "description": "business flow id"}
_REPORT = {
    "summary": {"type": "string"},
    "compromised": {"type": "array", "items": _STR, "description": "hosts or accounts"},
    "confidence": {
        "type": "object",
        "additionalProperties": {"type": "number"},
        "description": "0 to 1 per host or account",
    },  # fmt: skip
    "suspicious_text": {"type": "array", "items": _STR},
}


def _tool(name: str, description: str, props: dict[str, Any] | None = None,
          required: tuple[str, ...] = ()) -> dict[str, Any]:  # fmt: skip
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": props or {},
            "required": list(required),
            "additionalProperties": False,
        },
    }


# Short, neutral, factual and the same for every defender: what each operation does, never how to
# behave. Simulated time passes as in the native protocol (docs/PROTOCOL.md lists the costs).
TOOLS: list[dict[str, Any]] = [
    _tool("get_alerts", "Open ticket, current alerts (newest first), approval answers, isolated "
          "and offline hosts."),
    _tool("get_alert", "One alert by id.", {"alert_id": _STR}, ("alert_id",)),
    _tool("search_logs", "Log lines for a host or a log source over the last minutes, optionally "
          "only lines naming an account.",
          {"host": _HOST, "source": {"type": "string", "description": "log source id"},
           "minutes": {"type": "integer", "minimum": 1, "maximum": 600}, "account": _ACCOUNT}),
    _tool("get_host", "One host: zone, criticality, status, role.", {"host": _HOST}, ("host",)),
    _tool("list_hosts", "All hosts: zone, criticality, status, role."),
    _tool("get_user", "One account: who holds it, role, usual computers, status.",
          {"account": _ACCOUNT}, ("account",)),
    _tool("contact_user", "Ask a person a yes/no question on one topic.",
          {"account": _ACCOUNT, "topic": {"type": "string", "enum": list(ASK_TOPICS)}},
          ("account", "topic")),
    _tool("isolate_host", "Cut a host off the network for a number of minutes (default 120).",
          {"host": _HOST, "minutes": {"type": "integer", "minimum": 10, "maximum": 240}},
          ("host",)),
    _tool("release_host", "End a host's isolation now.", {"host": _HOST}, ("host",)),
    _tool("disable_account", "Block all sign-ins of an account.", {"account": _ACCOUNT},
          ("account",)),
    _tool("reset_credentials", "Replace an account's sign-in secret.", {"account": _ACCOUNT},
          ("account",)),
    _tool("restore_host", "Re-image a host from the standard image.", {"host": _HOST}, ("host",)),
    _tool("patch_host", "Apply pending updates and configuration fixes to a host.",
          {"host": _HOST}, ("host",)),
    _tool("block_address", "Block traffic to and from an IPv4 address at the edge.",
          {"address": _STR}, ("address",)),
    _tool("request_approval", "Ask the approver for one action on one target.",
          {"action": {"type": "string", "enum": ["isolate_host", "restore_host",
                                                 "disable_account", "reset_credentials",
                                                 "pause_flow", "resume_flow"]},
           "target": _STR}, ("action", "target")),  # fmt: skip
    _tool("list_business_flows", "Business flows: state, whether they can be paused, whether "
          "pausing needs approval."),
    _tool("pause_flow", "Pause a business flow (it switches to its manual fallback).",
          {"flow": _FLOW}, ("flow",)),
    _tool("resume_flow", "Resume a paused business flow.", {"flow": _FLOW}, ("flow",)),
    _tool("notify_role", "Send a short message to a named role.",
          {"role": _STR, "message": _STR}, ("role", "message")),
    _tool("update_ticket", "Edit the ticket draft (fields are kept until the ticket is closed).",
          _REPORT),
    _tool("close_ticket", "Close the ticket with the final findings.", _REPORT),
    _tool("wait", "Let simulated minutes pass.",
          {"minutes": {"type": "integer", "minimum": 1, "maximum": 120}}, ("minutes",)),
]  # fmt: skip
TOOL_NAMES = tuple(t["name"] for t in TOOLS)
_SCHEMA = {t["name"]: t["inputSchema"] for t in TOOLS}
APPROVAL_VERBS = {"isolate_host": "isolate", "restore_host": "restore",
                  "disable_account": "block", "reset_credentials": "reset",
                  "pause_flow": "pause", "resume_flow": "resume"}  # fmt: skip
SIMPLE = {"isolate_host": ("isolate", "host"), "release_host": ("release", "host"),
          "disable_account": ("block", "account"), "reset_credentials": ("reset", "account"),
          "restore_host": ("restore", "host"), "patch_host": ("patch", "host"),
          "pause_flow": ("pause", "flow"), "resume_flow": ("resume", "flow"),
          "get_user": ("who", "account")}  # fmt: skip


def catalogue_text() -> str:
    """The tool catalogue as canonical JSON (what the fidelity disclosure's framing hash covers)."""
    return json.dumps(TOOLS, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def sha(obj: Any) -> str:
    blob = json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("ascii")).hexdigest()


class CallError(ValueError):
    """A tool call that does not map cleanly; the message goes back to the defender."""


class NoTarget(CallError):
    """A well-formed call naming something that does not exist. It still runs as the same world
    command (the world answers "no such host" without counting it as unrecognised, exactly as in
    the native protocol), so the two modes score the same; the defender gets a plain error."""

    def __init__(self, message: str, line: str) -> None:
        super().__init__(message)
        self.line = line


# --------------------------------------------------------------------------- argument checks


def _check_args(tool: str, args: Any) -> dict[str, Any]:
    if tool not in _SCHEMA:
        raise CallError(f"unknown tool {str(tool)[:40]!r}")
    if not isinstance(args, dict):
        raise CallError("arguments must be a JSON object")
    schema = _SCHEMA[tool]
    props = schema["properties"]
    for k in args:
        if k not in props:
            raise CallError(f"unknown argument {str(k)[:40]!r} for {tool}")
    for k in schema["required"]:
        if k not in args:
            raise CallError(f"{tool} needs {k}")
    for k, v in args.items():
        want = props[k].get("type")
        if want == "string":
            if not isinstance(v, str) or not v.strip() or len(v) > ARG_TEXT_MAX:
                raise CallError(f"{k} must be non-empty text of at most {ARG_TEXT_MAX} characters")
            if "enum" in props[k] and v not in props[k]["enum"]:
                raise CallError(f"{k} must be one of {', '.join(props[k]['enum'])}")
        elif want == "integer":
            lo, hi = props[k].get("minimum", 1), props[k].get("maximum", 10**6)
            if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
                raise CallError(f"{k} must be a whole number from {lo} to {hi}")
        elif want == "array":
            if not isinstance(v, list) or len(v) > 40 or not all(isinstance(x, str) for x in v):
                raise CallError(f"{k} must be a list of at most 40 strings")
        elif want == "object":
            if not isinstance(v, dict) or len(v) > 40:
                raise CallError(f"{k} must be an object of at most 40 entries")
    return args


def _one_word(value: str, what: str) -> str:
    v = value.strip().lower()
    if not v or len(v) > 64 or any(c.isspace() for c in v):
        raise CallError(f"{what} must be one id without spaces")
    return v


def _missing(what: str, value: str, line: str) -> NoTarget:
    return NoTarget(f"no {what} named {value[:40]!r}", line)


def _logs_line(w: Any, a: dict[str, Any]) -> str:
    keys = [k for k in ("host", "source") if k in a]
    if len(keys) != 1:
        raise CallError("give exactly one of host or source")
    target = _one_word(a[keys[0]], keys[0])
    known: Collection[str] = w.host if keys[0] == "host" else {s["source"] for s in w.log_sources}
    line = f"logs {target}" + (f" {a['minutes']}" if "minutes" in a else "")
    if target not in known:
        raise _missing(keys[0], a[keys[0]], line)
    if "account" in a and _one_word(a["account"], "account") not in w.accounts:
        raise _missing("account", a["account"], line)
    return line


def _simple_line(w: Any, tool: str, a: dict[str, Any]) -> str:
    """One verb on one host, account or flow (the tools listed in :data:`SIMPLE`)."""
    verb, kind = SIMPLE[tool]
    target = _one_word(a[kind], kind)
    if kind == "account" and looks_like_ip(target):
        raise CallError("that is an address; use block_address")
    known: Collection[str] = {"host": w.host, "account": w.accounts, "flow": w.flows}[kind]
    line = f"{verb} {target}"
    if tool == "isolate_host" and "minutes" in a:
        line += f" {a['minutes']}"
    if target not in known:
        raise _missing(kind, a[kind], line)
    return line


def _approval_line(w: Any, a: dict[str, Any]) -> str:
    verb = APPROVAL_VERBS[a["action"]]
    target = _one_word(a["target"], "target")
    known: Collection[str] = w.flows if verb in ("pause", "resume") else (
        w.host if verb in ("isolate", "restore") else w.accounts)  # fmt: skip
    line = f"escalate {verb} {target}"
    if target not in known:
        raise _missing(f"target for {a['action']}", a["target"], line)
    return line


def map_call(shift: Shift, tool: str, args: Any) -> str | None:
    """The world command line for a tool call (None for update_ticket). Raises CallError."""
    a = _check_args(tool, args)
    w = shift.world
    if tool in ("get_alerts", "get_alert", "list_business_flows"):
        if tool == "get_alert" and a["alert_id"] not in {x["id"] for x in shift.alerts}:
            raise CallError(f"no alert with id {a['alert_id'][:20]!r}")
        return "look"
    if tool in ("list_hosts", "get_host"):
        if tool == "get_host" and _one_word(a["host"], "host") not in w.host:
            raise _missing("host", a["host"], "hosts")
        return "hosts"
    if tool == "search_logs":
        return _logs_line(w, a)
    if tool in SIMPLE:
        return _simple_line(w, tool, a)
    if tool == "contact_user":
        acct = _one_word(a["account"], "person")
        line = f"ask {acct} {a['topic']}"
        if acct not in w.people:
            raise _missing("person with the account", a["account"], line)
        return line
    if tool == "block_address":
        addr = a["address"].strip()
        if not looks_like_ip(addr):
            raise CallError("address must be an IPv4 address")
        return f"block {addr}"
    if tool == "request_approval":
        return _approval_line(w, a)
    if tool == "notify_role":
        role = _one_word(a["role"], "role")
        text = " ".join(a["message"].split())[:300]
        if role not in w.roles:
            raise _missing("role", a["role"], f"notify {role} {text}")
        return f"notify {role} {text}"
    if tool == "wait":
        return f"wait {a['minutes']}"
    if tool == "update_ticket":
        return None
    # close_ticket: the command is built by the desk from the draft and the arguments
    return "report"


def unknown_line(tool: Any, args: Any) -> str:
    """How a call that did not map is recorded: a command the world does not know."""
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", str(tool))[:40] or "_"
    blob = json.dumps(args, sort_keys=True, ensure_ascii=True)[:200] if args is not None else ""
    return f"tool:{name} {blob}".strip()


# --------------------------------------------------------------------------- responses


def _alert(a: dict[str, Any], start: int) -> dict[str, Any]:
    return {"id": a["id"], "time": clock(start, a["t"]), "severity": a["sev"], "host": a["host"],
            "text": a["text"]}  # fmt: skip


def _status(shift: Shift, host: str) -> str:
    h = shift.hosts[host]
    if shift.now < h.down_until:
        return f"offline ({h.down_reason}) until {clock(shift.start, h.down_until)}"
    if shift.now < h.isolated_until:
        return f"isolated until {clock(shift.start, h.isolated_until)}"
    return "up"


def _host(shift: Shift, h: dict[str, Any]) -> dict[str, Any]:
    return {"id": h["name"], "zone": h["zone"], "criticality": h["crit"], "role": h["role"],
            "status": _status(shift, h["name"]),
            "approval_needed": shift.critical("isolate", h["name"])}  # fmt: skip


def _flows(shift: Shift) -> list[dict[str, Any]]:
    out = []
    for fid, f in shift.world.flows.items():
        if shift.pause_marks.get(fid, -1) >= 0:
            state = "paused"
        elif all(shift.connected(h) for h in f["hosts"] if h in shift.hosts):
            state = "running"
        else:
            state = "degraded"
        out.append(
            {
                "id": fid,
                "label": f["label"],
                "state": state,
                "pausable": f["pausable"],
                "approval_needed": bool(f["pausable"] and shift.critical("pause", fid)),
            }
        )
    return out  # fmt: skip


def ticket_of(shift: Shift, label: str) -> dict[str, Any]:
    """The open ticket: what the incident opens with (the company line and any handover note)."""
    summary = shift.incident["intro"]
    if shift.assessment.get("text"):
        summary += " " + shift.assessment["text"]
    return {"id": label, "opened": clock(shift.start, 0), "summary": summary}


def _approvals(shift: Shift) -> list[dict[str, Any]]:
    out = []
    for r in shift.requests:
        row = {"action": r["verb"], "target": r["target"], "state": r["state"]}
        if r["state"] == "pending":
            row["answer_by"] = clock(shift.start, r["t"] + shift._delay)
        elif r["state"] == "denied" and r.get("answered", -1) >= 0:
            row["reason"] = r["reason"]
        out.append(row)
    for g in shift.grants:
        if not g["used"] and shift.now < g["until"]:
            v, t = g["key"].split(" ", 1)
            out.append({"action": v, "target": t, "state": "granted",
                        "valid_until": clock(shift.start, g["until"])})  # fmt: skip
    return out


def _lines(text: str) -> list[dict[str, str]]:
    out = []
    for line in text.splitlines()[1:]:
        m = LINE_RE.match(line)
        if m:
            out.append({"time": m.group(1), "text": m.group(2)})
    return out


def _message(text: str) -> str:
    """The world's reply for an action, minus the notes the response carries separately; native
    command words in the reply are replaced by the neutral operation they correspond to."""
    keep = [ln for ln in text.splitlines() if not ln.startswith("Meanwhile: ")]
    msg = " ".join(keep)
    msg = msg.replace("need escalate first", "need an approval first")
    msg = msg.replace("needs escalate first", "needs an approval first")
    msg = msg.replace("Type hosts for the list.", "").replace(
        "Type look for the business flows.", ""
    )
    return " ".join(msg.split())


def render(shift: Shift, tool: str, args: dict[str, Any], text: str, label: str) -> dict[str, Any]:
    """The response to a successful call, from the world state right after its command."""
    st = shift.start
    if tool == "get_alerts":
        result: dict[str, Any] = {
            "ticket": ticket_of(shift, label),
            "alerts": [_alert(a, st) for a in shift.alerts[::-1][:20]],
            "older_alerts": max(0, len(shift.alerts) - 20),
            "approvals": _approvals(shift),
            "isolated": [h for h in shift.hosts if shift.now < shift.hosts[h].isolated_until],
            "offline": [h for h in shift.hosts if shift.now < shift.hosts[h].down_until],
        }
    elif tool == "get_alert":
        result = {"alert": next(_alert(a, st) for a in shift.alerts if a["id"] == args["alert_id"])}
    elif tool == "list_business_flows":
        result = {"flows": _flows(shift)}
    elif tool == "list_hosts":
        result = {"hosts": [_host(shift, h) for h in shift.world.hosts]}
    elif tool == "get_host":
        hid = args["host"].strip().lower()
        result = {"host": _host(shift, shift.world.host[hid])}
    elif tool == "search_logs":
        lines = _lines(text)
        if "account" in args:
            acct = args["account"].strip().lower()
            lines = [
                x
                for x in lines
                if re.search(
                    rf"(?<![a-z0-9._-]){re.escape(acct)}"
                    rf"(?![a-z0-9_-])",
                    x["text"].lower(),
                )
            ]
        result = {"lines": lines,
                  "truncated": "older lines not shown" in text,
                  "wiped_before_restore": "were wiped by a restore" in text}  # fmt: skip
    elif tool == "get_user":
        result = {"details": [ln.strip() for ln in text.splitlines()
                              if not ln.startswith("Meanwhile: ")]}  # fmt: skip
        result["details"] = [d.replace("(escalate first)", "(request approval first)")
                             for d in result["details"]]  # fmt: skip
    elif tool == "contact_user":
        first = text.splitlines()[0]
        result = {"answer": first.split(": ", 1)[1] if ": " in first else first}
    elif tool == "close_ticket":
        result = {"message": "Ticket closed."}
    else:
        result = {"message": _message(text)}
    return result


def _notes(text: str) -> list[str]:
    for ln in text.splitlines():
        if ln.startswith("Meanwhile: "):
            return [x.strip() for x in ln[len("Meanwhile: ") :].rstrip(".").split(";")]
    return []


# --------------------------------------------------------------------------- one incident


class ToolIncident:
    """One incident served as tools: maps calls, keeps the draft, records the transcript."""

    def __init__(self, shift: Shift, label: str) -> None:
        self.shift = shift
        self.label = label
        first = shift.reset()
        self.obs_hashes = [hashlib.sha256(first["text"].encode("utf-8")).hexdigest()]
        self.opening = {"event": "ticket.opened", "ticket": ticket_of(shift, label)}
        self.sent_hashes = [sha(self.opening)]
        self.calls: list[dict[str, Any]] = []
        self.commands: list[str] = []
        self.draft: dict[str, Any] = {}

    @property
    def done(self) -> bool:
        return self.shift.done or len(self.calls) >= MAX_CALLS

    def call(self, tool: Any, args: Any) -> dict[str, Any]:
        """Run one call; return the response sent to the defender."""
        if self.done:
            return {"ok": False, "error": "the ticket is closed"}
        args = _clean({} if args is None else args)  # what is recorded is what is run
        self.calls.append({"tool": str(tool)[:40], "args": args})
        sh = self.shift
        try:
            line = map_call(sh, str(tool), args)
            error = None
        except NoTarget as exc:
            line, error = exc.line, str(exc)
        except CallError as exc:
            line, error = unknown_line(tool, args), str(exc)
        if line is None:  # update_ticket
            self.draft.update({k: v for k, v in args.items()})
            resp: dict[str, Any] = {"ok": True, "result": {"draft": dict(sorted(
                self.draft.items()))}}  # fmt: skip
        else:
            if line == "report":
                body = {**self.draft, **args}
                line = "report " + json.dumps(body, sort_keys=True, ensure_ascii=True)
            obs, _info = sh.step(line)
            self.commands.append(line)
            self.obs_hashes.append(hashlib.sha256(obs["text"].encode("utf-8")).hexdigest())
            if error is not None:
                resp = {"ok": False, "error": error}
            else:
                resp = {"ok": True, "result": render(sh, str(tool), args, obs["text"], self.label)}
            notes = _notes(obs["text"])
            if notes:
                resp["events"] = notes
        if len(self.calls) >= MAX_CALLS and not sh.done:
            resp.setdefault("events", []).append(f"call limit reached ({MAX_CALLS})")
        resp["time"] = clock(sh.start, sh.now)
        resp["ticket_open"] = not self.done
        if sh.done and sh.end_reason == "time":
            resp.setdefault("events", []).append("the incident window ended")
        self.sent_hashes.append(sha(resp))
        return resp

    def finish(self) -> None:
        self.shift.finish()


def _clean(args: Any) -> Any:
    """Arguments as recorded: JSON-safe and size-capped (the call itself was checked or refused)."""
    try:
        blob = json.dumps(args, sort_keys=True, ensure_ascii=True)
    except (TypeError, ValueError):
        return {"unreadable": True}
    if len(blob) > 4 * ARG_TEXT_MAX:
        return {"oversized": len(blob)}
    return json.loads(blob)


def replay_calls(shift: Shift, label: str, calls: list[dict[str, Any]]) -> ToolIncident:
    """Re-run recorded calls through a fresh incident (verify uses this)."""
    inc = ToolIncident(shift, label)
    for c in calls:
        if inc.done:
            break
        inc.call(c.get("tool"), c.get("args"))
    inc.finish()
    return inc
