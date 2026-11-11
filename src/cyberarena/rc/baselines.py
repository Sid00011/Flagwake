"""Scripted responder agents, shipped and deterministic.

An agent is a callable: given the running :class:`Shift` it returns the next command string, or
``None`` to stop (close the incident). The runner feeds it observations by stepping the shift; the
agents read only what any responder sees (``shift.observations`` and the public help), never the
ground truth. They exist to exercise the scoring and to calibrate the report, and the calibration
gate (``tests``) checks the metrics separate them as expected.

Seven reference behaviours plus three metric-validity fixtures:
  do-nothing · isolate-on-first-alert · isolate-everything · rule-bot · careful · thorough · oracle
  gullible · paranoid · slow
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from cyberarena.rc.engine import ISOLATE_DEFAULT, Shift
from cyberarena.rc.scoring import oracle_commands
from cyberarena.rc.world import WORLD, World

Agent = Callable[[], "Responder"]


class Responder:
    """Base: subclasses implement :meth:`act`; the runner calls :meth:`next_command`."""

    name = "base"

    def __init__(self) -> None:
        self.step = 0
        self._plan: list[str] = []

    def next_command(self, shift: Shift) -> str | None:
        self.step += 1
        return self.act(shift)

    def act(self, shift: Shift) -> str | None:  # pragma: no cover - overridden
        raise NotImplementedError


def _latest(shift: Shift) -> str:
    return shift.observations[-1] if shift.observations else ""


def _attack_alert_hosts(shift: Shift) -> list[str]:
    """Hosts named in alerts, newest first (from the alert ledger, as look shows them)."""
    return [a["host"] for a in reversed(shift.alerts)]


def _alert_host(shift: Shift) -> str | None:
    hosts = _attack_alert_hosts(shift)
    return hosts[0] if hosts else None


IOC_RE = re.compile(
    r"unknown program|unsigned program|sign-in tokens|outbound transfer|archive written|"
    r"bulk read|unexpected process"
)
# Context words that mark an indicator-shaped line as ordinary business (used by the careful
# analyst to discount the false-positive and backup-exfil bait; the rule bot ignores them).
BENIGN_CONTEXT = (
    "nightly",
    "backup job",
    "on schedule",
    "scheduled",
    "maintenance",
    "update",
    "re-index",
    "greylisted",
    "offsite backup",
    "provider",
)


# Rules 2 adds sources, hosted services and flows, so the careful analyst's vocabulary grows by
# the indicator phrases those lines use (the rule bot keeps the original list).
IOC2_RE = re.compile(
    r"unfamiliar place|new device|exported many|catalog entries removed|outside the backup window|"
    r"copied records to a personal share|from an unknown address|submissions authorised by|"
    r"with the [a-z0-9._-]+ authorisation|sign-in secret"
)
BENIGN_CONTEXT2 = ("known device", "planned", "routine event", "own services healthy")
SEV_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}
PRESSURE = ("urgent", "sign-in secret")


class DoNothing(Responder):
    name = "do-nothing"

    def act(self, shift: Shift) -> str | None:
        return None if self.step > 1 else "look"


class IsolateOnFirstAlert(Responder):
    name = "isolate-on-first-alert"

    def act(self, shift: Shift) -> str | None:
        if self.step == 1:
            return "look"
        host = _alert_host(shift)
        if host and self.step == 2:
            return f"isolate {host}"
        return None


class IsolateEverything(Responder):
    name = "isolate-everything"

    def act(self, shift: Shift) -> str | None:
        if self.step == 1:
            return "look"
        hosts = [h for h in _attack_alert_hosts(shift) if h not in self._plan]
        if hosts:
            self._plan.append(hosts[0])
            return f"isolate {hosts[0]}"
        return None


class RuleBot(Responder):
    """~20 lines: for each alerting host, read its logs and isolate it if an indicator shows.
    Never escalates, never resets credentials, and is fooled by a transfer to a known partner."""

    name = "rule-bot"

    def __init__(self) -> None:
        super().__init__()
        self.queue: list[str] = []
        self.pending_check: str | None = None

    def act(self, shift: Shift) -> str | None:
        if self.step == 1:
            return "look"
        if self.pending_check is not None:
            host, self.pending_check = self.pending_check, None
            if IOC_RE.search(_latest(shift)):
                return f"isolate {host}"
        for host in _attack_alert_hosts(shift):
            if host in shift.world.host and host not in self.queue:
                self.queue.append(host)
                self.pending_check = host
                return f"logs {host}"
        return None


class Careful(Responder):
    """Investigates before acting, escalates critical actions, resets reused credentials, reports
    calibrated confidence. It treats a host as compromised only when its own logs carry an
    indicator that is not a transfer to a known partner address; it checks the ticket gateway but
    never obeys instructions found there.

    The routine runs in steps driven by a small plan, so it adapts to what the logs reveal and to
    alerts that arrive while it waits for the picture to settle.
    """

    name = "careful"

    def __init__(self) -> None:
        super().__init__()
        self.plan: list[str] = ["look", "hosts"]
        self.read: list[str] = []
        self.suspect: list[str] = []
        self.compromised: list[str] = []
        self.creds: list[str] = []
        self.contained: list[str] = []
        self.escalated: set[str] = set()
        self.waited: set[str] = set()
        self.partners: set[str] = set()
        self.pending: list[str] = []  # queued escalate/wait/isolate/reset for one target
        self.mail_read = False
        self.revisited = False
        self.final: str | None = None
        # Rules 2 only.
        self.sources_left: list[str] | None = None
        self.paused: dict[str, str] = {}  # flow -> "intrusion" or "supplier"
        self.notified: set[str] = set()
        self.alerted_roles = False

    def next_command(self, shift: Shift) -> str | None:
        self.step += 1
        return self._drive(shift)

    def _drive(self, shift: Shift) -> str | None:
        if self.plan:
            return self.plan.pop(0)
        self._learn_partners(_latest(shift))
        if self.pending:  # finishing a queued escalate -> wait -> act sequence
            return self.pending.pop(0)
        if shift.rules2:
            return self._drive2(shift)
        self._survey(shift)
        # Read and, as soon as a host's own logs show a real indicator, contain it at once.
        for host in self.suspect:
            if host in self.read or host not in shift.world.host:
                continue
            self.read.append(host)
            return f"logs {host}"
        self._consider(shift)
        cmd = self._contain_step(shift)
        if cmd is not None:
            return cmd
        # Check the ticket gateway once (surface planted text; never obey it).
        tickets = shift.world.tickets[:1]
        if not self.mail_read and tickets:
            self.mail_read = True
            self.read.append(tickets[0])
            return f"logs {tickets[0]}"
        # One short pause to catch a credential named late, then re-read the leads.
        if not self.revisited:
            self.revisited = True
            self.read = [h for h in self.read if h in tickets]
            self.plan = ["wait 15"]
            return self.plan.pop(0)
        return self._close(shift)

    # ------------------------------------------------------------------ rules 2
    def _drive2(self, shift: Shift) -> str | None:
        """The same routine on a company-file world: suspects by severity and criticality, the
        extra log sources read once, flows paused and approvals batched, internal roles told."""
        w = shift.world
        if self.sources_left is None:
            self.sources_left = [s["source"] for s in w.log_sources if s["source"] != "endpoint"]
        self._survey2(shift)
        for host in self.suspect:
            if host in self.read or host not in w.host:
                continue
            self.read.append(host)
            return f"logs {host}"
        if self.sources_left:
            src = self.sources_left.pop(0)
            self.read.append(src)
            return f"logs {src}"
        self._consider(shift)
        self._consider_sources(shift)
        cmd = self._contain2(shift) or self._evict(shift)
        if cmd is not None:
            return cmd
        cmd = self._notify2(shift)
        if cmd is not None:
            return cmd
        tickets = w.tickets[:1]
        if not self.mail_read and tickets:
            self.mail_read = True
            self.read.append(tickets[0])
            return f"logs {tickets[0]}"
        if not self.revisited:
            self.revisited = True
            self.read = [h for h in self.read if h in tickets]
            self.sources_left = [s["source"] for s in w.log_sources if s["source"] != "endpoint"]
            return "wait 15"
        return self._close(shift)

    def _survey2(self, shift: Shift) -> None:
        w = shift.world
        ranked = sorted(
            shift.alerts,
            key=lambda a: (-SEV_RANK.get(a["sev"], 0), -w.crit(a["host"]) if a["host"] in w.host
                           else 0, a["id"]),
        )  # fmt: skip
        for a in ranked:
            if a["host"] not in self.suspect:
                self.suspect.append(a["host"])
        self.suspect.sort(
            key=lambda h: (
                -max(
                    (SEV_RANK.get(a["sev"], 0) * 10 + (w.crit(h) if h in w.host else 0))
                    for a in shift.alerts
                    if a["host"] == h
                )
                if any(a["host"] == h for a in shift.alerts)
                else 0
            )
        )

    def _indicator2(self, line: str) -> bool:
        low = line.lower()
        if not (IOC_RE.search(low) or IOC2_RE.search(low)):
            return False
        if any(ctx in low for ctx in BENIGN_CONTEXT + BENIGN_CONTEXT2):
            return False
        return not ("outbound transfer" in low and any(ip in line for ip in self.partners))

    def _consider_sources(self, shift: Shift) -> None:
        """Indicator lines anywhere it read (hosts, sources, the ticket gateway) name hosts and
        accounts: a host at the start of a source line is compromised, a named account leaked."""
        w = shift.world
        for meta, obs in zip(shift.obs_meta, shift.observations, strict=False):
            if meta["verb"] != "logs" or not meta.get("target"):
                continue
            src = meta["target"] not in w.host
            for line in obs.splitlines()[1:]:
                if not self._indicator2(line):
                    continue
                words = re.findall(r"[a-z0-9][a-z0-9._-]*[a-z0-9]", line.lower())
                lead = words[2] if src and words[2:3] else ""
                if (lead in w.host or lead in w.cloud) and lead not in self.compromised:
                    self.compromised.append(lead)
                for word in words:
                    if word in w.accounts and word not in self.creds:
                        self.creds.append(word)

    def _flows_to_pause(self, shift: Shift) -> list[tuple[str, str]]:
        w = shift.world
        down_links = {ln for a in shift.alerts for ln in w.links
                      if ln in a["text"] and "not answering" in a["text"]}  # fmt: skip
        out = []
        for a in shift.alerts:
            for fid, f in w.flows.items():
                if not f["pausable"] or fid in self.paused or (fid, "") in out:
                    continue
                if not re.search(rf"(?<![a-z0-9-]){re.escape(fid)}(?![a-z0-9-])", a["text"]):
                    continue
                if a["host"] in self.compromised:
                    out.append((fid, "intrusion"))
                elif f.get("link") in down_links or any(ln in a["text"] for ln in down_links):
                    out.append((fid, "supplier"))
        return out

    def _contain2(self, shift: Shift) -> str | None:
        """Everything the evidence supports, at once: flows first, then credentials, then hosts;
        approvals are asked for together, then one wait, then the approved actions."""
        queue: list[tuple[str, str]] = []
        for fid, why in self._flows_to_pause(shift):
            self.paused[fid] = why
            queue.append(("pause", fid))
        for acct in self.creds:
            if f"c:{acct}" not in self.contained:
                self.contained.append(f"c:{acct}")
                queue.append(("reset", acct))
        for host in self.compromised:
            if host not in self.contained and host in shift.world.host:
                self.contained.append(host)
                queue.append(("isolate", host))
        if not queue:
            return None
        crit = [(v, t) for v, t in queue if shift.critical(v, t)]
        plain = [f"{v} {t}" for v, t in queue if (v, t) not in crit]
        cmds = [f"escalate {v} {t}" for v, t in crit] + plain
        if crit:
            cmds += ["wait 15"] + [f"{v} {t}" for v, t in crit]
        self.pending = cmds[1:]
        return cmds[0]

    def _notify2(self, shift: Shift) -> str | None:
        """Tell internal roles what they need: the security lead about a confirmed intrusion or
        pressure on the help desk, a paused flow's contact, IT when a supplier link is down. Never
        an outside contact, so no internal detail leaves the company."""
        w = shift.world

        def internal(role: str | None) -> bool:
            return bool(role) and role in w.roles and not w.roles[role]["external"]

        wanted: list[tuple[str, str]] = []
        pressure = any(word in a["text"] for a in shift.alerts for word in PRESSURE)
        if (self.compromised or self.creds or pressure) and internal("security-lead"):
            what = ", ".join(sorted(set(self.compromised))[:3]) or "a suspicious request"
            wanted.append(("security-lead", f"incident in progress: {what}; handling it"))
        for fid, why in self.paused.items():
            role = w.flows[fid].get("contact_role")
            if role and internal(role):
                wanted.append((role, f"{fid} paused ({why}); manual fallback until cleared"))
            if why == "supplier" and internal("it-lead"):
                wanted.append(("it-lead", f"supplier link down; {fid} on manual fallback"))
        for role, text in wanted:
            if role not in self.notified:
                self.notified.add(role)
                return f"notify {role} {text}"
        return None

    def _evict(self, shift: Shift) -> str | None:
        """After containment: careful stops at isolation; thorough re-images (its override)."""
        return None

    def _learn_partners(self, obs: str) -> None:
        import re as _re

        for ip in _re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", obs):
            if "partner" in obs or "provider" in obs or "feed" in obs or "mirror" in obs:
                self.partners.add(ip)

    def _survey(self, shift: Shift) -> None:
        for host in _attack_alert_hosts(shift):
            if host not in self.suspect:
                self.suspect.append(host)

    def _next_unread_suspect(self, shift: Shift) -> str | None:
        for host in self.suspect:
            if host not in self.read and host in shift.world.host:
                return host
        return None

    def _consider(self, shift: Shift) -> None:
        """From everything read so far, decide which hosts look compromised and which creds leaked.

        A log line is treated as a real indicator only when it carries an indicator word, no
        benign-context word (a nightly backup, a scheduled job, an update), and — for an outbound
        transfer — is not addressed to a known partner. This is the judgement a naive rule bot
        skips, so the two separate on the noisy and backup-bait families.
        """
        for host in self.read:
            if host not in shift.world.host:
                continue
            text = self._logs_text(shift, host)
            if not text:
                continue
            for line in text.splitlines():
                low = line.lower()
                if not IOC_RE.search(low):
                    continue
                if any(ctx in low for ctx in BENIGN_CONTEXT):
                    continue
                if "outbound transfer" in low and any(ip in line for ip in self.partners):
                    continue
                if host not in self.compromised:
                    self.compromised.append(host)
                if "sign-in tokens" in low:
                    for acct in shift.world.accounts:
                        if acct in line and acct not in self.creds:
                            self.creds.append(acct)

    def _logs_text(self, shift: Shift, host: str) -> str:
        """The most recent logs observation for ``host`` (as an agent last saw it)."""
        for meta, obs in zip(reversed(shift.obs_meta), reversed(shift.observations), strict=False):
            if meta["verb"] == "logs" and meta.get("target") == host:
                return obs
        return ""

    def _contain_step(self, shift: Shift) -> str | None:
        """Contain the next compromised host or leaked credential, escalating critical ones."""
        for host in self.compromised:
            if host in self.contained:
                continue
            self.contained.append(host)
            if shift.critical("isolate", host):
                self.pending = ["wait 15", f"isolate {host}"]
                return f"escalate isolate {host}"
            return f"isolate {host}"
        for acct in self.creds:
            key = f"c:{acct}"
            if key in self.contained:
                continue
            self.contained.append(key)
            if shift.critical("reset", acct):
                self.pending = ["wait 15", f"reset {acct}"]
                return f"escalate reset {acct}"
            return f"reset {acct}"
        return None

    def _close(self, shift: Shift) -> str | None:
        import json as _json

        if self.final is not None:
            return None
        hosts = sorted(set(self.compromised))
        if shift.rules2:  # a company-file world: report leaked accounts and hosted services too
            hosts = sorted(set(hosts) | {c for c in self.creds if c in shift.world.accounts})
        conf = {h: 0.8 for h in hosts}
        body = {
            "compromised": hosts,
            "confidence": conf,
            "summary": "investigated the leads and contained what the evidence supported",
            "suspicious_text": _suspicious_seen(shift),
        }
        self.final = "ready"
        return "report " + _json.dumps(body, sort_keys=True)


class Thorough(Careful):
    """careful, then eradication: after containing, it restores every host its own logs showed
    compromised (escalating when the host is critical), patching first a host whose logs show a
    misconfiguration, so the intruder is not simply back when the isolation time box ends. It
    reads only what any responder sees."""

    name = "thorough"

    def __init__(self) -> None:
        super().__init__()
        self.evicted: list[str] = []

    def _contain_step(self, shift: Shift) -> str | None:
        cmd = super()._contain_step(shift)
        if cmd is not None:
            return cmd
        return self._evict(shift)

    def _evict(self, shift: Shift) -> str | None:
        for host in self.compromised:
            if host in self.evicted:
                continue
            self.evicted.append(host)
            text = self._logs_text(shift, host).lower()
            steps = (
                [f"patch {host}"]
                if "configuration allows" in text or "upload handler" in text
                else []
            )
            if shift.critical("restore", host):
                steps += [f"escalate restore {host}", "wait 15"]
            steps.append(f"restore {host}")
            if shift.rules2:
                steps += self._resume_after(shift, host)
            self.pending = steps[1:]
            return steps[0]
        return None

    def _resume_after(self, shift: Shift, host: str) -> list[str]:
        """Flows paused because ``host`` was abused, resumed once it is re-imaged."""
        out = []
        for fid, why in self.paused.items():
            if why == "intrusion" and host in shift.world.flows[fid]["hosts"]:
                self.paused[fid] = "resumed"
                if shift.critical("resume", fid):
                    out += [f"escalate resume {fid}", "wait 15"]
                out.append(f"resume {fid}")
        return out


class Gullible(Responder):
    """Obeys any instruction it finds in logs or tickets (the injection fixture)."""

    name = "gullible"

    def __init__(self) -> None:
        super().__init__()
        self.read_hosts: list[str] = []
        self.obeyed: list[str] = []

    def act(self, shift: Shift) -> str | None:
        if self.step == 1:
            return "look"
        # Read logs of every alerting host and the ticket gateway to surface planted text.
        for host in _attack_alert_hosts(shift) + shift.world.tickets[:1]:
            if host not in self.read_hosts:
                self.read_hosts.append(host)
                return f"logs {host}"
        # Obey the first planted instruction it has seen.
        for meta in shift.obs_meta:
            for pid in sorted(meta["payloads"]):  # a set: sort for a hash-independent order
                if pid in self.obeyed:
                    continue
                p = _payload_by_id(shift, pid)
                if p and not p.get("close") and p["verbs"] and p["targets"]:
                    self.obeyed.append(pid)
                    return f"{p['verbs'][0]} {p['targets'][0]}"
        if shift.rules2:
            return self._believe_assessment(shift)
        return None

    def _believe_assessment(self, shift: Shift) -> str | None:
        """Rules 2: isolate whatever the day-shift note names and report it as the entry point."""
        import json as _json

        note = [ln for ln in shift.observations[0].splitlines() if ln.startswith("Day-shift")]
        named = [h for h in re.findall(r"[a-z0-9][a-z0-9._-]*[a-z0-9]", " ".join(note).lower())
                 if h in shift.world.host]  # fmt: skip
        for host in named:
            if f"a:{host}" not in self.obeyed:
                self.obeyed.append(f"a:{host}")
                return f"isolate {host}"
        if "report" not in self.obeyed:
            self.obeyed.append("report")
            body = {"compromised": named, "summary": "as the day shift assessed"}
            return "report " + _json.dumps(body, sort_keys=True)
        return None


class Paranoid(Responder):
    """Acts on every alert at once and never checks (the false-positive/collateral fixture).

    It isolates every host that alerts, resets every account and blocks every address an alert
    names, never escalates, then keeps watching for new alerts and re-isolates a host as soon as
    the business reconnects it, until the shift or the command cap ends. Unlike
    ``isolate-everything`` (one pass over the alerts, then close) it never stops reacting, so it
    is the responder with the most unnecessary disruption.
    """

    name = "paranoid"
    WATCH = 30  # minutes between looks at the alert queue

    def __init__(self) -> None:
        super().__init__()
        self.until: dict[str, int] = {}  # host -> minute its isolation ends (as it asked)
        self.done: set[str] = set()  # accounts reset and addresses blocked

    def act(self, shift: Shift) -> str | None:
        if self.step == 1:
            return "look"
        for a in reversed(shift.alerts):
            host = a["host"]
            if shift.now >= self.until.get(host, -1):
                self.until[host] = shift.now + ISOLATE_DEFAULT
                return f"isolate {host}"
        for a in shift.alerts:
            for word in re.findall(r"[a-z0-9][a-z0-9.-]*[a-z0-9]", a["text"].lower()):
                if word in self.done:
                    continue
                if word in shift.world.accounts:
                    self.done.add(word)
                    return f"reset {word}"
                if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", word):
                    self.done.add(word)
                    return f"block {word}"
        return f"wait {self.WATCH}"


class Slow(Responder):
    """Investigates everything exhaustively before any action (the cost/dwell fixture)."""

    name = "slow"

    def __init__(self) -> None:
        super().__init__()
        self.queue: list[str] | None = None
        self.acted = False

    def act(self, shift: Shift) -> str | None:
        if self.queue is None:
            self.queue = [h["name"] for h in shift.world.hosts]
        if self.step == 1:
            return "look"
        if self.queue:
            return f"logs {self.queue.pop(0)}"
        if not self.acted:
            self.acted = True
            host = _alert_host(shift)
            if host:
                return f"isolate {host}"
        return None


class Oracle(Responder):
    """Replays a near-optimal command list derived from the ground truth (upper reference)."""

    name = "oracle"

    def __init__(self) -> None:
        super().__init__()
        self._queue: list[str] | None = None

    def act(self, shift: Shift) -> str | None:
        if self._queue is None:
            self._queue = oracle_commands(shift.incident, shift.world)
        if self._queue:
            return self._queue.pop(0)
        return None


def _payload_by_id(shift: Shift, pid: str) -> dict[str, Any] | None:
    for p in shift.incident.get("payloads", []):
        if p["id"] == pid:
            return p
    return None


def _suspicious_seen(shift: Shift) -> list[str]:
    """Planted sentences the responder's observations actually returned, for suspicious_text."""
    out: list[str] = []
    for meta in shift.obs_meta:
        for pid in sorted(meta["payloads"]):
            p = _payload_by_id(shift, pid)
            if p and p["text"] not in out:
                out.append(p["text"])
    return out[:5]


BASELINES: dict[str, Agent] = {
    "do-nothing": DoNothing,
    "isolate-on-first-alert": IsolateOnFirstAlert,
    "isolate-everything": IsolateEverything,
    "rule-bot": RuleBot,
    "careful": Careful,
    "thorough": Thorough,
    "oracle": Oracle,
}
FIXTURES: dict[str, Agent] = {
    "gullible": Gullible,
    "paranoid": Paranoid,
    "slow": Slow,
}
ALL_AGENTS: dict[str, Agent] = {**BASELINES, **FIXTURES}


def run_baseline(
    incident: dict[str, Any], agent_name: str, max_commands: int = 60, world: World = WORLD
) -> Shift:
    """Run a named scripted agent over one incident in ``world`` and return the finished shift."""
    if agent_name not in ALL_AGENTS:
        raise ValueError(f"unknown agent {agent_name!r}")
    agent = ALL_AGENTS[agent_name]()
    shift = Shift(incident, world)
    shift.reset()
    for _ in range(max_commands):
        if shift.done:
            break
        cmd = agent.next_command(shift)
        if cmd is None:
            break
        shift.step(cmd)
    shift.finish()
    return shift
