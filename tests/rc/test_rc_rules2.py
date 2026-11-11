"""Rules 2: company-file worlds, family binding and skipping, the new commands and measures, and
reports that verify against the same company file."""

from __future__ import annotations

import copy
import json

import pytest

from cyberarena.rc import gen2, rules
from cyberarena.rc.company import CompanyError, parse_text, validate_company
from cyberarena.rc.engine import RULES1_COMMANDS, Shift
from cyberarena.rc.report import build_report, report_hash
from cyberarena.rc.runner import baseline_driver, pack_specs, run_pack
from cyberarena.rc.scoring import damage, damage_terms, score_shift
from cyberarena.rc.verify import verify
from cyberarena.rc.world import WORLD, World, shipped_world, world_from_file
from cyberarena.rc.world_cli import TEMPLATE


def template_doc() -> dict:
    """The template as parsed (raw), for tests that edit a field before validating."""
    return parse_text(TEMPLATE)


def world_of(doc: dict, source: str = "test") -> World:
    return World(validate_company(doc), rules=2, source=source)


@pytest.mark.parametrize("name", ["harlow-pine", "fenwick-brae"])
def test_every_family_binds_in_the_shipped_worlds(name):
    w = shipped_world(name)
    assert rules.families(w) == gen2.FAMILIES and rules.skipped(w) == ()
    assert len(gen2.FAMILIES) == 20


def test_generation_is_deterministic_and_differs_by_world():
    a = gen2.generate("privileged-laptop-to-payments", 120003, "hard", shipped_world())
    b = gen2.generate("privileged-laptop-to-payments", 120003, "hard", shipped_world())
    c = gen2.generate(
        "privileged-laptop-to-payments", 120003, "hard", shipped_world("fenwick-brae")
    )
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert a["world"]["digest"] != c["world"]["digest"]


def test_a_world_without_what_a_family_needs_skips_it_and_says_why():
    doc = template_doc()
    doc["flows"] = [f for f in doc["flows"] if f["kind"] != "payments"]
    for ln in doc["links"]:
        ln["flows"] = [x for x in ln["flows"] if x != "payments"]
    doc["approval"]["rules"] = [r for r in doc["approval"]["rules"] if "flows" not in r]
    doc["calendar"]["windows"] = [x for x in doc["calendar"]["windows"] if x["flow"] != "payments"]
    w = world_of(doc)
    skipped = dict(rules.skipped(w))
    assert "privileged-laptop-to-payments" in skipped
    assert "payments" in skipped["privileged-laptop-to-payments"]
    assert "privileged-laptop-to-payments" not in rules.families(w)
    with pytest.raises(ValueError, match="skipped"):
        rules.generate(w, "privileged-laptop-to-payments", 120000, "standard")
    specs = pack_specs("practice", 1, world=w)
    assert {s["family"] for s in specs} == set(rules.families(w))


def test_an_incident_runs_only_in_the_world_it_was_made_for():
    inc = gen2.generate("quiet", 120000, "standard", shipped_world())
    with pytest.raises(ValueError):
        Shift(inc, WORLD)  # a rules-2 incident in the rules-1 world
    with pytest.raises(ValueError):
        Shift(inc, shipped_world("fenwick-brae"))  # another company file


@pytest.mark.parametrize("name", ["harlow-pine", "fenwick-brae", "legacy"])
def test_a_report_verifies_on_each_shipped_world(name):
    from cyberarena.rc.world import resolve_world

    w = resolve_world(name)
    specs = pack_specs("practice", 1, world=w)
    doc = build_report(run_pack(lambda: baseline_driver("careful"), specs, world=w),
                       {"id": "baseline:careful"}, "practice", world=w)  # fmt: skip
    assert verify(doc) == []
    assert doc.get("rules", 1) == w.rules
    if w.rules == 2:
        assert doc["world"]["digest"] == w.digest and "decisions" in doc["metrics"]
    else:
        assert "decisions" not in doc["metrics"] and "world" not in doc


@pytest.fixture(scope="module")
def report2():
    w = shipped_world()
    specs = pack_specs("practice", 2, world=w)
    return build_report(run_pack(lambda: baseline_driver("careful"), specs, world=w),
                        {"id": "baseline:careful"}, "practice", world=w)  # fmt: skip


@pytest.mark.parametrize(
    "path",
    [
        ("metrics", "decisions", "flows", "net"),
        ("metrics", "decisions", "revision", "anchoring", "num"),
        ("metrics", "decisions", "groundedness", "unsupported", "den"),
        ("metrics", "decisions", "notification", "leaks"),
        ("metrics", "decisions", "damage_terms", "outflow"),
        ("profile", "decisions", "notification", "unneeded"),
    ],
)
def test_editing_a_new_measure_fails_verify(report2, path):
    d = copy.deepcopy(report2)
    node = d
    for k in path[:-1]:
        node = node[k]
    node[path[-1]] = (node[path[-1]] or 0) + 1
    d["report_hash"] = report_hash(d)  # even with a consistent hash, the replay disagrees
    assert verify(d), path


def test_editing_the_world_record_or_the_disclosure_fails_verify(report2):
    # (The adapter and instruction text are the harness's declaration: the report hash guards
    # them. What was sent is re-derived from the transcripts.)
    for key, sub, val in (("world", "hosts", 99), ("integration", "framing_sha256", "0" * 64),
                          ("integration", "sent_sha256", "0" * 64)):  # fmt: skip
        d = copy.deepcopy(report2)
        d[key][sub] = val
        d["report_hash"] = report_hash(d)
        assert verify(d), key


def test_a_custom_world_report_needs_the_same_company_file(tmp_path):
    f = tmp_path / "company.yaml"
    f.write_text(TEMPLATE, encoding="utf-8")
    w = world_from_file(f)
    assert w.custom and w.summary()["custom"]
    specs = pack_specs("practice", 1, world=w)[:4]
    doc = build_report(run_pack(lambda: baseline_driver("careful"), specs, world=w),
                       {"id": "baseline:careful"}, "practice", world=w)  # fmt: skip
    assert "custom company" in verify(doc)[0]
    assert verify(doc, f) == []
    f.write_text(TEMPLATE.replace("criticality: 3 ", "criticality: 2 ", 1), encoding="utf-8")
    assert "differs" in verify(doc, f)[0]


def test_custom_costs_change_the_damage_and_are_flagged():
    doc = template_doc()
    plain = world_of(copy.deepcopy(doc))
    doc["cost"] = {"weights": {"hold": 5}}
    costly = world_of(doc)
    assert costly.summary()["custom_costs"] and not plain.summary()["custom_costs"]
    from cyberarena.rc.cli import world_lines

    assert any("custom costs" in line for line in world_lines(costly))
    inc_p = rules.generate(plain, "signal-in-the-flood", 120001, "standard")
    inc_c = rules.generate(costly, "signal-in-the-flood", 120001, "standard")
    sp, sc = Shift(inc_p, plain), Shift(inc_c, costly)
    for s in (sp, sc):
        s.reset()
        s.finish()
    assert damage_terms(sc)["hold"] == damage_terms(sp)["hold"] * 5 // 2


def test_damage_terms_add_up_to_the_damage():
    w = shipped_world()
    for fam in ("privileged-laptop-to-payments", "backup-targeting", "supplier-down-spreading"):
        inc = rules.generate(w, fam, 120002, "standard")
        s = Shift(inc, w)
        s.reset()
        s.step("look")
        s.finish()
        assert sum(damage_terms(s).values()) == damage(s) > 0


def _shift(fam: str, seed: int = 120000, diff: str = "standard") -> Shift:
    w = shipped_world()
    s = Shift(rules.generate(w, fam, seed, diff), w)
    s.reset()
    return s


def test_pause_stops_the_outflow_and_costs_the_flow():
    s = next(x for x in (_shift("privileged-laptop-to-payments", 120000 + i) for i in range(10))
             if x.siphons)  # fmt: skip
    flow = s.siphons[0]["flow"]
    obs, _ = s.step(f"pause {flow}")
    assert "Paused" in obs["text"] and "without approval" in obs["text"]  # the policy marks it
    s.step("wait 60")
    s.step(f"resume {flow}")
    s.finish()
    d = score_shift(s)["decisions"]["flows"]
    # paused at the pause command, resumed after its own minute and the 60-minute wait
    assert d["pause_cost"] == 61 * shipped_world().flows[flow]["pause_cost_per_minute"]
    assert d["outflow_prevented"] > 0 and d["pauses"] == 1


def test_a_flow_without_a_fallback_cannot_be_paused():
    s = _shift("quiet")
    stuck = next(f for f, x in s.world.flows.items() if not x["pausable"])
    obs, _ = s.step(f"pause {stuck}")
    assert "cannot be paused" in obs["text"] and not s.actions


def test_notify_reaches_roles_and_a_detail_to_an_outsider_is_a_leak():
    s = _shift("supplier-down-spreading")
    outside = next(r for r, x in s.world.roles.items() if x["external"])
    s.step("notify ops-lead dispatch moved to the manual fallback")
    host = s.world.host_names[0]
    s.step(f"notify {outside} we see trouble on {host}")
    s.step("notify nobody-here hello")
    s.finish()
    n = score_shift(s)["decisions"]["notify"]
    assert n["sent"] == 2 and n["leaks"] == 1 and n["reached"] >= 1


def test_the_rules1_world_does_not_know_the_new_commands():
    from cyberarena.rc.generator import generate

    s = Shift(generate("quiet", 120000, "standard"), WORLD)
    s.reset()
    obs, _ = s.step("pause orders")
    assert obs["text"].startswith("Unknown command")
    s.finish()
    out = score_shift(s)
    assert out["cost"]["unrecognised_commands"] == 1 and "decisions" not in out
    assert s.commands_known == RULES1_COMMANDS


def test_an_unsupported_claim_and_an_anchored_report_are_counted():
    s = _shift("privileged-laptop-to-payments", 120001, "hard")  # hard: the assessment is wrong
    wrong = s.incident["truth"]["revision"]["superseded"][0]
    s.step(json_report([wrong, "dc-01"]))
    out = score_shift(s)["decisions"]
    assert out["revision"]["anchored"] and wrong in out["grounded"]["unsupported"]


def json_report(hosts: list[str]) -> str:
    return "report " + json.dumps({"compromised": hosts})


def test_a_source_gap_hides_the_lines_written_in_it():
    doc = template_doc()
    w = world_of(doc)
    s = Shift(rules.generate(w, "stolen-sign-in-saas", 120000, "standard"), w)
    s.reset()
    gaps = [g for src in w.log_sources for g in src["gaps"]]
    assert gaps  # the template gives the network source a gap
    src = next(x for x in w.log_sources if x["gaps"])
    a, _b = src["gaps"][0]
    minute = (a - w.shift_start) % 1440
    assert s._in_gap(src["source"], minute) and not s._in_gap(src["source"], minute - 1)


def test_hostile_text_in_a_company_file_is_rejected_or_inert():
    doc = template_doc()
    doc["hosts"][0]["label"] = "web\x1b[31m"
    with pytest.raises(CompanyError, match="control"):
        validate_company(doc)
    doc = template_doc()
    doc["company"]["name"] = "<script>alert(1)</script> Ltd"
    w = world_of(doc)
    specs = pack_specs("practice", 1, world=w)[:2]
    rep = build_report(run_pack(lambda: baseline_driver("careful"), specs, world=w),
                       {"id": "baseline:careful"}, "practice", world=w)  # fmt: skip
    from cyberarena.rc.html import build_html

    page = build_html(rep, True)
    assert "<script>alert(1)" not in page


def test_plain_word_lists_parse_in_company_files():
    doc = parse_text('schema: x\nusers: [a.b, svc-1, "q r"]\nnone: []\n')
    assert doc["users"] == ["a.b", "svc-1", "q r"] and doc["none"] == []


def test_an_escalation_reveals_nothing_the_defender_was_not_shown():
    """Rules 2: the approver decides on the evidence the requester had seen, never on where the
    intruder really is, so spamming escalations at minute 0 is not a free oracle."""
    w = shipped_world()
    for fam, seed in (("privileged-laptop-to-payments", 120001), ("signal-in-the-flood", 120001),
                      ("approval-required", 120001), ("quiet", 120000)):  # fmt: skip
        s = Shift(rules.generate(w, fam, seed, "standard"), w)
        s.reset()
        critical = [h for h in w.host_names if s.critical("isolate", h)]
        critical += [a for a in sorted(w.admins) if s.critical("reset", a)]
        for t in critical:
            verb = "reset" if t in w.admins else "isolate"
            s.step(f"escalate {verb} {t}")
        s.step("wait 20")
        shown = s._seen_names  # what the opening alerts named, before any investigation
        for r in s.requests:
            assert (r["state"] == "granted") == (r["target"] in shown), (fam, r)
            assert "intruder" not in r["reason"] and "misused" not in r["reason"]


def test_the_approver_grants_on_shown_evidence_even_for_a_clean_host():
    w = shipped_world()
    # A real traveller's sign-in raises a harmless alert on the remote-access gateway (critical).
    s = Shift(rules.generate(w, "travelling-insider", 120000, "standard"), w)
    s.reset()
    truth = set(s.incident["truth"]["compromised"])
    clean = [a["host"] for a in s.alerts if a["host"] not in truth and s.critical("isolate",
             a["host"])]  # fmt: skip
    assert clean == ["vpn-01"]
    s.step(f"escalate isolate {clean[0]}")
    s.step("wait 20")
    assert s.requests[0]["state"] == "granted"  # judged on what was shown; isolating it is
    s.step(f"isolate {clean[0]}")  # then scored as an action on a clean target
    s.finish()
    assert score_shift(s)["containment"]["false_containment_actions"] == 1


def test_wording_variants_keep_the_facts_and_vary_by_incident():
    """Each paraphrase keeps the same slots and indicator words as the base line, pick() is
    deterministic, and the same event reads differently across incidents."""
    from cyberarena.rc import text2

    assert text2.VARIANTS and text2.check_tables() == []  # filled and valid
    # Deterministic, and every wording (base + variants) is reachable across styles.
    base = text2.pick("log.tokens-read", "s/1", host="h1", acct="a1")
    assert base == text2.pick("log.tokens-read", "s/1", host="h1", acct="a1")
    seen = {text2.pick("log.tokens-read", f"s/{i}", host="h1", acct="a1") for i in range(50)}
    assert len(seen) == 1 + len(text2.VARIANTS["log.tokens-read"])
    assert all("sign-in tokens" in s for s in seen)  # the indicator survives every wording
    # The validator rejects a variant that drops the indicator or changes the slots.
    saved = dict(text2.VARIANTS)
    try:
        text2.VARIANTS["log.bulk-read"] = ["{host} looked at some records"]  # no "bulk read"
        assert any("indicator" in p for p in text2.check_tables())
        text2.VARIANTS["log.bulk-read"] = ["{acct} bulk read of records"]  # wrong slot
        assert any("slots" in p for p in text2.check_tables())
    finally:
        text2.VARIANTS.clear()
        text2.VARIANTS.update(saved)


def test_the_same_incident_reads_differently_across_seeds():
    """Across incidents of one family, an attacker line appears in more than one wording, so a
    fixed-string shortcut cannot identify the compromised host."""
    w = shipped_world()
    lines = set()
    for seed in range(120000, 120010):
        inc = rules.generate(w, "cred-reuse", seed, "standard")
        for rows in inc["logs"].values():
            lines |= {r[1] for r in rows if "sign-in tokens" in r[1] or "bulk read" in r[1]}
        for m in inc["moves"]:
            lines |= {row[2] for row in m.get("logs", []) if "sign-in tokens" in row[2]}
    # more than one distinct wording of the token-theft / bulk-read events across the ten incidents
    assert len({_strip_hosts(ln) for ln in lines}) >= 2


def _strip_hosts(line: str) -> str:
    import re as _re

    return _re.sub(r"\b[a-z]+-[a-z0-9]+\b", "H", line)


def test_routine_log_lines_fit_the_machine_and_the_hour():
    """Mail lines belong to the mail gateway, office sign-ins to a desk in office hours and the
    nightly backup to the night; only the two bait slots carry an indicator word."""
    from cyberarena.rc import text2

    noon, night = 12 * 60, 3 * 60
    assert text2.routine("traffic", "mail", noon) == "mail delivered"
    assert text2.routine("sign-in", "workstation", noon) == "user signed in from the office"
    assert text2.routine("sign-in", "workstation", night) != "user signed in from the office"
    assert "nightly" in text2.routine("bulk-read", "files", night)
    assert "nightly" not in text2.routine("bulk-read", "files", noon)
    kinds = ("workstation", "database", "web", "remote-access", "mail", "app", "files", "print",
             "identity", "backup", "monitoring", "server", "ci", "payments", "")  # fmt: skip
    for kind in kinds:
        for minute in range(0, 1440, 30):
            for slot in text2.ROUTINE_SLOTS:
                line = text2.routine(slot, kind, minute)
                assert ("mail delivered" in line) <= (kind == "mail"), (kind, line)
                assert ("bulk read" in line) == (slot == "bulk-read"), (slot, line)
                assert ("archive written" in line) == (slot == "archive"), (slot, line)
            for slot in ("bulk-read", "archive"):  # bait keeps an ordinary-context word beside it
                low = text2.routine(slot, kind, minute)
                assert any(c in low for c in ("nightly", "backup job", "scheduled")), low


@pytest.mark.parametrize("name", ["harlow-pine", "fenwick-brae"])
def test_generated_routine_lines_are_plausible(name):
    from cyberarena.rc.text2 import NIGHT_HOURS, OFFICE_HOURS

    w = shipped_world(name)
    for fam in rules.families(w):
        inc = rules.generate(w, fam, 120003, "hard")
        for host, rows in inc["logs"].items():
            for minute, text, tag in rows:
                if tag or host not in w.host:
                    continue
                of_day = (inc["start"] + minute) % 1440
                kind = w.host[host]["kind"]
                if "mail delivered" in text:
                    assert kind == "mail", text
                if "signed in from the office" in text:
                    assert kind == "workstation" and of_day in OFFICE_HOURS, (text, of_day)
                if "nightly" in text:
                    assert any(of_day in r for r in NIGHT_HOURS), (text, of_day)
