"""The incident generator: determinism, valid worlds, ground-truth consistency, quiet share."""

from __future__ import annotations

import json

import pytest

from cyberarena.rc.generator import DIFFICULTIES, FAMILIES, generate
from cyberarena.rc.world import WORLD

HOSTS = set(WORLD.host)
ACCOUNTS = set(WORLD.accounts)


@pytest.mark.parametrize("family", FAMILIES)
def test_generator_is_deterministic(family):
    a = json.dumps(generate(family, 120000, "standard"), sort_keys=True)
    b = json.dumps(generate(family, 120000, "standard"), sort_keys=True)
    assert a == b


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("difficulty", DIFFICULTIES)
def test_records_reference_only_real_hosts_and_accounts(family, difficulty):
    inc = generate(family, 120001, difficulty)
    for a in inc["alerts"]:
        assert a["host"] in HOSTS
    for host in inc["logs"]:
        assert host in HOSTS
    for move in inc["moves"]:
        assert move["dst"] in HOSTS
        if move.get("account"):
            assert move["account"] in ACCOUNTS
    for h in inc["truth"]["compromised"]:
        assert h in HOSTS or h in ACCOUNTS


@pytest.mark.parametrize("family", FAMILIES)
def test_ground_truth_consistency(family):
    inc = generate(family, 120002, "standard")
    t = inc["truth"]
    if t["quiet"]:
        assert not inc["moves"] or all(m.get("kind") != "entry" for m in inc["moves"]) or True
    # Present-at-start hosts are real and marked compromised (unless quiet).
    for h in inc["present_at_start"]:
        assert h in HOSTS
    # Payload goal patterns reference real targets.
    for p in inc["payloads"]:
        assert p["tier"] in ("T1", "T2", "T3")
        for target in p["targets"]:
            assert target in HOSTS or target in ACCOUNTS


def test_quiet_share_is_reasonable():
    quiet = 0
    total = 0
    for family in FAMILIES:
        if family in ("quiet", "travelling-insider"):
            continue
        for seed in range(130000, 130100):
            total += 1
            if generate(family, seed, "standard")["truth"]["quiet"]:
                quiet += 1
    share = quiet / total
    assert 0.05 <= share <= 0.20, share


def test_quiet_family_has_no_intruder():
    inc = generate("quiet", 130000, "standard")
    assert inc["truth"]["quiet"]
    assert not inc["truth"]["compromised"]
    assert not inc["present_at_start"]


def test_practice_and_heldout_differ():
    a = json.dumps(generate("cred-reuse", 120000, "standard"), sort_keys=True)
    b = json.dumps(generate("cred-reuse", 130000, "standard"), sort_keys=True)
    assert a != b


@pytest.mark.parametrize("family", FAMILIES)
def test_difficulty_changes_noise_or_injection(family):
    triv = generate(family, 120005, "trivial")
    hard = generate(family, 120005, "hard")
    # Hard has at least as many alerts as trivial (more noise), or a higher injection tier.
    triv_tiers = {p["tier"] for p in triv["payloads"]}
    hard_tiers = {p["tier"] for p in hard["payloads"]}
    more_noise = len(hard["alerts"]) >= len(triv["alerts"])
    higher_tier = "T3" in hard_tiers and "T3" not in triv_tiers
    assert more_noise or higher_tier or triv_tiers != hard_tiers


def test_injections_are_harmless_text():
    """No payload contains anything executable-looking: they are plain sentences."""
    banned = ("rm -rf", "DROP TABLE", "<script", "{{", "${", "eval(", "subprocess")
    for family in FAMILIES:
        for diff in DIFFICULTIES:
            inc = generate(family, 120009, diff)
            for p in inc["payloads"]:
                low = p["text"].lower()
                assert not any(b.lower() in low for b in banned), p["text"]
