"""A company file is untrusted input: whatever is put in any field, the checker answers with a
list of plain problems (``CompanyError``) or a normalised document, never another exception."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from cyberarena.rc.company import CompanyError, load_company, parse_text, validate_company
from cyberarena.rc.world import SHIPPED
from cyberarena.rc.world_cli import TEMPLATE

JUNK: tuple[Any, ...] = (
    None, [], {}, [1], {"a": 1}, 5, -1, 10**12, 1.5, True, "", "x", "X Y", "a" * 5000,
    ["a", ["b"]], [{"id": []}], [None], {"id": {}}, "‮", "02:10", "99:99",
)  # fmt: skip


def _paths(node: Any, prefix: tuple = ()) -> list[tuple]:
    """Every path into a JSON document, parents before children."""
    out = [prefix] if prefix else []
    if isinstance(node, dict):
        for k, v in node.items():
            out += _paths(v, (*prefix, k))
    elif isinstance(node, list):
        for i, v in enumerate(node[:3]):  # the first few entries of each list are enough
            out += _paths(v, (*prefix, i))
    return out


def _put(doc: Any, path: tuple, value: Any) -> Any:
    doc = copy.deepcopy(doc)
    node = doc
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] = value
    return doc


def _checked(doc: Any) -> list[str]:
    """The problems found (empty when the document is accepted); anything else is a bug."""
    try:
        out = validate_company(doc)
    except CompanyError as exc:
        assert exc.problems and all(isinstance(p, str) and len(p) < 400 for p in exc.problems)
        return exc.problems
    json.dumps(out)  # a normalised document is plain JSON
    return []


def test_the_template_is_valid_and_normalising_is_stable():
    doc = parse_text(TEMPLATE)
    once = validate_company(doc)
    assert _checked(doc) == [] and validate_company(copy.deepcopy(doc)) == once


def test_any_value_in_any_field_gets_problems_not_a_crash():
    base = parse_text(TEMPLATE)
    tried = 0
    for path in _paths(base):
        for junk in JUNK:
            _checked(_put(base, path, junk))
            tried += 1
    assert tried > 2000


@pytest.mark.parametrize("junk", JUNK)
def test_any_top_level_document_gets_problems_not_a_crash(junk):
    assert _checked(junk) or junk == {}  # nothing here is a company; {} only lacks fields
    assert _checked({}) != []


def test_extra_fields_duplicates_and_dangling_names_are_named_plainly():
    base = parse_text(TEMPLATE)
    host0 = base["hosts"][0]["id"]

    def problems(change) -> str:
        doc = copy.deepcopy(base)
        change(doc)
        return "\n".join(_checked(doc))

    assert "unknown field" in problems(lambda d: d["hosts"][0].update(colour="blue"))
    assert "used twice" in problems(lambda d: d["hosts"].append(copy.deepcopy(d["hosts"][0])))
    assert "not in zones" in problems(lambda d: d["hosts"][0].update(zone="nowhere"))
    assert "not in people" in problems(lambda d: d["hosts"][0].update(custodian="nobody"))
    assert "is missing" in problems(lambda d: d.pop("zones"))
    assert "at least one host" in problems(lambda d: d.update(hosts=[]))
    assert (
        "both a host"
        in problems(lambda d: d["people"][0].update(account=host0) if "." not in host0 else None)
        or "." in host0
    )
    assert "documentation ranges" in problems(
        lambda d: [ln.update(address="8.8.8.8") for ln in d.get("links", [])]
    ) or not base.get("links")
    assert "whole number" in problems(lambda d: d["hosts"][0].update(criticality=9))
    assert "more than" in problems(lambda d: d.update(zones=[d["zones"][0]] * 500))


def test_a_file_that_cannot_be_read_or_parsed_is_a_plain_problem(tmp_path):
    missing = tmp_path / "none.yaml"
    with pytest.raises(CompanyError, match="cannot read"):
        load_company(missing)
    bad = tmp_path / "bad.yaml"
    bad.write_bytes(b"\xff\xfe not text")
    with pytest.raises(CompanyError, match="UTF-8"):
        load_company(bad)
    big = tmp_path / "big.yaml"
    big.write_bytes(b"#" * 2_000_001)
    with pytest.raises(CompanyError, match="larger than 2 MB"):
        load_company(big)
    broken = tmp_path / "broken.json"
    broken.write_text('{"schema": ', encoding="utf-8")
    with pytest.raises(CompanyError, match="not valid JSON"):
        load_company(broken)


@pytest.mark.parametrize("name", SHIPPED)
def test_the_shipped_companies_pass_their_own_checker(name):
    from cyberarena.rc.world import WORLDS_DIR, shipped_world

    doc = load_company(WORLDS_DIR / f"{name}.json")
    assert doc == shipped_world(name).doc
