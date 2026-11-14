"""Signed reports: the GitHub Actions record, the signature check, the signer, the attempt ticket
and history, and a defender that never gets the job's signing tokens. The real Sigstore check runs
in the repository's signed self-test workflow; here the verifier is replaced by a function that
stands in for it, and the public log by an in-memory one."""

from __future__ import annotations

import hashlib
import json
import sys

import pytest
from rckit import FakeRekor

from cyberarena.cli import main
from cyberarena.rc import provenance
from cyberarena.rc.attempt import ticket_digest, ticket_text
from cyberarena.rc.provenance import (
    DRAWN,
    FIXED,
    GIVEN,
    IN_TOTO,
    ProvenanceError,
    attempt_lines,
    check_signature,
    child_env,
    ci_record,
    harness,
    official_problems,
    record_problems,
    summary,
    verify_ticket,
)
from cyberarena.rc.report import report_hash, terminal_summary
from cyberarena.rc.verify import verify

REPO_ID = "1454082854"
GH = {
    "GITHUB_ACTIONS": "true",
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_REPOSITORY": "example-org/defender",
    "GITHUB_REPOSITORY_ID": REPO_ID,
    "GITHUB_SHA": "0123456789abcdef0123456789abcdef01234567",
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_WORKFLOW_REF": "example-org/defender/.github/workflows/flagwake.yml@refs/heads/main",
    "GITHUB_RUN_ID": "123456789",
    "GITHUB_RUN_ATTEMPT": "2",
    "RUNNER_ENVIRONMENT": "github-hosted",
}
RUN = "https://github.com/example-org/defender/actions/runs/123456789/attempts/2"
OFFICIAL = "https://github.com/Sid00011/Flagwake/.github/workflows/check.yml@refs/tags/v0.5.0rc6"


def _signed_report(tmp_path, monkeypatch, *extra, pack="fresh", families=()):
    for k, v in GH.items():
        monkeypatch.setenv(k, v)
    out = tmp_path / "out"
    chosen = [x for f in families for x in ("--family", f)]
    argv = ["check", "--agent", "baseline:careful", "--pack", pack, "--seeds", "1", *chosen,
            "--out", str(out), "--record-ci", *extra]  # fmt: skip
    assert main(argv) == 0
    path = out / "report.json"
    return path, path.read_bytes(), json.loads(path.read_text(encoding="utf-8"))


def _statement(raw: bytes) -> bytes:
    digest = hashlib.sha256(raw).hexdigest()
    return json.dumps({"subject": [{"name": "report.json", "digest": {"sha256": digest}}]}).encode()


def _signer(raw: bytes, signer: str = OFFICIAL, time: int = 100, log_index: int = 7):
    facts = {"build_signer_uri": signer, "time": time, "log_index": log_index}
    return lambda _b, _w: (IN_TOTO, _statement(raw), dict(facts))


def _strong(doc: dict, n: int = 2, log_index: str = "1001") -> dict:
    """The record a run of the official workflow writes: isolated, with an attempt ticket."""
    rec = {**doc["provenance"], "defender_isolation": "separate user flagwake-defender",
           "attempt": str(n), "attempt_ticket": ticket_digest(REPO_ID, n),
           "attempt_log_index": log_index}  # fmt: skip
    out = {**doc, "provenance": rec}
    out["report_hash"] = report_hash(out)
    return out


def test_the_record_is_read_from_the_github_actions_variables():
    rec = ci_record(GH)
    assert rec["ci"] == "github-actions" and rec["repository"] == "example-org/defender"
    assert rec["repository_id"] == REPO_ID
    assert rec["defender_isolation"] == "none" and rec["incidents"] == DRAWN
    assert record_problems(rec) == []
    with pytest.raises(ValueError, match="only inside a GitHub Actions job"):
        ci_record({})
    with pytest.raises(ValueError, match="GITHUB_RUN_ID"):
        ci_record({**GH, "GITHUB_RUN_ID": ""})
    with pytest.raises(ValueError, match="commit"):
        ci_record({**GH, "GITHUB_SHA": "main"})
    for field, value in (("defender_isolation", "root"), ("incidents", "chosen"),
                         ("attempt", "3"), ("repository_id", "abc")):  # fmt: skip
        assert record_problems({**rec, field: value}), field


def test_check_records_the_run_and_the_report_hash_covers_it(tmp_path, monkeypatch):
    _path, _raw, doc = _signed_report(tmp_path, monkeypatch)
    assert doc["provenance"] == {**ci_record(GH), "defender_command": "baseline:careful"}
    assert verify(doc) == []
    assert "made in GitHub Actions: example-org/defender" in terminal_summary(doc, True)
    moved = {**doc, "provenance": {**doc["provenance"], "repository": "someone/else"}}
    assert any("report hash" in p for p in verify(moved))
    odd = {**doc, "provenance": {**doc["provenance"], "run_id": "12x"}}
    odd["report_hash"] = report_hash(odd)
    assert any("run id" in p for p in verify(odd))


def test_the_record_says_how_the_incidents_were_chosen(tmp_path, monkeypatch):
    fresh = _signed_report(tmp_path / "a", monkeypatch)[2]
    given = _signed_report(tmp_path / "b", monkeypatch, "--run-key", "ab" * 16)[2]
    public = _signed_report(tmp_path / "c", monkeypatch, pack="practice")[2]
    forced = _signed_report(tmp_path / "d", monkeypatch, "--difficulty", "standard")[2]
    said = [d["provenance"]["incidents"] for d in (fresh, given, public, forced)]
    assert said == [DRAWN, GIVEN, FIXED, FIXED]  # only fresh seeds from the run's own key are drawn


def test_check_refuses_to_record_outside_github_actions(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    base = ["check", "--agent", "baseline:careful", "--pack", "practice", "--seeds", "1",
            "--out", str(tmp_path / "o")]  # fmt: skip
    assert main([*base, "--record-ci"]) == 2
    assert main([*base, "--attempt-ticket", "ticket.txt"]) == 2  # a ticket needs --record-ci


def test_a_signature_counts_only_for_these_bytes_this_run_and_a_hosted_runner(
    tmp_path, monkeypatch
):
    _path, raw, doc = _signed_report(tmp_path, monkeypatch)
    seen = {}

    def fake(bundle: bytes, want: dict[str, str]):
        seen.update(want)
        return IN_TOTO, _statement(raw), {"build_signer_uri": OFFICIAL}

    assert check_signature(raw, doc, b"{}", "Example-Org/Defender", fake) == (
        [],
        {"build_signer_uri": OFFICIAL},
    )
    assert seen == {
        "issuer": "https://token.actions.githubusercontent.com",
        "repository_uri": "https://github.com/example-org/defender",
        "repository_id": REPO_ID,
        "commit": GH["GITHUB_SHA"],
        "run_uri": RUN,
        "runner": "github-hosted",
    }
    edited = raw.replace(b'"quiet"', b'"quiet" ', 1)
    assert "changed after it was signed" in check_signature(edited, doc, b"{}", None, fake)[0][0]
    assert "not in other/repo" in check_signature(raw, doc, b"{}", "other/repo", fake)[0][0]
    hosted = {**doc, "provenance": {**doc["provenance"], "runner_environment": "self-hosted"}}
    assert "self-hosted" in check_signature(raw, hosted, b"{}", None, fake)[0][0]
    bare = {k: v for k, v in doc.items() if k != "provenance"}
    assert "--record-ci" in check_signature(raw, bare, b"{}", None, fake)[0][0]
    wrong = _strong(doc)
    wrong["provenance"]["attempt_ticket"] = "0" * 64
    assert "does not match" in check_signature(raw, wrong, b"{}", None, fake)[0][0]

    def refuses(_bundle, _want):
        raise ProvenanceError("the signature does not check out: wrong repository")

    assert check_signature(raw, doc, b"{}", None, refuses)[0] == [
        "the signature does not check out: wrong repository"
    ]
    plain = check_signature(raw, doc, b"{}", None, lambda _b, _w: ("text/plain", b"", {}))
    assert "not an attestation" in plain[0][0]


def test_the_signer_tells_whether_flagwakes_own_workflow_ran():
    assert harness({"build_signer_uri": OFFICIAL}) == (
        "Flagwake's signing workflow at release v0.5.0rc6",
        True,
    )
    branch = OFFICIAL.replace("refs/tags/v0.5.0rc6", "refs/heads/main")
    assert harness({"build_signer_uri": branch})[1] is False
    assert "not a release" in harness({"build_signer_uri": branch})[0]
    by_commit = OFFICIAL.replace("refs/tags/v0.5.0rc6", "0123456789abcdef0123456789abcdef01234567")
    assert harness({"build_signer_uri": by_commit})[1] is False  # a commit is not a release tag
    own = "https://github.com/example-org/defender/.github/workflows/flagwake.yml@refs/heads/main"
    assert "own workflow" in harness({"build_signer_uri": own})[0]
    fork = "https://github.com/someone/Flagwake/.github/workflows/check.yml@refs/tags/v9"
    assert harness({"build_signer_uri": fork})[1] is False


def test_require_official_names_every_missing_guarantee(tmp_path, monkeypatch):
    families = ("quiet", "cred-reuse")
    weak = _signed_report(tmp_path / "a", monkeypatch, pack="practice", families=families)[2]
    problems = official_problems(weak["provenance"], {"build_signer_uri": "x"}, weak)
    assert len(problems) == 5  # signer, isolation, fresh incidents, every family, attempt ticket
    strong = _strong(_signed_report(tmp_path / "b", monkeypatch)[2])
    assert official_problems(strong["provenance"], {"build_signer_uri": OFFICIAL}, strong) == []
    key_known = {**strong, "provenance": {**strong["provenance"], "incidents": GIVEN}}
    said = official_problems(key_known["provenance"], {"build_signer_uri": OFFICIAL}, key_known)
    assert said == ["the incidents were not fresh ones drawn in the run"]


def test_the_ticket_must_be_signed_by_this_run_before_the_draw(tmp_path, monkeypatch):
    for k, v in GH.items():
        monkeypatch.setenv(k, v)
    ticket = tmp_path / "attempt-ticket.txt"
    ticket.write_bytes(ticket_text(REPO_ID, 4))
    bundle = tmp_path / "attempt-ticket.sigstore.json"
    bundle.write_text("{}", encoding="utf-8")
    base = ["check", "--agent", "baseline:careful", "--pack", "fresh", "--seeds", "1",
            "--family", "quiet", "--record-ci"]  # fmt: skip
    signed = [*base, "--attempt-ticket", str(ticket), "--attempt-bundle", str(bundle)]

    monkeypatch.setattr(provenance, "_sigstore_verify", _signer(ticket.read_bytes(), log_index=77))
    assert main([*signed, "--out", str(tmp_path / "ok")]) == 0
    rec = json.loads((tmp_path / "ok" / "report.json").read_text(encoding="utf-8"))["provenance"]
    assert (rec["attempt"], rec["attempt_log_index"]) == ("4", "77")
    assert rec["attempt_ticket"] == ticket_digest(REPO_ID, 4)

    # A signature over other bytes, a signature with no public-log entry, a ticket of another
    # repository, a ticket without its signature: no incident is drawn for any of them.
    monkeypatch.setattr(provenance, "_sigstore_verify", _signer(b"another file"))
    assert main([*signed, "--out", str(tmp_path / "x1")]) == 2
    no_log = lambda _b, _w: (IN_TOTO, _statement(ticket.read_bytes()), {})  # noqa: E731
    monkeypatch.setattr(provenance, "_sigstore_verify", no_log)
    assert main([*signed, "--out", str(tmp_path / "x2")]) == 2
    ticket.write_bytes(ticket_text("999", 4))
    monkeypatch.setattr(provenance, "_sigstore_verify", _signer(ticket.read_bytes()))
    assert main([*signed, "--out", str(tmp_path / "x3")]) == 2
    assert main([*base, "--attempt-ticket", str(ticket), "--out", str(tmp_path / "x4")]) == 2
    assert not any((tmp_path / d / "report.json").exists() for d in ("x1", "x2", "x3", "x4"))
    with pytest.raises(ProvenanceError, match="does not check out"):
        verify_ticket(b"t", b"{}", ci_record(GH), _signer(b"other"))


def _log(*tickets: tuple[int, int, int]) -> FakeRekor:
    """A public log holding tickets (number, run id, run attempt) of the report's repository."""
    rekor = FakeRekor()
    for n, run, attempt in tickets:
        rekor.add(ticket_digest(REPO_ID, n), REPO_ID, run=run, attempt=attempt)
    return rekor


def test_the_attempt_history_lists_every_run_and_checks_this_one(tmp_path, monkeypatch):
    _path, _raw, doc = _signed_report(tmp_path, monkeypatch)
    rec = _strong(doc, n=2, log_index="1001")["provenance"]
    rekor = _log((1, 7, 1), (2, 123456789, 2))  # this run's ticket is the second entry: 1001
    problems, lines = attempt_lines(rec, {"time": 100}, rekor.log())
    assert problems == [] and "1 other attempt ticket(s)" in lines[0]
    assert sum("<- this report" in line for line in lines) == 1

    rekor.add(ticket_digest(REPO_ID, 2), REPO_ID, run=99)  # another run took the same number
    rekor.add(ticket_digest(REPO_ID, 2), REPO_ID, run=5, trusted=False)  # a forged one
    problems, lines = attempt_lines(rec, {"time": 100}, rekor.log())
    assert problems == [] and "2 other attempt ticket(s)" in lines[0]  # not the forgery

    # Twenty checks in one run are twenty tickets, not one: a best-of-many cannot hide.
    many = _log((1, 7, 1), *[(2, 123456789, 2)] * 20)
    own = {**rec, "attempt_log_index": "1005"}
    problems, lines = attempt_lines(own, {"time": 100}, many.log())
    assert problems == [] and "20 other attempt ticket(s)" in lines[0]
    assert sum("<- this report" in line for line in lines) == 1

    late = attempt_lines(rec, {"time": 10}, _log((1, 7, 1), (2, 123456789, 2)).log())[0]
    assert any("after the report was signed" in p for p in late)  # the log time is 50
    other_run = attempt_lines(rec, {"time": 100}, _log((1, 7, 1), (2, 55, 1)).log())[0]
    assert any("no ticket 2 signed by this run" in p for p in other_run)
    moved = {**rec, "attempt_log_index": "4242"}
    assert any(
        "not the one the report recorded" in p for p in attempt_lines(moved, {}, rekor.log())[0]
    )
    no_ticket = {**rec, "attempt": "", "attempt_ticket": "", "attempt_log_index": ""}
    assert "not on record" in attempt_lines(no_ticket, {}, rekor.log())[1][0]


def test_verify_with_a_signature_bundle(tmp_path, monkeypatch, capsys):
    path, raw, _doc = _signed_report(tmp_path, monkeypatch)
    bundle = tmp_path / "report.sigstore.json"
    bundle.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(provenance, "_sigstore_verify", _signer(raw, time=1794541414))
    capsys.readouterr()
    repo = GH["GITHUB_REPOSITORY"]
    assert main(["verify", str(path), "--provenance", str(bundle), "--repo", repo]) == 0
    out = capsys.readouterr().out
    assert "signature: made in GitHub Actions" in out and "; signed 2026-11-13 03:43 UTC" in out
    assert "harness: Flagwake's signing workflow at release v0.5.0rc6" in out
    assert "defender: baseline:careful; ran as the harness's own user" in out
    assert "incidents: drawn in the run; pack fresh, 20 incidents in 20 of 20 families" in out
    assert "world: the default company" in out
    assert main(["verify", str(path), "--provenance", str(bundle), "--require-official"]) == 1
    assert "not isolated" in capsys.readouterr().out
    assert main(["verify", str(path)]) == 0
    assert "check that with --provenance" in capsys.readouterr().out
    path.write_bytes(raw + b"\n")  # one byte more: the numbers still verify, the signature not
    assert main(["verify", str(path), "--provenance", str(bundle)]) == 1
    assert "changed after it was signed" in capsys.readouterr().out
    assert main(["verify", str(path), "--repo", "a/b"]) == 2
    assert main(["verify", str(path), "--attempts"]) == 2


def test_verify_survives_a_file_that_is_not_a_report(tmp_path, capsys):
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 100_000, encoding="utf-8")
    assert main(["verify", str(deep)]) == 1
    assert "FAIL" in capsys.readouterr().out


def test_the_model_line_trusts_only_flagwakes_own_agent(tmp_path, monkeypatch):
    _path, _raw, doc = _signed_report(tmp_path, monkeypatch)
    usage = {"model": "m-2026", "endpoint": "models.example", "calls": 3}
    doc["incidents"][0]["usage"] = usage
    facts = {"build_signer_uri": OFFICIAL}
    own = {**doc["provenance"], "defender_command": "reference:model --max-calls 6"}
    (line,) = [x for x in summary(own, facts, doc) if x.startswith("model:")]
    assert "m-2026 at models.example" in line and "Flagwake's own model agent" in line
    # Any other command is the defender's word, whatever it calls itself or imports.
    for command in ("python -m cyberarena.rc.model_agent", "python reference:model", "x"):
        other = {**doc["provenance"], "defender_command": command}
        (line,) = [x for x in summary(other, facts, doc) if x.startswith("model:")]
        assert "the defender (its own word)" in line
    doc["incidents"][0]["usage"] = {"calls": 3}
    assert not any(x.startswith("model:") for x in summary(own, facts, doc))
    doc["incidents"].append("not an incident")  # a hostile file does not stop the summary
    assert summary(own, facts, doc)


def test_without_sigstore_the_check_says_what_to_install(monkeypatch):
    monkeypatch.setitem(sys.modules, "sigstore", None)
    monkeypatch.setitem(sys.modules, "sigstore.models", None)
    with pytest.raises(ProvenanceError, match=r"flagwake\[provenance\]"):
        provenance._sigstore_verify(b"{}", {})


def test_a_defender_never_gets_the_jobs_signing_tokens(monkeypatch):
    from cyberarena.rc.protocol import subprocess_driver_factory
    from cyberarena.rc.runner import run_pack

    assert "ACTIONS_ID_TOKEN_REQUEST_TOKEN" not in child_env(
        {"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "t", "ACTIONS_ID_TOKEN_REQUEST_URL": "u", "PATH": "p"}
    )
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "a-signing-token")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.invalid/token")
    code = (
        "import json, os, sys\nfor line in sys.stdin:\n    m = json.loads(line)\n"
        "    if m.get('type') == 'end': break\n"
        "    seen = 'ACTIONS_ID_TOKEN_REQUEST_TOKEN' in os.environ\n"
        "    print(json.dumps({'cmd': 'wait 2' if seen else 'wait 1'}), flush=True)\n"
    )
    specs = [{"family": "quiet", "seed": 120000, "difficulty": "standard"}]
    result = run_pack(subprocess_driver_factory([sys.executable, "-I", "-c", code], 5.0), specs)
    assert result["transcripts"][0]["commands"][0] == "wait 1"
