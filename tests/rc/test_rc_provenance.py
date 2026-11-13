"""Signed reports: the GitHub Actions record, the signature check, the signer, the attempt history,
and a defender that never gets the job's signing tokens. The real Sigstore check runs in the
repository's signed self-test workflow; here the verifier is replaced by a function that stands in
for it, and the public log by an in-memory one."""

from __future__ import annotations

import hashlib
import json
import sys

import pytest
from test_rc_attempt import FakeRekor

from cyberarena.cli import main
from cyberarena.rc import provenance
from cyberarena.rc.attempt import ticket_digest
from cyberarena.rc.provenance import (
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
)
from cyberarena.rc.report import report_hash, terminal_summary
from cyberarena.rc.verify import verify

GH = {
    "GITHUB_ACTIONS": "true",
    "GITHUB_SERVER_URL": "https://github.com",
    "GITHUB_REPOSITORY": "example-org/defender",
    "GITHUB_SHA": "0123456789abcdef0123456789abcdef01234567",
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_WORKFLOW_REF": "example-org/defender/.github/workflows/flagwake.yml@refs/heads/main",
    "GITHUB_RUN_ID": "123456789",
    "GITHUB_RUN_ATTEMPT": "2",
    "RUNNER_ENVIRONMENT": "github-hosted",
}
RUN = "https://github.com/example-org/defender/actions/runs/123456789/attempts/2"
OFFICIAL = "https://github.com/Sid00011/Flagwake/.github/workflows/check.yml@refs/tags/v0.5.0rc4"


def _signed_report(tmp_path, monkeypatch, *extra):
    for k, v in GH.items():
        monkeypatch.setenv(k, v)
    out = tmp_path / "out"
    argv = ["check", "--agent", "baseline:careful", "--pack", "practice", "--seeds", "1",
            "--family", "quiet", "--family", "cred-reuse", "--out", str(out),
            "--record-ci", *extra]  # fmt: skip
    assert main(argv) == 0
    path = out / "report.json"
    return path, path.read_bytes(), json.loads(path.read_text(encoding="utf-8"))


def _statement(raw: bytes) -> bytes:
    digest = hashlib.sha256(raw).hexdigest()
    return json.dumps({"subject": [{"name": "report.json", "digest": {"sha256": digest}}]}).encode()


def _signer(raw: bytes, signer: str = OFFICIAL, time: int = 100):
    return lambda _b, _w: (IN_TOTO, _statement(raw), {"build_signer_uri": signer, "time": time})


def _strong(doc: dict, n: int = 2, log_index: str = "1001") -> dict:
    """The record a run of the official workflow writes: isolated, with an attempt ticket."""
    rec = {**doc["provenance"], "defender_isolation": "separate user flagwake-defender",
           "attempt": str(n), "attempt_ticket": ticket_digest(GH["GITHUB_REPOSITORY"], n),
           "attempt_log_index": log_index}  # fmt: skip
    out = {**doc, "provenance": rec}
    out["report_hash"] = report_hash(out)
    return out


def test_the_record_is_read_from_the_github_actions_variables():
    rec = ci_record(GH)
    assert rec["ci"] == "github-actions" and rec["repository"] == "example-org/defender"
    assert rec["defender_isolation"] == "none" and rec["incidents"] == "drawn in the run"
    assert record_problems(rec) == []
    with pytest.raises(ValueError, match="only inside a GitHub Actions job"):
        ci_record({})
    with pytest.raises(ValueError, match="GITHUB_RUN_ID"):
        ci_record({**GH, "GITHUB_RUN_ID": ""})
    with pytest.raises(ValueError, match="commit"):
        ci_record({**GH, "GITHUB_SHA": "main"})
    for field, value in (("defender_isolation", "root"), ("incidents", "chosen"),
                         ("attempt", "3")):  # fmt: skip
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


def test_a_given_run_key_is_recorded_as_given(tmp_path, monkeypatch):
    _path, _raw, doc = _signed_report(tmp_path, monkeypatch, "--run-key", "ab" * 16)
    assert doc["provenance"]["incidents"] == GIVEN


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
        "Flagwake's signing workflow at release v0.5.0rc4",
        True,
    )
    branch = OFFICIAL.replace("refs/tags/v0.5.0rc4", "refs/heads/main")
    assert harness({"build_signer_uri": branch})[1] is False
    assert "not a release" in harness({"build_signer_uri": branch})[0]
    own = "https://github.com/example-org/defender/.github/workflows/flagwake.yml@refs/heads/main"
    assert "own workflow" in harness({"build_signer_uri": own})[0]
    fork = "https://github.com/someone/Flagwake/.github/workflows/check.yml@refs/tags/v9"
    assert harness({"build_signer_uri": fork})[1] is False


def test_require_official_names_every_missing_guarantee(tmp_path, monkeypatch):
    _path, _raw, doc = _signed_report(tmp_path, monkeypatch, "--run-key", "ab" * 16)
    problems = official_problems(doc["provenance"], {"build_signer_uri": "x"})
    assert len(problems) == 4  # signer, isolation, incidents and attempt ticket
    strong = _strong(_signed_report(tmp_path / "b", monkeypatch)[2])
    assert official_problems(strong["provenance"], {"build_signer_uri": OFFICIAL}) == []


def _log(*tickets: tuple[int, int, int]) -> FakeRekor:
    """A public log holding tickets (number, run id, run attempt) of the report's repository."""
    rekor = FakeRekor()
    for n, run, attempt in tickets:
        rekor.add(ticket_digest(GH["GITHUB_REPOSITORY"], n), repo=GH["GITHUB_REPOSITORY"],
                  run=run, attempt=attempt)  # fmt: skip
    return rekor


def test_the_attempt_history_shows_earlier_and_duplicate_runs(tmp_path, monkeypatch):
    _path, _raw, doc = _signed_report(tmp_path, monkeypatch)
    rec = _strong(doc, n=2, log_index="1001")["provenance"]
    rekor = _log((1, 7, 1), (2, 123456789, 2))  # this run's ticket is the second entry: 1001
    problems, lines = attempt_lines(rec, {"time": 100}, rekor.log())
    assert problems == [] and "1 earlier attempt(s)" in lines[0]
    assert any("<- this report" in line for line in lines)
    rekor.add(ticket_digest(GH["GITHUB_REPOSITORY"], 2), repo=GH["GITHUB_REPOSITORY"], run=99)
    problems, _ = attempt_lines(rec, {"time": 100}, rekor.log())
    assert any("two runs claimed it" in p for p in problems)
    late = attempt_lines(rec, {"time": 10}, _log((1, 7, 1), (2, 123456789, 2)).log())[0]
    assert any("after the report was signed" in p for p in late)  # the log time is 50
    other_run = attempt_lines(rec, {"time": 100}, _log((1, 7, 1), (2, 55, 1)).log())[0]
    assert any("no ticket 2 signed by this run" in p for p in other_run)
    no_ticket = {**rec, "attempt": "", "attempt_ticket": "", "attempt_log_index": ""}
    assert "not on record" in attempt_lines(no_ticket, {}, rekor.log())[1][0]


def test_verify_with_a_signature_bundle(tmp_path, monkeypatch, capsys):
    path, raw, _doc = _signed_report(tmp_path, monkeypatch)
    bundle = tmp_path / "report.sigstore.json"
    bundle.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(provenance, "_sigstore_verify", _signer(raw))
    capsys.readouterr()
    repo = GH["GITHUB_REPOSITORY"]
    assert main(["verify", str(path), "--provenance", str(bundle), "--repo", repo]) == 0
    out = capsys.readouterr().out
    assert "signature: made in GitHub Actions" in out
    assert "harness: Flagwake's signing workflow at release v0.5.0rc4" in out
    assert "defender: baseline:careful; ran as the harness's own user" in out
    assert main(["verify", str(path), "--provenance", str(bundle), "--require-official"]) == 1
    assert "not isolated" in capsys.readouterr().out
    assert main(["verify", str(path)]) == 0
    assert "check that with --provenance" in capsys.readouterr().out
    path.write_bytes(raw + b"\n")  # one byte more: the numbers still verify, the signature not
    assert main(["verify", str(path), "--provenance", str(bundle)]) == 1
    assert "changed after it was signed" in capsys.readouterr().out
    assert main(["verify", str(path), "--repo", "a/b"]) == 2
    assert main(["verify", str(path), "--attempts"]) == 2


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


def test_the_summary_names_the_model_from_the_hashed_incidents(tmp_path, monkeypatch):
    from cyberarena.rc.provenance import summary

    _path, _raw, doc = _signed_report(tmp_path, monkeypatch)
    rec = {**doc["provenance"], "defender_command": "python -m cyberarena.rc.model_agent"}
    incidents = [{"usage": {"model": "m-2026", "endpoint": "models.example", "calls": 3}}]
    lines = summary(rec, {"build_signer_uri": OFFICIAL}, incidents)
    assert any(
        line.startswith("model: m-2026 at models.example") and "reference model agent" in line
        for line in lines
    )
    assert not any(line.startswith("model:") for line in summary(rec, {}, []))
