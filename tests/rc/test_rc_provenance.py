"""Signed reports: the GitHub Actions record, the signature check, and a defender that never gets
the job's signing tokens. The real Sigstore check runs in the repository's signed self-test
workflow; here the verifier is replaced by a function that stands in for it."""

from __future__ import annotations

import hashlib
import json
import sys

import pytest

from cyberarena.cli import main
from cyberarena.rc import provenance
from cyberarena.rc.provenance import (
    IN_TOTO,
    ProvenanceError,
    check_signature,
    child_env,
    ci_record,
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


def _signed_report(tmp_path, monkeypatch):
    for k, v in GH.items():
        monkeypatch.setenv(k, v)
    out = tmp_path / "out"
    argv = ["check", "--agent", "baseline:careful", "--pack", "practice", "--seeds", "1",
            "--family", "quiet", "--family", "cred-reuse", "--out", str(out),
            "--record-ci"]  # fmt: skip
    assert main(argv) == 0
    path = out / "report.json"
    return path, path.read_bytes(), json.loads(path.read_text(encoding="utf-8"))


def _statement(raw: bytes) -> bytes:
    digest = hashlib.sha256(raw).hexdigest()
    return json.dumps({"subject": [{"name": "report.json", "digest": {"sha256": digest}}]}).encode()


def test_the_record_is_read_from_the_github_actions_variables():
    rec = ci_record(GH)
    assert rec["ci"] == "github-actions" and rec["repository"] == "example-org/defender"
    assert record_problems(rec) == []
    with pytest.raises(ValueError, match="only inside a GitHub Actions job"):
        ci_record({})
    with pytest.raises(ValueError, match="GITHUB_RUN_ID"):
        ci_record({**GH, "GITHUB_RUN_ID": ""})
    with pytest.raises(ValueError, match="commit"):
        ci_record({**GH, "GITHUB_SHA": "main"})


def test_check_records_the_run_and_the_report_hash_covers_it(tmp_path, monkeypatch):
    _path, _raw, doc = _signed_report(tmp_path, monkeypatch)
    assert doc["provenance"] == ci_record(GH)
    assert verify(doc) == []
    assert "made in GitHub Actions: example-org/defender" in terminal_summary(doc, True)
    moved = {**doc, "provenance": {**doc["provenance"], "repository": "someone/else"}}
    assert any("report hash" in p for p in verify(moved))
    odd = {**doc, "provenance": {**doc["provenance"], "run_id": "12x"}}
    odd["report_hash"] = report_hash(odd)
    assert any("run id" in p for p in verify(odd))


def test_check_refuses_to_record_outside_github_actions(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    argv = ["check", "--agent", "baseline:careful", "--pack", "practice", "--seeds", "1",
            "--out", str(tmp_path / "o"), "--record-ci"]  # fmt: skip
    assert main(argv) == 2


def test_a_signature_counts_only_for_these_bytes_this_run_and_a_hosted_runner(
    tmp_path, monkeypatch
):
    _path, raw, doc = _signed_report(tmp_path, monkeypatch)
    seen = {}

    def fake(bundle: bytes, want: dict[str, str]) -> tuple[str, bytes]:
        seen.update(want)
        return IN_TOTO, _statement(raw)

    assert check_signature(raw, doc, b"{}", "Example-Org/Defender", fake) == []
    assert seen == {
        "issuer": "https://token.actions.githubusercontent.com",
        "repository_uri": "https://github.com/example-org/defender",
        "commit": GH["GITHUB_SHA"],
        "run_uri": "https://github.com/example-org/defender/actions/runs/123456789/attempts/2",
        "runner": "github-hosted",
    }
    edited = raw.replace(b'"quiet"', b'"quiet" ', 1)
    assert "changed after it was signed" in check_signature(edited, doc, b"{}", None, fake)[0]
    assert "not in other/repo" in check_signature(raw, doc, b"{}", "other/repo", fake)[0]
    hosted = {**doc, "provenance": {**doc["provenance"], "runner_environment": "self-hosted"}}
    assert "self-hosted" in check_signature(raw, hosted, b"{}", None, fake)[0]
    bare = {k: v for k, v in doc.items() if k != "provenance"}
    assert "--record-ci" in check_signature(raw, bare, b"{}", None, fake)[0]

    def refuses(_bundle, _want):
        raise ProvenanceError("the signature does not check out: wrong repository")

    assert check_signature(raw, doc, b"{}", None, refuses) == [
        "the signature does not check out: wrong repository"
    ]
    assert (
        "not an attestation"
        in check_signature(raw, doc, b"{}", None, lambda _b, _w: ("text/plain", _statement(raw)))[0]
    )


def test_verify_with_a_signature_bundle(tmp_path, monkeypatch, capsys):
    path, raw, _doc = _signed_report(tmp_path, monkeypatch)
    bundle = tmp_path / "report.sigstore.json"
    bundle.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(provenance, "_sigstore_verify", lambda _b, _w: (IN_TOTO, _statement(raw)))
    capsys.readouterr()
    assert (
        main(["verify", str(path), "--provenance", str(bundle), "--repo", GH["GITHUB_REPOSITORY"]])
        == 0
    )
    assert "signature OK: made in GitHub Actions" in capsys.readouterr().out
    assert main(["verify", str(path)]) == 0
    assert "check that with --provenance" in capsys.readouterr().out
    path.write_bytes(raw + b"\n")  # one byte more: the numbers still verify, the signature not
    assert main(["verify", str(path), "--provenance", str(bundle)]) == 1
    assert "changed after it was signed" in capsys.readouterr().out
    assert main(["verify", str(path), "--repo", "a/b"]) == 2


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
