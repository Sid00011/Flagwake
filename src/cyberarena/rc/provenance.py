"""Who made a report: a record of the GitHub Actions run, and a check of its signature.

``flagwake check --record-ci`` (the Flagwake GitHub Action passes it) adds a ``provenance`` block
to the report: the repository, commit, workflow and run that produced it. The block is hashed with
the rest of the report, and the action then signs report.json with a GitHub artifact attestation
(Sigstore). ``flagwake verify report.json --provenance report.sigstore.json`` checks that
signature: it was issued to a GitHub Actions run on a GitHub-hosted runner, for exactly the
repository, commit, run and attempt the block names, over exactly these bytes. Without a signature
the block is only a claim, and verify says so.

What a valid signature shows: these numbers came out of that run of that public workflow at that
commit, on a machine the repository's maintainers did not control, and nothing was edited
afterwards.
What it cannot show: that the defender code at that commit is honest (read it: it is public at that
commit) or how many runs were made before this one (see the repository's run history).

Checking needs the optional ``sigstore`` package (``pip install "flagwake[provenance]"``) and
works offline: it uses the trust root shipped with that package and the transparency-log proof
inside the signature bundle.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from collections.abc import Callable, Mapping
from typing import Any

CI = "github-actions"
GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
IN_TOTO = "application/vnd.in-toto+json"
# Report field -> the GitHub Actions variable it is read from.
ENV = {
    "server": "GITHUB_SERVER_URL",
    "repository": "GITHUB_REPOSITORY",
    "commit": "GITHUB_SHA",
    "ref": "GITHUB_REF",
    "workflow_ref": "GITHUB_WORKFLOW_REF",
    "run_id": "GITHUB_RUN_ID",
    "run_attempt": "GITHUB_RUN_ATTEMPT",
    "runner_environment": "RUNNER_ENVIRONMENT",
}
# What a job uses to obtain a signing identity. A defender process is never given them, so it
# cannot sign files as the job.
SIGNING_ENV = ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL")
MAX_FIELD = 300

Verifier = Callable[[bytes, dict[str, str]], tuple[str, bytes]]


class ProvenanceError(Exception):
    """The signature could not be checked or did not check out."""


def ci_record(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """The provenance block for the GitHub Actions job this runs in (ValueError elsewhere)."""
    env = os.environ if env is None else env
    if env.get("GITHUB_ACTIONS") != "true":
        raise ValueError("--record-ci works only inside a GitHub Actions job")
    rec = {"ci": CI}
    for field, var in ENV.items():
        value = env.get(var, "")
        if not value or len(value) > MAX_FIELD:
            raise ValueError(f"the GitHub Actions variable {var} is not set")
        rec[field] = value
    problems = record_problems(rec)
    if problems:
        raise ValueError(problems[0])
    return rec


def record_problems(rec: Any) -> list[str]:
    """What is wrong with a provenance block's shape (empty when it is well formed)."""
    if not isinstance(rec, dict) or rec.get("ci") != CI:
        return ["the provenance block is not a GitHub Actions record"]
    if set(rec) != {"ci", *ENV}:
        return ["the provenance block does not have exactly the GitHub Actions fields"]
    if not all(isinstance(rec[f], str) and 0 < len(rec[f]) <= MAX_FIELD for f in ENV):
        return ["a provenance field is empty or not text"]
    if not re.fullmatch(r"[0-9a-f]{40}", rec["commit"]):
        return ["the provenance commit is not a full commit id"]
    if not (rec["run_id"].isascii() and rec["run_id"].isdigit()):
        return ["the provenance run id is not a number"]
    if not (rec["run_attempt"].isascii() and rec["run_attempt"].isdigit()):
        return ["the provenance run attempt is not a number"]
    if not re.fullmatch(r"https://[A-Za-z0-9.-]+", rec["server"]):
        return ["the provenance server is not an https address"]
    return []


def describe(rec: dict[str, str]) -> str:
    """One line: where the report says it was made."""
    return (
        f"made in GitHub Actions: {rec['repository']} at commit {rec['commit'][:12]}, "
        f"run {rec['run_id']} (attempt {rec['run_attempt']}, {rec['runner_environment']} runner)"
    )


def child_env(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """The environment a defender process gets: the given one (or ours) without signing tokens."""
    out = dict(os.environ if env is None else env)
    for name in SIGNING_ENV:
        out.pop(name, None)
    return out


def expected(rec: dict[str, str]) -> dict[str, str]:
    """What the signing certificate must say for a report that carries this record."""
    repo_uri = f"{rec['server']}/{rec['repository']}"
    return {
        "issuer": GITHUB_ISSUER,
        "repository_uri": repo_uri,
        "commit": rec["commit"],
        "run_uri": f"{repo_uri}/actions/runs/{rec['run_id']}/attempts/{rec['run_attempt']}",
        "runner": "github-hosted",  # a self-hosted runner is their own machine
    }


def check_signature(
    report_bytes: bytes,
    doc: dict[str, Any],
    bundle_bytes: bytes,
    repo: str | None = None,
    verify_dsse: Verifier | None = None,
) -> list[str]:
    """Problems with a report's signature (empty when it checks out).

    ``report_bytes`` are the report file exactly as signed; ``doc`` is the same file parsed;
    ``repo`` (org/repo), when given, is the repository the reader expects.
    """
    rec = doc.get("provenance")
    if rec is None:
        return ["the report has no provenance block (it was made without --record-ci)"]
    problems = record_problems(rec)
    if problems:
        return problems
    if repo is not None and repo.lower() != rec["repository"].lower():
        return [f"the report was made in {rec['repository']}, not in {repo}"]
    if rec["runner_environment"] != "github-hosted":
        return ["the report was made on a self-hosted runner, a machine the repository's "
                "maintainers control, so a signature cannot vouch for the run"]  # fmt: skip
    digest = hashlib.sha256(report_bytes).hexdigest()
    refused: list[str] = []
    other_bytes: list[str] = []
    for bundle in split_bundles(bundle_bytes):  # any one valid signature is enough
        try:
            payload_type, payload = (verify_dsse or _sigstore_verify)(bundle, expected(rec))
        except ProvenanceError as exc:
            refused.append(str(exc))
            continue
        problems = statement_problems(payload_type, payload, digest)
        if not problems:
            return []
        other_bytes += problems
    return (other_bytes or refused or ["the bundle file holds no signature"])[:1]


def split_bundles(raw: bytes) -> list[bytes]:
    """One signature bundle, or several: a .jsonl as ``gh attestation download`` writes it."""
    text = raw.decode("utf-8", errors="replace").strip()
    try:
        docs = [json.loads(text)]
    except (ValueError, RecursionError):
        try:
            docs = [json.loads(line) for line in text.splitlines() if line.strip()]
        except (ValueError, RecursionError):
            return [raw]  # let the verifier say what is wrong with it
    out = []
    for doc in docs:
        if isinstance(doc, dict) and isinstance(doc.get("bundle"), dict):
            doc = doc["bundle"]
        out.append(json.dumps(doc).encode("utf-8"))
    return out


def statement_problems(payload_type: str, payload: bytes, digest: str) -> list[str]:
    """The signed statement must name this file's sha256 among its subjects."""
    if payload_type != IN_TOTO:
        return [f"the signature is over a {payload_type!r} payload, not an attestation"]
    try:
        statement = json.loads(payload)
        subjects = statement["subject"]
        digests = {s["digest"]["sha256"] for s in subjects if isinstance(s, dict)}
    except (ValueError, KeyError, TypeError, RecursionError):
        return ["the signed attestation cannot be read"]
    if digest not in digests:
        return ["the signature is for other bytes: this file was changed after it was signed"]
    return []


def _sigstore_verify(bundle_bytes: bytes, want: dict[str, str]) -> tuple[str, bytes]:
    try:
        from sigstore.models import Bundle
        from sigstore.verify import Verifier as SigstoreVerifier
        from sigstore.verify import policy
    except ImportError as exc:
        raise ProvenanceError(
            'checking a signature needs the sigstore package: pip install "flagwake[provenance]"'
        ) from exc
    rules = policy.AllOf(
        [
            policy.OIDCIssuerV2(want["issuer"]),
            policy.OIDCSourceRepositoryURI(want["repository_uri"]),
            policy.OIDCSourceRepositoryDigest(want["commit"]),
            policy.OIDCRunInvocationURI(want["run_uri"]),
            policy.OIDCRunnerEnvironment(want["runner"]),
        ]
    )
    logging.getLogger("sigstore").setLevel(logging.ERROR)  # not its "offline mode" notice
    try:
        bundle = Bundle.from_json(bundle_bytes)
        result: tuple[str, bytes] = SigstoreVerifier.production(offline=True).verify_dsse(
            bundle, rules
        )
    except Exception as exc:  # a bad bundle, signature or policy match: each has its own type
        raise ProvenanceError(f"the signature does not check out: {exc}") from exc
    return result
