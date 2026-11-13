"""Who made a report: a record of the GitHub Actions run, and a check of its signature.

``flagwake check --record-ci`` adds a ``provenance`` block to the report: the repository (name and
numeric id), commit, workflow and run that produced it, the defender command, whether the defender
ran as a separate user, how the incidents were chosen, and the attempt ticket the run logged before
drawing them. The block is hashed with the rest of the report, and the workflow then signs
report.json with a GitHub artifact attestation (Sigstore). ``flagwake verify report.json
--provenance report.sigstore.json`` checks that signature: issued to a GitHub Actions run on a
GitHub-hosted runner, for exactly the repository, commit, run and attempt the block names, over
exactly these bytes. Without a signature the block is only a claim, and verify says so.

The signing certificate also names the workflow that signed. When it is Flagwake's own signing
workflow (``.github/workflows/check.yml`` of the Flagwake repository) at a release tag, the steps
of that workflow ran unmodified, whatever the calling repository's workflow says: the defender ran
as a separate user without sudo, the attempt ticket was signed and logged before the incidents
were drawn, and the incidents were drawn inside the run. verify reports this as the harness.

What a signature cannot show: that the defender is honest (it points to the exact commit, so a
public defender can be read as it was), or anything about a closed product beyond what it did in
this run. docs/SIGNED_RESULTS.md has the full account.

Checking needs the optional ``sigstore`` package (``pip install "flagwake[provenance]"``) and
works offline: it uses the trust root shipped with that package and the transparency-log proof
inside the signature bundle. Only ``--attempts`` reads the public log over the network.
"""

from __future__ import annotations

import datetime
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
# The signing workflow whose signature vouches for the whole harness (see the module docstring).
OFFICIAL = "https://github.com/Sid00011/Flagwake/.github/workflows/check.yml@"
# Report field -> the GitHub Actions variable it is read from.
ENV = {
    "server": "GITHUB_SERVER_URL",
    "repository": "GITHUB_REPOSITORY",
    "repository_id": "GITHUB_REPOSITORY_ID",
    "commit": "GITHUB_SHA",
    "ref": "GITHUB_REF",
    "workflow_ref": "GITHUB_WORKFLOW_REF",
    "run_id": "GITHUB_RUN_ID",
    "run_attempt": "GITHUB_RUN_ATTEMPT",
    "runner_environment": "RUNNER_ENVIRONMENT",
}
# How the incidents were chosen.
DRAWN = "drawn in the run"  # fresh seeds from a key made inside the run
GIVEN = "given (--run-key)"  # the caller supplied the key, so it knew the incidents
FIXED = "a fixed or custom pack"  # public seeds, or a difficulty set by hand
# Facts the harness adds about the run itself, with their values when nothing is said.
EXTRA = {
    "defender_command": "",
    "defender_isolation": "none",
    "incidents": DRAWN,
    "attempt": "",
    "attempt_ticket": "",
    "attempt_log_index": "",
}
# The defender command that means Flagwake's own model agent, started by the harness itself.
REFERENCE_MODEL = "reference:model"
# What a job uses to obtain a signing identity. A defender process is never given them.
SIGNING_ENV = ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL")
MAX_FIELD = 300
MAX_COMMAND = 2000

# (bundle bytes, what the certificate must say) -> (payload type, payload, certificate facts)
Verifier = Callable[[bytes, dict[str, str]], tuple[str, bytes, dict[str, Any]]]


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
    rec.update(EXTRA)
    problems = record_problems(rec)
    if problems:
        raise ValueError(problems[0])
    return rec


def record_problems(rec: Any) -> list[str]:
    """What is wrong with a provenance block's shape (empty when it is well formed)."""
    if not isinstance(rec, dict) or rec.get("ci") != CI:
        return ["the provenance block is not a GitHub Actions record"]
    if set(rec) != {"ci", *ENV, *EXTRA}:
        return ["the provenance block does not have exactly the expected fields"]
    if not all(isinstance(rec[f], str) and len(rec[f]) <= MAX_COMMAND for f in (*ENV, *EXTRA)):
        return ["a provenance field is not text, or is too long"]
    if not all(0 < len(rec[f]) <= MAX_FIELD for f in ENV):
        return ["a provenance field is empty or too long"]
    checks = [
        (re.fullmatch(r"[0-9a-f]{40}", rec["commit"]), "the commit is not a full commit id"),
        (_digits(rec["repository_id"]), "the repository id is not a number"),
        (_digits(rec["run_id"]), "the run id is not a number"),
        (_digits(rec["run_attempt"]), "the run attempt is not a number"),
        (re.fullmatch(r"https://[A-Za-z0-9.-]+", rec["server"]), "the server is not https"),
        (rec["defender_isolation"] == "none"
         or re.fullmatch(r"separate user [a-z_][a-z0-9_-]{0,31}", rec["defender_isolation"]),
         "the defender isolation is not a known value"),
        (rec["incidents"] in (DRAWN, GIVEN, FIXED), "the incident source is unknown"),
        (bool(rec["attempt"]) == bool(rec["attempt_ticket"]) == bool(rec["attempt_log_index"]),
         "the attempt, its ticket and its log index must be all present or all absent"),
        (not rec["attempt"] or (_digits(rec["attempt"]) and _digits(rec["attempt_log_index"])),
         "the attempt number or its log index is not a number"),
        (not rec["attempt_ticket"] or re.fullmatch(r"[0-9a-f]{64}", rec["attempt_ticket"]),
         "the attempt ticket is not a sha256"),
    ]  # fmt: skip
    return [f"provenance: {why}" for ok, why in checks if not ok][:1]


def _digits(text: str) -> bool:
    return text.isascii() and text.isdigit() and len(text) <= 20


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
        "repository_id": rec["repository_id"],
        "commit": rec["commit"],
        "run_uri": f"{repo_uri}/actions/runs/{rec['run_id']}/attempts/{rec['run_attempt']}",
        "runner": "github-hosted",  # a self-hosted runner is a machine its maintainers control
    }


def harness(facts: dict[str, Any]) -> tuple[str, bool]:
    """(what signed, official release?) from the certificate's build-signer facts."""
    signer = str(facts.get("build_signer_uri") or "")
    if signer.startswith(OFFICIAL):
        ref = signer[len(OFFICIAL) :]
        tag = ref.removeprefix("refs/tags/")
        if ref.startswith("refs/tags/v"):
            return f"Flagwake's signing workflow at release {tag}", True
        return f"Flagwake's signing workflow at {ref} (not a release)", False
    return "the repository's own workflow (its steps are what that workflow says)", False


def _incidents(doc: dict[str, Any]) -> list[dict[str, Any]]:
    raw = doc.get("incidents")
    return [i for i in raw if isinstance(i, dict)] if isinstance(raw, list) else []


def _coverage(doc: dict[str, Any]) -> tuple[int, int, Any]:
    """(incidents, families run, families the company can host) of a report."""
    incidents = _incidents(doc)
    return len(incidents), len({i.get("family") for i in incidents}), doc.get("families_available")


def summary(rec: dict[str, str], facts: dict[str, Any], doc: dict[str, Any]) -> list[str]:
    """What a checked signature vouches for, one fact per line. The model line is read from the
    per-incident usage, which the report hash covers (the summed usage in the "agent" block is
    not)."""
    from cyberarena.rc.report import sum_usage, world_notes

    who, _official = harness(facts)
    iso = rec["defender_isolation"]
    ran = f"ran as a {iso}, without sudo" if iso != "none" else "ran as the harness's own user"
    when = facts.get("time")
    signed = ""
    if isinstance(when, int) and when > 0:
        stamp = datetime.datetime.fromtimestamp(when, datetime.UTC)
        signed = f"; signed {stamp:%Y-%m-%d %H:%M} UTC"
    n, ran_families, available = _coverage(doc)
    lines = [
        "signature: " + describe(rec) + signed,
        "harness: " + who,
        f"defender: {rec['defender_command'] or '(not recorded)'}; {ran}",
        f"incidents: {rec['incidents']}; pack {doc.get('pack')}, {n} incidents in "
        f"{ran_families} of {available} families",
        *(world_notes(doc) or ["world: the default company"]),
    ]
    usage = sum_usage([i for i in _incidents(doc) if isinstance(i.get("usage"), dict)])
    if usage.get("model"):
        reference = rec["defender_command"].split()[:1] == [REFERENCE_MODEL]
        relay = "Flagwake's own model agent" if reference else "the defender (its own word)"
        where = f" at {usage['endpoint']}" if usage.get("endpoint") else ""
        lines.append(f"model: {usage['model']}{where}, as the model's server reported it, "
                     f"relayed by {relay}")  # fmt: skip
    if rec["attempt"]:
        at = "index " + rec["attempt_log_index"]
        lines.append(f"attempt {rec['attempt']}: ticket signed and in the public log ({at}) "
                     "before the draw; --attempts lists every run")  # fmt: skip
    else:
        lines.append("attempt: no ticket, so the runs before this one are not on record")
    return lines


def official_problems(rec: dict[str, str], facts: dict[str, Any], doc: dict[str, Any]) -> list[str]:
    """For --require-official: everything a citable result needs."""
    problems = []
    if not harness(facts)[1]:
        problems.append("not signed by Flagwake's signing workflow at a release")
    if rec["defender_isolation"] == "none":
        problems.append("the defender was not isolated from the harness")
    if rec["incidents"] != DRAWN or doc.get("pack") != "fresh":
        problems.append("the incidents were not fresh ones drawn in the run")
    _n, ran_families, available = _coverage(doc)
    if not isinstance(available, int) or ran_families != available:
        problems.append("not every incident family the company can host was run")
    if not rec["attempt"]:
        problems.append("the run has no attempt ticket")
    return problems


def check_signature(
    report_bytes: bytes,
    doc: dict[str, Any],
    bundle_bytes: bytes,
    repo: str | None = None,
    verify_dsse: Verifier | None = None,
) -> tuple[list[str], dict[str, Any]]:
    """(problems, certificate facts) for a report's signature; no problems when it checks out.

    ``report_bytes`` are the report file exactly as signed; ``doc`` is the same file parsed;
    ``repo`` (org/repo), when given, is the repository the reader expects.
    """
    rec = doc.get("provenance")
    if rec is None:
        return ["the report has no provenance block (it was made without --record-ci)"], {}
    problems = record_problems(rec)
    if problems:
        return problems, {}
    if repo is not None and repo.lower() != rec["repository"].lower():
        return [f"the report was made in {rec['repository']}, not in {repo}"], {}
    if rec["runner_environment"] != "github-hosted":
        return ["the report was made on a self-hosted runner, a machine the repository's "
                "maintainers control, so a signature cannot vouch for the run"], {}  # fmt: skip
    if rec["attempt"]:
        from cyberarena.rc.attempt import AttemptError, ticket_digest

        try:
            if ticket_digest(rec["repository_id"], int(rec["attempt"])) != rec["attempt_ticket"]:
                return ["the attempt ticket does not match the repository and attempt number"], {}
        except AttemptError as exc:
            return [str(exc)], {}
    return _first_valid(bundle_bytes, rec, hashlib.sha256(report_bytes).hexdigest(), verify_dsse)


def _first_valid(
    bundle_bytes: bytes, rec: dict[str, str], digest: str, verify_dsse: Verifier | None
) -> tuple[list[str], dict[str, Any]]:
    """Check each signature in a bundle file against the record; one valid signature over
    ``digest`` is enough."""
    refused: list[str] = []
    other_bytes: list[str] = []
    for bundle in split_bundles(bundle_bytes):
        try:
            payload_type, payload, facts = (verify_dsse or _sigstore_verify)(bundle, expected(rec))
        except ProvenanceError as exc:
            refused.append(str(exc))
            continue
        problems = statement_problems(payload_type, payload, digest)
        if not problems:
            return [], facts
        other_bytes += problems
    return (other_bytes or refused or ["the bundle file holds no signature"])[:1], {}


def verify_ticket(
    ticket: bytes, bundle_bytes: bytes, rec: dict[str, str], verify_dsse: Verifier | None = None
) -> dict[str, Any]:
    """The certificate facts of an attempt ticket this very run signed (ProvenanceError if not).

    The signature is checked like a report's: Sigstore's authority issued the certificate to this
    repository, commit and run, and the bundle proves the public log took the entry. So the ticket
    is on public record before anything else happens."""
    problems, facts = _first_valid(
        bundle_bytes, rec, hashlib.sha256(ticket).hexdigest(), verify_dsse
    )
    if problems:
        raise ProvenanceError("the attempt ticket's signature does not check out: " + problems[0])
    if not isinstance(facts.get("log_index"), int):
        raise ProvenanceError("the attempt ticket's signature carries no public-log entry")
    return facts


def attempt_lines(
    rec: dict[str, str], facts: dict[str, Any], log: Any
) -> tuple[list[str], list[str]]:
    """(problems, lines) from the public log: this run's ticket, and every run of the repository
    that holds a ticket.

    This run's ticket must be in the log under the index the report recorded, and it must have
    been logged before the report was signed. Every other ticket is listed, never hidden:
    signings that share a number (they started together) are each an attempt."""
    from cyberarena.rc.attempt import AttemptError, history

    if not rec["attempt"]:
        return [], ["no attempt ticket: the number of runs before this one is not on record"]
    n = int(rec["attempt"])
    run_uri = expected(rec)["run_uri"]
    try:
        attempts = history(log, rec["repository_id"], n)
    except AttemptError as exc:
        return [str(exc)], []
    recorded = rec["attempt_log_index"]
    signed_here = [e for k, found in attempts if k == n for e in found
                   if e.get("run_uri") == run_uri]  # fmt: skip
    own = [e for e in signed_here if recorded in {str(i) for i in e.get("log_indexes", [])}]
    lines, problems = [], []
    others = 0
    for k, found in attempts:
        for e in found:
            mine = bool(own) and e is own[0]
            others += not mine
            run = str(e.get("run_uri", "?")).rsplit("/actions/runs/", 1)[-1]
            lines.append(f"  attempt {k}: run {run} (log index {e.get('log_index')})"
                         + ("  <- this report" if mine else ""))  # fmt: skip
        if not found:
            lines.append(f"  attempt {k}: no ticket")
    if not signed_here:
        problems.append(f"the public log has no ticket {n} signed by this run")
    elif not own:
        problems.append("the ticket's log index is not the one the report recorded")
    elif isinstance(facts.get("time"), int) and (own[0].get("time") or 0) > facts["time"]:
        problems.append("the ticket was logged after the report was signed")
    lines.insert(0, f"attempt {n} of {rec['repository']}: {others} other attempt ticket(s) of "
                    "this repository are in the public log")  # fmt: skip
    return problems, lines


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


def _sigstore_verify(
    bundle_bytes: bytes, want: dict[str, str]
) -> tuple[str, bytes, dict[str, Any]]:
    try:
        from cryptography.hazmat.primitives.serialization import Encoding
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
            policy.OIDCSourceRepositoryIdentifier(want["repository_id"]),
            policy.OIDCSourceRepositoryDigest(want["commit"]),
            policy.OIDCRunInvocationURI(want["run_uri"]),
            policy.OIDCRunnerEnvironment(want["runner"]),
        ]
    )
    logging.getLogger("sigstore").setLevel(logging.ERROR)  # not its "offline mode" notice
    try:
        bundle = Bundle.from_json(bundle_bytes)
        payload_type, payload = SigstoreVerifier.production(offline=True).verify_dsse(bundle, rules)
    except Exception as exc:  # a bad bundle, signature or policy match: each has its own type
        raise ProvenanceError(f"the signature does not check out: {exc}") from exc
    from cyberarena.rc.attempt import cert_facts

    facts: dict[str, Any] = cert_facts(bundle.signing_certificate.public_bytes(Encoding.PEM))
    try:
        entry = json.loads(bundle_bytes)["verificationMaterial"]["tlogEntries"][0]
        facts["time"] = int(entry["integratedTime"])
        facts["log_index"] = int(entry["logIndex"])
    except (ValueError, KeyError, IndexError, TypeError):
        pass  # no public-log entry in the bundle: callers that need one say so
    return payload_type, payload, facts
