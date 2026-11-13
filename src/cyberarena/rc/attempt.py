"""The attempt log: every official run of a repository leaves a ticket in Sigstore's public log
before its incidents are drawn, so anyone can count the runs a repository made.

A ticket is a three-line text naming the repository and the attempt number, so its sha256 is
predictable and the public log can be searched by it. ``flagwake attempt next`` finds the next
free number for a repository; the workflow signs the ticket (a GitHub artifact attestation, which
Sigstore's log records for good); ``flagwake check --attempt-ticket`` then confirms that the
ticket, signed by this very run, is in the log before it draws the incidents, and records it in the
report. ``flagwake verify --provenance --attempts`` lists every attempt of the report's repository,
so a result that was the fifth try cannot pass for the first.

Only tickets signed by a GitHub Actions run of the repository itself count, so nobody else can add
attempts to it. Searching the log needs the network; reading the signing certificates needs the
optional ``cryptography`` package (``pip install "flagwake[provenance]"``).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

REKOR = "https://rekor.sigstore.dev"
GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
HEADER = "flagwake attempt ticket 1"
REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
# Certificate extensions GitHub's signing certificates carry (Fulcio's OID arc 1.3.6.1.4.1.57264.1).
OIDS = {
    "issuer": "1.3.6.1.4.1.57264.1.8",
    "build_signer_uri": "1.3.6.1.4.1.57264.1.9",
    "build_signer_digest": "1.3.6.1.4.1.57264.1.10",
    "runner": "1.3.6.1.4.1.57264.1.11",
    "repository_uri": "1.3.6.1.4.1.57264.1.12",
    "commit": "1.3.6.1.4.1.57264.1.13",
    "run_uri": "1.3.6.1.4.1.57264.1.21",
}
MAX_ATTEMPTS = 100_000


class AttemptError(Exception):
    """The attempt log could not be read, or a ticket is missing or malformed."""


def ticket_text(repo: str, n: int) -> bytes:
    if not REPO.match(repo) or not 0 < n <= MAX_ATTEMPTS:
        raise AttemptError(f"not a repository and attempt number: {repo!r} {n!r}")
    return f"{HEADER}\nrepository: {repo}\nattempt: {n}\n".encode("ascii")


def ticket_digest(repo: str, n: int) -> str:
    return hashlib.sha256(ticket_text(repo, n)).hexdigest()


def read_ticket(raw: bytes) -> tuple[str, int]:
    """(repository, attempt) of a ticket file, which must be exactly in the canonical form."""
    try:
        lines = raw.decode("ascii").split("\n")
        if len(lines) != 4 or lines[0] != HEADER or lines[3] != "":
            raise ValueError("not three lines under the header")
        repo = lines[1].removeprefix("repository: ")
        n = int(lines[2].removeprefix("attempt: "))
    except (UnicodeDecodeError, ValueError) as exc:
        raise AttemptError("not a Flagwake attempt ticket") from exc
    if ticket_text(repo, n) != raw:
        raise AttemptError("the ticket is not in its canonical form")
    return repo, n


def cert_facts(pem: bytes) -> dict[str, str]:
    """The GitHub Actions facts a Sigstore signing certificate carries (missing ones left out)."""
    try:
        from cryptography import x509
    except ImportError as exc:  # pragma: no cover - the provenance extra installs it
        raise AttemptError(
            'reading signing certificates needs: pip install "flagwake[provenance]"'
        ) from exc
    cert = x509.load_pem_x509_certificate(pem)
    out = {}
    for name, oid in OIDS.items():
        try:
            raw = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(oid)).value.value
        except x509.ExtensionNotFound:
            continue
        out[name] = _der_text(raw)
    return out


def _der_text(raw: bytes) -> str:
    """A DER UTF8String's text (the newer extensions), or the raw bytes (the older ones)."""
    if len(raw) >= 2 and raw[0] == 0x0C and raw[1] < 0x80 and len(raw) == raw[1] + 2:
        return raw[2:].decode("utf-8", "replace")
    if len(raw) >= 3 and raw[0] == 0x0C and raw[1] == 0x81 and len(raw) == raw[2] + 3:
        return raw[3:].decode("utf-8", "replace")
    return raw.decode("utf-8", "replace")


Fetch = Callable[[str, bytes | None], Any]


def _fetch(url: str, body: bytes | None) -> Any:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    req = urllib.request.Request(url, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (the public log)
            return json.loads(resp.read(5_000_000))
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise AttemptError(f"the public log did not answer: {exc}") from exc


class Log:
    """Sigstore's public transparency log, searched by a subject's sha256."""

    def __init__(
        self,
        base: str = REKOR,
        fetch: Fetch = _fetch,
        facts: Callable[[bytes], dict[str, str]] | None = None,
    ) -> None:
        self.base = base
        self.fetch = fetch
        self.facts = facts or cert_facts

    def entries(self, digest: str) -> list[dict[str, Any]]:
        """Every entry indexed under this digest: its index, time and signing-certificate facts."""
        body = json.dumps({"hash": f"sha256:{digest}"}).encode()
        uuids = self.fetch(f"{self.base}/api/v1/index/retrieve", body) or []
        out = []
        for uuid in uuids[:50]:
            for item in (self.fetch(f"{self.base}/api/v1/log/entries/{uuid}", None) or {}).values():
                pem = _signer_pem(item.get("body", ""))
                if pem is None:
                    continue
                out.append({"log_index": item.get("logIndex"), "time": item.get("integratedTime"),
                            **self.facts(pem)})  # fmt: skip
        return out


def _signer_pem(body_b64: str) -> bytes | None:
    """The signing certificate of a dsse or hashedrekord entry (None for other kinds)."""
    try:
        body = json.loads(base64.b64decode(body_b64))
        spec = body["spec"]
        if body["kind"] == "dsse":
            return base64.b64decode(spec["signatures"][0]["verifier"])
        if body["kind"] == "hashedrekord":
            return base64.b64decode(spec["signature"]["publicKey"]["content"])
    except (ValueError, KeyError, IndexError, TypeError):
        return None
    return None


def tickets(
    log: Log, repo: str, n: int, server: str = "https://github.com"
) -> list[dict[str, Any]]:
    """The log entries of ticket ``n`` signed by a GitHub Actions run of ``repo`` itself."""
    uri = f"{server}/{repo}"
    uri = uri.lower()
    found = log.entries(ticket_digest(repo, n))
    return [e for e in found if e.get("issuer") == GITHUB_ISSUER
            and str(e.get("repository_uri") or "").lower() == uri]  # fmt: skip


def next_number(log: Log, repo: str) -> int:
    """The first attempt number with no ticket yet."""
    for n in range(1, MAX_ATTEMPTS + 1):
        if not tickets(log, repo, n):
            return n
    raise AttemptError("too many attempts")


def confirm(
    log: Log, repo: str, n: int, run_uri: str, tries: int = 10, wait: float = 3.0
) -> dict[str, Any]:
    """The ticket entry this very run signed (waits briefly for the log's index to catch up)."""
    for i in range(tries):
        mine = [e for e in tickets(log, repo, n) if e.get("run_uri") == run_uri]
        if mine:
            return mine[0]
        if i + 1 < tries:
            time.sleep(wait)
    raise AttemptError(
        f"attempt ticket {n} of {repo}, signed by this run, is not in the public log: sign it "
        "before the check (the Flagwake workflow does)"
    )


def history(log: Log, repo: str, upto: int, beyond: int = 3) -> list[tuple[int, list[dict]]]:
    """(number, ticket entries) for attempts 1..upto, then until ``beyond`` numbers in a row have
    no ticket: a reader sees earlier attempts, duplicates and later ones."""
    out: list[tuple[int, list[dict]]] = []
    empty = 0
    n = 1
    while n <= upto or empty < beyond:
        found = tickets(log, repo, n)
        out.append((n, found))
        empty = 0 if found else empty + 1
        n += 1
        if n > MAX_ATTEMPTS:
            break
    while out and not out[-1][1] and out[-1][0] > upto:
        out.pop()
    return out
