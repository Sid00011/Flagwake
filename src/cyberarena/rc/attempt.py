"""The attempt log: every signed run of a repository leaves a ticket in Sigstore's public log
before its incidents are drawn, so anyone can count the runs a repository made.

A ticket is a three-line text naming the repository's numeric id (which survives a rename) and the
attempt number, so its sha256 is predictable and the public log can be searched by it.
``flagwake ci attempt`` finds the next free number; the workflow signs the ticket (a GitHub
artifact attestation, which Sigstore's log records for good); ``flagwake check --attempt-ticket``
verifies that signature and its place in the log before it draws the incidents, and records the
ticket in the report. ``flagwake verify --provenance --attempts`` lists every run of the report's
repository that holds a ticket, so a result that was the fifth try cannot pass for the first.

The public log stores whatever certificate comes with an entry; it does not check who issued it.
So a ticket counts only when its certificate chains to Sigstore's certificate authority, was valid
when the log took the entry, and names GitHub Actions and this repository's id: nobody else can
add attempts to a repository. Each signing has its own certificate, so every ticket is listed,
also several signed in one run, and the same signature logged twice counts once. Searching the
log needs the network; checking certificates needs the optional packages
(``pip install "flagwake[provenance]"``).
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

REKOR = "https://rekor.sigstore.dev"
GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
HEADER = "flagwake attempt ticket 2"
REPO_ID = re.compile(r"[0-9]{1,20}\Z")
# Certificate extensions GitHub's signing certificates carry (Fulcio's OID arc 1.3.6.1.4.1.57264.1).
OIDS = {
    "issuer": "1.3.6.1.4.1.57264.1.8",
    "build_signer_uri": "1.3.6.1.4.1.57264.1.9",
    "build_signer_digest": "1.3.6.1.4.1.57264.1.10",
    "runner": "1.3.6.1.4.1.57264.1.11",
    "repository_uri": "1.3.6.1.4.1.57264.1.12",
    "commit": "1.3.6.1.4.1.57264.1.13",
    "repository_id": "1.3.6.1.4.1.57264.1.15",
    "run_uri": "1.3.6.1.4.1.57264.1.21",
}
MAX_ATTEMPTS = 100_000


class AttemptError(Exception):
    """The attempt log could not be read, or a ticket is missing or malformed."""


def ticket_text(repo_id: str, n: int) -> bytes:
    if not REPO_ID.match(repo_id) or not 0 < n <= MAX_ATTEMPTS:
        raise AttemptError(f"not a repository id and attempt number: {repo_id!r} {n!r}")
    return f"{HEADER}\nrepository-id: {repo_id}\nattempt: {n}\n".encode("ascii")


def ticket_digest(repo_id: str, n: int) -> str:
    return hashlib.sha256(ticket_text(repo_id, n)).hexdigest()


def read_ticket(raw: bytes) -> tuple[str, int]:
    """(repository id, attempt) of a ticket file, which must be exactly in the canonical form."""
    try:
        lines = raw.decode("ascii").split("\n")
        if len(lines) != 4 or lines[0] != HEADER or lines[3] != "":
            raise ValueError("not three lines under the header")
        repo_id = lines[1].removeprefix("repository-id: ")
        n = int(lines[2].removeprefix("attempt: "))
    except (UnicodeDecodeError, ValueError) as exc:
        raise AttemptError("not a Flagwake attempt ticket") from exc
    if ticket_text(repo_id, n) != raw:
        raise AttemptError("the ticket is not in its canonical form")
    return repo_id, n


def cert_facts(pem: bytes) -> dict[str, str]:
    """The GitHub Actions facts a Sigstore signing certificate carries (missing ones left out).

    This only reads the certificate; ``trusted_facts`` also checks who issued it."""
    try:
        from cryptography import x509
    except ImportError as exc:
        raise AttemptError(
            'reading signing certificates needs: pip install "flagwake[provenance]"'
        ) from exc
    try:
        cert = x509.load_pem_x509_certificate(pem)
    except ValueError as exc:
        raise AttemptError("not a certificate") from exc
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


def trusted_facts(pem: bytes, when: int) -> dict[str, str] | None:
    """The facts of a certificate that Sigstore's certificate authority issued and that was valid
    at ``when`` (seconds since 1970, the time the log took the entry); None for any other."""
    try:
        from cryptography import x509
        from sigstore.verify import Verifier
    except ImportError as exc:
        raise AttemptError(
            'checking certificates needs: pip install "flagwake[provenance]"'
        ) from exc
    import logging

    logging.getLogger("sigstore").setLevel(logging.ERROR)  # not its "offline mode" notice
    try:
        cert = x509.load_pem_x509_certificate(pem)
        at = datetime.datetime.fromtimestamp(int(when), datetime.UTC)
        check = Verifier.production(offline=True)._verify_chain_at_time
    except AttributeError as exc:  # another sigstore than the one this was written against
        raise AttemptError("this version of sigstore cannot check a certificate chain") from exc
    except (ValueError, TypeError, OverflowError, OSError):
        return None
    try:
        check(cert, SimpleNamespace(time=at))
    except Exception:  # not issued by Sigstore's authority, or not valid at that time
        return None
    from cryptography.hazmat.primitives import hashes

    return {**cert_facts(pem), "certificate": cert.fingerprint(hashes.SHA256()).hex()}


Fetch = Callable[[str, bytes | None], Any]
Facts = Callable[[bytes, int], dict[str, str] | None]


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

    def __init__(self, base: str = REKOR, fetch: Fetch = _fetch, facts: Facts | None = None):
        self.base = base
        self.fetch = fetch
        self.facts = facts or trusted_facts

    def entries(self, digest: str) -> list[dict[str, Any]]:
        """Every entry indexed under this digest whose certificate Sigstore's authority issued:
        its index, time and certificate facts."""
        body = json.dumps({"hash": f"sha256:{digest}"}).encode()
        uuids = self.fetch(f"{self.base}/api/v1/index/retrieve", body)
        out = []
        for uuid in (uuids if isinstance(uuids, list) else [])[:50]:
            found = self.fetch(f"{self.base}/api/v1/log/entries/{uuid}", None)
            for item in found.values() if isinstance(found, dict) else []:
                pem = _signer_pem(item.get("body", "")) if isinstance(item, dict) else None
                when = item.get("integratedTime") if isinstance(item, dict) else None
                facts = self.facts(pem, when) if pem and isinstance(when, int) else None
                if facts is not None:
                    out.append({"log_index": item.get("logIndex"), "time": when, **facts})
        return out


def _signer_pem(body_b64: str) -> bytes | None:
    """The signing certificate of a dsse, intoto or hashedrekord entry (None for other kinds)."""
    try:
        body = json.loads(base64.b64decode(body_b64))
        spec, kind = body["spec"], body["kind"]
        if kind == "dsse":
            return base64.b64decode(spec["signatures"][0]["verifier"])
        if kind == "intoto":
            content = spec["content"]
            envelope = content.get("envelope") or content
            sig = envelope["signatures"][0]
            return base64.b64decode(sig.get("publicKey") or sig["verifier"])
        if kind == "hashedrekord":
            return base64.b64decode(spec["signature"]["publicKey"]["content"])
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        return None
    return None


def tickets(log: Log, repo_id: str, n: int) -> list[dict[str, Any]]:
    """One entry per signing of ticket ``n`` by a GitHub Actions run of the repository.

    Every signing has its own short-lived certificate, so several checks in one run are
    several tickets, while one signature that was logged more than once (the same
    certificate) counts once, under its first entry in the log."""
    signings: dict[str, list[dict[str, Any]]] = {}
    for e in log.entries(ticket_digest(repo_id, n)):
        if e.get("issuer") == GITHUB_ISSUER and e.get("repository_id") == repo_id:
            signings.setdefault(str(e.get("certificate") or _index(e)), []).append(e)
    out = []
    for group in signings.values():
        group.sort(key=_index)
        out.append({**group[0], "log_indexes": [_index(e) for e in group]})
    return sorted(out, key=_index)


def _index(entry: dict[str, Any]) -> int:
    value = entry.get("log_index")
    return value if isinstance(value, int) else 0


def next_number(log: Log, repo_id: str) -> int:
    """The first attempt number with no ticket yet."""
    for n in range(1, MAX_ATTEMPTS + 1):
        if not tickets(log, repo_id, n):
            return n
    raise AttemptError("too many attempts")


def history(log: Log, repo_id: str, upto: int, beyond: int = 3) -> list[tuple[int, list[dict]]]:
    """(number, the runs holding that ticket) for attempts 1..upto, then until ``beyond`` numbers
    in a row have no ticket: a reader sees earlier runs, runs sharing a number and later ones."""
    out: list[tuple[int, list[dict]]] = []
    empty = 0
    n = 1
    while n <= upto or empty < beyond:
        found = tickets(log, repo_id, n)
        out.append((n, found))
        empty = 0 if found else empty + 1
        n += 1
        if n > MAX_ATTEMPTS:
            break
    while out and not out[-1][1] and out[-1][0] > upto:
        out.pop()
    return out
