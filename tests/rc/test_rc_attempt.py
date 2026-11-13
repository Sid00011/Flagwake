"""The attempt log: canonical tickets, and counting a repository's attempts in a public log that
answers like Sigstore's (here a fake that keeps entries in memory; the real log is used by the
signed self-test workflow)."""

from __future__ import annotations

import base64
import json

import pytest

from cyberarena.rc.attempt import (
    GITHUB_ISSUER,
    AttemptError,
    Log,
    _der_text,
    confirm,
    history,
    next_number,
    read_ticket,
    ticket_digest,
    ticket_text,
)

REPO = "example-org/defender"


def run_uri(run: int, repo: str = REPO, attempt: int = 1) -> str:
    return f"https://github.com/{repo}/actions/runs/{run}/attempts/{attempt}"


class FakeRekor:
    """digest -> entries, each signed by a certificate whose facts are given directly."""

    def __init__(self) -> None:
        self.by_digest: dict[str, list[str]] = {}
        self.entries: dict[str, dict] = {}

    def add(
        self,
        digest: str,
        repo: str = REPO,
        run: int = 1,
        issuer: str = GITHUB_ISSUER,
        attempt: int = 1,
    ) -> None:
        facts = {"issuer": issuer, "repository_uri": f"https://github.com/{repo}",
                 "run_uri": run_uri(run, repo, attempt)}  # fmt: skip
        verifier = base64.b64encode(json.dumps(facts).encode()).decode()
        body = {"kind": "dsse", "spec": {"signatures": [{"verifier": verifier}]}}
        uuid = f"u{len(self.entries)}"
        encoded = base64.b64encode(json.dumps(body).encode()).decode()
        index = 1000 + len(self.entries)
        self.entries[uuid] = {"body": encoded, "logIndex": index, "integratedTime": 50}
        self.by_digest.setdefault(digest, []).append(uuid)

    def fetch(self, url: str, body: bytes | None):
        if url.endswith("/index/retrieve"):
            return self.by_digest.get(json.loads(body)["hash"].removeprefix("sha256:"), [])
        uuid = url.rsplit("/", 1)[1]
        return {uuid: self.entries[uuid]}

    def log(self) -> Log:
        return Log(fetch=self.fetch, facts=lambda pem: json.loads(pem))


def test_a_ticket_is_canonical_and_its_digest_predictable():
    text = ticket_text(REPO, 3)
    assert text == b"flagwake attempt ticket 1\nrepository: example-org/defender\nattempt: 3\n"
    assert read_ticket(text) == (REPO, 3)
    assert ticket_digest(REPO, 3) == ticket_digest(REPO, 3) != ticket_digest(REPO, 4)
    for bad in (text + b"\n", text.replace(b"3", b"03"), b"hello", text.replace(b"1\n", b"2\n", 1)):
        with pytest.raises(AttemptError):
            read_ticket(bad)
    for repo, n in (("no-slash", 1), (REPO, 0), ("a/b c", 1)):
        with pytest.raises(AttemptError):
            ticket_text(repo, n)


def test_only_the_repositorys_own_tickets_count():
    rekor = FakeRekor()
    rekor.add(ticket_digest(REPO, 1), run=10)
    rekor.add(ticket_digest(REPO, 2), repo="someone/else", run=11)  # not this repository's
    rekor.add(ticket_digest(REPO, 2), issuer="https://example.invalid", run=12)
    log = rekor.log()
    assert next_number(log, REPO) == 2  # nobody else can use up or fake an attempt number
    rekor.add(ticket_digest(REPO, 2), run=13)
    assert next_number(log, REPO) == 3


def test_the_check_waits_for_its_own_ticket_and_refuses_without_it():
    rekor = FakeRekor()
    rekor.add(ticket_digest(REPO, 1), run=20)
    log = rekor.log()
    assert confirm(log, REPO, 1, run_uri(20), tries=1)["log_index"] == 1000
    with pytest.raises(AttemptError, match="not in the public log"):
        confirm(log, REPO, 1, run_uri(21), tries=2, wait=0)  # another run's ticket is not ours


def test_history_shows_earlier_later_and_duplicate_attempts():
    rekor = FakeRekor()
    for n, run in ((1, 1), (2, 2), (3, 3), (3, 4), (5, 6)):
        rekor.add(ticket_digest(REPO, n), run=run)
    found = dict(history(rekor.log(), REPO, 2))
    assert sorted(found) == [1, 2, 3, 4, 5]  # numbers after the report's are listed too
    assert len(found[3]) == 2 and found[4] == []


def test_der_text_reads_both_certificate_encodings():
    assert _der_text(b"\x0c\x05hello") == "hello"
    long = "x" * 200
    assert _der_text(b"\x0c\x81\xc8" + long.encode()) == long
    assert _der_text(b"https://token.actions.githubusercontent.com") == GITHUB_ISSUER
