"""The attempt log: canonical tickets, and counting a repository's runs in a public log that
answers like Sigstore's (here one kept in memory; the real log and real certificates are used by
the signed self-test workflow, and by the last test here when sigstore is installed)."""

from __future__ import annotations

import datetime

import pytest
from rckit import FakeRekor

from cyberarena.rc.attempt import (
    GITHUB_ISSUER,
    OIDS,
    AttemptError,
    _der_text,
    _signer_pem,
    history,
    next_number,
    read_ticket,
    ticket_digest,
    ticket_text,
    tickets,
)

REPO = "1454082854"  # a repository's numeric id: it does not change when the repository is renamed


def test_a_ticket_is_canonical_and_its_digest_predictable():
    text = ticket_text(REPO, 3)
    assert text == b"flagwake attempt ticket 2\nrepository-id: 1454082854\nattempt: 3\n"
    assert read_ticket(text) == (REPO, 3)
    assert ticket_digest(REPO, 3) == ticket_digest(REPO, 3) != ticket_digest(REPO, 4)
    for bad in (
        text + b"\n",
        text.replace(b": 3", b": 03"),
        b"hello",
        text.replace(b"2\n", b"1\n", 1),
    ):
        with pytest.raises(AttemptError):
            read_ticket(bad)
    for repo, n in (("example-org/defender", 1), (REPO, 0), ("12 34", 1), ("", 1)):
        with pytest.raises(AttemptError):
            ticket_text(repo, n)


def test_only_tickets_sigstore_issued_to_this_repository_count():
    rekor = FakeRekor()
    rekor.add(ticket_digest(REPO, 1), REPO, run=10)
    # None of these may use up or fake attempt 2: another repository's certificate, a
    # certificate from another issuer, and one that says the right things but that Sigstore's
    # authority never issued (the public log stores any certificate it is given).
    rekor.add(ticket_digest(REPO, 2), "999", run=11)
    rekor.add(ticket_digest(REPO, 2), REPO, run=12, issuer="https://example.invalid")
    rekor.add(ticket_digest(REPO, 2), REPO, run=13, trusted=False)
    log = rekor.log()
    assert next_number(log, REPO) == 2
    rekor.add(ticket_digest(REPO, 2), REPO, run=14)
    assert next_number(log, REPO) == 3


def test_one_signature_logged_twice_counts_once_but_every_signing_counts():
    rekor = FakeRekor()
    first = rekor.add(ticket_digest(REPO, 1), REPO, run=20, cert="a")
    again = rekor.add(ticket_digest(REPO, 1), REPO, run=20, cert="a")  # replayed
    (only,) = tickets(rekor.log(), REPO, 1)
    assert only["log_index"] == first and only["log_indexes"] == [first, again]
    # Checks started together in one run (a matrix) each sign their own ticket: all count.
    for _ in range(4):
        rekor.add(ticket_digest(REPO, 1), REPO, run=20)
    assert len(tickets(rekor.log(), REPO, 1)) == 5


def test_history_shows_earlier_later_and_shared_numbers():
    rekor = FakeRekor()
    for n, run in ((1, 1), (2, 2), (3, 3), (3, 4), (5, 6)):
        rekor.add(ticket_digest(REPO, n), REPO, run=run)
    found = dict(history(rekor.log(), REPO, 2))
    assert sorted(found) == [1, 2, 3, 4, 5]  # numbers after the report's are listed too
    assert len(found[3]) == 2 and found[4] == []  # two runs took number 3: both are attempts


def test_der_text_reads_both_certificate_encodings():
    assert _der_text(b"\x0c\x05hello") == "hello"
    long = "x" * 200
    assert _der_text(b"\x0c\x81\xc8" + long.encode()) == long
    assert _der_text(b"https://token.actions.githubusercontent.com") == GITHUB_ISSUER


def test_the_certificate_is_found_in_each_kind_of_log_entry():
    import base64
    import json

    pem = base64.b64encode(b"CERT").decode()

    def body(kind: str, spec: dict) -> str:
        return base64.b64encode(json.dumps({"kind": kind, "spec": spec}).encode()).decode()

    assert _signer_pem(body("dsse", {"signatures": [{"verifier": pem}]})) == b"CERT"
    envelope = {"signatures": [{"publicKey": pem}]}
    assert _signer_pem(body("intoto", {"content": {"envelope": envelope}})) == b"CERT"
    assert (
        _signer_pem(body("hashedrekord", {"signature": {"publicKey": {"content": pem}}})) == b"CERT"
    )
    assert _signer_pem(body("rekord", {})) is None and _signer_pem("not base64 json") is None


def test_a_certificate_sigstore_did_not_issue_is_not_trusted():
    """With the real libraries: a self-made certificate that says exactly what a real one says."""
    pytest.importorskip("sigstore")
    x509 = pytest.importorskip("cryptography.x509")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from cyberarena.rc.attempt import cert_facts, trusted_facts

    now = datetime.datetime.now(datetime.UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "sigstore.dev")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(minutes=10))
    )
    for field, value in (("issuer", GITHUB_ISSUER), ("repository_id", REPO)):
        der = b"\x0c" + bytes([len(value)]) + value.encode()
        ext = x509.UnrecognizedExtension(x509.ObjectIdentifier(OIDS[field]), der)
        builder = builder.add_extension(ext, critical=False)
    pem = builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    assert cert_facts(pem) == {"issuer": GITHUB_ISSUER, "repository_id": REPO}
    assert trusted_facts(pem, int(now.timestamp())) is None
    assert trusted_facts(b"not a certificate", int(now.timestamp())) is None
