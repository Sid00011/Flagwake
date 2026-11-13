"""A forged attempt ticket must not count (the signed self-test runs this).

Sigstore's public log stores any certificate that comes with an entry, without checking who issued
it. So this script makes its own certificate that says exactly what a real one says (GitHub
Actions, this repository's id, a run) and checks that Flagwake refuses it; then it takes the real
certificate of a signed result and checks that Flagwake accepts it at the time the log took the
entry and refuses it a day later, which is what stops an old ticket from being logged again.

Usage: python forged_ticket.py <a real signature bundle> <the repository's numeric id>
"""

import base64
import datetime
import json
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cyberarena.rc.attempt import GITHUB_ISSUER, OIDS, cert_facts, trusted_facts


def utf8(text: str) -> bytes:
    raw = text.encode()
    return b"\x0c" + (bytes([len(raw)]) if len(raw) < 128 else b"\x81" + bytes([len(raw)])) + raw


def forged(repo_id: str, now: datetime.datetime) -> bytes:
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
    says = {
        "issuer": GITHUB_ISSUER,
        "repository_id": repo_id,
        "run_uri": "https://github.com/example/example/actions/runs/1/attempts/1",
    }
    for field, value in says.items():
        ext = x509.UnrecognizedExtension(x509.ObjectIdentifier(OIDS[field]), utf8(value))
        builder = builder.add_extension(ext, critical=False)
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM)


def main() -> int:
    bundle = json.load(open(sys.argv[1], encoding="utf-8"))
    repo_id = sys.argv[2]
    now = datetime.datetime.now(datetime.UTC)

    fake = forged(repo_id, now)
    looks = cert_facts(fake)
    assert looks["issuer"] == GITHUB_ISSUER and looks["repository_id"] == repo_id, looks
    assert trusted_facts(fake, int(now.timestamp())) is None, "a forged certificate was trusted"
    print("forged certificate: says the right things, refused")

    material = bundle["verificationMaterial"]
    der = base64.b64decode(material["certificate"]["rawBytes"])
    real = x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM)
    logged = int(material["tlogEntries"][0]["integratedTime"])
    facts = trusted_facts(real, logged)
    assert facts and facts["issuer"] == GITHUB_ISSUER and facts["repository_id"] == repo_id, facts
    print("real certificate: trusted at the time the log took the entry")
    assert trusted_facts(real, logged + 86400) is None, "an expired certificate was trusted"
    print("real certificate a day later: refused (a ticket cannot be logged again later)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
