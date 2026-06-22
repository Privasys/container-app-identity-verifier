# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""Passive Authentication against a synthetic CSCA → DSC → EF.SOD chain."""

import datetime

import pytest
from cryptography import x509 as c_x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import fixtures
from verifier import passive_auth
from verifier.passive_auth import PAError


def test_passive_auth_happy_path():
    dg1, dg2 = b"MRZ-DATA-GROUP-1", b"FACE-DATA-GROUP-2"
    sod, csca, _ = fixtures.build_chain({1: dg1, 2: dg2})

    pa = passive_auth.verify(sod, [fixtures.cert_der(csca)])
    assert pa.hash_algo == "sha256"
    assert set(pa.dg_hashes) == {1, 2}
    assert pa.issuing_country == "UT"

    passive_auth.check_data_group(pa, 1, dg1)
    passive_auth.check_data_group(pa, 2, dg2)


def test_tampered_data_group_rejected():
    sod, csca, _ = fixtures.build_chain({1: b"MRZ", 2: b"FACE"})
    pa = passive_auth.verify(sod, [fixtures.cert_der(csca)])
    with pytest.raises(PAError):
        passive_auth.check_data_group(pa, 1, b"TAMPERED")


def test_untrusted_csca_rejected():
    sod, _csca, _ = fixtures.build_chain({1: b"x"})
    other_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    other = (
        c_x509.CertificateBuilder()
        .subject_name(c_x509.Name([c_x509.NameAttribute(NameOID.COMMON_NAME, "Other CA")]))
        .issuer_name(c_x509.Name([c_x509.NameAttribute(NameOID.COMMON_NAME, "Other CA")]))
        .public_key(other_key.public_key())
        .serial_number(c_x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
        .sign(other_key, hashes.SHA256())
    )
    with pytest.raises(PAError):
        passive_auth.verify(sod, [fixtures.cert_der(other)])


def test_no_trust_anchors_rejected():
    sod, _csca, _ = fixtures.build_chain({1: b"x"})
    with pytest.raises(PAError):
        passive_auth.verify(sod, [])


def test_tampered_sod_signature_rejected():
    sod, csca, _ = fixtures.build_chain({1: b"x", 2: b"y"})
    bad = bytearray(sod)
    bad[len(bad) // 2] ^= 0xFF
    with pytest.raises(PAError):
        passive_auth.verify(bytes(bad), [fixtures.cert_der(csca)])


def test_rsassa_pss_typed_dsc_key_verifies():
    """A DSC whose SPKI is tagged id-RSASSA-PSS (as some EU passports encode it)
    must verify. Older pyca/cryptography rejects that SPKI outright; the verifier
    re-wraps it as rsaEncryption. On newer pyca it loads directly — either way
    _verify_signature must accept a valid PSS signature and reject a bad one."""
    from asn1crypto import keys
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    plain_spki = key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    info = keys.PublicKeyInfo.load(plain_spki)
    pss_spki = keys.PublicKeyInfo({
        "algorithm": {"algorithm": "rsassa_pss"},
        "public_key": info["public_key"].parsed,
    }).dump()

    msg = b"LDS-SECURITY-OBJECT"
    sig = key.sign(
        msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256())
    passive_auth._verify_signature(pss_spki, "rsassa_pss", "sha256", msg, sig)
    bad_sig = sig[:-1] + bytes([sig[-1] ^ 0xFF])
    with pytest.raises(PAError):
        passive_auth._verify_signature(pss_spki, "rsassa_pss", "sha256", msg, bad_sig)


def test_brainpool_explicit_params_dsc_key_verifies():
    """The real German-passport case: a Brainpool EC DSC whose SubjectPublicKeyInfo
    carries explicit domain parameters (no named-curve OID). cryptography raises
    'ECDSA keys with explicit parameters are unsupported'; the verifier falls back
    to python-ecdsa, which parses the explicit params and verifies."""
    import hashlib

    import ecdsa
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    sk = ecdsa.SigningKey.generate(curve=ecdsa.BRAINPOOLP256r1)
    spki = sk.verifying_key.to_der(curve_parameters_encoding="explicit")

    # Precondition: cryptography cannot load an explicit-parameters EC key.
    with pytest.raises(ValueError):
        load_der_public_key(spki)

    msg = b"LDS-SECURITY-OBJECT"
    sig = sk.sign(msg, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_der)
    # The verifier accepts it via the fallback …
    passive_auth._verify_signature(spki, "sha256_ecdsa", "sha256", msg, sig)
    # … and rejects a tampered signature.
    with pytest.raises(PAError):
        passive_auth._verify_signature(
            spki, "sha256_ecdsa", "sha256", msg, sig[:-1] + bytes([sig[-1] ^ 0xFF]))
