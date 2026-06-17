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
