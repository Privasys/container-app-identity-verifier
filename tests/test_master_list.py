# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""CSCA Master List ingestion: the signer must chain to the *pinned* ICAO/UN
CSCA root, not merely to any self-signed certificate carried in the list."""

import hashlib

import pytest
from asn1crypto import cms, x509 as a_x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

import fixtures
from verifier import master_list


def _self_signed(cn: str):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = fixtures._cert(fixtures._name(cn), fixtures._name(cn), key, key, ca=True)
    return key, cert


def build_master_list(root_key, root_cert, signer_subject_issuer, cscas):
    """Build a CSCA Master List CMS signed by an ML signer that `root_key` issues."""
    ml_key = ec.generate_private_key(ec.SECP256R1())
    ml_signer = fixtures._cert(
        fixtures._name("Test ML Signer"), signer_subject_issuer, ml_key, root_key, ca=False)

    mld = master_list._CscaMasterListData({
        "version": 0,
        "cert_list": [a_x509.Certificate.load(fixtures.cert_der(c)) for c in cscas],
    })
    econtent = mld.dump()

    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({"type": "content_type", "values": [master_list.CSCA_MASTER_LIST_OID]}),
        cms.CMSAttribute({"type": "message_digest", "values": [hashlib.sha256(econtent).digest()]}),
    ])
    signature = ml_key.sign(signed_attrs.dump(), ec.ECDSA(hashes.SHA256()))

    ml_signer_a = a_x509.Certificate.load(fixtures.cert_der(ml_signer))
    root_a = a_x509.Certificate.load(fixtures.cert_der(root_cert))
    signer = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({"issuer_and_serial_number": cms.IssuerAndSerialNumber(
            {"issuer": ml_signer_a.issuer, "serial_number": ml_signer_a.serial_number})}),
        "digest_algorithm": {"algorithm": "sha256"},
        "signed_attrs": signed_attrs,
        "signature_algorithm": {"algorithm": "sha256_ecdsa"},
        "signature": signature,
    })
    sd = cms.SignedData({
        "version": "v3",
        "digest_algorithms": [{"algorithm": "sha256"}],
        "encap_content_info": {"content_type": master_list.CSCA_MASTER_LIST_OID, "content": econtent},
        "certificates": [
            cms.CertificateChoices({"certificate": ml_signer_a}),
            cms.CertificateChoices({"certificate": root_a}),
        ],
        "signer_infos": [signer],
    })
    return cms.ContentInfo({"content_type": "signed_data", "content": sd}).dump()


def _country_csca(cn="Test Country CSCA"):
    _key, cert = _self_signed(cn)
    return cert


def test_pinned_root_accepted_and_cscas_extracted():
    root_key, root = _self_signed("Test Root CSCA")
    root_sha = hashlib.sha256(fixtures.cert_der(root)).hexdigest()
    ml = build_master_list(root_key, root, root.subject, [_country_csca(), _country_csca("Test Country B")])

    pem = master_list.verify_and_extract(ml, expected_root_sha256=root_sha)
    assert pem.count(b"BEGIN CERTIFICATE") == 2


def test_unpinned_root_rejected_by_default_icao_pin():
    # A self-consistent list whose root is NOT the genuine ICAO/UN CSCA must be
    # rejected under the default pin (the real ICAO root). This is the forgery
    # the pin exists to stop.
    root_key, root = _self_signed("Attacker Root CSCA")
    ml = build_master_list(root_key, root, root.subject, [_country_csca()])
    with pytest.raises(master_list.MasterListError):
        master_list.verify_and_extract(ml)  # default expected_root_sha256 = ICAO root


def test_wrong_pin_rejected():
    root_key, root = _self_signed("Test Root CSCA")
    ml = build_master_list(root_key, root, root.subject, [_country_csca()])
    with pytest.raises(master_list.MasterListError):
        master_list.verify_and_extract(ml, expected_root_sha256="00" * 32)


def test_tampered_content_rejected():
    root_key, root = _self_signed("Test Root CSCA")
    root_sha = hashlib.sha256(fixtures.cert_der(root)).hexdigest()
    ml = bytearray(build_master_list(root_key, root, root.subject, [_country_csca()]))
    ml[len(ml) // 2] ^= 0xFF
    with pytest.raises(master_list.MasterListError):
        master_list.verify_and_extract(bytes(ml), expected_root_sha256=root_sha)
