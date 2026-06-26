# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""Shared test fixtures: synthetic CSCA → DSC → EF.SOD chains and a DG1."""

import datetime
import hashlib

from asn1crypto import cms, x509 as a_x509
from cryptography import x509 as c_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from verifier import master_list
from verifier.passive_auth import LDS_SECURITY_OBJECT_OID, LDSSecurityObject


def self_signed_ca(cn: str):
    """A self-signed CA key+cert (a synthetic root CSCA, or a country CSCA)."""
    key = ec.generate_private_key(ec.SECP256R1())
    return key, _cert(_name(cn), _name(cn), key, key, ca=True)


def build_master_list(root_key, root_cert, signer_issuer, cscas):
    """A CSCA Master List CMS signed by an ML signer that `root_key` issues, with
    `cscas` (cryptography certs) as the contained country CSCAs. Tests pin the
    verifier to `root_cert`'s SHA-256 to accept it."""
    ml_key = ec.generate_private_key(ec.SECP256R1())
    ml_signer = _cert(_name("Test ML Signer"), signer_issuer, ml_key, root_key, ca=False)

    mld = master_list._CscaMasterListData({
        "version": 0,
        "cert_list": [a_x509.Certificate.load(cert_der(c)) for c in cscas],
    })
    econtent = mld.dump()

    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({"type": "content_type", "values": [master_list.CSCA_MASTER_LIST_OID]}),
        cms.CMSAttribute({"type": "message_digest", "values": [hashlib.sha256(econtent).digest()]}),
    ])
    signature = ml_key.sign(signed_attrs.dump(), ec.ECDSA(hashes.SHA256()))

    ml_signer_a = a_x509.Certificate.load(cert_der(ml_signer))
    root_a = a_x509.Certificate.load(cert_der(root_cert))
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

# A valid TD3 (passport) MRZ for "ALICE DOE", GBR, born 2000-01-01, expiry
# 2030-01-01. Two 44-char lines concatenated.
_L1 = "P<GBR" + "DOE<<ALICE" + "<" * 29
_L2 = "123456789" + "0" + "GBR" + "000101" + "0" + "F" + "300101" + "0" + "<" * 14 + "0" + "0"
SAMPLE_MRZ = _L1 + _L2
SAMPLE_FIELDS = {
    "document_type": "P", "issuing_state": "GBR",
    "family_name": "DOE", "given_name": "ALICE",
    "document_number": "123456789", "nationality": "GBR",
    "birthdate": "2000-01-01", "sex": "F", "doc_expiry": "2030-01-01",
}


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return b"\x81" + bytes([n])
    return b"\x82" + n.to_bytes(2, "big")


def build_dg1(mrz: str = SAMPLE_MRZ) -> bytes:
    inner = mrz.encode("ascii")
    f1f = b"\x5f\x1f" + _ber_len(len(inner)) + inner
    return b"\x61" + _ber_len(len(f1f)) + f1f


def _name(cn: str) -> c_x509.Name:
    return c_x509.Name([
        c_x509.NameAttribute(NameOID.COUNTRY_NAME, "UT"),
        c_x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def _cert(subject, issuer, subject_key, issuer_key, ca: bool):
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    return (
        c_x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(c_x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(c_x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )


def cert_der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def cert_pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def build_chain(dgs: dict[int, bytes], *, signing_time=None):
    """Return (sod_der, csca_cert, dsc_cert) for the given data groups. Pass a
    timezone-aware `signing_time` to add the CMS signingTime signed attribute
    (used to exercise the DSC/CSCA validity-at-signing-time check)."""
    csca_key = ec.generate_private_key(ec.SECP256R1())
    dsc_key = ec.generate_private_key(ec.SECP256R1())
    csca = _cert(_name("Test CSCA"), _name("Test CSCA"), csca_key, csca_key, ca=True)
    dsc = _cert(_name("Test DSC"), _name("Test CSCA"), dsc_key, csca_key, ca=False)

    lds = LDSSecurityObject({
        "version": 0,
        "hash_algorithm": {"algorithm": "sha256"},
        "data_group_hash_values": [
            {"data_group_number": n, "data_group_hash_value": hashlib.sha256(b).digest()}
            for n, b in sorted(dgs.items())
        ],
    })
    econtent = lds.dump()

    attrs = [
        cms.CMSAttribute({"type": "content_type", "values": [LDS_SECURITY_OBJECT_OID]}),
        cms.CMSAttribute({"type": "message_digest",
                          "values": [hashlib.sha256(econtent).digest()]}),
    ]
    if signing_time is not None:
        attrs.append(cms.CMSAttribute(
            {"type": "signing_time", "values": [cms.Time({"utc_time": signing_time})]}))
    signed_attrs = cms.CMSAttributes(attrs)
    signature = dsc_key.sign(signed_attrs.dump(), ec.ECDSA(hashes.SHA256()))

    dsc_a = a_x509.Certificate.load(cert_der(dsc))
    signer = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({"issuer_and_serial_number": cms.IssuerAndSerialNumber(
            {"issuer": dsc_a.issuer, "serial_number": dsc_a.serial_number})}),
        "digest_algorithm": {"algorithm": "sha256"},
        "signed_attrs": signed_attrs,
        "signature_algorithm": {"algorithm": "sha256_ecdsa"},
        "signature": signature,
    })
    signed_data = cms.SignedData({
        "version": "v3",
        "digest_algorithms": [{"algorithm": "sha256"}],
        "encap_content_info": {"content_type": LDS_SECURITY_OBJECT_OID, "content": econtent},
        "certificates": [cms.CertificateChoices({"certificate": dsc_a})],
        "signer_infos": [signer],
    })
    ci = cms.ContentInfo({"content_type": "signed_data", "content": signed_data})
    return ci.dump(), csca, dsc
