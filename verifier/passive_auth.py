# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""ICAO 9303 Passive Authentication.

Verifies that an eMRTD's data is genuine and untampered:

  1. EF.SOD is a CMS SignedData whose eContent is an LDSSecurityObject (the
     per-data-group hashes). Verify the SignedData signature with the embedded
     Document Signer Certificate (DSC).
  2. Chain the DSC to a trusted Country Signing CA (CSCA) from the active trust
     anchors.
  3. Return the DG hashes so the caller can check each data group's integrity.

Uses vetted libraries only — `asn1crypto` for ASN.1/CMS parsing and `pyca
cryptography` for signature verification. No crypto primitives are hand-rolled.
Reference: ICAO Doc 9303 Part 11; ZeroPass/pymrtd.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from asn1crypto import cms, core, x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

LDS_SECURITY_OBJECT_OID = "2.23.136.1.1.1"

_HASHES = {
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}
_HASHLIB = {
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


class PAError(Exception):
    """Passive Authentication failed."""


# ── LDS Security Object ASN.1 ──────────────────────────────────────────────

class _DataGroupHash(core.Sequence):
    _fields = [
        ("data_group_number", core.Integer),
        ("data_group_hash_value", core.OctetString),
    ]


class _DataGroupHashValues(core.SequenceOf):
    _child_spec = _DataGroupHash


class LDSSecurityObject(core.Sequence):
    _fields = [
        ("version", core.Integer),
        ("hash_algorithm", x509.DigestAlgorithm),
        ("data_group_hash_values", _DataGroupHashValues),
    ]


@dataclass
class PAResult:
    hash_algo: str               # e.g. "sha256"
    dg_hashes: dict[int, bytes]  # data-group number → expected hash
    dsc_subject: str
    issuing_country: str         # DSC subject country (ISO 3166-1 alpha-2)


# ── signature verification (vetted primitives) ─────────────────────────────

def _verify_signature(spki_der: bytes, sig_algo: str, hash_algo: str,
                      message: bytes, signature: bytes) -> None:
    """Verify `signature` over `message`. Raises PAError on any failure."""
    if hash_algo not in _HASHES:
        raise PAError(f"unsupported hash algorithm: {hash_algo}")
    try:
        pub = load_der_public_key(spki_der)
    except ValueError as exc:
        raise PAError("invalid signer public key") from exc
    h = _HASHES[hash_algo]()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pad = padding.PSS(mgf=padding.MGF1(h), salt_length=padding.PSS.DIGEST_LENGTH) \
                if sig_algo == "rsassa_pss" else padding.PKCS1v15()
            pub.verify(signature, message, pad, h)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, message, ec.ECDSA(h))
        else:
            raise PAError("unsupported public key type")
    except InvalidSignature as exc:
        raise PAError("signature verification failed") from exc


def _digest(hash_algo: str, data: bytes) -> bytes:
    if hash_algo not in _HASHLIB:
        raise PAError(f"unsupported hash algorithm: {hash_algo}")
    return _HASHLIB[hash_algo](data).digest()


# ── Passive Authentication ─────────────────────────────────────────────────

def verify(sod_der: bytes, trust_anchors_der: list[bytes]) -> PAResult:
    try:
        ci = cms.ContentInfo.load(sod_der)
    except Exception as exc:  # noqa: BLE001
        raise PAError(f"EF.SOD is not valid CMS: {exc}") from exc
    if ci["content_type"].native != "signed_data":
        raise PAError("EF.SOD is not CMS SignedData")
    sd = ci["content"]

    eci = sd["encap_content_info"]
    if eci["content_type"].dotted != LDS_SECURITY_OBJECT_OID:
        raise PAError("eContent is not an LDS Security Object")
    econtent = eci["content"].native
    if not isinstance(econtent, (bytes, bytearray)):
        raise PAError("missing eContent")

    signer_infos = sd["signer_infos"]
    if len(signer_infos) != 1:
        raise PAError("expected exactly one SignerInfo")
    signer = signer_infos[0]
    digest_algo = signer["digest_algorithm"]["algorithm"].native

    dsc = _signer_cert(sd, signer)

    # 1. Verify the SignerInfo signature (DSC signed the SOD).
    signed_attrs = signer["signed_attrs"]
    if signed_attrs and len(signed_attrs) > 0:
        _check_message_digest(signed_attrs, digest_algo, bytes(econtent))
        # The signature is over the DER SET OF signed attributes (universal tag
        # 0x31), not the IMPLICIT [0] form carried in the SignerInfo.
        to_verify = b"\x31" + signed_attrs.dump()[1:]
    else:
        to_verify = bytes(econtent)
    sig_algo = signer["signature_algorithm"].signature_algo
    _verify_signature(dsc.public_key.dump(), sig_algo, digest_algo,
                      to_verify, signer["signature"].native)

    # 2. Chain the DSC to a trusted CSCA.
    _verify_dsc_chain(dsc, trust_anchors_der)

    # 3. Parse the LDS Security Object → per-DG hashes.
    lds = LDSSecurityObject.load(bytes(econtent))
    lds_hash_algo = lds["hash_algorithm"]["algorithm"].native
    dg_hashes = {
        int(item["data_group_number"].native): item["data_group_hash_value"].native
        for item in lds["data_group_hash_values"]
    }
    if not dg_hashes:
        raise PAError("LDS Security Object has no data-group hashes")

    return PAResult(
        hash_algo=lds_hash_algo,
        dg_hashes=dg_hashes,
        dsc_subject=dsc.subject.human_friendly,
        issuing_country=_country(dsc),
    )


def check_data_group(pa: PAResult, dg_number: int, dg_bytes: bytes) -> None:
    """Verify a read data group matches its SOD hash. Raises PAError otherwise."""
    expected = pa.dg_hashes.get(dg_number)
    if expected is None:
        raise PAError(f"DG{dg_number} not present in the SOD")
    if _digest(pa.hash_algo, dg_bytes) != expected:
        raise PAError(f"DG{dg_number} hash does not match the SOD (tampered)")


# ── helpers ────────────────────────────────────────────────────────────────

def _signer_cert(sd, signer) -> x509.Certificate:
    sid = signer["sid"]
    certs = [c.chosen for c in sd["certificates"] if c.name == "certificate"]
    if not certs:
        raise PAError("EF.SOD carries no Document Signer Certificate")
    if sid.name == "issuer_and_serial_number":
        want = sid.chosen["serial_number"].native
        for c in certs:
            if c.serial_number == want:
                return c
    elif sid.name == "subject_key_identifier":
        want = sid.chosen.native
        for c in certs:
            if c.key_identifier == want:
                return c
    return certs[0]


def _check_message_digest(signed_attrs, digest_algo: str, econtent: bytes) -> None:
    md = None
    ctype_ok = False
    for attr in signed_attrs:
        name = attr["type"].native
        if name == "message_digest":
            md = attr["values"][0].native
        elif name == "content_type":
            ctype_ok = attr["values"][0].dotted == LDS_SECURITY_OBJECT_OID
    if not ctype_ok:
        raise PAError("signed contentType is not the LDS Security Object")
    if md is None:
        raise PAError("missing messageDigest signed attribute")
    if _digest(digest_algo, econtent) != md:
        raise PAError("messageDigest does not match eContent (tampered)")


def _verify_dsc_chain(dsc: x509.Certificate, trust_anchors_der: list[bytes]) -> None:
    if not trust_anchors_der:
        raise PAError("no CSCA trust anchors configured")
    anchors = [x509.Certificate.load(a) for a in trust_anchors_der]
    issuer = dsc.issuer
    for csca in anchors:
        if csca.subject == issuer:
            _verify_signature(
                csca.public_key.dump(),
                dsc["signature_algorithm"].signature_algo,
                dsc["signature_algorithm"].hash_algo,
                dsc["tbs_certificate"].dump(),
                dsc["signature_value"].native,
            )
            return
    raise PAError("DSC issuer is not a trusted CSCA")


def _country(cert: x509.Certificate) -> str:
    try:
        c = cert.subject.native.get("country_name", "")
        return str(c or "")
    except Exception:  # noqa: BLE001
        return ""
