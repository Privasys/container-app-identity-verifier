# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""ICAO CSCA Master List ingestion (ICAO Doc 9303 Part 12).

A Master List is a CMS SignedData whose eContent is a CscaMasterListData
(version + SET OF Certificate). It is signed by a Master List Signer certificate
that chains to a CSCA included alongside it. We verify the signature and the
signer's chain to a self-signed root carried in the list, then return the
contained CSCA certificates as a PEM bundle for the trust store.

This lets the operator hand the verifier the raw `.ml` (which changes ~quarterly)
and have the enclave validate + extract it, rather than trusting a client-side
conversion.
"""

from __future__ import annotations

import hashlib

from asn1crypto import cms, core, pem, x509

from . import passive_auth

# id-icao-cscaMasterList (ICAO Doc 9303 Part 12).
CSCA_MASTER_LIST_OID = "2.23.136.1.1.2"


class MasterListError(Exception):
    """The master list could not be parsed or verified."""


class _CscaMasterListData(core.Sequence):
    _fields = [
        ("version", core.Integer),
        ("cert_list", core.SetOf, {"spec": x509.Certificate}),
    ]


def _verify_chain_to_root(signer: x509.Certificate, certs: list[x509.Certificate]) -> None:
    """Verify the ML signer chains to a self-signed root present in the list."""
    issuer = signer.issuer
    for ca in certs:
        if ca.subject != issuer:
            continue
        try:
            passive_auth._verify_signature(
                ca.public_key.dump(),
                signer["signature_algorithm"].signature_algo,
                signer["signature_algorithm"].hash_algo,
                signer["tbs_certificate"].dump(),
                signer["signature_value"].native,
            )
        except passive_auth.PAError:
            continue
        # The CA that signed the ML signer must itself be a trust root: self-signed.
        if ca.subject == ca.issuer:
            return
        # Otherwise climb one more level (the root that signed this CA).
        _verify_chain_to_root(ca, certs)
        return
    raise MasterListError("master-list signer does not chain to a root in the list")


def verify_and_extract(ml_bytes: bytes) -> bytes:
    """Verify a CSCA Master List CMS and return its CSCA certs as a PEM bundle."""
    try:
        ci = cms.ContentInfo.load(ml_bytes)
    except Exception as exc:  # noqa: BLE001
        raise MasterListError(f"not valid CMS: {exc}") from exc
    if ci["content_type"].native != "signed_data":
        raise MasterListError("not CMS SignedData")
    sd = ci["content"]

    eci = sd["encap_content_info"]
    if eci["content_type"].dotted != CSCA_MASTER_LIST_OID:
        raise MasterListError("eContent is not a CSCA Master List")
    econtent = eci["content"].native
    if not isinstance(econtent, (bytes, bytearray)):
        raise MasterListError("missing eContent")

    signer = sd["signer_infos"][0]
    digest_algo = signer["digest_algorithm"]["algorithm"].native
    ml_signer = passive_auth._signer_cert(sd, signer)

    # 1. Verify the SignerInfo signature over the eContent.
    signed_attrs = signer["signed_attrs"]
    if signed_attrs and len(signed_attrs) > 0:
        md = None
        for attr in signed_attrs:
            if attr["type"].native == "message_digest":
                md = attr["values"][0].native
        if md is None or passive_auth._digest(digest_algo, bytes(econtent)) != md:
            raise MasterListError("messageDigest does not match the master list content")
        to_verify = b"\x31" + signed_attrs.dump()[1:]
    else:
        to_verify = bytes(econtent)
    try:
        passive_auth._verify_signature(
            ml_signer.public_key.dump(),
            signer["signature_algorithm"].signature_algo,
            digest_algo,
            to_verify,
            signer["signature"].native,
        )
    except passive_auth.PAError as exc:
        raise MasterListError(f"master-list signature invalid: {exc}") from exc

    # 2. Chain the ML signer to a self-signed root carried in the list.
    certs = [c.chosen for c in sd["certificates"] if c.name == "certificate"]
    _verify_chain_to_root(ml_signer, certs)

    # 3. Extract the CSCA certificates (deduped) as a PEM bundle.
    mld = _CscaMasterListData.load(bytes(econtent))
    seen: set[str] = set()
    chunks: list[bytes] = []
    for cert in mld["cert_list"]:
        der = cert.dump()
        h = hashlib.sha256(der).hexdigest()
        if h in seen:
            continue
        seen.add(h)
        chunks.append(pem.armor("CERTIFICATE", der))
    if not chunks:
        raise MasterListError("master list contained no certificates")
    return b"".join(chunks)
