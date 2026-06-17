# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""Document authentication and biometric matching.

These are the heavy, in-enclave steps. They are NOT wired yet — this module
defines the interfaces and a clearly-gated dev stub so the crypto + receipt +
disclosure flow is testable end-to-end without a real passport. Replace the
stubs with the open-source implementations below (all permissive / no licence
fee; see kyc-enclave-design.md §7):

  Passive Authentication (EF.SOD CMS signature → DSC → CSCA chain + DG hashes)
  and Chip/Active Authentication:
      Rust crypto (x509/CMS) or Python `asn1crypto`/`pyca cryptography`;
      references: ZeroPass/pymrtd, the Rust `emrtd` crate.
  DG2 face image decode:
      jnbis (JPEG2000/WSQ, legacy ISO 19794-5) + an ISO 39794-5 parser
      (new, ICAO Doc 9303 eff. 2026-01-01) — must support BOTH.
  Face match (DG2 portrait ↔ live capture):
      AuraFace (open ArcFace, commercial-OK) / FaceNet-512 (MIT), ONNX Runtime.
  Liveness / presentation-attack detection:
      Silent-Face / MiniFASNetV2 (Apache-2.0) + an active challenge.

EVERYTHING here runs in-enclave with NO external calls — that is the whole point
(kyc-enclave-design.md §7). Do not call a vendor cloud.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import config


class VerificationError(Exception):
    """Raised when a document or biometric check fails (or isn't wired)."""


@dataclass
class DocResult:
    fields: dict          # CERTIFIED_FIELDS → value (extracted from the chip)
    doc_type: str
    issuing_state: str
    doc_expiry: str       # YYYY-MM-DD
    passive_auth: bool
    chip_auth: bool


@dataclass
class BioResult:
    face_match: bool
    liveness_score: float


def authenticate_and_extract(request: dict) -> DocResult:
    """Verify the eMRTD (PA + CA) and extract the certified fields.

    PROD: parse DG1/DG2/SOD, run Passive + Chip Authentication against the
    active CSCA trust anchors, and extract fields from the chip itself.
    """
    if not config.ALLOW_DEV_STUB:
        raise VerificationError(
            "passive/chip authentication not wired — see verifier/verification.py "
            "(set IDENTITY_VERIFIER_DEV_STUB=1 only for dev/test)"
        )
    # Dev stub: trust pre-parsed fields from the request; treat PA/CA as passed.
    fields = request.get("fields") or {}
    extracted = {k: str(fields[k]) for k in config.CERTIFIED_FIELDS if fields.get(k)}
    if "birthdate" not in extracted:
        raise VerificationError("dev stub: 'fields.birthdate' is required")
    return DocResult(
        fields=extracted,
        doc_type=extracted.get("document_type", "P"),
        issuing_state=extracted.get("issuing_state", "UTO"),
        doc_expiry=str(request.get("doc_expiry", "2099-12-31")),
        passive_auth=True,
        chip_auth=True,
    )


def match_biometric(request: dict, doc: DocResult) -> BioResult:
    """Compare the live capture to the DG2 portrait and score liveness.

    PROD: decode DG2, run the face matcher (ONNX) + liveness (MiniFASNet +
    active challenge) in-enclave; threshold both.
    """
    if not config.ALLOW_DEV_STUB:
        raise VerificationError(
            "face match / liveness not wired — see verifier/verification.py "
            "(set IDENTITY_VERIFIER_DEV_STUB=1 only for dev/test)"
        )
    return BioResult(face_match=True, liveness_score=0.99)
