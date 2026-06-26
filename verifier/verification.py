# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""Document + biometric verification for `verify_identity`.

Orchestrates the real checks:
  - Passive Authentication of EF.SOD against the active CSCA trust anchors, and
    integrity of each supplied data group (verifier/passive_auth.py);
  - MRZ field extraction from the authenticated DG1 (verifier/mrz.py);
  - face match (DG2 ↔ live capture) + liveness (verifier/biometrics.py).

Active/Chip Authentication (anti-clone) is a documented hardening TODO: RSA AA
uses ISO 9796-2 and Chip Authentication a DH key agreement — both need a vetted
eMRTD implementation (per the "don't hand-roll crypto" rule). Passive
Authentication + biometric holder-binding are the v1 gates.
"""

from __future__ import annotations

import base64
import datetime
from dataclasses import dataclass

from . import biometrics, mrz, passive_auth, trust_anchors
from .biometrics import BioResult, BiometricError  # re-exported for receipt.py


class VerificationError(Exception):
    """Document or biometric verification failed."""


@dataclass
class DocResult:
    fields: dict          # certified fields from DG1
    doc_type: str
    issuing_state: str
    doc_expiry: str       # YYYY-MM-DD
    passive_auth: bool
    chip_auth: bool       # Active/Chip Authentication (anti-clone); TODO
    viz_match: bool | None = None  # GPG45 box 3: OCR'd visual MRZ == chip DG1 MRZ
                                   # (None = not supplied by the client)
    not_expired: bool = True       # document expiry > today (hard-gated below)
    mrz_valid: bool = True         # DG1 MRZ check digits are self-consistent
    dsc_time_valid: bool | None = None  # DSC+CSCA verified valid at SOD signingTime
                                        # (None = SOD carried no signingTime)


def _b64(s: str) -> bytes:
    try:
        return base64.b64decode(s, validate=False)
    except Exception as exc:  # noqa: BLE001
        raise VerificationError("invalid base64 input") from exc


def authenticate_and_extract(body: dict) -> tuple[DocResult, dict]:
    """Run Passive Authentication + DG integrity, extract DG1 fields.

    Returns (DocResult, data_groups) where data_groups maps DG number → bytes.
    """
    sod = body.get("sod")
    if not sod:
        raise VerificationError("sod (EF.SOD) is required")
    dgs_in = body.get("data_groups") or {}
    try:
        dgs = {int(k): _b64(v) for k, v in dgs_in.items()}
    except (TypeError, ValueError) as exc:
        raise VerificationError("data_groups must map DG number → base64") from exc
    if 1 not in dgs:
        raise VerificationError("DG1 is required")

    try:
        pa = passive_auth.verify(_b64(sod), trust_anchors.anchors_der())
        for n, raw in dgs.items():
            passive_auth.check_data_group(pa, n, raw)
    except passive_auth.PAError as exc:
        raise VerificationError(f"passive authentication failed: {exc}") from exc

    try:
        fields = mrz.parse_dg1(dgs[1])
    except mrz.MRZError as exc:
        raise VerificationError(f"DG1: {exc}") from exc

    # DG11 (optional) — additional personal details (place of birth, personal
    # number). Already hash-checked against the SOD by the loop above, so trusted.
    if 11 in dgs:
        try:
            fields.update(mrz.parse_dg11(dgs[11]))
        except mrz.MRZError:
            pass

    # Hard gate: reject an expired document. The MRZ expiry is the last day the
    # document is valid, so it is expired only strictly before today (UTC).
    expiry = fields.get("doc_expiry", "")
    try:
        exp_date = datetime.date.fromisoformat(expiry) if expiry else None
    except ValueError as exc:
        raise VerificationError(f"invalid document expiry date {expiry!r}") from exc
    if exp_date is None:
        raise VerificationError("document has no expiry date")
    if exp_date < datetime.datetime.now(datetime.timezone.utc).date():
        raise VerificationError(f"document expired on {expiry}")

    # Soft signal: DG1 MRZ check-digit self-consistency. On a Passive-Auth-genuine
    # DG1 this is always true (ICAO-mandated), so a false here is recorded for the
    # relying party rather than hard-failing a genuine (if oddly encoded) chip.
    mrz_valid = mrz.check_digits_consistent(dgs[1])

    # GPG45 box 3 (M1C) — cross-reference the *visual* data against the chip. The
    # wallet sends the data-page image; we OCR it here with OmniMRZ (the on-device
    # OCR is unreliable on OCR-B) and check the read is consistent with DG1. The
    # chip is authoritative and doc number / DOB / expiry are already BAC-proven,
    # so we tolerate OCR noise and fail only on a genuine contradiction (likely
    # tampering). No image ⇒ box 3 not performed (viz_match=None).
    # M1C: record the result as a fraud signal, do NOT hard-fail. The chip +
    # biometric are authoritative and OmniMRZ can misread, so a mismatch (or a
    # screenshot/replay flag) is surfaced for review but does not block a genuine
    # holder. (At higher confidence these would gate.)
    viz_match: bool | None = None
    doc_image = body.get("doc_image")
    if doc_image:
        from . import doc_ocr
        ocr = doc_ocr.read_mrz(_b64(doc_image))
        if ocr.get("mrz"):
            viz_match = mrz.cross_reference(ocr["mrz"], dgs[1]).get("consistent")
        if ocr.get("is_screenshot"):
            viz_match = False  # replay/screenshot of the page → not consistent

    return DocResult(
        fields=fields,
        doc_type=fields.get("document_type", "P"),
        issuing_state=fields.get("issuing_state", pa.issuing_country),
        doc_expiry=fields.get("doc_expiry", ""),
        passive_auth=True,
        chip_auth=False,  # AA/CA not yet wired (see module docstring)
        viz_match=viz_match,
        not_expired=True,  # enforced above; recorded for the receipt
        mrz_valid=mrz_valid,
        dsc_time_valid=True if pa.signing_time_verified else None,
    ), dgs


def match_biometric(body: dict, dgs: dict) -> BioResult:
    """Face match (DG2 ↔ live capture) + liveness."""
    dg2 = dgs.get(2, b"")
    live = body.get("live_image")
    live_bytes = _b64(live) if live else b""
    try:
        return biometrics.match(dg2, live_bytes)
    except BiometricError as exc:
        raise VerificationError(str(exc)) from exc
