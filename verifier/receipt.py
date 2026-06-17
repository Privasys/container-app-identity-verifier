# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""Identity Verification Receipt (IVR) + disclosure tokens (commit-and-prove).

`verify_identity` issues a signed IVR: per-field SHA-256 commitments + validity
+ holder binding. The wallet keeps the field values + salts. Later, cheap
`prove_*` derivations re-open only the one commitment they need and return a
short-lived, audience-bound disclosure token. The enclave stores nothing.

See kyc-enclave-design.md §1, §2, §4, §5.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone

from . import config, crypto
from .verification import BioResult, DocResult


def _now() -> int:
    return int(time.time())


# ── IVR ──────────────────────────────────────────────────────────────────

def build_ivr(
    key: crypto.SigningKey,
    measurement: str,
    doc: DocResult,
    bio: BioResult,
    holder_pub_raw: bytes,
) -> tuple[str, dict]:
    """Return (ivr_jws, salts) where salts maps field → b64url(salt).

    The wallet stores {value, salt} per field; the enclave keeps neither.
    """
    salts: dict[str, str] = {}
    commitments: dict[str, str] = {}
    for field, value in doc.fields.items():
        salt = crypto.new_salt()
        salts[field] = crypto.b64u_encode(salt)
        commitments[field] = crypto.commit(value, salt)

    now = _now()
    payload = {
        "v": 1,
        "jti": crypto.b64u_encode(os.urandom(16)),
        "measurement": measurement,
        "verifier_id": "privasys-identity",
        "holder_binding": crypto.holder_binding(holder_pub_raw),
        "doc": {
            "passive_auth": doc.passive_auth,
            "chip_auth": doc.chip_auth,
            "doc_type": doc.doc_type,
            "issuing_state": doc.issuing_state,
            "doc_expiry": doc.doc_expiry,
        },
        "biometric": {
            "face_match": bio.face_match,
            "liveness_score": round(bio.liveness_score, 4),
        },
        "commitments": commitments,
        "iat": now,
        "exp": now + config.IVR_TTL_SECONDS,
    }
    return crypto.jws_sign(payload, key, config.IVR_TYP), salts


def verify_ivr(ivr_jws: str, pub: crypto.PublicKey) -> dict:
    """Verify the IVR signature + expiry + that it passed verification. Raises."""
    payload = crypto.jws_verify(ivr_jws, pub)  # raises on bad sig
    if payload.get("exp", 0) < _now():
        raise ValueError("IVR expired")
    doc = payload.get("doc", {})
    bio = payload.get("biometric", {})
    if not (doc.get("passive_auth") and doc.get("chip_auth") and bio.get("face_match")):
        raise ValueError("IVR did not pass verification")
    return payload


# ── holder binding ────────────────────────────────────────────────────────

def _holder_message(jti: str, rp_id: str, nonce: str, ts: int) -> bytes:
    return crypto.canonical_json(
        {"ivr": jti, "rp_id": rp_id, "nonce": nonce, "ts": ts}
    )


def check_holder(
    ivr: dict,
    holder_pub_raw: bytes,
    rp_id: str,
    nonce: str,
    ts: int,
    holder_sig_raw: bytes,
) -> None:
    """Verify the request comes from the IVR's bound holder. Raises on failure.

    Binds the disclosure to the wallet's hardware key (the same key used for
    FIDO2): a stolen IVR is useless without it.
    """
    if crypto.holder_binding(holder_pub_raw) != ivr.get("holder_binding"):
        raise ValueError("holder key does not match IVR binding")
    if abs(_now() - ts) > 300:
        raise ValueError("stale holder timestamp")
    msg = _holder_message(ivr["jti"], rp_id, nonce, ts)
    if not crypto.PublicKey.from_raw(holder_pub_raw).verify(msg, holder_sig_raw):
        raise ValueError("bad holder signature")


def _open(ivr: dict, field: str, value: str, salt_b64: str) -> None:
    commitment = ivr.get("commitments", {}).get(field)
    if not commitment:
        raise ValueError(f"IVR has no commitment for {field!r}")
    if not crypto.commit_matches(value, crypto.b64u_decode(salt_b64), commitment):
        raise ValueError(f"value for {field!r} does not match the IVR commitment")


# ── disclosure tokens ──────────────────────────────────────────────────────

def _evidence(ivr: dict) -> dict:
    return {
        "ivr": ivr["jti"],
        "doc_type": ivr["doc"]["doc_type"],
        "issuing_state": ivr["doc"]["issuing_state"],
        "verified_at": ivr["iat"],
    }


def _token(key: crypto.SigningKey, ivr: dict, sub: str, rp_id: str,
           claim: str, value) -> str:
    now = _now()
    payload = {
        "iss": ivr["verifier_id"],
        "sub": sub,           # pairwise sub for rp_id (computed by the wallet)
        "aud": rp_id,
        "claim": claim,
        "value": value,
        "assurance": "gov",
        "evidence": _evidence(ivr),
        "iat": now,
        "exp": now + config.TOKEN_TTL_SECONDS,
    }
    return crypto.jws_sign(payload, key, config.DISCLOSURE_TYP)


# ── derivations (each = one consented disclosure) ──────────────────────────

def _age_from(birthdate: str) -> int:
    try:
        bd = datetime.strptime(birthdate, "%Y-%m-%d").date()
    except ValueError as exc:
        raise ValueError("birthdate must be YYYY-MM-DD") from exc
    today = datetime.now(timezone.utc).date()
    return today.year - bd.year - ((today.month, today.day) < (bd.month, bd.day))


def prove_age_over(key, ivr, sub, rp_id, birthdate, salt_b64, threshold) -> str:
    _open(ivr, "birthdate", birthdate, salt_b64)
    over = _age_from(birthdate) >= int(threshold)
    return _token(key, ivr, sub, rp_id, f"age_over_{int(threshold)}", over)


# Default age bands (lower-inclusive). Override per request if needed.
DEFAULT_BANDS = (0, 13, 16, 18, 21, 25, 65)


def _band_label(age: int, bounds) -> str:
    bounds = sorted(set(int(b) for b in bounds))
    lo = bounds[0]
    for b in bounds[1:]:
        if age < b:
            return f"{lo}-{b - 1}"
        lo = b
    return f"{lo}+"


def prove_age_band(key, ivr, sub, rp_id, birthdate, salt_b64, bands=None) -> str:
    _open(ivr, "birthdate", birthdate, salt_b64)
    label = _band_label(_age_from(birthdate), bands or DEFAULT_BANDS)
    return _token(key, ivr, sub, rp_id, "age_band", label)


def prove_field(key, ivr, sub, rp_id, field, value, salt_b64) -> str:
    if field not in config.CERTIFIED_FIELDS:
        raise ValueError(f"{field!r} is not a certified field")
    _open(ivr, field, value, salt_b64)
    return _token(key, ivr, sub, rp_id, field, value)


def prove_document_valid(key, ivr, sub, rp_id) -> str:
    # No field disclosed — only that a genuine government document was verified.
    return _token(key, ivr, sub, rp_id, "document_valid", True)
