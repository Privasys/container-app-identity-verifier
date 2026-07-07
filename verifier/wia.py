# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""Wallet Instance Attestation (WIA) — wallet-provider JWKS + verification.

Free identity verification must be wallet-only by construction. The IdP, acting
as wallet provider, verifies device integrity (Android hardware key attestation /
iOS App Attest) over the wallet's hardware holder key and issues a short-lived
WIA JWT whose `cnf.jwk` binds exactly that holder key. This enclave requires a
valid WIA (and the key match) before issuing an IVR or a disclosure — the hard
gate that a modified client cannot bypass.

The set of accepted wallet-provider signing keys (a JWKS) is NOT baked into the
measured image (it rotates): it is provisioned at runtime via /configure, stored
on the per-app sealed volume, and its SHA-256 is published as the
WALLET_PROVIDER_JWKS_OID attestation extension — exactly like the CSCA anchors
(see trust_anchors.py) — so a relying party can pin which wallet-provider keys
the verifier trusts from the RA-TLS leaf. See attribute-billing-plan §3.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

from . import config, crypto, manager

_LOCK = threading.Lock()


def _path() -> Path:
    """Wallet-provider JWKS file on the per-app sealed volume (env-overridable)."""
    return Path(os.environ.get("IDENTITY_VERIFIER_DATA_DIR", "/data")) / "wallet_provider_jwks.json"


def _canonical(doc: dict) -> bytes:
    """Deterministic JWKS bytes so the attested digest is stable across restarts."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def load() -> bytes:
    try:
        return _path().read_bytes()
    except FileNotFoundError:
        return b""


def keys() -> list[dict]:
    """The active wallet-provider public keys (JWK dicts)."""
    raw = load()
    if not raw:
        return []
    doc = json.loads(raw)
    return doc.get("keys", []) if isinstance(doc, dict) else []


def digest_hex() -> str:
    raw = load()
    return hashlib.sha256(raw).hexdigest() if raw else ""


def count() -> int:
    return len(keys())


def _validate(doc: dict) -> None:
    """Reject anything that is not a JWKS of usable EC P-256 signing keys, before
    it is persisted and attested."""
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list) or not doc["keys"]:
        raise ValueError("wallet_provider_jwks must be a JWKS with a non-empty keys array")
    for k in doc["keys"]:
        if not isinstance(k, dict):
            raise ValueError("each JWKS key must be an object")
        if not k.get("kid"):
            raise ValueError("each wallet-provider key needs a kid")
        # from_jwk validates kty/crv/coordinate lengths.
        crypto.public_from_jwk(k)


def set_jwks(doc: dict, *, push_oid: bool = True) -> str:
    """Persist a new wallet-provider JWKS and publish its digest as the attested
    OID. Returns the hex digest. Gated to the app owner / admin at the API layer
    (it is a /configure input, the configure-authz standard)."""
    _validate(doc)
    data = _canonical(doc)
    with _LOCK:
        path = _path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_bytes(data)
        tmp.replace(path)
        d = hashlib.sha256(data).digest()
    if push_oid and manager.available():
        manager.set_attestation_extension(config.WALLET_PROVIDER_JWKS_OID, d)
    return d.hex()


def verify_wia(token: str, holder_pub_raw: bytes) -> dict:
    """Verify a Wallet Instance Attestation and return its claims. The WIA must:
      - be signed by a provisioned wallet-provider key (ES256, kid-selected),
      - be unexpired (exp required), and
      - bind exactly this holder key: cnf.jwk == JWK(holder_pub).
    Raises ValueError on any failure. Note: the WIA attests that the holder key
    lives in genuine hardware inside our genuine app — the wallet's per-request
    holder signature (checked separately by receipt.check_holder on prove_*)
    proves possession; on verify_identity the holder key is bound into the IVR."""
    jwks = keys()
    if not jwks:
        raise ValueError("no wallet-provider keys configured")
    claims = crypto.verify_jwt_jwks(token, jwks)

    exp = claims.get("exp")
    if exp is None:
        raise ValueError("WIA missing exp")
    if int(exp) < int(time.time()):
        raise ValueError("WIA expired")

    cnf = claims.get("cnf")
    jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
    if not isinstance(jwk, dict):
        raise ValueError("WIA missing cnf.jwk")
    holder_jwk = crypto.PublicKey.from_raw(holder_pub_raw).jwk_public()
    if crypto.normalize_ec_jwk(jwk) != holder_jwk:
        raise ValueError("WIA cnf.jwk does not match the holder key")
    return claims
