# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""Cryptographic primitives for the identity verifier.

ES256 (P-256) signing for the Identity Verification Receipt (IVR) and disclosure
tokens, SHA-256 field commitments, and the small JOSE helpers (base64url, raw
R||S signatures) needed to emit/verify compact JWS.

Why ES256: consistent with the Privasys IdP's ES256/JWKS ecosystem so relying
parties verify disclosure tokens the same way they verify IdP tokens.

Key custody (kyc-enclave-design.md §4): the signing key is **generated inside
the enclave on first start** and persisted on the per-app sealed volume
(IDENTITY_VERIFIER_DATA_DIR, /data on the platform). That volume's data key is
vault-wrapped under the app-identity (MR_APP) policy, so the signing key is
re-released only to owner-approved measurements of THIS app: it survives
restarts and promoted upgrades, and it is never minted or exportable outside
the enclave. On the platform an externally supplied PEM is REFUSED — a key a
human ever held could mint "enclave" receipts from a laptop. The PEM env and
the ephemeral fallback exist for dev/test only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.exceptions import InvalidSignature

_CURVE = ec.SECP256R1()
_COORD_BYTES = 32  # P-256 field element size


# ── base64url + canonical JSON ───────────────────────────────────────────

def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON encoding (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ── commitments ──────────────────────────────────────────────────────────

def new_salt() -> bytes:
    return os.urandom(16)


def commit(value: str, salt: bytes) -> str:
    """C = b64url(SHA-256(value ‖ salt)). Hides the value; salt prevents
    correlation/guessing across fields and users."""
    h = hashlib.sha256()
    h.update(value.encode("utf-8"))
    h.update(salt)
    return b64u_encode(h.digest())


def commit_matches(value: str, salt: bytes, commitment: str) -> bool:
    expected = commit(value, salt)
    # constant-time compare on the decoded digests
    return _ct_eq(b64u_decode(expected), b64u_decode(commitment))


def _ct_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    res = 0
    for x, y in zip(a, b):
        res |= x ^ y
    return res == 0


# ── ES256 raw signatures (JOSE) ──────────────────────────────────────────

def _der_to_raw(der: bytes) -> bytes:
    r, s = decode_dss_signature(der)
    return r.to_bytes(_COORD_BYTES, "big") + s.to_bytes(_COORD_BYTES, "big")


def _raw_to_der(raw: bytes) -> bytes:
    if len(raw) != 2 * _COORD_BYTES:
        raise ValueError("bad ES256 signature length")
    r = int.from_bytes(raw[:_COORD_BYTES], "big")
    s = int.from_bytes(raw[_COORD_BYTES:], "big")
    return encode_dss_signature(r, s)


@dataclass
class SigningKey:
    """The verifier's ES256 signing key + a stable kid (SHA-256 of the SPKI)."""

    _priv: ec.EllipticCurvePrivateKey

    @property
    def kid(self) -> str:
        spki = self._priv.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return b64u_encode(hashlib.sha256(spki).digest()[:16])

    def sign(self, msg: bytes) -> bytes:
        der = self._priv.sign(msg, ec.ECDSA(hashes.SHA256()))
        return _der_to_raw(der)

    def public(self) -> "PublicKey":
        return PublicKey(self._priv.public_key())

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(ec.generate_private_key(_CURVE))

    @classmethod
    def from_pem(cls, pem: bytes) -> "SigningKey":
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("not an EC private key")
        return cls(key)

    @classmethod
    def load(cls) -> "SigningKey":
        """Resolve the signing key, strongest custody first:

        1. The key persisted on the per-app sealed volume — generated
           IN-ENCLAVE on first start, never exported. The volume's data key is
           vault-wrapped under the MR_APP policy, so it re-releases only to
           owner-approved measurements of this app (survives restarts and
           promoted upgrades; a restart no longer rotates the JWKS and
           strands outstanding IVRs).
        2. IDENTITY_VERIFIER_SIGNING_KEY_PEM (path or inline) — dev/test
           ONLY. On the platform (PRIVASYS_IMAGE_DIGEST set) it is refused:
           a key a human ever held could mint "enclave" receipts outside
           the enclave, which would void the audit story.
        3. Ephemeral — bare dev/test runs with no data dir.
        """
        on_platform = bool(os.environ.get("PRIVASYS_IMAGE_DIGEST"))
        ref = os.environ.get("IDENTITY_VERIFIER_SIGNING_KEY_PEM", "")
        if ref:
            if on_platform:
                raise RuntimeError(
                    "refusing an externally supplied signing key inside the "
                    "enclave — the key is generated in-enclave and sealed on "
                    "the app volume (unset IDENTITY_VERIFIER_SIGNING_KEY_PEM)"
                )
            data = open(ref, "rb").read() if os.path.exists(ref) else ref.encode()
            return cls.from_pem(data)

        key_path = os.path.join(
            os.environ.get("IDENTITY_VERIFIER_DATA_DIR", "/data"), "signing_key.pem"
        )
        try:
            if os.path.exists(key_path):
                with open(key_path, "rb") as f:
                    return cls.from_pem(f.read())
            key = cls.generate()
            pem = key._priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            # 0600, exclusive create: single-writer app; a concurrent loser
            # falls through to reading the winner's key on next start.
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, pem)
            finally:
                os.close(fd)
            return key
        except OSError as exc:
            if on_platform:
                # The sealed volume is the ONLY acceptable custody in prod —
                # never fall through to an ephemeral (restart-rotating) key.
                raise RuntimeError(
                    f"cannot persist the signing key on the sealed volume: {exc}"
                ) from exc
            return cls.generate()


@dataclass
class PublicKey:
    _pub: ec.EllipticCurvePublicKey

    def verify(self, msg: bytes, raw_sig: bytes) -> bool:
        try:
            self._pub.verify(_raw_to_der(raw_sig), msg, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError):
            return False

    def jwk_public(self) -> dict:
        """Minimal EC JWK (kty/crv/x/y) — e.g. a disclosure token's cnf.jwk."""
        nums = self._pub.public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": b64u_encode(nums.x.to_bytes(_COORD_BYTES, "big")),
            "y": b64u_encode(nums.y.to_bytes(_COORD_BYTES, "big")),
        }

    def jwk(self, kid: str) -> dict:
        return {**self.jwk_public(), "use": "sig", "alg": "ES256", "kid": kid}

    def raw(self) -> bytes:
        """Uncompressed SEC1 point (0x04 ‖ X ‖ Y)."""
        return self._pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

    @classmethod
    def from_raw(cls, raw: bytes) -> "PublicKey":
        return cls(ec.EllipticCurvePublicKey.from_encoded_point(_CURVE, raw))


# ── compact JWS ──────────────────────────────────────────────────────────

def jws_sign(payload: dict, key: SigningKey, typ: str) -> str:
    header = {"alg": "ES256", "typ": typ, "kid": key.kid}
    signing_input = (
        b64u_encode(canonical_json(header)).encode()
        + b"."
        + b64u_encode(canonical_json(payload)).encode()
    )
    sig = key.sign(signing_input)
    return signing_input.decode() + "." + b64u_encode(sig)


def jws_verify(token: str, pub: PublicKey) -> dict:
    """Verify a compact JWS and return the payload. Raises on failure."""
    try:
        h_b64, p_b64, s_b64 = token.split(".")
    except ValueError as exc:
        raise ValueError("malformed JWS") from exc
    signing_input = (h_b64 + "." + p_b64).encode()
    if not pub.verify(signing_input, b64u_decode(s_b64)):
        raise ValueError("bad signature")
    return json.loads(b64u_decode(p_b64))


def holder_binding(holder_pub_raw: bytes) -> str:
    """The IVR binds to SHA-256 of the holder's SEC1 public key."""
    return b64u_encode(hashlib.sha256(holder_pub_raw).digest())


# ── JWKS-verified JWTs (e.g. the Wallet Instance Attestation) ─────────────

def public_from_jwk(jwk: dict) -> "PublicKey":
    """Build a PublicKey from a minimal EC P-256 public JWK (kty/crv/x/y)."""
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("unsupported JWK (want EC P-256)")
    x = b64u_decode(jwk["x"]) if jwk.get("x") else b""
    y = b64u_decode(jwk["y"]) if jwk.get("y") else b""
    if len(x) != _COORD_BYTES or len(y) != _COORD_BYTES:
        raise ValueError("bad EC coordinate length")
    return PublicKey.from_raw(b"\x04" + x + y)


def normalize_ec_jwk(jwk: dict) -> dict:
    """Canonical minimal EC public JWK (kty/crv/x/y, fixed 32-byte coords) for
    equality comparison — tolerant of coordinate zero-padding and extra members."""
    return public_from_jwk(jwk).jwk_public()


def verify_jwt_jwks(token: str, jwks: list[dict]) -> dict:
    """Verify a compact JWS/JWT against a JWKS of EC P-256 keys and return the
    claims. Selects the key by header `kid` (any key when the JWT omits kid),
    pins `alg=ES256`, and checks the signature. Does NOT check `exp`/`typ` — the
    caller applies those policy checks (mirrors `jws_verify`). Raises ValueError
    on any failure."""
    try:
        h_b64, p_b64, s_b64 = token.split(".")
    except ValueError as exc:
        raise ValueError("malformed JWT") from exc
    try:
        header = json.loads(b64u_decode(h_b64))
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError("malformed JWT header") from exc
    if header.get("alg") != "ES256":
        raise ValueError("unexpected JWT alg (want ES256)")
    kid = header.get("kid")
    candidates = [k for k in jwks if not kid or k.get("kid") == kid]
    if not candidates:
        raise ValueError("no wallet-provider key matches the JWT kid")
    signing_input = (h_b64 + "." + p_b64).encode()
    sig = b64u_decode(s_b64)
    for jwk in candidates:
        try:
            pub = public_from_jwk(jwk)
        except ValueError:
            continue
        if pub.verify(signing_input, sig):
            return json.loads(b64u_decode(p_b64))
    raise ValueError("JWT signature did not verify against any wallet-provider key")
