# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""Privasys Identity Verifier — confidential-computing container app.

Receipt-based identity verification: `verify_identity` issues a signed Identity
Verification Receipt (IVR) of per-field commitments; cheap `prove_*` derivations
return consented, audience-bound, government-certified disclosure tokens. Raw data
stays with the client. See .operations/identity-platform/kyc-enclave-design.md.

HTTP on $PORT (platform-allocated; 8080 fallback) with RA-TLS terminated in front.
Configure-then-freeze: the app boots frozen (503) until POST /configure
provisions the CSCA trust anchors.
"""

from __future__ import annotations

import base64
import http.server
import json
import os
import threading
import time
from urllib.parse import urlparse

from verifier import aa, config, crypto, manager, master_list, mrz, receipt, trust_anchors
from verifier.verification import VerificationError, authenticate_and_extract, match_biometric

# ── Process state ────────────────────────────────────────────────────────
_CONFIG_LOCK = threading.Lock()
_CONFIGURED = False
_SIGNING_KEY = crypto.SigningKey.load()
_MEASUREMENT_PLACEHOLDER = "unbound"  # PROD: the enclave measurement (OID 3.2)

_OPEN_PATHS = ("/health", "/version", "/.well-known/jwks.json")


def _b64u_field(payload: dict, name: str) -> bytes:
    v = payload.get(name)
    if not isinstance(v, str) or not v:
        raise ValueError(f"{name} (base64url string) is required")
    return crypto.b64u_decode(v)


def _require(payload: dict, name: str):
    v = payload.get(name)
    if v in (None, ""):
        raise ValueError(f"{name} is required")
    return v


class Handler(http.server.BaseHTTPRequestHandler):
    # ── helpers ──────────────────────────────────────────────────────────
    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw or b"{}")

    def _frozen(self, path: str) -> bool:
        if path in _OPEN_PATHS:
            return False
        with _CONFIG_LOCK:
            return not _CONFIGURED

    # ── GET ──────────────────────────────────────────────────────────────
    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if self._frozen(path):
            self._json(503, {"error": "app is awaiting initial configuration"})
            return
        if path == "/health":
            self._json(200, {"status": "healthy"})
        elif path == "/version":
            self._json(200, {"version": config.APP_VERSION})
        elif path == "/.well-known/jwks.json":
            pub = _SIGNING_KEY.public()
            self._json(200, {"keys": [pub.jwk(_SIGNING_KEY.kid)]})
        elif path == "/trust-anchors":
            self._json(200, {"digest": trust_anchors.digest_hex(),
                             "count": trust_anchors.count(),
                             "oid": config.TRUST_ANCHORS_OID})
        else:
            self._json(404, {"error": "not found"})

    # ── POST ─────────────────────────────────────────────────────────────
    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/configure":
            self._configure()
            return
        if self._frozen(path):
            self._json(503, {"error": "app is awaiting initial configuration"})
            return
        try:
            body = self._body()
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid JSON body"})
            return

        try:
            if path == "/read-mrz":
                self._read_mrz(body)
            elif path == "/aa-challenge":
                self._aa_challenge()
            elif path == "/verify-identity":
                self._verify_identity(body)
            elif path == "/prove/age-over":
                self._prove(body, self._do_age_over)
            elif path == "/prove/age-band":
                self._prove(body, self._do_age_band)
            elif path == "/prove/field":
                self._prove(body, self._do_field)
            elif path == "/prove/document-valid":
                self._prove(body, self._do_document_valid)
            elif path == "/trust-anchors":
                self._set_trust_anchors(body)
            else:
                self._json(404, {"error": "not found"})
        except (ValueError, VerificationError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            self._json(500, {"error": str(exc)})

    # ── endpoints ─────────────────────────────────────────────────────────
    def _configure(self) -> None:
        try:
            body = self._body()
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid JSON body"})
            return
        try:
            # Trust anchors are supplied ONLY as a raw ICAO CSCA Master List: the
            # verifier validates its CMS signature and that it chains to the pinned
            # ICAO/UN CSCA root, then stores the contained CSCAs. There is no raw,
            # unsigned anchor path — that would defeat the verification.
            ml_b64 = body.get("master_list_cms")
            if not ml_b64:
                self._json(400, {"error": "master_list_cms (base64 ICAO CSCA Master List) is required"})
                return
            import base64
            trust_anchors.set_anchors(master_list.verify_and_extract(base64.b64decode(ml_b64)))
            if manager.available():
                manager.config_complete()
        except master_list.MasterListError as exc:
            self._json(400, {"error": f"master list rejected: {exc}"})
            return
        except Exception as exc:  # noqa: BLE001 — surface manager/validation error
            self._json(500, {"error": str(exc)})
            return
        global _CONFIGURED
        with _CONFIG_LOCK:
            _CONFIGURED = True
        self._json(200, {"status": "configured",
                         "trust_anchors_digest": trust_anchors.digest_hex()})

    def _read_mrz(self, body: dict) -> None:
        """Pre-NFC step: OCR the data-page image with OmniMRZ and return the
        BAC/PACE access-key fields (document number + birth/expiry dates). The
        on-device OCR is unreliable on the OCR-B MRZ, so the wallet unlocks the
        chip with this enclave-grade read instead. Raw image stays only for this
        RA-TLS hop; nothing is persisted."""
        from verifier import doc_ocr  # lazy: keep PaddleOCR off the startup path
        image = body.get("doc_image")
        if not isinstance(image, str) or not image:
            raise ValueError("doc_image (base64) is required")
        try:
            raw = base64.b64decode(image, validate=False)
        except Exception as exc:  # noqa: BLE001
            raise ValueError("doc_image is not valid base64") from exc
        ocr = doc_ocr.read_mrz(raw)
        try:
            fields = mrz.mrz_access_fields(ocr.get("mrz") or "")
        except mrz.MRZError as exc:
            # OCR could not produce a usable, check-digit-valid MRZ — ask the
            # client to retake rather than attempt the chip with a bad key.
            self._json(422, {"error": f"could not read the document MRZ: {exc}",
                             "is_screenshot": ocr.get("is_screenshot")})
            return
        self._json(200, {**fields, "is_screenshot": ocr.get("is_screenshot")})

    def _aa_challenge(self) -> None:
        """Issue a fresh Active Authentication challenge the chip must sign. The
        nonce is wrapped in a short-lived JWS the enclave signs, so freshness is
        verified statelessly when the chip's signature comes back."""
        nonce = os.urandom(8)
        exp = int(time.time()) + config.AA_CHALLENGE_TTL_SECONDS
        token = crypto.jws_sign(
            {"n": crypto.b64u_encode(nonce), "exp": exp},
            _SIGNING_KEY, config.AA_CHALLENGE_TYP)
        self._json(200, {"challenge": crypto.b64u_encode(nonce), "token": token})

    def _check_active_auth(self, body: dict, dgs: dict) -> bool:
        """When the chip carries DG15, the holder must prove the chip is genuine
        via Active Authentication over our fresh challenge. Returns True when
        verified, False when the chip's AA key type is not yet verifiable (RSA /
        ISO 9796-2). Raises VerificationError on a missing block or a bad
        signature (a clone)."""
        if 15 not in dgs:
            return False
        blk = body.get("aa")
        if not isinstance(blk, dict):
            raise VerificationError("DG15 present: Active Authentication is required")
        try:
            payload = crypto.jws_verify(blk.get("token", ""), _SIGNING_KEY.public())
        except ValueError as exc:
            raise VerificationError("invalid Active Authentication challenge token") from exc
        if int(payload.get("exp", 0)) < int(time.time()):
            raise VerificationError("Active Authentication challenge expired")
        challenge_b64 = blk.get("challenge", "")
        if not challenge_b64 or payload.get("n") != challenge_b64:
            raise VerificationError("Active Authentication challenge mismatch")
        try:
            aa.verify(dgs[15], crypto.b64u_decode(challenge_b64),
                      _b64u_field(blk, "signature"))
            return True
        except aa.AAUnsupported:
            return False  # recorded as chip_auth=false; not yet enforced
        except aa.AAError as exc:
            raise VerificationError(f"Active Authentication failed: {exc}") from exc

    def _verify_identity(self, body: dict) -> None:
        holder_pub = _b64u_field(body, "holder_pub")
        doc, dgs = authenticate_and_extract(body)
        doc.chip_auth = self._check_active_auth(body, dgs)
        bio = match_biometric(body, dgs)
        ivr, salts = receipt.build_ivr(
            _SIGNING_KEY, _MEASUREMENT_PLACEHOLDER, doc, bio, holder_pub
        )
        # `salts` go to the client so it can later open commitments; the enclave
        # keeps nothing. The client auto-fills its profile from doc.fields as
        # gov-assurance attributes (kyc-enclave-design §2.1).
        self._json(200, {"ivr": ivr, "salts": salts, "fields": doc.fields,
                         "viz_match": doc.viz_match})

    def _prove(self, body: dict, fn) -> None:
        """Shared pre-flight for every derivation: verify IVR + holder binding,
        then run the specific derivation `fn(ivr, sub, rp_id, body)`."""
        ivr = receipt.verify_ivr(_require(body, "ivr"), _SIGNING_KEY.public())
        sub = _require(body, "sub")
        rp_id = _require(body, "rp_id")
        receipt.check_holder(
            ivr,
            _b64u_field(body, "holder_pub"),
            rp_id,
            _require(body, "nonce"),
            int(_require(body, "ts")),
            _b64u_field(body, "holder_sig"),
        )
        token = fn(ivr, sub, rp_id, body)
        self._json(200, {"token": token})

    def _do_age_over(self, ivr, sub, rp_id, body) -> str:
        return receipt.prove_age_over(
            _SIGNING_KEY, ivr, sub, rp_id,
            _require(body, "birthdate"), _require(body, "salt"),
            _require(body, "threshold"),
        )

    def _do_age_band(self, ivr, sub, rp_id, body) -> str:
        return receipt.prove_age_band(
            _SIGNING_KEY, ivr, sub, rp_id,
            _require(body, "birthdate"), _require(body, "salt"),
            body.get("bands"),
        )

    def _do_field(self, ivr, sub, rp_id, body) -> str:
        return receipt.prove_field(
            _SIGNING_KEY, ivr, sub, rp_id,
            _require(body, "field"), _require(body, "value"), _require(body, "salt"),
        )

    def _do_document_valid(self, ivr, sub, rp_id, body) -> str:
        return receipt.prove_document_valid(_SIGNING_KEY, ivr, sub, rp_id)

    def _set_trust_anchors(self, body: dict) -> None:
        # Rotate the anchor set at runtime. Same validation as /configure: only a
        # genuine ICAO CSCA Master List (CMS-verified, chaining to the pinned
        # ICAO/UN CSCA root) is accepted, never a raw PEM bundle.
        # PROD: also gate to the app owner / trust-anchor admin (owner bearer).
        import base64
        ml_b64 = _require(body, "master_list_cms")
        pem = master_list.verify_and_extract(base64.b64decode(ml_b64))
        digest = trust_anchors.set_anchors(pem)
        self._json(200, {"digest": digest, "count": trust_anchors.count(),
                         "oid": config.TRUST_ANCHORS_OID})

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A002
        pass


if __name__ == "__main__":
    # Lift the startup freeze if trust anchors were already loaded on a previous
    # run and persisted on the per-app sealed volume. Without this a restart or
    # redeploy leaves an already-configured verifier frozen (503 on every POST
    # but /configure) until /configure is sent again — which, with a large body
    # like a selfie, surfaces on the client as a broken pipe rather than a clean
    # 503, because the handler returns without draining the request body.
    if trust_anchors.load():
        _CONFIGURED = True
        print(f"identity-verifier: resuming with persisted trust anchors "
              f"({trust_anchors.count()} CSCA, digest={trust_anchors.digest_hex()[:12]})")

    # The platform allocates a unique host port per app and passes it as $PORT
    # (host networking -> listen port == host port; see management-service
    # migration 034 / bug #43). Fall back to 8080 for local runs.
    port = int(os.environ.get("PORT", "8080"))
    server = http.server.HTTPServer(("0.0.0.0", port), Handler)
    print(f"identity-verifier listening on :{port} (kid={_SIGNING_KEY.kid}, configured={_CONFIGURED})")
    server.serve_forever()
