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

import http.server
import json
import os
import threading
from urllib.parse import urlparse

from verifier import config, crypto, manager, receipt, trust_anchors
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
            if path == "/verify-identity":
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
            pem = body.get("trust_anchors_pem")
            if pem:
                trust_anchors.set_anchors(pem.encode("utf-8"))
            if manager.available():
                manager.config_complete()
        except Exception as exc:  # noqa: BLE001 — surface manager/validation error
            self._json(500, {"error": str(exc)})
            return
        global _CONFIGURED
        with _CONFIG_LOCK:
            _CONFIGURED = True
        self._json(200, {"status": "configured",
                         "trust_anchors_digest": trust_anchors.digest_hex()})

    def _verify_identity(self, body: dict) -> None:
        holder_pub = _b64u_field(body, "holder_pub")
        doc, dgs = authenticate_and_extract(body)
        bio = match_biometric(body, dgs)
        ivr, salts = receipt.build_ivr(
            _SIGNING_KEY, _MEASUREMENT_PLACEHOLDER, doc, bio, holder_pub
        )
        # `salts` go to the client so it can later open commitments; the enclave
        # keeps nothing. The client auto-fills its profile from doc.fields as
        # gov-assurance attributes (kyc-enclave-design §2.1).
        self._json(200, {"ivr": ivr, "salts": salts, "fields": doc.fields})

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
        # PROD: gate to the app owner / trust-anchor admin (owner bearer), and
        # validate the master list before swapping (kyc-enclave-design §7.4).
        pem = _require(body, "pem")
        digest = trust_anchors.set_anchors(pem.encode("utf-8"))
        self._json(200, {"digest": digest, "count": trust_anchors.count(),
                         "oid": config.TRUST_ANCHORS_OID})

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A002
        pass


if __name__ == "__main__":
    # The platform allocates a unique host port per app and passes it as $PORT
    # (host networking -> listen port == host port; see management-service
    # migration 034 / bug #43). Fall back to 8080 for local runs.
    port = int(os.environ.get("PORT", "8080"))
    server = http.server.HTTPServer(("0.0.0.0", port), Handler)
    print(f"identity-verifier listening on :{port} (kid={_SIGNING_KEY.kid})")
    server.serve_forever()
