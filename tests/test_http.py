# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""End-to-end HTTP test: configure → verify-identity (real PA + MRZ) → prove."""

import base64
import hashlib
import json
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import HTTPServer

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

import fixtures
import main
from verifier import biometrics, config, crypto, master_list, receipt


def _configure_with_csca(base, monkeypatch, cscas, wallet_provider_jwks=None):
    """Configure the running verifier with a synthetic master list containing
    `cscas`, pinning the verifier to that list's (synthetic) ICAO root for the
    test. Optionally also provision a wallet-provider JWKS (for WIA). Returns the
    configure HTTP status."""
    root_key, root = fixtures.self_signed_ca("Test ICAO Root")
    monkeypatch.setattr(master_list, "ICAO_ML_ROOT_SHA256",
                        hashlib.sha256(fixtures.cert_der(root)).hexdigest())
    ml = fixtures.build_master_list(root_key, root, root.subject, cscas)
    body = {"master_list_cms": _b64(ml)}
    if wallet_provider_jwks is not None:
        body["wallet_provider_jwks"] = wallet_provider_jwks
    return _req(base, "POST", "/configure", body)[0]


def _wia_provider():
    """A synthetic wallet-provider signing key + the JWKS to provision."""
    signer = crypto.SigningKey.generate()
    jwks = {"keys": [signer.public().jwk(signer.kid)]}
    return signer, jwks


def _build_wia(signer, holder_pub_raw, *, exp=None):
    """Mint a WIA JWT (as the IdP would): ES256, kid = provider kid, cnf.jwk bound
    to the holder key, exp in the future by default."""
    payload = {
        "cnf": {"jwk": crypto.PublicKey.from_raw(holder_pub_raw).jwk_public()},
        "iat": int(time.time()),
        "exp": exp if exp is not None else int(time.time()) + 3600,
        "wallet_version": "1.3.17",
        "level": "strongbox",
    }
    return crypto.jws_sign(payload, signer, config.WIA_TYP)


@pytest.fixture()
def server(monkeypatch, tmp_path):
    # Real Passive Auth + MRZ; biometric uses the test-only stub (no ONNX models
    # here). The stub is a module flag, never an env/config option (so it can
    # never be enabled on a deployed enclave).
    monkeypatch.setattr(biometrics, "_ALLOW_TEST_STUB", True)
    monkeypatch.setattr(biometrics, "_models_available", lambda: False)
    monkeypatch.setenv("IDENTITY_VERIFIER_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(main, "_CONFIGURED", False)
    # Enforcement flags default ON since 0.5.1 (baked into the measured
    # image). The generic flow tests exercise the dev-relaxed mode; the
    # strict-mode tests re-enable each flag explicitly.
    monkeypatch.setattr(config, "REQUIRE_WIA", False)
    monkeypatch.setattr(config, "REQUIRE_VOUCHER", False)
    httpd = HTTPServer(("127.0.0.1", 0), main.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _req(base, method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(base + path, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def test_end_to_end(server, monkeypatch):
    base = server

    assert _req(base, "GET", "/health")[0] == 200

    # The IVR must carry the verifier's measurement (the launcher-injected
    # image digest in production; monkeypatched here).
    monkeypatch.setattr(config, "MEASUREMENT", "test-image-digest")

    # Build a real SOD + DG1 chain and configure its CSCA via a (synthetic,
    # pinned) ICAO master list.
    dg1 = fixtures.build_dg1()
    sod, csca, _ = fixtures.build_chain({1: dg1})
    assert _configure_with_csca(base, monkeypatch, [csca]) == 200

    holder = crypto.SigningKey.generate()
    holder_pub = holder.public().raw()

    status, vi = _req(base, "POST", "/verify-identity", {
        "holder_pub": crypto.b64u_encode(holder_pub),
        "sod": _b64(sod),
        "data_groups": {"1": _b64(dg1)},
    })
    assert status == 200, vi
    assert vi["fields"]["family_name"] == "DOE"
    assert vi["fields"]["birthdate"] == "2000-01-01"
    ivr_jws, salts = vi["ivr"], vi["salts"]

    # prove age-over with a holder-signed request.
    ivr = receipt.verify_ivr(ivr_jws, main._SIGNING_KEY.public())
    assert ivr["measurement"] == "test-image-digest"
    rp, nonce, ts = "shop.example", "n1", int(time.time())
    holder_sig = holder.sign(receipt._holder_message(ivr["jti"], rp, nonce, ts))
    status, out = _req(base, "POST", "/prove/age-over", {
        "ivr": ivr_jws, "sub": "pairwise", "rp_id": rp, "nonce": nonce, "ts": ts,
        "holder_pub": crypto.b64u_encode(holder_pub),
        "holder_sig": crypto.b64u_encode(holder_sig),
        "birthdate": "2000-01-01", "salt": salts["birthdate"], "threshold": 18,
    })
    assert status == 200, out
    # The token is an SD-JWT VC: `<JWS>~`, iss = the origin the wallet called
    # (Host header), holder key in cnf, measurement in the evidence.
    token = out["token"]
    assert token.endswith("~")
    payload = receipt.verify_disclosure(token, main._SIGNING_KEY.public())
    assert payload["claim"] == "age_over_18" and payload["value"] is True
    assert payload["aud"] == rp and payload["assurance"] == "gov"
    assert payload["vct"] == config.DISCLOSURE_VCT
    assert payload["iss"] == f"https://{base.removeprefix('http://')}"
    assert payload["cnf"]["jwk"] == crypto.PublicKey.from_raw(holder_pub).jwk_public()
    assert payload["evidence"]["measurement"] == "test-image-digest"

    # SD-JWT VC issuer metadata: how a relying party resolves the signing keys.
    status, meta = _req(base, "GET", "/.well-known/jwt-vc-issuer")
    assert status == 200
    assert meta["issuer"].startswith("https://")
    assert meta["jwks"]["keys"][0]["kid"] == main._SIGNING_KEY.kid

    # Status tool endpoint (POST-able for the platform RPC proxy).
    status, ta = _req(base, "POST", "/trust-anchors/status", {})
    assert status == 200
    assert ta["count"] == 1 and ta["oid"] == config.TRUST_ANCHORS_OID


def _proven_setup(base, monkeypatch):
    """Configure + verify-identity, returning the pieces a /prove call needs."""
    dg1 = fixtures.build_dg1()
    sod, csca, _ = fixtures.build_chain({1: dg1})
    assert _configure_with_csca(base, monkeypatch, [csca]) == 200
    holder = crypto.SigningKey.generate()
    holder_pub = holder.public().raw()
    status, vi = _req(base, "POST", "/verify-identity", {
        "holder_pub": crypto.b64u_encode(holder_pub),
        "sod": _b64(sod), "data_groups": {"1": _b64(dg1)},
    })
    assert status == 200, vi
    return holder, holder_pub, vi["ivr"], vi["salts"]


def _age_over_body(holder, holder_pub, ivr_jws, salts, rp="shop.example", threshold=18):
    ivr = receipt.verify_ivr(ivr_jws, main._SIGNING_KEY.public())
    nonce, ts = "n1", int(time.time())
    holder_sig = holder.sign(receipt._holder_message(ivr["jti"], rp, nonce, ts))
    return {
        "ivr": ivr_jws, "sub": "pairwise", "rp_id": rp, "nonce": nonce, "ts": ts,
        "holder_pub": crypto.b64u_encode(holder_pub),
        "holder_sig": crypto.b64u_encode(holder_sig),
        "birthdate": "2000-01-01", "salt": salts["birthdate"], "threshold": threshold,
    }


def test_voucher_gate_enforces_and_echoes_jti(server, monkeypatch):
    """A verified voucher (its authorised keys injected by the runtime as the
    trusted header) that covers the requested attribute is honoured and its jti
    is echoed for settlement audit; one that does not cover it is refused."""
    base = server
    holder, holder_pub, ivr_jws, salts = _proven_setup(base, monkeypatch)
    body = _age_over_body(holder, holder_pub, ivr_jws, salts)

    # Voucher authorises age_over_18 → 200 + jti echoed.
    st, out = _req(base, "POST", "/prove/age-over", body, headers={
        "X-Privasys-Voucher-Claims": "privasys:age_over_18,privasys:nationality",
        "X-Privasys-Voucher-Jti": "vch-abc",
    })
    assert st == 200, out
    assert out["voucher_jti"] == "vch-abc"

    # Voucher authorises only nationality → age_over_18 refused.
    st, out = _req(base, "POST", "/prove/age-over", body, headers={
        "X-Privasys-Voucher-Claims": "privasys:nationality",
        "X-Privasys-Voucher-Jti": "vch-def",
    })
    assert st == 400 and "does not authorise" in out["error"]


def test_voucher_required_in_strict_mode(server, monkeypatch):
    """With REQUIRE_VOUCHER on, a non-self relying party with no voucher is
    refused; a self audience (wallet-internal proof) is still allowed."""
    base = server
    monkeypatch.setattr(config, "REQUIRE_VOUCHER", True)
    monkeypatch.setattr(config, "SELF_AUDIENCES", {"self"})
    holder, holder_pub, ivr_jws, salts = _proven_setup(base, monkeypatch)

    st, out = _req(base, "POST", "/prove/age-over",
                   _age_over_body(holder, holder_pub, ivr_jws, salts, rp="shop.example"))
    assert st == 400 and "voucher is required" in out["error"]

    st, out = _req(base, "POST", "/prove/age-over",
                   _age_over_body(holder, holder_pub, ivr_jws, salts, rp="self"))
    assert st == 200, out
    assert "voucher_jti" not in out


def test_verify_identity_rejects_untrusted_document(server, monkeypatch):
    base = server
    # Configure trust anchor A, but present a SOD signed under a different chain.
    _sod_a, csca_a, _ = fixtures.build_chain({1: fixtures.build_dg1()})
    assert _configure_with_csca(base, monkeypatch, [csca_a]) == 200

    dg1 = fixtures.build_dg1()
    sod_b, _csca_b, _ = fixtures.build_chain({1: dg1})  # different CSCA
    holder_pub = crypto.SigningKey.generate().public().raw()
    status, _ = _req(base, "POST", "/verify-identity", {
        "holder_pub": crypto.b64u_encode(holder_pub),
        "sod": _b64(sod_b), "data_groups": {"1": _b64(dg1)},
    })
    assert status == 400  # passive authentication fails (untrusted CSCA)


def test_verify_identity_rejects_face_mismatch(server, monkeypatch):
    # A genuine document presented with someone else's face: the biometric is
    # computed and does NOT match → the enclave must refuse to issue an IVR,
    # not return 200 with face_match=false recorded (which the wallet would
    # treat as a successful verification).
    base = server
    dg1 = fixtures.build_dg1()
    sod, csca, _ = fixtures.build_chain({1: dg1})
    assert _configure_with_csca(base, monkeypatch, [csca]) == 200
    monkeypatch.setattr(main, "match_biometric",
                        lambda body, dgs: biometrics.BioResult(face_match=False, liveness_score=1.0))
    holder_pub = crypto.SigningKey.generate().public().raw()
    status, out = _req(base, "POST", "/verify-identity", {
        "holder_pub": crypto.b64u_encode(holder_pub),
        "sod": _b64(sod), "data_groups": {"1": _b64(dg1)},
    })
    assert status == 400
    assert "face" in str(out).lower()


def test_verify_identity_rejects_expired_document(server, monkeypatch):
    base = server
    l2 = list(fixtures.SAMPLE_MRZ[44:88])
    l2[21:27] = "200101"  # expiry 2020-01-01 (past)
    dg1 = fixtures.build_dg1(fixtures.SAMPLE_MRZ[:44] + "".join(l2))
    sod, csca, _ = fixtures.build_chain({1: dg1})
    assert _configure_with_csca(base, monkeypatch, [csca]) == 200
    holder_pub = crypto.SigningKey.generate().public().raw()
    status, out = _req(base, "POST", "/verify-identity", {
        "holder_pub": crypto.b64u_encode(holder_pub),
        "sod": _b64(sod), "data_groups": {"1": _b64(dg1)},
    })
    assert status == 400
    assert "expired" in str(out).lower()


def _aa_dg15():
    aa_key = ec.generate_private_key(ec.SECP256R1())
    return aa_key, fixtures.build_dg15(aa_key.public_key())


def test_verify_identity_active_auth_accepts_genuine_chip(server, monkeypatch):
    base = server
    dg1 = fixtures.build_dg1()
    aa_key, dg15 = _aa_dg15()
    sod, csca, _ = fixtures.build_chain({1: dg1, 15: dg15})
    assert _configure_with_csca(base, monkeypatch, [csca]) == 200
    st, ch = _req(base, "POST", "/aa-challenge")
    assert st == 200
    sig = fixtures.aa_sign_ecdsa(aa_key, crypto.b64u_decode(ch["challenge"]))
    holder = crypto.SigningKey.generate()
    st, vi = _req(base, "POST", "/verify-identity", {
        "holder_pub": crypto.b64u_encode(holder.public().raw()),
        "sod": _b64(sod), "data_groups": {"1": _b64(dg1), "15": _b64(dg15)},
        "aa": {"challenge": ch["challenge"], "token": ch["token"],
               "signature": crypto.b64u_encode(sig)},
    })
    assert st == 200, vi
    payload = receipt.verify_ivr(vi["ivr"], main._SIGNING_KEY.public())
    assert payload["doc"]["chip_auth"] is True


def test_verify_identity_accepts_chip_read_challenge_without_token(server, monkeypatch):
    # iOS path: the NFC reader owns the session and issues its own random per-read
    # challenge, so the wallet relays {challenge, signature} with no enclave token.
    base = server
    dg1 = fixtures.build_dg1()
    aa_key, dg15 = _aa_dg15()
    sod, csca, _ = fixtures.build_chain({1: dg1, 15: dg15})
    assert _configure_with_csca(base, monkeypatch, [csca]) == 200
    challenge = os.urandom(8)
    sig = fixtures.aa_sign_ecdsa(aa_key, challenge)
    holder = crypto.SigningKey.generate()
    st, vi = _req(base, "POST", "/verify-identity", {
        "holder_pub": crypto.b64u_encode(holder.public().raw()),
        "sod": _b64(sod), "data_groups": {"1": _b64(dg1), "15": _b64(dg15)},
        "aa": {"challenge": crypto.b64u_encode(challenge),
               "signature": crypto.b64u_encode(sig)},  # no token
    })
    assert st == 200, vi
    payload = receipt.verify_ivr(vi["ivr"], main._SIGNING_KEY.public())
    assert payload["doc"]["chip_auth"] is True


def test_verify_identity_rejects_cloned_chip(server, monkeypatch):
    base = server
    dg1 = fixtures.build_dg1()
    _aa_key, dg15 = _aa_dg15()
    sod, csca, _ = fixtures.build_chain({1: dg1, 15: dg15})
    assert _configure_with_csca(base, monkeypatch, [csca]) == 200
    st, ch = _req(base, "POST", "/aa-challenge")
    bad = fixtures.aa_sign_ecdsa(ec.generate_private_key(ec.SECP256R1()),
                                 crypto.b64u_decode(ch["challenge"]))
    holder = crypto.SigningKey.generate()
    st, out = _req(base, "POST", "/verify-identity", {
        "holder_pub": crypto.b64u_encode(holder.public().raw()),
        "sod": _b64(sod), "data_groups": {"1": _b64(dg1), "15": _b64(dg15)},
        "aa": {"challenge": ch["challenge"], "token": ch["token"],
               "signature": crypto.b64u_encode(bad)},
    })
    assert st == 400
    assert "active authentication" in str(out).lower()


def test_verify_identity_requires_aa_when_dg15_present(server, monkeypatch):
    base = server
    dg1 = fixtures.build_dg1()
    _aa_key, dg15 = _aa_dg15()
    sod, csca, _ = fixtures.build_chain({1: dg1, 15: dg15})
    assert _configure_with_csca(base, monkeypatch, [csca]) == 200
    holder = crypto.SigningKey.generate()
    st, out = _req(base, "POST", "/verify-identity", {  # no "aa" block
        "holder_pub": crypto.b64u_encode(holder.public().raw()),
        "sod": _b64(sod), "data_groups": {"1": _b64(dg1), "15": _b64(dg15)},
    })
    assert st == 400
    assert "active authentication" in str(out).lower()


# ── Wallet Instance Attestation (WIA) ────────────────────────────────────

def _configure_for_wia(base, monkeypatch):
    """Configure with a CSCA + wallet-provider JWKS; return (sod, dg1, signer)."""
    dg1 = fixtures.build_dg1()
    sod, csca, _ = fixtures.build_chain({1: dg1})
    signer, jwks = _wia_provider()
    assert _configure_with_csca(base, monkeypatch, [csca], wallet_provider_jwks=jwks) == 200
    return sod, dg1, signer


def test_wia_missing_allowed_when_relaxed(server, monkeypatch):
    # Rollout default: REQUIRE_WIA is false, so a wallet with no WIA still verifies
    # (a partial-coverage fleet must not break).
    base = server
    dg1 = fixtures.build_dg1()
    sod, csca, _ = fixtures.build_chain({1: dg1})
    assert _configure_with_csca(base, monkeypatch, [csca]) == 200
    holder = crypto.SigningKey.generate()
    st, vi = _req(base, "POST", "/verify-identity", {
        "holder_pub": crypto.b64u_encode(holder.public().raw()),
        "sod": _b64(sod), "data_groups": {"1": _b64(dg1)},
    })
    assert st == 200, vi


def test_wia_required_rejects_missing(server, monkeypatch):
    base = server
    monkeypatch.setattr(config, "REQUIRE_WIA", True)
    sod, dg1, _signer = _configure_for_wia(base, monkeypatch)
    holder = crypto.SigningKey.generate()
    st, out = _req(base, "POST", "/verify-identity", {
        "holder_pub": crypto.b64u_encode(holder.public().raw()),
        "sod": _b64(sod), "data_groups": {"1": _b64(dg1)},
    })
    assert st == 400
    assert "wallet instance attestation" in str(out).lower()


def test_wia_valid_accepted_when_required(server, monkeypatch):
    base = server
    monkeypatch.setattr(config, "MEASUREMENT", "test-image-digest")
    monkeypatch.setattr(config, "REQUIRE_WIA", True)
    sod, dg1, signer = _configure_for_wia(base, monkeypatch)
    holder = crypto.SigningKey.generate()
    holder_pub = holder.public().raw()
    wia_jwt = _build_wia(signer, holder_pub)
    st, vi = _req(base, "POST", "/verify-identity", {
        "holder_pub": crypto.b64u_encode(holder_pub),
        "sod": _b64(sod), "data_groups": {"1": _b64(dg1)}, "wia": wia_jwt,
    })
    assert st == 200, vi

    # The same WIA gates prove_* too.
    ivr = receipt.verify_ivr(vi["ivr"], main._SIGNING_KEY.public())
    rp, nonce, ts = "shop.example", "n1", int(time.time())
    holder_sig = holder.sign(receipt._holder_message(ivr["jti"], rp, nonce, ts))
    st, out = _req(base, "POST", "/prove/age-over", {
        "ivr": vi["ivr"], "sub": "pairwise", "rp_id": rp, "nonce": nonce, "ts": ts,
        "holder_pub": crypto.b64u_encode(holder_pub),
        "holder_sig": crypto.b64u_encode(holder_sig),
        "birthdate": "2000-01-01", "salt": vi["salts"]["birthdate"], "threshold": 18,
        "wia": wia_jwt,
    })
    assert st == 200, out


def test_wia_rejects_cnf_mismatch(server, monkeypatch):
    # A WIA that binds a DIFFERENT holder key must not authorise this holder.
    base = server
    monkeypatch.setattr(config, "REQUIRE_WIA", True)
    sod, dg1, signer = _configure_for_wia(base, monkeypatch)
    holder = crypto.SigningKey.generate()
    other_pub = crypto.SigningKey.generate().public().raw()
    wia_jwt = _build_wia(signer, other_pub)  # bound to a different key
    st, out = _req(base, "POST", "/verify-identity", {
        "holder_pub": crypto.b64u_encode(holder.public().raw()),
        "sod": _b64(sod), "data_groups": {"1": _b64(dg1)}, "wia": wia_jwt,
    })
    assert st == 400
    assert "holder" in str(out).lower() or "cnf" in str(out).lower()


def test_wia_rejects_expired(server, monkeypatch):
    base = server
    monkeypatch.setattr(config, "REQUIRE_WIA", True)
    sod, dg1, signer = _configure_for_wia(base, monkeypatch)
    holder = crypto.SigningKey.generate()
    holder_pub = holder.public().raw()
    wia_jwt = _build_wia(signer, holder_pub, exp=int(time.time()) - 10)  # expired
    st, out = _req(base, "POST", "/verify-identity", {
        "holder_pub": crypto.b64u_encode(holder_pub),
        "sod": _b64(sod), "data_groups": {"1": _b64(dg1)}, "wia": wia_jwt,
    })
    assert st == 400
    assert "expired" in str(out).lower()


def test_wia_rejects_untrusted_signer(server, monkeypatch):
    # A WIA signed by a key NOT in the provisioned wallet-provider JWKS is rejected.
    base = server
    monkeypatch.setattr(config, "REQUIRE_WIA", True)
    sod, dg1, _signer = _configure_for_wia(base, monkeypatch)
    rogue = crypto.SigningKey.generate()  # not in the JWKS
    holder = crypto.SigningKey.generate()
    holder_pub = holder.public().raw()
    wia_jwt = _build_wia(rogue, holder_pub)
    st, out = _req(base, "POST", "/verify-identity", {
        "holder_pub": crypto.b64u_encode(holder_pub),
        "sod": _b64(sod), "data_groups": {"1": _b64(dg1)}, "wia": wia_jwt,
    })
    assert st == 400
    assert "wallet instance attestation" in str(out).lower()


def test_wia_jwks_status_and_digest(server, monkeypatch):
    base = server
    _sod, _dg1, _signer = _configure_for_wia(base, monkeypatch)
    st, s = _req(base, "POST", "/wallet-provider-jwks/status", {})
    assert st == 200
    assert s["count"] == 1
    assert s["oid"] == config.WALLET_PROVIDER_JWKS_OID
    assert len(s["digest"]) == 64  # sha256 hex
