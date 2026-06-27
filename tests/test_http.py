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


def _configure_with_csca(base, monkeypatch, cscas):
    """Configure the running verifier with a synthetic master list containing
    `cscas`, pinning the verifier to that list's (synthetic) ICAO root for the
    test. Returns the configure HTTP status."""
    root_key, root = fixtures.self_signed_ca("Test ICAO Root")
    monkeypatch.setattr(master_list, "ICAO_ML_ROOT_SHA256",
                        hashlib.sha256(fixtures.cert_der(root)).hexdigest())
    ml = fixtures.build_master_list(root_key, root, root.subject, cscas)
    return _req(base, "POST", "/configure", {"master_list_cms": _b64(ml)})[0]


@pytest.fixture()
def server(monkeypatch, tmp_path):
    # Real Passive Auth + MRZ; biometric uses the dev stub (no ONNX models here).
    monkeypatch.setattr(config, "ALLOW_DEV_STUB", True)
    monkeypatch.setattr(biometrics, "_models_available", lambda: False)
    monkeypatch.setenv("IDENTITY_VERIFIER_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(main, "_CONFIGURED", False)
    httpd = HTTPServer(("127.0.0.1", 0), main.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _req(base, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
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
    rp, nonce, ts = "shop.example", "n1", int(time.time())
    holder_sig = holder.sign(receipt._holder_message(ivr["jti"], rp, nonce, ts))
    status, out = _req(base, "POST", "/prove/age-over", {
        "ivr": ivr_jws, "sub": "pairwise", "rp_id": rp, "nonce": nonce, "ts": ts,
        "holder_pub": crypto.b64u_encode(holder_pub),
        "holder_sig": crypto.b64u_encode(holder_sig),
        "birthdate": "2000-01-01", "salt": salts["birthdate"], "threshold": 18,
    })
    assert status == 200, out
    payload = crypto.jws_verify(out["token"], main._SIGNING_KEY.public())
    assert payload["claim"] == "age_over_18" and payload["value"] is True
    assert payload["aud"] == rp and payload["assurance"] == "gov"


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
