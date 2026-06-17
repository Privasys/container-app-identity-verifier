# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""End-to-end HTTP test: configure → verify-identity → prove → verify token."""

import json
import threading
import time
import urllib.request
from http.server import HTTPServer

import pytest

import main
from verifier import config, crypto, receipt


@pytest.fixture()
def server(monkeypatch):
    # Allow the dev stub so verify_identity accepts pre-parsed fields.
    monkeypatch.setattr(config, "ALLOW_DEV_STUB", True)
    monkeypatch.setattr(main, "_CONFIGURED", False)
    httpd = HTTPServer(("127.0.0.1", 0), main.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield base
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


def test_end_to_end(server):
    base = server

    assert _req(base, "GET", "/health")[0] == 200
    assert _req(base, "GET", "/version")[1]["version"] == config.APP_VERSION

    # Frozen until configured.
    status, _ = _req(base, "POST", "/verify-identity", {})
    assert status == 503

    assert _req(base, "POST", "/configure", {})[0] == 200

    # jwks available.
    keys = _req(base, "GET", "/.well-known/jwks.json")[1]["keys"]
    assert keys and keys[0]["crv"] == "P-256"

    # verify-identity (dev stub: pre-parsed fields + holder pub).
    holder = crypto.SigningKey.generate()
    holder_pub = holder.public().raw()
    status, vi = _req(base, "POST", "/verify-identity", {
        "holder_pub": crypto.b64u_encode(holder_pub),
        "fields": {"given_name": "Alice", "family_name": "Doe",
                   "birthdate": "2000-01-01", "nationality": "GBR"},
    })
    assert status == 200
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
    assert status == 200
    payload = crypto.jws_verify(out["token"], main._SIGNING_KEY.public())
    assert payload["claim"] == "age_over_18" and payload["value"] is True
    assert payload["aud"] == rp and payload["assurance"] == "gov"

    # A tampered birthdate (not matching the commitment) is rejected.
    status, _ = _req(base, "POST", "/prove/age-over", {
        "ivr": ivr_jws, "sub": "pairwise", "rp_id": rp, "nonce": nonce, "ts": ts,
        "holder_pub": crypto.b64u_encode(holder_pub),
        "holder_sig": crypto.b64u_encode(holder_sig),
        "birthdate": "1990-01-01", "salt": salts["birthdate"], "threshold": 18,
    })
    assert status == 400
