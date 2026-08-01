# Copyright (c) Privasys. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

"""Restart republication of the attested runtime OIDs.

The anchors / WIA-JWKS digests live only in the manager's leaf-cert state,
which every container (re)start discards and nothing platform-side replays —
so the boot-restore path must republish them (prod regression 2026-08-01: a
restarted verifier served anchors its certificate no longer attested).
"""

import hashlib

import fixtures
from verifier import config, manager, trust_anchors, wia


def _capture_manager(monkeypatch):
    pushed: list[tuple[str, bytes]] = []
    monkeypatch.setattr(manager, "available", lambda: True)
    monkeypatch.setattr(
        manager, "set_attestation_extension", lambda oid, value: pushed.append((oid, value))
    )
    return pushed


def test_republish_anchor_oid_after_restart(monkeypatch, tmp_path):
    monkeypatch.setenv("IDENTITY_VERIFIER_DATA_DIR", str(tmp_path))
    _key, cert = fixtures.self_signed_ca("Test CSCA")
    pem = fixtures.cert_pem(cert)
    # Persist without pushing (the restart scenario: state on disk, fresh leaf).
    trust_anchors.set_anchors(pem, push_oid=False)

    pushed = _capture_manager(monkeypatch)
    assert trust_anchors.republish_oid() is True
    assert pushed == [(config.TRUST_ANCHORS_OID, hashlib.sha256(pem).digest())]


def test_republish_noop_without_persisted_anchors(monkeypatch, tmp_path):
    monkeypatch.setenv("IDENTITY_VERIFIER_DATA_DIR", str(tmp_path))
    pushed = _capture_manager(monkeypatch)
    assert trust_anchors.republish_oid() is False
    assert wia.republish_oid() is False
    assert pushed == []


def test_republish_wia_jwks_after_restart(monkeypatch, tmp_path):
    monkeypatch.setenv("IDENTITY_VERIFIER_DATA_DIR", str(tmp_path))
    jwks = {
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "kid": "test-1",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            }
        ]
    }
    wia.set_jwks(jwks, push_oid=False)

    pushed = _capture_manager(monkeypatch)
    assert wia.republish_oid() is True
    assert len(pushed) == 1
    oid, digest = pushed[0]
    assert oid == config.WALLET_PROVIDER_JWKS_OID
    assert digest == hashlib.sha256(wia.load()).digest()
