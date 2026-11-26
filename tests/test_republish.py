# Copyright (c) Privasys. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

"""Restart republication of the attested runtime OIDs.

The anchors / WIA-JWKS digests live only in the manager's leaf-cert state,
which every container (re)start discards and nothing platform-side replays —
so the boot-restore path must republish them (prod regression 2026-08-01: a
restarted verifier served anchors its certificate no longer attested).
"""

import hashlib

import pytest

import fixtures
from test_http import server  # noqa: F401 — the running-verifier fixture
from verifier import config, crypto, manager, trust_anchors, wia


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


def test_signing_key_oid_attests_the_issuer_key(monkeypatch):
    """The attested value is SHA-256 of the SPKI of the key in the issuer
    metadata, so a relying party can hash what it fetched and compare."""
    import base64

    import main
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    pushed = _capture_manager(monkeypatch)
    assert main.publish_signing_key_oid() is True
    assert len(pushed) == 1
    oid, digest = pushed[0]
    assert oid == config.SIGNING_KEY_OID

    # Rebuild the key from its published JWK, as a relying party would.
    jwk = main._SIGNING_KEY.public().jwk(main._SIGNING_KEY.kid)
    pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
    x = int.from_bytes(base64.urlsafe_b64decode(pad(jwk["x"])), "big")
    y = int.from_bytes(base64.urlsafe_b64decode(pad(jwk["y"])), "big")
    spki = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert digest == hashlib.sha256(spki).digest()
    # The token kid is a prefix of the same digest.
    assert base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode() == jwk["kid"]


_PLATFORM_ENV = ("PRIVASYS_IMAGE_DIGEST", "PRIVASYS_MANAGER_URL",
                 "PRIVASYS_CONTAINER_NAME", "PRIVASYS_CONTAINER_TOKEN")


class _Clock:
    """The gate's retry clock, moved by hand."""

    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def _gate(monkeypatch, *, platform_env=None):
    """Reset the signing gate: unattested, no retry yet, a hand-moved clock,
    and exactly the platform markers given (none = clearly off-platform)."""
    import main

    for name in _PLATFORM_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(manager, "_NAME", "")
    monkeypatch.setattr(manager, "_TOKEN", "")
    for name, value in (platform_env or {}).items():
        monkeypatch.setenv(name, value)
    clock = _Clock()
    monkeypatch.setattr(main, "_KEY_ATTESTED", False)
    monkeypatch.setattr(main, "_LAST_RETRY", float("-inf"))
    monkeypatch.setattr(main, "_clock", clock)
    return clock


def test_gate_open_only_clearly_off_platform(monkeypatch):
    """No platform marker at all: no attestation exists, the key may sign."""
    import main

    _gate(monkeypatch)
    assert main.publish_signing_key_oid() is False
    main._SIGNING_KEY.sign(b"dev")


@pytest.mark.parametrize("marker", _PLATFORM_ENV)
def test_on_platform_without_a_manager_never_signs(monkeypatch, marker):
    """Any one platform marker with no usable manager: refuse, never open."""
    import main

    _gate(monkeypatch, platform_env={marker: "x"})
    monkeypatch.setattr(manager, "available", lambda: False)
    with pytest.raises(RuntimeError):
        main.publish_signing_key_oid()
    with pytest.raises(crypto.KeyNotAttested):
        main._SIGNING_KEY.sign(b"token")


def test_unattested_key_never_signs(monkeypatch):
    """Fail closed: on the platform the key signs nothing until its digest is
    in the attested leaf; the gate retries the publish at most once per
    interval, shared across requests, then signs once it succeeds."""
    import main

    clock = _gate(monkeypatch, platform_env={"PRIVASYS_IMAGE_DIGEST": "sha256:test"})
    monkeypatch.setattr(manager, "available", lambda: True)
    attempts = []

    def refuse(oid, value):
        attempts.append(oid)
        raise RuntimeError("manager unreachable")

    monkeypatch.setattr(manager, "set_attestation_extension", refuse)
    with pytest.raises(crypto.KeyNotAttested):
        main._SIGNING_KEY.sign(b"token")
    assert len(attempts) == 1
    # A burst inside the interval is refused at once, without calling the manager.
    for _ in range(5):
        with pytest.raises(crypto.KeyNotAttested):
            crypto.jws_sign({"n": 1}, main._SIGNING_KEY, "test")
    assert len(attempts) == 1
    # After the interval: one more attempt.
    clock.t += main._RETRY_INTERVAL_S + 0.1
    with pytest.raises(crypto.KeyNotAttested):
        main._SIGNING_KEY.sign(b"token")
    assert len(attempts) == 2

    # The manager is back: the next attempt (after the interval) publishes, then signs.
    pushed = _capture_manager(monkeypatch)
    with pytest.raises(crypto.KeyNotAttested):
        main._SIGNING_KEY.sign(b"too soon")
    assert pushed == []
    clock.t += main._RETRY_INTERVAL_S + 0.1
    assert len(main._SIGNING_KEY.sign(b"token")) == 64
    assert pushed == [(config.SIGNING_KEY_OID, main._SIGNING_KEY.spki_sha256())]
    # Once attested, no further publish per signature.
    main._SIGNING_KEY.sign(b"again")
    assert len(pushed) == 1


def _refusing_manager(monkeypatch):
    """On the platform, with a manager that accepts everything except the
    signing-key OID."""
    calls: list[str] = []
    _gate(monkeypatch, platform_env={"PRIVASYS_IMAGE_DIGEST": "sha256:test"})
    monkeypatch.setattr(manager, "available", lambda: True)

    def ext(oid, value):
        if oid == config.SIGNING_KEY_OID:
            raise RuntimeError("refused")
        calls.append(oid)

    monkeypatch.setattr(manager, "set_attestation_extension", ext)
    monkeypatch.setattr(manager, "config_complete", lambda: calls.append("complete"))
    return calls


def test_configure_fails_closed_when_the_key_cannot_be_attested(server, monkeypatch):
    """/configure publishes the key before config_complete, so a refusal
    leaves the app frozen instead of lifting the freeze with an unattested key."""
    import main
    from test_http import _configure_with_csca

    calls = _refusing_manager(monkeypatch)
    _sod, csca, _ = fixtures.build_chain({1: fixtures.build_dg1()})
    assert _configure_with_csca(server, monkeypatch, [csca]) == 500
    assert "complete" not in calls
    assert main._CONFIGURED is False


def test_signing_endpoint_refuses_with_an_unattested_key(server, monkeypatch):
    """A route that signs answers 503 and signs nothing."""
    import main
    from test_http import _req

    _refusing_manager(monkeypatch)
    monkeypatch.setattr(main, "_CONFIGURED", True)
    status, body = _req(server, "POST", "/rebind-challenge", {})
    assert status == 503
    assert "not attested" in body["error"]
