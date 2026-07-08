# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

from verifier import crypto


def test_commitment_roundtrip():
    salt = crypto.new_salt()
    c = crypto.commit("2000-01-01", salt)
    assert crypto.commit_matches("2000-01-01", salt, c)
    assert not crypto.commit_matches("2000-01-02", salt, c)
    assert not crypto.commit_matches("2000-01-01", crypto.new_salt(), c)


def test_jws_sign_verify():
    key = crypto.SigningKey.generate()
    tok = crypto.jws_sign({"hello": "world", "n": 1}, key, "test+jws")
    payload = crypto.jws_verify(tok, key.public())
    assert payload == {"hello": "world", "n": 1}


def test_jws_rejects_tamper_and_wrong_key():
    key = crypto.SigningKey.generate()
    other = crypto.SigningKey.generate()
    tok = crypto.jws_sign({"a": 1}, key, "test+jws")
    # wrong key
    try:
        crypto.jws_verify(tok, other.public())
        assert False, "verified under the wrong key"
    except ValueError:
        pass
    # tampered payload
    h, p, s = tok.split(".")
    bad = h + "." + crypto.b64u_encode(crypto.canonical_json({"a": 2})) + "." + s
    try:
        crypto.jws_verify(bad, key.public())
        assert False, "verified a tampered payload"
    except ValueError:
        pass


def test_holder_pub_raw_roundtrip():
    k = crypto.SigningKey.generate()
    raw = k.public().raw()
    msg = b"bind-me"
    sig = k.sign(msg)
    assert crypto.PublicKey.from_raw(raw).verify(msg, sig)
    assert crypto.holder_binding(raw) == crypto.holder_binding(raw)


# ── signing-key custody (sealed volume / platform refusal) ──────────────────

def test_signing_key_persists_on_data_dir(tmp_path, monkeypatch):
    # First load generates in-enclave and persists; second load returns the
    # SAME key (restart must not rotate the JWKS / strand outstanding IVRs).
    monkeypatch.delenv("PRIVASYS_IMAGE_DIGEST", raising=False)
    monkeypatch.delenv("IDENTITY_VERIFIER_SIGNING_KEY_PEM", raising=False)
    monkeypatch.setenv("IDENTITY_VERIFIER_DATA_DIR", str(tmp_path))
    first = crypto.SigningKey.load()
    assert (tmp_path / "signing_key.pem").exists()
    second = crypto.SigningKey.load()
    assert first.kid == second.kid


def test_platform_refuses_external_pem(monkeypatch):
    # A key a human ever held could mint "enclave" receipts from a laptop —
    # inside the platform the env path must hard-fail, never be accepted.
    monkeypatch.setenv("PRIVASYS_IMAGE_DIGEST", "sha256-something")
    monkeypatch.setenv("IDENTITY_VERIFIER_SIGNING_KEY_PEM", "-----BEGIN X-----")
    try:
        crypto.SigningKey.load()
        assert False, "accepted an external key inside the enclave"
    except RuntimeError:
        pass


def test_platform_never_falls_back_to_ephemeral(tmp_path, monkeypatch):
    # No usable sealed volume on the platform → hard failure, not a silent
    # restart-rotating key.
    monkeypatch.setenv("PRIVASYS_IMAGE_DIGEST", "sha256-something")
    monkeypatch.delenv("IDENTITY_VERIFIER_SIGNING_KEY_PEM", raising=False)
    monkeypatch.setenv("IDENTITY_VERIFIER_DATA_DIR", str(tmp_path / "missing" / "dir"))
    try:
        crypto.SigningKey.load()
        assert False, "fell back to an ephemeral key on the platform"
    except RuntimeError:
        pass


def test_dev_falls_back_to_ephemeral(tmp_path, monkeypatch):
    # Bare dev/test run: no platform, no volume → ephemeral keys, distinct.
    monkeypatch.delenv("PRIVASYS_IMAGE_DIGEST", raising=False)
    monkeypatch.delenv("IDENTITY_VERIFIER_SIGNING_KEY_PEM", raising=False)
    monkeypatch.setenv("IDENTITY_VERIFIER_DATA_DIR", str(tmp_path / "missing"))
    assert crypto.SigningKey.load().kid != crypto.SigningKey.load().kid
