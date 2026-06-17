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
