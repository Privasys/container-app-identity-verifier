# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

import time

import pytest

from verifier import crypto, receipt
from verifier.verification import BioResult, DocResult


def _doc():
    return DocResult(
        fields={
            "given_name": "Alice",
            "family_name": "Doe",
            "birthdate": "2000-01-01",
            "nationality": "GBR",
        },
        doc_type="P",
        issuing_state="GBR",
        doc_expiry="2030-01-01",
        passive_auth=True,
        chip_auth=True,
    )


def _setup():
    vkey = crypto.SigningKey.generate()
    holder = crypto.SigningKey.generate()
    holder_pub = holder.public().raw()
    ivr_jws, salts = receipt.build_ivr(vkey, "m1", _doc(), BioResult(True, 0.99), holder_pub)
    ivr = receipt.verify_ivr(ivr_jws, vkey.public())
    return vkey, holder, holder_pub, ivr, salts


def _holder_sign(holder, ivr, rp, nonce, ts):
    return holder.sign(receipt._holder_message(ivr["jti"], rp, nonce, ts))


def test_full_age_over_flow():
    vkey, holder, holder_pub, ivr, salts = _setup()
    rp, nonce, ts = "shop.example", "abc", int(time.time())
    receipt.check_holder(ivr, holder_pub, rp, nonce, ts, _holder_sign(holder, ivr, rp, nonce, ts))

    token = receipt.prove_age_over(vkey, ivr, "pairwise-sub", rp,
                                   "2000-01-01", salts["birthdate"], 18)
    payload = crypto.jws_verify(token, vkey.public())
    assert payload["claim"] == "age_over_18"
    assert payload["value"] is True
    assert payload["assurance"] == "gov"
    assert payload["aud"] == rp
    assert payload["sub"] == "pairwise-sub"
    assert payload["evidence"]["issuing_state"] == "GBR"


def test_age_band_and_field_and_doc_valid():
    vkey, holder, holder_pub, ivr, salts = _setup()
    band = crypto.jws_verify(
        receipt.prove_age_band(vkey, ivr, "s", "rp", "2000-01-01", salts["birthdate"]),
        vkey.public())
    assert band["claim"] == "age_band" and "-" in band["value"] or band["value"].endswith("+")

    fld = crypto.jws_verify(
        receipt.prove_field(vkey, ivr, "s", "rp", "family_name", "Doe", salts["family_name"]),
        vkey.public())
    assert fld["claim"] == "family_name" and fld["value"] == "Doe"

    dv = crypto.jws_verify(receipt.prove_document_valid(vkey, ivr, "s", "rp"), vkey.public())
    assert dv["claim"] == "document_valid" and dv["value"] is True


def test_wrong_salt_rejected():
    vkey, holder, holder_pub, ivr, salts = _setup()
    with pytest.raises(ValueError):
        receipt.prove_age_over(vkey, ivr, "s", "rp", "2000-01-01",
                               crypto.b64u_encode(crypto.new_salt()), 18)


def test_lying_about_birthdate_rejected():
    # A different birthdate won't match the committed one.
    vkey, holder, holder_pub, ivr, salts = _setup()
    with pytest.raises(ValueError):
        receipt.prove_age_over(vkey, ivr, "s", "rp", "1990-01-01", salts["birthdate"], 18)


def test_wrong_holder_rejected():
    vkey, holder, holder_pub, ivr, salts = _setup()
    attacker = crypto.SigningKey.generate()
    rp, nonce, ts = "rp", "n", int(time.time())
    # attacker signs but presents the real holder's pub → binding check fails on sig
    sig = attacker.sign(receipt._holder_message(ivr["jti"], rp, nonce, ts))
    with pytest.raises(ValueError):
        receipt.check_holder(ivr, holder_pub, rp, nonce, ts, sig)
    # attacker presents their own pub → fails the holder_binding match
    with pytest.raises(ValueError):
        receipt.check_holder(ivr, attacker.public().raw(), rp, nonce, ts, sig)


def test_tampered_ivr_rejected():
    vkey, holder, holder_pub, ivr, salts = _setup()
    ivr_jws, _ = receipt.build_ivr(vkey, "m1", _doc(), BioResult(True, 0.99), holder_pub)
    h, p, s = ivr_jws.split(".")
    tampered = h + "." + p[:-2] + ("AA" if p[-2:] != "AA" else "BB") + "." + s
    with pytest.raises(ValueError):
        receipt.verify_ivr(tampered, vkey.public())


def test_failed_verification_not_accepted():
    vkey = crypto.SigningKey.generate()
    holder_pub = crypto.SigningKey.generate().public().raw()
    # face_match False → verify_ivr must reject
    ivr_jws, _ = receipt.build_ivr(vkey, "m", _doc(), BioResult(False, 0.1), holder_pub)
    with pytest.raises(ValueError):
        receipt.verify_ivr(ivr_jws, vkey.public())
