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
                                   "2000-01-01", salts["birthdate"], 18,
                                   "https://verifier.example", holder_pub)
    payload = receipt.verify_disclosure(token, vkey.public())
    assert payload["claim"] == "age_over_18"
    assert payload["value"] is True
    assert payload["assurance"] == "gov"
    assert payload["aud"] == rp
    assert payload["sub"] == "pairwise-sub"
    assert payload["evidence"]["issuing_state"] == "GBR"
    assert payload["evidence"]["measurement"] == "m1"


def test_disclosure_is_sd_jwt_vc():
    # SD-JWT VC shape: `<JWS>~` serialisation, dc+sd-jwt typ, vct, iss, and the
    # holder key in cnf.jwk (enables holder key binding at presentation time).
    import json as _json
    vkey, holder, holder_pub, ivr, salts = _setup()
    token = receipt.prove_age_over(vkey, ivr, "s", "rp",
                                   "2000-01-01", salts["birthdate"], 18,
                                   "https://verifier.example", holder_pub)
    assert token.endswith("~")
    header = _json.loads(crypto.b64u_decode(token.split(".")[0]))
    assert header["typ"] == "dc+sd-jwt"
    payload = receipt.verify_disclosure(token, vkey.public())
    assert payload["vct"] == "https://privasys.org/vct/identity-disclosure"
    assert payload["iss"] == "https://verifier.example"
    assert payload["cnf"]["jwk"] == crypto.PublicKey.from_raw(holder_pub).jwk_public()


def test_age_band_and_field_and_doc_valid():
    vkey, holder, holder_pub, ivr, salts = _setup()
    band = receipt.verify_disclosure(
        receipt.prove_age_band(vkey, ivr, "s", "rp", "2000-01-01", salts["birthdate"]),
        vkey.public())
    assert band["claim"] == "age_band" and "-" in band["value"] or band["value"].endswith("+")

    fld = receipt.verify_disclosure(
        receipt.prove_field(vkey, ivr, "s", "rp", "family_name", "Doe", salts["family_name"]),
        vkey.public())
    assert fld["claim"] == "family_name" and fld["value"] == "Doe"

    dv = receipt.verify_disclosure(receipt.prove_document_valid(vkey, ivr, "s", "rp"),
                                   vkey.public())
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


# ── /prove/presence (fresh holder check, commit-and-prove on the portrait) ──

_DG2 = b"\x02fake-jpeg-portrait-bytes\xff"


def _setup_with_portrait():
    vkey = crypto.SigningKey.generate()
    holder = crypto.SigningKey.generate()
    holder_pub = holder.public().raw()
    ivr_jws, salts = receipt.build_ivr(
        vkey, "m1", _doc(), BioResult(True, 0.99), holder_pub, dg2=_DG2)
    ivr = receipt.verify_ivr(ivr_jws, vkey.public())
    return vkey, holder_pub, ivr, salts


def test_presence_full_flow():
    vkey, holder_pub, ivr, salts = _setup_with_portrait()
    dg2_b64u = crypto.b64u_encode(_DG2)
    token = receipt.prove_presence(
        vkey, ivr, "pairwise-sub", "casino.example",
        dg2_b64u, salts[receipt.PORTRAIT_FIELD], BioResult(True, 0.97),
        "https://verifier.example", holder_pub)
    payload = receipt.verify_disclosure(token, vkey.public())
    assert payload["claim"] == "holder_present"
    assert payload["value"] is True
    assert payload["assurance"] == "gov"
    presence = payload["evidence"]["presence"]
    assert presence["face_match"] is True
    assert presence["liveness_score"] == 0.97
    assert presence["checked_at"] >= payload["evidence"]["verified_at"]
    # Base evidence still ties the receipt to the document + enclave.
    assert payload["evidence"]["measurement"] == "m1"


def test_presence_wrong_portrait_rejected():
    # A substituted photo (someone else's genuine-looking DG2) must not open
    # the commitment — only the exact portrait this IVR certified is accepted.
    vkey, holder_pub, ivr, salts = _setup_with_portrait()
    with pytest.raises(ValueError):
        receipt.prove_presence(
            vkey, ivr, "s", "rp",
            crypto.b64u_encode(b"another-portrait"), salts[receipt.PORTRAIT_FIELD],
            BioResult(True, 0.99))


def test_presence_face_mismatch_never_mints():
    # Fail closed: a failed live match raises; there is no negative token.
    vkey, holder_pub, ivr, salts = _setup_with_portrait()
    with pytest.raises(ValueError):
        receipt.prove_presence(
            vkey, ivr, "s", "rp",
            crypto.b64u_encode(_DG2), salts[receipt.PORTRAIT_FIELD],
            BioResult(False, 0.99))


def test_presence_unavailable_on_old_ivr():
    # IVRs minted before the portrait commitment (or chips without DG2)
    # cannot do presence — clean error, not a bypass.
    vkey, holder, holder_pub, ivr, salts = _setup()  # no dg2
    assert receipt.PORTRAIT_FIELD not in salts
    with pytest.raises(ValueError):
        receipt.prove_presence(
            vkey, ivr, "s", "rp",
            crypto.b64u_encode(_DG2), crypto.b64u_encode(crypto.new_salt()),
            BioResult(True, 0.99))


def test_portrait_is_not_a_certifiable_text_field():
    # The photo must never be disclosable as a value via prove_field.
    vkey, holder_pub, ivr, salts = _setup_with_portrait()
    with pytest.raises(ValueError):
        receipt.prove_field(
            vkey, ivr, "s", "rp", receipt.PORTRAIT_FIELD,
            crypto.b64u_encode(_DG2), salts[receipt.PORTRAIT_FIELD])


# ── charged-failure receipts (retryable flag only, no stage detail) ─────────

def test_failure_receipt_shape():
    vkey, holder_pub, ivr, salts = _setup_with_portrait()
    tok = receipt.failure_token(vkey, ivr, "s", "rp", "holder_present", True,
                                "https://v.example", holder_pub, "jti-1")
    p = receipt.verify_disclosure(tok, vkey.public())
    assert p["claim"] == "holder_present" and p["value"] is False
    assert p["failure"] == {"retryable": True}
    assert p["evidence"]["voucher"] == "jti-1"
    assert "stage" not in str(p.get("failure"))


def test_face_mismatch_is_retryable_ceremony_failure():
    vkey, holder_pub, ivr, salts = _setup_with_portrait()
    with pytest.raises(receipt.CeremonyFailure) as ei:
        receipt.prove_presence(vkey, ivr, "s", "rp",
                               crypto.b64u_encode(_DG2), salts[receipt.PORTRAIT_FIELD],
                               BioResult(False, 0.99))
    assert ei.value.retryable is True


def test_commitment_mismatch_is_nonretryable_ceremony_failure():
    vkey, holder, holder_pub, ivr, salts = _setup()
    with pytest.raises(receipt.CeremonyFailure) as ei:
        receipt.prove_age_over(vkey, ivr, "s", "rp", "1990-01-01",
                               salts["birthdate"], 18)
    assert ei.value.retryable is False
