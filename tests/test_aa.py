# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""Active Authentication (anti-clone): ECDSA over a fresh challenge against DG15."""

import os

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

import fixtures
from verifier import aa


def test_ecdsa_aa_accepts_valid_signature():
    priv = ec.generate_private_key(ec.SECP256R1())
    dg15 = fixtures.build_dg15(priv.public_key())
    challenge = os.urandom(8)
    aa.verify(dg15, challenge, fixtures.aa_sign_ecdsa(priv, challenge))  # no raise


def test_ecdsa_aa_rejects_a_different_challenge():
    # A captured signature over an old challenge must not verify against a new one
    # (this is what the enclave-issued fresh challenge defeats).
    priv = ec.generate_private_key(ec.SECP256R1())
    dg15 = fixtures.build_dg15(priv.public_key())
    sig = fixtures.aa_sign_ecdsa(priv, os.urandom(8))
    with pytest.raises(aa.AAError):
        aa.verify(dg15, os.urandom(8), sig)


def test_ecdsa_aa_rejects_a_clone():
    # DG15 advertises the genuine chip's key, but the signature is from a clone
    # that lacks the original private key.
    genuine = ec.generate_private_key(ec.SECP256R1())
    clone = ec.generate_private_key(ec.SECP256R1())
    dg15 = fixtures.build_dg15(genuine.public_key())
    challenge = os.urandom(8)
    with pytest.raises(aa.AAError):
        aa.verify(dg15, challenge, fixtures.aa_sign_ecdsa(clone, challenge))


def test_rsa_aa_reported_unsupported():
    # RSA AA (ISO 9796-2) is recorded as unverified, not hand-rolled.
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    dg15 = fixtures.build_dg15(priv.public_key())
    with pytest.raises(aa.AAUnsupported):
        aa.verify(dg15, os.urandom(8), b"\x00" * 256)
