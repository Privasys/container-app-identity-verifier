# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""ICAO 9303 Active Authentication (anti-clone).

Passive Authentication proves the chip's *data* is genuine government-issued, but
not that this is the *original* chip: an attacker can copy DG1/DG2/EF.SOD onto a
blank chip and PA still passes. Active Authentication closes that: the chip holds
a private key whose public half is in DG15 (hash-protected by EF.SOD, so PA-
verified). The chip signs a fresh terminal challenge (RND.IFD, 8 bytes) with
INTERNAL AUTHENTICATE; a valid signature proves the chip is the original, since
the private key is non-extractable and cannot be cloned.

The challenge MUST come from the verifier so it is fresh and unforgeable (a
client-chosen challenge could be replayed with a captured signature). The enclave
issues it (`/aa-challenge`) and verifies the chip's signature here.

ECDSA AA is verified with pyca over the raw challenge (the eMRTD "plain" r‖s
signature format, BSI TR-03111). RSA AA uses ISO 9796-2 Digital Signature scheme
1 with message recovery (ICAO 9303 Part 11 §6.1); a vetted, real-document-
validated implementation is a TODO, so RSA AA is reported as unverified rather
than hand-rolled here (which could wrongly reject genuine RSA-AA passports).

Reference: ICAO Doc 9303 Part 11 §6.1; BSI TR-03111.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import load_der_public_key


class AAError(Exception):
    """Active Authentication failed (the chip's signature did not verify)."""


class AAUnsupported(Exception):
    """The chip's AA key type is not yet verifiable here (e.g. RSA / ISO 9796-2)."""


# AA does not carry the hash algorithm in the ECDSA signature (it lives in DG14's
# ActiveAuthenticationInfo, which we do not parse), so we try the standard set.
# This cannot admit a clone: a forged chip lacks the private key and so cannot
# produce a signature valid under any hash.
_AA_HASHES = (hashes.SHA256, hashes.SHA384, hashes.SHA512, hashes.SHA224, hashes.SHA1)


def _unwrap_dg15(dg15: bytes) -> bytes:
    """DG15 is `[APPLICATION 15]` (tag 0x6F) wrapping a SubjectPublicKeyInfo.
    Strip that outer tag; a bare SPKI passes through unchanged."""
    if not dg15 or dg15[0] != 0x6F:
        return dg15
    i = 1
    n = dg15[i]
    i += 1
    if n & 0x80:
        count = n & 0x7F
        length = int.from_bytes(dg15[i:i + count], "big")
        i += count
    else:
        length = n
    return dg15[i:i + length]


def verify(dg15: bytes, challenge: bytes, signature: bytes) -> None:
    """Verify the chip's Active Authentication signature over `challenge` against
    the DG15 public key. Raises AAError if the signature is invalid (a clone or
    tamper), or AAUnsupported if the AA key type cannot be verified yet."""
    spki = _unwrap_dg15(dg15)
    try:
        pub = load_der_public_key(spki)
    except ValueError as exc:
        # EC keys with explicit domain parameters land here; supporting them needs
        # the python-ecdsa fallback (as in passive_auth). TODO.
        raise AAUnsupported("AA public key could not be loaded") from exc

    if isinstance(pub, ec.EllipticCurvePublicKey):
        _verify_ecdsa(pub, challenge, signature)
        return
    # RSA AA = ISO 9796-2 message recovery; not hand-rolled here (see module docs).
    raise AAUnsupported("RSA Active Authentication (ISO 9796-2) is not yet verified")


def _verify_ecdsa(pub: ec.EllipticCurvePublicKey, challenge: bytes, signature: bytes) -> None:
    size = (pub.curve.key_size + 7) // 8
    if len(signature) == 2 * size:  # eMRTD "plain" r‖s (BSI TR-03111)
        der = encode_dss_signature(
            int.from_bytes(signature[:size], "big"),
            int.from_bytes(signature[size:], "big"),
        )
    else:
        der = signature  # already DER-encoded
    for h in _AA_HASHES:
        try:
            pub.verify(der, challenge, ec.ECDSA(h()))
            return
        except InvalidSignature:
            continue
        except ValueError:
            continue
    raise AAError("Active Authentication signature is invalid")
