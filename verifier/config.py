# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""Static configuration: OIDs, certified fields, TTLs, env flags."""

from __future__ import annotations

import os

# Bumped per release so the deployed measurement (image digest at OID 3.2)
# changes and versions are distinguishable via GET /version.
APP_VERSION = "0.3.0"

# Custom attestation OID carrying the SHA-256 of the active CSCA / ICAO master
# list (the trust anchors used for Passive Authentication). Set at runtime via
# the manager's attestation-extensions endpoint when the anchors change, so the
# trust-anchor set is attested without baking it into the measured image — the
# direct analogue of EGRESS_CA_HASH_OID (…65230.2.1). See kyc-enclave-design §7.4.
TRUST_ANCHORS_OID = "1.3.6.1.4.1.65230.2.8"

# Document fields the enclave certifies and commits to in the IVR. These map to
# the canonical referential attributes the client auto-fills as gov-assurance.
CERTIFIED_FIELDS = (
    "given_name",
    "family_name",
    "birthdate",       # YYYY-MM-DD
    "nationality",     # ISO 3166-1 alpha-3
    "document_number",
    "document_type",
    "issuing_state",
    "sex",
)

# IVR lifetime (seconds). Also bounded by the document expiry. PROD: add a
# biometric re-verification interval policy (kyc-enclave-design §8).
IVR_TTL_SECONDS = int(os.environ.get("IDENTITY_VERIFIER_IVR_TTL", str(180 * 24 * 3600)))

# Disclosure token lifetime (seconds) — short-lived, single-audience.
TOKEN_TTL_SECONDS = int(os.environ.get("IDENTITY_VERIFIER_TOKEN_TTL", "300"))

# JOSE typ headers.
IVR_TYP = "application/privasys-ivr+jws"
DISCLOSURE_TYP = "application/privasys-disclosure+jws"
AA_CHALLENGE_TYP = "application/privasys-aa-challenge+jws"

# Active Authentication challenge lifetime (seconds). The enclave issues a fresh
# challenge the chip must sign; it must be redeemed quickly to bound replay.
AA_CHALLENGE_TTL_SECONDS = int(os.environ.get("IDENTITY_VERIFIER_AA_CHALLENGE_TTL", "120"))

# NOTE: there is deliberately no env-controlled biometric dev-stub here. A
# deployed verifier must fail closed when the face models are absent — it must
# never assert a face match it did not compute. The test-only stub lives as a
# module flag in verifier/biometrics.py (_ALLOW_TEST_STUB), unreachable in prod.
