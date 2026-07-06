# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""Static configuration: OIDs, certified fields, TTLs, env flags."""

from __future__ import annotations

import os

# Bumped per release so the deployed measurement (image digest at OID 3.2)
# changes and versions are distinguishable via GET /version.
APP_VERSION = "0.4.0"

# The verifier's own measurement, stamped into every IVR so a relying party can
# tell which audited verifier code produced a receipt. PRIVASYS_IMAGE_DIGEST is
# the hex SHA-256 of the pinned container image, injected by the enclave-os
# launcher at load — the same value the platform attests at OID 3.2, so the IVR
# claim is cross-checkable against the RA-TLS leaf. "unbound" only outside the
# platform (local dev/tests).
MEASUREMENT = os.environ.get("PRIVASYS_IMAGE_DIGEST", "unbound")

# Custom attestation OID carrying the SHA-256 of the active CSCA / ICAO master
# list (the trust anchors used for Passive Authentication). Set at runtime via
# the manager's attestation-extensions endpoint when the anchors change, so the
# trust-anchor set is attested without baking it into the measured image.
#
# This lives in the APP-CUSTOM per-workload arc (1.3.6.1.4.1.65230.3.5.<n>) —
# the ONLY arc the manager's attestation-extensions API accepts (it force-pins
# every app-set value under 3.5.*; see enclave-os oids.ParseEnvVarOID). Trust
# anchors are loaded by THIS app via /configure, so an app-custom OID is the
# correct home. (The earlier 2.8 was module-level — the 2.x arc is for
# platform-SET facts like the egress-CA hash 2.1, not app-managed values — so
# it silently never landed in the leaf.) See kyc-enclave-design §7.4.
TRUST_ANCHORS_OID = "1.3.6.1.4.1.65230.3.5.1"

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

# JOSE typ headers. Disclosure tokens are SD-JWT VCs (draft-ietf-oauth-sd-jwt-vc)
# so relying parties can use off-the-shelf SD-JWT tooling; the IVR and the AA
# challenge stay private, verifier-internal JWS formats.
IVR_TYP = "application/privasys-ivr+jws"
DISCLOSURE_TYP = "dc+sd-jwt"
AA_CHALLENGE_TYP = "application/privasys-aa-challenge+jws"

# SD-JWT VC type (vct) of every disclosure token. The concrete claim is carried
# in the token's `claim`/`value` pair, so one vct covers the whole family.
DISCLOSURE_VCT = "https://privasys.org/vct/identity-disclosure"


def issuer(host: str | None) -> str:
    """The disclosure-token `iss`. SD-JWT VC resolves the issuer's keys at
    https://<iss>/.well-known/jwt-vc-issuer, so this must be the verifier's own
    public origin: IDENTITY_VERIFIER_ISSUER when set, else derived from the
    request Host header (Caddy passes the app's public host). The URN fallback
    (no platform, no Host) is deliberately non-resolvable."""
    env = os.environ.get("IDENTITY_VERIFIER_ISSUER", "")
    if env:
        return env
    if host:
        return "https://" + host.split(",")[0].strip()
    return "urn:privasys:identity-verifier"

# Active Authentication challenge lifetime (seconds). The enclave issues a fresh
# challenge the chip must sign; it must be redeemed quickly to bound replay.
AA_CHALLENGE_TTL_SECONDS = int(os.environ.get("IDENTITY_VERIFIER_AA_CHALLENGE_TTL", "120"))

# NOTE: there is deliberately no env-controlled biometric dev-stub here. A
# deployed verifier must fail closed when the face models are absent — it must
# never assert a face match it did not compute. The test-only stub lives as a
# module flag in verifier/biometrics.py (_ALLOW_TEST_STUB), unreachable in prod.
