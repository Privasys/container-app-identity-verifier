# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""CSCA / ICAO master-list trust anchors — runtime-updatable, attested via OID.

The trust anchors used for Passive Authentication are NOT baked into the measured
image (they change constantly). They live on the per-app sealed volume, are
settable/updatable at runtime, and the active set is hashed and published as the
TRUST_ANCHORS_OID attestation extension — so relying parties can pin "which trust
anchors were in force" via the RA-TLS leaf, exactly like the egress CA-root hash
(EGRESS_CA_HASH_OID …65230.2.1). See kyc-enclave-design.md §7.4.
"""

from __future__ import annotations

import hashlib
import os
import threading
from pathlib import Path

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import serialization

from . import config, manager

_LOCK = threading.Lock()


def _path() -> Path:
    """Trust-anchor file on the per-app sealed volume (env-overridable for tests)."""
    return Path(os.environ.get("IDENTITY_VERIFIER_DATA_DIR", "/data")) / "trust_anchors.pem"


def _digest(pem: bytes) -> bytes:
    return hashlib.sha256(pem).digest()


def load() -> bytes:
    try:
        return _path().read_bytes()
    except FileNotFoundError:
        return b""


def anchors_der() -> list[bytes]:
    """Active CSCA trust anchors as DER certificates (for passive_auth.verify)."""
    pem = load()
    if not pem:
        return []
    return [c.public_bytes(serialization.Encoding.DER)
            for c in cx509.load_pem_x509_certificates(pem)]


def digest_hex() -> str:
    return _digest(load()).hex() if load() else ""


def count() -> int:
    """Rough count of PEM certificate blocks in the active anchor set."""
    return load().count(b"-----BEGIN CERTIFICATE-----")


def set_anchors(pem: bytes, *, push_oid: bool = True) -> str:
    """Persist a new trust-anchor set and publish its digest as the attested OID.

    Returns the hex digest. PROD: validate the master list (well-formed CMS /
    signed master list) before swapping. Gated to the app owner / trust-anchor
    admin at the API layer.
    """
    if b"-----BEGIN CERTIFICATE-----" not in pem:
        raise ValueError("trust anchors must be PEM certificate(s)")
    # Validate the bundle parses before swapping.
    cx509.load_pem_x509_certificates(pem)
    with _LOCK:
        path = _path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".pem.tmp")
        tmp.write_bytes(pem)
        tmp.replace(path)
        d = _digest(pem)
    if push_oid and manager.available():
        manager.set_attestation_extension(config.TRUST_ANCHORS_OID, d)
    return d.hex()
