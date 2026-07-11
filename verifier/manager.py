# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""Callbacks to the local enclave-os-virtual manager.

The launcher injects PRIVASYS_CONTAINER_NAME / PRIVASYS_CONTAINER_TOKEN; the
manager middleware enforces (loopback + token + name). We use it to publish
attestation-extension OIDs (so the next per-container RA-TLS leaf advertises
them) and to lift the configure-then-freeze gate. Mirrors container-app-example.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
from urllib.parse import urlparse

# The manager's callback URL. Since per-container network namespaces landed
# (enclave-os-virtual #45) a container can no longer reach the manager at its
# own 127.0.0.1 — the launcher injects PRIVASYS_MANAGER_URL pointing at the
# bridge gateway. Fall back to the pre-#45 loopback for older runtimes.
_MANAGER_URL = os.environ.get("PRIVASYS_MANAGER_URL", "http://127.0.0.1:9443")
_parsed = urlparse(_MANAGER_URL)
_HOST = _parsed.hostname or "127.0.0.1"
_PORT = _parsed.port or 9443
_NAME = os.environ.get("PRIVASYS_CONTAINER_NAME", "")
_TOKEN = os.environ.get("PRIVASYS_CONTAINER_TOKEN", "")


def available() -> bool:
    return bool(_NAME and _TOKEN)


def _post(path: str, body: dict) -> tuple[int, bytes]:
    if not available():
        raise RuntimeError(
            "PRIVASYS_CONTAINER_NAME / PRIVASYS_CONTAINER_TOKEN missing; "
            "is this running on enclave-os-virtual?"
        )
    conn = http.client.HTTPConnection(_HOST, _PORT, timeout=5)
    try:
        conn.request(
            "POST", path, body=json.dumps(body),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {_TOKEN}"},
        )
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def set_attestation_extension(oid: str, value: bytes) -> None:
    status, body = _post(
        f"/api/v1/containers/{_NAME}/attestation-extensions",
        {"oid": oid, "value_b64": base64.standard_b64encode(value).decode("ascii")},
    )
    if status >= 300:
        raise RuntimeError(f"manager attestation-extensions: {status} {body!r}")


def config_complete() -> None:
    status, body = _post(f"/api/v1/containers/{_NAME}/config-complete", {})
    if status >= 300:
        raise RuntimeError(f"manager config-complete: {status} {body!r}")
