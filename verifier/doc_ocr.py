# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""Enclave-side document OCR for the GPG45 box-3 cross-reference.

The on-device camera OCR is unreliable on the OCR-B MRZ font (e.g. it reads the
document number's 'I' as '1'), so the wallet forwards the data-page image and we
OCR it here with OmniMRZ (PaddleOCR) for a trustworthy read, then cross-reference
it against the authoritative chip data (verifier/mrz.cross_reference).

Imported lazily; the PaddleOCR models are baked into the image (no runtime
egress). Never raises — box 3 degrades gracefully (M1C does not fail when the VIZ
can't be read, provided the chip + biometric verify).
"""

from __future__ import annotations

import os
import tempfile

_omni = None


def _engine():
    global _omni
    if _omni is None:
        from omnimrz import OmniMRZ
        _omni = OmniMRZ()
    return _omni


def read_mrz(image_bytes: bytes) -> dict:
    """OCR a data-page image. Returns {"mrz": <joined TD3 lines or "">,
    "is_screenshot": bool|None} — the MRZ for cross-referencing, plus OmniMRZ's
    screenshot/replay fraud signal."""
    out: dict = {"mrz": "", "is_screenshot": None}
    path = ""
    try:
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(image_bytes)
            path = f.name
        res = _engine().process(path) or {}
        ext = res.get("extraction") or {}
        line1 = (ext.get("line1") or "").strip()
        line2 = (ext.get("line2") or "").strip()
        if line1 and line2:
            out["mrz"] = "".join((line1 + line2).split()).upper()
        sd = res.get("screenshot_detection") or {}
        if "is_screenshot" in sd:
            out["is_screenshot"] = bool(sd["is_screenshot"])
    except Exception as exc:  # noqa: BLE001 — OCR is best-effort; box 3 degrades to None
        # Log (don't raise): a misread degrades gracefully. But surface the cause
        # so a *systemic* failure (e.g. a missing OCR dep) is visible in the logs
        # instead of looking identical to "couldn't read this image".
        import sys
        print(f"[doc_ocr] read_mrz failed: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
    return out
