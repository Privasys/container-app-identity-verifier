# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""Enclave-side document OCR for the pre-NFC chip-key read (/read-mrz) and the
GPG45 box-3 cross-reference.

The on-device camera OCR is unreliable on the OCR-B MRZ font (e.g. it reads the
document number's 'I' as '1'), so the wallet forwards the data-page image and we
OCR it here with PaddleOCR for a trustworthy read.

We drive PaddleOCR directly rather than via OmniMRZ: OmniMRZ's extractor assumes
the MRZ is the only thing in the bottom 50% of the frame and takes the last two
detected rows, which on a real full-page phone photo (photo, fields, glare) read
only fragments. Instead we OCR the whole page with the document pre-stages
(orientation classify / unwarp / textline orientation) DISABLED — they add
latency, memory and distortion without helping a flat MRZ — and assemble the MRZ
by selecting the bottom-most lines that match the MRZ alphabet.

Imported lazily; the PaddleOCR det+rec models are baked into the image (no
runtime egress). Never raises — box 3 degrades gracefully (M1C does not fail when
the VIZ can't be read, provided the chip + biometric verify).
"""

from __future__ import annotations

import re
import sys

_ocr = None
_NON_MRZ = re.compile(r"[^A-Z0-9<]")


def _engine():
    global _ocr
    if _ocr is None:
        from paddleocr import PaddleOCR
        _ocr = PaddleOCR(
            lang="en",
            use_doc_orientation_classify=False,
            use_doc_unwarping=False,
            use_textline_orientation=False,
        )
    return _ocr


def _norm(s: str) -> str:
    return _NON_MRZ.sub("", (s or "").upper())


def _detected_lines(result) -> list[str]:
    """Each recognised text region, normalised to the MRZ alphabet. PaddleOCR
    already detects per text line, so we do NOT re-cluster by position: a slightly
    angled photo gives skewed polygons (a huge bounding height, a mid-image
    y-centre) that collapse any y-clustering and merge unrelated lines. The MRZ
    rows are self-identifying by content (long, filler-heavy)."""
    if not result or not result[0]:
        return []
    return [_norm(t) for t in (result[0].get("rec_texts") or [])]


def _assemble_mrz(lines: list[str]) -> str:
    """Pick the MRZ rows out of all detected lines and pad to the ICAO row width.

    MRZ rows are long runs of the MRZ alphabet carrying filler '<' (ordinary
    fields like an address normalise short and carry no '<'). For TD3/TD2 there
    are two; the names row has (almost) no digits and the data row is digit-heavy,
    which orders them reliably without trusting the skewed y-coordinates. Pad each
    to 44/36 so the check digits land at the fixed offsets verifier/mrz.py expects.
    """
    cands = [l for l in lines if len(l) >= 30 and l.count("<") >= 3]
    if len(cands) < 2:
        return ""
    cands.sort(key=len, reverse=True)
    pick = cands[:2]
    pick.sort(key=lambda s: sum(c.isdigit() for c in s))  # line1 (names) then line2 (data)
    target = 44 if max(len(pick[0]), len(pick[1])) > 38 else 36   # TD3 / TD2
    return "".join((l[:target] if len(l) > target else l + "<" * (target - len(l)))
                   for l in pick)


def read_mrz(image_bytes: bytes) -> dict:
    """OCR a data-page image. Returns {"mrz": <joined MRZ rows or "">,
    "lines": [all detected lines] (debug), "is_screenshot": None}."""
    out: dict = {"mrz": "", "lines": [], "is_screenshot": None}
    try:
        import cv2
        import numpy as np
        img = cv2.imdecode(np.frombuffer(image_bytes, dtype=np.uint8), cv2.IMREAD_COLOR)
        if img is None:
            return out
        lines = _detected_lines(_engine().predict(img))
        out["lines"] = lines
        out["mrz"] = _assemble_mrz(lines)
    except Exception as exc:  # noqa: BLE001 — OCR is best-effort; box 3 degrades to None
        # Log (don't raise): a misread degrades gracefully, but surface the cause
        # so a systemic failure (e.g. a missing OCR dep) is visible in the logs
        # rather than looking identical to "couldn't read this image".
        print(f"[doc_ocr] read_mrz failed: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
    return out
