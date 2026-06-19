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


def _cluster_lines(result) -> list[str]:
    """Cluster PaddleOCR's recognised boxes into reading-order lines, normalised
    to the MRZ alphabet. Boxes on the same text line (similar y) are joined left
    to right."""
    if not result or not result[0]:
        return []
    r = result[0]
    polys = r.get("dt_polys") or r.get("rec_polys") or []
    texts = r.get("rec_texts") or []
    if not polys or not texts:
        return []
    items, heights = [], []
    for poly, text in zip(polys, texts):
        ys = [float(p[1]) for p in poly]
        xs = [float(p[0]) for p in poly]
        items.append({"t": text, "y": sum(ys) / len(ys), "x": sum(xs) / len(xs)})
        heights.append(max(ys) - min(ys))
    items.sort(key=lambda k: k["y"])
    heights.sort()
    thr = max(8.0, (heights[len(heights) // 2] if heights else 16.0) * 0.6)
    lines, cur = [], []
    for it in items:
        if cur and abs(it["y"] - sum(i["y"] for i in cur) / len(cur)) > thr:
            lines.append(cur)
            cur = []
        cur.append(it)
    if cur:
        lines.append(cur)
    out = []
    for ln in lines:
        ln.sort(key=lambda k: k["x"])
        out.append(_norm("".join(i["t"] for i in ln)))
    return out


def _assemble_mrz(lines: list[str]) -> str:
    """Pick the MRZ rows out of all detected lines and pad to the ICAO row width.

    MRZ rows are long runs of the MRZ alphabet with filler '<' (ordinary fields
    like an address normalise short and carry no '<'). TD3/TD2 are the bottom 2
    rows, TD1 the bottom 3; pad each to 44/36/30 so the check digits land at the
    fixed offsets verifier/mrz.py expects."""
    cands = [l for l in lines if len(l) >= 28 and "<" in l]
    if len(cands) < 2:
        return ""
    tail3 = cands[-3:]
    if len(tail3) >= 3 and max(len(x) for x in tail3) <= 32:
        chosen, target = tail3, 30                      # TD1 (3 x 30)
    else:
        chosen = cands[-2:]
        target = 44 if max(len(x) for x in chosen) > 38 else 36  # TD3 / TD2
    return "".join((l[:target] if len(l) > target else l + "<" * (target - len(l)))
                   for l in chosen)


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
        lines = _cluster_lines(_engine().predict(img))
        out["lines"] = lines
        out["mrz"] = _assemble_mrz(lines)
    except Exception as exc:  # noqa: BLE001 — OCR is best-effort; box 3 degrades to None
        # Log (don't raise): a misread degrades gracefully, but surface the cause
        # so a systemic failure (e.g. a missing OCR dep) is visible in the logs
        # rather than looking identical to "couldn't read this image".
        print(f"[doc_ocr] read_mrz failed: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
    return out
