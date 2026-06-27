# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""Face matching + liveness (in-enclave, open-source, no licence fee).

The matching MATH (embedding cosine distance, thresholds) is implemented and
tested here. The model INFERENCE (decode DG2 portrait + live capture, embed with
FaceNet ONNX, score liveness with MiniFASNetV2) is wired but requires the model
artifacts, which are fetched at build/deploy (not vendored) — so `match()` runs
the real path when models + onnxruntime are present, and otherwise fails closed
(the test-only stub is a module flag, never enableable on a deployed enclave).

Models / licences (kyc-enclave-design.md §7.3):
  Face embedding : FaceNet ONNX (MIT)
  Liveness/PAD   : MiniFASNetV2 / Silent-Face (Apache-2.0)
Everything runs in-process; no external calls with biometric data.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass

# Test-only escape hatch. When True, match() returns a passing stub if the face
# models are absent, so the receipt/HTTP plumbing can be exercised in CI without
# the model artifacts. It is a MODULE flag set only by tests — deliberately NOT
# an env var or config option, so a deployed enclave can never enable it and
# always fails closed without models. A KYC verifier must never assert a face
# match it did not actually compute.
_ALLOW_TEST_STUB = False

# Cosine-distance threshold for a face match (1 - cosine similarity). Default is
# SFace's published operating point (cosine similarity >= 0.363 ⇔ distance
# <= 0.637). Tune + log the FAR/FRR against a labelled set before production.
FACE_MATCH_MAX_DISTANCE = float(os.environ.get("IDENTITY_VERIFIER_FACE_MAX_DIST", "0.637"))
# Minimum liveness score (0..1) to accept the capture as a live person.
LIVENESS_MIN_SCORE = float(os.environ.get("IDENTITY_VERIFIER_LIVENESS_MIN", "0.9"))

_MODEL_DIR = os.environ.get("IDENTITY_VERIFIER_MODEL_DIR", "/models")
# Model artifacts under _MODEL_DIR. Face detect + recognise are required for the
# match; liveness (PAD) is enforced only when its model is present (so PAD can be
# dropped in without a code change).
_YUNET = "yunet.onnx"          # face detection + 5 landmarks (OpenCV Zoo, MIT)
_SFACE = "sface.onnx"          # face recognition / embedding (OpenCV Zoo, Apache-2.0)
_MINIFASNET = "minifasnet.onnx"  # liveness / PAD (Silent-Face, Apache-2.0) — optional


@dataclass
class BioResult:
    face_match: bool
    liveness_score: float


class BiometricError(Exception):
    """Biometric verification could not be performed or failed."""


# ── matching maths (pure, tested) ──────────────────────────────────────────

def cosine_distance(a, b) -> float:
    """1 - cosine similarity of two equal-length embedding vectors."""
    if len(a) != len(b) or not a:
        raise BiometricError("embedding length mismatch")
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        raise BiometricError("zero-norm embedding")
    return 1.0 - dot / (na * nb)


def is_match(distance: float, threshold: float = FACE_MATCH_MAX_DISTANCE) -> bool:
    return distance <= threshold


def is_live(score: float, threshold: float = LIVENESS_MIN_SCORE) -> bool:
    return score >= threshold


# ── model inference (wired; model-provisioned) ─────────────────────────────

def _model_path(name: str) -> str:
    return os.path.join(_MODEL_DIR, name)


def _models_available() -> bool:
    """True when face detect + recognise can run (the match's mandatory path)."""
    try:
        import cv2  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return os.path.isfile(_model_path(_YUNET)) and os.path.isfile(_model_path(_SFACE))


# Lazily-built singletons so the models load once per process.
_detector = None
_recognizer = None
_liveness_net = None
_liveness_loaded = False


def _engines():
    global _detector, _recognizer
    import cv2
    if _detector is None:
        _detector = cv2.FaceDetectorYN.create(_model_path(_YUNET), "", (320, 320), score_threshold=0.6)
    if _recognizer is None:
        _recognizer = cv2.FaceRecognizerSF.create(_model_path(_SFACE), "")
    return _detector, _recognizer


def _decode(image_bytes: bytes):
    """Decode image bytes to a BGR ndarray. DG2 wraps the portrait (JPEG2000 or
    JPEG) in an ISO 19794-5 record, so locate the embedded image first; plain
    captures decode directly. OpenCV's JPEG2000 codec handles DG2."""
    import cv2
    import numpy as np
    buf = image_bytes
    if not (buf[:3] == b"\xff\xd8\xff"):  # not a bare JPEG → look inside (DG2)
        jp2 = image_bytes.find(bytes.fromhex("0000000C6A502020"))
        jpg = image_bytes.find(b"\xff\xd8\xff")
        start = min([i for i in (jp2, jpg) if i >= 0], default=0)
        buf = image_bytes[start:]
    img = cv2.imdecode(np.frombuffer(buf, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise BiometricError("could not decode a face image")
    return img


def _embed(image_bytes: bytes):
    """Detect the largest face, align it from the 5 landmarks, and return the
    SFace embedding as a list (so cosine_distance can score it)."""
    detector, recognizer = _engines()
    img = _decode(image_bytes)
    h, w = img.shape[:2]
    detector.setInputSize((w, h))
    _, faces = detector.detect(img)
    if faces is None or len(faces) == 0:
        raise BiometricError("no face found in the image")
    largest = max(faces, key=lambda f: float(f[2]) * float(f[3]))
    aligned = recognizer.alignCrop(img, largest)
    feat = recognizer.feature(aligned)
    return feat.flatten().tolist()


def match(dg2_bytes: bytes, live_image_bytes: bytes) -> BioResult:
    """Compare the DG2 portrait to the live capture and score liveness.

    Real path requires the face models in IDENTITY_VERIFIER_MODEL_DIR. Without
    them it fails closed (a deployed enclave can never stub — _ALLOW_TEST_STUB is
    test-only). Liveness (PAD) is enforced only when its model is present.
    """
    if not _models_available():
        if _ALLOW_TEST_STUB:
            return BioResult(face_match=True, liveness_score=0.99)
        raise BiometricError(
            "face models not provisioned (IDENTITY_VERIFIER_MODEL_DIR) — "
            "see verifier/biometrics.py"
        )
    dg2_emb = _embed(dg2_bytes)
    live_emb = _embed(live_image_bytes)
    distance = cosine_distance(dg2_emb, live_emb)
    score = _liveness(live_image_bytes)
    return BioResult(face_match=is_match(distance) and is_live(score),
                     liveness_score=score)


def _liveness(image_bytes: bytes) -> float:
    """MiniFASNet passive liveness on the live capture. Returns a 0..1 live
    probability.

    Fails CLOSED: if no PAD model is provisioned the enclave must not assert that
    the capture is live — it raises (so verify-identity denies) rather than
    silently returning 1.0. Provision a *validated* minifasnet.onnx in the model
    dir to enforce real PAD. (The test-only stub skips this for CI.)"""
    global _liveness_net, _liveness_loaded
    if not _liveness_loaded:
        path = _model_path(_MINIFASNET)
        if os.path.isfile(path):
            import cv2
            _liveness_net = cv2.dnn.readNetFromONNX(path)
        else:
            _liveness_net = None
        _liveness_loaded = True
    if _liveness_net is None:
        if _ALLOW_TEST_STUB:
            return 1.0
        raise BiometricError(
            "liveness (PAD) model not provisioned — refusing to assert a live "
            "capture (fail closed); provision a validated minifasnet.onnx")
    import cv2
    import numpy as np
    img = _decode(image_bytes)
    detector, _ = _engines()
    h, w = img.shape[:2]
    detector.setInputSize((w, h))
    _, faces = detector.detect(img)
    if faces is None or len(faces) == 0:
        raise BiometricError("no face found for liveness")
    largest = max(faces, key=lambda f: float(f[2]) * float(f[3]))
    # MiniFASNet expects the minivision preprocessing, empirically validated
    # against labelled live/print/replay samples (see tools/validate_pad.py):
    # a 2.7x-scale crop around the bbox centre, raw BGR [0,255] (the model bakes
    # in its own normalisation — feeding /255 saturates every class), 80x80.
    crop = _scale_crop(img, largest, 2.7)
    blob = cv2.dnn.blobFromImage(crop, scalefactor=1.0, size=(80, 80), swapRB=False)
    _liveness_net.setInput(blob)
    out = _liveness_net.forward().flatten()
    e = np.exp(out - np.max(out))
    probs = e / e.sum()
    # Validated label convention: index 1 = live (0 = print/2D, 2 = replay/3D).
    return float(probs[1]) if probs.shape[0] >= 2 else float(out[0])


def _scale_crop(img, box, scale: float):
    """Crop a `scale`x-enlarged square-ish region around the face bbox centre
    (minivision MiniFASNet preprocessing), clamped to the image. PAD models are
    trained on this context margin, not a tight face crop."""
    x, y, bw, bh = (float(v) for v in box[:4])
    sh, sw = img.shape[:2]
    s = min((sh - 1) / bh, (sw - 1) / bw, scale)
    nw, nh = bw * s, bh * s
    cx, cy = x + bw / 2, y + bh / 2
    lx, ly = int(max(0, cx - nw / 2)), int(max(0, cy - nh / 2))
    rx, ry = int(min(sw, cx + nw / 2)), int(min(sh, cy + nh / 2))
    return img[ly:ry, lx:rx]
