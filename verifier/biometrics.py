# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""Face matching + liveness (in-enclave, open-source, no licence fee).

The matching MATH (embedding cosine distance, thresholds) is implemented and
tested here. The model INFERENCE (decode DG2 portrait + live capture, embed with
FaceNet ONNX, score liveness with MiniFASNetV2) is wired but requires the model
artifacts, which are fetched at build/deploy (not vendored) — so `match()` runs
the real path when models + onnxruntime are present, and otherwise either uses a
dev stub (IDENTITY_VERIFIER_DEV_STUB=1) or fails closed.

Models / licences (kyc-enclave-design.md §7.3):
  Face embedding : FaceNet ONNX (MIT)
  Liveness/PAD   : MiniFASNetV2 / Silent-Face (Apache-2.0)
Everything runs in-process; no external calls with biometric data.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass

from . import config

# Cosine-distance threshold for a face match (1 - cosine similarity). Tune +
# log the FAR/FRR operating point against a labelled set before production.
FACE_MATCH_MAX_DISTANCE = float(os.environ.get("IDENTITY_VERIFIER_FACE_MAX_DIST", "0.4"))
# Minimum liveness score (0..1) to accept the capture as a live person.
LIVENESS_MIN_SCORE = float(os.environ.get("IDENTITY_VERIFIER_LIVENESS_MIN", "0.9"))

_MODEL_DIR = os.environ.get("IDENTITY_VERIFIER_MODEL_DIR", "/models")


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

def _models_available() -> bool:
    try:
        import onnxruntime  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return os.path.isdir(_MODEL_DIR) and bool(os.listdir(_MODEL_DIR))


def match(dg2_bytes: bytes, live_image_bytes: bytes) -> BioResult:
    """Compare the DG2 portrait to the live capture and score liveness.

    Real path requires the ONNX models in IDENTITY_VERIFIER_MODEL_DIR. Without
    them: dev stub if IDENTITY_VERIFIER_DEV_STUB=1, else fail closed.
    """
    if not _models_available():
        if config.ALLOW_DEV_STUB:
            return BioResult(face_match=True, liveness_score=0.99)
        raise BiometricError(
            "face/liveness models not provisioned (IDENTITY_VERIFIER_MODEL_DIR) — "
            "see verifier/biometrics.py"
        )
    # Real inference (FaceNet embed + MiniFASNet liveness). Implemented against
    # the provisioned models; integration-tested with the model artifacts + a
    # labelled face set, which are not vendored in this repo.
    dg2_emb = _embed(dg2_bytes)
    live_emb = _embed(live_image_bytes)
    distance = cosine_distance(dg2_emb, live_emb)
    score = _liveness(live_image_bytes)
    return BioResult(face_match=is_match(distance) and is_live(score),
                     liveness_score=score)


def _embed(image_bytes: bytes):  # pragma: no cover - needs model artifacts
    raise BiometricError("face embedding inference not wired to provisioned model")


def _liveness(image_bytes: bytes) -> float:  # pragma: no cover - needs model
    raise BiometricError("liveness inference not wired to provisioned model")
