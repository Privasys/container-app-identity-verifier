#!/usr/bin/env python3
# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.

"""Validate the liveness (PAD) model wiring against labelled samples.

Confirms that the baked MiniFASNet model + the preprocessing in
verifier/biometrics.py actually separate live faces from presentation attacks —
and, critically, that the live-label index is not inverted. The upstream model
card was empirically WRONG about both normalisation and the live index, so this
is the source of truth for the pin; re-run it whenever the model hash changes.

This checks *wiring correctness* (live scores high, spoof scores low with a clear
margin) on a handful of labelled samples. It is NOT a FAR/FRR calibration — that
needs a proper labelled dataset before relying on the score for production M1C.

Usage:
    python tools/validate_pad.py --models-dir /models --samples-dir ./samples

Samples are classified by filename: a name containing "real" or matching the
minivision convention (image_T*) is a live face; "fake"/"spoof"/image_F* is an
attack. Exit status is non-zero if any sample is misclassified or the live/spoof
score ranges overlap, so it can gate a build.
"""

import argparse
import glob
import os
import sys

import cv2
import numpy as np
import onnxruntime as ort

LIVE_INDEX = 1          # validated: 0 = print/2D, 1 = live, 2 = replay/3D
LIVENESS_MIN = 0.9      # must match biometrics.LIVENESS_MIN_SCORE


def is_real(path: str) -> bool:
    n = os.path.basename(path).lower()
    if "real" in n or "live" in n:
        return True
    if "fake" in n or "spoof" in n or "attack" in n:
        return False
    # minivision sample convention: image_T* = true/real, image_F* = fake
    return "_t" in n


def scale_crop(img, box, scale=2.7):
    x, y, bw, bh = (float(v) for v in box[:4])
    sh, sw = img.shape[:2]
    s = min((sh - 1) / bh, (sw - 1) / bw, scale)
    nw, nh = bw * s, bh * s
    cx, cy = x + bw / 2, y + bh / 2
    lx, ly = int(max(0, cx - nw / 2)), int(max(0, cy - nh / 2))
    rx, ry = int(min(sw, cx + nw / 2)), int(min(sh, cy + nh / 2))
    return img[ly:ry, lx:rx]


def live_score(sess, inp, det, img) -> float:
    h, w = img.shape[:2]
    det.setInputSize((w, h))
    _, faces = det.detect(img)
    if faces is None or len(faces) == 0:
        raise SystemExit(f"no face detected in a sample ({w}x{h})")
    box = max(faces, key=lambda f: float(f[2]) * float(f[3]))
    crop = scale_crop(img, box)
    blob = cv2.dnn.blobFromImage(crop, scalefactor=1.0, size=(80, 80), swapRB=False)
    out = sess.run(None, {inp: blob.astype(np.float32)})[0].flatten()
    e = np.exp(out - out.max())
    return float((e / e.sum())[LIVE_INDEX])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models-dir", default="/models")
    ap.add_argument("--samples-dir", required=True)
    args = ap.parse_args()

    sess = ort.InferenceSession(os.path.join(args.models_dir, "minifasnet.onnx"),
                                providers=["CPUExecutionProvider"])
    inp = sess.get_inputs()[0].name
    det = cv2.FaceDetectorYN.create(
        os.path.join(args.models_dir, "yunet.onnx"), "", (320, 320), score_threshold=0.6)

    reals, fakes, bad = [], [], []
    for path in sorted(glob.glob(os.path.join(args.samples_dir, "*"))):
        if not os.path.isfile(path):
            continue
        img = cv2.imread(path)
        if img is None:
            continue
        score = live_score(sess, inp, det, img)
        real = is_real(path)
        (reals if real else fakes).append(score)
        ok = (score >= LIVENESS_MIN) if real else (score < LIVENESS_MIN)
        if not ok:
            bad.append((path, real, score))
        print(f"  {'REAL' if real else 'FAKE'} {os.path.basename(path):24} "
              f"live={score:.3f} {'OK' if ok else 'MISCLASSIFIED'}")

    if not reals or not fakes:
        print("need at least one real and one fake sample", file=sys.stderr)
        return 2
    margin = min(reals) - max(fakes)
    print(f"\nlive min={min(reals):.3f}  spoof max={max(fakes):.3f}  margin={margin:.3f}")
    if bad or margin <= 0:
        print("FAIL: PAD wiring does not cleanly separate live from spoof", file=sys.stderr)
        return 1
    print("PASS: live and spoof separate at the configured threshold")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
