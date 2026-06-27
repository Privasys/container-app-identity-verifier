FROM python:3.12-slim
WORKDIR /app

# OpenCV runtime libs. PaddleOCR requires the opencv-contrib-python distribution
# (the GUI build), so install the GL/X shared libs it dylinks at import time on
# python:slim (GLib + OpenMP + libGL + the X libs highgui references). Without
# these `import cv2` fails and both the OCR and the face match break.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libglib2.0-0 libgomp1 libgl1 libsm6 libxext6 libxrender1 curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# PaddlePaddle (CPU) — OmniMRZ's OCR backend — from Paddle's own wheel index.
# Must match the paddleocr/paddlex 3.7 model format: 3.0.0 fails at inference
# with `ValueError: Type of attribute: strides is not right` (the PP-OCRv5 PIR
# attribute fix landed after 3.0.0). 3.2.x is past it and matches paddlex 3.7.
RUN pip install --no-cache-dir paddlepaddle==3.2.2 \
        -i https://www.paddlepaddle.org.cn/packages/stable/cpu/

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# NOTE (do not re-add a force-headless step here): PaddleOCR's paddlex dep check
# verifies the `opencv-contrib-python` distribution is installed (by name), so
# swapping it for opencv-python-headless made every OCR call raise DependencyError
# ("OCR requires additional dependencies") at runtime. We keep opencv-contrib-
# python (pulled by paddlex[ocr-core]) as the sole cv2 and supply its GL/X libs in
# the apt step above. The strict OmniMRZ() init below fails the build if cv2 can't
# import, so a regression here can't ship silently.

# Bake the PaddleOCR det+rec models into the image so the enclave needs NO network
# at runtime (no-egress invariant). We drive PaddleOCR directly with the document
# pre-stages disabled (see verifier/doc_ocr.py), so only the detection +
# recognition models are constructed/downloaded here — not the heavier
# orientation/unwarp models. FAIL THE BUILD (no `|| true`) on a missing OCR dep or
# a failed model fetch, so a broken OCR can never ship silently again (it once did:
# the import error was swallowed at runtime and every /read-mrz returned "couldn't
# read the page"). A green build proves the whole OCR stack: deps + cv2 + paddle
# inference + baked models.
RUN python -c "import numpy as np; from paddleocr import PaddleOCR; \
    o=PaddleOCR(lang='en', use_doc_orientation_classify=False, use_doc_unwarping=False, use_textline_orientation=False); \
    o.predict(np.full((80,300,3), 255, 'uint8')); \
    print('PaddleOCR init+predict OK (det+rec models baked)')"

# Biometric models — fetched and SHA-256-pinned (not vendored). A changed
# upstream file fails the checksum and the build, so the measured image stays
# reproducible. YuNet = face detect+landmarks (MIT); SFace = recognise/embed
# (Apache-2.0); both from OpenCV Zoo. MiniFASNetV2 (liveness/PAD, minivision /
# Silent-Face, Apache-2.0) is baked too: biometrics.py FAILS CLOSED without it
# (a verifier that cannot assess liveness denies, it does not silently pass). The
# preprocessing + live-label index were validated empirically against labelled
# live/print/replay samples (tools/validate_pad.py) — the upstream model card's
# claimed normalisation/label were WRONG, so do not trust it; re-run the
# validator if this pin changes. NOTE: this is a baseline single-frame PAD, not
# an iBeta-certified or FAR/FRR-calibrated one.
ENV IDENTITY_VERIFIER_MODEL_DIR=/models
RUN mkdir -p /models && cd /models \
    && curl -fsSL -o yunet.onnx "https://huggingface.co/opencv/face_detection_yunet/resolve/main/face_detection_yunet_2023mar.onnx" \
    && echo "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4  yunet.onnx" | sha256sum -c - \
    && curl -fsSL -o sface.onnx "https://huggingface.co/opencv/face_recognition_sface/resolve/main/face_recognition_sface_2021dec.onnx" \
    && echo "0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79  sface.onnx" | sha256sum -c - \
    && curl -fsSL -o minifasnet.onnx "https://huggingface.co/garciafido/minifasnet-v2-anti-spoofing-onnx/resolve/main/minifasnet_v2.onnx" \
    && echo "d7b3cd9ba8a7ceb13baa8c4720902e27ca3112eff52f926c08804af6b6eecc7b  minifasnet.onnx" | sha256sum -c -

COPY main.py .
COPY verifier/ verifier/

EXPOSE 8080

# Declare the configure-then-freeze entry point. The Privasys deploy pipeline
# reads this label to populate the per-app `config_api` field, so the runtime
# keeps every other path at HTTP 503 until POST /configure succeeds.
LABEL org.privasys.config_api="POST /configure"

CMD ["python", "main.py"]
