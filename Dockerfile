FROM python:3.12-slim
WORKDIR /app

# opencv-python-headless runtime libs (no GUI): GLib + OpenMP. curl fetches the
# pinned models below.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libglib2.0-0 libgomp1 libgl1 curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# PaddlePaddle (CPU) — OmniMRZ's OCR backend — from Paddle's own wheel index.
RUN pip install --no-cache-dir paddlepaddle==3.0.0 \
        -i https://www.paddlepaddle.org.cn/packages/stable/cpu/

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# PaddleOCR pulls opencv-contrib-python (the GUI build), which shadows
# opencv-python-headless and fails to import on slim — breaking the cv2-based
# face match. Force headless as the sole cv2 so both face match and PaddleOCR
# import cleanly (libgl1 above is belt-and-braces).
RUN pip uninstall -y opencv-python opencv-contrib-python opencv-contrib-python-headless 2>/dev/null || true \
    && pip install --no-cache-dir --force-reinstall --no-deps "opencv-python-headless>=4.10,<5"

# OmniMRZ is VENDORED at ./omnimrz (the PyPI wheel and a git/source install both
# ship no code — the upstream pyproject `packages.find include` filter discards
# the package; see requirements.txt). Copy it after the opencv fix-up so the
# import check below runs against the headless cv2, and FAIL THE BUILD if it can't
# import — a broken OCR previously shipped silently (the import error was
# swallowed at runtime and every /read-mrz returned "couldn't read the page").
COPY omnimrz/ omnimrz/
RUN python -c "from omnimrz import OmniMRZ; print('omnimrz import OK')"

# Bake the PaddleOCR models into the image so the enclave needs NO network at
# runtime (no-egress invariant). Warm up OmniMRZ on a throwaway image to trigger
# the one-time model download into this layer (it caches under /root). The
# process() call tolerates "no MRZ" on the blank image; the import is already
# guarded above.
# NOTE: no `|| true` — if PaddleOCR can't initialise (missing OCR deps) or the
# models can't be fetched into this layer, the build MUST fail rather than ship a
# verifier that returns "couldn't read the page" at runtime. Constructing OmniMRZ
# builds the PaddleOCR pipeline, which downloads + loads the detection/recognition
# models into this layer (baked for the no-egress runtime) and raises on missing
# deps. We avoid running process() on a synthetic image (its result-parsing has
# blank-image edge cases); a real read is validated post-deploy.
RUN python -c "from omnimrz import OmniMRZ; OmniMRZ(); print('OmniMRZ init OK (models baked)')"

# Biometric models — fetched and SHA-256-pinned (not vendored). A changed
# upstream file fails the checksum and the build, so the measured image stays
# reproducible. YuNet = face detect+landmarks (MIT); SFace = recognise/embed
# (Apache-2.0); both from OpenCV Zoo. MiniFASNet (liveness/PAD) is added later;
# verifier/biometrics.py enforces liveness only when minifasnet.onnx is present.
ENV IDENTITY_VERIFIER_MODEL_DIR=/models
RUN mkdir -p /models && cd /models \
    && curl -fsSL -o yunet.onnx "https://huggingface.co/opencv/face_detection_yunet/resolve/main/face_detection_yunet_2023mar.onnx" \
    && echo "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4  yunet.onnx" | sha256sum -c - \
    && curl -fsSL -o sface.onnx "https://huggingface.co/opencv/face_recognition_sface/resolve/main/face_recognition_sface_2021dec.onnx" \
    && echo "0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79  sface.onnx" | sha256sum -c -

COPY main.py .
COPY verifier/ verifier/

EXPOSE 8080

# Declare the configure-then-freeze entry point. The Privasys deploy pipeline
# reads this label to populate the per-app `config_api` field, so the runtime
# keeps every other path at HTTP 503 until POST /configure succeeds.
LABEL org.privasys.config_api="POST /configure"

CMD ["python", "main.py"]
