FROM python:3.12-slim
WORKDIR /app

# opencv-python-headless runtime libs (no GUI): GLib + OpenMP. curl fetches the
# pinned models below.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libglib2.0-0 libgomp1 curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

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
