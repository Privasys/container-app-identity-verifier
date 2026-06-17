FROM python:3.12-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY verifier/ verifier/

EXPOSE 8080

# Declare the configure-then-freeze entry point. The Privasys deploy pipeline
# reads this label to populate the per-app `config_api` field, so the runtime
# keeps every other path at HTTP 503 until POST /configure succeeds.
LABEL org.privasys.config_api="POST /configure"

CMD ["python", "main.py"]
