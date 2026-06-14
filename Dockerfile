# ── Builder ──────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN python -m venv /venv \
    && /venv/bin/pip install --no-cache-dir --upgrade pip \
    && /venv/bin/pip install --no-cache-dir -r requirements.txt

# ── Runtime ──────────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app
COPY --from=builder /venv /venv
COPY pcap_tool/ pcap_tool/
COPY web/ web/
COPY pcap.py .

ENV PATH="/venv/bin:$PATH" \
    PCAP_TOOL_UPLOAD_DIR=/data/uploads \
    PCAP_TOOL_OUTPUT_DIR=/data/outputs \
    PYTHONUNBUFFERED=1

VOLUME ["/data"]
EXPOSE 8000

CMD ["gunicorn", "-w", "1", "--threads", "4", "-b", "0.0.0.0:8000", "web.app:app"]
