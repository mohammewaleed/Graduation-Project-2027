# syntax=docker/dockerfile:1

# --- Stage 1: Build virtual environment & install Python dependencies ---
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY backend/requirements.txt ./requirements.txt
RUN pip install --upgrade pip && pip install -r requirements.txt

# --- Stage 2: Minimal non-root runtime image ---
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    APP_PORT=8000 \
    DATABASE_URL="sqlite:///./data/scanner.db"

WORKDIR /app

# Create unprivileged scanner user and writable data directory
RUN groupadd --system scanner \
    && useradd --system --gid scanner --home-dir /app --shell /usr/sbin/nologin scanner \
    && mkdir -p /app/data \
    && chown -R scanner:scanner /app

COPY --from=builder /opt/venv /opt/venv
COPY --chown=scanner:scanner backend ./backend
COPY --chown=scanner:scanner frontend ./frontend

USER scanner

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)" || exit 1

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
