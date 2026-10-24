# Automated MCP Pentester - single-stage image serving API + built frontend
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps kept minimal; reportlab/scikit-learn ship manylinux wheels.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates nodejs npm \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Build the frontend with the container's node, then layer in the backend.
COPY frontend/package.json frontend/package-lock.json* ./frontend/
RUN cd frontend && npm install --no-fund --no-audit
COPY frontend ./frontend
RUN cd frontend && npm run build && rm -rf node_modules

COPY backend ./backend
COPY fixtures ./fixtures
COPY conftest.py pytest.ini ./

# Non-root runtime user; data dir must be writable for SQLite/uploads/reports.
RUN useradd --create-home appuser && mkdir -p /app/data \
 && chown -R appuser:appuser /app
USER appuser

# Train the (advisory) ML model if artifacts are absent; never fails the image.
RUN python -m backend.ml.train || echo "ML training skipped in build"

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

CMD ["python", "-m", "uvicorn", "backend.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
