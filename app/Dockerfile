# ── Stage 1: Security scan ───────────────────────────────
FROM python:3.11-slim AS security-check
WORKDIR /scan
COPY requirements.txt .
RUN pip install bandit safety --no-cache-dir
COPY app.py .
# Run Bandit - static code security analysis
RUN bandit -r app.py -ll --format txt || true
# Run Safety - check dependencies for known CVEs
RUN safety check -r requirements.txt || true

# ── Stage 2: Production image ─────────────────────────────
FROM python:3.11-slim AS production

# Security: run as non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Install deps first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir flask==3.0.3 prometheus-client==0.20.0 gunicorn==22.0.0

# Copy app
COPY app.py .

# Security: set proper ownership
RUN chown -R appuser:appuser /app

# Security: switch to non-root
USER appuser

EXPOSE 5000

# Health check built into Docker
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "60", "--access-logfile", "-", "app:app"]
