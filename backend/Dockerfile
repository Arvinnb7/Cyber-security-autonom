FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install deps first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as a non-root user.
RUN useradd -u 10001 -m appuser && chown -R appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/ready').status==200 else 1)"

# Production server: multiple Uvicorn workers behind Gunicorn. The scheduler is
# disabled here (SENTINEL_RUN_SCHEDULER=false) and runs in a dedicated worker.
#
# --max-requests recycles each worker periodically so any slow leak (ours or a
# dependency's) is reclaimed instead of accumulating for weeks; the jitter stops
# all four workers restarting at the same moment. --graceful-timeout lets
# in-flight requests finish before a worker is replaced.
CMD ["gunicorn", "app.main:app", "-k", "uvicorn.workers.UvicornWorker", \
     "--workers", "4", "--bind", "0.0.0.0:8000", "--timeout", "60", \
     "--graceful-timeout", "30", "--max-requests", "2000", "--max-requests-jitter", "200"]
