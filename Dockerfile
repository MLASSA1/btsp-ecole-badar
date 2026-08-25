# syntax=docker/dockerfile:1.7
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    BTSP_DB_PATH=/data/database.db \
    BTSP_UPLOAD_DIR=/data/uploads \
    HTTPS=1

WORKDIR /app

COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip pip install -r requirements.txt

COPY . .

# The SQLite file and uploads live on /data, away from the app tree, so the
# volume never shadows code. Ownership is baked in here: Docker copies it onto
# a fresh named volume on first start.
RUN useradd -r -u 10001 btsp && mkdir -p /data/uploads && chown -R btsp:btsp /data
USER btsp

EXPOSE 8000
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8000", "--workers", "2"]
