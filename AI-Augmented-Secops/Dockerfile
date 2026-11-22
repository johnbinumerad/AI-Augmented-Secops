# syntax=docker/dockerfile:1
# Single image for the API and the Dashboard (Requirements 11.2, 11.3).
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app \
    HF_HOME=/opt/hf-cache \
    SENTENCE_TRANSFORMERS_HOME=/opt/hf-cache \
    DB_PATH=/var/lib/triage/db/findings.duckdb \
    RUNBOOK_STORE_PATH=/var/lib/triage/runbooks/store \
    AUDIT_LOG_PATH=/var/lib/triage/audit/audit_logs.jsonl

WORKDIR /app

# Non-root user (UID 10001) and the directories that back the named volumes.
# Creating them here with the right owner makes fresh named volumes writable.
RUN groupadd --gid 10001 triage \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin triage \
    && mkdir -p /var/lib/triage/db /var/lib/triage/runbooks /var/lib/triage/audit /opt/hf-cache \
    && chown -R triage:triage /var/lib/triage /opt/hf-cache /app

COPY requirements.txt /app/requirements.txt

# Pinned dependencies, then the spaCy model from its explicit release wheel
# (`spacy download` is not used because it fails behind some TLS setups).
RUN pip install -r /app/requirements.txt \
    && pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl

# Pre-download the embedding model so the container runs without internet access.
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')" \
    && chown -R triage:triage /opt/hf-cache

COPY --chown=triage:triage src /app/src
COPY --chown=triage:triage data /app/data
COPY --chown=triage:triage docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod 0755 /app/docker-entrypoint.sh

ENV HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1

USER 10001:10001

EXPOSE 8000 8501

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["api"]
