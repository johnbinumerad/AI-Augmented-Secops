#!/bin/sh
# Container entrypoint: `api` seeds missing stores then starts the API;
# `dashboard` starts the Streamlit Dashboard.
set -eu

SEED_TIMEOUT_SECONDS=120

case "${1:-api}" in
  api)
    # Seed only stores that do not exist yet (Requirements 11.4, 11.5).
    # Exit non-zero (and never start the API) when seeding fails or times out.
    status=0
    timeout "${SEED_TIMEOUT_SECONDS}" python /app/data/seed_findings.py --only-missing || status=$?
    if [ "${status}" -ne 0 ]; then
      if [ "${status}" -eq 124 ]; then
        echo "entrypoint: seeding timed out after ${SEED_TIMEOUT_SECONDS}s" >&2
      else
        echo "entrypoint: seeding failed (exit ${status}); stores: DB_PATH=${DB_PATH:-unset} RUNBOOK_STORE_PATH=${RUNBOOK_STORE_PATH:-unset}" >&2
      fi
      exit 1
    fi
    exec uvicorn src.api:app --host 0.0.0.0 --port 8000
    ;;
  dashboard)
    exec streamlit run src/app.py \
      --server.address 0.0.0.0 \
      --server.port 8501 \
      --server.headless true \
      --browser.gatherUsageStats false
    ;;
  *)
    exec "$@"
    ;;
esac
