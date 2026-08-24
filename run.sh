#!/usr/bin/env bash
# Runs the guardrails service standalone, independent of any caller.
#
#   ./run.sh              starts the service on 127.0.0.1:8028
#   JAAS_GUARDRAILS_PORT=9000 ./run.sh
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

export JAAS_GUARDRAILS_HOST="${JAAS_GUARDRAILS_HOST:-127.0.0.1}"
export JAAS_GUARDRAILS_PORT="${JAAS_GUARDRAILS_PORT:-8028}"

if ! command -v uv >/dev/null 2>&1; then
    echo "error: uv is required (https://docs.astral.sh/uv/)." >&2
    exit 1
fi

uv sync --quiet
echo "[jaas-guardrails] starting on http://${JAAS_GUARDRAILS_HOST}:${JAAS_GUARDRAILS_PORT} ..."
exec uv run jaas-guardrails
