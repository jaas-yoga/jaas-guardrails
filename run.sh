#!/usr/bin/env bash
# Runs the guardrails service standalone, independent of any caller.
#
#   ./run.sh              starts the service on 127.0.0.1:8028
#   RUNE_GUARDRAILS_PORT=9000 ./run.sh
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

export RUNE_GUARDRAILS_HOST="${RUNE_GUARDRAILS_HOST:-127.0.0.1}"
export RUNE_GUARDRAILS_PORT="${RUNE_GUARDRAILS_PORT:-8028}"

if ! command -v uv >/dev/null 2>&1; then
    echo "error: uv is required (https://docs.astral.sh/uv/)." >&2
    exit 1
fi

uv sync --quiet
echo "[rune-guardrails] starting on http://${RUNE_GUARDRAILS_HOST}:${RUNE_GUARDRAILS_PORT} ..."
exec uv run rune-guardrails
