"""Entry point: `python -m jaas_guardrails` or the `jaas-guardrails` console
script. Reads JAAS_GUARDRAILS_HOST/JAAS_GUARDRAILS_PORT, defaults chosen to
not collide with jaas_skills' own API (8027) or web (3027) ports."""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    host = os.environ.get("JAAS_GUARDRAILS_HOST", "127.0.0.1")
    port = int(os.environ.get("JAAS_GUARDRAILS_PORT", "8028"))
    uvicorn.run("jaas_guardrails.api.app:app", host=host, port=port)


if __name__ == "__main__":
    main()
