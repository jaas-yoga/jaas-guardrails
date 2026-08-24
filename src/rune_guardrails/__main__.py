"""Entry point: `python -m rune_guardrails` or the `rune-guardrails` console
script. Reads RUNE_GUARDRAILS_HOST/RUNE_GUARDRAILS_PORT, defaults chosen to
not collide with rune_skills' own API (8027) or web (3027) ports."""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    host = os.environ.get("RUNE_GUARDRAILS_HOST", "127.0.0.1")
    port = int(os.environ.get("RUNE_GUARDRAILS_PORT", "8028"))
    uvicorn.run("rune_guardrails.api.app:app", host=host, port=port)


if __name__ == "__main__":
    main()
