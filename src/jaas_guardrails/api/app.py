from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI

from jaas_guardrails.api.routes import router
from jaas_guardrails.catalog_loader import DEFAULT_CATALOG_DIR, load_catalog
from jaas_guardrails.models import GuardrailDefinition


def create_app(
    *, catalog: list[GuardrailDefinition] | None = None, catalog_dir: Path = DEFAULT_CATALOG_DIR
) -> FastAPI:
    app = FastAPI(
        title="jaas-guardrails",
        version="2.1.0",
        description="Standalone publish-time content-safety scanning service.",
    )
    # Fails fast, loudly, at startup — not on the first request — if the
    # catalog is missing/malformed.
    app.state.catalog = catalog if catalog is not None else load_catalog(catalog_dir)
    app.include_router(router)
    return app


app = create_app()
