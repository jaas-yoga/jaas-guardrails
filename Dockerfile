FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml uv.lock ./
COPY src/ ./src/
COPY catalog/ ./catalog/
COPY schema/ ./schema/
COPY README.md ./

# Plain `uv sync` (no --extra dev) already excludes pytest/ruff — matches
# this project's dev-tooling convention. `--frozen` uses the committed
# uv.lock as-is rather than re-resolving, so the image gets the exact
# versions tested in CI.
RUN uv sync --frozen

ENV JAAS_GUARDRAILS_HOST=0.0.0.0
ENV JAAS_GUARDRAILS_PORT=8028
EXPOSE 8028

CMD ["uv", "run", "jaas-guardrails"]
