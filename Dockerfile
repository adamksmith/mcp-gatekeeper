# --- Build stage: install dependencies with uv ---
FROM ghcr.io/astral-sh/uv:0.9-python3.13-trixie-slim AS builder

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

COPY pyproject.toml ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-install-project --no-dev

COPY src/ ./src/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-dev

# --- Runtime stage ---
FROM python:3.13-slim

RUN groupadd -r mcpuser && useradd -r -g mcpuser -m mcpuser

WORKDIR /app

COPY --chown=mcpuser:mcpuser --from=builder /app/.venv /app/.venv
COPY --chown=mcpuser:mcpuser --from=builder /app/src /app/src
COPY --chown=mcpuser:mcpuser fastmcp.json ./

USER mcpuser

ENV PATH="/app/.venv/bin:$PATH"
ENV VAULT_ADDR="" \
    VAULT_TOKEN=""

CMD ["fastmcp", "run", "fastmcp.json"]
