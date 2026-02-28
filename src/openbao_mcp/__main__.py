"""OpenBao MCP Server entrypoint."""

from __future__ import annotations

import os
import sys

from fastmcp import FastMCP

from .vault_client import VaultClient
from .tools import register_tools

_server: FastMCP | None = None


def _get_server() -> FastMCP:
    global _server
    if _server is not None:
        return _server

    vault_addr = os.environ.get("VAULT_ADDR", "")
    bootstrap_token = os.environ.get("VAULT_TOKEN", "")

    if not vault_addr or not bootstrap_token:
        print(
            "ERROR: VAULT_ADDR and VAULT_TOKEN environment variables are required.\n"
            "VAULT_TOKEN should be the bootstrap token (minimal permissions to "
            "read userpass credentials for DUO-gated auth flows).",
            file=sys.stderr,
        )
        sys.exit(1)

    client = VaultClient(addr=vault_addr, bootstrap_token=bootstrap_token)

    _server = FastMCP(name="openbao-mcp", version="0.1.0")
    register_tools(_server, client)

    return _server


class _DeferredMCP:
    """Proxy that lazily creates the FastMCP server on first attribute access."""

    def __getattr__(self, name: str):
        return getattr(_get_server(), name)


mcp = _DeferredMCP()
