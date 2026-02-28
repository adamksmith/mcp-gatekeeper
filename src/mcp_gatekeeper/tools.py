"""MCP Gatekeeper tool definitions."""

from __future__ import annotations

import json
from typing import Any

from fastmcp import FastMCP

from .vault_client import VaultClient


def register_tools(mcp: FastMCP, client: VaultClient) -> None:
    """Register all gatekeeper tools on the FastMCP server."""

    @mcp.tool()
    async def authenticate() -> str:
        """Pre-authenticate to obtain a read-only token via Duo push.

        Normally you don't need to call this explicitly — read and list
        operations will auto-trigger authentication if no valid token
        exists. Use this tool when you want to authenticate proactively
        (e.g. at session start) rather than on first read.

        Triggers a Duo push notification. Blocks until approved/denied/timeout.
        On success, an RO token is held for ~4 hours.
        """
        try:
            return await client.authenticate()
        except Exception as e:
            return f"Authentication failed: {e}"

    @mcp.tool()
    async def read_secret(path: str) -> str:
        """Read a KV v2 secret by path.

        If no valid token exists, a Duo push is automatically triggered
        to obtain one before reading. Uses the RW token if held.

        Args:
            path: Secret path relative to the KV v2 mount (e.g. "claude/config")
        """
        try:
            data = await client.read_secret(path)
            return json.dumps(data, indent=2)
        except Exception as e:
            return f"Error reading secret at '{path}': {e}"

    @mcp.tool()
    async def write_secret(path: str, data: dict[str, Any]) -> str:
        """Write or update a KV v2 secret.

        Requires a valid RW token. Unlike reads, writes do NOT auto-renew
        an expired token — you must explicitly call `escalate` first.
        This is intentional: RW is task-scoped consent with a 15min TTL.
        Each write task requires a conscious escalation decision.

        Args:
            path: Secret path relative to the KV v2 mount (e.g. "claude/config")
            data: Key-value pairs to write
        """
        try:
            result = await client.write_secret(path, data)
            version = result.get("data", {}).get("version", "unknown")
            return f"Secret written to '{path}' (version {version})."
        except PermissionError as e:
            return str(e)
        except Exception as e:
            return f"Error writing secret at '{path}': {e}"

    @mcp.tool()
    async def list_secrets(path: str) -> str:
        """List secret keys at a given path.

        If no valid token exists, a Duo push is automatically triggered.

        Args:
            path: Path to list (e.g. "claude/" or "ssh/")
        """
        try:
            keys = await client.list_secrets(path)
            if not keys:
                return f"No secrets found at '{path}'."
            return json.dumps(keys, indent=2)
        except Exception as e:
            return f"Error listing secrets at '{path}': {e}"

    @mcp.tool()
    async def escalate() -> str:
        """Escalate from RO to RW via a second Duo push.

        If the RO token is expired, it is automatically renewed first
        (one Duo push), then a second push fires for the RW escalation.

        On success, an RW token is held for ~15 minutes.
        """
        try:
            return await client.escalate()
        except Exception as e:
            return f"Escalation failed: {e}"

    @mcp.tool()
    async def token_status() -> str:
        """Check current access tier and token state.

        Returns the current tier (no_access / ro / rw), whether each
        token is held, and remaining TTL for active tokens.
        """
        status = client.token_status()
        return json.dumps(status, indent=2)
