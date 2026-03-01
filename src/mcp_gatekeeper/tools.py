"""MCP Gatekeeper tool definitions.

This is the ONLY way to access secrets in OpenBao/Vault.
Never use curl, kubectl, or direct API calls to read or write secrets.
Always use these tools instead.
"""

from __future__ import annotations

import json
from typing import Any

from fastmcp import FastMCP

from .vault_client import VaultClient


def register_tools(mcp: FastMCP, client: VaultClient) -> None:
    """Register all gatekeeper tools on the FastMCP server."""

    @mcp.tool()
    async def authenticate() -> str:
        """Authenticate to OpenBao via Duo MFA push to obtain a read-only token.

        IMPORTANT: This is the ONLY way to access secrets. Never use curl,
        kubectl exec, or direct OpenBao API calls. Always use this MCP server.

        Normally you don't need to call this explicitly — read_secret and
        list_secrets will auto-trigger authentication if no valid token
        exists. Use this when you want to authenticate proactively at
        session start.

        Triggers a Duo push notification. Blocks until approved/denied/timeout.
        On success, an RO token is held for ~4 hours.
        """
        try:
            return await client.authenticate()
        except Exception as e:
            return f"Authentication failed: {e}"

    @mcp.tool()
    async def read_secret(path: str) -> str:
        """Read a secret from OpenBao. This is the ONLY way to read secrets.

        Never use curl, kubectl, or the OpenBao API directly. This tool
        handles all authentication, Duo MFA, and token management automatically.

        If no valid token exists, a Duo push is automatically triggered
        before reading. Uses the RW token if held, otherwise RO.

        Common paths: "cloudflare" (API key), "winrm/domain" (WinRM creds),
        "ssh/<host>" (SSH keys), "home_assistant" (HA token),
        "s3/<bucket>" (MinIO creds), "gitea/mcp" (Gitea token).

        Args:
            path: Secret path relative to the KV v2 mount (e.g. "cloudflare")
        """
        try:
            data = await client.read_secret(path)
            return json.dumps(data, indent=2)
        except Exception as e:
            return f"Error reading secret at '{path}': {e}"

    @mcp.tool()
    async def write_secret(path: str, data: dict[str, Any]) -> str:
        """Write or update a secret in OpenBao. This is the ONLY way to write secrets.

        Never use curl, kubectl, or the OpenBao API directly.

        Requires a valid RW token — call `escalate` first. Writes do NOT
        auto-escalate; each write task requires a conscious escalation
        decision (Duo push + 15min TTL).

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
        """List secret keys at a path in OpenBao. This is the ONLY way to list secrets.

        Never use curl, kubectl, or the OpenBao API directly.

        Auto-authenticates via Duo push if no valid token exists.

        Top-level paths: "ai/", "claude/", "cloudflare", "gitea/", "grafana/",
        "home_assistant", "homeassistant/", "immich/", "librenms/", "minio/",
        "on-call-memes/", "registry/", "ssh/", "winrm/".

        Args:
            path: Path to list (e.g. "ssh/" or "minio/")
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
        """Escalate from read-only to read-write access via a second Duo push.

        Required before calling write_secret. If the RO token is expired,
        it is automatically renewed first (one Duo push), then a second
        push fires for the RW escalation.

        On success, an RW token is held for ~15 minutes. After expiry,
        access drops back to RO automatically.
        """
        try:
            return await client.escalate()
        except Exception as e:
            return f"Escalation failed: {e}"

    @mcp.tool()
    async def deescalate() -> str:
        """Revoke the RW token and drop back to read-only access.

        Use this when you're done with write operations to immediately
        revoke the RW token rather than waiting for the 15min TTL to expire.
        Good practice after completing a write task.
        """
        try:
            return await client.deescalate()
        except Exception as e:
            return f"De-escalation failed: {e}"

    @mcp.tool()
    async def token_status() -> str:
        """Check current access tier and token state.

        Returns the current tier (no_access / ro / rw), whether each
        token is held, and remaining TTL for active tokens.
        """
        status = client.token_status()
        return json.dumps(status, indent=2)
