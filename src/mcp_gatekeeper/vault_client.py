"""OpenBao HTTP client with zero-standing-access token management.

Token lifecycle:
  No Access (default) → authenticate (DUO push) → RO (4hr TTL)
  RO → escalate (second DUO push) → RW (15min TTL)
  RW expires → drops to RO (explicit re-escalation required)
  RO expires → auto re-auth (DUO push) → RO

RO auto-renews transparently (session-scoped consent — "yes I'm working").
RW requires explicit re-escalation (task-scoped consent — "yes do this
dangerous thing"). The 15min TTL is a hard boundary, not a rolling window.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone

import httpx

DUO_METHOD_ID = "a573c36b-3cb4-4ee1-b947-bc1a81bb674a"


class VaultClient:
    """Wraps the OpenBao HTTP API with zero-standing-access token brokering.

    Starts with no tokens. A bootstrap token (from VSO) is used only to
    read the userpass credentials needed to trigger DUO-gated auth flows.

    RO renewal is transparent — expired RO tokens are re-obtained via
    DUO push automatically on read/list. RW tokens are NOT auto-renewed;
    expired RW means writes fail until the user explicitly calls escalate.
    """

    def __init__(self, addr: str, bootstrap_token: str) -> None:
        self.addr = addr.rstrip("/")
        self._bootstrap_token = bootstrap_token
        self.ro_token: str | None = None
        self.ro_token_expiry: datetime | None = None
        self.rw_token: str | None = None
        self.rw_token_expiry: datetime | None = None
        self._http = httpx.AsyncClient(base_url=self.addr, timeout=120)

    # ── Token validity checks ────────────────────────────────────────

    def _has_valid_ro_token(self) -> bool:
        if not self.ro_token or not self.ro_token_expiry:
            return False
        if datetime.now(timezone.utc) >= self.ro_token_expiry:
            self.ro_token = None
            self.ro_token_expiry = None
            return False
        return True

    def _has_valid_rw_token(self) -> bool:
        if not self.rw_token or not self.rw_token_expiry:
            return False
        if datetime.now(timezone.utc) >= self.rw_token_expiry:
            self.rw_token = None
            self.rw_token_expiry = None
            return False
        return True

    @property
    def best_token(self) -> str | None:
        """Return the best available token, or None if unauthenticated."""
        if self._has_valid_rw_token():
            return self.rw_token
        if self._has_valid_ro_token():
            return self.ro_token
        return None

    def _headers(self, token: str) -> dict[str, str]:
        return {"X-Vault-Token": token}

    # ── Transparent token renewal ────────────────────────────────────

    async def _ensure_ro_token(self) -> str:
        """Return a valid RO token, re-authenticating via DUO if expired.

        If no RO token has ever been obtained (first call), this will
        also trigger the initial DUO push.
        """
        if self._has_valid_ro_token():
            return self.ro_token

        print("[mcp-gatekeeper] RO token expired or missing, re-authenticating via DUO...", file=sys.stderr)
        await self.authenticate()
        return self.ro_token

    # ── KV v2 operations ─────────────────────────────────────────────

    async def read_secret(self, path: str) -> dict:
        """Read a KV v2 secret. Auto-renews RO token if expired."""
        token = await self._ensure_ro_token()
        resp = await self._http.get(
            f"/v1/secret/data/{path}",
            headers=self._headers(token),
        )
        resp.raise_for_status()
        body = resp.json()
        return body.get("data", {}).get("data", {})

    async def write_secret(self, path: str, data: dict) -> dict:
        """Write a KV v2 secret. Requires a valid RW token (no auto-renewal)."""
        if not self._has_valid_rw_token():
            raise PermissionError(
                "RW token expired or not held. Call `escalate` to obtain a "
                "new read-write token (requires Duo approval)."
            )
        resp = await self._http.post(
            f"/v1/secret/data/{path}",
            headers=self._headers(self.rw_token),
            json={"data": data},
        )
        resp.raise_for_status()
        return resp.json()

    async def list_secrets(self, path: str) -> list[str]:
        """List secret keys at a given path. Auto-renews RO token if expired."""
        token = await self._ensure_ro_token()
        resp = await self._http.request(
            "LIST",
            f"/v1/secret/metadata/{path}",
            headers=self._headers(token),
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        body = resp.json()
        return body.get("data", {}).get("keys", [])

    # ── DUO-gated authentication (No Access → RO) ───────────────────

    async def authenticate(self) -> str:
        """Obtain an RO token via DUO push.

        1. Fetch claude-ro password from KV using the bootstrap token
        2. Login via userpass to get an MFA request ID
        3. Validate MFA (triggers Duo push) → RO token (4hr TTL)
        """
        password_data = await self._read_with_token(
            "secret/data/claude/ro-login", self._bootstrap_token
        )
        password = password_data.get("password")
        if not password:
            raise RuntimeError(
                "Failed to retrieve claude-ro password from "
                "secret/claude/ro-login"
            )

        client_token, lease_duration = await self._userpass_duo_flow(
            "claude-ro", password
        )

        self.ro_token = client_token
        self.ro_token_expiry = datetime.now(timezone.utc) + timedelta(
            seconds=lease_duration
        )

        return (
            f"Authentication successful. RO token acquired with "
            f"{lease_duration}s TTL (expires {self.ro_token_expiry.isoformat()})."
        )

    # ── DUO-gated escalation (RO → RW) ──────────────────────────────

    async def escalate(self) -> str:
        """Obtain an RW token via a second DUO push.

        Ensures RO token is valid first (re-auths if needed), then:
        1. Fetch claude-rw password from KV using the RO token
        2. Login via userpass to get an MFA request ID
        3. Validate MFA (triggers Duo push) → RW token (15min TTL)
        """
        ro_token = await self._ensure_ro_token()

        password_data = await self._read_with_token(
            "secret/data/claude/rw-login", ro_token
        )
        password = password_data.get("password")
        if not password:
            raise RuntimeError(
                "Failed to retrieve claude-rw password from "
                "secret/claude/rw-login"
            )

        client_token, lease_duration = await self._userpass_duo_flow(
            "claude-rw", password
        )

        self.rw_token = client_token
        self.rw_token_expiry = datetime.now(timezone.utc) + timedelta(
            seconds=lease_duration
        )

        return (
            f"Escalation successful. RW token acquired with "
            f"{lease_duration}s TTL (expires {self.rw_token_expiry.isoformat()})."
        )

    # ── De-escalation (RW → RO) ────────────────────────────────────

    async def deescalate(self) -> str:
        """Revoke the RW token and drop back to RO.

        Calls the OpenBao token revoke-self endpoint to immediately
        invalidate the RW token rather than waiting for TTL expiry.
        """
        if not self._has_valid_rw_token():
            return "No active RW token to revoke. Current tier: " + (
                "ro" if self._has_valid_ro_token() else "no_access"
            )

        try:
            resp = await self._http.post(
                "/v1/auth/token/revoke-self",
                headers=self._headers(self.rw_token),
            )
            resp.raise_for_status()
        except Exception:
            pass  # best-effort revoke; clear local state regardless

        self.rw_token = None
        self.rw_token_expiry = None

        tier = "ro" if self._has_valid_ro_token() else "no_access"
        return f"RW token revoked. Dropped to {tier}."

    # ── Token status ─────────────────────────────────────────────────

    def token_status(self) -> dict:
        """Return current token state across all three tiers."""
        now = datetime.now(timezone.utc)
        status: dict = {"tier": "no_access"}

        if self._has_valid_ro_token():
            remaining = (self.ro_token_expiry - now).total_seconds()
            status["ro_token"] = True
            status["ro_token_remaining_seconds"] = int(remaining)
            status["ro_token_expiry"] = self.ro_token_expiry.isoformat()
            status["tier"] = "ro"
        else:
            status["ro_token"] = False

        if self._has_valid_rw_token():
            remaining = (self.rw_token_expiry - now).total_seconds()
            status["rw_token"] = True
            status["rw_token_remaining_seconds"] = int(remaining)
            status["rw_token_expiry"] = self.rw_token_expiry.isoformat()
            status["tier"] = "rw"
        else:
            status["rw_token"] = False

        return status

    # ── Internal helpers ─────────────────────────────────────────────

    async def _userpass_duo_flow(
        self, username: str, password: str
    ) -> tuple[str, int]:
        """Execute userpass login + DUO MFA validation. Returns (token, ttl)."""
        login_resp = await self._http.post(
            f"/v1/auth/userpass/login/{username}",
            json={"password": password},
        )
        login_resp.raise_for_status()
        login_body = login_resp.json()

        mfa_request_id = (
            login_body.get("auth", {})
            .get("mfa_requirement", {})
            .get("mfa_request_id")
        )
        if not mfa_request_id:
            raise RuntimeError(
                f"Userpass login for {username} did not return an MFA request ID. "
                f"Check that MFA enforcement is configured."
            )

        mfa_resp = await self._http.post(
            "/v1/sys/mfa/validate",
            headers=self._headers(self._bootstrap_token),
            json={
                "mfa_request_id": mfa_request_id,
                "mfa_payload": {DUO_METHOD_ID: []},
            },
        )
        mfa_resp.raise_for_status()
        mfa_body = mfa_resp.json()

        auth = mfa_body.get("auth", {})
        client_token = auth.get("client_token")
        lease_duration = auth.get("lease_duration", 900)

        if not client_token:
            raise RuntimeError(
                f"MFA validation for {username} succeeded but no token was returned."
            )

        return client_token, lease_duration

    async def _read_with_token(self, full_api_path: str, token: str) -> dict:
        """Read from a specific Vault API path with a specific token."""
        resp = await self._http.get(
            f"/v1/{full_api_path}",
            headers={"X-Vault-Token": token},
        )
        resp.raise_for_status()
        body = resp.json()
        return body.get("data", {}).get("data", {})
