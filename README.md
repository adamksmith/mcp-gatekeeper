# MCP Gatekeeper

Zero-standing-access token broker for AI coding agents. Sits between Claude Code (or any MCP client) and [OpenBao](https://openbao.org/) / HashiCorp Vault, ensuring no secrets are accessible without explicit human approval via hardware 2FA.

## The Problem

MCP servers inherit whatever access the host process has. Connect Claude Code to your infrastructure and it gets the same credentials you do — permanently, silently, for the entire session. There's no consent model, no escalation path, no timeout. The current MCP ecosystem gives you two options: full access or no access.

MCP Gatekeeper adds a third option: **earned access**, scoped by intent and bounded by time.

## How It Works

MCP Gatekeeper implements a three-tier access model where every tier transition requires a DUO push notification to your phone. The AI agent starts with nothing and must ask for what it needs.

```
┌─────────────┐   DUO push    ┌─────────────┐   DUO push    ┌─────────────┐
│  No Access   │─────────────▶│   Read-Only  │─────────────▶│  Read-Write  │
│  (default)   │  authenticate │   (4hr TTL)  │   escalate   │  (15min TTL) │
└─────────────┘               └─────────────┘               └─────────────┘
                                     ▲                              │
                                     │        expires (hard)        │
                                     │◀─────────────────────────────┘
                                     │      drops to RO, not No Access
                              auto-renews
                              on expiry (DUO push)
```

### Consent Model

**Session-scoped consent (RO):** "Yes, I'm working." Auto-renews transparently when the 4-hour TTL expires. You approved a work session — reads shouldn't interrupt your flow.

**Task-scoped consent (RW):** "Yes, do this dangerous thing." Hard 15-minute TTL. When it expires, the agent drops back to read-only and must explicitly re-escalate. Every write task requires a conscious approval decision.

### Token Hierarchy

No permanent tokens. No cached credentials. Three tokens, three policies, each with only enough access to reach the next step:

1. **Bootstrap token** — Injected by Vault Secrets Operator (VSO). Can *only* read `secret/data/claude/ro-login`. Effectively inert without your phone.
2. **RO token** — Obtained via `claude-ro` userpass login + DUO push. Can read secrets and read `secret/data/claude/rw-login` to enable escalation.
3. **RW token** — Obtained via `claude-rw` userpass login + second DUO push. Can read and write secrets within scoped paths.

Even if the bootstrap token is compromised, an attacker can only *request* authentication. The DUO push goes to your phone. A compromised token becomes an alert system, not a silent exfiltration vector.

## Tools

MCP Gatekeeper exposes six tools to the AI agent:

| Tool | Requires | Description |
|------|----------|-------------|
| `authenticate` | Nothing | Trigger DUO push to obtain RO token (4hr). Reads auto-trigger this, so explicit use is optional. |
| `escalate` | RO | Trigger second DUO push to obtain RW token (15min). Required before any write. |
| `read_secret` | RO+ | Read a KV v2 secret. Auto-renews expired RO token. |
| `write_secret` | RW | Write a KV v2 secret. **No auto-renewal** — explicit escalation required. |
| `list_secrets` | RO+ | List secret keys at a path. Auto-renews expired RO token. |
| `token_status` | Nothing | Report current tier and remaining TTL for held tokens. |

## Prerequisites

- **OpenBao or HashiCorp Vault** with KV v2 secrets engine
- **DUO MFA** configured as an auth method enforcement on the Vault instance
- **Two userpass accounts** (`claude-ro`, `claude-rw`) with DUO MFA enforcement
- **Three policies** scoping each token tier's access
- **Vault Secrets Operator** (optional, for Kubernetes bootstrap token injection)

## Configuration

Two environment variables:

| Variable | Description |
|----------|-------------|
| `VAULT_ADDR` | OpenBao/Vault API address (e.g., `https://vault.example.com`) |
| `VAULT_TOKEN` | Bootstrap token — minimal policy, can only read userpass credentials |

## Deployment

### Kubernetes (recommended)

Deploy as a pod in a dedicated AI namespace with the bootstrap token injected via VSO:

```bash
docker build -t mcp-gatekeeper:latest .
# Push to your registry, deploy with your K8s manifests
```

The Dockerfile runs as a non-root user (`mcpuser`) and uses a multi-stage build with [uv](https://github.com/astral-sh/uv) for fast, reproducible installs.

### Local Development

```bash
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="hvs.bootstrap-token-here"
fastmcp run fastmcp.json
```

## Design Principles

**Invisible, not forbidden.** Don't give the agent the option to be dumb. If Claude Code can see VSO pods, it will try to extract secrets from them instead of using the API. Hide infrastructure entirely rather than returning 403s that invite retry loops.

**Every failure mode defaults to no access.** DUO timeout → no token. Token expiry → no access. Network partition → nothing executes. Pod crash → session ends. There is no state where a failure grants more access than was intended.

**DUO lives server-side.** The 2FA gate is in the MCP server infrastructure, not the agent's prompt or context window. The agent can't see it, reason about it, or engineer around it. From its perspective: call the tool, either get a token or don't.

**Design for compromise.** Assume the OAuth/OIDC stack gets compromised. What's the blast radius? With Gatekeeper, a compromised auth flow can only *request* tokens — DUO push approval still goes to your physical device. The architecture treats every layer as already breached and asks "what's the worst that can happen?"

## Project Structure

```
mcp-gatekeeper/
├── src/mcp_gatekeeper/
│   ├── __init__.py
│   ├── __main__.py        # Entrypoint, env config, FastMCP server init
│   ├── tools.py           # Six MCP tool definitions
│   └── vault_client.py    # OpenBao HTTP client, token lifecycle, DUO flows
├── Dockerfile             # Multi-stage build (uv + python:3.13-slim)
├── fastmcp.json           # FastMCP server configuration
└── pyproject.toml         # Python 3.13, fastmcp + httpx
```

## Related Projects

- **[ha-mcp-guardian](https://git.adamksmith.xyz/adamksmith/ha-mcp-guardian)** — Companion project applying the same zero-trust patterns to Home Assistant entity control. Because "AI should be able to read your thermostat" and "AI should be able to unlock your front door" are very different statements.

## Status

🚧 **Active development.** The token brokering architecture is solid but OpenBao policy configuration, K8s manifests, and integration tests are in progress.

## License

MIT
