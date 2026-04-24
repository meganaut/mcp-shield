# MCPShield

**MCP Governance Gateway**

MCPShield is an open source, self-hostable governance gateway for the Model Context Protocol. It sits between any MCP-compatible AI agent and the external tools and services that agent is permitted to use — enforcing access policies, scanning for sensitive data, and logging every operation.

MCPShield works with any MCP-compatible client. It makes no assumptions about which LLM or agent runtime is in use.

## The problem

MCP access is currently binary: an agent is connected to a service or it is not. There is no way to say that an agent may read email but not send, or that an automated agent may create calendar events but not delete them, or that tool responses must be scanned for credentials before entering the agent's context. MCPShield provides this governance layer, self-hosted in your own infrastructure.

## How it works

```
MCP-compatible agent (any client)
        |
        |  MCP protocol
        |
  [MCPShield Gateway]
        |-- Policy Engine      deny by default, per-tool permissions
        |-- DLP Pipeline       scan params + responses, redact sensitive values
        |-- Audit Logger       every call logged, allowed or denied
        |-- Credential Vault   OAuth tokens encrypted at rest, never exposed to agent
        |-- OAuth Server       issues tokens to agents
        |-- Web UI             management dashboard
        |
        |  Outbound HTTPS
        |
  Gmail API   Google Calendar API   Slack API   Any OAuth MCP Server
```

The agent connects to MCPShield as if it were a single MCP server. MCPShield proxies permitted tool calls to the appropriate downstream service using stored credentials — the agent never handles OAuth tokens directly.

## Roadmap

### Desktop edition (current focus)

A single-user, locally-run edition for developers and homelab users who want governed MCP access for their own agents.

- Register any OAuth-backed MCP server as an integration
- Configure which tools each agent is permitted to call, with optional parameter constraints
- Credential vault — OAuth tokens encrypted at rest, never returned to the agent
- DLP scanning — inbound parameters and outbound responses scanned for secrets and sensitive patterns, detected values redacted automatically
- Agent profiles — each agent authenticates via OAuth client credentials and has its own permission set
- Meta-tools — agents can discover available integrations, check connection status, and initiate OAuth flows from within a conversation
- Structured audit logging
- Single binary, no external dependencies

### Enterprise edition (future)

A multi-user, organisation-scale edition built on the same core.

- Multi-user with role-based access control
- SSO / external IDP integration
- PostgreSQL backend
- Policy-as-code for GitOps workflows
- Compliance presets and advanced DLP
- Kubernetes deployment

## Tech stack

| Component | Technology |
|-----------|------------|
| Gateway core | Rust, Axum, Tokio |
| Web UI | HTMX, Askama (server-rendered, no JS framework) |
| Database | SQLite via sqlx |
| Credential encryption | AES-256-GCM |
| TLS | rustls |
| Static assets | Embedded via rust-embed |

## Status

Early development. Not ready for use.

## Licence

Apache 2.0 — see [LICENSE](LICENSE).

Copyright 2026 Emil Levy (Emil Levy Advisory Pty Ltd)
