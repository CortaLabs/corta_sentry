# MCP integration

CortaSentry includes an MCP `2025-11-25` stdio server built with the official Go SDK. It exposes bounded asset, observation, change, finding, job, rule, audit, scope-preview, and system-status tools plus tightly controlled mutations. The MCP process writes protocol messages only to stdout; diagnostics go to stderr.

MCP is an adapter over the same SQLite store, authorization engine, durable job manager, scanner, rules, and audit trail used by the server. It cannot execute SQL, commands, arbitrary scripts, token operations, unrestricted file reads, or arbitrary URL requests. `scan_create` still normalizes, allowlists, audits, rate-limits, and rechecks every IP/port at connection time.

## Safety gates

Read tools work by default. Mutations require:

```yaml
mcp:
  write_enabled: true
  active_tools_enabled: false
```

`active_tools_enabled` must also be true before `scan_create` can queue active network work. Normal `scope.active_enabled`, CIDR, port, public-target, host, and port budgets still apply. Tool annotations help clients request approval but are not authorization controls.

## Codex

Codex supports local stdio servers through `mcp_servers.<id>.command`, `args`, `cwd`, and `env`. Use absolute paths:

```toml
[mcp_servers.cortasentry]
command = "/usr/local/bin/cortasentry"
args = ["mcp"]
cwd = "/absolute/path/to/cortasentry-data"
startup_timeout_sec = 10
tool_timeout_sec = 60
required = false
default_tools_approval_mode = "writes"

[mcp_servers.cortasentry.env]
CORTASENTRY_CONFIG = "/absolute/path/to/cortasentry-data/cortasentry.yaml"
```

Or install through the CLI:

```sh
codex mcp add cortasentry \
  --env CORTASENTRY_CONFIG=/absolute/path/cortasentry.yaml \
  -- /usr/local/bin/cortasentry mcp
```

Current Codex configuration reference: <https://learn.chatgpt.com/docs/config-file/config-reference#configtoml>.

## Claude Code

```sh
claude mcp add cortasentry --scope local \
  --env CORTASENTRY_CONFIG=/absolute/path/cortasentry.yaml \
  -- /usr/local/bin/cortasentry mcp
```

Project-shared `.mcp.json` shape:

```json
{
  "mcpServers": {
    "cortasentry": {
      "type": "stdio",
      "command": "/usr/local/bin/cortasentry",
      "args": ["mcp"],
      "env": {"CORTASENTRY_CONFIG": "/absolute/path/cortasentry.yaml"}
    }
  }
}
```

Claude Code asks for approval before project-scoped MCP servers. Current Anthropic documentation: <https://docs.anthropic.com/en/docs/claude-code/mcp>.

## Exposed tools

Read-only: `system_status`, `scope_preview`, `assets_list`, `asset_get`, `observations_list`, `changes_list`, `findings_list`, `jobs_list`, `job_get`, `audit_list`, `rules_list`, `rules_validate`.

Gated mutations: `scan_create`, `job_cancel`, `rules_reload`, `asset_merge`, `finding_set_disposition`, `change_acknowledge`.

Resources: `cortasentry://status`, `cortasentry://scope`, and `cortasentry://assets/{asset_id}`.

`scan_create` requires an `idempotency_key`; agent retries with the same job type/key return the original durable job instead of creating duplicate work.

Protocol reference: <https://modelcontextprotocol.io/specification/2025-11-25>. Official Go SDK: <https://github.com/modelcontextprotocol/go-sdk>.
