# fencer CLI

A standalone Go CLI for the [Fencer](https://app.fencer.dev) security platform REST API.

## Layout and libraries

```
cli/
├── cmd/fencer/main.go      # binary entry point
├── internal/
│   ├── auth/               # OAuth PKCE flow, token store, Bearer transport
│   ├── config/             # base URL and config-dir constants
│   ├── cmd/                # cobra command and MCP adapters
│   └── operations/         # shared typed Fencer operations
└── api/
    └── client.go           # thin HTTP wrapper + resource types
```

The `cmd/<binary>/` entry point and `internal/` visibility boundary follow the conventions in
[golang-standards/project-layout](https://github.com/golang-standards/project-layout), which is the
closest thing Go has to a community standard layout (it is not official, but it is widely adopted).
One deliberate deviation: the hand-written REST client lives in `api/` rather than `internal/api/`
to signal that it could be extracted as a standalone SDK later.

**Libraries:**

- [`cobra`](https://github.com/spf13/cobra) — the de-facto standard for Go CLIs. Handles
  subcommands, flag inheritance, help generation, and shell completion. Used by kubectl, Hugo, and
  most of the Go ecosystem.
- [`viper`](https://github.com/spf13/viper) — config and environment variable management, integrates
  cleanly with cobra flags so `--org` and `FENCER_ORG` resolve from the same call.
- [`lipgloss`](https://github.com/charmbracelet/lipgloss) — declarative terminal styling from
  Charmbracelet. Used for column-aligned table output with bold headers; automatically degrades to
  plain text when `NO_COLOR` is set or output is not a TTY.

## Install

Customer-facing install, auth, MCP, and upgrade docs live at
[docs.fencer.dev/cli/installation](https://docs.fencer.dev/cli/installation).

```sh
curl -fsSL https://docs.fencer.dev/cli/install.sh | sh
```

For local development from this repository:

```sh
cd cli
make build          # produces ./build/fencer, defaults to the local dev domain
make build-prod VERSION=1.2.3  # production API URL; VERSION cannot be 0.0.0
```

## Usage

### Global flags

These work on every command:

| Flag                | Env          | Default        | Notes                                                |
| ------------------- | ------------ | -------------- | ---------------------------------------------------- |
| `--org <slug>`      | `FENCER_ORG` | —              | Required for every org-scoped command                |
| `--output, -o`      | —            | `table`        | `table` or `json`                                    |
| `--base-url <url>`  | —            | from token     | Override the API base URL                            |
| `--yes, -y`         | —            | `false`        | Skip confirmation prompts on write commands          |
| `--page <n>`        | —            | `1`            | List commands only; 1-indexed                        |
| `--page-size <n>`   | —            | `50`           | List commands only; max 1000                         |

Non-TTY callers without `--yes` error out on write commands rather than hanging on a prompt.

### Pagination and machine-readable output

Every list command (`org list`, `vuln list`, `detection list`, `asset list`, `scan list`,
`scan vulns`, `identity list`) takes `--page` and `--page-size`. Defaults are page `1` and
page size `50`. Values outside `page >= 1` and `1 <= page_size <= 1000` fail the command;
they are not clamped. CLI and MCP share these defaults through `internal/operations`.

`--output json` on a successful path always emits a single JSON document. List results use a
stable envelope:

```json
{
  "results": [],
  "pagination": {
    "page": 1,
    "page_size": 50,
    "count": 120,
    "total_pages": 3,
    "next_page": 2,
    "previous_page": null
  }
}
```

No-op mutations (for example unassigning an already-unassigned finding) also return JSON in
JSON mode, not a plain-text message. `scan diff` walks every page of new and resolved findings
and never truncates; use `scan vulns --new/--resolved` with `--page` when you only need a slice.

### Auth & org

```sh
fencer login                                         # PKCE browser flow — required first
fencer logout                                        # revoke the stored token
fencer org list                                      # list organizations
fencer org use <slug>                                # set default org for the session
```

### Vulnerabilities

```sh
fencer vuln list [filters...]                        # list vulnerabilities (paginated)
fencer vuln get <slug>                               # get a single vulnerability
fencer vuln assign <slug> --email <email>|--me       # assign to a user
fencer vuln unassign <slug>                          # clear assignee
fencer vuln ignore <slug> [--reason <enum>] [--notes <text>]
fencer vuln unignore <slug>
fencer vuln defer <slug> [--days 7|14|30|90] [--reason <enum>] [--notes <text>]
fencer vuln undefer <slug>
fencer vuln priority <slug> --level urgent|high|moderate|low|minimal
```

`vuln list` filters (all repeatable flags are server-side OR):

| Flag               | Type        | Notes                                                            |
| ------------------ | ----------- | ---------------------------------------------------------------- |
| `--severity`       | repeatable  | `critical`, `high`, `medium`, `low`, `info`                      |
| `--status`         | string      | e.g. `open`, `resolved`                                          |
| `--category`       | string      | Vulnerability category                                           |
| `--asset`          | repeatable  | Asset slug from the ASSET column, e.g. `ARES-AJ3`                |
| `--assignee`       | repeatable  | Email or `me`                                                    |
| `--has-assignee`   | bool        | Assigned (use `--has-assignee=false` for unassigned)             |
| `--priority`       | repeatable  | Priority level                                                   |
| `--live`           | bool        | In-production findings (use `--live=false` to invert)            |
| `--ignored`        | bool        | Ignored (use `--ignored=false` to invert)                        |
| `--deferred`       | bool        | Deferred (use `--deferred=false` to invert)                      |
| `--in-scope`       | bool        | In-scope (use `--in-scope=false` for out-of-scope)               |
| `--query` / `-q`   | string      | Text search over title, description, slug. Use for package/technology names — `--query celery` matches dependency findings titled `Vulnerable package: celery@…`. |
| `--order-by`       | string      | One of: `severity`, `priority_level`, `first_seen`, `category`, `title`, `status`, `asset_name`, `assignee`, `assignee_name`, `sla_deadline`, `id`. Prefix `-` for descending. |

Searching by package or technology name: use `--query <term>`. `--query` matches
title, description, and slug (case-insensitive substring). It does **not**
match asset names, PURLs, or CWE ids — use `--asset <slug>` for asset filtering.

`vuln ignore` / `vuln defer` `--reason` enum:
`false_positive | will_not_fix | acceptable_risk | duplicate | superseded | third_party_code | rule_disabled | no_fix_available`.

### Detections

```sh
fencer detection list [filters...]                   # list detections
fencer detection get <slug>                          # get a single detection
fencer detection assign <slug> --email <email>|--me
fencer detection unassign <slug>
fencer detection investigate <slug>                    # mark under investigation
fencer detection resolve <slug> --as false-positive|true-positive
fencer detection reopen <slug>                         # transition back to new
```

`detection list` filters:

| Flag             | Type        | Notes                                                            |
| ---------------- | ----------- | ---------------------------------------------------------------- |
| `--severity`     | repeatable  | `critical`, `high`, `medium`, `low`, `info`                      |
| `--status`       | string      | e.g. `new`, `under_investigation`, `resolved_*`                  |
| `--asset`        | repeatable  | Asset slug, e.g. `ARES-AJ3`                                      |
| `--assignee`     | repeatable  | Email or `me`                                                    |
| `--has-assignee` | bool        | Assigned (use `--has-assignee=false` for unassigned)             |
| `--detected-at`  | string      | Relative window: `24h`, `7d`, `30d`, `90d`, `365d`               |
| `--q`            | string      | Text search over description                                     |
| `--order-by`     | string      | One of: `severity`, `detected_at`, `title`, `asset`, `asset_name`, `status`, `assignee_name`, `confidence_label`. Prefix `-` for descending. |

### Assets & scans

```sh
fencer asset list [--kind <kind>] [--order-by <field>] [--top-level]
                                                     # SLUG column feeds `criticality` below
fencer asset criticality <slug> --score <0-100>      # set asset criticality
fencer scan list --asset <slug> [--branch <branch>]
                                                     # list scans for one asset
fencer scan get <slug>                               # scan detail (counts, trigger, timing)
fencer scan vulns <slug> [filters...]                # vulnerability snapshots for a scan
fencer scan diff <slug>                              # every new vs resolved finding (all pages)
```

`asset list` filters: `--kind <kind>`, `--order-by description|belongs_to|kind|provider|region`,
`--top-level` (only resources with no parent).

`scan list` filters: `--asset <slug>` (required), `--branch <branch>`.

`scan vulns` filters: `--new`, `--resolved`, `--ignored` (each accepts `--flag` for true
or `--flag=false` for false; absent = no filter),
`--severity` (repeatable: `critical|high|medium|low|info`),
`--status`, `--category`, `--q`, `--order-by severity|title|first_seen|category|asset_name`.

### Identities

```sh
fencer identity list [filters...]                    # list identities
```

`identity list` filters: `--type`, `--status`, `--relationship`, `--needs-review`
(or `--needs-review=false`), `--has-owner` (or `--has-owner=false`), `--q`,
`--order-by display_name|primary_email|identity_type_display|identity_status_display|identity_relationship_display|first_seen_at|last_seen_at|needs_review`.

### MCP server

```sh
fencer mcp                                           # run an MCP server over stdio
```

`fencer mcp` turns the binary into a [Model Context Protocol](https://modelcontextprotocol.io)
server, so MCP clients (e.g. Claude Desktop) can query Fencer directly. It reuses the same
authenticated session as the rest of the CLI — run `fencer login` first. Tools match the
registered operations (`organizations.list`, `vulnerabilities.list`, `scans.diff`, write
actions, …). List tools take `page` / `page_size` and return the same `{results, pagination}`
envelope as CLI JSON. Org-scoped tools accept an optional `organization_slug`, falling back
to `--org` / `FENCER_ORG`. Write tools include MCP safety annotations; the CLI still prompts
unless `--yes` is passed.

Register it with an MCP client:

```json
{
  "mcpServers": {
    "fencer": { "command": "fencer", "args": ["mcp"], "env": { "FENCER_ORG": "<slug>" } }
  }
}
```

## Releases

Production releases are versioned binaries for linux, darwin, and windows on `amd64`/`arm64`. Each
release is cosign keyless-signed (`SHA256SUMS.sig`/`.pem`) and ships SPDX SBOMs, `LICENSE`, and
`THIRD_PARTY_NOTICES`, as tarballs/zip, `.deb`/`.rpm`, and a Homebrew cask.

Install and upgrade instructions: [docs.fencer.dev/cli/installation](https://docs.fencer.dev/cli/installation).

## Config

Tokens and base URL are stored at `~/.config/fencer/tokens.json` (XDG: `$XDG_CONFIG_HOME/fencer/`).
Credentials are bound to the origin used at `fencer login`. `--base-url` on other commands is
accepted only when it matches that origin; switching environments requires logging in again.
Production origins must use HTTPS. HTTP is allowed only for local development hosts
(`localhost`, `127.0.0.1`, `::1`, `app.fencer.home`).

Before the first login (no stored token yet), the base URL falls back to `config.DefaultBaseURL`,
which is compiled in at build time:

- `make build` (and plain `go build`/`go install`) → `http://app.fencer.home` (local dev)
- `make build-prod VERSION=<semver>` → `https://app.fencer.dev` (production). `VERSION=0.0.0` is rejected.

Once logged in, the base URL from the stored token is used regardless of what the binary was
compiled with — the compiled default only matters for that first `fencer login`.

`fencer version` and `fencer --version` print the build identity.
