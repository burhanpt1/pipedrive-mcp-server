# Pipedrive MCP Server for PT1

## Project Goal

Deploy a self-hosted Pipedrive MCP server on Render so the PT1 team (small VC firm, ~3-5 people) can connect Pipedrive to Claude via a custom connector in their Claude Team plan. The server needs to be publicly accessible with proper authentication.

## Decision: WillDent/pipedrive-mcp-server as the base

After auditing three Pipedrive MCP server repos, we chose **WillDent/pipedrive-mcp-server** (Node.js/TypeScript) as the deployment shell because:

- **Has JWT authentication** on the SSE endpoint (critical for public deployment)
- **Has rate limiting** via Bottleneck
- **Has a production Dockerfile** (multi-stage build, runs as non-root `node` user)
- **Has a health check endpoint** at `/health`
- **SSE transport works** with the MCP SDK's `SSEServerTransport`

Current limitation: it's **read-only** (16 tools — get/search/list only). Write tools will be added later.

### Repos evaluated

1. **Wirasm/pipedrive-mcp** (Python, ~38 tools, CRUD) — rejected because:
   - No authentication on SSE endpoint (anyone with the URL gets full CRM access)
   - Logging hardcoded to DEBUG (leaks API tokens in logs)
   - Feature flags broken on half the tools (deals, orgs use `@mcp.tool()` not the feature-gated `@tool()` decorator)
   - Rate limiting and retry logic configured but never implemented

2. **WillDent/pipedrive-mcp-server** (Node.js, 16 tools, read-only) — **selected**
   - JWT auth, rate limiting, Docker, health check
   - Uses official Pipedrive Node.js SDK (v1 API)
   - Has a hardcoded custom field key (`8f4b27fbd9dfc70d2296f23ce76987051ad7324e`) that needs removing

3. **iamsamuelfraga/mcp-pipedrive** (Node.js, ~223 tools, full CRUD) — best-engineered but:
   - stdio only (no SSE transport, no HTTP server)
   - No Dockerfile
   - Would need SSE transport added to deploy remotely
   - Best reference for future write tools: has proper rate limiting, retry with backoff, TTL caching, `PIPEDRIVE_READ_ONLY` mode, `PIPEDRIVE_TOOLSETS` filtering, API token via `x-api-token` header

## Hardening checklist before deployment

1. **Remove hardcoded custom field key** — `8f4b27fbd9dfc70d2296f23ce76987051ad7324e` in `src/index.ts` (lines ~308, ~411) is specific to the original author's Pipedrive instance
2. **Set up JWT auth** — configure `MCP_JWT_SECRET` and `MCP_JWT_TOKEN` env vars on Render
3. **Configure CORS** — currently set to `Access-Control-Allow-Origin: *`, should be tightened for production
4. **Review env vars for Render deployment**:
   - `PIPEDRIVE_API_TOKEN` — PT1's Pipedrive API token
   - `PIPEDRIVE_DOMAIN` — e.g. `pt1.pipedrive.com` (full domain, not just subdomain — this repo differs from Wirasm)
   - `MCP_TRANSPORT=sse`
   - `MCP_PORT=3000` (or whatever Render assigns)
   - `MCP_JWT_SECRET` — generate a strong secret
   - `MCP_JWT_TOKEN` — generate and sign a JWT for Claude to use
   - `PIPEDRIVE_RATE_LIMIT_MIN_TIME_MS=250`
   - `PIPEDRIVE_RATE_LIMIT_MAX_CONCURRENT=2`

## Architecture

```
Claude (claude.ai) 
  → Custom Connector (MCP over SSE)
    → Render Web Service (this server)
      → Pipedrive API v1
```

- Server is stateless — no database, no persistent storage
- Single shared Pipedrive API token for the whole team (no per-user Pipedrive auth)
- JWT protects the SSE endpoint so only Claude can connect

## Available tools (current, read-only)

- `get-users` — list all Pipedrive users/owners
- `get-deals` — filter deals by title, date, owner, stage, status, value range
- `get-deal` — get deal by ID with custom fields
- `get-deal-notes` — get notes for a deal
- `search-deals` — search deals by term
- `get-persons` / `get-person` / `search-persons`
- `get-organizations` / `get-organization` / `search-organizations`
- `get-pipelines` / `get-pipeline`
- `get-stages` — all stages across all pipelines
- `search-leads`
- `search-all` — cross-entity search

## Future work (medium-term)

Port write tools from iamsamuelfraga/mcp-pipedrive into this server:
- Deal create/update (most important for PT1's deal flow)
- Person/org create
- Activity create (for logging meetings, calls)
- Borrow iamsamuelfraga's patterns: retry logic with exponential backoff, TTL caching, `x-api-token` header auth, `PIPEDRIVE_READ_ONLY` flag, toolset filtering

## Tech stack

- Node.js 20 (Alpine)
- TypeScript
- `@modelcontextprotocol/sdk` for MCP server
- `pipedrive` (official SDK v22)
- `bottleneck` for rate limiting
- `jsonwebtoken` for JWT auth
- `zod` for input validation

## Commands

```bash
npm ci              # install deps
npm run build       # compile TypeScript
npm start           # run production server
npm run dev         # dev mode with tsx
```

## Deployment target

- **Platform:** Render (Web Service, Docker)
- **Instance:** Smallest paid tier (~$7/month)
- **Region:** EU (London) preferred for PT1
- **Auto-deploy:** from GitHub fork on push to main
