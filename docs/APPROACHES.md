# Three Approaches + Critical Evaluation: MCP Deployment (404 / Session / ngrok)

This document captures three distinct approaches to solving the deployment/session/404 issue, plus a harsh critical evaluation and a single recommended path.

---

## Approach A: Optimize Current Stack (Docker + ngrok) or Drop Docker

**Subagent A’s premise:** The problem is operational and tooling choice, not the protocol. Fix at the edge, simplify ops.

### A1. Keep Docker + ngrok, but tighten the loop
- **What:** Keep `streamable-http` in Docker, expose via ngrok. Rely on the **existing middleware** (pre-buffer body + retry without session id) so the client **never** sees 404.
- **Rebuild:** On any code change, rebuild and restart: `docker compose build --no-cache usgs-mcp && docker compose up -d usgs-mcp`. Document this and add a one-liner script.
- **ngrok:** Keep using ngrok; update `MCP_ALLOWED_HOSTS` when the ngrok subdomain changes.
- **Pros:** No new components; 404 is already fixed in code; Cursor/remote clients work.
- **Cons:** Docker adds a rebuild step for code changes; ngrok URL changes unless you use a reserved domain.

### A2. Drop Docker for local/dev; use process + ngrok
- **What:** Run the server as a normal process (e.g. `uv run python main.py --transport streamable-http --host 0.0.0.0 --port 8000`), optionally under systemd/supervisor. Expose with ngrok to the internet.
- **Pros:** No image rebuild; edit code and restart process; simpler debugging.
- **Cons:** No container isolation; you manage Python/env and restarts yourself; less “production-style” if you later move to K8s.

**Approach A verdict:** Either keep Docker and accept rebuilds, or drop Docker for simplicity. ngrok stays in both cases.

---

## Approach B: MCP Gateway / Registry

**Subagent B’s premise:** Put a gateway in front so routing, TLS, and “session” handling live in one place; the MCP server stays dumb and stateless behind it.

### What a “gateway” could do
- **Reverse proxy:** Caddy or Traefik in front of one or more MCP server instances. TLS termination, optional basic auth or JWT at the proxy.
- **Session affinity:** If the gateway sticks a client to a backend (e.g. by `mcp-session-id` or cookie), you could keep stateful streamable-http behind it. Requires sticky sessions and care when backends restart (same 404-on-restart issue unless the gateway rewrites or strips session id for unknown backends).
- **Registry:** A separate service that lists “available MCP servers” (URLs, names). Cursor or other clients would point at the registry or at a single gateway URL that routes by path or header to different MCP backends. No standard MCP “registry” protocol is assumed here; it’s a custom or minimal discovery layer.

### ngrok
- ngrok can expose the **gateway** (e.g. Caddy). One public URL; gateway routes to MCP server(s) on localhost or internal network.

### Pros
- Single entry point; can add more MCP servers later behind the same gateway.
- TLS and auth can be centralized.

### Cons
- More moving parts (proxy config, optional registry).
- Session affinity does **not** remove the “stale session id after restart” problem; you’d still need the same “retry without session id” or stateless behavior behind the gateway.
- Overkill if you only ever have one MCP server (USGS).

**Approach B verdict:** Reasonable for multi-server or enterprise; for a single USGS MCP server it adds complexity without solving the root cause (session lifecycle).

---

## Approach C: Change the Approach — Stateless HTTP or SSE

**Subagent C’s premise:** The root cause is **stateful session lookup** that returns 404 for unknown session ids. Remove session state for remote access so 404 cannot happen.

### C1. Streamable HTTP in **stateless** mode (recommended)
- **What:** The MCP Python SDK’s `StreamableHTTPSessionManager` supports `stateless=True`. Every request gets a **new** transport; no session id lookup, so **no 404** for “session not found.”
- **How:** Use FastMCP with `stateless_http=True` (or equivalent env if the SDK reads it). Our custom “retry on 404” middleware becomes unnecessary; we can remove it.
- **Trade-off:** Clients cannot reuse a long-lived session across requests; each request is independent. For Cursor and typical “call tools a few times” usage, this is acceptable and often simpler.
- **ngrok:** Unchanged; still expose the same `POST /mcp` endpoint via ngrok.
- **Docker:** Optional; can keep or drop. Stateless works the same in both.

### C2. Switch transport to SSE
- **What:** Run with `--transport sse`. Endpoints: `GET /sse`, `POST /messages`. Different URL shape; Cursor would need to point at the base URL (and support SSE MCP client).
- **Pros:** SSE is a different lifecycle (connection-oriented); some clients may handle it well.
- **Cons:** Cursor’s remote MCP config often expects a single URL (e.g. `https://.../mcp`); SSE uses two endpoints and a different flow. May not fit Cursor’s “URL + headers” model as cleanly as streamable-http.

### C3. stdio locally + tunnel only when needed
- **What:** Run MCP as stdio for Cursor when both are on the same machine; use ngrok only for remote testing or Inspector.
- **Pros:** No session/404 issues for stdio; simplest locally.
- **Cons:** Doesn’t help “expose to internet” for Cursor on another machine; that still needs HTTP (streamable-http or SSE) + ngrok.

**Approach C verdict:** **C1 (stateless streamable-http)** is the cleanest fix: it removes the condition that causes 404 and simplifies the server. ngrok and optional Docker still work.

---

## Fourth “Subagent”: Brutal Critic and Decision

### Critic’s take

- **Approach A:** The middleware fix (pre-buffer + retry) is correct and already ensures **no 404 to the client**. So the “issue we have been facing” is already solved in code. What’s left is ops: rebuild Docker when you change code, or drop Docker and run the process. A is **valid but reactive**: we’re papering over “session not found” by retrying without session id. It works, but the server is still stateful and the retry path is non-trivial (body buffering, two app calls).

- **Approach B:** A gateway/registry is **not** the best solution for “no 404.” It doesn’t remove session state from the MCP server; it only adds another layer. Sticky routing can make restarts even more confusing (client stuck to an old backend). Only choose B if you have multiple MCP servers or need a single TLS/auth front door for many services. For one USGS server, it’s **overkill and doesn’t fix the root cause**.

- **Approach C:** **C1 (stateless streamable-http)** is the only option that **eliminates the root cause**: there are no sessions, so there is no “session not found” and no 404 from the session manager. The SDK already supports it; we just enable it and can **remove** the 404-retry middleware. Fewer branches, easier to reason about, same ngrok story. C2 (SSE) and C3 (stdio) don’t improve the “expose via ngrok” case as clearly as C1.

### Decision

- **Implement Approach C1:** Run streamable-http in **stateless** mode and remove the “retry on 404” middleware. Keep ngrok (and optional Docker) as-is.
- **Optional:** Document Approach A (Docker rebuild or run without Docker) for teams that prefer to keep stateful mode and rely on the current middleware.
- **Reject Approach B** for this single-server use case.

---

## Summary Table

| Approach | Fixes 404? | ngrok? | Docker? | Complexity | Best for |
|----------|------------|--------|---------|------------|----------|
| A: Optimize current stack | Yes (via middleware) | Yes | Optional | Low | “Don’t change much” |
| B: Gateway/Registry | No (adds layer only) | Yes (in front) | Optional | High | Multi-server / central TLS |
| **C1: Stateless HTTP** | **Yes (root cause)** | **Yes** | **Optional** | **Lowest** | **Single server, remote access** |

**Implementation choice:** C1 (stateless streamable-http) + keep ngrok; remove 404-retry middleware; document A and B in this file for reference.
