# USGS Publications Warehouse MCP Server

A security-hardened MCP server that exposes the [USGS Publications Warehouse API](https://pubs.usgs.gov/documentation/web_service_documentation) with input validation, rate limiting, audit logging, and secure HTTP client controls.

## What this repo includes

- Single MCP tool: `search_publications` — full-text, title, and index_id search with pagination
- Three transport modes: `stdio` (Claude Desktop/Cursor), `sse`, `streamable-http` (Docker/k8s)
- Security module (`security/`) — validation, rate limiting, audit logging, OTel tracing
- Docker image + Helm chart for production deployment on AWS EKS
- agentevals integration (`examples/`) — benchmark harness + golden eval set

## Quick start

```bash
# Install dependencies
uv sync

# Run locally (stdio — for Claude Desktop / Cursor)
uv run python main.py --transport stdio

# Run locally (HTTP — for testing with curl or the agent harness)
uv run python main.py --transport streamable-http --host 127.0.0.1 --port 8000

# Health check
curl http://localhost:8000/health
```

Copy `.env.example` to `.env` before running to configure rate limits, timeouts, and OTel export.

## MCP endpoints (HTTP transports)

| Endpoint | Transport |
|---|---|
| `POST /mcp` | streamable-http |
| `GET /sse` + `POST /messages` | sse |
| `GET /health` | both |

Initialize over HTTP:

```bash
curl -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"local-test","version":"1.0"}}}'
```

## Tool

`search_publications(query, title, index_id, page_size, page_number)`

- `query` — full-text keyword search (drops stopwords, combines plurals)
- `title` — exact substring match within publication title
- `index_id` — retrieve a specific publication by its USGS index ID (exclusive with query/title)
- `page_size` — 1–100, default 10
- `page_number` — 1-based, default 1

## Tests

```bash
uv run pytest                        # unit tests + 100% coverage on security.tool_registry
uv run pytest tests/test_api_integration.py  # real USGS API calls (requires internet)
```

## agentevals integration

Evaluate agent behavior from OTel traces — no re-execution required.

```bash
# Terminal 1 — MCP server
uv run python main.py --transport streamable-http --host 127.0.0.1 --port 8000

# Terminal 2 — agentevals live UI (optional)
agentevals serve --dev

# Terminal 3 — run 10 benchmark tasks and save traces
export OPENAI_API_KEY=sk-...
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
uv run python examples/agent_harness.py

# Evaluate offline
agentevals run examples/traces/*.json \
  --eval-set examples/eval_set_usgs.json \
  -m tool_trajectory_avg_score \
  -m response_match_score
```

See [`examples/README.md`](examples/README.md) for the full workflow, Kubernetes setup, and troubleshooting.

## Docker

```bash
# Build local image (amd64)
make build-image

# Push multi-arch image (amd64 + arm64) to ECR
make push-image

# Run the published image
docker run --rm -p 8000:8000 \
  607399646027.dkr.ecr.us-east-1.amazonaws.com/navteca/images/usgs-mcp:latest
```

Key Makefile variables: `IMAGE_URI`, `IMAGE_PLATFORMS`, `AWS_PROFILE` (default `navteca`), `AWS_REGION` (default `us-east-1`).

## Kubernetes

```bash
make image IMAGE_URI=...607.../usgs-mcp:0.2.0

kubectl apply -k k8s

kubectl set image deployment/usgs-publications-mcp \
  mcp-server=...607.../usgs-mcp:0.2.0 -n mcp-servers

kubectl rollout status deployment/usgs-publications-mcp -n mcp-servers

kubectl port-forward svc/usgs-publications-mcp 8000:80 -n mcp-servers
```

Helm chart:

```bash
make chart-package          # → dist/usgs-pub-wh-mcp-<version>.tgz
make chart-release          # push to ECR OCI registry
helm install usgs-mcp ./chart
```

## Reference

- USGS API docs: <https://pubs.usgs.gov/documentation/web_service_documentation>
- Security controls: [SECURITY.md](SECURITY.md)
- Deployment options: [DEPLOYMENT.md](DEPLOYMENT.md)
- Developer guide: [AGENTS.md](AGENTS.md)
