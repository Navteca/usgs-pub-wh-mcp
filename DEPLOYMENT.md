# Deployment Guide

This guide covers common deployment options for the USGS Publications Warehouse MCP Server.

## MCP Transport Options

| Transport | Endpoint | Use Case |
|-----------|----------|----------|
| `stdio` (default) | stdin/stdout | Claude Desktop, Cursor, local CLI |
| `sse` | `GET /sse`, `POST /messages` | Web clients, remote access |
| `streamable-http` | `POST /mcp` | HTTP APIs and internal platform integrations (stateless by default) |

## Quick Start

```bash
git clone <your-repo-url>
cd usgs-warehouse-mcp
uv sync
```

Run with stdio:

```bash
uv run python main.py
```

Run with SSE:

```bash
uv run python main.py --transport sse --host 0.0.0.0 --port 8000
```

Run with streamable HTTP:

```bash
uv run python main.py --transport streamable-http --host 0.0.0.0 --port 8000
```

## Endpoint Checks

```bash
curl http://localhost:8000/health

curl -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
```

## Docker

```bash
docker build -t usgs-publications-mcp:latest .
docker run -p 8000:8000 usgs-publications-mcp:latest
docker-compose up -d
```

## Kubernetes

```bash
docker build -t your-registry/usgs-publications-mcp:v0.2.0 .
docker push your-registry/usgs-publications-mcp:v0.2.0

kubectl apply -k k8s/ --dry-run=client -o yaml
kubectl apply -k k8s/
kubectl -n mcp-servers get pods
kubectl -n mcp-servers get svc
kubectl -n mcp-servers get ingress
```

Verify:

```bash
kubectl -n mcp-servers get pods -w
kubectl -n mcp-servers logs -l app=usgs-publications-mcp -f
curl https://usgs-mcp.your-domain.com/health
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `USGS_MCP_RATE_LIMIT_REQUESTS_PER_MINUTE` | 60 | Rate limit per minute |
| `USGS_MCP_RATE_LIMIT_REQUESTS_PER_HOUR` | 1000 | Rate limit per hour |
| `USGS_MCP_MAX_PAGE_SIZE` | 100 | Maximum results per page |
| `USGS_MCP_REQUEST_TIMEOUT_SECONDS` | 30 | Request timeout |
| `USGS_MCP_AUDIT_LOGGING_ENABLED` | true | Enable audit logging |

See `SECURITY.md` for the full set.
