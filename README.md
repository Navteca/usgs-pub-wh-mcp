# USGS Publications Warehouse MCP Server

An MCP server that exposes the USGS Publications Warehouse API with input validation, rate limiting, audit logging, and secure HTTP client controls.

## What This Repo Includes

- Local development with `uv`
- Docker image build and publish via `make`
- Kubernetes manifests under `k8s/`
- Helm chart under `chart/`
- MCP endpoints:
  - `POST /mcp`
  - `GET /health`

## Quick Start

Install dependencies:

```bash
uv sync
```

Run locally:

```bash
uv run python main.py --transport streamable-http --host 0.0.0.0 --port 8000
```

Health check:

```bash
curl http://localhost:8000/health
```

Initialize MCP over HTTP:

```bash
curl -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"local-test","version":"1.0"}}}'
```

## Makefile Workflow

Main variables:

- `IMAGE_URI` (default `607399646027.dkr.ecr.us-east-1.amazonaws.com/navteca/images/usgs-mcp:latest`)
- `IMAGE_PLATFORMS` (default `linux/amd64,linux/arm64`)
- `LOCAL_IMAGE_PLATFORM` (default `linux/amd64`)
- `AWS_PROFILE` (default `navteca`)
- `AWS_REGION` (default `us-east-1`)

Main targets:

- `make ecr-login IMAGE_URI=...`
- `make build-image IMAGE_URI=...`
- `make push-image IMAGE_URI=...`
- `make image IMAGE_URI=...`

## Local Docker Usage

```bash
docker run --rm -p 8000:8000 \
  607399646027.dkr.ecr.us-east-1.amazonaws.com/navteca/images/usgs-mcp:0.1.2
```

## Kubernetes

Deploy flow:

1. Build and push the image.
2. Apply manifests.
3. Update deployment image.
4. Wait for rollout.
5. Port-forward service.

```bash
make image \
  IMAGE_URI=607399646027.dkr.ecr.us-east-1.amazonaws.com/navteca/images/usgs-mcp:0.1.2

kubectl apply -k k8s

kubectl set image deployment/usgs-publications-mcp \
  mcp-server=607399646027.dkr.ecr.us-east-1.amazonaws.com/navteca/images/usgs-mcp:0.1.2 \
  -n mcp-servers

kubectl rollout status deployment/usgs-publications-mcp -n mcp-servers

kubectl port-forward svc/usgs-publications-mcp 8000:80 -n mcp-servers
```

## Tool Summary

The server exposes one MCP tool:

- `search_publications` with `query`, `title`, `index_id`, `page_size`, and `page_number`.

## Reference

- API docs: <https://pubs.usgs.gov/documentation/web_service_documentation>
- Security details: [SECURITY.md](SECURITY.md)
- Deployment notes: [DEPLOYMENT.md](DEPLOYMENT.md)
