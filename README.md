# USGS Publications Warehouse MCP Server

An MCP server that exposes the USGS Publications Warehouse API over MCP with authentication, validation, rate limiting, and audit logging.

## What This Repo Includes

- Local development with `uv`
- Docker image build with baked `.env` credentials
- ECR login and push through `make`
- Kubernetes manifests under `k8s/`
- HTTP MCP endpoint at `POST /mcp`
- Health endpoint at `GET /health`

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

## Environment

The server loads `.env` from the repo root.

Required auth variables:

```bash
USGS_MCP_API_KEY=
USGS_MCP_BEARER_TOKEN=
```

If either value is missing, the `Makefile` generates a valid random value and writes it into `.env`.

## Makefile Workflow

Main variables:

- `IMAGE_URI`
  Full image URI including tag.
  Default: `607399646027.dkr.ecr.us-east-1.amazonaws.com/navteca/images/usgs-mcp:latest`
- `IMAGE_PLATFORMS`
  Platforms used when pushing the multi-arch image.
  Default: `linux/amd64,linux/arm64`
- `LOCAL_IMAGE_PLATFORM`
  Platform used for a local non-pushed image build.
  Default: `linux/amd64`
- `AWS_PROFILE`
  Default: `navteca`
- `AWS_REGION`
  Default: `us-east-1`
- `ENV_FILE`
  Default: `.env`

Main targets:

- `make prepare-env`
  Ensures `.env` exists and fills in missing auth values.
- `make print-image-env`
  Prints the auth values that will be used for the image build.
- `make ecr-login IMAGE_URI=...`
  Logs into the ECR registry derived from `IMAGE_URI`.
- `make build-image IMAGE_URI=...`
  Builds a local single-platform Docker image and loads it into Docker.
- `make push-image IMAGE_URI=...`
  Builds and pushes a multi-arch Docker image manifest.
- `make image IMAGE_URI=...`
  Runs the full publish flow: prepare env, login to ECR, buildx push for `linux/amd64` and `linux/arm64`.

## Common Commands

Use this command now to build and push both `amd64` and `arm64`:

```bash
make image \
  IMAGE_URI=607399646027.dkr.ecr.us-east-1.amazonaws.com/navteca/images/usgs-mcp:0.1.2
```

That command:

- ensures `.env` contains `USGS_MCP_API_KEY` and `USGS_MCP_BEARER_TOKEN`
- logs into ECR with the selected AWS profile
- builds a multi-arch image for `linux/amd64` and `linux/arm64`
- pushes the manifest and both platform images to ECR

Prepare credentials:

```bash
make prepare-env
```

Show the exact credentials used for the image:

```bash
make print-image-env
```

Build and push to ECR as a multi-arch image:

```bash
make image \
  IMAGE_URI=607399646027.dkr.ecr.us-east-1.amazonaws.com/navteca/images/usgs-mcp:0.1.2
```

Build and push the multi-arch image with a different AWS profile:

```bash
make image \
  IMAGE_URI=607399646027.dkr.ecr.us-east-1.amazonaws.com/navteca/images/usgs-mcp:0.1.2 \
  AWS_PROFILE=my-profile
```

Build and push with explicit platforms:

```bash
make image \
  IMAGE_URI=607399646027.dkr.ecr.us-east-1.amazonaws.com/navteca/images/usgs-mcp:0.1.2 \
  IMAGE_PLATFORMS=linux/amd64,linux/arm64
```

Build only a local single-platform image:

```bash
make build-image \
  IMAGE_URI=607399646027.dkr.ecr.us-east-1.amazonaws.com/navteca/images/usgs-mcp:0.1.2
```

## Local Docker Usage

Run the image:

```bash
docker run --rm -p 8000:8000 \
  607399646027.dkr.ecr.us-east-1.amazonaws.com/navteca/images/usgs-mcp:0.1.2
```

Load credentials from `.env`:

```bash
export USGS_MCP_API_KEY="$(sed -n 's/^USGS_MCP_API_KEY=//p' .env | tail -n 1)"
export USGS_MCP_BEARER_TOKEN="$(sed -n 's/^USGS_MCP_BEARER_TOKEN=//p' .env | tail -n 1)"
```

Initialize MCP over HTTP:

```bash
curl -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-API-Key: ${USGS_MCP_API_KEY}" \
  -H "Authorization: Bearer ${USGS_MCP_BEARER_TOKEN}" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"local-test","version":"1.0"}}}'
```

Call the tool:

```bash
curl -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-API-Key: ${USGS_MCP_API_KEY}" \
  -H "Authorization: Bearer ${USGS_MCP_BEARER_TOKEN}" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_publications","arguments":{"query":"groundwater contamination","page_size":3}}}'
```

## Kubernetes

The manifests are in [`k8s/`](/Users/francisco/Downloads/Navteca/usgs-warehouse-mcp/k8s). The service is [`usgs-publications-mcp`](/Users/francisco/Downloads/Navteca/usgs-warehouse-mcp/k8s/service.yaml) in the `mcp-servers` namespace and exposes port `80` to container port `8000`.

Deploy flow:

1. Build and push the multi-arch image.
2. Apply the manifests.
3. Update the deployment image.
4. Wait for rollout.
5. Port-forward the service.

Commands:

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

Test through the port-forward:

```bash
curl http://localhost:8000/health

curl -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-API-Key: ${USGS_MCP_API_KEY}" \
  -H "Authorization: Bearer ${USGS_MCP_BEARER_TOKEN}" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"k8s-port-forward","version":"1.0"}}}'
```

## Tool Summary

The server exposes one MCP tool:

- `search_publications`
  Accepts `query`, `title`, `index_id`, `page_size`, and `page_number`.
  `index_id` must be used alone.

## Reference

- API docs: <https://pubs.usgs.gov/documentation/web_service_documentation>
- Security details: [SECURITY.md](/Users/francisco/Downloads/Navteca/usgs-warehouse-mcp/SECURITY.md)
- Deployment notes: [DEPLOYMENT.md](/Users/francisco/Downloads/Navteca/usgs-warehouse-mcp/DEPLOYMENT.md)
