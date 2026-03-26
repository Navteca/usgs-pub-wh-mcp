# Deployment Guide

This guide covers different ways to deploy the USGS Publications Warehouse MCP Server.

## MCP Transport Options

| Transport | Endpoint | Use Case |
|-----------|----------|----------|
| `stdio` (default) | stdin/stdout | Claude Desktop, Cursor, local CLI |
| `sse` | `GET /sse`, `POST /messages` | Web clients, remote access |
| `streamable-http` | `POST /mcp` | HTTP APIs, remote Cursor/ngrok (runs **stateless** by default: no session lookup, no 404) |

For deployment options (Docker vs process, ngrok, gateway), see [docs/APPROACHES.md](docs/APPROACHES.md).

## Quick Start Options

### 1. Run Locally (Development)

```bash
# Clone and install
git clone <your-repo-url>
cd usgs-warehouse-mcp
uv sync

# Run with stdio transport (for Claude Desktop/Cursor)
uv run python main.py

# Run with SSE transport (for remote access)
uv run python main.py --transport sse --host 0.0.0.0 --port 8000
# Endpoints: GET /sse, POST /messages

# Run with streamable HTTP transport
uv run python main.py --transport streamable-http --host 0.0.0.0 --port 8000
# Endpoint: POST /mcp
```

### 2. Expose Temporarily (Testing with Teammates)

#### Using ngrok
```bash
# Terminal 1: Run server with SSE transport
uv run python main.py --transport sse --host 0.0.0.0 --port 8000

# Terminal 2: Expose via ngrok
ngrok http 8000

# Share the https://xxx.ngrok.io URL with teammates
# They connect to: 
#   GET  https://xxx.ngrok.io/sse      (SSE connection)
#   POST https://xxx.ngrok.io/messages (send messages)
```

#### Using Cloudflare Tunnel
```bash
# Terminal 1: Run server
uv run python main.py --transport sse --host 0.0.0.0 --port 8000

# Terminal 2: Expose via Cloudflare
cloudflared tunnel --url http://localhost:8000
```

#### Testing the Endpoints

```bash
# Test SSE endpoint (should stream)
curl -N http://localhost:8000/sse

# For streamable-http transport:
curl -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
```

### 3. Docker (Local or Server)

```bash
# Build
docker build -t usgs-publications-mcp:latest .

# Run
docker run -p 8000:8000 usgs-publications-mcp:latest

# Or use docker-compose
docker-compose up -d
```

---

## Share with Colleagues

### Option A: Git Repository

Share the repository URL. Colleagues can:
```bash
git clone <repo-url>
cd usgs-warehouse-mcp
./scripts/install.sh
```

### Option B: Create a ZIP Archive

```bash
# Create distributable archive
zip -r usgs-warehouse-mcp.zip . \
  -x ".git/*" \
  -x ".venv/*" \
  -x "__pycache__/*" \
  -x "*.pyc"
```

### Option C: Publish to PyPI (for wider distribution)

```bash
# Build wheel
uv build

# Upload to PyPI (or private registry)
uv publish
```

---

## Kubernetes Deployment (Production)

### Prerequisites

- Kubernetes cluster (1.25+)
- kubectl configured
- Container registry access
- (Optional) cert-manager for TLS
- (Optional) nginx-ingress controller

### Step 1: Build and Push Image

```bash
# Build image
docker build -t your-registry/usgs-publications-mcp:v0.2.0 .

# Push to registry
docker push your-registry/usgs-publications-mcp:v0.2.0
```

### Step 2: Update Configuration

Edit `k8s/kustomization.yaml`:
```yaml
images:
  - name: your-registry/usgs-publications-mcp
    newName: your-actual-registry/usgs-publications-mcp
    newTag: v0.2.0
```

Edit `k8s/ingress.yaml`:
```yaml
# Replace with your domain
- host: usgs-mcp.your-domain.com
```

### Step 3: Deploy

```bash
# Preview what will be deployed
kubectl apply -k k8s/ --dry-run=client -o yaml

# Deploy
kubectl apply -k k8s/

# Check status
kubectl -n mcp-servers get pods
kubectl -n mcp-servers get svc
kubectl -n mcp-servers get ingress
```

### Step 4: Verify

```bash
# Check pods are running
kubectl -n mcp-servers get pods -w

# Check logs
kubectl -n mcp-servers logs -l app=usgs-publications-mcp -f

# Test endpoint (if ingress is configured)
curl https://usgs-mcp.your-domain.com/health
```

---

## Best Practices for Production

### Security

1. **TLS Everywhere**: Use cert-manager with Let's Encrypt
2. **Network Policies**: Already included - restricts traffic
3. **Pod Security**: Runs as non-root, read-only filesystem
4. **Rate Limiting**: Both at ingress and application level
5. **Audit Logging**: Enable and forward to your SIEM

### High Availability

1. **Multiple Replicas**: Default is 2, HPA scales to 10
2. **Pod Disruption Budget**: Ensures at least 1 pod during updates
3. **Topology Spread**: Distributes across nodes
4. **Health Checks**: Liveness and readiness probes

### Monitoring

Add Prometheus ServiceMonitor:
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: usgs-publications-mcp
  namespace: mcp-servers
spec:
  selector:
    matchLabels:
      app: usgs-publications-mcp
  endpoints:
    - port: http
      interval: 30s
      path: /metrics
```

### Resource Tuning

Adjust based on load:
```yaml
resources:
  requests:
    cpu: "100m"      # Increase for higher load
    memory: "128Mi"
  limits:
    cpu: "500m"      # Increase for burst capacity
    memory: "256Mi"
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `USGS_MCP_RATE_LIMIT_REQUESTS_PER_MINUTE` | 60 | Rate limit per minute |
| `USGS_MCP_RATE_LIMIT_REQUESTS_PER_HOUR` | 1000 | Rate limit per hour |
| `USGS_MCP_MAX_PAGE_SIZE` | 100 | Maximum results per page |
| `USGS_MCP_REQUEST_TIMEOUT_SECONDS` | 30 | Request timeout |
| `USGS_MCP_AUDIT_LOGGING_ENABLED` | true | Enable audit logging |

See `SECURITY.md` for full list.

---

## Troubleshooting

### Pod won't start
```bash
kubectl -n mcp-servers describe pod <pod-name>
kubectl -n mcp-servers logs <pod-name>
```

### Connection refused
```bash
# Check service endpoints
kubectl -n mcp-servers get endpoints

# Check network policy
kubectl -n mcp-servers get networkpolicy
```

### Rate limiting too aggressive
```bash
# Update configmap
kubectl -n mcp-servers edit configmap usgs-mcp-config

# Restart pods to pick up changes
kubectl -n mcp-servers rollout restart deployment usgs-publications-mcp
```
