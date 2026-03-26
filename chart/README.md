# usgs-pub-wh-mcp Helm Chart

Ingress is disabled by default. The chart is set up to run as an internal cluster service that other pods can reach through the Kubernetes service.

## Install

Use the credentials baked into the image:

```bash
helm install usgs-pub-wh-mcp ./chart \
  --namespace mcp-servers \
  --create-namespace \
  --set image.repository=607399646027.dkr.ecr.us-east-1.amazonaws.com/navteca/images/usgs-mcp \
  --set image.tag=0.1.2
```

Provide auth via Kubernetes Secret values instead:

```bash
helm install usgs-pub-wh-mcp ./chart \
  --namespace mcp-servers \
  --create-namespace \
  --set image.repository=607399646027.dkr.ecr.us-east-1.amazonaws.com/navteca/images/usgs-mcp \
  --set image.tag=0.1.2 \
  --set auth.create=true \
  --set auth.apiKey=replace-me \
  --set auth.bearerToken=usgs_replace-me
```

## Upgrade

```bash
helm upgrade usgs-pub-wh-mcp ./chart --namespace mcp-servers
```

## Enable ingress only if needed

```bash
helm upgrade --install usgs-pub-wh-mcp ./chart \
  --namespace mcp-servers \
  --create-namespace \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=usgs-mcp.example.com \
  --set ingress.hosts[0].paths[0].path=/ \
  --set ingress.hosts[0].paths[0].pathType=Prefix
```

## Template

```bash
helm template usgs-pub-wh-mcp ./chart --namespace mcp-servers
```
