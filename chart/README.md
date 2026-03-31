# usgs-pub-wh-mcp Helm Chart

Ingress is disabled by default. The chart runs as an internal cluster service.

## Install

```bash
helm install usgs-pub-wh-mcp ./chart \
  --namespace mcp-servers \
  --create-namespace \
  --set image.repository=607399646027.dkr.ecr.us-east-1.amazonaws.com/navteca/images/usgs-mcp \
  --set image.tag=0.1.2
```

## Upgrade

```bash
helm upgrade usgs-pub-wh-mcp ./chart --namespace mcp-servers
```

## Enable ingress if needed

```bash
helm upgrade --install usgs-pub-wh-mcp ./chart \
  --namespace mcp-servers \
  --create-namespace \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=usgs-mcp.example.com \
  --set ingress.hosts[0].paths[0].path=/ \
  --set ingress.hosts[0].paths[0].pathType=Prefix
```
