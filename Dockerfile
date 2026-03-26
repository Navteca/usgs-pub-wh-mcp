# USGS Publications Warehouse MCP Server
# Multi-stage build for minimal image size

FROM python:3.12-slim AS builder

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency files and README needed for build metadata
COPY pyproject.toml uv.lock README.md ./

# Install dependencies
RUN uv sync --frozen --no-dev

# Copy source code
COPY main.py ./
COPY security/ ./security/

# Production stage
FROM python:3.12-slim

WORKDIR /app

ARG USGS_MCP_API_KEY=""
ARG USGS_MCP_BEARER_TOKEN=""

# Copy virtual environment and source from builder
COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/main.py /app/
COPY --from=builder /app/security /app/security

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

# Persist the credentials used at build time so main.py can load /app/.env.
RUN printf '%s\n' \
    "USGS_MCP_API_KEY=${USGS_MCP_API_KEY}" \
    "USGS_MCP_BEARER_TOKEN=${USGS_MCP_BEARER_TOKEN}" \
    > /app/.env

# Security: Run as non-root user
RUN useradd --create-home --shell /bin/bash mcpuser
USER mcpuser

# Health check — hit the /health endpoint on the running server
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Expose port for SSE transport
EXPOSE 8000

# Environment variables for transport configuration
ENV MCP_TRANSPORT=streamable-http
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=8000
# Force stateless streamable-http to avoid session-id 404 behavior
ENV FASTMCP_STATELESS_HTTP=true

# Run the MCP server (streamable-http exposes POST /mcp and GET /health for remote/ngrok use)
CMD ["python", "main.py", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "8000"]
