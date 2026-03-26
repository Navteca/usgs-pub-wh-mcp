# USGS Publications Warehouse MCP Server (Security Hardened)

An MCP (Model Context Protocol) server that provides **secure** access to the [USGS Publications Warehouse API](https://pubs.usgs.gov/documentation/web_service_documentation), allowing LLMs to search and retrieve USGS scientific publications.

## Security Features

This implementation follows security best practices from multiple authoritative sources:

| Security Control | Description |
|-----------------|-------------|
| **Input Validation** | All inputs sanitized against injection attacks |
| **Rate Limiting** | Token bucket with per-minute/hour limits |
| **Circuit Breaker** | Automatic failover on upstream errors |
| **Audit Logging** | Structured JSON logging for SIEM integration |
| **TLS Enforcement** | HTTPS required, TLS 1.2+ with cert verification |
| **URL Allowlisting** | Only approved endpoints accessible |

See [SECURITY.md](SECURITY.md) for complete security documentation.

## Features

- **Search Publications**: Full-text search across all USGS publications
- **Title Matching**: Find publications by exact title match
- **Direct Lookup**: Retrieve a specific publication by its index ID
- **Pagination**: Browse large result sets with page_size and page_number

## Installation

```bash
# Using uv (recommended)
uv sync

# Or using pip
pip install -e .
```

## Usage

### Running the Server

```bash
# Using uv
uv run python main.py

# Or directly
python main.py
```

### Configuring with Claude Desktop

Add to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "usgs-publications": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/usgs-warehouse-mcp",
        "run",
        "main.py"
      ]
    }
  }
}
```

### Configuring with Cursor

Add to your Cursor MCP settings (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "usgs-publications": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/usgs-warehouse-mcp",
        "run",
        "main.py"
      ]
    }
  }
}
```

## Available Tools

### search_publications

The single tool for all USGS publication queries.

| Parameter | Type | Description |
|-----------|------|-------------|
| `query` | string (optional) | Full-text search across all publication fields |
| `title` | string (optional) | Exact match within publication titles |
| `index_id` | string (optional) | Retrieve a specific publication by its unique ID |
| `page_size` | integer (optional) | Results per page, 1–100 (default 10) |
| `page_number` | integer (optional) | Page number for pagination (default 1) |

**Note:** `index_id` cannot be combined with `query` or `title`. Use it alone for direct lookups.

## Configuration

Security settings can be customized via environment variables:

```bash
# Rate limiting
export USGS_MCP_RATE_LIMIT_REQUESTS_PER_MINUTE=60
export USGS_MCP_RATE_LIMIT_REQUESTS_PER_HOUR=1000

# Request limits
export USGS_MCP_MAX_QUERY_LENGTH=500
export USGS_MCP_MAX_PAGE_SIZE=100

# Timeouts
export USGS_MCP_REQUEST_TIMEOUT_SECONDS=30

# Security
export USGS_MCP_ENFORCE_HTTPS=true
export USGS_MCP_VERIFY_SSL=true
export USGS_MCP_AUDIT_LOGGING_ENABLED=true
```

## Example Queries

Once connected to an LLM, you can ask questions like:

- "Search for USGS publications about groundwater contamination"
- "Find publications with 'water quality' in the title"
- "Find earthquake publications with 'hazard' in the title"
- "Get the publication with index_id ofr20151076"
- "What are the most recent USGS publications?"
- "Publications about sea-level rise in Florida"

## Project Structure

```
usgs-warehouse-mcp/
├── main.py                 # MCP server with security controls
├── security/
│   ├── __init__.py
│   ├── config.py           # Security configuration
│   ├── validation.py       # Input validation & sanitization
│   ├── rate_limiter.py     # Rate limiting & circuit breaker
│   ├── audit.py            # Audit logging
│   ├── http_client.py      # Secure HTTP client
│   ├── schema_compat.py    # OpenAI schema compatibility
│   └── tool_registry.py    # Tool registry for progressive disclosure
├── tests/
│   ├── test_user_queries.py      # User query validation tests
│   ├── test_api_integration.py   # API integration tests
│   ├── test_tool_discovery.py    # Tool registry tests
│   └── test_owasp_llm_top10.py  # OWASP security tests
├── pyproject.toml
├── README.md
├── SECURITY.md             # Security documentation
└── DEPLOYMENT.md           # Deployment guide
```

## API Reference

This MCP server wraps the USGS Publications Warehouse REST API:
- Base URL: `https://pubs.usgs.gov/pubs-services/`
- [Full API Documentation](https://pubs.usgs.gov/documentation/web_service_documentation)

## Security Resources

This implementation follows best practices from:
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)
- [WorkOS MCP Security Guide](https://workos.com/blog/mcp-security-risks-best-practices)
- [Aembit MCP Security](https://aembit.io/blog/securing-mcp-server-communications-best-practices/)
- [Red Hat MCP Security](https://www.redhat.com/en/blog/model-context-protocol-mcp-understanding-security-risks-and-controls)
- [Anthropic Code Execution with MCP](https://www.anthropic.com/engineering/code-execution-with-mcp)

## License

Public domain (as this wraps a US Government API)
