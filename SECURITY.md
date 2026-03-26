# Security Documentation

This document describes the security controls implemented in the USGS Publications Warehouse MCP Server.

## Security Best Practices Implemented

This implementation follows security best practices from:

- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)
- [WorkOS MCP Security Guide](https://workos.com/blog/mcp-security-risks-best-practices)
- [Aembit MCP Security](https://aembit.io/blog/securing-mcp-server-communications-best-practices/)
- [Red Hat MCP Security](https://www.redhat.com/en/blog/model-context-protocol-mcp-understanding-security-risks-and-controls)
- [Anthropic Code Execution with MCP](https://www.anthropic.com/engineering/code-execution-with-mcp)

## Security Controls

### 1. Input Validation & Sanitization

**Module:** `security/validation.py`

All inputs are validated and sanitized to prevent:

- **Prompt Injection**: Malicious instructions embedded in user input
- **Command Injection**: Shell escape sequences and dangerous characters
- **SQL Injection Patterns**: Even though the upstream API handles this
- **Resource Exhaustion**: Oversized inputs that could consume memory

Controls implemented:

| Control | Description |
|---------|-------------|
| Length limits | Maximum 500 characters for queries, 100 for IDs |
| Character allowlists | Only safe characters accepted for structured fields |
| Pattern detection | Common injection patterns are detected and blocked |
| Type validation | All parameters validated for correct type |
| Range validation | Years, page numbers bounded to reasonable ranges |
| Unicode normalization | NFKC normalization prevents homograph attacks |
| Null byte removal | Prevents string termination attacks |

### 2. Rate Limiting & Circuit Breaker

**Module:** `security/rate_limiter.py`

Protects against denial of service and runaway tool invocations:

| Limit | Default | Purpose |
|-------|---------|---------|
| Requests per minute | 60 | Prevent burst abuse |
| Requests per hour | 1000 | Prevent sustained abuse |
| Burst size | 10 | Allow short bursts |
| Concurrent requests | 5 | Prevent resource exhaustion |
| Session results | 10,000 | Limit data extraction |

**Circuit Breaker Pattern:**
- Opens after 5 consecutive failures
- 60-second recovery timeout
- Half-open testing before full recovery

### 3. Audit Logging

**Module:** `security/audit.py`

Comprehensive logging for security monitoring:

```json
{
  "event_type": "tool_invocation",
  "tool_name": "search_publications",
  "timestamp": "2024-01-15T10:30:00Z",
  "correlation_id": "abc123",
  "parameters": {"query": "groundwater"},
  "duration_ms": 250,
  "result_count": 100
}
```

Logged events:
- All tool invocations with parameters
- Success/failure outcomes with duration
- Rate limit violations
- Validation errors
- Security violations (potential attacks)
- Circuit breaker state changes

**Sensitive Field Redaction:**
Fields containing: `email`, `password`, `token`, `api_key`, `secret`, `credential` are automatically redacted in logs.

### 4. Transport Security

**Module:** `security/http_client.py`

| Control | Description |
|---------|-------------|
| TLS 1.2+ required | Older protocols disabled |
| Certificate verification | SSL certificates validated |
| HTTPS enforcement | HTTP connections rejected |
| HTTP/2 enabled | Better performance and security |

### 5. URL Allowlisting

Only approved endpoints are accessible:

```python
allowed_base_urls = ("https://pubs.usgs.gov/pubs-services",)
```

Attempts to access other URLs are blocked and logged as security violations.

### 6. Timeout Configuration

| Setting | Default | Purpose |
|---------|---------|---------|
| Connect timeout | 10s | Prevent slow connection attacks |
| Request timeout | 30s | Prevent hung requests |
| Retry with backoff | 3 attempts | Handle transient failures |

### 7. Progressive Tool Disclosure

**Module:** `security/tool_registry.py`

Implements the [Anthropic code execution pattern](https://www.anthropic.com/engineering/code-execution-with-mcp) for context efficiency:

- Tools can be discovered on-demand via `list_tools`, `search_tools`
- Reduces context window usage by 98%+ for large tool sets
- Agents load only the tools they need

### 8. Privacy Controls

- Author emails are NOT included in formatted output
- Sensitive fields are redacted in audit logs
- PII is not logged or exposed

## Configuration

All security settings can be overridden via environment variables:

```bash
# Rate limiting
export USGS_MCP_RATE_LIMIT_REQUESTS_PER_MINUTE=100
export USGS_MCP_RATE_LIMIT_REQUESTS_PER_HOUR=2000
export USGS_MCP_RATE_LIMIT_BURST_SIZE=20

# Request limits
export USGS_MCP_MAX_QUERY_LENGTH=1000
export USGS_MCP_MAX_PAGE_SIZE=200
export USGS_MCP_MAX_RESULTS_PER_SESSION=50000

# Timeouts
export USGS_MCP_REQUEST_TIMEOUT_SECONDS=60
export USGS_MCP_CONNECT_TIMEOUT_SECONDS=15

# Security controls
export USGS_MCP_ENFORCE_HTTPS=true
export USGS_MCP_VERIFY_SSL=true
export USGS_MCP_AUDIT_LOGGING_ENABLED=true
export USGS_MCP_REDACT_SENSITIVE_FIELDS=true
```

## Security Checklist

- [x] Input validation for all parameters
- [x] Rate limiting with multiple windows
- [x] Circuit breaker for upstream failures
- [x] Comprehensive audit logging
- [x] Sensitive field redaction
- [x] TLS 1.2+ enforcement
- [x] Certificate verification
- [x] URL allowlisting
- [x] Request timeouts
- [x] Response size limits
- [x] Retry with exponential backoff
- [x] Session-level limits
- [x] Concurrent request limiting
- [x] Progressive tool disclosure

## Threat Model

### Mitigated Threats

| Threat | Mitigation |
|--------|------------|
| Prompt injection | Input sanitization, pattern detection |
| Command injection | Character allowlists, no shell execution |
| Denial of service | Rate limiting, circuit breaker |
| Resource exhaustion | Size limits, concurrent request limits |
| Data exfiltration | Session result limits, audit logging |
| MITM attacks | TLS enforcement, cert verification |
| Log injection | Sensitive field redaction, structured logging |
| Tool poisoning | Static tool definitions, no dynamic loading |

### Residual Risks

| Risk | Status | Notes |
|------|--------|-------|
| Upstream API vulnerabilities | Accepted | Cannot control USGS API |
| Sophisticated prompt injection | Monitored | Audit logging helps detect |
| Zero-day in dependencies | Monitored | Keep dependencies updated |

## Reporting Security Issues

If you discover a security vulnerability, please report it responsibly:

1. Do NOT open a public GitHub issue
2. Email the maintainers with details
3. Allow reasonable time for a fix before disclosure

## Version History

| Version | Changes |
|---------|---------|
| 0.2.0 | Added comprehensive security controls |
| 0.1.0 | Initial release (basic functionality) |
