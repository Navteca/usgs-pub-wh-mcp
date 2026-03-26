"""
Security module for USGS Publications Warehouse MCP Server.

This module implements security best practices from:
- https://modelcontextprotocol.io/specification/draft/basic/security_best_practices
- https://workos.com/blog/mcp-security-risks-best-practices
- https://aembit.io/blog/securing-mcp-server-communications-best-practices/
- https://www.redhat.com/en/blog/model-context-protocol-mcp-understanding-security-risks-and-controls

NOTE: .env is loaded by main.py BEFORE importing this module.
Do not load .env here to avoid double-loading.
"""

from .config import SecurityConfig, get_security_config
from .validation import InputValidator, ValidationError
from .rate_limiter import RateLimiter, RateLimitExceeded
from .auth import (
    AuthManager,
    AuthMiddleware,
    get_auth_manager,
    reset_auth_manager,
)
from .audit import (
    AuditLogger,
    AuditEvent,
    SecurityEventLogger,
    SecurityEventCategory,
    get_security_event_logger,
)
from .http_client import SecureHTTPClient
from .context_limits import ContextSizeLimits, ContextLimiter, ContextLimitExceededError
from .bearer import (
    BearerTokenManager,
    BearerTokenValidationResult,
    BearerTokenLockedOutError,
    TokenMetadata,
    get_bearer_token_manager,
    reset_bearer_token_manager,
)
from .tracing import (
    TraceContext,
    TraceSpan,
    SpanStatus,
    TracingManager,
    get_tracing_manager,
    traced,
    get_propagation_headers,
    extract_trace_context,
    TRACE_PARENT_HEADER,
    TRACE_STATE_HEADER,
    BAGGAGE_HEADER,
)

__all__ = [
    "SecurityConfig",
    "get_security_config",
    "InputValidator",
    "ValidationError",
    "RateLimiter",
    "RateLimitExceeded",
    "AuthManager",
    "AuthMiddleware",
    "get_auth_manager",
    "reset_auth_manager",
    "AuditLogger",
    "AuditEvent",
    "SecurityEventLogger",
    "SecurityEventCategory",
    "get_security_event_logger",
    "SecureHTTPClient",
    "ContextSizeLimits",
    "ContextLimiter",
    "ContextLimitExceededError",
    # Bearer token auth
    "BearerTokenManager",
    "BearerTokenValidationResult",
    "BearerTokenLockedOutError",
    "TokenMetadata",
    "get_bearer_token_manager",
    "reset_bearer_token_manager",
    # Tracing
    "TraceContext",
    "TraceSpan",
    "SpanStatus",
    "TracingManager",
    "get_tracing_manager",
    "traced",
    "get_propagation_headers",
    "extract_trace_context",
    "TRACE_PARENT_HEADER",
    "TRACE_STATE_HEADER",
    "BAGGAGE_HEADER",
]
