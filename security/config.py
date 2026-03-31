"""
Security configuration for the MCP server.

Implements centralized security settings with environment variable overrides.
Based on MCP security best practices for scope minimization and secure defaults.
"""

import os
from dataclasses import dataclass
from typing import ClassVar
from functools import lru_cache


@dataclass(frozen=True)
class SecurityConfig:
    """
    Immutable security configuration with secure defaults.
    
    All settings can be overridden via environment variables prefixed with USGS_MCP_.
    """
    
    # Rate limiting settings
    rate_limit_requests_per_minute: int = 60
    rate_limit_requests_per_hour: int = 1000
    rate_limit_burst_size: int = 10
    
    # Request size limits (protection against resource exhaustion)
    max_query_length: int = 500
    max_page_size: int = 100  # API recommends < 5000, we enforce stricter limit
    max_results_per_session: int = 100000  # High limit for read-only API

    # Context size limits (resource exhaustion prevention)
    max_request_size_bytes: int = 1 * 1024 * 1024  # 1 MB
    max_response_size_bytes: int = 5 * 1024 * 1024  # 5 MB
    max_total_results: int = 1000  # Max records per request response
    max_abstract_length: int = 10000
    max_field_length: int = 5000
    
    # Timeout settings (circuit breaker pattern)
    request_timeout_seconds: float = 30.0
    connect_timeout_seconds: float = 10.0
    
    # TLS/Security settings
    enforce_https: bool = True
    verify_ssl: bool = True
    min_tls_version: str = "TLSv1.2"
    
    # Audit logging settings
    audit_logging_enabled: bool = True
    log_request_params: bool = True
    log_response_size: bool = True
    redact_sensitive_fields: bool = True
    
    # Allowed API endpoints (allowlist approach)
    allowed_base_urls: tuple[str, ...] = ("https://pubs.usgs.gov/pubs-services",)
    
    # Input validation patterns
    allowed_publication_id_pattern: str = r"^[a-zA-Z0-9\-_]+$"
    allowed_query_pattern: str = r"^[a-zA-Z0-9\s\-_.,;:&/'\"()\[\]]+$"
    
    # Year validation bounds
    min_year: int = 1800
    max_year: int = 2100
    
    # Session settings
    session_timeout_minutes: int = 30
    max_concurrent_requests: int = 5

    # Sensitive fields to redact in logs
    SENSITIVE_FIELDS: ClassVar[frozenset[str]] = frozenset({
        "email", "password", "token", "api_key", "secret", "credential"
    })

    @classmethod
    def from_environment(cls) -> "SecurityConfig":
        """
        Create configuration from environment variables.
        
        Environment variables are prefixed with USGS_MCP_ and use uppercase.
        Example: USGS_MCP_RATE_LIMIT_REQUESTS_PER_MINUTE=100
        """
        def get_env(key: str, default, type_func):
            env_key = f"USGS_MCP_{key.upper()}"
            value = os.environ.get(env_key)
            if value is None:
                return default
            try:
                if type_func is bool:
                    return value.lower() in ("true", "1", "yes")
                return type_func(value)
            except (ValueError, TypeError):
                return default

        return cls(
            rate_limit_requests_per_minute=get_env(
                "rate_limit_requests_per_minute", 60, int
            ),
            rate_limit_requests_per_hour=get_env(
                "rate_limit_requests_per_hour", 1000, int
            ),
            rate_limit_burst_size=get_env("rate_limit_burst_size", 10, int),
            max_query_length=get_env("max_query_length", 500, int),
            max_page_size=get_env("max_page_size", 100, int),
            max_results_per_session=get_env("max_results_per_session", 100000, int),
            max_request_size_bytes=get_env(
                "max_request_size_bytes", 1 * 1024 * 1024, int
            ),
            max_response_size_bytes=get_env(
                "max_response_size_bytes", 5 * 1024 * 1024, int
            ),
            max_total_results=get_env("max_total_results", 1000, int),
            max_abstract_length=get_env("max_abstract_length", 10000, int),
            max_field_length=get_env("max_field_length", 5000, int),
            request_timeout_seconds=get_env("request_timeout_seconds", 30.0, float),
            connect_timeout_seconds=get_env("connect_timeout_seconds", 10.0, float),
            enforce_https=get_env("enforce_https", True, bool),
            verify_ssl=get_env("verify_ssl", True, bool),
            audit_logging_enabled=get_env("audit_logging_enabled", True, bool),
            log_request_params=get_env("log_request_params", True, bool),
            log_response_size=get_env("log_response_size", True, bool),
            redact_sensitive_fields=get_env("redact_sensitive_fields", True, bool),
            session_timeout_minutes=get_env("session_timeout_minutes", 30, int),
            max_concurrent_requests=get_env("max_concurrent_requests", 5, int),
        )


@lru_cache(maxsize=1)
def get_security_config() -> SecurityConfig:
    """Get the singleton security configuration instance."""
    return SecurityConfig.from_environment()
