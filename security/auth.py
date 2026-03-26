"""
API Key and Bearer Token authentication for the USGS Publications Warehouse MCP Server.

Implements OWASP-compliant authentication with:
- Cryptographically secure API key generation (256-bit entropy)
- Cryptographically secure Bearer token generation (384-bit entropy, via BearerTokenManager)
- Constant-time secret comparison (timing attack prevention)
- Brute-force protection with account lockout
- Bearer token rotation with grace period
- Audit logging integration
- HTTP security headers

This module is designed for use with HTTP transports (SSE, streamable-http).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import secrets
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from .audit import get_security_event_logger
from .bearer import BearerTokenManager, get_bearer_token_manager
from .config import get_security_config

logger = logging.getLogger(__name__)

# Brute-force protection constants (OWASP recommendation)
MAX_FAILED_ATTEMPTS = 10
LOCKOUT_WINDOW_SECONDS = 300  # 5 minutes
AUTH_FAILURE_RATE_LIMIT = 10  # 429 after this many failures in window
AUTH_FAILURE_WINDOW_SECONDS = 300  # 5 minutes

# Paths that skip authentication (e.g., health checks)
SKIP_AUTH_PATHS = frozenset({"/health", "/health/"})

# Security headers (OWASP recommendations)
SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "x-xss-protection": "1; mode=block",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=(), microphone=(), camera=()",
}


def _hash_key(key: str) -> str:
    """Return SHA-256 hash of the key (hex digest)."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


@dataclass
class _FailedAttemptTracker:
    """Tracks failed authentication attempts for brute-force detection."""

    attempts: list[float] = field(default_factory=list)

    def record_failure(self) -> None:
        """Record a failed attempt."""
        self.attempts.append(time.monotonic())

    def prune_old(self, window_seconds: float) -> None:
        """Remove attempts outside the window."""
        cutoff = time.monotonic() - window_seconds
        self.attempts = [t for t in self.attempts if t > cutoff]

    def is_locked(self, max_attempts: int, window_seconds: float) -> bool:
        """Check if locked due to too many failures."""
        self.prune_old(window_seconds)
        return len(self.attempts) >= max_attempts

    def failure_count(self, window_seconds: float) -> int:
        """Return number of failures in window."""
        self.prune_old(window_seconds)
        return len(self.attempts)


class AuthManager:
    """
    Manages API key and Bearer token authentication for the MCP server.

    Generates a cryptographically secure API key at initialization, stores only
    the SHA-256 hash (never plaintext after initial display), and validates
    credentials using constant-time comparison to prevent timing attacks.

    Tracks failed authentication attempts for brute-force detection and
    integrates with the audit logging system.
    """

    def __init__(self) -> None:
        """Initialize AuthManager with API key and Bearer token.

        Credentials are loaded from environment variables if set, otherwise
        generated randomly on each start:
        - USGS_MCP_API_KEY: static API key (any non-empty string)
        - USGS_MCP_BEARER_TOKEN: static Bearer token (must use usgs_ prefix)

        When env vars are set, credentials remain the same across restarts.
        """
        import os

        # API key: use env var if set, otherwise generate random (256-bit entropy)
        self._api_key_plaintext: Optional[str] = None
        env_api_key = os.environ.get("USGS_MCP_API_KEY", "").strip()
        if env_api_key:
            api_key = env_api_key
            logger.info("Using static API key from USGS_MCP_API_KEY environment variable")
        else:
            api_key = secrets.token_urlsafe(32)
        self._api_key_hash = _hash_key(api_key)
        self._api_key_plaintext = api_key

        # Bearer token: use env var if set, otherwise generate random (384-bit entropy)
        self._bearer_manager = get_bearer_token_manager()
        env_bearer = os.environ.get("USGS_MCP_BEARER_TOKEN", "").strip()
        if env_bearer:
            self._bearer_token_plaintext = self._bearer_manager.set_token(env_bearer)
            logger.info("Using static Bearer token from USGS_MCP_BEARER_TOKEN environment variable")
        else:
            self._bearer_token_plaintext: Optional[str] = self._bearer_manager.generate_token()

        self._config = get_security_config()
        self._security_event_logger = get_security_event_logger()

        # Brute-force protection for API key: track failures (keyed by "global")
        self._failed_attempts: dict[str, _FailedAttemptTracker] = defaultdict(
            _FailedAttemptTracker
        )
        self._lockout_until: float = 0.0

    def validate_api_key(self, key: str) -> bool:
        """
        Validate an API key using constant-time comparison.

        Uses hmac.compare_digest() to prevent timing attacks (OWASP recommendation).
        Tracks failed attempts for brute-force detection.

        Args:
            key: The API key to validate (from X-API-Key header).

        Returns:
            True if the key is valid, False otherwise.
        """
        if not key or not key.strip():
            return False

        # Check lockout
        if time.monotonic() < self._lockout_until:
            return False

        # Constant-time comparison (OWASP: prevents timing attacks)
        key_hash = _hash_key(key.strip())
        if hmac.compare_digest(key_hash, self._api_key_hash):
            # Success: reset failure tracker for this "client"
            self._failed_attempts["global"].prune_old(0)  # Clear
            return True

        # Failure: record and check lockout
        tracker = self._failed_attempts["global"]
        tracker.record_failure()
        if tracker.is_locked(MAX_FAILED_ATTEMPTS, LOCKOUT_WINDOW_SECONDS):
            self._lockout_until = time.monotonic() + LOCKOUT_WINDOW_SECONDS
            logger.warning(
                "Auth lockout triggered: %d failed attempts in %d seconds",
                MAX_FAILED_ATTEMPTS,
                LOCKOUT_WINDOW_SECONDS,
            )
        return False

    def validate_bearer_token(self, token: str, source: Optional[str] = None) -> bool:
        """
        Validate a Bearer token via BearerTokenManager.

        Delegates to the BearerTokenManager which provides:
        - Constant-time comparison (hmac.compare_digest)
        - Token format validation
        - Per-source brute force protection
        - Token rotation with grace period support

        Args:
            token: The Bearer token to validate (with or without 'Bearer ' prefix).
            source: Optional client identifier for per-source brute force tracking.

        Returns:
            True if the token is valid, False otherwise.
        """
        if not token or not token.strip():
            return False

        result = self._bearer_manager.validate_token(token, source=source)
        return result.valid

    def get_bearer_lockout_remaining(self, source: Optional[str] = None) -> Optional[float]:
        """Get remaining lockout time for bearer token brute force protection.

        Args:
            source: Client identifier (e.g., IP address).

        Returns:
            Seconds remaining in lockout, or None if not locked out.
        """
        return self._bearer_manager.get_lockout_remaining_seconds(source)

    def get_plaintext_credentials(self) -> dict[str, str]:
        """
        Return plaintext API key and Bearer token for initial console display only.

        Call once at startup to display credentials to the operator, then keys
        are discarded from memory. Subsequent calls return redacted placeholders.

        Returns:
            Dict with 'api_key' and 'bearer_token' (or '[ALREADY_DISPLAYED]' if consumed).
        """
        result: dict[str, str] = {}
        if self._api_key_plaintext is not None:
            result["api_key"] = self._api_key_plaintext
            self._api_key_plaintext = None  # Discard after display
        else:
            result["api_key"] = "[ALREADY_DISPLAYED - key was shown at startup]"

        if self._bearer_token_plaintext is not None:
            result["bearer_token"] = self._bearer_token_plaintext
            self._bearer_token_plaintext = None  # Discard after display
        else:
            result["bearer_token"] = "[ALREADY_DISPLAYED - token was shown at startup]"

        return result

    def is_locked(self) -> bool:
        """Check if authentication is currently locked due to brute-force protection."""
        return time.monotonic() < self._lockout_until


# Singleton instance
_auth_manager: Optional[AuthManager] = None


def get_auth_manager() -> AuthManager:
    """Get the singleton AuthManager instance."""
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthManager()
    return _auth_manager


def reset_auth_manager() -> None:
    """Reset the AuthManager singleton (for testing)."""
    global _auth_manager
    _auth_manager = None


def _get_client_ip(scope: dict[str, Any]) -> str:
    """Extract client IP from ASGI scope with trusted proxy checks."""
    config = get_security_config()
    client = scope.get("client")
    direct_ip = client[0] if client else "unknown"

    # Never trust forwarded headers unless explicitly enabled.
    if not config.trust_proxy_headers:
        return direct_ip

    # Only trust forwarded headers when request comes from a trusted proxy IP/CIDR.
    if not _is_trusted_proxy_ip(direct_ip, config.trusted_proxy_ips):
        return direct_ip

    headers = Headers(scope=scope)
    # Check common proxy headers (order matters)
    for header in ("x-forwarded-for", "x-real-ip", "cf-connecting-ip"):
        value = headers.get(header)
        if value:
            return value.split(",")[0].strip()

    return direct_ip


def _is_trusted_proxy_ip(client_ip: str, trusted_proxy_ips: tuple[str, ...]) -> bool:
    """Return True when client_ip matches a trusted proxy IP or CIDR."""
    if not trusted_proxy_ips:
        return False
    try:
        ip_obj = ipaddress.ip_address(client_ip)
    except ValueError:
        return False

    for candidate in trusted_proxy_ips:
        try:
            if "/" in candidate:
                if ip_obj in ipaddress.ip_network(candidate, strict=False):
                    return True
            elif ip_obj == ipaddress.ip_address(candidate):
                return True
        except ValueError:
            continue
    return False


def _get_user_agent(scope: dict[str, Any]) -> str:
    """Extract User-Agent from ASGI scope."""
    headers = Headers(scope=scope)
    return headers.get("user-agent", "[NOT_AVAILABLE]")


def _normalize_path(path: str) -> str:
    """Normalize path for skip-auth matching."""
    return path.rstrip("/") or "/"


def _add_security_headers(headers: list[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
    """Add OWASP security headers to response headers."""
    existing = {k.lower(): v for k, v in headers}
    for name, value in SECURITY_HEADERS.items():
        key = name.encode("ascii").lower()
        if key not in existing:
            headers.append((key, value.encode("ascii")))
    return headers


class AuthMiddleware:
    """
    ASGI middleware for API Key and Bearer Token authentication.

    Intercepts HTTP requests before they reach the MCP handler. Validates
    X-API-Key or Authorization: Bearer credentials. Returns 401 if missing,
    403 if invalid, 429 if rate limited. Skips auth for health check paths.
    Adds security headers to all responses.
    """

    def __init__(self, app: ASGIApp, auth_manager: Optional[AuthManager] = None) -> None:
        """
        Initialize the middleware.

        Args:
            app: The ASGI application to wrap.
            auth_manager: AuthManager instance (defaults to get_auth_manager()).
        """
        self.app = app
        self._auth_manager = auth_manager or get_auth_manager()
        self._security_event_logger = get_security_event_logger()
        # Per-IP auth failure tracking for 429 rate limiting
        self._failure_counts: dict[str, _FailedAttemptTracker] = defaultdict(
            _FailedAttemptTracker
        )

    def _check_auth_failure_rate_limit(self, client_ip: str) -> bool:
        """Return True if client should receive 429 (too many auth failures)."""
        tracker = self._failure_counts[client_ip]
        tracker.prune_old(AUTH_FAILURE_WINDOW_SECONDS)
        return tracker.failure_count(AUTH_FAILURE_WINDOW_SECONDS) >= AUTH_FAILURE_RATE_LIMIT

    def _record_auth_failure(self, client_ip: str) -> None:
        """Record an auth failure for rate limiting."""
        self._failure_counts[client_ip].record_failure()

    async def _send_error_response(
        self,
        send: Send,
        status: int,
        detail: str,
        scope: Scope,
        add_security_headers: bool = True,
    ) -> None:
        """Send a JSON error response with optional security headers."""
        body = {"detail": detail, "status_code": status}
        import json
        body_bytes = json.dumps(body).encode("utf-8")
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body_bytes)).encode("ascii")),
        ]
        if add_security_headers:
            headers = _add_security_headers(headers)
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": headers,
            }
        )
        await send({"type": "http.response.body", "body": body_bytes})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Process the request; validate auth for HTTP requests."""
        # Pass through non-HTTP (lifespan, websocket, etc.) to preserve streamable-http session manager
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = _normalize_path(scope.get("path", "/"))
        client_ip = _get_client_ip(scope)
        user_agent = _get_user_agent(scope)

        # Skip auth for health check endpoints (still add security headers)
        if path in SKIP_AUTH_PATHS:
            async def send_with_headers(message: dict[str, Any]) -> None:
                if message.get("type") == "http.response.start":
                    headers_list = list(message.get("headers", []))
                    _add_security_headers(headers_list)
                    message = {**message, "headers": headers_list}
                await send(message)

            await self.app(scope, receive, send_with_headers)
            return

        # Check global lockout
        if self._auth_manager.is_locked():
            self._security_event_logger.log_auth(
                success=False,
                auth_method="none",
                source_ip=client_ip,
                user_agent=user_agent,
                failure_reason="Authentication locked due to brute-force protection",
            )
            await self._send_error_response(
                send, 403, "Authentication temporarily locked", scope
            )
            return

        # Check per-IP auth failure rate limit (429)
        if self._check_auth_failure_rate_limit(client_ip):
            self._security_event_logger.log_auth(
                success=False,
                auth_method="none",
                source_ip=client_ip,
                user_agent=user_agent,
                failure_reason="Too many authentication failures",
            )
            await self._send_error_response(
                send,
                429,
                "Too many authentication failures. Try again later.",
                scope,
            )
            return

        # Extract credentials
        headers = Headers(scope=scope)
        api_key = headers.get("x-api-key", "").strip()
        auth_header = headers.get("authorization", "").strip()
        bearer_token: Optional[str] = None
        if auth_header.lower().startswith("bearer "):
            bearer_token = auth_header[7:].strip()

        # 401 if neither credential provided
        if not api_key and not bearer_token:
            self._security_event_logger.log_auth(
                success=False,
                auth_method="none",
                source_ip=client_ip,
                user_agent=user_agent,
                failure_reason="Missing credentials (X-API-Key or Authorization: Bearer)",
            )
            await self._send_error_response(
                send,
                401,
                "Missing credentials. Provide X-API-Key or Authorization: Bearer header.",
                scope,
            )
            return

        # Validate (prefer API key if both provided)
        auth_method: Optional[str] = None
        valid = False
        if api_key:
            valid = self._auth_manager.validate_api_key(api_key)
            auth_method = "api_key"
        elif bearer_token:
            valid = self._auth_manager.validate_bearer_token(bearer_token, source=client_ip)
            auth_method = "bearer_token"

        if not valid:
            self._record_auth_failure(client_ip)

            # Check if bearer lockout applies (provide Retry-After)
            bearer_lockout = self._auth_manager.get_bearer_lockout_remaining(client_ip)
            if bearer_lockout is not None and bearer_lockout > 0:
                self._security_event_logger.log_auth(
                    success=False,
                    auth_method=auth_method or "unknown",
                    source_ip=client_ip,
                    user_agent=user_agent,
                    failure_reason="Bearer token brute force lockout",
                )
                await self._send_error_response(
                    send, 429, "Too many failed attempts. Try again later.", scope
                )
                return

            self._security_event_logger.log_auth(
                success=False,
                auth_method=auth_method or "unknown",
                source_ip=client_ip,
                user_agent=user_agent,
                failure_reason="Invalid credentials",
            )
            await self._send_error_response(send, 403, "Invalid credentials", scope)
            return

        # Success: set auth_method in scope for downstream use (request.state.auth_method)
        state = scope.get("state")
        if state is None:
            scope["state"] = {"auth_method": auth_method}
        else:
            state["auth_method"] = auth_method

        self._security_event_logger.log_auth(
            success=True,
            auth_method=auth_method or "unknown",
            source_ip=client_ip,
            user_agent=user_agent,
        )

        # Wrap send to add security headers to successful responses
        async def send_with_headers(message: dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                headers_list = list(message.get("headers", []))
                _add_security_headers(headers_list)
                message = {**message, "headers": headers_list}
            await send(message)

        await self.app(scope, receive, send_with_headers)
