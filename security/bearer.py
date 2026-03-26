"""
Bearer Token authentication for USGS Publications Warehouse MCP Server.

Implements OWASP-compliant Bearer token authentication with:
- Cryptographically secure token generation (384-bit entropy)
- Constant-time comparison (hmac.compare_digest)
- Token rotation with grace period
- Brute force protection with lockout
- Token metadata tracking
- No token exposure in logs or error messages

This module is designed to be integrated into security.auth.AuthManager.
"""

import hashlib
import hmac
import re
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from .audit import (
    AuditEventType,
    AuditSeverity,
    get_audit_logger,
    _now_iso8601,
)
from .config import get_security_config
from .audit import SecurityEventCategory

# Token prefix for identification in logs (never log the actual token)
TOKEN_PREFIX = "usgs_"

# Valid token format: usgs_ + URL-safe base64 chars (A-Za-z0-9_-)
# token_urlsafe(48) produces ~64 chars, total ~69
_TOKEN_FORMAT_RE = re.compile(r"^usgs_[A-Za-z0-9_-]{40,100}$")


@dataclass
class TokenMetadata:
    """Metadata tracked for the current Bearer token."""

    created_at: float = field(default_factory=time.time)
    last_successful_use: Optional[float] = None
    successful_validations_count: int = 0


@dataclass
class BearerTokenValidationResult:
    """
    Result of token validation for integration with auth middleware.

    When valid=False due to lockout, lockout_remaining_seconds is set
    for Retry-After header in HTTP responses.
    """

    valid: bool
    lockout_remaining_seconds: Optional[float] = None


class BearerTokenLockedOutError(Exception):
    """
    Raised when validation is rejected due to brute force lockout.

    retry_after_seconds: Time until lockout expires, for Retry-After header.
    """

    def __init__(self, retry_after_seconds: float):
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            "Authentication temporarily unavailable. Retry after specified time."
        )


class BearerTokenManager:
    """
    Manages Bearer token generation, validation, rotation, and brute force protection.

    OWASP compliance:
    - Constant-time comparison via hmac.compare_digest
    - Token entropy >= 256 bits (384 bits used)
    - No token exposure in logs
    - Format validation before expensive operations
    - Brute force lockout with audit logging
    """

    def __init__(self) -> None:
        """Initialize the Bearer token manager with config-driven settings."""
        self._config = get_security_config()
        self._audit_logger = get_audit_logger()

        # Current token: SHA-256 hash only (never store plaintext)
        self._current_token_hash: Optional[str] = None
        # During rotation: old token hash valid for grace period
        self._previous_token_hash: Optional[str] = None
        self._previous_token_expires_at: float = 0.0

        # Metadata
        self._metadata = TokenMetadata()

        # Brute force: sliding window per source
        # source_key -> deque of (timestamp,) for failed attempts
        self._failed_attempts: dict[str, deque[float]] = {}
        self._lockout_until: dict[str, float] = {}
        self._lock = threading.Lock()

        # Initialize with a token if none exists (for first use)
        if self._current_token_hash is None:
            self._generate_and_store_token()

    def _generate_and_store_token(self) -> str:
        """
        Generate a new token, store its hash, return plaintext for one-time display.

        Returns:
            The new token (caller must display once, then discard).
        """
        raw = secrets.token_urlsafe(48)  # 384-bit entropy
        token = f"{TOKEN_PREFIX}{raw}"
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self._lock:
            self._current_token_hash = token_hash
            self._metadata = TokenMetadata(created_at=time.time())
        return token

    def generate_token(self) -> str:
        """
        Generate a new cryptographically secure Bearer token.

        Uses secrets.token_urlsafe(48) for 384-bit entropy.
        Token is prefixed with 'usgs_' for identification.
        Only the SHA-256 hash is stored; the plaintext is returned once for display.

        Returns:
            The new token. Display to user once, then discard. Never log or store.
        """
        return self._generate_and_store_token()

    def set_token(self, token: str) -> str:
        """
        Set a predefined Bearer token (e.g. from an environment variable).

        If the token doesn't have the required 'usgs_' prefix it is added
        automatically so format validation will pass on future requests.

        Args:
            token: The static token to use. Must be non-empty.

        Returns:
            The token (with usgs_ prefix) that should be used in requests.
        """
        token = token.strip()
        if not token:
            raise ValueError("Bearer token cannot be empty")
        if not token.startswith(TOKEN_PREFIX):
            token = f"{TOKEN_PREFIX}{token}"
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with self._lock:
            self._current_token_hash = token_hash
            self._metadata = TokenMetadata(created_at=time.time())
        return token

    def _strip_bearer_prefix(self, value: str) -> str:
        """Strip 'Bearer ' prefix if present. Accept both 'Bearer xyz' and 'xyz'."""
        if value.startswith("Bearer "):
            return value[7:].strip()
        return value.strip()

    def _validate_token_format(self, token: str) -> bool:
        """
        Validate token format before expensive comparison.

        Rejects obviously invalid tokens early to save CPU.
        """
        if not token or len(token) > self._config.bearer_token_max_length:
            return False
        return bool(_TOKEN_FORMAT_RE.match(token))

    def _get_source_key(self, source: Optional[str]) -> str:
        """Normalize source for brute force tracking."""
        return source if source else "default"

    def _is_locked_out(self, source_key: str) -> tuple[bool, float]:
        """
        Check if source is locked out. Returns (is_locked, remaining_seconds).
        """
        now = time.monotonic()
        until = self._lockout_until.get(source_key, 0)
        if until <= now:
            return False, 0.0
        return True, until - now

    def _record_failed_attempt(self, source_key: str) -> None:
        """Record failed attempt and potentially trigger lockout."""
        now = time.monotonic()
        window = self._config.bearer_brute_force_window_seconds
        threshold = self._config.bearer_brute_force_fail_threshold
        lockout = self._config.bearer_brute_force_lockout_seconds

        with self._lock:
            if source_key not in self._failed_attempts:
                self._failed_attempts[source_key] = deque(maxlen=100)
            q = self._failed_attempts[source_key]
            # Prune old entries outside sliding window
            while q and q[0] < now - window:
                q.popleft()
            q.append(now)
            if len(q) >= threshold:
                self._lockout_until[source_key] = now + lockout
                self._log_lockout(source_key, len(q))

    def _log_lockout(self, source_key: str, attempt_count: int) -> None:
        """Log lockout event as CRITICAL via audit logger."""
        if not self._audit_logger.config.audit_logging_enabled:
            return
        security_extra = {
            "what_happened": "Bearer token brute force lockout triggered",
            "trigger": "bearer_token_validation",
            "where": "bearer_auth",
            "when": _now_iso8601(),
            "source_key_hash": hashlib.sha256(source_key.encode()).hexdigest()[:16],
            "attempt_count": attempt_count,
            "lockout_seconds": self._config.bearer_brute_force_lockout_seconds,
        }
        event = self._audit_logger._create_event(
            AuditEventType.POTENTIAL_ATTACK,
            "bearer_token",
            security_extra=security_extra,
            security_category=SecurityEventCategory.AUTHENTICATION.value,
            severity=AuditSeverity.CRITICAL,
            actionable_info={
                "action": "Block source; investigate repeated failures",
                "priority": "CRITICAL",
            },
        )
        self._audit_logger._log_event(event)

    def get_lockout_remaining_seconds(self, source: Optional[str] = None) -> Optional[float]:
        """
        Get remaining lockout time for a source, if locked out.

        Use when validate_token returns False to provide Retry-After in responses.

        Args:
            source: Client identifier (e.g., IP hash). None uses default bucket.

        Returns:
            Seconds remaining in lockout, or None if not locked out.
        """
        source_key = self._get_source_key(source)
        with self._lock:
            is_locked, remaining = self._is_locked_out(source_key)
            return remaining if is_locked else None

    def validate_token(
        self,
        token: Optional[str],
        source: Optional[str] = None,
    ) -> BearerTokenValidationResult:
        """
        Validate a Bearer token using constant-time comparison.

        Handles both "Bearer <token>" and raw token formats.
        Rejects invalid format early. Uses hmac.compare_digest for comparison.
        Tracks failed attempts and enforces brute force lockout.

        Args:
            token: The token or "Bearer <token>" string. May be None.
            source: Optional client identifier for brute force tracking.

        Returns:
            BearerTokenValidationResult with valid flag and optional lockout_remaining.
        """
        source_key = self._get_source_key(source)

        # Check lockout first
        with self._lock:
            is_locked, remaining = self._is_locked_out(source_key)
        if is_locked:
            return BearerTokenValidationResult(
                valid=False,
                lockout_remaining_seconds=remaining,
            )

        # Reject None, empty, wrong type
        if token is None or not isinstance(token, str):
            return BearerTokenValidationResult(valid=False)

        stripped = self._strip_bearer_prefix(token)
        if not stripped:
            return BearerTokenValidationResult(valid=False)

        # Format validation before expensive ops
        if not self._validate_token_format(stripped):
            self._record_failed_attempt(source_key)
            return BearerTokenValidationResult(valid=False)

        # Constant-time comparison
        token_hash = hashlib.sha256(stripped.encode()).hexdigest()

        with self._lock:
            now = time.time()
            current = self._current_token_hash
            previous = self._previous_token_hash
            prev_expires = self._previous_token_expires_at

        valid = False
        if current and hmac.compare_digest(token_hash, current):
            valid = True
        elif previous and now < prev_expires and hmac.compare_digest(token_hash, previous):
            valid = True

        if valid:
            with self._lock:
                self._metadata.last_successful_use = time.time()
                self._metadata.successful_validations_count += 1
            return BearerTokenValidationResult(valid=True)
        else:
            self._record_failed_attempt(source_key)
            return BearerTokenValidationResult(valid=False)

    def rotate_token(self) -> str:
        """
        Rotate to a new token. Old token remains valid for grace period.

        OWASP best practice: support token rotation for compromise recovery.
        Logs rotation event via audit logger.

        Returns:
            The new token. Display once, then discard.
        """
        grace = self._config.bearer_token_rotation_grace_seconds
        now = time.time()

        with self._lock:
            self._previous_token_hash = self._current_token_hash
            self._previous_token_expires_at = now + grace
        new_token = self._generate_and_store_token()

        if self._audit_logger.config.audit_logging_enabled:
            security_extra = {
                "what_happened": "Bearer token rotated",
                "trigger": "bearer_token_rotation",
                "where": "bearer_auth",
                "when": _now_iso8601(),
                "grace_period_seconds": grace,
            }
            event = self._audit_logger._create_event(
                AuditEventType.CONFIG_CHANGE,
                "bearer_token",
                security_extra=security_extra,
                security_category=SecurityEventCategory.AUTHENTICATION.value,
                severity=AuditSeverity.INFO,
                actionable_info={
                    "action": "New token active; old token valid during grace period",
                },
            )
            self._audit_logger._log_event(event)

        return new_token

    def get_metadata(self) -> TokenMetadata:
        """Return a copy of current token metadata."""
        with self._lock:
            return TokenMetadata(
                created_at=self._metadata.created_at,
                last_successful_use=self._metadata.last_successful_use,
                successful_validations_count=self._metadata.successful_validations_count,
            )

    def has_token(self) -> bool:
        """Return True if a token has been generated."""
        with self._lock:
            return self._current_token_hash is not None


# Singleton
_bearer_token_manager: Optional[BearerTokenManager] = None
_singleton_lock = threading.Lock()


def get_bearer_token_manager() -> BearerTokenManager:
    """Get the singleton BearerTokenManager instance."""
    global _bearer_token_manager
    with _singleton_lock:
        if _bearer_token_manager is None:
            _bearer_token_manager = BearerTokenManager()
        return _bearer_token_manager


def reset_bearer_token_manager() -> None:
    """Reset the singleton (for testing)."""
    global _bearer_token_manager
    with _singleton_lock:
        _bearer_token_manager = None
