"""
Rate limiting and circuit breaker implementation.

Protects against:
- Resource exhaustion attacks
- Denial of service
- Runaway tool invocations
- Cost overruns from excessive API calls

Implements token bucket algorithm with per-client tracking.
Logs rate limit and circuit breaker events with full context for security monitoring.
"""

import time
import asyncio
from dataclasses import dataclass, field
from typing import Callable, Optional
from collections import defaultdict
from .config import get_security_config
from .audit import get_audit_logger


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        limit_type: str,
        retry_after: float,
        current_usage: Optional[int] = None,
        threshold: Optional[int] = None,
        violation_count: Optional[int] = None,
    ):
        self.limit_type = limit_type
        self.retry_after = retry_after
        self.current_usage = current_usage
        self.threshold = threshold
        self.violation_count = violation_count
        super().__init__(
            f"Rate limit exceeded ({limit_type}). Retry after {retry_after:.1f} seconds."
        )


@dataclass
class TokenBucket:
    """
    Token bucket for rate limiting.
    
    Allows bursting up to capacity, then refills at a steady rate.
    """
    capacity: float
    refill_rate: float  # tokens per second
    tokens: float = field(default=0.0)
    last_update: float = field(default_factory=time.monotonic)
    
    def __post_init__(self):
        self.tokens = self.capacity
    
    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_update = now
    
    def try_acquire(self, tokens: float = 1.0) -> bool:
        """
        Try to acquire tokens from the bucket.
        
        Args:
            tokens: Number of tokens to acquire
            
        Returns:
            True if tokens were acquired, False if rate limited
        """
        self._refill()
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False
    
    def time_until_available(self, tokens: float = 1.0) -> float:
        """Calculate seconds until tokens will be available."""
        self._refill()
        if self.tokens >= tokens:
            return 0.0
        needed = tokens - self.tokens
        return needed / self.refill_rate


@dataclass
class CircuitBreaker:
    """
    Circuit breaker pattern for handling upstream failures.

    States:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Failing, requests are rejected immediately
    - HALF_OPEN: Testing if service recovered
    """

    failure_threshold: int = 5
    recovery_timeout: float = 60.0  # seconds
    half_open_max_calls: int = 1
    on_state_change: Optional[Callable[[str, str, int, Optional[float]], None]] = None

    _failures: int = field(default=0, init=False)
    _state: str = field(default="CLOSED", init=False)
    _last_failure_time: float = field(default=0.0, init=False)
    _state_entered_time: float = field(default=0.0, init=False)
    _half_open_calls: int = field(default=0, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)

    def _notify_state_change(
        self, new_state: str, previous_state: str, failure_count: int
    ) -> None:
        """Notify listener of state change with timing info."""
        if self.on_state_change:
            now = time.monotonic()
            time_in_prev = (
                now - self._state_entered_time if self._state_entered_time else None
            )
            try:
                self.on_state_change(
                    new_state, previous_state, failure_count, time_in_prev
                )
            except Exception:
                pass

    async def can_execute(self) -> bool:
        """Check if a request can be executed."""
        async with self._lock:
            if self._state == "CLOSED":
                return True

            if self._state == "OPEN":
                # Check if recovery timeout has passed
                if time.monotonic() - self._last_failure_time > self.recovery_timeout:
                    prev = self._state
                    prev_entered = self._state_entered_time
                    self._state = "HALF_OPEN"
                    self._half_open_calls = 0
                    self._state_entered_time = time.monotonic()
                    time_in_prev = (
                        self._state_entered_time - prev_entered
                        if prev_entered
                        else None
                    )
                    self._notify_state_change("HALF_OPEN", prev, self._failures)
                    return True
                return False

            # HALF_OPEN state
            if self._half_open_calls < self.half_open_max_calls:
                self._half_open_calls += 1
                return True
            return False

    async def record_success(self) -> None:
        """Record a successful request."""
        async with self._lock:
            prev = self._state
            if self._state == "HALF_OPEN":
                self._state = "CLOSED"
                self._state_entered_time = time.monotonic()
                self._notify_state_change("CLOSED", prev, 0)
            self._failures = 0

    async def record_failure(self) -> None:
        """Record a failed request."""
        async with self._lock:
            prev = self._state
            prev_entered = self._state_entered_time
            self._failures += 1
            self._last_failure_time = time.monotonic()

            if self._state == "HALF_OPEN":
                self._state = "OPEN"
                self._state_entered_time = time.monotonic()
                self._notify_state_change("OPEN", prev, self._failures)
            elif self._failures >= self.failure_threshold:
                self._state = "OPEN"
                self._state_entered_time = time.monotonic()
                self._notify_state_change("OPEN", prev, self._failures)
            elif prev_entered == 0:
                self._state_entered_time = time.monotonic()

    @property
    def state(self) -> str:
        """Get current circuit state."""
        return self._state


class RateLimiter:
    """
    Composite rate limiter with multiple limit types.
    
    Implements:
    - Per-minute rate limiting
    - Per-hour rate limiting  
    - Burst control
    - Circuit breaker for upstream failures
    """
    
    def __init__(self):
        self.config = get_security_config()
        self._audit_logger = get_audit_logger()

        # Violation tracking for repeated rate limit hits (potential attack indicator)
        self._violation_counts: dict[str, int] = defaultdict(int)
        self._violation_window_start = time.monotonic()
        self._violation_window_seconds = 300  # 5 minutes

        def _on_circuit_state_change(
            new_state: str,
            previous_state: str,
            failure_count: int,
            time_in_prev: Optional[float],
        ) -> None:
            self._audit_logger.log_circuit_breaker(
                new_state,
                failure_count=failure_count,
                previous_state=previous_state,
                time_in_state_seconds=time_in_prev,
            )

        # Token buckets for different time windows
        self._minute_bucket = TokenBucket(
            capacity=float(self.config.rate_limit_requests_per_minute),
            refill_rate=self.config.rate_limit_requests_per_minute / 60.0
        )
        
        self._hour_bucket = TokenBucket(
            capacity=float(self.config.rate_limit_requests_per_hour),
            refill_rate=self.config.rate_limit_requests_per_hour / 3600.0
        )
        
        self._burst_bucket = TokenBucket(
            capacity=float(self.config.rate_limit_burst_size),
            refill_rate=1.0  # 1 token per second for burst recovery
        )
        
        # Circuit breaker for upstream API (with logging callback)
        self._circuit_breaker = CircuitBreaker(on_state_change=_on_circuit_state_change)
        
        # Concurrent request tracking
        self._concurrent_requests = 0
        self._concurrent_lock = asyncio.Lock()
        
        # Request counting for session limits
        self._session_request_count = 0
        self._session_result_count = 0
    
    def _get_violation_count(self, limit_type: str) -> int:
        """Get violation count for limit type, resetting window if expired."""
        now = time.monotonic()
        if now - self._violation_window_start > self._violation_window_seconds:
            self._violation_counts.clear()
            self._violation_window_start = now
        return self._violation_counts[limit_type]

    def _record_violation(self, limit_type: str) -> int:
        """Record a rate limit violation and return updated count."""
        self._violation_counts[limit_type] += 1
        return self._violation_counts[limit_type]

    async def acquire(self) -> None:
        """
        Acquire permission to make a request.

        Raises:
            RateLimitExceeded: If any rate limit is exceeded
        """
        # Check circuit breaker first
        if not await self._circuit_breaker.can_execute():
            vcount = self._record_violation("circuit_breaker")
            raise RateLimitExceeded(
                "circuit_breaker",
                self._circuit_breaker.recovery_timeout,
                current_usage=0,
                threshold=0,
                violation_count=vcount,
            )

        # Check concurrent request limit
        async with self._concurrent_lock:
            if self._concurrent_requests >= self.config.max_concurrent_requests:
                vcount = self._record_violation("concurrent_requests")
                raise RateLimitExceeded(
                    "concurrent_requests",
                    1.0,
                    current_usage=self._concurrent_requests,
                    threshold=self.config.max_concurrent_requests,
                    violation_count=vcount,
                )
            self._concurrent_requests += 1

        try:
            # Check minute limit
            if not self._minute_bucket.try_acquire():
                retry_after = self._minute_bucket.time_until_available()
                vcount = self._record_violation("per_minute")
                used = int(self.config.rate_limit_requests_per_minute - self._minute_bucket.tokens)
                raise RateLimitExceeded(
                    "per_minute",
                    retry_after,
                    current_usage=used,
                    threshold=self.config.rate_limit_requests_per_minute,
                    violation_count=vcount,
                )

            # Check hour limit
            if not self._hour_bucket.try_acquire():
                retry_after = self._hour_bucket.time_until_available()
                vcount = self._record_violation("per_hour")
                used = int(self.config.rate_limit_requests_per_hour - self._hour_bucket.tokens)
                raise RateLimitExceeded(
                    "per_hour",
                    retry_after,
                    current_usage=used,
                    threshold=self.config.rate_limit_requests_per_hour,
                    violation_count=vcount,
                )

            # Check burst limit
            if not self._burst_bucket.try_acquire():
                retry_after = self._burst_bucket.time_until_available()
                vcount = self._record_violation("burst")
                used = int(self.config.rate_limit_burst_size - self._burst_bucket.tokens)
                raise RateLimitExceeded(
                    "burst",
                    retry_after,
                    current_usage=used,
                    threshold=self.config.rate_limit_burst_size,
                    violation_count=vcount,
                )

            self._session_request_count += 1

        except RateLimitExceeded:
            async with self._concurrent_lock:
                self._concurrent_requests -= 1
            raise
    
    async def release(self, success: bool = True) -> None:
        """
        Release a request slot after completion.
        
        Args:
            success: Whether the request succeeded
        """
        async with self._concurrent_lock:
            self._concurrent_requests = max(0, self._concurrent_requests - 1)
        
        if success:
            await self._circuit_breaker.record_success()
        else:
            await self._circuit_breaker.record_failure()
    
    def record_results(self, count: int) -> None:
        """
        Record the number of results returned.
        
        Used for session-level limits on total data retrieved.
        
        Args:
            count: Number of results in the response
        """
        self._session_result_count += count
    
    def check_session_limits(self) -> None:
        """
        Check if session-level limits are exceeded.

        Raises:
            RateLimitExceeded: If session limits are exceeded
        """
        if self._session_result_count >= self.config.max_results_per_session:
            vcount = self._record_violation("session_results")
            raise RateLimitExceeded(
                "session_results",
                float(self.config.session_timeout_minutes * 60),
                current_usage=self._session_result_count,
                threshold=self.config.max_results_per_session,
                violation_count=vcount,
            )
    
    def get_stats(self) -> dict:
        """Get current rate limiter statistics."""
        return {
            "minute_tokens": self._minute_bucket.tokens,
            "hour_tokens": self._hour_bucket.tokens,
            "burst_tokens": self._burst_bucket.tokens,
            "concurrent_requests": self._concurrent_requests,
            "session_requests": self._session_request_count,
            "session_results": self._session_result_count,
            "circuit_state": self._circuit_breaker.state,
        }
    
    def reset_session(self) -> None:
        """Reset session-level counters."""
        self._session_request_count = 0
        self._session_result_count = 0


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get the singleton rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


def reset_rate_limiter() -> None:
    """Reset the rate limiter (useful for testing)."""
    global _rate_limiter
    _rate_limiter = None
