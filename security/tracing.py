"""
Distributed tracing module for the USGS Publications Warehouse MCP Server.

Provides OpenTelemetry-compatible tracing with:
- Trace and span context propagation
- Nested span support
- Async-safe context management via contextvars
- Integration with audit logging
- HTTP header propagation for distributed systems
"""

from __future__ import annotations

import functools
import json
import logging
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional, TypeVar

from .audit import get_audit_logger
from .config import get_security_config


# Context vars for async-safe trace context propagation
_trace_context_var: ContextVar[Optional["TraceContext"]] = ContextVar(
    "trace_context", default=None
)
_current_span_var: ContextVar[Optional["TraceSpan"]] = ContextVar(
    "current_span", default=None
)


class SpanStatus(str, Enum):
    """Span status compatible with OpenTelemetry."""

    UNSET = "UNSET"
    OK = "OK"
    ERROR = "ERROR"


# Standard W3C Trace Context header names
TRACE_PARENT_HEADER = "traceparent"
TRACE_STATE_HEADER = "tracestate"
BAGGAGE_HEADER = "baggage"


@dataclass
class TraceContext:
    """
    Represents the context of a distributed trace.

    Holds identifiers and metadata that propagate across operation boundaries.
    trace_id and span_id use W3C Trace Context format (32 and 16 hex chars)
    for interoperability with OpenTelemetry and distributed systems.
    """

    trace_id: str = field(
        default_factory=lambda: str(uuid.uuid4()).replace("-", "")[:32]
    )
    span_id: Optional[str] = None
    parent_span_id: Optional[str] = None
    baggage: dict[str, str] = field(default_factory=dict)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    def __post_init__(self) -> None:
        """Ensure trace_id and span_id format for W3C compatibility."""
        if len(self.trace_id) == 32 and "-" not in self.trace_id:
            pass  # Already W3C format (32 hex chars)
        else:
            self.trace_id = str(uuid.uuid4()).replace("-", "")[:32]
        if self.span_id is None:
            self.span_id = str(uuid.uuid4()).replace("-", "")[:16]

    def with_span_id(self, span_id: str) -> "TraceContext":
        """Create a copy with a new span ID (for child spans)."""
        return TraceContext(
            trace_id=self.trace_id,
            span_id=span_id,
            parent_span_id=self.span_id,
            baggage=dict(self.baggage),
            start_time=self.start_time,
            end_time=self.end_time,
        )


class TraceSpan:
    """
    Context manager for creating and managing spans within a trace.

    Tracks duration, status, and attributes. Supports nested spans.
    Integrates with the audit logger for logging span events.
    """

    def __init__(
        self,
        operation_name: str,
        trace_context: TraceContext,
        parent_span: Optional["TraceSpan"] = None,
        attributes: Optional[dict[str, Any]] = None,
    ) -> None:
        self.operation_name = operation_name
        self.trace_context = trace_context
        self.parent_span = parent_span
        self.attributes = dict(attributes or {})

        self._span_id = str(uuid.uuid4()).replace("-", "")[:16]
        self._parent_span_id = (
            parent_span.span_id
            if parent_span
            else (trace_context.span_id if trace_context else None)
        )
        self._start_time: Optional[float] = None
        self._end_time: Optional[float] = None
        self._status = SpanStatus.UNSET
        self._error_message: Optional[str] = None
        self._error_type: Optional[str] = None
        self._token: Optional[Any] = None

    @property
    def span_id(self) -> str:
        return self._span_id

    @property
    def parent_span_id(self) -> Optional[str]:
        return self._parent_span_id

    @property
    def duration_ms(self) -> Optional[float]:
        """Duration in milliseconds."""
        if self._start_time is not None and self._end_time is not None:
            return (self._end_time - self._start_time) * 1000
        return None

    def set_status(self, status: SpanStatus, message: Optional[str] = None) -> None:
        """Set the span status."""
        self._status = status
        if message is not None:
            self._error_message = message

    def set_attribute(self, key: str, value: Any) -> None:
        """Add or update a span attribute."""
        self.attributes[key] = value

    def record_exception(self, exc: BaseException) -> None:
        """Record an exception on the span."""
        self._status = SpanStatus.ERROR
        self._error_type = type(exc).__name__
        self._error_message = str(exc)[:500]

    def _to_otel_format(self) -> dict[str, Any]:
        """Export span in OpenTelemetry-compatible structured format."""
        return {
            "name": self.operation_name,
            "trace_id": self.trace_context.trace_id,
            "span_id": self._span_id,
            "parent_span_id": self._parent_span_id,
            "start_time_unix_nano": int(self._start_time * 1e9) if self._start_time else None,
            "end_time_unix_nano": int(self._end_time * 1e9) if self._end_time else None,
            "duration_ms": self.duration_ms,
            "status": self._status.value,
            "attributes": self.attributes,
            "events": [],
            "error": (
                {"type": self._error_type, "message": self._error_message}
                if self._error_message
                else None
            ),
        }

    def __enter__(self) -> "TraceSpan":
        self._start_time = time.monotonic()
        self._token = _current_span_var.set(self)

        config = get_security_config()
        if config.audit_logging_enabled:
            audit = get_audit_logger()
            audit.set_correlation_id(self.trace_context.trace_id)
            span_start_log = {
                "event": "span_start",
                "trace_id": self.trace_context.trace_id,
                "span_id": self._span_id,
                "parent_span_id": self._parent_span_id,
                "operation": self.operation_name,
                "attributes": self.attributes,
            }
            audit.logger.info(f"TRACE: {json.dumps(span_start_log, default=str)}")

        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[Any],
    ) -> bool:
        self._end_time = time.monotonic()
        _current_span_var.reset(self._token)

        if exc_val is not None:
            self.record_exception(exc_val)

        if self._status == SpanStatus.UNSET and exc_val is None:
            self._status = SpanStatus.OK

        config = get_security_config()
        if config.audit_logging_enabled:
            audit = get_audit_logger()
            span_end_log = {
                "event": "span_end",
                "trace_id": self.trace_context.trace_id,
                "span_id": self._span_id,
                "operation": self.operation_name,
                "duration_ms": round(self.duration_ms or 0, 2),
                "status": self._status.value,
                "error": (
                    {"type": self._error_type, "message": self._error_message}
                    if self._error_message
                    else None
                ),
            }
            level = logging.ERROR if self._status == SpanStatus.ERROR else logging.INFO
            audit.logger.log(level, f"TRACE: {json.dumps(span_end_log, default=str)}")

        return False  # Do not suppress exceptions


class TracingManager:
    """
    Singleton manager for distributed tracing.

    Uses contextvars for async-safe trace context propagation.
    Provides methods to start/end traces and create spans.
    """

    _instance: Optional["TracingManager"] = None

    def __new__(cls) -> "TracingManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if not hasattr(self, "_initialized"):
            self._initialized = True
            self._logger = logging.getLogger("usgs_mcp.tracing")

    def start_trace(
        self,
        trace_id: Optional[str] = None,
        baggage: Optional[dict[str, str]] = None,
    ) -> TraceContext:
        """
        Start a new trace.

        Returns a TraceContext that should be used for creating root spans.
        """
        ctx = TraceContext(
            trace_id=trace_id or str(uuid.uuid4()).replace("-", "")[:32],
            span_id=str(uuid.uuid4()).replace("-", "")[:16],
            parent_span_id=None,
            baggage=dict(baggage or {}),
            start_time=datetime.now(timezone.utc),
        )
        _trace_context_var.set(ctx)
        audit = get_audit_logger()
        audit.set_correlation_id(ctx.trace_id)
        return ctx

    def end_trace(self) -> None:
        """End the current trace and clear context."""
        ctx = _trace_context_var.get()
        if ctx:
            ctx.end_time = datetime.now(timezone.utc)
        _trace_context_var.set(None)
        _current_span_var.set(None)

    @contextmanager
    def create_span(
        self,
        operation_name: str,
        attributes: Optional[dict[str, Any]] = None,
    ):
        """
        Create a span within the current trace.

        If no trace exists, starts a new trace automatically.
        Yields a TraceSpan that tracks duration and status.
        """
        ctx = _trace_context_var.get()
        parent = _current_span_var.get()

        if ctx is None:
            ctx = self.start_trace()

        span = TraceSpan(
            operation_name=operation_name,
            trace_context=ctx,
            parent_span=parent,
            attributes=attributes,
        )

        with span:
            yield span

    def get_current_trace_id(self) -> Optional[str]:
        """Get the trace ID of the current trace."""
        ctx = _trace_context_var.get()
        return ctx.trace_id if ctx else None

    def get_current_span_id(self) -> Optional[str]:
        """Get the span ID of the current span."""
        span = _current_span_var.get()
        return span.span_id if span else None

    def export_trace_log(self, span: TraceSpan) -> str:
        """
        Export a span to structured JSON log (OpenTelemetry-compatible).

        Suitable for forwarding to tracing backends.
        """
        return json.dumps(span._to_otel_format(), default=str)


# Singleton instance
_tracing_manager: Optional[TracingManager] = None


def get_tracing_manager() -> TracingManager:
    """Get the singleton tracing manager instance."""
    global _tracing_manager
    if _tracing_manager is None:
        _tracing_manager = TracingManager()
    return _tracing_manager


# -----------------------------------------------------------------------------
# Integration helpers
# -----------------------------------------------------------------------------

F = TypeVar("F", bound=Callable[..., Any])


def traced(
    operation_name: Optional[str] = None,
    attributes: Optional[dict[str, Any]] = None,
) -> Callable[[F], F]:
    """
    Decorator to trace function execution.

    Usage:
        @traced()
        async def my_func():
            ...

        @traced(operation_name="custom_search", attributes={"service": "usgs"})
        def sync_func():
            ...
    """

    def decorator(func: F) -> F:
        name = operation_name or f"{func.__module__}.{func.__qualname__}"

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            manager = get_tracing_manager()
            with manager.create_span(name, attributes):
                return func(*args, **kwargs)

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            manager = get_tracing_manager()
            with manager.create_span(name, attributes):
                return await func(*args, **kwargs)

        if _is_async_func(func):
            return async_wrapper  # type: ignore[return-value]
        return sync_wrapper  # type: ignore[return-value]

    return decorator


def _is_async_func(func: Callable[..., Any]) -> bool:
    """Check if a callable is an async function."""
    import asyncio

    return asyncio.iscoroutinefunction(func)


# -----------------------------------------------------------------------------
# Context propagation headers (for HTTP propagation)
# -----------------------------------------------------------------------------


def get_propagation_headers() -> dict[str, str]:
    """
    Get HTTP headers for trace context propagation.

    Returns W3C Trace Context headers that can be sent with outbound HTTP
    requests to propagate the trace to downstream services.

    Format: traceparent = "00-{trace_id}-{span_id}-01"
    """
    headers: dict[str, str] = {}
    ctx = _trace_context_var.get()
    span = _current_span_var.get()

    if ctx is None:
        return headers

    # W3C traceparent: version-trace_id-span_id-flags
    span_id = span.span_id if span else ctx.span_id or ""
    traceparent = f"00-{ctx.trace_id}-{span_id}-01"
    headers[TRACE_PARENT_HEADER] = traceparent

    if ctx.baggage:
        # W3C baggage: key1=value1,key2=value2
        baggage_parts = [f"{k}={v}" for k, v in ctx.baggage.items()]
        headers[BAGGAGE_HEADER] = ",".join(baggage_parts)

    return headers


def extract_trace_context(headers: dict[str, str]) -> Optional[TraceContext]:
    """
    Extract TraceContext from incoming HTTP headers.

    Parses W3C traceparent format: "00-{trace_id}-{span_id}-01"
    Optionally parses baggage header for metadata.
    """
    traceparent = headers.get(TRACE_PARENT_HEADER) or headers.get(
        "Traceparent"
    )  # case-insensitive fallback
    if not traceparent:
        return None

    parts = traceparent.split("-")
    if len(parts) < 4:
        return None

    version, trace_id, span_id = parts[0], parts[1], parts[2]
    if version != "00":
        return None

    baggage: dict[str, str] = {}
    baggage_header = headers.get(BAGGAGE_HEADER) or headers.get("Baggage")
    if baggage_header:
        for item in baggage_header.split(","):
            item = item.strip()
            if "=" in item:
                k, _, v = item.partition("=")
                baggage[k.strip()] = v.strip()

    return TraceContext(
        trace_id=trace_id,
        span_id=span_id,
        parent_span_id=None,
        baggage=baggage,
    )
