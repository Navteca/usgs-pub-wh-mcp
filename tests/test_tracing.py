"""Tests for the distributed tracing module (security/tracing.py)."""

import pytest
from security import (
    TraceContext,
    TraceSpan,
    SpanStatus,
    TracingManager,
    get_tracing_manager,
    traced,
    get_propagation_headers,
    extract_trace_context,
    TRACE_PARENT_HEADER,
    BAGGAGE_HEADER,
)


class TestTraceContext:
    def test_trace_context_has_required_fields(self) -> None:
        ctx = TraceContext()
        assert len(ctx.trace_id) == 32
        assert ctx.span_id is not None
        assert ctx.parent_span_id is None
        assert ctx.baggage == {}

    def test_trace_context_with_span_id(self) -> None:
        ctx = TraceContext()
        child = ctx.with_span_id("abc1234567890abc")
        assert child.trace_id == ctx.trace_id
        assert child.span_id == "abc1234567890abc"
        assert child.parent_span_id == ctx.span_id


class TestTraceSpan:
    def test_span_tracks_duration(self) -> None:
        mgr = get_tracing_manager()
        mgr.start_trace()
        with mgr.create_span("test_op") as span:
            pass
        assert span.duration_ms is not None
        mgr.end_trace()

    def test_nested_spans(self) -> None:
        mgr = get_tracing_manager()
        mgr.start_trace()
        with mgr.create_span("outer") as outer:
            with mgr.create_span("inner") as inner:
                assert inner.parent_span_id == outer.span_id
        mgr.end_trace()


class TestTracingManager:
    def test_singleton(self) -> None:
        m1 = get_tracing_manager()
        m2 = TracingManager()
        assert m1 is m2

    def test_start_and_end_trace(self) -> None:
        mgr = get_tracing_manager()
        ctx = mgr.start_trace()
        assert mgr.get_current_trace_id() == ctx.trace_id
        mgr.end_trace()
        assert mgr.get_current_trace_id() is None


class TestPropagationHeaders:
    def test_get_propagation_headers_empty_when_no_trace(self) -> None:
        mgr = get_tracing_manager()
        mgr.end_trace()
        assert get_propagation_headers() == {}

    def test_extract_trace_context(self) -> None:
        headers = {
            TRACE_PARENT_HEADER: "00-abc123def45678901234567890123456-abcd1234567890ab-01",
        }
        ctx = extract_trace_context(headers)
        assert ctx is not None
        assert ctx.trace_id == "abc123def45678901234567890123456"
        assert ctx.span_id == "abcd1234567890ab"
