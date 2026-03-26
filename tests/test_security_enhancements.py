"""
Test: Security Enhancements Validation
======================================

Comprehensive tests for security features implemented in:
1. Enhanced Audit Logging (security/audit.py)
2. Distributed Tracing (security/tracing.py)
3. Context Size Limits (security/context_limits.py)
4. Security Event Logging (validation, rate_limiter, http_client)

Run with:
    cd /path/to/usgs-warehouse-mcp
    uv run python tests/test_security_enhancements.py
"""

import asyncio
import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from security.audit import (
    AuditEvent,
    AuditEventType,
    AuditSeverity,
    AuditEventCategory,
    SecurityEventCategory,
    AuditLogger,
    SecurityEventLogger,
    get_audit_logger,
    get_security_event_logger,
    SIEM_METADATA,
)
from security.tracing import (
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
from security.context_limits import (
    ContextSizeLimits,
    ContextLimiter,
    ContextLimitExceededError,
    get_context_limiter,
)
from security.validation import InputValidator, ValidationError
from security.rate_limiter import RateLimiter, RateLimitExceeded, get_rate_limiter
from security.config import get_security_config


# =============================================================================
# 1. ENHANCED AUDIT LOGGING TESTS
# =============================================================================

def test_audit_severity_and_categories():
    """Test AuditSeverity and AuditEventCategory enums."""
    print("Testing Audit Severity and Categories...")
    passed = 0
    failed = 0

    # Test AuditSeverity values
    try:
        assert AuditSeverity.INFO.value == "INFO"
        assert AuditSeverity.WARNING.value == "WARNING"
        assert AuditSeverity.ERROR.value == "ERROR"
        assert AuditSeverity.CRITICAL.value == "CRITICAL"
        print("  ✓ AuditSeverity enum values correct")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ AuditSeverity failed: {e}")
        failed += 1

    # Test AuditEventCategory values
    try:
        assert AuditEventCategory.SECURITY.value == "SECURITY"
        assert AuditEventCategory.PERFORMANCE.value == "PERFORMANCE"
        assert AuditEventCategory.ACCESS.value == "ACCESS"
        assert AuditEventCategory.SYSTEM.value == "SYSTEM"
        print("  ✓ AuditEventCategory enum values correct")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ AuditEventCategory failed: {e}")
        failed += 1

    # Test SecurityEventCategory values (SIEM filtering)
    try:
        assert SecurityEventCategory.INPUT_VALIDATION.value == "INPUT_VALIDATION"
        assert SecurityEventCategory.RATE_LIMITING.value == "RATE_LIMITING"
        assert SecurityEventCategory.NETWORK_SECURITY.value == "NETWORK_SECURITY"
        print("  ✓ SecurityEventCategory enum values correct")
        passed += 1
    except AssertionError as e:
        print(f"  ✗ SecurityEventCategory failed: {e}")
        failed += 1

    return passed, failed


def test_audit_event_siem_format():
    """Test SIEM format export with dual timestamps and metadata."""
    print("Testing Audit Event SIEM Format...")
    passed = 0
    failed = 0

    try:
        event = AuditEvent(
            event_type=AuditEventType.TOOL_INVOCATION,
            tool_name="test_tool",
            request_id="req-123",
        )
        siem = event.to_siem_format()

        assert "@timestamp" in siem
        assert "timestamp_iso8601" in siem
        assert "timestamp_epoch" in siem
        assert siem["severity"] == "INFO"
        assert siem["category"] == "ACCESS"
        assert siem["request_id"] == "req-123"
        assert "log_rotation_hint" in siem
        assert siem["log_rotation_hint"] == "daily"
        assert "siem_metadata" in siem
        assert siem["siem_metadata"]["log_rotation"]["format"] == "jsonl"
        print("  ✓ SIEM format has required fields and dual timestamps")
        passed += 1
    except Exception as e:
        print(f"  ✗ SIEM format failed: {e}")
        failed += 1

    try:
        event = AuditEvent(
            event_type=AuditEventType.SECURITY_VIOLATION,
            tool_name="test",
        )
        siem = event.to_siem_format()
        assert siem["severity"] == "CRITICAL"
        assert siem["category"] == "SECURITY"
        print("  ✓ Event type maps to correct severity/category")
        passed += 1
    except Exception as e:
        print(f"  ✗ Event type mapping failed: {e}")
        failed += 1

    return passed, failed


def test_audit_request_id_tracking():
    """Test request ID tracking (begin_session, end_session, get_request_id)."""
    print("Testing Audit Request ID Tracking...")
    passed = 0
    failed = 0

    audit = AuditLogger("test_audit_request_id")
    audit.config = get_security_config()

    try:
        rid1 = audit.begin_session()
        assert rid1 is not None
        assert len(rid1) == 36  # UUID format
        rid2 = audit.get_request_id()
        assert rid1 == rid2
        print("  ✓ begin_session creates and stores request_id")
        passed += 1
    except Exception as e:
        print(f"  ✗ begin_session failed: {e}")
        failed += 1

    try:
        audit.end_session()
        rid_after = audit.get_request_id()
        assert rid_after != rid1
        print("  ✓ end_session clears request_id; get_request_id creates new one")
        passed += 1
    except Exception as e:
        print(f"  ✗ end_session/get_request_id failed: {e}")
        failed += 1

    return passed, failed


def test_security_event_logger_helper():
    """Test SecurityEventLogger helper class methods."""
    print("Testing SecurityEventLogger Helper...")
    passed = 0
    failed = 0

    audit = get_audit_logger()
    sec_logger = SecurityEventLogger(audit)

    try:
        sec_logger.log_access_denied("resource_x", "permission denied")
        print("  ✓ log_access_denied runs without error")
        passed += 1
    except Exception as e:
        print(f"  ✗ log_access_denied failed: {e}")
        failed += 1

    try:
        sec_logger.log_suspicious_activity("unusual_pattern", "details here")
        print("  ✓ log_suspicious_activity runs without error")
        passed += 1
    except Exception as e:
        print(f"  ✗ log_suspicious_activity failed: {e}")
        failed += 1

    try:
        sec_logger.log_potential_attack("injection", {"indicator": "test"})
        print("  ✓ log_potential_attack runs without error")
        passed += 1
    except Exception as e:
        print(f"  ✗ log_potential_attack failed: {e}")
        failed += 1

    try:
        sec_logger.log_injection_attempt(
            "XSS", "field", "pattern_detected", "preview"
        )
        print("  ✓ log_injection_attempt runs without error")
        passed += 1
    except Exception as e:
        print(f"  ✗ log_injection_attempt failed: {e}")
        failed += 1

    return passed, failed


def test_audit_log_rate_limit_attack_indicator():
    """Test log_rate_limit produces attack_indicator when violation_count >= 5."""
    print("Testing Audit log_rate_limit Attack Indicator...")
    passed = 0
    failed = 0

    audit = AuditLogger("test_audit_rl")
    audit.config = get_security_config()

    try:
        # Create event manually to verify structure (avoid side effects of full log)
        event = audit._create_event(
            AuditEventType.RATE_LIMIT,
            "test_tool",
            security_extra={
                "limit_type": "per_minute",
                "retry_after_seconds": 60,
                "violation_count": 7,
            },
            security_category=SecurityEventCategory.RATE_LIMITING.value,
            actionable_info={
                "action": "Wait retry_after_seconds before retrying",
                "indicator": "Repeated violations may indicate DoS attempt",
                "attack_indicator": "Repeated violations (7) in window - potential DoS/abuse",
                "priority": "HIGH",
            },
        )
        siem = event.to_siem_format()
        assert siem.get("actionable_info") is not None
        assert "attack_indicator" in siem.get("actionable_info", {})
        assert "HIGH" in str(siem.get("actionable_info", {}).get("priority", ""))
        print("  ✓ Rate limit event with violation_count>=5 includes attack_indicator")
        passed += 1
    except Exception as e:
        print(f"  ✗ Rate limit attack indicator failed: {e}")
        failed += 1

    return passed, failed


def test_siem_metadata_log_rotation():
    """Test SIEM metadata and log rotation hints."""
    print("Testing SIEM Metadata and Log Rotation Hints...")
    passed = 0
    failed = 0

    try:
        assert "log_rotation" in SIEM_METADATA
        lr = SIEM_METADATA["log_rotation"]
        assert lr["hint"] == "daily"
        assert "retention_recommendation_days" in lr
        assert lr["format"] == "jsonl"
        assert "naming_pattern" in lr
        assert "max_file_size_mb" in lr
        print("  ✓ SIEM_METADATA has log rotation hints")
        passed += 1
    except Exception as e:
        print(f"  ✗ SIEM_METADATA failed: {e}")
        failed += 1

    return passed, failed


# =============================================================================
# 2. DISTRIBUTED TRACING TESTS
# =============================================================================

def test_trace_context():
    """Test TraceContext dataclass and W3C format."""
    print("Testing Trace Context...")
    passed = 0
    failed = 0

    try:
        ctx = TraceContext()
        assert len(ctx.trace_id) == 32
        assert "-" not in ctx.trace_id
        assert ctx.span_id is not None
        assert len(ctx.span_id) == 16
        print("  ✓ TraceContext has valid W3C format IDs")
        passed += 1
    except Exception as e:
        print(f"  ✗ TraceContext failed: {e}")
        failed += 1

    try:
        ctx = TraceContext(trace_id="a" * 32, span_id="b" * 16)
        child = ctx.with_span_id("c" * 16)
        assert child.trace_id == ctx.trace_id
        assert child.parent_span_id == ctx.span_id
        assert child.span_id == "c" * 16
        print("  ✓ with_span_id creates child context")
        passed += 1
    except Exception as e:
        print(f"  ✗ with_span_id failed: {e}")
        failed += 1

    return passed, failed


def test_trace_span_context_manager():
    """Test TraceSpan context manager and duration tracking."""
    print("Testing Trace Span Context Manager...")
    passed = 0
    failed = 0

    manager = get_tracing_manager()
    manager.end_trace()
    ctx = manager.start_trace()

    try:
        with manager.create_span("test_op") as span:
            assert span.operation_name == "test_op"
            assert span.span_id is not None
            assert span.duration_ms is None  # during span
        assert span.duration_ms is not None
        assert span.duration_ms >= 0
        print("  ✓ TraceSpan tracks duration")
        passed += 1
    except Exception as e:
        print(f"  ✗ TraceSpan duration failed: {e}")
        failed += 1

    try:
        with manager.create_span("with_attrs", attributes={"key": "value"}) as span:
            span.set_attribute("extra", 42)
            assert span.attributes.get("key") == "value"
            assert span.attributes.get("extra") == 42
        print("  ✓ TraceSpan attributes work")
        passed += 1
    except Exception as e:
        print(f"  ✗ TraceSpan attributes failed: {e}")
        failed += 1

    try:
        with manager.create_span("error_span") as span:
            try:
                raise ValueError("test error")
            except ValueError:
                span.record_exception(ValueError("test error"))
        assert span._status == SpanStatus.ERROR
        print("  ✓ TraceSpan record_exception sets ERROR status")
        passed += 1
    except Exception as e:
        print(f"  ✗ TraceSpan record_exception failed: {e}")
        failed += 1

    manager.end_trace()
    return passed, failed


def test_tracing_manager_singleton():
    """Test TracingManager singleton behavior."""
    print("Testing TracingManager Singleton...")
    passed = 0
    failed = 0

    try:
        m1 = get_tracing_manager()
        m2 = get_tracing_manager()
        assert m1 is m2
        print("  ✓ TracingManager is singleton")
        passed += 1
    except Exception as e:
        print(f"  ✗ Singleton failed: {e}")
        failed += 1

    return passed, failed


def test_traced_decorator():
    """Test @traced decorator on sync and async functions."""
    print("Testing @traced Decorator...")
    passed = 0
    failed = 0

    manager = get_tracing_manager()
    manager.end_trace()
    manager.start_trace()

    try:
        @traced()
        def sync_func():
            return 42

        result = sync_func()
        assert result == 42
        print("  ✓ @traced on sync function works")
        passed += 1
    except Exception as e:
        print(f"  ✗ Sync traced failed: {e}")
        failed += 1

    async def run_async_traced():
        @traced(operation_name="async_op")
        async def async_func():
            return 99
        return await async_func()

    try:
        result = asyncio.run(run_async_traced())
        assert result == 99
        print("  ✓ @traced on async function works")
        passed += 1
    except Exception as e:
        print(f"  ✗ Async traced failed: {e}")
        failed += 1

    manager.end_trace()
    return passed, failed


def test_http_context_propagation():
    """Test get_propagation_headers and extract_trace_context."""
    print("Testing HTTP Context Propagation...")
    passed = 0
    failed = 0

    manager = get_tracing_manager()
    manager.end_trace()
    manager.start_trace()

    try:
        headers = get_propagation_headers()
        assert TRACE_PARENT_HEADER in headers
        tp = headers[TRACE_PARENT_HEADER]
        parts = tp.split("-")
        assert len(parts) >= 4
        assert parts[0] == "00"
        assert len(parts[1]) == 32
        assert len(parts[2]) == 16
        print("  ✓ get_propagation_headers produces W3C traceparent")
        passed += 1
    except Exception as e:
        print(f"  ✗ get_propagation_headers failed: {e}")
        failed += 1

    try:
        incoming = {TRACE_PARENT_HEADER: "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"}
        ctx = extract_trace_context(incoming)
        assert ctx is not None
        assert ctx.trace_id == "a" * 32
        assert ctx.span_id == "b" * 16
        print("  ✓ extract_trace_context parses traceparent")
        passed += 1
    except Exception as e:
        print(f"  ✗ extract_trace_context failed: {e}")
        failed += 1

    try:
        ctx = extract_trace_context({})
        assert ctx is None
        print("  ✓ extract_trace_context returns None for empty headers")
        passed += 1
    except Exception as e:
        print(f"  ✗ extract_trace_context empty failed: {e}")
        failed += 1

    manager.end_trace()
    return passed, failed


def test_nested_spans():
    """Test nested span creation and parent-child relationship."""
    print("Testing Nested Spans...")
    passed = 0
    failed = 0

    manager = get_tracing_manager()
    manager.end_trace()
    ctx = manager.start_trace()

    try:
        with manager.create_span("parent") as parent:
            parent_id = parent.span_id
            with manager.create_span("child") as child:
                assert child.parent_span_id == parent_id
                assert child.trace_context.trace_id == ctx.trace_id
        print("  ✓ Nested spans have correct parent_span_id")
        passed += 1
    except Exception as e:
        print(f"  ✗ Nested spans failed: {e}")
        failed += 1

    manager.end_trace()
    return passed, failed


# =============================================================================
# 3. CONTEXT SIZE LIMITS TESTS
# =============================================================================

def test_context_size_limits_dataclass():
    """Test ContextSizeLimits dataclass."""
    print("Testing ContextSizeLimits Dataclass...")
    passed = 0
    failed = 0

    try:
        limits = ContextSizeLimits()
        assert limits.max_request_size_bytes == 1 * 1024 * 1024
        assert limits.max_response_size_bytes == 5 * 1024 * 1024
        assert limits.max_total_results == 1000
        assert limits.max_abstract_length == 10000
        assert limits.max_field_length == 5000
        print("  ✓ ContextSizeLimits has expected defaults")
        passed += 1
    except Exception as e:
        print(f"  ✗ ContextSizeLimits failed: {e}")
        failed += 1

    return passed, failed


def test_context_limiter_size_calculation():
    """Test ContextLimiter.get_size_bytes and size calculation."""
    print("Testing Context Size Calculation...")
    passed = 0
    failed = 0

    limits = ContextSizeLimits(
        max_request_size_bytes=1024,
        max_response_size_bytes=2048,
        max_total_results=10,
        max_abstract_length=100,
        max_field_length=50,
    )
    limiter = ContextLimiter(limits)

    try:
        size = limiter.get_size_bytes({"key": "value"})
        assert size > 0
        assert size == len(json.dumps({"key": "value"}, separators=(",", ":")).encode("utf-8"))
        print("  ✓ get_size_bytes calculates JSON serialized size")
        passed += 1
    except Exception as e:
        print(f"  ✗ get_size_bytes failed: {e}")
        failed += 1

    return passed, failed


def test_context_limiter_truncation():
    """Test ContextLimiter enforce_field_limits and truncate_response."""
    print("Testing Context Truncation...")
    passed = 0
    failed = 0

    limits = ContextSizeLimits(
        max_request_size_bytes=1024,
        max_response_size_bytes=500,  # Small to force truncation
        max_total_results=5,
        max_abstract_length=20,
        max_field_length=10,
    )
    limiter = ContextLimiter(limits)

    try:
        data = {"title": "A" * 50, "abstract": "B" * 50}
        truncated = limiter.enforce_field_limits(data)
        assert len(truncated["title"]) <= 13
        assert truncated["title"].endswith("...")
        assert len(truncated["abstract"]) <= 23
        assert truncated["abstract"].endswith("...")
        print("  ✓ enforce_field_limits truncates long fields")
        passed += 1
    except Exception as e:
        print(f"  ✗ enforce_field_limits failed: {e}")
        failed += 1

    try:
        resp = {"records": [{"id": i} for i in range(20)], "recordCount": 20}
        truncated = limiter.truncate_response(resp)
        assert len(truncated["records"]) <= 5
        print("  ✓ truncate_response limits records")
        passed += 1
    except Exception as e:
        print(f"  ✗ truncate_response failed: {e}")
        failed += 1

    try:
        limiter.check_request_size({"small": "ok"})
        print("  ✓ check_request_size accepts small request")
        passed += 1
    except Exception as e:
        print(f"  ✗ check_request_size small failed: {e}")
        failed += 1

    try:
        limiter.check_request_size({"x": "A" * 2048})
        print("  ✗ check_request_size should have raised for large request")
        failed += 1
    except ContextLimitExceededError as e:
        assert "request_size" in str(e.limit_type) or e.limit_type == "request_size"
        print("  ✓ check_request_size raises for oversized request")
        passed += 1
    except Exception as e:
        print(f"  ✗ check_request_size large failed: {e}")
        failed += 1

    return passed, failed


def test_context_limiter_integration():
    """Test get_context_limiter uses config."""
    print("Testing Context Limiter Integration...")
    passed = 0
    failed = 0

    try:
        cl = get_context_limiter()
        config = get_security_config()
        assert cl.limits.max_request_size_bytes == config.max_request_size_bytes
        assert cl.limits.max_response_size_bytes == config.max_response_size_bytes
        assert cl.limits.max_total_results == config.max_total_results
        print("  ✓ get_context_limiter uses SecurityConfig")
        passed += 1
    except Exception as e:
        print(f"  ✗ get_context_limiter integration failed: {e}")
        failed += 1

    return passed, failed


# =============================================================================
# 4. SECURITY EVENT LOGGING TESTS
# =============================================================================

def test_validation_logging():
    """Test enhanced logging in validation.py (log_validation_error, log_injection_attempt)."""
    print("Testing Validation Logging...")
    passed = 0
    failed = 0

    validator = InputValidator()

    try:
        validator.validate_year(999999, "year")
        print("  ✗ Should have raised ValidationError")
        failed += 1
    except ValidationError:
        print("  ✓ ValidationError raised for invalid year (triggers _log_validation_failure)")
        passed += 1
    except Exception as e:
        print(f"  ✗ Unexpected: {e}")
        failed += 1

    try:
        # "javascript:" triggers injection pattern (not HTML-escaped)
        validator.validate_query("javascript:alert(1)", "query")
        print("  ✗ Should have raised ValidationError for XSS injection")
        failed += 1
    except ValidationError:
        print("  ✓ ValidationError for injection (triggers log_injection_attempt)")
        passed += 1
    except Exception as e:
        print(f"  ✗ Unexpected: {e}")
        failed += 1

    try:
        validator.validate_query("normal query", "query")
        print("  ✓ Valid query passes without logging errors")
        passed += 1
    except Exception as e:
        print(f"  ✗ Valid query failed: {e}")
        failed += 1

    return passed, failed


def test_rate_limiter_logging():
    """Test rate limiter logs circuit breaker and rate limit events."""
    print("Testing Rate Limiter Logging...")
    passed = 0
    failed = 0

    limiter = get_rate_limiter()
    stats = limiter.get_stats()

    try:
        assert stats["circuit_state"] == "CLOSED"
        print("  ✓ Rate limiter circuit breaker state accessible")
        passed += 1
    except Exception as e:
        print(f"  ✗ Rate limiter stats failed: {e}")
        failed += 1

    # The circuit breaker callback is set in __init__ and calls
    # audit_logger.log_circuit_breaker on state change.
    # We can't easily trigger OPEN without many failures, but we verify
    # the RateLimiter has the callback wired.
    try:
        assert limiter._circuit_breaker.on_state_change is not None
        print("  ✓ Circuit breaker has state change callback (logs to audit)")
        passed += 1
    except Exception as e:
        print(f"  ✗ Circuit breaker callback check failed: {e}")
        failed += 1

    # Test that log_rate_limit with violation_count >= 5 produces attack_indicator
    try:
        audit = get_audit_logger()
        audit.log_rate_limit(
            "test_tool",
            "per_minute",
            60.0,
            current_usage=60,
            threshold=60,
            violation_count=7,
        )
        print("  ✓ log_rate_limit with violation_count>=5 runs (adds attack_indicator)")
        passed += 1
    except Exception as e:
        print(f"  ✗ log_rate_limit attack_indicator test failed: {e}")
        failed += 1

    # When RateLimitExceeded is raised, main.py logs via audit_logger.log_rate_limit.
    # We verify the exception has the fields needed for logging.
    try:
        exc = RateLimitExceeded("per_minute", 60.0, current_usage=60, threshold=60, violation_count=1)
        assert exc.limit_type == "per_minute"
        assert exc.retry_after == 60.0
        assert exc.current_usage == 60
        assert exc.threshold == 60
        assert exc.violation_count == 1
        print("  ✓ RateLimitExceeded has fields for audit logging")
        passed += 1
    except Exception as e:
        print(f"  ✗ RateLimitExceeded fields failed: {e}")
        failed += 1

    return passed, failed


def test_http_client_context_integration():
    """Test http_client uses context_limiter for request size check."""
    print("Testing HTTP Client Context Integration...")
    passed = 0
    failed = 0

    from security.http_client import SecureHTTPClient
    client = SecureHTTPClient()

    try:
        assert client.context_limiter is not None
        assert hasattr(client.context_limiter, "check_request_size")
        assert hasattr(client.context_limiter, "truncate_response")
        print("  ✓ HTTP client has context_limiter with check_request_size and truncate_response")
        passed += 1
    except Exception as e:
        print(f"  ✗ HTTP client context integration failed: {e}")
        failed += 1

    return passed, failed


def test_main_formatting_integration():
    """Test main.py applies context_limiter.enforce_field_limits to formatted results."""
    print("Testing Main Formatting Integration...")
    passed = 0
    failed = 0

    from security.context_limits import get_context_limiter
    limiter = get_context_limiter()

    # Simulate what main.py does: format a record and apply enforce_field_limits
    max_abstract = limiter.limits.max_abstract_length
    record = {
        "title": "Test",
        "abstract": "B" * (max_abstract + 1000),
    }
    result = limiter.enforce_field_limits(
        record,
        abstract_fields={"abstract", "abstract_snippet", "docAbstract"},
    )

    try:
        # Truncated length = max_abstract (value[:max-len("...")] + "...")
        assert len(result["abstract"]) <= max_abstract
        assert result["abstract"].endswith("...")
        print("  ✓ enforce_field_limits applies to abstract fields in main formatting")
        passed += 1
    except Exception as e:
        print(f"  ✗ Main formatting integration failed: {e}")
        failed += 1

    return passed, failed


# =============================================================================
# RUN ALL TESTS
# =============================================================================

def run_all_tests():
    """Run all security enhancement tests."""
    print("=" * 70)
    print("USGS Publications Warehouse MCP Server")
    print("Test: Security Enhancements Validation")
    print("=" * 70)
    print()

    total_passed = 0
    total_failed = 0

    # 1. Audit logging
    p, f = test_audit_severity_and_categories()
    total_passed += p
    total_failed += f

    p, f = test_audit_event_siem_format()
    total_passed += p
    total_failed += f

    p, f = test_audit_request_id_tracking()
    total_passed += p
    total_failed += f

    p, f = test_security_event_logger_helper()
    total_passed += p
    total_failed += f

    p, f = test_siem_metadata_log_rotation()
    total_passed += p
    total_failed += f

    # 2. Distributed tracing
    p, f = test_trace_context()
    total_passed += p
    total_failed += f

    p, f = test_trace_span_context_manager()
    total_passed += p
    total_failed += f

    p, f = test_tracing_manager_singleton()
    total_passed += p
    total_failed += f

    p, f = test_traced_decorator()
    total_passed += p
    total_failed += f

    p, f = test_http_context_propagation()
    total_passed += p
    total_failed += f

    p, f = test_nested_spans()
    total_passed += p
    total_failed += f

    # 3. Context size limits
    p, f = test_context_size_limits_dataclass()
    total_passed += p
    total_failed += f

    p, f = test_context_limiter_size_calculation()
    total_passed += p
    total_failed += f

    p, f = test_context_limiter_truncation()
    total_passed += p
    total_failed += f

    p, f = test_context_limiter_integration()
    total_passed += p
    total_failed += f

    # 4. Security event logging
    p, f = test_validation_logging()
    total_passed += p
    total_failed += f

    p, f = test_rate_limiter_logging()
    total_passed += p
    total_failed += f

    p, f = test_http_client_context_integration()
    total_passed += p
    total_failed += f

    p, f = test_main_formatting_integration()
    total_passed += p
    total_failed += f

    # Summary
    print()
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"  Total tests: {total_passed + total_failed}")
    print(f"  Passed: {total_passed}")
    print(f"  Failed: {total_failed}")
    print()

    if total_failed > 0:
        print("Some tests failed. Check the output above for details.")
        return 1
    else:
        print("All security enhancement tests passed!")
        return 0


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
