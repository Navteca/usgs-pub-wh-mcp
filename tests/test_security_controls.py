"""
Test: Security Controls Validation
==================================

This test validates that the security controls are working correctly:

1. Input Validation
   - Query length limits
   - Injection pattern detection
   - Publication ID format validation
   - Year range validation
   - Page size capping

2. Rate Limiting
   - Token bucket rate limiting
   - Session result counting
   - Rate limit status reporting

3. Audit Logging
   - Tool invocations are logged
   - Errors are logged
   - Sensitive fields are redacted

Run with:
    cd /path/to/usgs-warehouse-mcp
    uv run python tests/test_security_controls.py
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from security.validation import InputValidator, ValidationError
from security.rate_limiter import RateLimiter, RateLimitExceeded
from security.config import get_security_config
from security.context_limits import (
    ContextSizeLimits,
    ContextLimiter,
    ContextLimitExceededError,
    get_context_limiter,
)


def test_input_validation():
    """Test input validation and sanitization."""
    print("Testing Input Validation...")
    validator = InputValidator()
    passed = 0
    failed = 0
    
    # Test 1: Valid query accepted
    try:
        result = validator.validate_query('groundwater contamination', 'query')
        assert result == 'groundwater contamination'
        print("  ✓ Valid query accepted")
        passed += 1
    except Exception as e:
        print(f"  ✗ Valid query rejected: {e}")
        failed += 1
    
    # Test 2: Long query rejected
    try:
        long_query = 'a' * 600
        validator.validate_query(long_query, 'query')
        print("  ✗ Long query should have been rejected")
        failed += 1
    except ValidationError:
        print("  ✓ Long query rejected (exceeds 500 char limit)")
        passed += 1
    
    # Test 3: Valid publication ID accepted
    try:
        result = validator.validate_publication_id('ofr20151076', 'id')
        assert result == 'ofr20151076'
        print("  ✓ Valid publication ID accepted")
        passed += 1
    except Exception as e:
        print(f"  ✗ Valid publication ID rejected: {e}")
        failed += 1
    
    # Test 4: Path traversal in ID rejected
    try:
        validator.validate_publication_id('../../../etc/passwd', 'id')
        print("  ✗ Path traversal should have been rejected")
        failed += 1
    except ValidationError:
        print("  ✓ Path traversal blocked in publication ID")
        passed += 1
    
    # Test 5: Special characters in ID rejected
    try:
        validator.validate_publication_id('test<script>', 'id')
        print("  ✗ Special characters should have been rejected")
        failed += 1
    except ValidationError:
        print("  ✓ Special characters blocked in publication ID")
        passed += 1
    
    # Test 6: Valid year accepted
    try:
        result = validator.validate_year(2024, 'year')
        assert result == 2024
        print("  ✓ Valid year accepted")
        passed += 1
    except Exception as e:
        print(f"  ✗ Valid year rejected: {e}")
        failed += 1
    
    # Test 7: Invalid year rejected (too old)
    try:
        validator.validate_year(1500, 'year')
        print("  ✗ Invalid year should have been rejected")
        failed += 1
    except ValidationError:
        print("  ✓ Invalid year rejected (1500 < min 1800)")
        passed += 1
    
    # Test 8: Invalid year rejected (future)
    try:
        validator.validate_year(2200, 'year')
        print("  ✗ Future year should have been rejected")
        failed += 1
    except ValidationError:
        print("  ✓ Future year rejected (2200 > max 2100)")
        passed += 1
    
    # Test 9: Page size capped to max
    try:
        result = validator.validate_page_size(5000, 'page_size')
        config = get_security_config()
        assert result == config.max_page_size
        print(f"  ✓ Page size capped to max ({config.max_page_size})")
        passed += 1
    except Exception as e:
        print(f"  ✗ Page size capping failed: {e}")
        failed += 1
    
    # Test 10: Days validation
    try:
        result = validator.validate_days(30, 'days')
        assert result == 30
        print("  ✓ Valid days accepted")
        passed += 1
    except Exception as e:
        print(f"  ✗ Valid days rejected: {e}")
        failed += 1
    
    # Test 11: Days over max rejected
    try:
        validator.validate_days(5000, 'days')
        print("  ✗ Days over max should have been rejected")
        failed += 1
    except ValidationError:
        print("  ✓ Days over max rejected (5000 > 3650)")
        passed += 1
    
    return passed, failed


def test_rate_limiter():
    """Test rate limiting functionality."""
    print("\nTesting Rate Limiting...")
    passed = 0
    failed = 0
    
    # Create fresh rate limiter
    rate_limiter = RateLimiter()
    
    # Test 1: Check initial state
    stats = rate_limiter.get_stats()
    if stats['circuit_state'] == 'CLOSED':
        print("  ✓ Circuit breaker starts CLOSED")
        passed += 1
    else:
        print(f"  ✗ Circuit breaker should be CLOSED, got {stats['circuit_state']}")
        failed += 1
    
    # Test 2: Check token buckets initialized
    if stats['minute_tokens'] == 60.0:
        print("  ✓ Minute token bucket initialized to 60")
        passed += 1
    else:
        print(f"  ✗ Minute tokens should be 60, got {stats['minute_tokens']}")
        failed += 1
    
    # Test 3: Session counters start at zero
    if stats['session_requests'] == 0 and stats['session_results'] == 0:
        print("  ✓ Session counters start at zero")
        passed += 1
    else:
        print(f"  ✗ Session counters should be 0, got requests={stats['session_requests']}, results={stats['session_results']}")
        failed += 1
    
    # Test 4: Record results updates counter
    rate_limiter.record_results(100)
    stats = rate_limiter.get_stats()
    if stats['session_results'] == 100:
        print("  ✓ Session results counter updated correctly")
        passed += 1
    else:
        print(f"  ✗ Session results should be 100, got {stats['session_results']}")
        failed += 1
    
    # Test 5: Reset session clears counters
    rate_limiter.reset_session()
    stats = rate_limiter.get_stats()
    if stats['session_results'] == 0:
        print("  ✓ Reset session clears counters")
        passed += 1
    else:
        print(f"  ✗ Session results should be 0 after reset, got {stats['session_results']}")
        failed += 1
    
    return passed, failed


def test_security_config():
    """Test security configuration."""
    print("\nTesting Security Configuration...")
    passed = 0
    failed = 0
    
    config = get_security_config()
    
    # Test 1: Default rate limits
    if config.rate_limit_requests_per_minute == 60:
        print("  ✓ Default rate limit is 60/minute")
        passed += 1
    else:
        print(f"  ✗ Rate limit should be 60, got {config.rate_limit_requests_per_minute}")
        failed += 1
    
    # Test 2: HTTPS enforcement enabled
    if config.enforce_https:
        print("  ✓ HTTPS enforcement is enabled")
        passed += 1
    else:
        print("  ✗ HTTPS enforcement should be enabled")
        failed += 1
    
    # Test 3: SSL verification enabled
    if config.verify_ssl:
        print("  ✓ SSL verification is enabled")
        passed += 1
    else:
        print("  ✗ SSL verification should be enabled")
        failed += 1
    
    # Test 4: Audit logging enabled
    if config.audit_logging_enabled:
        print("  ✓ Audit logging is enabled")
        passed += 1
    else:
        print("  ✗ Audit logging should be enabled")
        failed += 1
    
    # Test 5: Sensitive field redaction enabled
    if config.redact_sensitive_fields:
        print("  ✓ Sensitive field redaction is enabled")
        passed += 1
    else:
        print("  ✗ Sensitive field redaction should be enabled")
        failed += 1
    
    # Test 6: Allowed base URLs configured
    if 'https://pubs.usgs.gov/pubs-services' in config.allowed_base_urls:
        print("  ✓ USGS API in allowed base URLs")
        passed += 1
    else:
        print("  ✗ USGS API should be in allowed base URLs")
        failed += 1
    
    return passed, failed


def test_context_limits():
    """Test context size limits for resource exhaustion protection."""
    print("\nTesting Context Size Limits...")
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

    # Test 1: get_size_bytes
    try:
        size = limiter.get_size_bytes({"url": "https://test", "params": {"q": "x"}})
        assert size > 0
        print("  ✓ get_size_bytes calculates size correctly")
        passed += 1
    except Exception as e:
        print(f"  ✗ get_size_bytes failed: {e}")
        failed += 1

    # Test 2: check_request_size - small request OK
    try:
        limiter.check_request_size({"url": "https://test", "params": {}})
        print("  ✓ Small request accepted")
        passed += 1
    except Exception as e:
        print(f"  ✗ Small request rejected: {e}")
        failed += 1

    # Test 3: check_request_size - large request raised
    try:
        limiter.check_request_size({"x": "A" * 2048})
        print("  ✗ Large request should have been rejected")
        failed += 1
    except ContextLimitExceededError:
        print("  ✓ Large request rejected (ContextLimitExceededError)")
        passed += 1

    # Test 4: enforce_field_limits truncates long fields
    try:
        long_title = {"title": "A" * 100, "abstract": "Short"}
        truncated = limiter.enforce_field_limits(long_title)
        assert len(truncated["title"]) <= 53  # 50 + "..."
        assert truncated["abstract"] == "Short"
        print("  ✓ enforce_field_limits truncates long fields")
        passed += 1
    except Exception as e:
        print(f"  ✗ enforce_field_limits failed: {e}")
        failed += 1

    # Test 5: truncate_response limits records
    try:
        resp = {"records": [{"title": f"Record {i}"} for i in range(20)], "recordCount": 20}
        truncated = limiter.truncate_response(resp)
        assert len(truncated["records"]) <= 10
        print("  ✓ truncate_response limits records to max_total_results")
        passed += 1
    except Exception as e:
        print(f"  ✗ truncate_response failed: {e}")
        failed += 1

    # Test 6: get_context_limiter uses config
    try:
        cl = get_context_limiter()
        assert cl is not None
        assert cl.limits.max_total_results == get_security_config().max_total_results
        print("  ✓ get_context_limiter returns configured limiter")
        passed += 1
    except Exception as e:
        print(f"  ✗ get_context_limiter failed: {e}")
        failed += 1

    return passed, failed


def run_all_tests():
    """Run all security tests."""
    print("=" * 70)
    print("USGS Publications Warehouse MCP Server")
    print("Test: Security Controls Validation")
    print("=" * 70)
    print()
    
    total_passed = 0
    total_failed = 0
    
    # Run test suites
    passed, failed = test_input_validation()
    total_passed += passed
    total_failed += failed
    
    passed, failed = test_rate_limiter()
    total_passed += passed
    total_failed += failed
    
    passed, failed = test_security_config()
    total_passed += passed
    total_failed += failed

    passed, failed = test_context_limits()
    total_passed += passed
    total_failed += failed
    
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
        print("All security tests passed!")
        return 0


for _name in (
    "test_input_validation",
    "test_rate_limiter",
    "test_security_config",
    "test_context_limits",
):
    globals()[_name].__test__ = False


def test_security_controls_suite() -> None:
    """Pytest entrypoint for this legacy tuple-based suite."""
    assert run_all_tests() == 0


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
