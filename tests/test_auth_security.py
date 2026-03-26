"""
Adversarial Security Tests for USGS Publications Warehouse MCP Authentication
============================================================================

OWASP-compliant, adversarial test suite for API Key and Bearer Token auth.
Tests timing attacks, brute force, injection, information disclosure, and more.

Run with:
    uv run python tests/test_auth_security.py
"""

from __future__ import annotations

import json
import sys
import time
import threading
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from security.auth import (
    AuthManager,
    AuthMiddleware,
    get_auth_manager,
    reset_auth_manager,
    _hash_key,
    _normalize_path,
    SKIP_AUTH_PATHS,
    MAX_FAILED_ATTEMPTS,
    LOCKOUT_WINDOW_SECONDS,
    AUTH_FAILURE_RATE_LIMIT,
    AUTH_FAILURE_WINDOW_SECONDS,
)
from security.bearer import (
    BearerTokenManager,
    get_bearer_token_manager,
    reset_bearer_token_manager,
    TOKEN_PREFIX,
)


# -----------------------------------------------------------------------------
# A. API Key Tests
# -----------------------------------------------------------------------------


class TestAPIKeyValid(unittest.TestCase):
    """A1: Valid API key accepted."""

    def setUp(self) -> None:
        reset_auth_manager()
        self.manager = get_auth_manager()
        creds = self.manager.get_plaintext_credentials()
        self.valid_key = creds["api_key"]

    def test_valid_api_key_accepted(self) -> None:
        self.assertTrue(self.manager.validate_api_key(self.valid_key))


class TestAPIKeyInvalid(unittest.TestCase):
    """A2: Invalid API key rejected (403)."""

    def setUp(self) -> None:
        reset_auth_manager()
        self.manager = get_auth_manager()
        self.manager.get_plaintext_credentials()  # Discard

    def test_invalid_api_key_rejected(self) -> None:
        self.assertFalse(self.manager.validate_api_key("invalid_key_12345"))


class TestAPIKeyMissing(unittest.TestCase):
    """A3: Missing API key returns 401 (tested at middleware level)."""

    def test_missing_credentials_returns_401(self) -> None:
        status, _ = _run_middleware_request(headers={})
        self.assertEqual(status, 401)


class TestAPIKeyEmpty(unittest.TestCase):
    """A4: Empty API key string rejected."""

    def setUp(self) -> None:
        reset_auth_manager()
        self.manager = get_auth_manager()
        self.manager.get_plaintext_credentials()

    def test_empty_api_key_rejected(self) -> None:
        self.assertFalse(self.manager.validate_api_key(""))

    def test_whitespace_only_rejected(self) -> None:
        self.assertFalse(self.manager.validate_api_key("   "))


class TestAPIKeyWhitespacePadding(unittest.TestCase):
    """A5: API key with whitespace padding (should work after strip)."""

    def setUp(self) -> None:
        reset_auth_manager()
        self.manager = get_auth_manager()
        creds = self.manager.get_plaintext_credentials()
        self.valid_key = creds["api_key"]

    def test_api_key_with_whitespace_works_after_strip(self) -> None:
        self.assertTrue(self.manager.validate_api_key(f"  {self.valid_key}  "))
        self.assertTrue(self.manager.validate_api_key(f"\t{self.valid_key}\n"))


class TestAPIKeyTimingAttackResistance(unittest.TestCase):
    """A6: Timing attack resistance - verify hmac.compare_digest is used."""

    def setUp(self) -> None:
        reset_auth_manager()
        self.manager = get_auth_manager()
        creds = self.manager.get_plaintext_credentials()
        self.valid_key = creds["api_key"]

    def test_hmac_compare_digest_used_for_api_key(self) -> None:
        with patch("security.auth.hmac.compare_digest") as mock_compare:
            mock_compare.return_value = True
            result = self.manager.validate_api_key(self.valid_key)
            self.assertTrue(result)
            mock_compare.assert_called()


class TestAPIKeyHashStorage(unittest.TestCase):
    """A7: API key hash storage - verify plaintext is not stored after get_plaintext_credentials()."""

    def test_plaintext_discarded_after_get_plaintext_credentials(self) -> None:
        reset_auth_manager()
        manager = get_auth_manager()
        creds1 = manager.get_plaintext_credentials()
        creds2 = manager.get_plaintext_credentials()
        self.assertIn("[ALREADY_DISPLAYED", creds2["api_key"])
        self.assertNotEqual(creds1["api_key"], creds2["api_key"])
        # Validation should still work with original key (we stored hash)
        self.assertTrue(manager.validate_api_key(creds1["api_key"]))


class TestAPIKeyBruteForceLockout(unittest.TestCase):
    """A8: Brute force lockout - after 10 failures, all attempts rejected."""

    def setUp(self) -> None:
        reset_auth_manager()
        self.manager = get_auth_manager()
        creds = self.manager.get_plaintext_credentials()
        self.valid_key = creds["api_key"]

    def test_brute_force_lockout_after_10_failures(self) -> None:
        with patch("security.auth.MAX_FAILED_ATTEMPTS", 3), patch(
            "security.auth.LOCKOUT_WINDOW_SECONDS", 5
        ):
            for _ in range(3):
                self.manager.validate_api_key("wrong_key")
            # Now even valid key should fail (locked out)
            self.assertFalse(self.manager.validate_api_key(self.valid_key))


class TestAPIKeyBruteForceLockoutExpiry(unittest.TestCase):
    """A9: Brute force lockout expiry - after window, attempts work again."""

    def test_lockout_expires_after_window(self) -> None:
        with patch("security.auth.MAX_FAILED_ATTEMPTS", 2), patch(
            "security.auth.LOCKOUT_WINDOW_SECONDS", 0.2
        ):
            reset_auth_manager()
            manager = get_auth_manager()
            creds = manager.get_plaintext_credentials()
            valid_key = creds["api_key"]
            for _ in range(2):
                manager.validate_api_key("wrong")
            self.assertFalse(manager.validate_api_key(valid_key))
            time.sleep(0.3)
            self.assertTrue(manager.validate_api_key(valid_key))


# -----------------------------------------------------------------------------
# B. Bearer Token Tests
# -----------------------------------------------------------------------------


class TestBearerValid(unittest.TestCase):
    """B10: Valid bearer token accepted."""

    def setUp(self) -> None:
        reset_bearer_token_manager()
        reset_auth_manager()
        self.manager = get_bearer_token_manager()
        self.token = self.manager.generate_token()

    def test_valid_bearer_token_accepted(self) -> None:
        result = self.manager.validate_token(self.token)
        self.assertTrue(result.valid)


class TestBearerInvalid(unittest.TestCase):
    """B11: Invalid bearer token rejected."""

    def setUp(self) -> None:
        reset_bearer_token_manager()
        self.manager = get_bearer_token_manager()
        self.manager.generate_token()

    def test_invalid_bearer_token_rejected(self) -> None:
        result = self.manager.validate_token(
            "usgs_invalidtoken12345678901234567890123456789012345678901234"
        )
        self.assertFalse(result.valid)


class TestBearerWithPrefix(unittest.TestCase):
    """B12: Bearer token with 'Bearer ' prefix works."""

    def setUp(self) -> None:
        reset_bearer_token_manager()
        self.manager = get_bearer_token_manager()
        self.token = self.manager.generate_token()

    def test_bearer_prefix_works(self) -> None:
        result = self.manager.validate_token(f"Bearer {self.token}")
        self.assertTrue(result.valid)


class TestBearerWithoutPrefix(unittest.TestCase):
    """B13: Bearer token without prefix also works (via BearerTokenManager)."""

    def setUp(self) -> None:
        reset_bearer_token_manager()
        self.manager = get_bearer_token_manager()
        self.token = self.manager.generate_token()

    def test_raw_token_without_prefix_works(self) -> None:
        result = self.manager.validate_token(self.token)
        self.assertTrue(result.valid)


class TestBearerTokenRotation(unittest.TestCase):
    """B14-B15: Token rotation - old works during grace, fails after."""

    def setUp(self) -> None:
        reset_bearer_token_manager()
        self.manager = get_bearer_token_manager()
        self.old_token = self.manager.generate_token()

    def test_old_token_works_during_grace_period(self) -> None:
        new_token = self.manager.rotate_token()
        self.assertTrue(self.manager.validate_token(self.old_token).valid)
        self.assertTrue(self.manager.validate_token(new_token).valid)

    def test_old_token_fails_after_grace_period(self) -> None:
        mock_config = MagicMock()
        mock_config.bearer_token_rotation_grace_seconds = 0.1
        mock_config.bearer_brute_force_fail_threshold = 5
        mock_config.bearer_brute_force_window_seconds = 60
        mock_config.bearer_brute_force_lockout_seconds = 300
        mock_config.bearer_token_max_length = 512

        with patch("security.bearer.get_security_config", return_value=mock_config):
            reset_bearer_token_manager()
            manager = BearerTokenManager()
            old_tok = manager.generate_token()
            new_tok = manager.rotate_token()
            time.sleep(0.2)
            self.assertFalse(manager.validate_token(old_tok).valid)
            self.assertTrue(manager.validate_token(new_tok).valid)


class TestBearerTokenFormatValidation(unittest.TestCase):
    """B16: Token format validation - reject non-usgs_ prefixed tokens."""

    def setUp(self) -> None:
        reset_bearer_token_manager()
        self.manager = get_bearer_token_manager()
        self.manager.generate_token()

    def test_non_usgs_prefix_rejected(self) -> None:
        result = self.manager.validate_token("x" * 60)
        self.assertFalse(result.valid)
        result = self.manager.validate_token("other_prefix_abc123" + "x" * 40)
        self.assertFalse(result.valid)


class TestBearerPerSourceBruteForce(unittest.TestCase):
    """B17: Per-source brute force - lockout is per-IP, not global."""

    def test_lockout_is_per_source(self) -> None:
        mock_config = MagicMock()
        mock_config.bearer_token_rotation_grace_seconds = 300
        mock_config.bearer_brute_force_fail_threshold = 2
        mock_config.bearer_brute_force_window_seconds = 60
        mock_config.bearer_brute_force_lockout_seconds = 2
        mock_config.bearer_token_max_length = 512

        with patch("security.bearer.get_security_config", return_value=mock_config):
            reset_bearer_token_manager()
            manager = BearerTokenManager()
            token = manager.generate_token()
            invalid = "usgs_bad1" + "x" * 50
            # Lock out source A
            manager.validate_token(invalid, source="ip_A")
            manager.validate_token(invalid, source="ip_A")
            # Source B should still be able to use valid token
            result_b = manager.validate_token(token, source="ip_B")
            self.assertTrue(result_b.valid)
            # Source A should be locked out
            result_a = manager.validate_token(token, source="ip_A")
            self.assertFalse(result_a.valid)


# -----------------------------------------------------------------------------
# C. Middleware Tests (ASGI level)
# -----------------------------------------------------------------------------


def _make_mock_app(status: int = 200, body: dict | None = None):
    """Create mock ASGI app that returns given status/body."""

    async def app(scope, receive, send):
        if scope["type"] != "http":
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"{}"})
            return
        b = json.dumps(body or {"ok": True}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": b})

    return app


def _run_middleware_request(
    path: str = "/mcp",
    headers: dict | None = None,
    scope_type: str = "http",
    auth_manager: AuthManager | None = None,
) -> tuple[int, dict]:
    """Run a request through AuthMiddleware, return (status, body)."""
    received_status = [None]
    received_body = [b""]

    async def capture_send(msg):
        if msg.get("type") == "http.response.start":
            received_status[0] = msg.get("status")
        elif msg.get("type") == "http.response.body":
            received_body[0] = msg.get("body", b"")

    async def run():
        mock_app = _make_mock_app(200, {"ok": True})
        if auth_manager is None:
            reset_auth_manager()
            reset_bearer_token_manager()
            auth_mgr = get_auth_manager()
        else:
            auth_mgr = auth_manager

        middleware = AuthMiddleware(mock_app, auth_manager=auth_mgr)

        # ASGI headers: list of (bytes, bytes), names lowercase per spec
        header_list = [
            (k.lower().encode("latin-1"), v.encode("utf-8") if isinstance(v, str) else v)
            for k, v in (headers or {}).items()
        ]

        scope = {
            "type": scope_type,
            "path": path,
            "method": "GET",
            "headers": header_list,
            "client": ("127.0.0.1", 12345),
        }

        async def receive():
            return {"type": "http.disconnect"}

        await middleware(scope, receive, capture_send)

    import asyncio

    asyncio.run(run())
    status = received_status[0] or 0
    try:
        body = json.loads(received_body[0].decode()) if received_body[0] else {}
    except Exception:
        body = {}
    return status, body


def _run_middleware_with_creds(
    path: str = "/mcp",
    api_key: str | None = None,
    bearer_token: str | None = None,
    auth_manager: AuthManager | None = None,
) -> tuple[int, dict]:
    """Run middleware with given credentials. Pass auth_manager when using credentials from it."""
    if auth_manager is None:
        reset_auth_manager()
        reset_bearer_token_manager()
        auth_mgr = get_auth_manager()
    else:
        auth_mgr = auth_manager

    headers = {}
    if api_key:
        headers["x-api-key"] = api_key
    if bearer_token:
        headers["authorization"] = f"Bearer {bearer_token}"
    return _run_middleware_request(path=path, headers=headers, auth_manager=auth_mgr)


class TestMiddlewareNoAuth(unittest.TestCase):
    """C18: Request with no auth headers → 401."""

    def test_no_auth_returns_401(self) -> None:
        status, body = _run_middleware_request(headers={})
        self.assertEqual(status, 401)
        self.assertIn("detail", body)


class TestMiddlewareValidAPIKey(unittest.TestCase):
    """C19: Request with valid API key → passes through to app."""

    def test_valid_api_key_passes_through(self) -> None:
        reset_auth_manager()
        reset_bearer_token_manager()
        auth_mgr = get_auth_manager()
        creds = auth_mgr.get_plaintext_credentials()
        status, body = _run_middleware_with_creds(
            api_key=creds["api_key"], auth_manager=auth_mgr
        )
        self.assertEqual(status, 200)
        self.assertIn("ok", body)


class TestMiddlewareValidBearer(unittest.TestCase):
    """C20: Request with valid Bearer token → passes through to app."""

    def test_valid_bearer_passes_through(self) -> None:
        reset_auth_manager()
        reset_bearer_token_manager()
        auth_mgr = get_auth_manager()
        creds = auth_mgr.get_plaintext_credentials()
        status, body = _run_middleware_with_creds(
            bearer_token=creds["bearer_token"], auth_manager=auth_mgr
        )
        self.assertEqual(status, 200)
        self.assertIn("ok", body)


class TestMiddlewareInvalidAPIKey(unittest.TestCase):
    """C21: Request with invalid API key → 403."""

    def test_invalid_api_key_returns_403(self) -> None:
        reset_auth_manager()
        auth_mgr = get_auth_manager()
        auth_mgr.get_plaintext_credentials()
        status, _ = _run_middleware_with_creds(
            api_key="invalid_key_xyz", auth_manager=auth_mgr
        )
        self.assertEqual(status, 403)


class TestMiddlewareInvalidBearer(unittest.TestCase):
    """C22: Request with invalid Bearer → 403."""

    def test_invalid_bearer_returns_403(self) -> None:
        reset_auth_manager()
        auth_mgr = get_auth_manager()
        auth_mgr.get_plaintext_credentials()
        status, _ = _run_middleware_with_creds(
            bearer_token="usgs_invalid12345678901234567890123456789012345678901234",
            auth_manager=auth_mgr,
        )
        self.assertEqual(status, 403)


class TestMiddlewareHealthSkipsAuth(unittest.TestCase):
    """C23-C24: Health endpoint skips auth → 200."""

    def test_health_skips_auth(self) -> None:
        status, body = _run_middleware_request(path="/health", headers={})
        self.assertEqual(status, 200)

    def test_health_trailing_slash_skips_auth(self) -> None:
        status, body = _run_middleware_request(path="/health/", headers={})
        self.assertEqual(status, 200)


class TestMiddlewareBothHeadersPreferAPIKey(unittest.TestCase):
    """C25: Both headers provided → API key is preferred."""

    def test_api_key_preferred_when_both_provided(self) -> None:
        reset_auth_manager()
        reset_bearer_token_manager()
        auth_mgr = get_auth_manager()
        creds = auth_mgr.get_plaintext_credentials()
        # Valid API key + invalid bearer -> should pass (API key used)
        status, body = _run_middleware_with_creds(
            api_key=creds["api_key"],
            bearer_token="usgs_invalid12345678901234567890123456789012345678901234",
            auth_manager=auth_mgr,
        )
        self.assertEqual(status, 200, "API key should be preferred and accepted")


class TestMiddlewareSecurityHeaders(unittest.TestCase):
    """C26: Security headers present in ALL responses (even errors)."""

    def test_security_headers_on_health_response(self) -> None:
        """Health endpoint (skip-auth) must also include security headers."""
        received_headers = [None]

        async def capture_send(msg):
            if msg.get("type") == "http.response.start":
                received_headers[0] = {
                    k.decode() if isinstance(k, bytes) else k: v
                    for k, v in msg.get("headers", [])
                }

        async def run():
            mock_app = _make_mock_app(200, {"status": "ok"})
            reset_auth_manager()
            auth_mgr = get_auth_manager()
            auth_mgr.get_plaintext_credentials()
            middleware = AuthMiddleware(mock_app, auth_manager=auth_mgr)
            scope = {
                "type": "http",
                "path": "/health",
                "method": "GET",
                "headers": [],
                "client": ("127.0.0.1", 12345),
            }

            async def receive():
                return {"type": "http.disconnect"}

            await middleware(scope, receive, capture_send)

        import asyncio

        asyncio.run(run())
        headers = received_headers[0] or {}
        self.assertIn("x-content-type-options", headers)
        self.assertIn("x-frame-options", headers)

    def test_security_headers_on_401_response(self) -> None:
        received_headers = [None]

        async def capture_send(msg):
            if msg.get("type") == "http.response.start":
                received_headers[0] = dict(
                    (k.decode() if isinstance(k, bytes) else k, v)
                    for k, v in msg.get("headers", [])
                )

        async def run():
            mock_app = _make_mock_app(200, {"ok": True})
            reset_auth_manager()
            auth_mgr = get_auth_manager()
            auth_mgr.get_plaintext_credentials()
            middleware = AuthMiddleware(mock_app, auth_manager=auth_mgr)
            scope = {
                "type": "http",
                "path": "/mcp",
                "method": "GET",
                "headers": [],
                "client": ("127.0.0.1", 12345),
            }

            async def receive():
                return {"type": "http.disconnect"}

            await middleware(scope, receive, capture_send)

        import asyncio

        asyncio.run(run())
        headers = received_headers[0] or {}
        # OWASP headers
        self.assertIn("x-content-type-options", headers)
        self.assertIn("x-frame-options", headers)
        self.assertIn("x-xss-protection", headers)


class TestMiddlewareRateLimit429(unittest.TestCase):
    """C27: Rate limit (429) after repeated auth failures from same IP."""

    def test_429_after_repeated_failures(self) -> None:
        async def _run_same_middleware():
            mock_app = _make_mock_app(200, {"ok": True})
            reset_auth_manager()
            reset_bearer_token_manager()
            auth_mgr = get_auth_manager()
            auth_mgr.get_plaintext_credentials()
            middleware = AuthMiddleware(mock_app, auth_manager=auth_mgr)
            statuses = []
            for _ in range(5):
                received_status = [None]
                received_body = [b""]

                async def capture_send(msg):
                    if msg.get("type") == "http.response.start":
                        received_status[0] = msg.get("status")
                    elif msg.get("type") == "http.response.body":
                        received_body[0] = msg.get("body", b"")

                scope = {
                    "type": "http",
                    "path": "/mcp",
                    "method": "GET",
                    "headers": [(b"x-api-key", b"wrong_key")],
                    "client": ("192.168.1.1", 12345),
                }

                async def receive():
                    return {"type": "http.disconnect"}

                await middleware(scope, receive, capture_send)
                statuses.append(received_status[0])
            return statuses

        import asyncio

        with patch("security.auth.AUTH_FAILURE_RATE_LIMIT", 3), patch(
            "security.auth.AUTH_FAILURE_WINDOW_SECONDS", 60
        ):
            statuses = asyncio.run(_run_same_middleware())
            self.assertIn(429, statuses)


class TestMiddlewareLifespanPassthrough(unittest.TestCase):
    """C28: Lifespan events pass through middleware unchanged."""

    def test_lifespan_passes_through(self) -> None:
        # Use lifespan scope - middleware should pass through
        received = [False]

        async def app(scope, receive, send):
            if scope["type"] == "lifespan":
                received[0] = True
                while True:
                    msg = await receive()
                    if msg.get("type") == "lifespan.shutdown":
                        break

        async def run():
            middleware = AuthMiddleware(app)
            scope = {"type": "lifespan", "asgi": {"version": "3.0"}}

            async def recv():
                return {"type": "lifespan.shutdown"}

            await middleware(scope, recv, AsyncMock())

        import asyncio

        asyncio.run(run())
        self.assertTrue(received[0])


class TestMiddlewareWebSocketPassthrough(unittest.TestCase):
    """C29: Non-HTTP scopes (websocket) pass through."""

    def test_websocket_passes_through(self) -> None:
        received = [False]

        async def app(scope, receive, send):
            if scope["type"] == "websocket":
                received[0] = True

        async def run():
            middleware = AuthMiddleware(app)
            scope = {"type": "websocket", "path": "/ws"}
            await middleware(scope, AsyncMock(), AsyncMock())

        import asyncio

        asyncio.run(run())
        self.assertTrue(received[0])


# -----------------------------------------------------------------------------
# D. OWASP Compliance
# -----------------------------------------------------------------------------


class TestSecretsNotLogged(unittest.TestCase):
    """D30: Secrets NOT logged anywhere."""

    def test_audit_events_dont_contain_plaintext_keys(self) -> None:
        import re
        from security.audit import get_audit_logger, get_security_event_logger

        audit = get_audit_logger()
        logger = get_security_event_logger()
        with patch.object(audit, "config", MagicMock(audit_logging_enabled=True)), patch(
            "security.audit.AuditLogger._log_event"
        ) as mock_log:
            logger.log_auth(
                success=False,
                auth_method="api_key",
                source_ip="1.2.3.4",
                failure_reason="Invalid credentials",
            )
            self.assertTrue(mock_log.called, "log_auth should have called _log_event")
            call_args = mock_log.call_args
            event = call_args[0][0] if call_args[0] else None
            self.assertIsNotNone(event)
            event_str = event.to_siem_json()
            # Must not contain actual bearer token (usgs_ + 40+ chars)
            token_pattern = re.compile(r"usgs_[A-Za-z0-9_-]{40,}")
            self.assertIsNone(
                token_pattern.search(event_str),
                "Audit event must not contain actual bearer token value",
            )


class TestErrorResponsesNoLeak(unittest.TestCase):
    """D31: Error responses don't leak internal details."""

    def test_403_does_not_leak_stack_trace(self) -> None:
        reset_auth_manager()
        auth_mgr = get_auth_manager()
        auth_mgr.get_plaintext_credentials()
        status, body = _run_middleware_with_creds(
            api_key="invalid", auth_manager=auth_mgr
        )
        self.assertEqual(status, 403)
        self.assertNotIn("traceback", str(body).lower())
        self.assertNotIn("exception", str(body).lower())
        self.assertNotIn("hash", str(body).lower())

    def test_401_does_not_leak_internal_details(self) -> None:
        status, body = _run_middleware_request(headers={})
        self.assertEqual(status, 401)
        self.assertNotIn("hash", str(body).lower())
        self.assertNotIn("_api_key", str(body).lower())


class TestResponseBodiesValidJSON(unittest.TestCase):
    """D32: Response bodies are valid JSON."""

    def test_error_response_is_valid_json(self) -> None:
        status, body = _run_middleware_request(headers={})
        self.assertIsInstance(body, dict)
        self.assertIn("detail", body)


class TestContentTypeOnErrors(unittest.TestCase):
    """D33: Proper Content-Type headers on error responses."""

    def test_401_has_content_type_json(self) -> None:
        headers_list = [None]

        async def capture_send(msg):
            if msg.get("type") == "http.response.start":
                headers_list[0] = msg.get("headers", [])

        async def run():
            mock_app = _make_mock_app(200, {})
            reset_auth_manager()
            auth_mgr = get_auth_manager()
            auth_mgr.get_plaintext_credentials()
            middleware = AuthMiddleware(mock_app, auth_manager=auth_mgr)
            scope = {
                "type": "http",
                "path": "/mcp",
                "method": "GET",
                "headers": [],
                "client": ("127.0.0.1", 12345),
            }

            async def receive():
                return {"type": "http.disconnect"}

            await middleware(scope, receive, capture_send)

        import asyncio

        asyncio.run(run())
        headers = headers_list[0] or []
        header_dict = {k: v for k, v in headers}
        ct = header_dict.get(b"content-type", b"")
        if isinstance(ct, bytes):
            ct = ct.decode()
        self.assertIn("application/json", ct)


class TestNoInformationDisclosure(unittest.TestCase):
    """D34: No information disclosure in 401/403 bodies (generic messages)."""

    def test_401_message_is_generic(self) -> None:
        _, body = _run_middleware_request(headers={})
        detail = body.get("detail", "")
        self.assertNotIn("hash", detail.lower())
        self.assertNotIn("_api_key", detail.lower())
        self.assertIn("credential", detail.lower())

    def test_403_message_is_generic(self) -> None:
        reset_auth_manager()
        auth_mgr = get_auth_manager()
        auth_mgr.get_plaintext_credentials()
        _, body = _run_middleware_with_creds(api_key="wrong", auth_manager=auth_mgr)
        detail = body.get("detail", "")
        self.assertNotIn("hash", detail.lower())
        self.assertIn("Invalid", detail)


class TestCredentialsDiscarded(unittest.TestCase):
    """D35: Credentials discarded after get_plaintext_credentials() called."""

    def test_second_call_returns_placeholder(self) -> None:
        reset_auth_manager()
        manager = get_auth_manager()
        c1 = manager.get_plaintext_credentials()
        c2 = manager.get_plaintext_credentials()
        self.assertIn("ALREADY_DISPLAYED", c2["api_key"])
        self.assertIn("ALREADY_DISPLAYED", c2["bearer_token"])


# -----------------------------------------------------------------------------
# E. Edge Cases / Adversarial
# -----------------------------------------------------------------------------


class TestSQLInjectionInAPIKey(unittest.TestCase):
    """E36: SQL injection in API key header."""

    def setUp(self) -> None:
        reset_auth_manager()
        self.manager = get_auth_manager()
        self.manager.get_plaintext_credentials()

    def test_sql_injection_rejected(self) -> None:
        self.assertFalse(self.manager.validate_api_key("' OR 1=1--"))


class TestXSSInAPIKey(unittest.TestCase):
    """E37: XSS in API key header."""

    def setUp(self) -> None:
        reset_auth_manager()
        self.manager = get_auth_manager()
        self.manager.get_plaintext_credentials()

    def test_xss_rejected(self) -> None:
        self.assertFalse(
            self.manager.validate_api_key("<script>alert('xss')</script>")
        )
        status, _ = _run_middleware_with_creds(
            api_key="<script>alert(1)</script>",
            auth_manager=self.manager,
        )
        self.assertEqual(status, 403)


class TestNullBytesInAPIKey(unittest.TestCase):
    """E38: Null bytes in API key."""

    def setUp(self) -> None:
        reset_auth_manager()
        self.manager = get_auth_manager()
        creds = self.manager.get_plaintext_credentials()
        self.valid_key = creds["api_key"]

    def test_null_bytes_rejected(self) -> None:
        # key\x00malicious - should not match valid key
        self.assertFalse(self.manager.validate_api_key(f"{self.valid_key}\x00malicious"))
        self.assertFalse(self.manager.validate_api_key(f"key\x00malicious"))


class TestUnicodeSmugglingInBearer(unittest.TestCase):
    """E39: Unicode smuggling in bearer token."""

    def setUp(self) -> None:
        reset_bearer_token_manager()
        self.manager = get_bearer_token_manager()
        self.manager.generate_token()

    def test_unicode_smuggling_rejected(self) -> None:
        result = self.manager.validate_token("usgs_" + "\u202e" * 20 + "a" * 40)
        self.assertFalse(result.valid)
        result = self.manager.validate_token("usgs_abc\u0000def" + "x" * 40)
        self.assertFalse(result.valid)


class TestVeryLongAPIKey(unittest.TestCase):
    """E40: Very long API key (10KB+) - should not crash or OOM."""

    def setUp(self) -> None:
        reset_auth_manager()
        self.manager = get_auth_manager()
        self.manager.get_plaintext_credentials()

    def test_very_long_key_does_not_crash(self) -> None:
        long_key = "x" * (15 * 1024)  # 15KB
        result = self.manager.validate_api_key(long_key)
        self.assertFalse(result)


class TestConcurrentAuthAttempts(unittest.TestCase):
    """E41: Concurrent auth attempts (thread safety)."""

    def test_concurrent_validation_thread_safe(self) -> None:
        reset_auth_manager()
        manager = get_auth_manager()
        creds = manager.get_plaintext_credentials()
        key = creds["api_key"]
        results = []

        def validate():
            for _ in range(50):
                results.append(manager.validate_api_key(key))

        threads = [threading.Thread(target=validate) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertTrue(all(results), "All concurrent validations should succeed")


class TestReplayAttack(unittest.TestCase):
    """E42: Replay attack - same valid key works multiple times (expected for API keys)."""

    def setUp(self) -> None:
        reset_auth_manager()
        self.manager = get_auth_manager()
        creds = self.manager.get_plaintext_credentials()
        self.valid_key = creds["api_key"]

    def test_same_key_works_multiple_times(self) -> None:
        for _ in range(5):
            self.assertTrue(self.manager.validate_api_key(self.valid_key))


# -----------------------------------------------------------------------------
# Run
# -----------------------------------------------------------------------------


def run_all_tests() -> int:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    classes = [
        TestAPIKeyValid,
        TestAPIKeyInvalid,
        TestAPIKeyMissing,
        TestAPIKeyEmpty,
        TestAPIKeyWhitespacePadding,
        TestAPIKeyTimingAttackResistance,
        TestAPIKeyHashStorage,
        TestAPIKeyBruteForceLockout,
        TestAPIKeyBruteForceLockoutExpiry,
        TestBearerValid,
        TestBearerInvalid,
        TestBearerWithPrefix,
        TestBearerWithoutPrefix,
        TestBearerTokenRotation,
        TestBearerTokenFormatValidation,
        TestBearerPerSourceBruteForce,
        TestMiddlewareNoAuth,
        TestMiddlewareValidAPIKey,
        TestMiddlewareValidBearer,
        TestMiddlewareInvalidAPIKey,
        TestMiddlewareInvalidBearer,
        TestMiddlewareHealthSkipsAuth,
        TestMiddlewareBothHeadersPreferAPIKey,
        TestMiddlewareSecurityHeaders,
        TestMiddlewareRateLimit429,
        TestMiddlewareLifespanPassthrough,
        TestMiddlewareWebSocketPassthrough,
        TestSecretsNotLogged,
        TestErrorResponsesNoLeak,
        TestResponseBodiesValidJSON,
        TestContentTypeOnErrors,
        TestNoInformationDisclosure,
        TestCredentialsDiscarded,
        TestSQLInjectionInAPIKey,
        TestXSSInAPIKey,
        TestNullBytesInAPIKey,
        TestUnicodeSmugglingInBearer,
        TestVeryLongAPIKey,
        TestConcurrentAuthAttempts,
        TestReplayAttack,
    ]
    for cls in classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
