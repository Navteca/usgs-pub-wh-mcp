"""
Test: Bearer Token Authentication
==================================

Comprehensive tests for security.bearer.BearerTokenManager:

1. Token generation (length, prefix, entropy)
2. Token validation (valid, invalid, empty, malformed)
3. Constant-time comparison (hmac.compare_digest)
4. Token rotation (new works, old during grace, old fails after grace)
5. Brute force protection (lockout after N failures, lockout duration)
6. Token metadata (creation time, last use, validation count)
7. Singleton pattern (get/reset)
8. Edge cases (None, empty, very long, special chars)

Run with:
    uv run python tests/test_bearer_auth.py
"""

import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from security.bearer import (
    BearerTokenManager,
    BearerTokenValidationResult,
    BearerTokenLockedOutError,
    TokenMetadata,
    TOKEN_PREFIX,
    get_bearer_token_manager,
    reset_bearer_token_manager,
)


class TestTokenGeneration(unittest.TestCase):
    """Test token generation: length, prefix, entropy."""

    def setUp(self) -> None:
        reset_bearer_token_manager()
        self.manager = BearerTokenManager()

    def test_token_has_usgs_prefix(self) -> None:
        """Generated token must start with usgs_."""
        token = self.manager.generate_token()
        self.assertTrue(
            token.startswith(TOKEN_PREFIX),
            f"Token should start with {TOKEN_PREFIX!r}, got {token[:20]}...",
        )

    def test_token_length_reasonable(self) -> None:
        """Token from token_urlsafe(48) + prefix should be ~69 chars."""
        token = self.manager.generate_token()
        # token_urlsafe(48) produces 64 chars, prefix is 5
        self.assertGreaterEqual(len(token), 60, "Token too short")
        self.assertLessEqual(len(token), 100, "Token too long")

    def test_token_entropy_urlsafe_chars(self) -> None:
        """Token body should use URL-safe base64 chars (A-Za-z0-9_-)."""
        token = self.manager.generate_token()
        body = token[len(TOKEN_PREFIX) :]
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        for c in body:
            self.assertIn(c, valid_chars, f"Invalid char in token: {c!r}")

    def test_generate_token_stores_hash_only(self) -> None:
        """Manager must not retain plaintext; only hash is stored."""
        token = self.manager.generate_token()
        # We can't directly inspect _current_token_hash, but we verify
        # validation works with the token (hash matches)
        result = self.manager.validate_token(token)
        self.assertTrue(result.valid, "Generated token should validate")

    def test_multiple_generations_produce_different_tokens(self) -> None:
        """Each generate_token() call should produce a unique token."""
        tokens = [self.manager.generate_token() for _ in range(5)]
        self.assertEqual(len(tokens), len(set(tokens)), "Tokens should be unique")


class TestTokenValidation(unittest.TestCase):
    """Test token validation: valid, invalid, empty, malformed."""

    def setUp(self) -> None:
        reset_bearer_token_manager()
        self.manager = BearerTokenManager()
        self.valid_token = self.manager.generate_token()

    def test_valid_token_accepted(self) -> None:
        """Valid token returns valid=True."""
        result = self.manager.validate_token(self.valid_token)
        self.assertTrue(result.valid)

    def test_valid_token_with_bearer_prefix_accepted(self) -> None:
        """Token with 'Bearer ' prefix is accepted."""
        result = self.manager.validate_token(f"Bearer {self.valid_token}")
        self.assertTrue(result.valid)

    def test_invalid_token_rejected(self) -> None:
        """Wrong token returns valid=False."""
        result = self.manager.validate_token("usgs_wrongtoken12345678901234567890123456789012345678901234")
        self.assertFalse(result.valid)

    def test_empty_string_rejected(self) -> None:
        """Empty string returns valid=False."""
        result = self.manager.validate_token("")
        self.assertFalse(result.valid)

    def test_empty_after_strip_rejected(self) -> None:
        """'Bearer ' with no token is rejected."""
        result = self.manager.validate_token("Bearer ")
        self.assertFalse(result.valid)

    def test_none_rejected(self) -> None:
        """None returns valid=False."""
        result = self.manager.validate_token(None)  # type: ignore[arg-type]
        self.assertFalse(result.valid)

    def test_malformed_no_prefix_rejected(self) -> None:
        """Token without usgs_ prefix is rejected."""
        result = self.manager.validate_token("x" * 60)
        self.assertFalse(result.valid)

    def test_malformed_too_short_rejected(self) -> None:
        """Token shorter than min format length is rejected."""
        result = self.manager.validate_token("usgs_short")
        self.assertFalse(result.valid)

    def test_special_chars_in_body_rejected(self) -> None:
        """Token with invalid chars (e.g. spaces, <>) is rejected."""
        bad = "usgs_" + "a" * 39 + "!@#"
        result = self.manager.validate_token(bad)
        self.assertFalse(result.valid)


class TestConstantTimeComparison(unittest.TestCase):
    """Verify hmac.compare_digest is used for constant-time comparison."""

    def setUp(self) -> None:
        reset_bearer_token_manager()
        self.manager = BearerTokenManager()
        self.valid_token = self.manager.generate_token()

    def test_hmac_compare_digest_used(self) -> None:
        """validate_token must use hmac.compare_digest (mock to verify)."""
        with patch("security.bearer.hmac.compare_digest") as mock_compare:
            mock_compare.return_value = True
            result = self.manager.validate_token(self.valid_token)
            self.assertTrue(result.valid)
            mock_compare.assert_called()

    def test_hmac_compare_digest_called_on_valid_format(self) -> None:
        """compare_digest is only called after format validation."""
        with patch("security.bearer.hmac.compare_digest") as mock_compare:
            self.manager.validate_token("")  # Invalid format
            mock_compare.assert_not_called()


class TestTokenRotation(unittest.TestCase):
    """Test token rotation: new works, old during grace, old fails after grace."""

    def setUp(self) -> None:
        reset_bearer_token_manager()
        self.manager = BearerTokenManager()
        self.old_token = self.manager.generate_token()

    def test_rotate_returns_new_token(self) -> None:
        """rotate_token returns a new token string."""
        new_token = self.manager.rotate_token()
        self.assertIsInstance(new_token, str)
        self.assertTrue(new_token.startswith(TOKEN_PREFIX))
        self.assertNotEqual(new_token, self.old_token)

    def test_new_token_works_after_rotation(self) -> None:
        """After rotation, new token validates."""
        new_token = self.manager.rotate_token()
        result = self.manager.validate_token(new_token)
        self.assertTrue(result.valid)

    def test_old_token_works_during_grace_period(self) -> None:
        """During grace period, old token still validates."""
        new_token = self.manager.rotate_token()
        result_old = self.manager.validate_token(self.old_token)
        self.assertTrue(result_old.valid, "Old token should work during grace")
        result_new = self.manager.validate_token(new_token)
        self.assertTrue(result_new.valid)

    def test_old_token_fails_after_grace_period(self) -> None:
        """After grace period, only new token works."""
        # Create manager with short grace period via patched config
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
            time.sleep(0.2)  # Wait past grace
            result_old = manager.validate_token(old_tok)
            self.assertFalse(result_old.valid, "Old token should fail after grace")
            result_new = manager.validate_token(new_tok)
            self.assertTrue(result_new.valid, "New token should still work")


class TestBruteForceProtection(unittest.TestCase):
    """Test brute force protection: lockout after N failures, lockout duration."""

    def _make_manager_with_config(
        self,
        fail_threshold: int = 2,
        window_seconds: int = 60,
        lockout_seconds: float = 5,
    ) -> BearerTokenManager:
        """Create manager with custom brute force config (frozen config can't be patched)."""
        mock_config = MagicMock()
        mock_config.bearer_token_rotation_grace_seconds = 300
        mock_config.bearer_brute_force_fail_threshold = fail_threshold
        mock_config.bearer_brute_force_window_seconds = window_seconds
        mock_config.bearer_brute_force_lockout_seconds = lockout_seconds
        mock_config.bearer_token_max_length = 512

        with patch("security.bearer.get_security_config", return_value=mock_config):
            reset_bearer_token_manager()
            return BearerTokenManager()

    def test_lockout_after_threshold_failures(self) -> None:
        """After N failed attempts in window, source is locked out."""
        manager = self._make_manager_with_config(
            fail_threshold=3,
            lockout_seconds=2,
        )
        source = "test_source_1"
        invalid = "usgs_invalidtoken12345678901234567890123456789012345678901234"
        for _ in range(3):
            manager.validate_token(invalid, source=source)
        result = manager.validate_token(
            "usgs_anotherinvalid12345678901234567890123456789012345678901234",
            source=source,
        )
        self.assertFalse(result.valid)
        self.assertIsNotNone(result.lockout_remaining_seconds)
        self.assertGreater(result.lockout_remaining_seconds, 0)

    def test_lockout_remaining_returned(self) -> None:
        """get_lockout_remaining_seconds returns time when locked out."""
        manager = self._make_manager_with_config(
            fail_threshold=2,
            lockout_seconds=5,
        )
        source = "test_source_2"
        manager.validate_token("usgs_bad1" + "x" * 50, source=source)
        manager.validate_token("usgs_bad2" + "x" * 50, source=source)
        remaining = manager.get_lockout_remaining_seconds(source)
        self.assertIsNotNone(remaining)
        self.assertGreater(remaining, 0)

    def test_lockout_expires_after_duration(self) -> None:
        """Lockout expires after configured duration."""
        manager = self._make_manager_with_config(
            fail_threshold=2,
            lockout_seconds=0.2,
        )
        source = "test_source_3"
        manager.validate_token("usgs_bad1" + "x" * 50, source=source)
        manager.validate_token("usgs_bad2" + "x" * 50, source=source)
        time.sleep(0.3)
        remaining = manager.get_lockout_remaining_seconds(source)
        self.assertIsNone(remaining)


class TestTokenMetadata(unittest.TestCase):
    """Test token metadata: creation time, last use, validation count."""

    def setUp(self) -> None:
        reset_bearer_token_manager()
        self.manager = BearerTokenManager()
        self.token = self.manager.generate_token()

    def test_metadata_has_created_at(self) -> None:
        """Metadata includes creation timestamp."""
        meta = self.manager.get_metadata()
        self.assertIsNotNone(meta.created_at)
        self.assertGreater(meta.created_at, 0)

    def test_metadata_last_use_updated_on_success(self) -> None:
        """Last successful use is updated when token validates."""
        self.manager.validate_token(self.token)
        meta = self.manager.get_metadata()
        self.assertIsNotNone(meta.last_successful_use)
        self.assertGreaterEqual(meta.last_successful_use, meta.created_at)

    def test_metadata_validation_count_increments(self) -> None:
        """Successful validation count increments."""
        for _ in range(3):
            self.manager.validate_token(self.token)
        meta = self.manager.get_metadata()
        self.assertEqual(meta.successful_validations_count, 3)


class TestSingletonPattern(unittest.TestCase):
    """Test singleton getter and reset."""

    def test_get_returns_same_instance(self) -> None:
        """get_bearer_token_manager returns same instance."""
        reset_bearer_token_manager()
        a = get_bearer_token_manager()
        b = get_bearer_token_manager()
        self.assertIs(a, b)

    def test_reset_clears_singleton(self) -> None:
        """reset_bearer_token_manager clears the singleton."""
        m1 = get_bearer_token_manager()
        reset_bearer_token_manager()
        m2 = get_bearer_token_manager()
        self.assertIsNot(m1, m2)


class TestEdgeCases(unittest.TestCase):
    """Edge cases: None, empty, very long tokens, special chars."""

    def setUp(self) -> None:
        reset_bearer_token_manager()
        self.manager = BearerTokenManager()

    def test_none_token(self) -> None:
        """None token is rejected without exception."""
        result = self.manager.validate_token(None)  # type: ignore[arg-type]
        self.assertFalse(result.valid)

    def test_empty_string(self) -> None:
        """Empty string is rejected."""
        result = self.manager.validate_token("")
        self.assertFalse(result.valid)

    def test_very_long_token_rejected(self) -> None:
        """Token longer than max_length is rejected early."""
        long_token = "usgs_" + "a" * 600
        result = self.manager.validate_token(long_token)
        self.assertFalse(result.valid)

    def test_whitespace_only(self) -> None:
        """Whitespace-only input is rejected."""
        result = self.manager.validate_token("   ")
        self.assertFalse(result.valid)

    def test_bearer_prefix_only(self) -> None:
        """'Bearer' with no value is rejected."""
        result = self.manager.validate_token("Bearer")
        self.assertFalse(result.valid)


class TestBearerTokenLockedOutError(unittest.TestCase):
    """Test BearerTokenLockedOutError exception."""

    def test_exception_has_retry_after(self) -> None:
        """BearerTokenLockedOutError has retry_after_seconds attribute."""
        err = BearerTokenLockedOutError(120.5)
        self.assertEqual(err.retry_after_seconds, 120.5)
        self.assertIn("Retry", str(err))


def run_all_tests() -> int:
    """Run all bearer auth tests."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for cls in [
        TestTokenGeneration,
        TestTokenValidation,
        TestConstantTimeComparison,
        TestTokenRotation,
        TestBruteForceProtection,
        TestTokenMetadata,
        TestSingletonPattern,
        TestEdgeCases,
        TestBearerTokenLockedOutError,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
