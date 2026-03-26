"""
Context size limits for the MCP server.

Implements protection against resource exhaustion by enforcing limits on
request sizes, response sizes, and individual field lengths.
"""

import json
import logging
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

logger = logging.getLogger(__name__)


class ContextLimitExceededError(Exception):
    """Raised when a context size limit is exceeded."""

    def __init__(self, message: str, limit_type: str):
        super().__init__(message)
        self.limit_type = limit_type


@dataclass(frozen=True)
class ContextSizeLimits:
    """
    Configurable limits for context size management.

    All values are in bytes unless otherwise specified.
    """

    max_request_size_bytes: int = 1 * 1024 * 1024  # 1 MB
    max_response_size_bytes: int = 5 * 1024 * 1024  # 5 MB
    max_total_results: int = 1000
    max_abstract_length: int = 10000
    max_field_length: int = 5000


class ContextLimiter:
    """
    Enforces context size limits on requests and responses.
    """

    def __init__(self, limits: ContextSizeLimits | None = None):
        self.limits = limits or ContextSizeLimits()

    def get_size_bytes(self, data: Any) -> int:
        """
        Calculate the approximate size of data in bytes.

        Args:
            data: Any JSON-serializable data (dict, list, str, etc.)

        Returns:
            Approximate size in bytes as if serialized to JSON.
        """
        try:
            serialized = json.dumps(data, default=str, separators=(",", ":"))
            return len(serialized.encode("utf-8"))
        except (TypeError, ValueError) as e:
            logger.warning(f"Could not serialize data for size calculation: {e}")
            # Fallback: estimate from repr
            return len(repr(data).encode("utf-8"))

    def check_request_size(self, data: dict) -> None:
        """
        Validate that request data does not exceed the maximum request size.

        Args:
            data: Request data to validate (typically params dict)

        Raises:
            ContextLimitExceededError: If request size exceeds limit
        """
        size = self.get_size_bytes(data)
        if size > self.limits.max_request_size_bytes:
            raise ContextLimitExceededError(
                f"Request size {size} bytes exceeds limit of "
                f"{self.limits.max_request_size_bytes} bytes",
                limit_type="request_size",
            )

    def enforce_field_limits(
        self,
        data: dict,
        *,
        abstract_fields: set[str] | None = None,
        truncation_suffix: str = "...",
    ) -> dict:
        """
        Truncate individual string fields that exceed max_field_length.

        Args:
            data: Dictionary to process (shallow copy; nested objects not modified)
            abstract_fields: Field names that use max_abstract_length (default: abstract-like fields)
            truncation_suffix: Suffix to append when truncating (default: "...")

        Returns:
            New dict with truncated string values
        """
        abstract_fields = abstract_fields or {
            "docAbstract",
            "abstract",
            "abstract_snippet",
        }
        result = {}
        for key, value in data.items():
            if isinstance(value, str):
                max_len = (
                    self.limits.max_abstract_length
                    if key in abstract_fields
                    else self.limits.max_field_length
                )
                if len(value) > max_len:
                    result[key] = value[: max_len - len(truncation_suffix)] + truncation_suffix
                else:
                    result[key] = value
            else:
                result[key] = value
        return result

    def truncate_response(
        self,
        data: dict,
        *,
        records_key: str = "records",
    ) -> dict:
        """
        Safely truncate oversized responses.

        - If total size exceeds max_response_size_bytes, truncates the records list
        - Limits records to max_total_results
        - Applies enforce_field_limits to each record

        Args:
            data: Response dict (typically from API)
            records_key: Key containing the list of records (default: "records")

        Returns:
            New dict with enforced limits
        """
        result = dict(data)
        if records_key not in result:
            # No records to truncate; still enforce total size
            size = self.get_size_bytes(result)
            if size > self.limits.max_response_size_bytes:
                logger.warning(
                    f"Response without records exceeds size limit: {size} > "
                    f"{self.limits.max_response_size_bytes}"
                )
            return result

        records = list(result.get(records_key, []))
        if not records:
            return result

        # Limit number of records
        if len(records) > self.limits.max_total_results:
            records = records[: self.limits.max_total_results]
            logger.info(
                f"Truncated records to max_total_results={self.limits.max_total_results}"
            )

        # Apply field limits to each record
        truncated_records = []
        total_size = self.get_size_bytes(
            {k: v for k, v in result.items() if k != records_key}
        )
        for record in records:
            if isinstance(record, dict):
                truncated = self.enforce_field_limits(record)
            else:
                truncated = record
            truncated_records.append(truncated)
            total_size += self.get_size_bytes(truncated)
            if total_size > self.limits.max_response_size_bytes:
                # Stop adding records once we hit size limit
                logger.warning(
                    f"Response truncated at size limit: ~{total_size} bytes"
                )
                break

        result[records_key] = truncated_records
        return result


@lru_cache(maxsize=1)
def get_context_limiter() -> ContextLimiter:
    """
    Get a ContextLimiter configured from SecurityConfig.
    Uses late import to avoid circular dependency.
    Cached for consistency with get_security_config.
    """
    from .config import get_security_config

    config = get_security_config()
    limits = ContextSizeLimits(
        max_request_size_bytes=config.max_request_size_bytes,
        max_response_size_bytes=config.max_response_size_bytes,
        max_total_results=config.max_total_results,
        max_abstract_length=config.max_abstract_length,
        max_field_length=config.max_field_length,
    )
    return ContextLimiter(limits)
