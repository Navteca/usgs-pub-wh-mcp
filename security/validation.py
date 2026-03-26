"""
Input validation and sanitization module.

Implements defense against:
- Prompt injection through malicious input
- Command injection via unsanitized parameters
- SQL injection patterns (though this API doesn't use SQL directly)
- Resource exhaustion through oversized inputs

Based on OWASP input validation best practices and MCP security guidelines.
"""

import re
import html
import unicodedata
from dataclasses import dataclass
from typing import Any, Optional
from .config import get_security_config
from .audit import get_audit_logger, get_security_event_logger


class ValidationError(Exception):
    """Raised when input validation fails."""

    def __init__(
        self,
        field: str,
        message: str,
        value: Any = None,
        pattern_detected: Optional[str] = None,
        sanitized_value_preview: Optional[str] = None,
    ):
        self.field = field
        self.message = message
        self.value = value
        self.pattern_detected = pattern_detected
        self.sanitized_value_preview = sanitized_value_preview
        super().__init__(f"Validation error for '{field}': {message}")


@dataclass
class ValidationResult:
    """Result of input validation."""
    is_valid: bool
    sanitized_value: Any
    warnings: list[str]


class InputValidator:
    """
    Validates and sanitizes all input parameters.
    
    Security controls implemented:
    1. Length limits to prevent resource exhaustion
    2. Character allowlists to prevent injection attacks
    3. Type validation for all parameters
    4. Range validation for numeric values
    5. Pattern matching for structured IDs
    """
    
    # Patterns for detecting potential injection attempts (pattern, injection_type)
    INJECTION_PATTERNS: list[tuple[str, str]] = [
        (r"<script", "XSS"),
        (r"javascript:", "XSS"),
        (r"on\w+\s*=", "XSS_EVENT_HANDLER"),
        (r";\s*(?:drop|delete|truncate|alter|create|insert|update)\s", "SQL"),
        (r"\$\{", "TEMPLATE"),
        (r"\{\{", "TEMPLATE"),
        (r"__proto__", "PROTOTYPE_POLLUTION"),
        (r"constructor\s*\(", "PROTOTYPE_POLLUTION"),
    ]

    # Compiled patterns for efficiency
    _injection_regex: re.Pattern | None = None
    _injection_type_map: dict[int, str] = {}  # group index -> injection type
    
    def __init__(self):
        self.config = get_security_config()
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns for efficient reuse."""
        patterns = [p for p, _ in self.INJECTION_PATTERNS]
        combined_pattern = "|".join(f"({p})" for p in patterns)
        self._injection_regex = re.compile(combined_pattern, re.IGNORECASE)
        self._injection_type_map = {
            i: self.INJECTION_PATTERNS[i][1] for i in range(len(self.INJECTION_PATTERNS))
        }
        self._publication_id_regex = re.compile(self.config.allowed_publication_id_pattern)
        self._query_regex = re.compile(self.config.allowed_query_pattern)

    def _log_validation_failure(
        self,
        field: str,
        message: str,
        pattern_detected: Optional[str] = None,
        sanitized_value_preview: Optional[str] = None,
        tool_name: str = "input_validator",
    ) -> None:
        """
        Log validation failure with detailed context for incident response.
        Captures: field name, pattern detected, sanitized value preview.
        """
        try:
            get_audit_logger().log_validation_error(
                tool_name=tool_name,
                field=field,
                message=message,
                pattern_detected=pattern_detected,
                sanitized_value_preview=sanitized_value_preview,
            )
        except Exception:
            pass  # Don't let logging failures break validation

    def _check_injection_patterns(self, value: str, field: str) -> None:
        """Check for common injection patterns and log if detected."""
        if not self._injection_regex:
            return
        match = self._injection_regex.search(value)
        if match:
            # Determine which pattern matched and its type
            injection_type = "UNKNOWN"
            pattern_detected = "malicious_pattern"
            for i, group in enumerate(match.groups()):
                if group is not None and i in self._injection_type_map:
                    injection_type = self._injection_type_map[i]
                    pattern_detected = group[:50] if group else "matched"
                    break

            self.log_injection_attempt(
                injection_type=injection_type,
                field=field,
                pattern_detected=pattern_detected,
                value_preview=value[:100].replace("<", "&lt;").replace(">", "&gt;"),
            )
            raise ValidationError(
                field,
                f"Input contains potentially malicious patterns (detected: {injection_type})",
                "[REDACTED]",
            )

    def log_injection_attempt(
        self,
        injection_type: str,
        field: str,
        pattern_detected: str,
        value_preview: Optional[str] = None,
        tool_name: str = "validation",
    ) -> None:
        """
        Log a potential injection attack attempt for security monitoring.
        Logs the specific injection pattern: XSS, SQL, TEMPLATE, PROTOTYPE_POLLUTION, etc.

        Args:
            injection_type: XSS, SQL, TEMPLATE, PROTOTYPE_POLLUTION, etc.
            field: Field name where injection was detected
            pattern_detected: The specific pattern that triggered detection
            value_preview: Sanitized preview of the value (first 100 chars, HTML-escaped)
            tool_name: Tool or component where detection occurred
        """
        try:
            get_security_event_logger().log_injection_attempt(
                injection_type=injection_type,
                field=field,
                pattern_detected=pattern_detected,
                value_preview=value_preview,
                tool_name=tool_name,
            )
        except Exception:
            pass  # Don't let logging failures break validation
    
    def _sanitize_string(self, value: str) -> str:
        """
        Sanitize a string value.
        
        - Removes null bytes (can bypass validation)
        - Normalizes unicode (prevents homograph attacks)
        - Strips leading/trailing whitespace
        
        NOTE: HTML escaping is NOT applied here. It was previously applied
        before regex validation, which caused legitimate queries containing
        apostrophes, ampersands, or quotes to be rejected (e.g., "water's
        edge" became "water&#x27;s edge" which failed the allowed char regex).
        HTML escaping is now only used in logging contexts.
        """
        if not isinstance(value, str):
            value = str(value)

        # Remove null bytes (can bypass validation)
        value = value.replace("\x00", "")

        # Normalize unicode to prevent homograph attacks
        value = unicodedata.normalize("NFKC", value)
        
        # Strip whitespace
        value = value.strip()
        
        return value
    
    def validate_query(self, query: str | None, field: str = "query") -> str | None:
        """
        Validate a search query string.
        
        Args:
            query: The query string to validate
            field: Field name for error messages
            
        Returns:
            Sanitized query string or None
            
        Raises:
            ValidationError: If validation fails
        """
        if query is None:
            return None
        
        if not isinstance(query, str):
            self._log_validation_failure(field, "Must be a string")
            raise ValidationError(field, "Must be a string", type(query).__name__)
        
        query = self._sanitize_string(query)
        
        if not query:
            return None
        
        # Check length
        if len(query) > self.config.max_query_length:
            safe_preview = html.escape(query[:50], quote=True)
            if len(query) > 50:
                safe_preview += "..."
            self._log_validation_failure(
                field,
                f"Exceeds maximum length of {self.config.max_query_length} characters",
                pattern_detected="length_exceeded",
                sanitized_value_preview=safe_preview,
            )
            raise ValidationError(
                field,
                f"Exceeds maximum length of {self.config.max_query_length} characters",
                f"[{len(query)} chars]",
                sanitized_value_preview=safe_preview,
            )
        
        # Check for injection patterns
        self._check_injection_patterns(query, field)
        
        # Validate against allowed character pattern
        if not self._query_regex.match(query):
            safe_preview = html.escape(query[:50], quote=True)
            if len(query) > 50:
                safe_preview += "..."
            self._log_validation_failure(
                field,
                "Query contains characters outside the allowed set",
                pattern_detected="invalid_characters",
                sanitized_value_preview=safe_preview,
            )
            raise ValidationError(
                field,
                "Query contains invalid characters. "
                "Only alphanumeric characters, spaces, and basic punctuation are allowed.",
                "[REDACTED]",
                pattern_detected="invalid_characters",
                sanitized_value_preview=safe_preview,
            )
        
        return query
    
    def validate_publication_id(self, pub_id: str, field: str = "publication_id") -> str:
        """
        Validate a publication ID.
        
        Publication IDs should be alphanumeric with hyphens/underscores only.
        
        Args:
            pub_id: The publication ID to validate
            field: Field name for error messages
            
        Returns:
            Sanitized publication ID
            
        Raises:
            ValidationError: If validation fails
        """
        if not isinstance(pub_id, str):
            self._log_validation_failure(field, "Must be a string")
            raise ValidationError(field, "Must be a string", type(pub_id).__name__)
        
        pub_id = self._sanitize_string(pub_id)
        
        if not pub_id:
            self._log_validation_failure(field, "Cannot be empty")
            raise ValidationError(field, "Cannot be empty")
        
        if len(pub_id) > 100:
            self._log_validation_failure(
                field,
                "Exceeds maximum length of 100 characters",
                sanitized_value_preview=html.escape(pub_id[:50], quote=True),
            )
            raise ValidationError(field, "Exceeds maximum length of 100 characters")
        
        # Strict validation for IDs - must match pattern exactly
        if not self._publication_id_regex.match(pub_id):
            safe_preview = html.escape(pub_id[:50], quote=True)
            if len(pub_id) > 50:
                safe_preview += "..."
            self._log_validation_failure(
                field,
                "Invalid format. Must contain only alphanumeric characters, hyphens, and underscores",
                pattern_detected="invalid_characters",
                sanitized_value_preview=safe_preview,
            )
            raise ValidationError(
                field,
                "Invalid format. Must contain only alphanumeric characters, hyphens, and underscores",
                "[REDACTED]",
                pattern_detected="invalid_characters",
                sanitized_value_preview=safe_preview,
            )
        
        return pub_id
    
    def validate_year(self, year: int | None, field: str = "year") -> int | None:
        """
        Validate a year value.
        
        Args:
            year: The year to validate
            field: Field name for error messages
            
        Returns:
            Validated year or None
            
        Raises:
            ValidationError: If validation fails
        """
        if year is None:
            return None
        
        if not isinstance(year, int):
            try:
                year = int(year)
            except (ValueError, TypeError):
                self._log_validation_failure(field, "Must be an integer")
                raise ValidationError(field, "Must be an integer", type(year).__name__)
        
        if year < self.config.min_year or year > self.config.max_year:
            self._log_validation_failure(
                field,
                f"Must be between {self.config.min_year} and {self.config.max_year}",
                pattern_detected="out_of_range",
            )
            raise ValidationError(
                field,
                f"Must be between {self.config.min_year} and {self.config.max_year}",
                year
            )
        
        return year
    
    def validate_page_size(self, page_size: int, field: str = "page_size") -> int:
        """
        Validate page size parameter.
        
        Args:
            page_size: The page size to validate
            field: Field name for error messages
            
        Returns:
            Validated page size (capped at max)
            
        Raises:
            ValidationError: If validation fails
        """
        if not isinstance(page_size, int):
            try:
                page_size = int(page_size)
            except (ValueError, TypeError):
                self._log_validation_failure(field, "Must be an integer")
                raise ValidationError(field, "Must be an integer", type(page_size).__name__)
        
        if page_size < 1:
            self._log_validation_failure(field, "Must be at least 1", pattern_detected="out_of_range")
            raise ValidationError(field, "Must be at least 1", page_size)
        
        # Cap at maximum - don't error, just limit
        return min(page_size, self.config.max_page_size)
    
    def validate_page_number(self, page_number: int, field: str = "page_number") -> int:
        """
        Validate page number parameter.
        
        Args:
            page_number: The page number to validate
            field: Field name for error messages
            
        Returns:
            Validated page number
            
        Raises:
            ValidationError: If validation fails
        """
        if not isinstance(page_number, int):
            try:
                page_number = int(page_number)
            except (ValueError, TypeError):
                self._log_validation_failure(field, "Must be an integer")
                raise ValidationError(field, "Must be an integer", type(page_number).__name__)
        
        if page_number < 1:
            self._log_validation_failure(field, "Must be at least 1", pattern_detected="out_of_range")
            raise ValidationError(field, "Must be at least 1", page_number)
        
        # Reasonable upper limit to prevent abuse
        if page_number > 10000:
            self._log_validation_failure(
                field,
                "Exceeds maximum page number",
                pattern_detected="out_of_range",
            )
            raise ValidationError(field, "Exceeds maximum page number", page_number)
        
        return page_number
    
    def validate_days(self, days: int, field: str = "days") -> int:
        """
        Validate a days parameter (for recent/modified queries).
        
        Args:
            days: The number of days to validate
            field: Field name for error messages
            
        Returns:
            Validated days value
            
        Raises:
            ValidationError: If validation fails
        """
        if not isinstance(days, int):
            try:
                days = int(days)
            except (ValueError, TypeError):
                self._log_validation_failure(field, "Must be an integer")
                raise ValidationError(field, "Must be an integer", type(days).__name__)
        
        if days < 1:
            self._log_validation_failure(field, "Must be at least 1", pattern_detected="out_of_range")
            raise ValidationError(field, "Must be at least 1", days)
        
        # Maximum 10 years lookback
        if days > 3650:
            self._log_validation_failure(
                field,
                "Cannot exceed 3650 days (10 years)",
                pattern_detected="out_of_range",
            )
            raise ValidationError(field, "Cannot exceed 3650 days (10 years)", days)
        
        return days
    
    def validate_type_id(self, type_id: int, field: str = "type_id") -> int:
        """
        Validate a publication type/subtype ID.
        
        Args:
            type_id: The type ID to validate
            field: Field name for error messages
            
        Returns:
            Validated type ID
            
        Raises:
            ValidationError: If validation fails
        """
        if not isinstance(type_id, int):
            try:
                type_id = int(type_id)
            except (ValueError, TypeError):
                self._log_validation_failure(field, "Must be an integer")
                raise ValidationError(field, "Must be an integer", type(type_id).__name__)
        
        if type_id < 0:
            self._log_validation_failure(field, "Must be non-negative", pattern_detected="out_of_range")
            raise ValidationError(field, "Must be non-negative", type_id)
        
        # Reasonable upper bound
        if type_id > 100000:
            self._log_validation_failure(field, "Invalid ID range", pattern_detected="out_of_range")
            raise ValidationError(field, "Invalid ID range", type_id)
        
        return type_id
