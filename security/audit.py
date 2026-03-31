"""
Audit logging module for security monitoring and compliance.

Implements comprehensive logging for:
- All tool invocations with parameters
- Request/response metadata
- Security events (rate limits, validation failures)
- Error conditions

Logs are structured JSON for easy parsing by SIEM systems.

Features:
- Security context: source_ip, user_agent (placeholders [NOT_AVAILABLE] when unknown)
- Event severity levels: INFO, WARNING, ERROR, CRITICAL
- Event categories: SECURITY, PERFORMANCE, ACCESS, SYSTEM
- SIEM-ready structured format with dual timestamps (ISO8601, Unix epoch)
- Request ID tracking that persists across tool calls (call begin_session() at session start)
- Log rotation hints for SIEM integration
"""

import json
import logging
import time
import hashlib
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from contextlib import contextmanager
from .config import get_security_config


class SecurityEventCategory(str, Enum):
    """
    Security event categories for SIEM filtering and incident response.
    Use these tags to categorize all security-related log events.
    """
    AUTHORIZATION = "AUTHORIZATION"
    INPUT_VALIDATION = "INPUT_VALIDATION"
    RATE_LIMITING = "RATE_LIMITING"
    NETWORK_SECURITY = "NETWORK_SECURITY"
    DATA_ACCESS = "DATA_ACCESS"
    CONFIGURATION = "CONFIGURATION"


class AuditEventType(str, Enum):
    """Types of audit events."""
    TOOL_INVOCATION = "tool_invocation"
    TOOL_SUCCESS = "tool_success"
    TOOL_ERROR = "tool_error"
    RATE_LIMIT = "rate_limit"
    VALIDATION_ERROR = "validation_error"
    SECURITY_VIOLATION = "security_violation"
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    CIRCUIT_BREAKER = "circuit_breaker"
    INJECTION_ATTEMPT = "injection_attempt"
    ACCESS_DENIED = "access_denied"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    CONFIG_CHANGE = "config_change"
    POTENTIAL_ATTACK = "potential_attack"


class AuditSeverity(str, Enum):
    """Severity levels for audit events."""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class AuditEventCategory(str, Enum):
    """Categories for filtering and grouping audit events."""
    SECURITY = "SECURITY"
    PERFORMANCE = "PERFORMANCE"
    ACCESS = "ACCESS"
    SYSTEM = "SYSTEM"


# Mapping from event type to (severity, category)
_EVENT_TYPE_METADATA: dict[AuditEventType, tuple[AuditSeverity, AuditEventCategory]] = {
    AuditEventType.TOOL_INVOCATION: (AuditSeverity.INFO, AuditEventCategory.ACCESS),
    AuditEventType.TOOL_SUCCESS: (AuditSeverity.INFO, AuditEventCategory.ACCESS),
    AuditEventType.TOOL_ERROR: (AuditSeverity.ERROR, AuditEventCategory.ACCESS),
    AuditEventType.RATE_LIMIT: (AuditSeverity.WARNING, AuditEventCategory.PERFORMANCE),
    AuditEventType.VALIDATION_ERROR: (AuditSeverity.WARNING, AuditEventCategory.ACCESS),
    AuditEventType.SECURITY_VIOLATION: (AuditSeverity.CRITICAL, AuditEventCategory.SECURITY),
    AuditEventType.SESSION_START: (AuditSeverity.INFO, AuditEventCategory.ACCESS),
    AuditEventType.SESSION_END: (AuditSeverity.INFO, AuditEventCategory.ACCESS),
    AuditEventType.CIRCUIT_BREAKER: (AuditSeverity.WARNING, AuditEventCategory.SYSTEM),
    AuditEventType.INJECTION_ATTEMPT: (AuditSeverity.CRITICAL, AuditEventCategory.SECURITY),
    AuditEventType.ACCESS_DENIED: (AuditSeverity.WARNING, AuditEventCategory.SECURITY),
    AuditEventType.SUSPICIOUS_ACTIVITY: (AuditSeverity.WARNING, AuditEventCategory.SECURITY),
    AuditEventType.CONFIG_CHANGE: (AuditSeverity.WARNING, AuditEventCategory.SYSTEM),
    AuditEventType.POTENTIAL_ATTACK: (AuditSeverity.CRITICAL, AuditEventCategory.SECURITY),
}

# SIEM integration metadata and log rotation hints
SIEM_METADATA = {
    "source": "usgs_mcp_audit",
    "schema_version": "1.0",
    "log_rotation": {
        "hint": "daily",
        "retention_recommendation_days": 90,
        "format": "jsonl",
        "compression_supported": True,
        "max_file_size_mb": 100,
        "naming_pattern": "audit-{YYYY-MM-DD}.jsonl",
        "max_entries_per_file_hint": 500000,
    },
}


def _now_iso8601() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _now_epoch() -> float:
    """Return current UTC time as Unix epoch (seconds with fractional part)."""
    return time.time()


@dataclass
class AuditEvent:
    """
    Structured audit event for logging.
    
    All events include a correlation ID for tracing across tool calls,
    request_id for session-level tracking, and dual timestamps for compatibility.
    """
    event_type: AuditEventType
    tool_name: str
    timestamp: str = field(default_factory=_now_iso8601)
    timestamp_epoch: Optional[float] = field(default_factory=_now_epoch)
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    request_id: Optional[str] = None
    severity: Optional[AuditSeverity] = None
    category: Optional[AuditEventCategory] = None
    duration_ms: Optional[float] = None
    parameters: Optional[dict] = None
    result_count: Optional[int] = None
    result_size_bytes: Optional[int] = None
    error_message: Optional[str] = None
    error_type: Optional[str] = None
    client_info: Optional[dict] = None
    security_context: Optional[dict] = None
    security_category: Optional[str] = None  # SecurityEventCategory for SIEM filtering
    actionable_info: Optional[dict] = None  # For incident response

    def _get_severity_and_category(self) -> tuple[AuditSeverity, AuditEventCategory]:
        """Resolve severity and category from event type if not explicitly set."""
        if self.severity is not None and self.category is not None:
            return self.severity, self.category
        severity, category = _EVENT_TYPE_METADATA.get(
            self.event_type, (AuditSeverity.INFO, AuditEventCategory.SYSTEM)
        )
        return self.severity or severity, self.category or category
    
    def to_dict(self) -> dict:
        """Convert to dictionary, excluding None values. Always includes severity and category."""
        severity, category = self._get_severity_and_category()
        d = asdict(self)
        result = {}
        for k, v in d.items():
            if v is None:
                continue
            if k == "severity":
                result[k] = severity.value
            elif k == "category":
                result[k] = category.value
            elif isinstance(v, Enum):
                result[k] = v.value
            else:
                result[k] = v
        # Always include severity and category for filtering (resolve from event type if not set)
        result["severity"] = severity.value
        result["category"] = category.value
        return result
    
    def to_json(self) -> str:
        """Convert to JSON string (backward compatible)."""
        return json.dumps(self.to_dict(), default=str)
    
    def to_siem_format(self) -> dict:
        """
        Convert to SIEM-ready structured format with all metadata.
        
        Includes dual timestamps, severity, category, request_id, security context,
        and log rotation hints for integration with Splunk, ELK, etc.
        """
        event_dict = self.to_dict()
        base_keys = (
            "timestamp", "timestamp_epoch", "event_type", "severity", "category",
            "request_id", "correlation_id", "tool_name", "security_context",
            "security_category", "actionable_info",
        )
        return {
            "@timestamp": event_dict.get("timestamp"),
            "timestamp_iso8601": event_dict.get("timestamp"),
            "timestamp_epoch": event_dict.get("timestamp_epoch"),
            "event_type": event_dict.get("event_type"),
            "severity": event_dict.get("severity"),
            "category": event_dict.get("category"),
            "security_category": event_dict.get("security_category"),
            "request_id": event_dict.get("request_id"),
            "correlation_id": event_dict.get("correlation_id"),
            "tool_name": event_dict.get("tool_name"),
            "message": f"{event_dict.get('event_type', '')} - {event_dict.get('tool_name', '')}",
            "security_context": event_dict.get("security_context"),
            "actionable_info": event_dict.get("actionable_info"),
            "log_rotation_hint": SIEM_METADATA["log_rotation"]["hint"],
            "siem_metadata": SIEM_METADATA,
            **{k: v for k, v in event_dict.items() if k not in base_keys}
        }
    
    def to_siem_json(self) -> str:
        """Convert to SIEM JSON string (one log line per event, JSONL style)."""
        return json.dumps(self.to_siem_format(), default=str)


class AuditLogger:
    """
    Centralized audit logging with security controls.
    
    Features:
    - Automatic redaction of sensitive fields
    - Structured JSON output (SIEM-ready)
    - Request ID and correlation ID tracking
    - Security context (source IP, user agent placeholders)
    - Event severity and category for filtering
    - Log rotation hints for SIEM integration
    - Performance metrics
    """
    
    def __init__(self, logger_name: str = "usgs_mcp.audit"):
        self.config = get_security_config()
        self.logger = logging.getLogger(logger_name)
        self._setup_logger()
        self._current_correlation_id: Optional[str] = None
        self._current_request_id: Optional[str] = None
        self._security_context: dict = {}
    
    def _setup_logger(self) -> None:
        """Configure the audit logger."""
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            ))
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def _redact_sensitive(self, data: dict) -> dict:
        """
        Redact sensitive fields from data.
        
        Args:
            data: Dictionary to redact
            
        Returns:
            Dictionary with sensitive values replaced
        """
        if not self.config.redact_sensitive_fields:
            return data
        
        redacted = {}
        for key, value in data.items():
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in self.config.SENSITIVE_FIELDS):
                redacted[key] = "[REDACTED]"
            elif isinstance(value, dict):
                redacted[key] = self._redact_sensitive(value)
            elif isinstance(value, list):
                redacted[key] = [
                    self._redact_sensitive(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                redacted[key] = value
        
        return redacted
    
    def _hash_for_correlation(self, value: str) -> str:
        """Create a short hash for correlation purposes."""
        return hashlib.sha256(value.encode()).hexdigest()[:12]
    
    def set_correlation_id(self, correlation_id: str) -> None:
        """Set the current correlation ID for request tracing."""
        self._current_correlation_id = correlation_id
    
    def get_correlation_id(self) -> str:
        """Get or create a correlation ID."""
        if self._current_correlation_id is None:
            self._current_correlation_id = str(uuid.uuid4())
        return self._current_correlation_id
    
    def set_request_id(self, request_id: str) -> None:
        """Set the request ID for session-level tracking across tool calls."""
        self._current_request_id = request_id
    
    def get_request_id(self) -> str:
        """Get or create a request ID that persists across tool calls in a session."""
        if self._current_request_id is None:
            self._current_request_id = str(uuid.uuid4())
        return self._current_request_id

    def begin_session(self) -> str:
        """
        Start a new session: generate and set a new request_id that persists across
        all tool calls until end_session(). Call at MCP session start for proper
        request tracing across a session.
        Returns the new request_id.
        """
        self._current_request_id = str(uuid.uuid4())
        return self._current_request_id

    def end_session(self) -> None:
        """Clear the current request_id. Call when an MCP session ends."""
        self._current_request_id = None

    def set_security_context(
        self,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Set security context for all subsequent audit events.
        
        Call with source_ip and/or user_agent when available (e.g., from HTTP
        request headers). Values are placeholders when not available in MCP stdio.
        """
        if source_ip is not None:
            self._security_context["source_ip"] = source_ip
        if user_agent is not None:
            self._security_context["user_agent"] = user_agent
        self._security_context.update(kwargs)
    
    def _build_security_context(self, extra: Optional[dict] = None) -> dict:
        """
        Build full security context with placeholders for SIEM integration.
        
        Includes source_ip and user_agent (placeholders when not available).
        Merges stored context with event-specific context.
        """
        ctx = dict(self._security_context)
        # Ensure placeholders for standard fields when not set
        if "source_ip" not in ctx:
            ctx["source_ip"] = "[NOT_AVAILABLE]"  # Set via set_security_context when available
        if "user_agent" not in ctx:
            ctx["user_agent"] = "[NOT_AVAILABLE]"  # Set when available from request
        if "session_id" not in ctx:
            ctx["session_id"] = self._current_request_id or "[NOT_AVAILABLE]"
        if extra:
            ctx.update(extra)
        return ctx
    
    def _create_event(
        self,
        event_type: AuditEventType,
        tool_name: str,
        security_extra: Optional[dict] = None,
        **kwargs: Any,
    ) -> AuditEvent:
        """Create an AuditEvent with session-level context applied."""
        security_context = self._build_security_context(security_extra)
        return AuditEvent(
            event_type=event_type,
            tool_name=tool_name,
            correlation_id=self.get_correlation_id(),
            request_id=self.get_request_id(),
            timestamp=_now_iso8601(),
            timestamp_epoch=_now_epoch(),
            security_context=security_context,
            **kwargs,
        )
    
    def _log_event(self, event: AuditEvent, use_siem_format: bool = True) -> None:
        """Log an audit event with appropriate level and format."""
        log_msg = event.to_siem_json() if use_siem_format else event.to_json()
        severity, _ = event._get_severity_and_category()
        if severity == AuditSeverity.CRITICAL:
            self.logger.critical(f"AUDIT: {log_msg}")
        elif severity == AuditSeverity.ERROR:
            self.logger.error(f"AUDIT: {log_msg}")
        elif severity == AuditSeverity.WARNING:
            self.logger.warning(f"AUDIT: {log_msg}")
        else:
            self.logger.info(f"AUDIT: {log_msg}")
    
    @contextmanager
    def audit_context(self, tool_name: str, parameters: Optional[dict] = None):
        """
        Context manager for auditing a tool invocation.
        
        Usage:
            with audit_logger.audit_context("search_publications", params) as ctx:
                result = await do_work()
                ctx.set_result(result)
        
        Args:
            tool_name: Name of the tool being invoked
            parameters: Tool parameters (will be redacted)
            
        Yields:
            AuditContext for recording results
        """
        correlation_id = self.get_correlation_id()
        start_time = time.monotonic()
        
        # Log invocation
        if self.config.audit_logging_enabled:
            redacted_params = self._redact_sensitive(parameters) if parameters else None
            
            invocation_event = self._create_event(
                AuditEventType.TOOL_INVOCATION,
                tool_name,
                parameters=redacted_params if self.config.log_request_params else None,
                security_category=SecurityEventCategory.DATA_ACCESS.value,
            )
            self._log_event(invocation_event)
        
        context = _AuditContext(correlation_id)
        
        try:
            yield context
            
            # Log success
            if self.config.audit_logging_enabled:
                duration_ms = (time.monotonic() - start_time) * 1000
                
                success_event = self._create_event(
                    AuditEventType.TOOL_SUCCESS,
                    tool_name,
                    duration_ms=round(duration_ms, 2),
                    result_count=context.result_count,
                    result_size_bytes=context.result_size if self.config.log_response_size else None,
                    security_category=SecurityEventCategory.DATA_ACCESS.value,
                )
                self._log_event(success_event)
                
        except Exception as e:
            # Log error
            if self.config.audit_logging_enabled:
                duration_ms = (time.monotonic() - start_time) * 1000
                
                error_event = self._create_event(
                    AuditEventType.TOOL_ERROR,
                    tool_name,
                    duration_ms=round(duration_ms, 2),
                    error_type=type(e).__name__,
                    error_message=str(e)[:500],
                    security_category=SecurityEventCategory.DATA_ACCESS.value,
                    security_extra={
                        "what_happened": f"Tool {tool_name} failed",
                        "trigger": tool_name,
                    },
                )
                self._log_event(error_event)
            raise
    
    def log_rate_limit(
        self,
        tool_name: str,
        limit_type: str,
        retry_after: float,
        current_usage: Optional[int] = None,
        threshold: Optional[int] = None,
        violation_count: Optional[int] = None,
    ) -> None:
        """Log a rate limit event with full context for incident response."""
        if not self.config.audit_logging_enabled:
            return

        security_extra = {
            "limit_type": limit_type,
            "retry_after_seconds": round(retry_after, 2),
            "what_happened": f"Rate limit exceeded for {limit_type}",
            "trigger": tool_name,
            "where": "rate_limiter",
            "when": _now_iso8601(),
        }
        if current_usage is not None:
            security_extra["current_usage"] = current_usage
        if threshold is not None:
            security_extra["threshold"] = threshold
        if violation_count is not None:
            security_extra["violation_count"] = violation_count

        actionable_info = {
            "action": "Wait retry_after_seconds before retrying",
            "indicator": "Repeated violations may indicate DoS attempt",
        }
        if violation_count is not None and violation_count >= 5:
            actionable_info["attack_indicator"] = (
                f"Repeated violations ({violation_count}) in window - potential DoS/abuse"
            )
            actionable_info["priority"] = "HIGH"

        event = self._create_event(
            AuditEventType.RATE_LIMIT,
            tool_name,
            security_extra=security_extra,
            security_category=SecurityEventCategory.RATE_LIMITING.value,
            actionable_info=actionable_info,
        )
        self._log_event(event)
    
    def log_validation_error(
        self,
        tool_name: str,
        field: str,
        message: str,
        pattern_detected: Optional[str] = None,
        sanitized_value_preview: Optional[str] = None,
    ) -> None:
        """Log a validation error with detailed context for incident response."""
        if not self.config.audit_logging_enabled:
            return

        security_extra = {
            "field_name": field,
            "message": message,
            "what_happened": f"Validation failed for field '{field}'",
            "trigger": tool_name,
            "where": "input_validation",
            "when": _now_iso8601(),
        }
        if pattern_detected:
            security_extra["pattern_detected"] = pattern_detected
        if sanitized_value_preview:
            security_extra["value_preview_sanitized"] = sanitized_value_preview[:100]

        severity_hint = "HIGH" if pattern_detected else "LOW"
        actionable_info = {
            "action": "Review input format and retry with valid data",
            "severity": severity_hint,
            "investigation": "Check pattern_detected for potential injection" if pattern_detected else None,
        }

        event = self._create_event(
            AuditEventType.VALIDATION_ERROR,
            tool_name,
            error_message=f"{field}: {message}",
            security_extra=security_extra,
            security_category=SecurityEventCategory.INPUT_VALIDATION.value,
            actionable_info={k: v for k, v in actionable_info.items() if v is not None},
        )
        self._log_event(event)
    
    def log_security_violation(
        self,
        tool_name: str,
        violation_type: str,
        details: str,
        resource: Optional[str] = None,
        source: Optional[str] = None,
        error_context: Optional[dict] = None,
    ) -> None:
        """Log a security violation (potential attack attempt) with full context."""
        security_extra = {
            "violation_type": violation_type,
            "details": details[:500],
            "what_happened": f"Security violation: {violation_type}",
            "trigger": tool_name,
            "where": "network",
            "when": _now_iso8601(),
        }
        if resource:
            security_extra["resource"] = resource
        if source:
            security_extra["source"] = source
        if error_context:
            security_extra["error_context"] = {
                k: (str(v)[:200] if isinstance(v, str) else v)
                for k, v in error_context.items()
            }

        event = self._create_event(
            AuditEventType.SECURITY_VIOLATION,
            tool_name,
            security_extra=security_extra,
            security_category=SecurityEventCategory.NETWORK_SECURITY.value,
            actionable_info={
                "action": "Investigate source and block if malicious",
                "priority": "HIGH",
                "debug": "Check error_context for technical details",
            },
        )
        self._log_event(event)
    
    def log_circuit_breaker(
        self,
        state: str,
        failure_count: int = 0,
        previous_state: Optional[str] = None,
        time_in_state_seconds: Optional[float] = None,
        tool_name: str = "upstream_api",
    ) -> None:
        """Log circuit breaker state change with full timing context."""
        if not self.config.audit_logging_enabled:
            return

        security_extra = {
            "state": state,
            "failure_count": failure_count,
            "what_happened": f"Circuit breaker transitioned to {state}",
            "trigger": tool_name,
            "where": "circuit_breaker",
            "when": _now_iso8601(),
        }
        if previous_state:
            security_extra["previous_state"] = previous_state
        if time_in_state_seconds is not None:
            security_extra["time_in_previous_state_seconds"] = round(
                time_in_state_seconds, 2
            )

        event = self._create_event(
            AuditEventType.CIRCUIT_BREAKER,
            tool_name,
            security_extra=security_extra,
            security_category=SecurityEventCategory.NETWORK_SECURITY.value,
            actionable_info={
                "action": "Monitor upstream API health; OPEN state blocks requests",
                "recovery_timeout_seconds": 60,
                "timing": f"Was in {previous_state or 'N/A'} for {time_in_state_seconds or 0:.1f}s before transition",
            },
        )
        self._log_event(event)


class SecurityEventLogger:
    """
    Helper providing convenience methods for security event logging.
    All methods produce structured events with security_category tags.
    """

    def __init__(self, audit_logger: AuditLogger):
        self._audit = audit_logger

    def log_access_denied(
        self,
        resource: str,
        reason: str,
        context: Optional[dict] = None,
        tool_name: str = "system",
    ) -> None:
        """Log when access to a resource is denied."""
        if not self._audit.config.audit_logging_enabled:
            return

        security_extra = {
            "resource": resource,
            "reason": reason,
            "what_happened": f"Access denied to {resource}",
            "trigger": tool_name,
            "where": "authorization",
            "when": _now_iso8601(),
        }
        if context:
            security_extra.update(context)

        event = self._audit._create_event(
            AuditEventType.ACCESS_DENIED,
            tool_name,
            security_extra=security_extra,
            security_category=SecurityEventCategory.AUTHORIZATION.value,
            actionable_info={
                "action": "Review access policy; block source if unauthorized",
                "priority": "MEDIUM",
            },
        )
        self._audit._log_event(event)

    def log_suspicious_activity(
        self,
        activity_type: str,
        details: str,
        severity: str = "MEDIUM",
        tool_name: str = "system",
        indicators: Optional[dict] = None,
    ) -> None:
        """Log suspicious activity that may warrant investigation."""
        if not self._audit.config.audit_logging_enabled:
            return

        security_extra = {
            "activity_type": activity_type,
            "details": details[:500],
            "severity": severity,
            "what_happened": f"Suspicious activity: {activity_type}",
            "trigger": tool_name,
            "where": "suspicious_activity",
            "when": _now_iso8601(),
        }
        if indicators:
            security_extra["indicators"] = indicators

        event = self._audit._create_event(
            AuditEventType.SUSPICIOUS_ACTIVITY,
            tool_name,
            security_extra=security_extra,
            security_category=SecurityEventCategory.INPUT_VALIDATION.value,
            actionable_info={
                "action": "Review activity and escalate if severity is HIGH",
                "priority": severity,
            },
        )
        self._audit._log_event(event)

    def log_security_config_change(
        self,
        setting: str,
        old_value: Any,
        new_value: Any,
        source: str = "runtime",
    ) -> None:
        """Log when a security-relevant configuration is changed."""
        if not self._audit.config.audit_logging_enabled:
            return

        redacted_old = self._audit._redact_sensitive({"v": old_value}).get("v", old_value)
        redacted_new = self._audit._redact_sensitive({"v": new_value}).get("v", new_value)

        security_extra = {
            "setting": setting,
            "old_value": redacted_old,
            "new_value": redacted_new,
            "source": source,
            "what_happened": f"Security config changed: {setting}",
            "trigger": "config_manager",
            "where": "configuration",
            "when": _now_iso8601(),
        }

        event = self._audit._create_event(
            AuditEventType.CONFIG_CHANGE,
            "config",
            security_extra=security_extra,
            security_category=SecurityEventCategory.CONFIGURATION.value,
            actionable_info={
                "action": "Verify change was authorized",
                "priority": "HIGH",
            },
        )
        self._audit._log_event(event)

    def log_potential_attack(
        self,
        attack_type: str,
        indicators: dict,
        source: Optional[str] = None,
        tool_name: str = "system",
    ) -> None:
        """Log a potential attack attempt with indicators for incident response."""
        security_extra = {
            "attack_type": attack_type,
            "what_happened": f"Potential {attack_type} attack detected",
            "trigger": tool_name,
            "where": "attack_detection",
            "when": _now_iso8601(),
            **{k: (str(v)[:200] if isinstance(v, str) else v) for k, v in indicators.items()},
        }
        if source:
            security_extra["source"] = source

        event = self._audit._create_event(
            AuditEventType.POTENTIAL_ATTACK,
            tool_name,
            security_extra=security_extra,
            security_category=SecurityEventCategory.INPUT_VALIDATION.value,
            actionable_info={
                "action": "Block source; escalate to security team",
                "priority": "CRITICAL",
            },
        )
        self._audit._log_event(event)

    def log_injection_attempt(
        self,
        injection_type: str,
        field: str,
        pattern_detected: str,
        value_preview: Optional[str] = None,
        tool_name: str = "validation",
    ) -> None:
        """Log a potential injection attack attempt with injection pattern type (XSS, SQL, template, etc.)."""
        security_extra = {
            "injection_type": injection_type,
            "field": field,
            "pattern_detected": pattern_detected,
            "what_happened": f"Potential {injection_type} injection in field '{field}'",
            "trigger": tool_name,
            "where": "input_validation",
            "when": _now_iso8601(),
        }
        if value_preview:
            security_extra["value_preview_sanitized"] = value_preview[:100]

        event = self._audit._create_event(
            AuditEventType.INJECTION_ATTEMPT,
            tool_name,
            security_extra=security_extra,
            security_category=SecurityEventCategory.INPUT_VALIDATION.value,
            actionable_info={
                "action": "Block request; escalate if repeated",
                "priority": "CRITICAL",
                "injection_pattern": injection_type,
                "investigation": f"Pattern '{pattern_detected}' detected - check value_preview_sanitized",
            },
        )
        self._audit._log_event(event)


class _AuditContext:
    """Helper class for tracking audit context within a request."""
    
    def __init__(self, correlation_id: str):
        self.correlation_id = correlation_id
        self.result_count: Optional[int] = None
        self.result_size: Optional[int] = None
    
    def set_result(self, result: Any) -> None:
        """Record result metadata."""
        if isinstance(result, dict):
            if "total_count" in result:
                self.result_count = result["total_count"]
            elif "publications" in result:
                self.result_count = len(result["publications"])
            self.result_size = len(json.dumps(result, default=str))
        elif isinstance(result, list):
            self.result_count = len(result)
            self.result_size = len(json.dumps(result, default=str))


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None
_security_event_logger: Optional["SecurityEventLogger"] = None


def get_audit_logger() -> AuditLogger:
    """Get the singleton audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def get_security_event_logger() -> SecurityEventLogger:
    """Get the singleton SecurityEventLogger instance."""
    global _security_event_logger
    if _security_event_logger is None:
        _security_event_logger = SecurityEventLogger(get_audit_logger())
    return _security_event_logger
