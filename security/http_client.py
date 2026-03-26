"""
Secure HTTP client with TLS enforcement and security controls.

Implements:
- TLS 1.2+ enforcement
- Certificate verification
- Request timeouts
- URL allowlisting
- Response size limits
- Retry with exponential backoff

Logs security-relevant HTTP events (SSL/TLS, certificates, URL blocking)
for incident response and debugging.
"""

import asyncio
import json
import logging
import ssl
import httpx
from typing import Any, Optional
from urllib.parse import urlparse, urlencode
from .config import get_security_config
from .rate_limiter import get_rate_limiter, RateLimitExceeded
from .audit import get_audit_logger
from .context_limits import get_context_limiter, ContextLimitExceededError

# Configure logging for HTTP client
logger = logging.getLogger(__name__)


class SecureHTTPClientError(Exception):
    """Base exception for secure HTTP client errors."""
    pass


class URLNotAllowedError(SecureHTTPClientError):
    """Raised when URL is not in the allowlist."""
    pass


class ResponseTooLargeError(SecureHTTPClientError):
    """Raised when response exceeds size limit."""
    pass


class RequestTooLargeError(SecureHTTPClientError):
    """Raised when request exceeds size limit."""
    pass


class SecureHTTPClient:
    """
    Secure HTTP client with built-in security controls.
    
    Security features:
    - URL allowlisting (only approved domains)
    - TLS enforcement with minimum version
    - Certificate verification
    - Connection and request timeouts
    - Response size limits
    - Automatic retry with backoff
    - Integration with rate limiter
    """
    
    # Retry configuration
    MAX_RETRIES = 3
    RETRY_BACKOFF_FACTOR = 2.0
    RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
    
    def __init__(self):
        self.config = get_security_config()
        self.rate_limiter = get_rate_limiter()
        self.audit_logger = get_audit_logger()
        self.context_limiter = get_context_limiter()
        self._client: Optional[httpx.AsyncClient] = None
    
    def _log_network_security_event(
        self,
        event_type: str,
        details: str,
        resource: Optional[str] = None,
        error_context: Optional[dict] = None,
    ) -> None:
        """Log a security-relevant HTTP/network event for incident response."""
        self.audit_logger.log_security_violation(
            "http_client",
            event_type,
            details,
            resource=resource,
            source="http_client",
            error_context=error_context,
        )
        if error_context:
            logger.warning(
                f"NETWORK_SECURITY: {event_type} - {details} | context={error_context}"
            )

    def _log_http_request_error(
        self, url: str, error: httpx.RequestError, attempt: int
    ) -> None:
        """
        Log HTTP request errors with security context.
        Detects and logs SSL/TLS, certificate, and connection issues.
        """
        exc = error
        while exc.__cause__:
            exc = exc.__cause__
        cause = exc

        error_context = {
            "url": url,
            "attempt": attempt + 1,
            "error_type": type(error).__name__,
            "error_message": str(error)[:300],
        }

        if isinstance(cause, ssl.SSLCertVerificationError):
            self._log_network_security_event(
                "ssl_certificate_verification_failed",
                f"Certificate verification failed: {str(cause)[:200]}",
                resource=url,
                error_context={
                    **error_context,
                    "cert_error": str(cause)[:200],
                    "reason": getattr(cause, "verify_message", str(cause)),
                },
            )
        elif isinstance(cause, ssl.SSLError):
            self._log_network_security_event(
                "ssl_tls_error",
                f"SSL/TLS error: {str(cause)[:200]}",
                resource=url,
                error_context={
                    **error_context,
                    "ssl_error": str(cause)[:200],
                },
            )
        else:
            # Log non-SSL errors at ERROR level with full context for debugging
            logger.error(
                f"HTTP request error: {type(error).__name__}: {error} | "
                f"url={url} attempt={attempt + 1} | cause={cause}"
            )

    def _validate_url(self, url: str) -> None:
        """
        Validate URL against allowlist.

        Args:
            url: URL to validate

        Raises:
            URLNotAllowedError: If URL is not allowed
        """
        parsed = urlparse(url)

        # Enforce HTTPS
        if self.config.enforce_https and parsed.scheme != "https":
            self._log_network_security_event(
                "https_required",
                f"HTTPS required but got {parsed.scheme}://",
                resource=url,
                error_context={"scheme": parsed.scheme, "netloc": parsed.netloc},
            )
            raise URLNotAllowedError(
                f"HTTPS required but got {parsed.scheme}://"
            )

        # Check against allowlist
        url_base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")
        allowed = any(
            url_base.startswith(allowed_base)
            for allowed_base in self.config.allowed_base_urls
        )

        if not allowed:
            self._log_network_security_event(
                "url_not_allowed",
                f"Attempted access to non-allowlisted URL: {parsed.netloc}",
                resource=url_base,
                error_context={
                    "attempted_netloc": parsed.netloc,
                    "allowed_base_urls": list(self.config.allowed_base_urls),
                },
            )
            raise URLNotAllowedError(
                f"URL not in allowlist: {parsed.netloc}"
            )
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """
        Create SSL context with secure defaults.
        
        Returns:
            Configured SSL context
        """
        # Create context with high security settings
        context = ssl.create_default_context()
        
        # Set minimum TLS version
        if self.config.min_tls_version == "TLSv1.2":
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        elif self.config.min_tls_version == "TLSv1.3":
            context.minimum_version = ssl.TLSVersion.TLSv1_3
        
        # Disable older protocols explicitly
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        
        # Require certificate verification
        if self.config.verify_ssl:
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
        
        return context
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None or self._client.is_closed:
            timeout = httpx.Timeout(
                connect=self.config.connect_timeout_seconds,
                read=self.config.request_timeout_seconds,
                write=self.config.request_timeout_seconds,
                pool=self.config.connect_timeout_seconds,
            )
            
            self._client = httpx.AsyncClient(
                timeout=timeout,
                verify=self._create_ssl_context() if self.config.verify_ssl else False,
                # Keep redirects disabled so allowlist validation cannot be bypassed via redirect hops.
                follow_redirects=False,
                http2=True,  # Enable HTTP/2 for better performance
            )
        
        return self._client
    
    async def get(
        self, 
        url: str, 
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        debug: bool = False,
    ) -> dict:
        """
        Make a secure GET request.
        
        Args:
            url: URL to request
            params: Query parameters
            headers: Additional headers
            debug: If True, log detailed request/response information
            
        Returns:
            JSON response as dictionary
            
        Raises:
            URLNotAllowedError: If URL is not allowed
            RateLimitExceeded: If rate limit is exceeded
            ResponseTooLargeError: If response is too large
            httpx.HTTPError: For HTTP errors
        """
        # Validate URL
        self._validate_url(url)
        
        # Validate request size (params as the main variable part)
        request_data = {"url": url, "params": params or {}}
        try:
            self.context_limiter.check_request_size(request_data)
        except ContextLimitExceededError as e:
            self._log_network_security_event(
                "request_too_large",
                str(e),
                resource=url,
                error_context={"max_size": self.config.max_request_size_bytes},
            )
            raise RequestTooLargeError(str(e))
        
        # Check session limits before making request
        self.rate_limiter.check_session_limits()
        
        # Acquire rate limit
        await self.rate_limiter.acquire()
        
        success = False
        last_error: Optional[Exception] = None
        
        # Build full URL for logging
        full_url = url
        if params:
            query_string = urlencode(params)
            full_url = f"{url}?{query_string}"
        
        # Log the request
        logger.info(f"HTTP REQUEST: GET {full_url}")
        if debug:
            logger.debug(f"Request params: {json.dumps(params, indent=2) if params else 'None'}")
        
        try:
            client = await self._get_client()
            
            # Retry loop with exponential backoff
            for attempt in range(self.MAX_RETRIES):
                try:
                    response = await client.get(
                        url,
                        params=params,
                        headers=headers,
                    )
                    
                    # Log response status
                    logger.info(f"HTTP RESPONSE: {response.status_code} {response.reason_phrase} for {url}")
                    
                    # Check for retryable status codes
                    if response.status_code in self.RETRYABLE_STATUS_CODES:
                        logger.warning(f"Retryable status {response.status_code}, attempt {attempt + 1}/{self.MAX_RETRIES}")
                        if attempt < self.MAX_RETRIES - 1:
                            import asyncio
                            wait_time = self.RETRY_BACKOFF_FACTOR ** attempt
                            await asyncio.sleep(wait_time)
                            continue
                    
                    # Raise for non-retryable errors
                    response.raise_for_status()
                    
                    # Check response size against configured limit
                    content_length = response.headers.get("content-length")
                    max_size = self.config.max_response_size_bytes
                    if content_length and int(content_length) > max_size:
                        self._log_network_security_event(
                            "response_too_large",
                            f"Response size {content_length} exceeds limit of {max_size} bytes",
                            resource=url,
                            error_context={
                                "content_length": int(content_length),
                                "max_size": max_size,
                            },
                        )
                        raise ResponseTooLargeError(
                            f"Response size {content_length} exceeds limit of {max_size} bytes"
                        )
                    
                    # Parse and return JSON
                    data = response.json()
                    
                    # Apply context size limits (truncate records/fields if needed)
                    if isinstance(data, dict):
                        data = self.context_limiter.truncate_response(data)
                    
                    success = True
                    
                    # Log response summary
                    if isinstance(data, dict):
                        record_count = data.get("recordCount", "N/A")
                        records_returned = len(data.get("records", []))
                        logger.info(f"Response: recordCount={record_count}, records_returned={records_returned}")
                        if debug and "records" in data and data["records"]:
                            # Log first record structure for debugging
                            first_record = data["records"][0]
                            logger.debug(f"First record keys: {list(first_record.keys())}")
                            logger.debug(f"First record sample: {json.dumps(first_record, indent=2, default=str)[:2000]}")
                    elif isinstance(data, list):
                        logger.info(f"Response: list with {len(data)} items")
                    
                    # Record actual results returned for session limiting
                    # (not recordCount which is total matching, but actual records array)
                    if isinstance(data, dict) and "records" in data:
                        self.rate_limiter.record_results(len(data["records"]))
                    elif isinstance(data, list):
                        self.rate_limiter.record_results(len(data))
                    
                    # Check session limits
                    self.rate_limiter.check_session_limits()
                    
                    return data
                    
                except httpx.HTTPStatusError as e:
                    logger.error(
                        f"HTTP error: {e.response.status_code} - {e.response.text[:500]}"
                    )
                    if e.response.status_code not in self.RETRYABLE_STATUS_CODES:
                        raise
                    last_error = e
                    if attempt < self.MAX_RETRIES - 1:
                        wait_time = self.RETRY_BACKOFF_FACTOR ** attempt
                        await asyncio.sleep(wait_time)

                except httpx.RequestError as e:
                    # Log SSL/TLS and certificate issues for security monitoring
                    self._log_http_request_error(url, e, attempt)
                    last_error = e
                    if attempt < self.MAX_RETRIES - 1:
                        wait_time = self.RETRY_BACKOFF_FACTOR ** attempt
                        await asyncio.sleep(wait_time)
            
            # All retries exhausted
            if last_error:
                raise last_error
            raise SecureHTTPClientError("Request failed after retries")
            
        finally:
            await self.rate_limiter.release(success=success)
    
    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None


# Global client instance
_http_client: Optional[SecureHTTPClient] = None


def get_http_client() -> SecureHTTPClient:
    """Get the singleton HTTP client instance."""
    global _http_client
    if _http_client is None:
        _http_client = SecureHTTPClient()
    return _http_client


def reset_http_client() -> None:
    """Reset the HTTP client (useful for testing)."""
    global _http_client
    _http_client = None
