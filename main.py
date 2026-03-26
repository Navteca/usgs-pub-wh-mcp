"""
USGS Publications Warehouse MCP Server (Security Hardened)

An MCP server that provides secure access to the USGS Publications Warehouse API,
allowing search and retrieval of USGS scientific publications.

Security features implemented:
- Input validation and sanitization (injection prevention)
- Rate limiting with circuit breaker pattern
- Comprehensive audit logging
- TLS enforcement with certificate verification
- URL allowlisting

API Documentation: https://pubs.usgs.gov/documentation/web_service_documentation

Security Best Practices Sources:
- https://modelcontextprotocol.io/specification/draft/basic/security_best_practices
- https://workos.com/blog/mcp-security-risks-best-practices
- https://aembit.io/blog/securing-mcp-server-communications-best-practices/
- https://www.redhat.com/en/blog/model-context-protocol-mcp-understanding-security-risks-and-controls
- https://www.anthropic.com/engineering/code-execution-with-mcp
"""

import logging
import os
import re
from pathlib import Path
from typing import Annotated

import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from pydantic import Field
from starlette.responses import JSONResponse

from security.audit import get_audit_logger
from security.auth import AuthMiddleware, get_auth_manager
from security.config import get_security_config
from security.context_limits import get_context_limiter
from security.http_client import SecureHTTPClientError, get_http_client
from security.rate_limiter import RateLimitExceeded
from security.schema_compat import transform_schema_for_openai
from security.validation import InputValidator, ValidationError

# ---------------------------------------------------------------------------
# Load .env file BEFORE any security imports (they read env vars at import time)
# ---------------------------------------------------------------------------
_env_path = Path(__file__).parent / ".env"
if _env_path.is_file():
    load_dotenv(_env_path, override=False)

# Security imports

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Verify .env was loaded and required credentials are present
# ---------------------------------------------------------------------------


def _verify_env() -> None:
    """Check that the .env file exists and critical variables are set."""
    if _env_path.is_file():
        logger.info("Loaded environment from %s", _env_path)
    else:
        logger.warning(
            "No .env file found at %s — credentials will be generated randomly on each start. "
            "Copy .env.example to .env and fill in your values for persistent credentials.",
            _env_path,
        )
        return

    missing = []
    if not os.environ.get("USGS_MCP_API_KEY", "").strip():
        missing.append("USGS_MCP_API_KEY")
    if not os.environ.get("USGS_MCP_BEARER_TOKEN", "").strip():
        missing.append("USGS_MCP_BEARER_TOKEN")

    if missing:
        logger.warning(
            "The following variables are empty in .env (credentials will be generated randomly): %s",
            ", ".join(missing),
        )
    else:
        logger.info(
            "Static credentials loaded from .env (API key + Bearer token)")


_verify_env()

# Initialize security components
config = get_security_config()
validator = InputValidator()
audit_logger = get_audit_logger()
context_limiter = get_context_limiter()

# Initialize the MCP server.
# stateless_http=True: every request gets a new transport; no session lookup, so no 404 "session not found".
# Recommended when exposing via ngrok or behind load balancers. Overridable via FASTMCP_STATELESS_HTTP=false.
mcp = FastMCP(
    "USGS Publications Warehouse",
    stateless_http=True,
    instructions="""Search and retrieve USGS scientific publications from the USGS Publications Warehouse API.

Available tools:
- search_publications: Search for publications by keyword, title, or both, with pagination.

Use search_publications for ALL publication queries — topic searches, title lookups,
browsing recent publications, or any combination. All parameters are optional and can
be freely combined to narrow results.

Notes for the model (important):
- The `query` parameter corresponds to the official USGS Publications Warehouse core search parameter (`q`),
  which searches a text index across fields (common words dropped; plurals combined).
- Results can include an `abstract` (USGS field `docAbstract`, often HTML), `indexId`, publication year,
  DOI, and `links` (Document / Index Page / etc.).
- When merging results across multiple searches, always deduplicate by `index_id` / `indexId`.

Real-world query examples and how to map them to tool calls:
- "Provide me a list of publications related to earthquakes"
    → search_publications(query="earthquakes")
- "What are the most recent publications about critical minerals?"
    → search_publications(query="critical minerals")
- "What publications are available on sea-level rise in Florida?"
    → search_publications(query="sea-level rise Florida")
- "Find publications titled National Water Summary"
    → search_publications(title="National Water Summary")
- "Earthquake publications with 'hazard' in the title"
    → search_publications(query="earthquake", title="hazard")
- "Most recent USGS publications" (no topic)
    → search_publications()
- "Publications about groundwater in Texas"
    → search_publications(query="groundwater Texas")
- "Climate publications with 'water quality' in the title"
    → search_publications(query="climate", title="water quality")
- "Get the publication with index_id 70273506"
    → search_publications(index_id="70273506")

------------------------------------------------------------
Workflow recipes (10 supported tasks)
------------------------------------------------------------

Task 1 — Multi-Hazard Risk Briefing Generator (any place; e.g., Alaska/California)
Trigger: user asks "What natural hazards should I worry about in <PLACE>?"
Plan: run 4+ separate hazard searches (include <PLACE> in every query), then summarize by hazard.
Suggested calls (page_size=5 each):
- search_publications(query="earthquake <PLACE>", page_size=5)
- search_publications(query="volcano <PLACE>", page_size=5)
- search_publications(query="flood <PLACE>", page_size=5)
- search_publications(query="wildfire <PLACE>", page_size=5)
Optional (often useful, especially coastal/mountain regions):
- search_publications(query="tsunami <PLACE>", page_size=5)
- search_publications(query="landslide <PLACE>", page_size=5)
Output: sections per hazard + key risks/themes synthesized from abstracts.

Task 2 — Cross-Disciplinary Research Synthesizer (PFAS + Groundwater)
Plan (3 calls; page_size=15):
- search_publications(query="PFAS contamination", page_size=15)
- search_publications(query="groundwater contamination", page_size=15)
- search_publications(query="PFAS groundwater", page_size=15)
Then: deduplicate by index_id and summarize overlap + themes from abstracts.

Task 3 — Multi-Step Fact Verification Pipeline (claim → candidate → verify by index_id)
Plan:
1) search_publications(query="low-frequency earthquakes Mendocino slab", page_size=10)
2) choose best candidate; then verify:
   - search_publications(index_id="<candidate_index_id>")
Then: check candidate abstract for supporting evidence terms (slab, Mendocino, low-frequency, etc.).

Task 4 — Temporal Research Trend Analyst (Critical minerals acceleration)
Plan (paginate; page_size=100):
- search_publications(query="critical minerals", page_size=100, page_number=1)
- search_publications(query="critical minerals", page_size=100, page_number=2)
- search_publications(query="critical minerals", page_size=100, page_number=3)
Then: extract year; count per year; compare recent vs older windows.

Task 5 — Scientific Jargon-to-Plain-Language Translator (find technical abstract)
Plan:
1) search_publications(query="geochemical isotope analysis groundwater", page_size=10)
2) select most technical abstract; verify:
   - search_publications(index_id="<selected_index_id>")
Then: explain why it's jargon-heavy and optionally rewrite plainly.

Task 6 — Research Gap Detector (Arsenic problem vs remediation vs monitoring)
Plan (3 calls; page_size=5):
- search_publications(query="arsenic groundwater contamination", page_size=5)
- search_publications(query="arsenic remediation groundwater", page_size=5)
- search_publications(query="arsenic groundwater monitoring", page_size=5)
Then: compare `total_count` across searches; detect asymmetry; deduplicate index_ids.

Task 7 — Resource-Constrained Summarization (Earthquake research in ≤5 calls)
Plan (exactly 5 calls; page_size=20):
1) search_publications(query="earthquake", page_size=20, page_number=1)
2) search_publications(query="earthquake", page_size=20, page_number=2)
3) search_publications(query="earthquake hazard assessment", page_size=20)
4) search_publications(query="seismic risk", page_size=20)
5) search_publications(query="earthquake", title="fault", page_size=20)
Then: deduplicate; summarize themes using abstracts; report diversity (type/year spread if available).

Task 8 — Emergency Response Literature Kit (Hawaii volcanic eruption)
Plan (2 calls; page_size=15):
- search_publications(query="volcano eruption Hawaii", page_size=15)
- search_publications(query="volcanic hazard Hawaii lava", page_size=15)
Then: deduplicate; group links into Documents vs Index Pages vs other assets.

Task 9 — Data Asset Discovery from Publications (Water quality datasets)
Plan (2 calls; page_size=20):
- search_publications(query="water quality monitoring data", page_size=20)
- search_publications(query="water quality assessment", page_size=20)
Then: deduplicate; scan publication links; catalog dataset-like assets (data release/dataset/table).

Task 10 — Policy Impact Briefing from Publication (Water availability assessment)
Plan:
1) find candidates:
   - search_publications(query="water availability assessment", title="assessment", page_size=5)
2) pick best; verify:
   - search_publications(index_id="<chosen_index_id>")
Then: produce a 1-page policy brief using abstract + citation metadata (title, year, DOI, series/type if present)."""
)

# Base URL for the USGS Publications API
BASE_URL = "https://pubs.usgs.gov/pubs-services"


# =============================================================================
# CUSTOM ROUTES (HTTP transports only)
# =============================================================================

@mcp.custom_route("/health", methods=["GET"])
async def health_check(request):
    """Health check endpoint (skips auth - for load balancers and monitoring)."""
    return JSONResponse({"status": "ok", "service": "usgs-warehouse-mcp"})


# =============================================================================
# TOOLS
# =============================================================================

@mcp.tool()
async def search_publications(
    query: Annotated[str | None, Field(
        description="Full-text search across all publication fields. "
        "The API drops stopwords (a, the, in, etc.) and handles plurals automatically — "
        "pass substantive keywords, not full sentences. "
        "Keep locations and meaningful qualifiers; drop conversational filler "
        "(e.g., 'I want to know about water pollution in rivers' → 'water pollution rivers'). "
        "Examples: 'groundwater contamination', 'earthquake hazards', "
        "'sea-level rise Florida', 'critical minerals'."
    )] = None,
    title: Annotated[str | None, Field(
        description="An exact match for the string within the title of a publication."
    )] = None,
    index_id: Annotated[str | None, Field(
        description="The unique publication index ID for retrieving a specific publication "
        "(e.g., 'ofr20151076', '70273506'). When provided, returns that exact publication."
    )] = None,
    page_size: Annotated[int, Field(
        description="Number of results per page (1-100). Default is 10.",
        ge=1, le=100,
    )] = 10,
    page_number: Annotated[int, Field(
        description="Page number for paginated results. Default is 1.",
        ge=1,
    )] = 1,
) -> dict:
    """Search the United States Geological Survey (USGS) Publications Warehouse for scientific publications, reports, articles, and books.

This is the ONLY tool for finding USGS publications. Use it whenever the user asks about
USGS research, scientific reports, publications on a topic, or any query related to finding
or discovering USGS scientific literature.

Parameters:
- query: Optional full-text search keywords. If omitted, returns the most recent publications.
  (This corresponds to the official Publications Warehouse core search parameter which searches a text index and
  combines plurals / drops common words.)
- title: Optional exact match within publication titles. Use when looking for a specific
  publication by name.
- index_id: Optional publication index ID to retrieve a specific publication (e.g., "ofr20151076").
  When provided, returns that exact publication. Cannot be combined with query or title.
  (Official responses include `records[].indexId`.)
- page_size: Number of results per page (1-100). Default is 10.
  (Official service supports `page_size`; recommended to keep page sizes reasonable for performance.)
- page_number: Page number for paginated results. Default is 1.
  (Official service supports `page_number`.)

Common usage patterns:
- Topic search: set 'query' to keywords (e.g., "groundwater contamination", "earthquake hazards")
- Regional topic: include the location in 'query' (e.g., "sea-level rise Florida")
- Title search: set 'title' to match a specific publication name
- Combined search: use 'query' for broad topic and 'title' to narrow by name
- Search by publication index_id: use 'index_id' to retrieve a specific publication

Hard rules for multi-step tasks:
- If the user asks to compare/synthesize multiple publications: retrieve a manageable set (default page_size=10-20),
  then for each publication abstract produce 3-5 key points, then list common themes across abstracts.
  (Official responses include `docAbstract`, often HTML.)
- If the user asks for trends over time or “acceleration”: use pagination with page_number and a larger page_size
  (e.g., 100) across multiple pages; then extract years and count by year.
- If the user asks “what hazards should I worry about in <PLACE>?”: run 4+ hazard-domain searches (earthquake, volcano,
  flood, wildfire; optionally tsunami/landslide), include <PLACE> in each query, then synthesize by hazard using abstracts.

Real-world examples:
- "publications related to earthquakes" → query="earthquakes"
- "most recent publications about critical minerals" → query="critical minerals"
- "sea-level rise in Florida" → query="sea-level rise Florida"
- "find the publication titled National Water Summary" → title="National Water Summary"
- "earthquake publications with 'hazard' in the title" → query="earthquake", title="hazard"
- "most recent USGS publications" (no filters) → search_publications()
- "publications about groundwater in Texas" → query="groundwater Texas"
- "climate publications with 'water quality' in the title" → query="climate", title="water quality"
- "get the publication with index_id 70273506" → index_id="70273506"

Task recipes (supported; follow these plans when relevant):
1) Multi-Hazard briefing (place) → 4-6 hazard searches + abstract synthesis
2) PFAS + groundwater synthesizer → 3 searches + dedupe + overlap + abstract themes
3) Claim verification → candidate search + index_id verification + evidence terms in abstract
4) Trend analysis → 3 pages (page_size=100) + count by year
5) Jargon translation → pick densest abstract + verify by index_id + plain-language rewrite
6) Research gap detection → compare total_count across 3 searches + dedupe
7) 5-call constrained earthquake overview → exactly 5 calls + dedupe + diversity report
8) Hawaii eruption kit → 2 searches + dedupe + group links
9) Data asset discovery → 2 searches + dedupe + catalog dataset-like links
10) Policy briefing → candidate search + verify by index_id + policy synthesis from abstract

Returns:
A dictionary with:
- total_count (official service calls this `recordCount`)
- publications: list where each entry includes title, authors, year, DOI, links, abstract, etc.
  (Official fields commonly include `records[].title`, `records[].publicationYear`, `records[].doi`,
  `records[].links`, `records[].docAbstract`, and `records[].indexId`.)
- pagination info (page_size/page_number)
    """
    # Only log parameters that were actually provided
    params_raw = {
        k: v for k, v in {
            "query": query,
            "title": title,
            "index_id": index_id,
            "page_size": page_size,
            "page_number": page_number,
        }.items() if v is not None
    }

    with audit_logger.audit_context("search_publications", params_raw) as ctx:
        try:
            # Validate parameter combinations: index_id is exclusive
            if index_id is not None and (query is not None or title is not None):
                return {
                    "error": "index_id cannot be combined with query or title. "
                    "Use index_id alone to retrieve a specific publication, "
                    "or use query/title for searching.",
                    "field": "index_id",
                }

            # Validate all inputs
            query = validator.validate_query(query, "query")
            title = validator.validate_query(title, "title")
            if index_id is not None:
                index_id = validator.validate_publication_id(
                    index_id, "index_id")
            page_size = validator.validate_page_size(page_size, "page_size")
            page_number = validator.validate_page_number(
                page_number, "page_number")

        except ValidationError as e:
            audit_logger.log_validation_error(
                "search_publications",
                e.field,
                e.message,
                pattern_detected=getattr(e, "pattern_detected", None),
                sanitized_value_preview=getattr(
                    e, "sanitized_value_preview", None),
            )
            return {"error": str(e), "field": e.field}

        # Build API parameters — only include non-None values
        # mimeType=json is required per USGS doc for JSON; path has no trailing slash to avoid 404s
        params: dict[str, str | int] = {
            "page_size": page_size,
            "page_number": page_number,
            "mimeType": "json",
        }
        if query:
            params["q"] = query
        if title:
            params["title"] = title
        if index_id:
            params["indexId"] = index_id

        # USGS API path is /publication (no trailing slash) per documentation
        api_url = f"{BASE_URL}/publication"
        headers = {
            "User-Agent": "USGS-Pubs-MCP/0.2.0 (MCP server; +https://pubs.usgs.gov/documentation/web_service_documentation)"}

        try:
            http_client = get_http_client()
            data = await http_client.get(api_url, params=params, headers=headers)
            result = _format_search_results(data)
            ctx.set_result(result)
            return result

        except RateLimitExceeded as e:
            audit_logger.log_rate_limit(
                "search_publications",
                e.limit_type,
                e.retry_after,
                current_usage=getattr(e, "current_usage", None),
                threshold=getattr(e, "threshold", None),
                violation_count=getattr(e, "violation_count", None),
            )
            return {
                "error": "Rate limit exceeded",
                "retry_after_seconds": e.retry_after,
                "limit_type": e.limit_type,
            }
        except SecureHTTPClientError as e:
            return {"error": f"Request failed: {str(e)}"}
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.warning(
                    "USGS Publications API returned 404: %s", e.request.url)
                return {
                    "error": "USGS Publications API returned not found (404). This can be temporary. Please try again in a moment or simplify your search.",
                    "retry": True,
                }
            return {"error": f"USGS API error: {e.response.status_code} {e.response.reason_phrase}"}
        except Exception as e:
            logger.exception(f"Unexpected error in search_publications: {e}")
            return {"error": "An unexpected error occurred. Please try again."}


# =============================================================================
# FORMATTING HELPERS
# =============================================================================

def _strip_html(text: str) -> str:
    """Remove HTML tags and entities from text."""
    if not text:
        return ""
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    # Replace common HTML entities
    text = text.replace('&nbsp;', ' ').replace('&amp;', '&')
    text = text.replace('&lt;', '<').replace('&gt;', '>')
    text = text.replace('&quot;', '"').replace('&#39;', "'")
    # Remove any remaining HTML entities (&#xxx; or &name;)
    text = re.sub(r'&(?:#\d+|#x[\da-fA-F]+|\w+);', ' ', text)
    # Collapse multiple whitespace into single spaces
    text = re.sub(r'\s+', ' ', text)
    return text.strip()


def _format_search_results(data: dict) -> dict:
    """Format search results for better readability."""
    records = data.get("records", [])
    # Limit number of records returned (defense in depth)
    max_results = config.max_total_results
    if len(records) > max_results:
        records = records[:max_results]
    formatted_records = [_format_publication_summary(
        record) for record in records]

    return {
        "total_count": data.get("recordCount", 0),
        "page_size": data.get("pageSize"),
        "page_number": data.get("pageNumber"),
        "publications": formatted_records,
    }


def _format_publication_summary(record: dict) -> dict:
    """Format a publication record summary."""
    # Extract authors
    authors = []
    contributors = record.get("contributors", {})
    for author in contributors.get("authors", []):
        name = f"{author.get('given', '')} {author.get('family', '')}".strip()
        if name:
            authors.append(name)

    # Extract all available links with full metadata
    all_links = []
    for link in record.get("links", []):
        link_type = link.get("type", {}).get("text")
        link_url = link.get("url")
        if link_type and link_url:
            link_entry: dict = {"type": link_type, "url": link_url}
            if link.get("description"):
                link_entry["description"] = link["description"]
            if link.get("size"):
                link_entry["size"] = link["size"]
            if link.get("linkFileType", {}).get("text"):
                link_entry["file_format"] = link["linkFileType"]["text"]
            all_links.append(link_entry)

    # Extract index_id — the unique identifier for each publication.
    # The numeric 'id' is intentionally excluded from results to avoid confusion.
    index_id = record.get("indexId")

    if not index_id:
        title = record.get("title", "Unknown title")[:50]
        logger.warning(
            f"Missing index_id for publication: '{title}...' - Available keys: {list(record.keys())}")

    # Full abstract (HTML stripped). The context_limiter.enforce_field_limits()
    # call below enforces the max_abstract_length safety cap (default 10,000 chars).
    raw_abstract = record.get("docAbstract") or ""
    abstract = _strip_html(raw_abstract)

    result = {
        "index_id": index_id,
        "title": record.get("title"),
        "abstract": abstract or None,
        "year": record.get("publicationYear"),
        "authors": authors[:5] if len(authors) > 5 else authors,
        "author_count": len(authors),
        "type": record.get("publicationType", {}).get("text"),
        "subtype": record.get("publicationSubtype", {}).get("text"),
        "series": record.get("seriesTitle", {}).get("text"),
        "series_number": record.get("seriesNumber"),
        "doi": record.get("doi"),
        "links": all_links,
    }
    return context_limiter.enforce_field_limits(result)


def _transform_tool_schemas() -> None:
    """Transform all tool schemas to be OpenAI-compatible.

    OpenAI's function calling API with strict mode requires:
    1. All properties must be in the 'required' array
    2. No anyOf/oneOf patterns (not well supported)
    3. additionalProperties: false

    This function modifies the tool schemas in-place to ensure compatibility.
    """
    tools = mcp._tool_manager._tools
    transformed_count = 0

    for name, tool in tools.items():
        original_schema = tool.parameters
        transformed_schema = transform_schema_for_openai(original_schema)

        # Update the schema in-place
        tool.parameters.clear()
        tool.parameters.update(transformed_schema)
        transformed_count += 1

    logger.info(
        f"Transformed {transformed_count} tool schemas for OpenAI compatibility")


# =============================================================================
# APPLY SCHEMA TRANSFORMATIONS AT MODULE LOAD TIME
# =============================================================================
# This ensures all tool schemas are OpenAI-compatible regardless of how the
# server is started (via main(), imported as module, etc.)
_transform_tool_schemas()


def main():
    """Run the MCP server."""
    import argparse
    import os

    parser = argparse.ArgumentParser(
        description="USGS Publications Warehouse MCP Server")
    parser.add_argument(
        "--transport", "-t",
        choices=["stdio", "sse", "streamable-http"],
        default=os.environ.get("MCP_TRANSPORT", "stdio"),
        help="Transport protocol (default: stdio, or set MCP_TRANSPORT env var)"
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("MCP_HOST", "127.0.0.1"),
        help="Host to bind to for HTTP transports (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=int(os.environ.get("MCP_PORT", "8000")),
        help="Port to bind to for HTTP transports (default: 8000)"
    )
    parser.add_argument(
        "--allowed-hosts",
        nargs="*",
        default=os.environ.get("MCP_ALLOWED_HOSTS", "").split(
            ",") if os.environ.get("MCP_ALLOWED_HOSTS") else None,
        help="Additional allowed hosts for HTTP transports (e.g., '*.ngrok-free.app' or 'myapp.example.com'). "
             "Can also set MCP_ALLOWED_HOSTS env var (comma-separated)"
    )
    parser.add_argument(
        "--disable-dns-rebinding-protection",
        action="store_true",
        default=os.environ.get("MCP_DISABLE_DNS_REBINDING_PROTECTION", "").lower() in (
            "true", "1", "yes"),
        help="Disable DNS rebinding protection (NOT recommended for production). "
             "Can also set MCP_DISABLE_DNS_REBINDING_PROTECTION=true"
    )

    args = parser.parse_args()

    logger.info(
        "Starting USGS Publications Warehouse MCP Server (Security Hardened)")
    logger.info(f"Transport: {args.transport}")
    logger.info(f"Security config: rate_limit={config.rate_limit_requests_per_minute}/min, "
                f"max_page_size={config.max_page_size}, audit_logging={config.audit_logging_enabled}")

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    elif args.transport == "sse":
        # SSE transport endpoints:
        #   GET  /sse      - SSE connection endpoint
        #   POST /messages - Message endpoint
        #   GET  /health   - Health check (no auth)
        logger.info(
            f"SSE endpoints: GET /sse, POST /messages, GET /health on http://{args.host}:{args.port}")
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        _configure_transport_security(args)
        auth_manager = get_auth_manager()
        creds = auth_manager.get_plaintext_credentials()
        _display_auth_credentials(creds)
        starlette_app = mcp.sse_app()
        wrapped_app = AuthMiddleware(starlette_app, auth_manager=auth_manager)
        import anyio
        import uvicorn

        async def _run():
            config = uvicorn.Config(
                wrapped_app,
                host=mcp.settings.host,
                port=mcp.settings.port,
                log_level=mcp.settings.log_level.lower(),
            )
            server = uvicorn.Server(config)
            await server.serve()
        anyio.run(_run)
    elif args.transport == "streamable-http":
        # Streamable HTTP transport endpoint:
        #   POST /mcp - Main MCP endpoint
        #   GET  /health - Health check (no auth)
        logger.info(
            f"HTTP endpoint: POST /mcp, GET /health on http://{args.host}:{args.port}")
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        _configure_transport_security(args)
        auth_manager = get_auth_manager()
        creds = auth_manager.get_plaintext_credentials()
        _display_auth_credentials(creds)
        starlette_app = mcp.streamable_http_app()
        # Stateless mode: no session lookup, so no 404. Auth only.
        wrapped_app = AuthMiddleware(starlette_app, auth_manager=auth_manager)
        import anyio
        import uvicorn

        async def _run():
            config = uvicorn.Config(
                wrapped_app,
                host=mcp.settings.host,
                port=mcp.settings.port,
                log_level=mcp.settings.log_level.lower(),
            )
            server = uvicorn.Server(config)
            await server.serve()
        anyio.run(_run)


def _display_auth_credentials(creds: dict[str, str]) -> None:
    """Display credential guidance without printing full secrets to logs."""
    def _mask(value: str) -> str:
        if not value or value.startswith("["):
            return value
        if len(value) <= 8:
            return "*" * len(value)
        return f"{value[:4]}...{value[-4:]}"

    banner = "=" * 70
    logger.info(banner)
    logger.info("  USGS MCP HTTP AUTHENTICATION CREDENTIALS")
    logger.info(banner)
    logger.info("  API Key:    %s", _mask(creds.get("api_key", "")))
    if not creds.get("api_key", "").startswith("["):
        logger.info("  Header:     X-API-Key: <key>")
    logger.info("  Bearer:     %s", _mask(creds.get("bearer_token", "")))
    if not creds.get("bearer_token", "").startswith("["):
        logger.info("  Header:     Authorization: Bearer <token>")
    logger.info(banner)


def _configure_transport_security(args) -> None:
    """Configure transport security settings for HTTP transports.

    Note: The MCP SDK's host validation supports:
    - Exact match: "example.com" matches only "example.com"
    - Wildcard port: "localhost:*" matches "localhost:8000", "localhost:3000", etc.

    It does NOT support subdomain wildcards like "*.example.com".
    For ngrok, you must use the exact hostname (e.g., "abc123.ngrok-free.app").
    """
    from mcp.server.transport_security import TransportSecuritySettings

    # Default allowed hosts (always include localhost variants)
    default_hosts = [
        "127.0.0.1:*",
        "localhost:*",
        "[::1]:*",
    ]

    # Default allowed origins
    default_origins = [
        "http://127.0.0.1:*",
        "http://localhost:*",
        "http://[::1]:*",
    ]

    # Add custom allowed hosts if specified
    allowed_hosts = list(default_hosts)
    allowed_origins = list(default_origins)

    if args.allowed_hosts:
        for host in args.allowed_hosts:
            host = host.strip()
            if host:
                # Warn about unsupported wildcard patterns
                if host.startswith("*."):
                    logger.warning(
                        f"Subdomain wildcards like '{host}' are NOT supported by MCP SDK. "
                        f"Use the exact hostname instead (e.g., 'abc123.ngrok-free.app')"
                    )
                    # Still add it in case future SDK versions support it

                # Add host pattern (with wildcard port if not specified)
                if ":" not in host:
                    allowed_hosts.append(f"{host}:*")
                    allowed_hosts.append(host)
                else:
                    allowed_hosts.append(host)

                # Add corresponding origin patterns
                # Strip any wildcard port suffix for origin base
                host_base = host.rstrip(":*").rstrip("*").rstrip(":")
                allowed_origins.append(f"http://{host_base}")
                allowed_origins.append(f"http://{host_base}:*")
                allowed_origins.append(f"https://{host_base}")
                allowed_origins.append(f"https://{host_base}:*")

        logger.info(f"Added allowed hosts: {args.allowed_hosts}")
        logger.info(f"Allowed hosts list: {allowed_hosts}")

    # Configure transport security
    if args.disable_dns_rebinding_protection:
        logger.warning(
            "DNS rebinding protection is DISABLED - this is NOT recommended for production!")
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=False,
            allowed_hosts=allowed_hosts,
            allowed_origins=allowed_origins,
        )
    else:
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
            allowed_origins=allowed_origins,
        )

    logger.info(
        f"Transport security configured with {len(allowed_hosts)} allowed hosts")


if __name__ == "__main__":
    main()
