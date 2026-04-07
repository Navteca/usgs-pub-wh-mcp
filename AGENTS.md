# AGENTS.md

## What this repo is

A Python MCP server that exposes a single tool (`search_publications`) wrapping the USGS Publications Warehouse REST API. The entire application lives in two places: `main.py` (server + tool definition) and `security/` (reusable security primitives). There is no database, no frontend, no monorepo structure.

---

## Runtime and package management

- Python 3.12 (enforced by `.python-version`). Use `uv`, not pip or poetry.
- Install deps: `uv sync`
- Run the server: `uv run python main.py`
- Run tests: `uv run pytest`
- First-time setup shortcut: `bash scripts/install.sh`

---

## Dev commands

```bash
# Local server (stdio transport — for Claude Desktop / Cursor)
uv run python main.py --transport stdio

# Local server (HTTP transport)
uv run python main.py --transport streamable-http --host 127.0.0.1 --port 8000

# Tests (all tests + coverage enforcement)
uv run pytest

# Single test file
uv run pytest tests/test_security_controls.py

# Lint (no config; ruff runs with defaults)
uv run ruff check .

# Type check (no config; mypy runs with defaults)
uv run mypy main.py security/
```

No `make test` or `make lint` targets exist. The Makefile is only for Docker image builds and Helm chart packaging (ECR/k8s deployment).

---

## Transport modes

| Mode | Flag | Use case |
|---|---|---|
| `stdio` | `--transport stdio` | Claude Desktop, Cursor IDE (default entrypoint) |
| `sse` | `--transport sse` | SSE clients (`GET /sse`, `POST /messages`) |
| `streamable-http` | `--transport streamable-http` | Docker / Kubernetes (default in Dockerfile) |

Docker/production CMD: `python main.py --transport streamable-http --host 0.0.0.0 --port 8000`

---

## Environment variables

Copy `.env.example` to `.env` before running locally. Key vars:

| Variable | Default | Notes |
|---|---|---|
| `MCP_TRANSPORT` | `stdio` | Overrides `--transport` |
| `MCP_HOST` | `127.0.0.1` | |
| `MCP_PORT` | `8000` | |
| `USGS_MCP_RATE_LIMIT_REQUESTS_PER_MINUTE` | `60` | |
| `USGS_MCP_MAX_QUERY_LENGTH` | `500` | |
| `USGS_MCP_MAX_PAGE_SIZE` | `100` | |
| `FASTMCP_STATELESS_HTTP` | `true` (in Docker) | Set `false` to enable sessions |

`main.py` calls `load_dotenv(override=False)` **at module import time**, before any `security.*` singleton is initialized. Do not call `load_dotenv()` inside `security/` — the `__init__.py` documents this explicitly to avoid double-loading.

---

## Critical import-time side effects

Two things happen when `main` is imported (not just when `main()` is called):

1. `load_dotenv(override=False)` — loads `.env` into the environment.
2. `_transform_tool_schemas()` — mutates `mcp._tool_manager._tools[*].parameters` in-place to make tool schemas OpenAI-compatible (converts `anyOf`/null to type arrays, adds `required`, `additionalProperties: false`).

This means test collection triggers both side effects. Tests that need a clean security state call `reset_rate_limiter()` and `reset_http_client()` at **module import time** (not inside fixtures).

`get_security_config()` is `@lru_cache(maxsize=1)` — environment must be set before the first call or the cached stale config will be used throughout the test run.

---

## Testing

- Test runner: `pytest` with `asyncio_mode = "auto"` — all `async def test_*` functions run automatically as coroutines.
- Coverage is **scoped only to `security.tool_registry`** with `--cov-fail-under=100`. The rest of the codebase is not measured.
- Several test files contain legacy helper functions with `__test__ = False` that are not collected by pytest. Only `test_*` functions/classes are collected; a single `test_*_suite()` function drives those files via `run_all_tests()`.
- `test_api_integration.py`, `test_user_queries.py`, and `test_llm_benchmark_tasks.py` make **real HTTP calls** to `https://pubs.usgs.gov/pubs-services`. They require internet access and will be slow.
- `tests/run_all_tests.py` is a subprocess-based runner for the five main test files; it is separate from the `pytest` invocation.

---

## Security module (`security/`)

All modules expose singleton getter functions (e.g., `get_security_config()`, `get_audit_logger()`). Never instantiate these classes directly in `main.py` — always use the getters. Reset functions (`reset_rate_limiter()`, `reset_http_client()`) exist specifically for tests.

Key modules:
- `config.py` — `SecurityConfig` frozen dataclass; reads `USGS_MCP_*` env vars.
- `validation.py` — input sanitization; blocks XSS, SQL injection, template injection, prototype pollution patterns.
- `rate_limiter.py` — token bucket + circuit breaker; per-minute/hour/burst/concurrent/session limits.
- `http_client.py` — `SecureHTTPClient`; URL allowlist restricted to `https://pubs.usgs.gov/pubs-services`; TLS 1.2+; retries with backoff.
- `tool_registry.py` — `ToolRegistry` with progressive disclosure (list/search/get); the only module tracked for coverage.
- `schema_compat.py` — OpenAI strict-mode schema normalization (called at import time via `_transform_tool_schemas()`).

---

## Deployment

- **Target**: AWS ECR → Kubernetes namespace `mcp-servers` (kustomize in `k8s/`) or Helm chart (`chart/`).
- **AWS profile**: `navteca`, region `us-east-1` (Makefile defaults).
- **ECR image URI**: `607399646027.dkr.ecr.us-east-1.amazonaws.com/navteca/images/usgs-mcp:latest`
- Build local image: `make build-image`
- Push multi-arch image (amd64 + arm64): `make push-image`
- Package Helm chart: `make chart-package` → `dist/usgs-pub-wh-mcp-<version>.tgz`
- Push Helm chart to ECR OCI: `make chart-release`

---

## agentevals integration (`examples/`)

The `examples/` directory wires the MCP server to [agentevals](https://aevals.ai) for evaluation.

### How it works

agentevals evaluates **agent behavior from OTel traces** — it does not call the MCP server directly. The flow is:

```
examples/agent_harness.py
  → OpenAI Agents SDK (agents package)
      → calls search_publications via MCPServerStreamableHttp
          → spans captured by JaegerTracingProcessor
              → saved as Jaeger JSON in examples/traces/
                  → agentevals run scores the traces
```

Additionally, `security/tracing.py` now exports spans via OTLP when `OTEL_EXPORTER_OTLP_ENDPOINT` is set, so MCP server-internal spans (rate limits, validation errors, circuit breaker state) are also visible in agentevals.

### New env vars (OTel / agentevals)

| Variable | Notes |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Set to `http://localhost:4318` when `agentevals serve --dev` is running |
| `OTEL_SERVICE_NAME` | Tag on all server-side spans (default: `usgs-warehouse-mcp`) |
| `OTEL_SDK_DISABLED` | Set `true` to suppress OTLP export entirely |

When `OTEL_EXPORTER_OTLP_ENDPOINT` is **not set**, `security/tracing.py` behaves exactly as before (audit-log only). Zero OTLP packages are imported at startup.

### Quick eval workflow

```bash
# Terminal 1 — MCP server
uv run python main.py --transport streamable-http --host 127.0.0.1 --port 8000

# Terminal 2 — agentevals (optional live UI)
agentevals serve --dev

# Terminal 3 — run benchmark tasks (requires OPENAI_API_KEY)
export OPENAI_API_KEY=sk-...
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
uv run python examples/agent_harness.py

# Evaluate offline
agentevals run examples/traces/*.json \
  --eval-set examples/eval_set_usgs.json \
  -m tool_trajectory_avg_score \
  -m response_match_score
```

Run a single task: `uv run python examples/agent_harness.py --task 0`

See `examples/README.md` for full documentation, Kubernetes setup, and troubleshooting.

### OTel package note

`opentelemetry-sdk` and `opentelemetry-exporter-otlp-proto-http` are now **runtime dependencies** (not dev-only). They add ~2 MB to the installed footprint. The Dockerfile's production stage still only copies `main.py` and `security/` — the examples directory is excluded from the image.

---

## No CI

`.github/workflows/` is empty. There are no automated tests, lint, or build checks on push/PR.
