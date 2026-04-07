# USGS MCP — agentevals Integration

This directory contains everything needed to evaluate the USGS Publications Warehouse MCP server using [agentevals](https://aevals.ai).

## What's here

| File | Purpose |
|---|---|
| `agent_harness.py` | Runs 10 benchmark tasks against the MCP server, saves Jaeger JSON traces |
| `eval_set_usgs.json` | Golden eval set defining expected tool trajectories and response content |
| `traces/` | Created at runtime — stores one JSON trace file per task run |

---

## How agentevals works with this MCP server

agentevals evaluates **agent behavior from OTel traces**. It does not call the MCP server directly. The flow is:

```
agent_harness.py
  → OpenAI Agents SDK agent
      → calls search_publications via MCP (streamable-http)
          → emits spans via TracingProcessor
              → saved as Jaeger JSON in traces/
                  → agentevals run evaluates the traces
```

The MCP server also emits its own internal spans via `security/tracing.py`. When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, those spans are exported to the agentevals OTLP receiver in addition to the agent-side spans.

---

## Prerequisites

1. Python 3.12, `uv` installed
2. `OPENAI_API_KEY` set in environment
3. Dependencies installed: `uv sync`

---

## Quick start

### Step 1 — Start the MCP server

```bash
uv run python main.py --transport streamable-http --host 127.0.0.1 --port 8000
```

### Step 2 — (Optional) Start agentevals for live UI

```bash
pip install agentevals-cli
agentevals serve --dev
# Opens http://localhost:8001, OTLP receiver on http://localhost:4318
```

### Step 3 — Configure environment

```bash
export OPENAI_API_KEY=sk-...
export MCP_URL=http://127.0.0.1:8000/mcp            # default
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318  # if using agentevals serve
export AGENTEVALS_SESSION_NAME=usgs-benchmark       # groups runs in UI
```

Or add to `.env`:

```ini
OPENAI_API_KEY=sk-...
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
OTEL_SERVICE_NAME=usgs-warehouse-mcp
```

### Step 4 — Run the harness

```bash
# All 10 tasks
uv run python examples/agent_harness.py

# Single task (0-based index)
uv run python examples/agent_harness.py --task 0

# Custom MCP URL
uv run python examples/agent_harness.py --mcp-url http://localhost:8000/mcp
```

The harness saves one trace file per task in `examples/traces/`:

```
examples/traces/
  task_01_earthquakes_3a7f2c1d.json
  task_02_multi_hazard_alaska_9b4e1a2f.json
  ...
  harness_summary.json
```

### Step 5 — Evaluate offline

```bash
agentevals run examples/traces/*.json \
  --eval-set examples/eval_set_usgs.json \
  -m tool_trajectory_avg_score \
  -m response_match_score
```

---

## What the eval set measures

| Task | Key assertion |
|---|---|
| `task_01_earthquakes` | `search_publications` called with `query` containing "earthquake" |
| `task_02_multi_hazard_alaska` | ≥4 calls, each query includes "Alaska" and a hazard keyword |
| `task_03_pfas_groundwater` | 3 calls: PFAS contamination, groundwater contamination, PFAS groundwater |
| `task_04_claim_verification` | 2 calls: first by keyword, second by `index_id` |
| `task_05_critical_minerals_trend` | ≥2 calls with increasing `page_number` |
| `task_06_title_search` | `title` parameter used (not `query`) |
| `task_07_research_gap` | 3 arsenic searches in any order |
| `task_08_hawaii_eruption` | 2 Hawaii volcano searches |
| `task_09_water_quality_data` | 2 water quality searches |
| `task_10_policy_brief` | ≥1 water availability search, response reads as a brief |

---

## Evaluating security/rate-limiting behavior

The `security/tracing.py` module now exports spans to OTLP when `OTEL_EXPORTER_OTLP_ENDPOINT` is set. This means security events (rate limit hits, validation failures, circuit breaker trips) appear as spans in the agentevals UI and can be scored with custom evaluators.

To write a custom evaluator for security behavior, scaffold one with:

```bash
agentevals evaluator init usgs_security_evaluator
```

Then reference it in a separate eval set that targets `RateLimitExceeded` or `ValidationError` span operation names.

---

## Running against Docker / Kubernetes

To evaluate the containerised server, set `MCP_URL` to the service address:

```bash
# Docker Compose
export MCP_URL=http://localhost:8000/mcp

# Kubernetes (port-forwarded)
kubectl port-forward -n mcp-servers svc/usgs-mcp 8000:8000
export MCP_URL=http://localhost:8000/mcp

uv run python examples/agent_harness.py
```

---

## Troubleshooting

**`ConnectionRefusedError` / MCP connection fails**
The MCP server is not running or the `--port` doesn't match `MCP_URL`. Start the server first.

**`openai-agents SDK` not found**
Run `uv sync` from the repo root. The `agents` package is in the `dev` dependency group.

**Spans not appearing in agentevals UI**
Check that `OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318` is set and `agentevals serve --dev` is running in a separate terminal.

**All tasks fail with `OPENAI_API_KEY` error**
The harness uses OpenAI's API to drive the agent. Set `OPENAI_API_KEY` in your environment or `.env`.

**Rate limit errors from the MCP server**
The default rate limit is 60 requests/minute. Run tasks sequentially (`--concurrency 1`, the default) or raise `USGS_MCP_RATE_LIMIT_REQUESTS_PER_MINUTE` in `.env`.
