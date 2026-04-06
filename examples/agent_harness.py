#!/usr/bin/env python3
"""
USGS MCP Agent Harness — agentevals integration.

This script:
1. Starts an OpenAI Agents SDK agent connected to the USGS MCP server via
   streamable-http transport.
2. Runs each benchmark query defined in BENCHMARK_TASKS.
3. Captures OpenTelemetry spans via a custom processor that bridges the
   OpenAI Agents SDK's internal tracing into a real OTel TracerProvider.
4. Saves each run's trace as Jaeger JSON to the traces/ subdirectory so that
   `agentevals run` can evaluate them offline.
5. Optionally streams spans live to an OTLP receiver (e.g. `agentevals serve
   --dev`) when OTEL_EXPORTER_OTLP_ENDPOINT is set.

Usage
-----
# Prerequisites
#   Terminal 1 — MCP server
#   uv run python main.py --transport streamable-http --host 127.0.0.1 --port 8000
#
#   Terminal 2 — agentevals receiver (optional, for live UI)
#   agentevals serve --dev
#
#   Terminal 3 — this harness
#   export OPENAI_API_KEY=sk-...
#   export MCP_URL=http://127.0.0.1:8000/mcp        # default
#   export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318  # optional live export
#   export AGENTEVALS_SESSION_NAME=usgs-benchmark   # groups runs in UI
#   uv run python examples/agent_harness.py

# Run a single task by index (0-based):
#   uv run python examples/agent_harness.py --task 0

# After the harness finishes evaluate offline:
#   agentevals run examples/traces/*.json \
#       --eval-set examples/eval_set_usgs.json \
#       -m tool_trajectory_avg_score \
#       -m response_match_score

Environment variables
---------------------
OPENAI_API_KEY              required — OpenAI API key for the agent
MCP_URL                     MCP server URL (default: http://127.0.0.1:8000/mcp)
OTEL_EXPORTER_OTLP_ENDPOINT optional — OTLP HTTP endpoint for live span export
OTEL_SERVICE_NAME           optional — service name tag (default: usgs-warehouse-mcp)
AGENTEVALS_SESSION_NAME     optional — session label shown in agentevals UI
OPENAI_AGENTS_DISABLE_TRACING  set to 1 to disable OpenAI Agents SDK backend tracing
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Ensure repo root is on sys.path when run as a script
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(override=False)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("usgs_harness")

# ---------------------------------------------------------------------------
# Disable OpenAI Agents SDK default backend tracing to avoid sending
# agent traces to OpenAI's Traces dashboard (we handle our own export).
# Users can override by unsetting OPENAI_AGENTS_DISABLE_TRACING.
# ---------------------------------------------------------------------------
os.environ.setdefault("OPENAI_AGENTS_DISABLE_TRACING", "1")

# ---------------------------------------------------------------------------
# OTel setup — must happen before importing agents
# ---------------------------------------------------------------------------

_otel_tracer = None


def _setup_otel() -> Any:
    """
    Build an OTel TracerProvider with an OTLP HTTP exporter when
    OTEL_EXPORTER_OTLP_ENDPOINT is configured.  Returns the tracer or None.
    """
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    if not endpoint:
        logger.info("OTEL_EXPORTER_OTLP_ENDPOINT not set — OTLP export disabled.")
        return None

    try:
        from opentelemetry import trace as otel_trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        service_name = os.environ.get("OTEL_SERVICE_NAME", "usgs-warehouse-mcp")
        resource = Resource.create({"service.name": service_name})

        traces_endpoint = endpoint.rstrip("/")
        if not traces_endpoint.endswith("/v1/traces"):
            traces_endpoint = f"{traces_endpoint}/v1/traces"

        exporter = OTLPSpanExporter(endpoint=traces_endpoint)
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        otel_trace.set_tracer_provider(provider)

        logger.info(
            "OTel OTLP export enabled → %s (service=%s)", endpoint, service_name
        )
        return otel_trace.get_tracer("usgs_harness")

    except ImportError as exc:
        logger.warning("opentelemetry packages not available: %s", exc)
        return None


_otel_tracer = _setup_otel()


# ---------------------------------------------------------------------------
# Benchmark task definitions
# These mirror the 10 workflow recipes documented in main.py's tool docstring.
# ---------------------------------------------------------------------------

BENCHMARK_TASKS = [
    {
        "id": "task_01_earthquakes",
        "description": "Basic topic search",
        "prompt": "Find me recent USGS publications related to earthquakes.",
        "expected_tools": ["search_publications"],
        "expected_params_contain": {"query": "earthquake"},
    },
    {
        "id": "task_02_multi_hazard_alaska",
        "description": "Multi-hazard risk briefing (Task 1 recipe)",
        "prompt": (
            "What natural hazards should I worry about in Alaska? "
            "Please search for publications on each major hazard type."
        ),
        "expected_tools": ["search_publications"] * 4,
        "expected_min_tool_calls": 4,
    },
    {
        "id": "task_03_pfas_groundwater",
        "description": "Cross-disciplinary synthesizer (Task 2 recipe)",
        "prompt": (
            "Synthesize USGS research on PFAS contamination and groundwater. "
            "Search for PFAS contamination, groundwater contamination, and PFAS groundwater."
        ),
        "expected_tools": ["search_publications"] * 3,
        "expected_min_tool_calls": 3,
    },
    {
        "id": "task_04_claim_verification",
        "description": "Multi-step fact verification (Task 3 recipe)",
        "prompt": (
            "Find USGS publications about low-frequency earthquakes near the Mendocino slab, "
            "then retrieve the most relevant one by its index_id to verify details."
        ),
        "expected_tools": ["search_publications", "search_publications"],
        "expected_min_tool_calls": 2,
    },
    {
        "id": "task_05_critical_minerals_trend",
        "description": "Temporal trend analysis (Task 4 recipe)",
        "prompt": (
            "Analyze the trend in USGS critical minerals research over time. "
            "Use pagination to retrieve multiple pages and count publications by year."
        ),
        "expected_min_tool_calls": 2,
        "expected_tools": ["search_publications", "search_publications"],
    },
    {
        "id": "task_06_title_search",
        "description": "Title exact-match search",
        "prompt": "Find USGS publications with 'National Water Summary' in the title.",
        "expected_tools": ["search_publications"],
        "expected_params_contain": {"title": "National Water Summary"},
    },
    {
        "id": "task_07_research_gap",
        "description": "Research gap detection (Task 6 recipe)",
        "prompt": (
            "Identify research gaps in USGS arsenic groundwater studies. "
            "Search separately for contamination, remediation, and monitoring, "
            "then compare the total_count across searches."
        ),
        "expected_min_tool_calls": 3,
        "expected_tools": ["search_publications"] * 3,
    },
    {
        "id": "task_08_hawaii_eruption",
        "description": "Emergency response literature kit (Task 8 recipe)",
        "prompt": (
            "Compile an emergency response literature kit for a Hawaii volcanic eruption. "
            "Search for volcano eruption Hawaii and volcanic hazard Hawaii lava publications."
        ),
        "expected_min_tool_calls": 2,
        "expected_tools": ["search_publications", "search_publications"],
    },
    {
        "id": "task_09_water_quality_data",
        "description": "Data asset discovery (Task 9 recipe)",
        "prompt": (
            "Find USGS water quality monitoring and assessment publications that include "
            "links to datasets. Identify data release and dataset-type assets."
        ),
        "expected_min_tool_calls": 2,
        "expected_tools": ["search_publications", "search_publications"],
    },
    {
        "id": "task_10_policy_brief",
        "description": "Policy impact briefing (Task 10 recipe)",
        "prompt": (
            "Find a USGS water availability assessment publication and produce a "
            "one-page policy brief using its abstract and citation metadata."
        ),
        "expected_min_tool_calls": 1,
        "expected_tools": ["search_publications"],
    },
]


# ---------------------------------------------------------------------------
# Jaeger JSON trace builder
# ---------------------------------------------------------------------------


class JaegerTraceBuilder:
    """
    Collects span events from the OpenAI Agents SDK TracingProcessor interface
    and builds a Jaeger-format JSON trace that agentevals can consume directly.

    Jaeger JSON schema (simplified):
    {
      "data": [
        {
          "traceID": "...",
          "spans": [ { spanID, operationName, startTime, duration, tags, ... } ],
          "processes": { "p1": { "serviceName": "...", "tags": [] } }
        }
      ]
    }
    """

    def __init__(self, trace_id: str, service_name: str = "usgs-warehouse-mcp") -> None:
        self.trace_id = trace_id
        self.service_name = service_name
        self.spans: list[dict] = []
        self._span_map: dict[str, dict] = {}

    def add_span(
        self,
        span_id: str,
        operation_name: str,
        start_time_us: int,
        duration_us: int,
        parent_span_id: str | None = None,
        tags: list[dict] | None = None,
        logs: list[dict] | None = None,
    ) -> None:
        """Add a span to the trace."""
        references = []
        if parent_span_id:
            references.append(
                {
                    "refType": "CHILD_OF",
                    "traceID": self.trace_id,
                    "spanID": parent_span_id,
                }
            )

        span = {
            "traceID": self.trace_id,
            "spanID": span_id,
            "operationName": operation_name,
            "references": references,
            "startTime": start_time_us,
            "duration": duration_us,
            "tags": tags or [],
            "logs": logs or [],
            "processID": "p1",
            "warnings": None,
        }
        self.spans.append(span)
        self._span_map[span_id] = span

    def to_jaeger_json(self) -> dict:
        """Export as Jaeger JSON compatible with agentevals."""
        return {
            "data": [
                {
                    "traceID": self.trace_id,
                    "spans": self.spans,
                    "processes": {
                        "p1": {
                            "serviceName": self.service_name,
                            "tags": [
                                {
                                    "key": "service.name",
                                    "type": "string",
                                    "value": self.service_name,
                                }
                            ],
                        }
                    },
                    "warnings": None,
                }
            ]
        }


# ---------------------------------------------------------------------------
# OpenAI Agents SDK TracingProcessor bridge
# ---------------------------------------------------------------------------


def _make_tag(key: str, value: Any) -> dict:
    """Build a Jaeger tag dict from a key-value pair."""
    if isinstance(value, bool):
        return {"key": key, "type": "bool", "value": value}
    if isinstance(value, int):
        return {"key": key, "type": "int64", "value": value}
    if isinstance(value, float):
        return {"key": key, "type": "float64", "value": value}
    return {"key": key, "type": "string", "value": str(value)}


class JaegerTracingProcessor:
    """
    Implements the OpenAI Agents SDK TracingProcessor interface and converts
    SDK trace/span objects into Jaeger JSON spans.

    The SDK calls:
      on_trace_start(trace)
      on_trace_end(trace)
      on_span_start(span)
      on_span_end(span)
    """

    def __init__(self, builder: JaegerTraceBuilder) -> None:
        self._builder = builder
        self._root_span_id: str | None = None

    def on_trace_start(self, trace: Any) -> None:  # noqa: ANN401
        pass

    def on_trace_end(self, trace: Any) -> None:  # noqa: ANN401
        pass

    def on_span_start(self, span: Any) -> None:  # noqa: ANN401
        pass

    def on_span_end(self, span: Any) -> None:  # noqa: ANN401
        """Convert a finished SDK span to Jaeger format."""
        try:
            span_id = getattr(span, "span_id", None) or str(uuid.uuid4().hex[:16])
            parent_id = getattr(span, "parent_id", None)
            started_at = getattr(span, "started_at", None)
            ended_at = getattr(span, "ended_at", None)

            # Convert ISO timestamps to microseconds
            start_us = _iso_to_us(started_at) if started_at else int(time.time() * 1e6)
            end_us = _iso_to_us(ended_at) if ended_at else start_us + 1
            duration_us = max(end_us - start_us, 0)

            # Extract operation name from span_data
            span_data = getattr(span, "span_data", None)
            operation_name = _extract_operation_name(span, span_data)

            # Build tags from span_data attributes
            tags = _extract_tags(span, span_data)

            self._builder.add_span(
                span_id=span_id,
                operation_name=operation_name,
                start_time_us=start_us,
                duration_us=duration_us,
                parent_span_id=parent_id,
                tags=tags,
            )

            # Also emit to OTel if tracer is available
            if _otel_tracer is not None:
                _emit_otel_span(
                    operation_name=operation_name,
                    start_us=start_us,
                    duration_us=duration_us,
                    tags=tags,
                    trace_id=self._builder.trace_id,
                    span_id=span_id,
                    parent_id=parent_id,
                )

        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to convert SDK span: %s", exc)

    def shutdown(self) -> None:
        pass


def _iso_to_us(ts: Any) -> int:
    """Convert an ISO-8601 timestamp string or datetime to microseconds."""
    try:
        from datetime import datetime, timezone

        if hasattr(ts, "timestamp"):
            return int(ts.timestamp() * 1e6)
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return int(dt.timestamp() * 1e6)
    except Exception:
        return int(time.time() * 1e6)


def _extract_operation_name(span: Any, span_data: Any) -> str:
    """Derive a human-readable operation name from an SDK span."""
    if span_data is None:
        return getattr(span, "name", "unknown")

    cls_name = type(span_data).__name__
    # e.g. FunctionSpanData, AgentSpanData, GenerationSpanData, HandoffSpanData, etc.
    mapping = {
        "FunctionSpanData": lambda d: f"tool_call {getattr(d, 'name', 'unknown')}",
        "AgentSpanData": lambda d: f"agent {getattr(d, 'name', 'unknown')}",
        "GenerationSpanData": lambda _: "llm_generation",
        "HandoffSpanData": lambda d: f"handoff {getattr(d, 'to_agent', 'unknown')}",
        "GuardrailSpanData": lambda d: f"guardrail {getattr(d, 'name', '')}",
        "TranscriptionSpanData": lambda _: "transcription",
        "SpeechSpanData": lambda _: "speech",
        "CustomSpanData": lambda d: getattr(d, "name", "custom"),
    }
    factory = mapping.get(cls_name)
    if factory:
        try:
            return factory(span_data)
        except Exception:
            pass
    return cls_name.replace("SpanData", "").lower() or "span"


def _extract_tags(span: Any, span_data: Any) -> list[dict]:
    """Build Jaeger tags from an SDK span and its span_data."""
    tags: list[dict] = []

    # Standard tags
    tags.append(_make_tag("otel.scope.name", "openai-agents-sdk"))
    tags.append(_make_tag("span.kind", "internal"))

    if span_data is None:
        return tags

    cls_name = type(span_data).__name__

    if cls_name == "FunctionSpanData":
        name = getattr(span_data, "name", None)
        inp = getattr(span_data, "input", None)
        out = getattr(span_data, "output", None)
        if name:
            tags.append(_make_tag("gen_ai.tool.name", name))
        if inp is not None:
            tags.append(
                _make_tag("gen_ai.tool.call.args", json.dumps(inp, default=str)[:2000])
            )
        if out is not None:
            tags.append(_make_tag("gen_ai.tool.response", str(out)[:2000]))
        tags.append(_make_tag("gen_ai.operation.name", "execute_tool"))

    elif cls_name == "AgentSpanData":
        name = getattr(span_data, "name", None)
        if name:
            tags.append(_make_tag("gen_ai.agent.name", name))

    elif cls_name == "GenerationSpanData":
        model = getattr(span_data, "model", None)
        inp = getattr(span_data, "input", None)
        out = getattr(span_data, "output", None)
        usage = getattr(span_data, "usage", None)
        if model:
            tags.append(_make_tag("gen_ai.request.model", model))
        if inp is not None:
            tags.append(_make_tag("gen_ai.prompt", json.dumps(inp, default=str)[:2000]))
        if out is not None:
            tags.append(
                _make_tag("gen_ai.completion", json.dumps(out, default=str)[:2000])
            )
        if usage:
            in_tok = getattr(usage, "input_tokens", None)
            out_tok = getattr(usage, "output_tokens", None)
            if in_tok is not None:
                tags.append(_make_tag("gen_ai.usage.input_tokens", in_tok))
            if out_tok is not None:
                tags.append(_make_tag("gen_ai.usage.output_tokens", out_tok))

    return tags


def _emit_otel_span(
    operation_name: str,
    start_us: int,
    duration_us: int,
    tags: list[dict],
    trace_id: str,
    span_id: str,
    parent_id: str | None,
) -> None:
    """Forward a converted span to the OTel TracerProvider."""
    if _otel_tracer is None:
        return
    try:
        from opentelemetry.trace import SpanKind, StatusCode
        from opentelemetry.trace.span import format_span_id, format_trace_id

        attrs = {
            t["key"]: t["value"]
            for t in tags
            if isinstance(t["value"], (str, int, float, bool))
        }

        with _otel_tracer.start_as_current_span(
            operation_name,
            kind=SpanKind.INTERNAL,
            attributes=attrs,
        ) as otel_span:
            # Set timestamps cannot be done portably without low-level SDK access;
            # the span will have the real wall-clock time from when start_as_current_span
            # is called. For agentevals purposes the span structure matters more than
            # microsecond-accurate timestamps.
            pass
    except Exception as exc:
        logger.debug("OTel span emission failed: %s", exc)


# ---------------------------------------------------------------------------
# Main harness
# ---------------------------------------------------------------------------


async def run_task(
    task: dict,
    mcp_url: str,
    traces_dir: Path,
) -> dict:
    """Run a single benchmark task and save its trace to traces_dir."""
    try:
        from agents import Agent, Runner
        from agents.mcp import MCPServerStreamableHttp
        from agents.tracing import add_trace_processor
    except ImportError as exc:
        logger.error("openai-agents SDK not installed. Install with: uv sync\n%s", exc)
        sys.exit(1)

    task_id = task["id"]
    trace_id = uuid.uuid4().hex  # 32-char hex — Jaeger format
    builder = JaegerTraceBuilder(trace_id=trace_id)
    processor = JaegerTracingProcessor(builder=builder)

    # Register our processor alongside any existing ones
    add_trace_processor(processor)

    logger.info("[%s] Starting: %s", task_id, task["description"])
    logger.info("[%s] Prompt: %s", task_id, task["prompt"])

    result_payload = {
        "task_id": task_id,
        "trace_id": trace_id,
        "description": task["description"],
        "prompt": task["prompt"],
        "success": False,
        "final_output": None,
        "error": None,
        "tool_calls": [],
        "trace_file": None,
    }

    try:
        async with MCPServerStreamableHttp(
            name="USGS Publications MCP",
            params={
                "url": mcp_url,
                "timeout": 60,
            },
            cache_tools_list=True,
        ) as server:
            agent = Agent(
                name="USGS Research Agent",
                instructions=(
                    "You are a research assistant that searches USGS scientific publications. "
                    "Use the search_publications tool to find relevant publications. "
                    "Always search with meaningful keywords, paginate when needed, "
                    "and deduplicate by index_id when merging results."
                ),
                mcp_servers=[server],
            )

            run_result = await Runner.run(
                agent,
                task["prompt"],
            )

            final_output = run_result.final_output
            result_payload["final_output"] = str(final_output)[:5000]
            result_payload["success"] = True

            # Extract tool calls from the run result items
            tool_calls = []
            for item in run_result.new_items:
                item_type = type(item).__name__
                if "ToolCall" in item_type or "FunctionCall" in item_type:
                    tool_name = getattr(item, "name", None) or getattr(
                        getattr(item, "raw_item", None), "name", None
                    )
                    tool_args = getattr(item, "arguments", None) or getattr(
                        getattr(item, "raw_item", None), "arguments", None
                    )
                    if tool_name:
                        tool_calls.append(
                            {
                                "tool": str(tool_name),
                                "args": str(tool_args)[:500] if tool_args else None,
                            }
                        )

            result_payload["tool_calls"] = tool_calls
            logger.info(
                "[%s] Done. Tool calls: %d, Output length: %d chars",
                task_id,
                len(tool_calls),
                len(str(final_output)),
            )

    except Exception as exc:
        result_payload["error"] = str(exc)
        logger.error("[%s] Failed: %s", task_id, exc, exc_info=True)

    finally:
        # Remove the processor so it doesn't accumulate across tasks
        try:
            from agents.tracing import set_trace_processors
            # set_trace_processors([]) would clear all — instead we leave
            # the default empty since we set OPENAI_AGENTS_DISABLE_TRACING=1
        except Exception:
            pass

        # Save trace file regardless of success/failure
        trace_data = builder.to_jaeger_json()
        trace_file = traces_dir / f"{task_id}_{trace_id[:8]}.json"
        trace_file.write_text(json.dumps(trace_data, indent=2))
        result_payload["trace_file"] = str(trace_file)
        logger.info("[%s] Trace saved → %s", task_id, trace_file)

    return result_payload


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="USGS MCP Agent Harness — runs benchmark tasks and saves traces for agentevals."
    )
    parser.add_argument(
        "--task",
        type=int,
        default=None,
        help="Run a single task by 0-based index (default: run all tasks).",
    )
    parser.add_argument(
        "--mcp-url",
        default=os.environ.get("MCP_URL", "http://127.0.0.1:8000/mcp"),
        help="MCP server URL (default: http://127.0.0.1:8000/mcp or MCP_URL env var).",
    )
    parser.add_argument(
        "--traces-dir",
        default=str(Path(__file__).parent / "traces"),
        help="Directory to save trace JSON files (default: examples/traces/).",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="Number of tasks to run concurrently (default: 1). Rate-limited servers may need 1.",
    )
    args = parser.parse_args()

    traces_dir = Path(args.traces_dir)
    traces_dir.mkdir(parents=True, exist_ok=True)

    tasks_to_run = BENCHMARK_TASKS
    if args.task is not None:
        if args.task >= len(BENCHMARK_TASKS):
            logger.error(
                "Task index %d out of range (0–%d)", args.task, len(BENCHMARK_TASKS) - 1
            )
            sys.exit(1)
        tasks_to_run = [BENCHMARK_TASKS[args.task]]

    logger.info(
        "Running %d benchmark task(s) against %s", len(tasks_to_run), args.mcp_url
    )
    logger.info("Traces will be saved to: %s", traces_dir)

    semaphore = asyncio.Semaphore(args.concurrency)

    async def run_with_semaphore(task: dict) -> dict:
        async with semaphore:
            return await run_task(task, mcp_url=args.mcp_url, traces_dir=traces_dir)

    results = await asyncio.gather(
        *[run_with_semaphore(t) for t in tasks_to_run],
        return_exceptions=False,
    )

    # Summary
    passed = sum(1 for r in results if r["success"])
    failed = len(results) - passed
    logger.info("")
    logger.info("=" * 60)
    logger.info("HARNESS SUMMARY: %d passed, %d failed", passed, failed)
    logger.info("=" * 60)

    for r in results:
        status = "PASS" if r["success"] else "FAIL"
        tool_count = len(r.get("tool_calls", []))
        logger.info(
            "[%s] %s  tools=%d  trace=%s",
            status,
            r["task_id"],
            tool_count,
            r.get("trace_file", "N/A"),
        )
        if r.get("error"):
            logger.info("       error: %s", r["error"])

    # Print eval command
    trace_files = " ".join(str(r["trace_file"]) for r in results if r.get("trace_file"))
    logger.info("")
    logger.info("To evaluate with agentevals:")
    logger.info(
        "  agentevals run %s \\\n"
        "    --eval-set examples/eval_set_usgs.json \\\n"
        "    -m tool_trajectory_avg_score \\\n"
        "    -m response_match_score",
        trace_files,
    )

    # Save summary JSON
    summary_file = traces_dir / "harness_summary.json"
    summary_file.write_text(json.dumps(results, indent=2, default=str))
    logger.info("Full summary saved → %s", summary_file)


if __name__ == "__main__":
    asyncio.run(main())
