#!/usr/bin/env python3
"""
USGS MCP Agent Harness — agentevals integration.

This script:
1. Starts an OpenAI Agents SDK agent connected to the USGS MCP server via
   streamable-http transport.
2. Runs each benchmark query defined in BENCHMARK_TASKS.
3. Captures spans via JaegerTracingProcessor that emits GenAI semantic
   convention tags (gen_ai.input.messages, gen_ai.output.messages,
   gen_ai.tool.name, etc.) so agentevals can auto-detect and convert traces.
4. Saves each run's trace as Jaeger JSON to examples/traces/.
5. Optionally streams spans live to an OTLP receiver when
   OTEL_EXPORTER_OTLP_ENDPOINT is set.

Usage
-----
# Prerequisites
#   Terminal 1 — MCP server
#   uv run python main.py --transport streamable-http --host 127.0.0.1 --port 8000
#
#   Terminal 2 — agentevals receiver (optional live UI)
#   agentevals serve --dev
#
#   Terminal 3 — this harness
#   export OPENAI_API_KEY=sk-...
#   export MCP_URL=http://127.0.0.1:8000/mcp        # default
#   export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318  # optional live export
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
OPENAI_API_KEY              required
MCP_URL                     MCP server URL (default: http://127.0.0.1:8000/mcp)
OTEL_EXPORTER_OTLP_ENDPOINT optional OTLP HTTP endpoint for live span export
OTEL_SERVICE_NAME           optional service name (default: usgs-warehouse-mcp)
OPENAI_AGENTS_DISABLE_TRACING  set 1 to suppress OpenAI backend tracing
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
# Ensure repo root on sys.path when run as a script
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

# NOTE: Do NOT set OPENAI_AGENTS_DISABLE_TRACING — we need SDK tracing active so
# JaegerTracingProcessor receives span callbacks from AgentSpanData, ResponseSpanData,
# and FunctionSpanData. Disabling it suppresses all span callbacks.

# ---------------------------------------------------------------------------
# OTel setup (optional — only when OTEL_EXPORTER_OTLP_ENDPOINT is set)
# ---------------------------------------------------------------------------

_otel_tracer = None


def _setup_otel() -> Any:
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
# Benchmark tasks — mirrors 10 workflow recipes in main.py docstring
# ---------------------------------------------------------------------------

BENCHMARK_TASKS = [
    {
        "id": "task_01_earthquakes",
        "description": "Basic topic search — earthquakes",
        "prompt": "Find me recent USGS publications related to earthquakes.",
        "expected_min_tool_calls": 1,
    },
    {
        "id": "task_02_multi_hazard_alaska",
        "description": "Multi-hazard risk briefing for Alaska",
        "prompt": (
            "What natural hazards should I worry about in Alaska? "
            "Please search for publications on each major hazard type separately: "
            "earthquakes, volcanoes, floods, and wildfires."
        ),
        "expected_min_tool_calls": 4,
    },
    {
        "id": "task_03_pfas_groundwater",
        "description": "PFAS + groundwater cross-disciplinary synthesizer",
        "prompt": (
            "Synthesize USGS research on PFAS contamination and groundwater. "
            "Search separately for: PFAS contamination, groundwater contamination, "
            "and PFAS groundwater together."
        ),
        "expected_min_tool_calls": 3,
    },
    {
        "id": "task_04_claim_verification",
        "description": "Multi-step fact verification — search then index_id lookup",
        "prompt": (
            "Find USGS publications about low-frequency earthquakes near the Mendocino slab. "
            "Then retrieve the most relevant one using its index_id to verify the details."
        ),
        "expected_min_tool_calls": 2,
    },
    {
        "id": "task_05_critical_minerals_trend",
        "description": "Temporal trend analysis — critical minerals",
        "prompt": (
            "Analyze the trend in USGS critical minerals research over time. "
            "Use pagination to retrieve multiple pages of results and summarize "
            "how the volume of publications has changed."
        ),
        "expected_min_tool_calls": 2,
    },
    {
        "id": "task_06_title_search",
        "description": "Title exact-match search",
        "prompt": (
            "Find USGS publications with 'National Water Summary' in the title. "
            "Use the title search parameter."
        ),
        "expected_min_tool_calls": 1,
    },
    {
        "id": "task_07_research_gap",
        "description": "Research gap detection — arsenic groundwater",
        "prompt": (
            "Identify research gaps in USGS arsenic groundwater studies. "
            "Search separately for: arsenic groundwater contamination, "
            "arsenic remediation groundwater, and arsenic groundwater monitoring. "
            "Then compare total_count across the three searches."
        ),
        "expected_min_tool_calls": 3,
    },
    {
        "id": "task_08_hawaii_eruption",
        "description": "Emergency response literature kit — Hawaii volcanic eruption",
        "prompt": (
            "Compile an emergency response literature kit for a Hawaii volcanic eruption. "
            "Search for 'volcano eruption Hawaii' and 'volcanic hazard Hawaii lava'."
        ),
        "expected_min_tool_calls": 2,
    },
    {
        "id": "task_09_water_quality_data",
        "description": "Data asset discovery — water quality datasets",
        "prompt": (
            "Find USGS water quality monitoring and assessment publications that include "
            "links to datasets. Search for 'water quality monitoring data' and "
            "'water quality assessment'. Identify data release and dataset-type assets."
        ),
        "expected_min_tool_calls": 2,
    },
    {
        "id": "task_10_policy_brief",
        "description": "Policy impact briefing — water availability",
        "prompt": (
            "Find a USGS water availability assessment publication and produce a "
            "one-page policy brief using its abstract and citation metadata."
        ),
        "expected_min_tool_calls": 1,
    },
]

# ---------------------------------------------------------------------------
# Jaeger JSON trace builder
# ---------------------------------------------------------------------------


class JaegerTraceBuilder:
    """
    Builds a Jaeger-format JSON trace that agentevals can consume.

    agentevals auto-detects GenAI format when spans have:
      - gen_ai.input.messages + gen_ai.output.messages  → is_llm_span = True
      - gen_ai.tool.name                                 → is_tool_span = True
      - operation_name contains "agent"                 → is_invocation_span = True
    """

    def __init__(self, trace_id: str, service_name: str = "usgs-warehouse-mcp") -> None:
        self.trace_id = trace_id
        self.service_name = service_name
        self.spans: list[dict] = []

    def add_span(
        self,
        span_id: str,
        operation_name: str,
        start_time_us: int,
        duration_us: int,
        parent_span_id: str | None = None,
        tags: list[dict] | None = None,
    ) -> None:
        references = []
        if parent_span_id:
            references.append(
                {
                    "refType": "CHILD_OF",
                    "traceID": self.trace_id,
                    "spanID": parent_span_id,
                }
            )
        self.spans.append(
            {
                "traceID": self.trace_id,
                "spanID": span_id,
                "operationName": operation_name,
                "references": references,
                "startTime": start_time_us,
                "duration": max(duration_us, 1),
                "tags": tags or [],
                "logs": [],
                "processID": "p1",
                "warnings": None,
            }
        )

    def to_jaeger_json(self) -> dict:
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
# Helpers
# ---------------------------------------------------------------------------


def _make_tag(key: str, value: Any) -> dict:
    if isinstance(value, bool):
        return {"key": key, "type": "bool", "value": value}
    if isinstance(value, int):
        return {"key": key, "type": "int64", "value": value}
    if isinstance(value, float):
        return {"key": key, "type": "float64", "value": value}
    return {"key": key, "type": "string", "value": str(value)}


def _iso_to_us(ts: Any) -> int:
    try:
        from datetime import datetime

        if hasattr(ts, "timestamp"):
            return int(ts.timestamp() * 1e6)
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return int(dt.timestamp() * 1e6)
    except Exception:
        return int(time.time() * 1e6)


# ---------------------------------------------------------------------------
# SDK TracingProcessor — converts SDK spans to Jaeger + GenAI tags
# ---------------------------------------------------------------------------


class JaegerTracingProcessor:
    """
    Implements OpenAI Agents SDK TracingProcessor interface.

    Emits spans with GenAI semantic convention tags so agentevals
    auto-detects the trace format as "genai":

    is_llm_span   = span has gen_ai.request.model OR gen_ai.input.messages
    is_tool_span  = span has gen_ai.tool.name
    is_invocation = operation_name contains "agent"

    The SDK emits an AgentSpanData span as the trace root (parent_id=None).
    ResponseSpanData and FunctionSpanData spans are children of it.
    We pass SDK span_id/parent_id through directly so agentevals can build
    the correct parent-child tree.
    """

    def __init__(self, builder: JaegerTraceBuilder) -> None:
        self._builder = builder

    def on_trace_start(self, trace: Any) -> None:
        pass

    def on_trace_end(self, trace: Any) -> None:
        pass

    def on_span_start(self, span: Any) -> None:
        pass

    def on_span_end(self, span: Any) -> None:
        try:
            self._process_span(span)
        except Exception as exc:
            logger.debug("Failed to convert SDK span: %s", exc)

    def _process_span(self, span: Any) -> None:
        span_id = getattr(span, "span_id", None) or uuid.uuid4().hex[:16]
        # Use SDK parent_id directly. If None, span becomes a trace root.
        # Do NOT override with synthetic invocation_span_id — the AgentSpanData
        # span IS the root and must have parent_span_id=None so agentevals
        # recognises it as root_span and traverses its children correctly.
        parent_id = getattr(span, "parent_id", None)
        started_at = getattr(span, "started_at", None)
        ended_at = getattr(span, "ended_at", None)

        start_us = _iso_to_us(started_at) if started_at else int(time.time() * 1e6)
        end_us = _iso_to_us(ended_at) if ended_at else start_us + 1000
        duration_us = max(end_us - start_us, 1)

        span_data = getattr(span, "span_data", None)
        operation_name, tags = self._build_span_info(span, span_data)

        self._builder.add_span(
            span_id=span_id,
            operation_name=operation_name,
            start_time_us=start_us,
            duration_us=duration_us,
            parent_span_id=parent_id,
            tags=tags,
        )

    def _build_span_info(self, span: Any, span_data: Any) -> tuple[str, list[dict]]:
        """Return (operation_name, tags) with correct GenAI semantic convention tags."""
        tags: list[dict] = [
            _make_tag("otel.scope.name", "openai-agents-sdk"),
            _make_tag("span.kind", "internal"),
        ]

        if span_data is None:
            return getattr(span, "name", "unknown"), tags

        cls = type(span_data).__name__

        # ------------------------------------------------------------------
        # AgentSpanData  →  invocation span (op name contains "agent")
        # ------------------------------------------------------------------
        if cls == "AgentSpanData":
            name = getattr(span_data, "name", "agent")
            tags.append(_make_tag("gen_ai.operation.name", "invoke_agent"))
            tags.append(_make_tag("gen_ai.agent.name", name))
            tools = getattr(span_data, "tools", None)
            if tools:
                tags.append(_make_tag("gen_ai.agent.tools", json.dumps(tools)))
            return f"agent {name}", tags

        # ------------------------------------------------------------------
        # GenerationSpanData  →  LLM span (older SDK versions)
        # ResponseSpanData    →  LLM span (openai-agents >=0.13)
        # Needs gen_ai.input.messages + gen_ai.output.messages for agentevals
        # ------------------------------------------------------------------
        if cls in ("GenerationSpanData", "ResponseSpanData"):
            if cls == "GenerationSpanData":
                model = getattr(span_data, "model", None)
                inp = getattr(span_data, "input", None)  # list[Mapping] | None
                out = getattr(span_data, "output", None)  # list[Mapping] | None
                usage = getattr(span_data, "usage", None)

                tags.append(_make_tag("gen_ai.operation.name", "chat"))
                if model:
                    tags.append(_make_tag("gen_ai.request.model", model))

                input_msgs = inp if inp is not None else []
                output_msgs = out if out is not None else []
                tags.append(
                    _make_tag(
                        "gen_ai.input.messages", json.dumps(input_msgs, default=str)
                    )
                )
                tags.append(
                    _make_tag(
                        "gen_ai.output.messages", json.dumps(output_msgs, default=str)
                    )
                )
                if usage:
                    in_tok = (
                        usage.get("input_tokens")
                        if isinstance(usage, dict)
                        else getattr(usage, "input_tokens", None)
                    )
                    out_tok = (
                        usage.get("output_tokens")
                        if isinstance(usage, dict)
                        else getattr(usage, "output_tokens", None)
                    )
                    if in_tok is not None:
                        tags.append(_make_tag("gen_ai.usage.input_tokens", int(in_tok)))
                    if out_tok is not None:
                        tags.append(
                            _make_tag("gen_ai.usage.output_tokens", int(out_tok))
                        )
                return "llm_generation", tags

            # ResponseSpanData — openai-agents >= 0.13
            response = getattr(span_data, "response", None)
            inp = getattr(span_data, "input", None)  # list of message dicts

            model = getattr(response, "model", None) if response else None
            tags.append(_make_tag("gen_ai.operation.name", "chat"))
            if model:
                tags.append(_make_tag("gen_ai.request.model", model))

            # Build input messages list for agentevals
            input_msgs = inp if isinstance(inp, list) else []
            tags.append(
                _make_tag("gen_ai.input.messages", json.dumps(input_msgs, default=str))
            )

            # Build output messages from response.output items
            output_msgs: list[dict] = []
            output_tool_calls: list[dict] = []
            if response:
                output = getattr(response, "output", None) or []
                for item in output:
                    item_type = type(item).__name__
                    if item_type == "ResponseFunctionToolCall":
                        # Tool call emitted by the LLM
                        try:
                            args = json.loads(getattr(item, "arguments", "{}"))
                        except Exception:
                            args = {}
                        output_tool_calls.append(
                            {
                                "name": getattr(item, "name", ""),
                                "arguments": args,
                                "id": getattr(item, "call_id", None)
                                or getattr(item, "id", None),
                            }
                        )
                    elif item_type == "ResponseOutputMessage":
                        content_parts = getattr(item, "content", [])
                        text = ""
                        for part in content_parts:
                            t = getattr(part, "text", None)
                            if t:
                                text += t
                        if output_tool_calls:
                            output_msgs.append(
                                {
                                    "role": "assistant",
                                    "content": text,
                                    "tool_calls": output_tool_calls,
                                }
                            )
                            output_tool_calls = []
                        elif text:
                            output_msgs.append({"role": "assistant", "content": text})

                usage = getattr(response, "usage", None)
                if usage:
                    in_tok = getattr(usage, "input_tokens", None)
                    out_tok = getattr(usage, "output_tokens", None)
                    if in_tok is not None:
                        tags.append(_make_tag("gen_ai.usage.input_tokens", int(in_tok)))
                    if out_tok is not None:
                        tags.append(
                            _make_tag("gen_ai.usage.output_tokens", int(out_tok))
                        )

            tags.append(
                _make_tag(
                    "gen_ai.output.messages", json.dumps(output_msgs, default=str)
                )
            )
            return "llm_generation", tags

        # ------------------------------------------------------------------
        # FunctionSpanData  →  tool span
        # Needs gen_ai.tool.name for agentevals is_tool_span detection
        # ------------------------------------------------------------------
        if cls == "FunctionSpanData":
            name = getattr(span_data, "name", "unknown_tool")
            inp = getattr(span_data, "input", None)
            out = getattr(span_data, "output", None)
            mcp = getattr(span_data, "mcp_data", None)

            tags.append(_make_tag("gen_ai.operation.name", "execute_tool"))
            tags.append(_make_tag("gen_ai.tool.name", name))

            # Serialise input as tool call arguments
            if inp is not None:
                try:
                    parsed = json.loads(inp) if isinstance(inp, str) else inp
                    tags.append(
                        _make_tag(
                            "gen_ai.tool.call.arguments",
                            json.dumps(parsed, default=str),
                        )
                    )
                except Exception:
                    tags.append(
                        _make_tag("gen_ai.tool.call.arguments", str(inp)[:2000])
                    )

            # Serialise output as tool call result
            if out is not None:
                result_str = str(out)[:4000]
                tags.append(_make_tag("gen_ai.tool.call.result", result_str))

            if mcp:
                tags.append(_make_tag("gen_ai.tool.type", "MCPTool"))
                server = mcp.get("server_name", "") if isinstance(mcp, dict) else ""
                if server:
                    tags.append(_make_tag("gen_ai.tool.mcp_server", server))

            return f"execute_tool {name}", tags

        # ------------------------------------------------------------------
        # HandoffSpanData
        # ------------------------------------------------------------------
        if cls == "HandoffSpanData":
            to_agent = getattr(span_data, "to_agent", "unknown")
            tags.append(_make_tag("gen_ai.operation.name", "handoff"))
            tags.append(_make_tag("gen_ai.handoff.target", to_agent))
            return f"handoff {to_agent}", tags

        # ------------------------------------------------------------------
        # GuardrailSpanData
        # ------------------------------------------------------------------
        if cls == "GuardrailSpanData":
            name = getattr(span_data, "name", "guardrail")
            triggered = getattr(span_data, "triggered", False)
            tags.append(_make_tag("gen_ai.guardrail.name", name))
            tags.append(_make_tag("gen_ai.guardrail.triggered", bool(triggered)))
            return f"guardrail {name}", tags

        # ------------------------------------------------------------------
        # CustomSpanData / fallback
        # ------------------------------------------------------------------
        name = getattr(span_data, "name", None) or cls.replace("SpanData", "").lower()
        return name, tags

    def shutdown(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Main task runner
# ---------------------------------------------------------------------------


async def run_task(
    task: dict,
    mcp_url: str,
    traces_dir: Path,
) -> dict:
    """Run one benchmark task, save Jaeger JSON trace, return result dict."""
    try:
        from agents import Agent, Runner
        from agents.mcp import MCPServerStreamableHttp
        from agents.tracing import add_trace_processor
    except ImportError as exc:
        logger.error("openai-agents not installed. Run: uv sync\n%s", exc)
        sys.exit(1)

    task_id = task["id"]
    trace_id = uuid.uuid4().hex  # 32-char hex
    task_start_us = int(time.time() * 1e6)

    builder = JaegerTraceBuilder(trace_id=trace_id)
    processor = JaegerTracingProcessor(builder=builder)
    add_trace_processor(processor)

    logger.info("[%s] Starting: %s", task_id, task["description"])
    logger.info("[%s] Prompt: %s", task_id, task["prompt"][:120])

    result_payload: dict = {
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
            params={"url": mcp_url, "timeout": 60},
            cache_tools_list=True,
        ) as server:
            agent = Agent(
                name="USGS Research Agent",
                instructions=(
                    "You are a research assistant that searches USGS scientific publications. "
                    "Use the search_publications tool to find relevant publications. "
                    "Search with meaningful keywords, paginate when needed, "
                    "and deduplicate by index_id when merging results."
                ),
                mcp_servers=[server],
            )

            run_result = await Runner.run(agent, task["prompt"])

            final_output = run_result.final_output
            result_payload["final_output"] = str(final_output)[:5000]
            result_payload["success"] = True

            # Extract tool calls from new_items
            tool_calls = []
            for item in run_result.new_items:
                item_type = type(item).__name__
                if "ToolCall" in item_type or "FunctionCall" in item_type:
                    raw = getattr(item, "raw_item", None)
                    tool_name = getattr(item, "name", None) or getattr(
                        raw, "name", None
                    )
                    tool_args = getattr(item, "arguments", None) or getattr(
                        raw, "arguments", None
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
                "[%s] Done. tool_calls=%d output_len=%d",
                task_id,
                len(tool_calls),
                len(str(final_output)),
            )

    except Exception as exc:
        result_payload["error"] = str(exc)
        logger.error("[%s] Failed: %s", task_id, exc, exc_info=True)

    finally:
        task_end_us = int(time.time() * 1e6)

        # The SDK AgentSpanData span IS the root invocation span — it was already
        # captured by JaegerTracingProcessor.on_span_end with operation_name
        # "agent USGS Research Agent" and parent_span_id=None.
        # Do NOT add a duplicate synthetic root span here.

        trace_data = builder.to_jaeger_json()
        trace_file = traces_dir / f"{task_id}_{trace_id[:8]}.json"
        trace_file.write_text(json.dumps(trace_data, indent=2))
        result_payload["trace_file"] = str(trace_file)
        logger.info(
            "[%s] Trace saved → %s (%d spans)", task_id, trace_file, len(builder.spans)
        )

    return result_payload


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


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
        help="Number of concurrent tasks (default: 1).",
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

    logger.info("Running %d task(s) against %s", len(tasks_to_run), args.mcp_url)
    logger.info("Traces → %s", traces_dir)

    semaphore = asyncio.Semaphore(args.concurrency)

    async def _run(task: dict) -> dict:
        async with semaphore:
            return await run_task(task, mcp_url=args.mcp_url, traces_dir=traces_dir)

    results = await asyncio.gather(*[_run(t) for t in tasks_to_run])

    passed = sum(1 for r in results if r["success"])
    failed = len(results) - passed
    logger.info("")
    logger.info("=" * 60)
    logger.info("SUMMARY: %d passed, %d failed", passed, failed)
    logger.info("=" * 60)
    for r in results:
        status = "PASS" if r["success"] else "FAIL"
        logger.info(
            "[%s] %s  tools=%d  trace=%s",
            status,
            r["task_id"],
            len(r.get("tool_calls", [])),
            r.get("trace_file", "N/A"),
        )
        if r.get("error"):
            logger.info("       error: %s", r["error"])

    trace_files = " ".join(str(r["trace_file"]) for r in results if r.get("trace_file"))
    logger.info("")
    logger.info("Evaluate with:")
    logger.info(
        "  agentevals run %s \\\n"
        "    --eval-set examples/eval_set_usgs.json \\\n"
        "    -m tool_trajectory_avg_score \\\n"
        "    -m response_match_score",
        trace_files,
    )

    summary_file = traces_dir / "harness_summary.json"
    summary_file.write_text(json.dumps(results, indent=2, default=str))
    logger.info("Summary → %s", summary_file)


if __name__ == "__main__":
    asyncio.run(main())
