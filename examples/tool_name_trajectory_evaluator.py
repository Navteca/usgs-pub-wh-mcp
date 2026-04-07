#!/usr/bin/env python3
"""
Custom agentevals evaluator: tool_name_in_order_score.

Reads EvalInput JSON from stdin.
Checks that each expected tool name appears in the actual tool calls list
in the specified order (IN_ORDER semantics, args ignored).
Writes EvalResult JSON to stdout.

Usage: referenced via examples/eval_config.yaml as a 'code' evaluator.
"""

from __future__ import annotations

import json
import sys
from typing import Any


def _tool_names_in_order(actual: list[str], expected: list[str]) -> bool:
    """Return True if every name in expected appears in actual in order."""
    if not expected:
        return True
    exp_iter = iter(expected)
    current = next(exp_iter)
    for name in actual:
        if name == current:
            try:
                current = next(exp_iter)
            except StopIteration:
                return True
    return False


def evaluate(payload: dict[str, Any]) -> dict[str, Any]:
    invocations = payload.get("invocations", [])
    expected_invocations = payload.get("expected_invocations") or []
    threshold = payload.get("threshold", 0.5)

    per_scores: list[float] = []

    for i, actual_inv in enumerate(invocations):
        actual_tools: list[str] = [
            tc["name"]
            for tc in actual_inv.get("intermediate_steps", {}).get("tool_calls", [])
        ]

        if i < len(expected_invocations):
            expected_tools: list[str] = [
                tc["name"]
                for tc in expected_invocations[i]
                .get("intermediate_steps", {})
                .get("tool_calls", [])
            ]
        else:
            expected_tools = []

        score = 1.0 if _tool_names_in_order(actual_tools, expected_tools) else 0.0
        per_scores.append(score)

    overall = sum(per_scores) / len(per_scores) if per_scores else 0.0
    status = "PASSED" if overall >= threshold else "FAILED"

    return {
        "score": overall,
        "status": status,
        "per_invocation_scores": per_scores,
        "details": {
            "match_type": "IN_ORDER_NAME_ONLY",
            "note": "Checks expected tool names appear in actual calls in order; args ignored.",
        },
    }


if __name__ == "__main__":
    payload = json.load(sys.stdin)
    result = evaluate(payload)
    print(json.dumps(result))
