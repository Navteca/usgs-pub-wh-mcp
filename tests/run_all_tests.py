"""
Run All Tests
=============

This script runs all test suites for the USGS Publications Warehouse MCP Server.

Test Suites:
1. User Query Validation - Tests real-world user questions
2. Security Controls - Tests input validation, rate limiting, config
3. Tool Discovery - Tests progressive disclosure pattern
4. API Integration - Tests all tool endpoints with real API calls

Run with:
    cd /path/to/usgs-warehouse-mcp
    uv run python tests/run_all_tests.py
"""

import asyncio
import sys
import subprocess
from pathlib import Path


def run_test_file(test_file: Path) -> tuple[bool, str]:
    """Run a test file and return success status and output."""
    result = subprocess.run(
        [sys.executable, str(test_file)],
        capture_output=True,
        text=True,
        cwd=test_file.parent.parent,
    )
    
    output = result.stdout + result.stderr
    success = result.returncode == 0
    
    return success, output


def main():
    print("=" * 70)
    print("USGS Publications Warehouse MCP Server")
    print("Running All Test Suites")
    print("=" * 70)
    print()
    
    tests_dir = Path(__file__).parent
    
    test_files = [
        ("User Query Validation", tests_dir / "test_user_queries.py"),
        ("Security Controls", tests_dir / "test_security_controls.py"),
        ("Tool Discovery", tests_dir / "test_tool_discovery.py"),
        ("API Integration", tests_dir / "test_api_integration.py"),
        ("LLM Benchmark Tasks", tests_dir / "test_llm_benchmark_tasks.py"),
    ]
    
    results = []
    
    for name, test_file in test_files:
        print(f"\n{'=' * 70}")
        print(f"Running: {name}")
        print(f"File: {test_file.name}")
        print("=" * 70)
        
        if not test_file.exists():
            print(f"  ✗ Test file not found: {test_file}")
            results.append((name, False, "File not found"))
            continue
        
        success, output = run_test_file(test_file)
        results.append((name, success, output))
        
        # Print output
        print(output)
    
    # Final summary
    print()
    print("=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, success, _ in results if success)
    failed = len(results) - passed
    
    for name, success, _ in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"  {status}: {name}")
    
    print()
    print(f"Test Suites: {passed}/{len(results)} passed")
    
    if failed > 0:
        print("\nSome test suites failed. Review output above.")
        return 1
    else:
        print("\nAll test suites passed!")
        return 0


if __name__ == "__main__":
    sys.exit(main())
