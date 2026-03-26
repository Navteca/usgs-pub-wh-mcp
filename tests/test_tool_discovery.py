"""
Test: Tool Discovery (Progressive Disclosure)
==============================================

This test validates the tool registry that implements the progressive
disclosure pattern from Anthropic's code execution with MCP.

The progressive disclosure pattern allows agents to:
1. List available tools without loading all definitions
2. Search for relevant tools by keyword
3. Load only the tool definitions they need

Reference:
https://www.anthropic.com/engineering/code-execution-with-mcp

Run with:
    cd /path/to/usgs-warehouse-mcp
    uv run python tests/test_tool_discovery.py
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from security.tool_registry import get_tool_registry, ToolCategory


def test_list_tools():
    """Test listing all available tools."""
    print("Testing list_tools()...")

    registry = get_tool_registry()
    tools = registry.list_tools()

    print(f"  Found {len(tools)} tools: {tools}")

    passed = 0
    failed = 0

    if len(tools) >= 1:
        print("  ✓ At least 1 tool registered")
        passed += 1
    else:
        print(f"  ✗ Expected at least 1 tool, got {len(tools)}")
        failed += 1

    if "search_publications" in tools:
        print("  ✓ Tool 'search_publications' found")
        passed += 1
    else:
        print("  ✗ Tool 'search_publications' not found")
        failed += 1

    return passed, failed


def test_list_tools_by_category():
    """Test listing tools filtered by category."""
    print("\nTesting list_tools(category=SEARCH)...")

    registry = get_tool_registry()
    tools = registry.list_tools(category=ToolCategory.SEARCH)

    print(f"  Found {len(tools)} search tools: {tools}")

    passed = 0
    failed = 0

    if "search_publications" in tools:
        print("  ✓ search_publications in search category")
        passed += 1
    else:
        print("  ✗ search_publications should be in search category")
        failed += 1

    return passed, failed


def test_search_tools():
    """Test searching for tools by keyword."""
    print("\nTesting search_tools(query='publication')...")

    registry = get_tool_registry()
    matches = registry.search_tools("publication")

    print(f"  Found {len(matches)} matching tools")

    passed = 0
    failed = 0

    if len(matches) >= 1:
        print("  ✓ At least 1 tool matches 'publication'")
        passed += 1
    else:
        print(f"  ✗ Expected at least 1 match, got {len(matches)}")
        failed += 1

    if matches and "name" in matches[0] and "description" in matches[0]:
        print("  ✓ Matches include name and description (summary format)")
        passed += 1
    else:
        print("  ✗ Matches should include name and description")
        failed += 1

    return passed, failed


def test_search_tools_detail_levels():
    """Test different detail levels in search."""
    print("\nTesting search_tools detail levels...")

    registry = get_tool_registry()
    passed = 0
    failed = 0

    # Test name_only
    matches = registry.search_tools("publication", detail_level="name_only")
    if matches and list(matches[0].keys()) == ["name"]:
        print("  ✓ name_only returns only names")
        passed += 1
    else:
        print("  ✗ name_only should return only names")
        failed += 1

    # Test summary
    matches = registry.search_tools("publication", detail_level="summary")
    match = matches[0] if matches else {}
    if "name" in match and "description" in match and "category" in match:
        print("  ✓ summary returns name, description, category")
        passed += 1
    else:
        print("  ✗ summary should return name, description, category")
        failed += 1

    # Test full
    matches = registry.search_tools("search_publications", detail_level="full")
    match = matches[0] if matches else {}
    if "parameters" in match and "examples" in match:
        print("  ✓ full returns parameters and examples")
        passed += 1
    else:
        print("  ✗ full should return parameters and examples")
        failed += 1

    return passed, failed


def test_get_tool_definition():
    """Test getting a full tool definition."""
    print("\nTesting get_tool('search_publications')...")

    registry = get_tool_registry()
    result = registry.get_tool("search_publications")

    passed = 0
    failed = 0

    if result is not None:
        print("  ✓ Tool definition retrieved successfully")
        passed += 1
    else:
        print("  ✗ Tool definition not found")
        failed += 1
        return passed, failed

    # Check required fields
    required_fields = ["name", "description", "category", "parameters", "examples"]
    for field in required_fields:
        if field in result:
            print(f"  ✓ Definition includes '{field}'")
            passed += 1
        else:
            print(f"  ✗ Definition missing '{field}'")
            failed += 1

    # Check parameters include all actual tool params
    params = result.get("parameters", {})
    expected_params = ["query", "title", "index_id", "page_size", "page_number"]
    for param in expected_params:
        if param in params:
            print(f"  ✓ Parameter '{param}' documented")
            passed += 1
        else:
            print(f"  ✗ Parameter '{param}' not documented")
            failed += 1

    return passed, failed


def test_nonexistent_tool():
    """Test getting definition for a tool that doesn't exist."""
    print("\nTesting get_tool('nonexistent_tool')...")

    registry = get_tool_registry()
    result = registry.get_tool("nonexistent_tool")

    passed = 0
    failed = 0

    if result is None:
        print("  ✓ Returns None for nonexistent tool")
        passed += 1
    else:
        print("  ✗ Should return None for nonexistent tool")
        failed += 1

    return passed, failed


def test_no_stale_tools():
    """Verify that non-existent tools are NOT in the registry."""
    print("\nTesting that removed tools are not registered...")

    registry = get_tool_registry()
    all_tools = registry.list_tools()

    passed = 0
    failed = 0

    removed_tools = [
        "get_publication",
        "get_multiple_publications",
        "get_recent_publications",
        "get_modified_publications",
        "get_publication_types",
        "get_publication_subtypes",
        "get_publication_series",
        "get_cost_centers",
        "list_tools",
        "search_tools",
        "get_tool_definition",
        "get_openai_tools_schema",
        "get_rate_limit_status",
    ]

    for tool_name in removed_tools:
        if tool_name not in all_tools:
            passed += 1
        else:
            print(f"  ✗ Stale tool '{tool_name}' still registered")
            failed += 1

    if failed == 0:
        print(f"  ✓ No stale tools found ({len(removed_tools)} verified)")

    return passed, failed


def run_all_tests():
    """Run all tool discovery tests."""
    print("=" * 70)
    print("USGS Publications Warehouse MCP Server")
    print("Test: Tool Discovery (Progressive Disclosure)")
    print("=" * 70)
    print()
    print("Testing the tool registry for progressive disclosure.")
    print()

    total_passed = 0
    total_failed = 0

    tests = [
        test_list_tools,
        test_list_tools_by_category,
        test_search_tools,
        test_search_tools_detail_levels,
        test_get_tool_definition,
        test_nonexistent_tool,
        test_no_stale_tools,
    ]

    for test_func in tests:
        try:
            passed, failed = test_func()
            total_passed += passed
            total_failed += failed
        except Exception as e:
            print(f"  ✗ EXCEPTION: {e}")
            total_failed += 1

    # Summary
    print()
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"  Total assertions: {total_passed + total_failed}")
    print(f"  Passed: {total_passed}")
    print(f"  Failed: {total_failed}")
    print()

    if total_failed > 0:
        print("Some tests failed. Check the output above for details.")
        return 1
    else:
        print("All tool discovery tests passed!")
        return 0


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
