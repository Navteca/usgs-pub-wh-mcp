"""
Test: API Integration
=====================

This test validates the full integration with the USGS Publications
Warehouse API, including:

1. search_publications endpoint works correctly
2. Response formatting is correct (field names, structure)
3. All parameter modes work (query, title, index_id)
4. Error handling works as expected

These tests make real API calls to the USGS server.

Run with:
    cd /path/to/usgs-warehouse-mcp
    uv run python tests/test_api_integration.py
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Reset singletons for clean test state
from security.rate_limiter import reset_rate_limiter
from security.http_client import reset_http_client
reset_rate_limiter()
reset_http_client()

from main import search_publications


async def test_search_publications():
    """Test basic search_publications endpoint."""
    print("Testing search_publications(query='water')...")

    result = await search_publications(query='water', page_size=3)

    passed = 0
    failed = 0

    if 'error' not in result:
        print("  ✓ Request succeeded")
        passed += 1
    else:
        print(f"  ✗ Request failed: {result['error']}")
        failed += 1
        return passed, failed

    # Check response structure
    if 'total_count' in result:
        print(f"  ✓ total_count present: {result['total_count']}")
        passed += 1
    else:
        print("  ✗ total_count missing")
        failed += 1

    if 'publications' in result and len(result['publications']) > 0:
        print(f"  ✓ publications array present with {len(result['publications'])} items")
        passed += 1
    else:
        print("  ✗ publications array missing or empty")
        failed += 1

    # Check publication structure uses correct field names
    if result.get('publications'):
        pub = result['publications'][0]
        required_fields = ['index_id', 'title', 'year', 'authors']
        for field in required_fields:
            if field in pub:
                passed += 1
            else:
                print(f"  ✗ Publication missing '{field}'")
                failed += 1

        if all(f in pub for f in required_fields):
            print(f"  ✓ Publication has required fields ({', '.join(required_fields)})")

    return passed, failed


async def test_search_by_title():
    """Test search_publications with title parameter."""
    print("\nTesting search_publications(title='groundwater')...")

    result = await search_publications(title='groundwater', page_size=3)

    passed = 0
    failed = 0

    if 'error' not in result:
        print(f"  ✓ Request succeeded: {result.get('total_count', 0)} publications")
        passed += 1
    else:
        print(f"  ✗ Request failed: {result['error']}")
        failed += 1

    if result.get('total_count', 0) > 0:
        print("  ✓ Title search returned results")
        passed += 1
    else:
        print("  ✗ Title search returned no results")
        failed += 1

    return passed, failed


async def test_search_by_index_id():
    """Test search_publications with index_id parameter."""
    print("\nTesting search_publications with index_id...")

    # First, search to get a valid index_id
    search_result = await search_publications(query='earthquake', page_size=1)

    if 'error' in search_result or not search_result.get('publications'):
        print("  ✗ Could not find a publication to get an index_id")
        return 0, 1

    index_id = search_result['publications'][0]['index_id']
    expected_title = search_result['publications'][0]['title']
    print(f"  Using index_id: {index_id}")

    result = await search_publications(index_id=index_id)

    passed = 0
    failed = 0

    if 'error' not in result:
        print("  ✓ Request succeeded")
        passed += 1
    else:
        print(f"  ✗ Request failed: {result['error']}")
        failed += 1
        return passed, failed

    if result.get('total_count', 0) == 1:
        print("  ✓ Exactly 1 result returned for index_id lookup")
        passed += 1
    else:
        print(f"  ✗ Expected 1 result, got {result.get('total_count', 0)}")
        failed += 1

    if result.get('publications') and result['publications'][0].get('index_id') == index_id:
        print("  ✓ Returned publication matches requested index_id")
        passed += 1
    else:
        print("  ✗ Returned publication does not match requested index_id")
        failed += 1

    return passed, failed


async def test_index_id_exclusive():
    """Test that index_id cannot be combined with query or title."""
    print("\nTesting index_id exclusivity...")

    passed = 0
    failed = 0

    result = await search_publications(index_id="70273506", query="earthquake")

    if 'error' in result:
        print("  ✓ Correctly rejected index_id + query combination")
        passed += 1
    else:
        print("  ✗ Should reject index_id + query combination")
        failed += 1

    result = await search_publications(index_id="70273506", title="test")

    if 'error' in result:
        print("  ✓ Correctly rejected index_id + title combination")
        passed += 1
    else:
        print("  ✗ Should reject index_id + title combination")
        failed += 1

    return passed, failed


async def test_pagination():
    """Test pagination parameters."""
    print("\nTesting pagination...")

    passed = 0
    failed = 0

    result = await search_publications(query='water', page_size=2, page_number=1)

    if 'error' not in result:
        print("  ✓ Page 1 request succeeded")
        passed += 1
    else:
        print(f"  ✗ Page 1 failed: {result['error']}")
        failed += 1
        return passed, failed

    # API may return page_size as string or int — normalize for comparison
    if int(result.get('page_size', 0)) == 2:
        print("  ✓ page_size correctly reflected in response")
        passed += 1
    else:
        print(f"  ✗ Expected page_size=2, got {result.get('page_size')}")
        failed += 1

    if int(result.get('page_number', 0)) == 1:
        print("  ✓ page_number correctly reflected in response")
        passed += 1
    else:
        print(f"  ✗ Expected page_number=1, got {result.get('page_number')}")
        failed += 1

    return passed, failed


async def test_empty_search():
    """Test search with no parameters returns recent publications."""
    print("\nTesting search with no parameters...")

    result = await search_publications(page_size=3)

    passed = 0
    failed = 0

    if 'error' not in result:
        print("  ✓ Request succeeded without any search parameters")
        passed += 1
    else:
        print(f"  ✗ Request failed: {result['error']}")
        failed += 1

    if result.get('total_count', 0) > 0:
        print(f"  ✓ Returned {result['total_count']} publications (most recent)")
        passed += 1
    else:
        print("  ✗ Expected results for parameterless search")
        failed += 1

    return passed, failed


async def run_all_tests():
    """Run all API integration tests."""
    print("=" * 70)
    print("USGS Publications Warehouse MCP Server")
    print("Test: API Integration")
    print("=" * 70)
    print()
    print("Testing integration with the USGS Publications Warehouse API.")
    print("These tests make real API calls.")
    print()

    total_passed = 0
    total_failed = 0

    tests = [
        test_search_publications,
        test_search_by_title,
        test_search_by_index_id,
        test_index_id_exclusive,
        test_pagination,
        test_empty_search,
    ]

    for test_func in tests:
        try:
            passed, failed = await test_func()
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
        print("All API integration tests passed!")
        return 0


if __name__ == "__main__":
    exit_code = asyncio.run(run_all_tests())
    sys.exit(exit_code)
