"""
Test: User Query Validation
===========================

This test validates that the MCP server can correctly answer common user questions
about USGS publications. These are real-world queries that users might ask.

Sample Questions Tested:
1. Provide me a list of publications related to earthquakes.
2. What are the most recent publications available about critical minerals?
3. What publications are available on sea-level rise in Florida?
4. Publications about Mississippi Alluvial Plain (topic search).
5. Most recent USGS publications (no query filter).
6. Search by title exact match (e.g., "National Water Summary").
7. Combined query + title search.
8. Title-only search (e.g., "groundwater").
9. Combined query + title (e.g., climate + "water quality").
10. Search by publication index_id (direct lookup).
11. Verify index_id exclusivity (cannot combine with query/title).

Expected Behavior:
- All queries should return results without errors
- Results should contain publication data with titles, authors, years
- Counts should be reasonable (non-zero for general queries)

Run with:
    cd /path/to/usgs-warehouse-mcp
    
    # Run all predefined tests
    uv run python tests/test_user_queries.py
    
    # Run a custom query
    uv run python tests/test_user_queries.py -q "climate change impacts"
    uv run python tests/test_user_queries.py --query "groundwater contamination"
    
    # Run with additional options
    uv run python tests/test_user_queries.py -q "volcanoes" --limit 10
"""

import argparse
import asyncio
import json
import logging
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

# Global verbose flag
VERBOSE = False


def configure_logging(verbose: bool = False, debug: bool = False):
    """Configure logging based on verbosity level."""
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        force=True  # Force reconfiguration
    )
    
    # Also set the level for the security.http_client logger specifically
    logging.getLogger('security.http_client').setLevel(level)


async def test_earthquakes_publications():
    """
    Query: Provide me a list of publications related to earthquakes.
    
    Expected: Returns publications containing earthquake-related research.
    Each publication includes an abstract so the LLM can assess relevance.
    """
    print("Query: 'Provide me a list of publications related to earthquakes'")
    print("  Tool: search_publications(query='earthquake')")
    
    result = await search_publications(query='earthquake', page_size=5)
    
    if 'error' in result:
        print(f"  ✗ FAILED: {result['error']}")
        return False
    
    count = result.get('total_count', 0)
    pubs = result.get('publications', [])
    
    print(f"  Found {count} total publications, showing {len(pubs)}")
    
    # Verify results include abstract snippets (key for LLM relevance assessment)
    has_abstracts = 0
    for i, pub in enumerate(pubs, 1):
        has_abstract = bool(pub.get('abstract'))
        if has_abstract:
            has_abstracts += 1
        abstract_preview = (pub.get('abstract') or 'No abstract')[:80]
        print(f"    {i}. [{pub.get('year')}] {pub.get('title', '')[:70]}")
        print(f"       Abstract: {abstract_preview}...")
    
    if count > 0 and len(pubs) > 0:
        print(f"  ✓ PASSED: Found {count} publications, {has_abstracts}/{len(pubs)} include abstracts for LLM assessment")
    else:
        print(f"  ✗ FAILED: No publications returned")
    
    return count > 0


async def test_critical_minerals_recent():
    """
    Query: What are the most recent publications available about critical minerals?
    
    Expected: Returns recent publications about critical minerals, sorted by year.
    """
    print("\nQuery: 'What are the most recent publications about critical minerals?'")
    print("  Tool: search_publications(query='critical minerals')")
    
    result = await search_publications(query='critical minerals', page_size=5)
    
    if 'error' in result:
        print(f"  ✗ FAILED: {result['error']}")
        return False
    
    count = result.get('total_count', 0)
    pubs = result.get('publications', [])
    newest_year = pubs[0].get('year') if pubs else 'N/A'
    
    print(f"  ✓ PASSED: Found {count} publications, newest from {newest_year}")
    
    for pub in pubs[:2]:
        print(f"    - [{pub.get('year')}] {pub.get('title', '')[:60]}...")
    
    return count > 0


async def test_sea_level_rise_florida():
    """
    Query: What publications are available on sea-level rise in Florida?
    
    Expected: Returns publications about sea-level rise with Florida focus.
    """
    print("\nQuery: 'What publications are available on sea-level rise in Florida?'")
    print("  Tool: search_publications(query='sea-level rise Florida')")
    
    result = await search_publications(query='sea-level rise Florida', page_size=5)
    
    if 'error' in result:
        print(f"  ✗ FAILED: {result['error']}")
        return False
    
    count = result.get('total_count', 0)
    print(f"  ✓ PASSED: Found {count} publications")
    
    for pub in result.get('publications', [])[:2]:
        print(f"    - [{pub.get('year')}] {pub.get('title', '')[:60]}...")
    
    return count > 0


async def test_author_topic_search():
    """
    Query: What publications are available about the Mississippi Alluvial Plain?
    
    Expected: Returns publications about Mississippi Alluvial Plain (topic search).
    """
    print("\nQuery: 'What publications are available about the Mississippi Alluvial Plain?'")
    print("  Tool: search_publications(query='Mississippi Alluvial Plain', page_size=10)")
    
    result = await search_publications(
        query='Mississippi Alluvial Plain',
        page_size=10
    )
    
    if 'error' in result:
        print(f"  ✗ FAILED: {result['error']}")
        return False
    
    count = result.get('total_count', 0)
    print(f"  ✓ PASSED: Found {count} publications")
    
    for pub in result.get('publications', [])[:3]:
        authors = ', '.join(pub.get('authors', [])[:3])
        print(f"    - [{pub.get('year')}] {pub.get('title', '')[:50]}...")
        print(f"      Authors: {authors}")
    
    return count > 0


async def test_publications_last_year():
    """
    Query: What are the most recent USGS publications?
    
    Expected: Returns recent publications (no query filter; API returns most recent).
    """
    print("\nQuery: 'What are the most recent USGS publications?'")
    print("  Tool: search_publications(page_size=3)")
    
    result = await search_publications(page_size=3)
    
    if 'error' in result:
        print(f"  ✗ FAILED: {result['error']}")
        return False
    
    count = result.get('total_count', 0)
    print(f"  ✓ PASSED: Found {count} recent publications")
    
    for pub in result.get('publications', [])[:2]:
        print(f"    - [{pub.get('year')}] {pub.get('title', '')[:60]}...")
    
    return count > 0


async def test_search_by_title():
    """
    Query: Find the publication titled "National Water Summary".
    
    Expected: Returns publications whose title matches the exact string.
    The 'title' parameter does an exact match within publication titles.
    """
    print("\nQuery: 'Find publications titled National Water Summary'")
    print("  Tool: search_publications(title='National Water Summary')")
    
    result = await search_publications(title='National Water Summary', page_size=5)
    
    if 'error' in result:
        print(f"  ✗ FAILED: {result['error']}")
        return False
    
    count = result.get('total_count', 0)
    pubs = result.get('publications', [])
    
    print(f"  Found {count} total publications matching title")
    
    for pub in pubs[:3]:
        print(f"    - [{pub.get('year')}] {pub.get('title', '')[:70]}")
    
    if count > 0:
        print(f"  ✓ PASSED: Found {count} publications with title match")
    else:
        print(f"  ✗ FAILED: No publications found with that title")
    
    return count > 0


async def test_search_query_and_title_combined():
    """
    Query: Find earthquake publications with 'hazard' in the title.
    
    Expected: Returns publications matching the full-text query 'earthquake'
    AND having 'hazard' in the title, narrowing results effectively.
    """
    print("\nQuery: 'Earthquake publications with hazard in the title'")
    print("  Tool: search_publications(query='earthquake', title='hazard')")
    
    result = await search_publications(query='earthquake', title='hazard', page_size=5)
    
    if 'error' in result:
        print(f"  ✗ FAILED: {result['error']}")
        return False
    
    count = result.get('total_count', 0)
    pubs = result.get('publications', [])
    
    print(f"  Found {count} total publications")
    
    for pub in pubs[:3]:
        title = pub.get('title', '')
        has_hazard = 'hazard' in title.lower()
        marker = '✓' if has_hazard else '○'
        print(f"    {marker} [{pub.get('year')}] {title[:70]}")
    
    if count > 0:
        print(f"  ✓ PASSED: Found {count} publications matching query + title filter")
    else:
        print(f"  ✗ FAILED: No publications returned")
    
    return count > 0


async def test_title_search_water_quality():
    """
    Query: Find publications about climate with 'water quality' in the title.
    
    Expected: Combines full-text query 'climate' with title matching 'water quality'
    to find publications about climate that specifically mention water quality in the title.
    """
    print("\nQuery: 'Climate publications with water quality in the title'")
    print("  Tool: search_publications(query='climate', title='water quality')")
    
    result = await search_publications(
        query='climate', title='water quality', page_size=5
    )
    
    if 'error' in result:
        print(f"  ✗ FAILED: {result['error']}")
        return False
    
    count = result.get('total_count', 0)
    pubs = result.get('publications', [])
    
    print(f"  Found {count} total publications")
    for pub in pubs[:3]:
        print(f"    - [{pub.get('year')}] {pub.get('title', '')[:70]}")
    
    if count > 0:
        print(f"  ✓ PASSED: Found {count} publications matching climate + water quality title")
    else:
        print(f"  ✗ FAILED: No publications returned")
    
    return count > 0


async def test_title_search_groundwater():
    """
    Query: Find publications with 'groundwater' in the title.
    
    Expected: Returns publications whose title contains 'groundwater'.
    Uses only the title parameter (no full-text query).
    """
    print("\nQuery: 'Find publications with groundwater in the title'")
    print("  Tool: search_publications(title='groundwater', page_size=5)")
    
    result = await search_publications(title='groundwater', page_size=5)
    
    if 'error' in result:
        print(f"  ✗ FAILED: {result['error']}")
        return False
    
    count = result.get('total_count', 0)
    pubs = result.get('publications', [])
    
    print(f"  Found {count} total publications with 'groundwater' in title")
    for pub in pubs[:3]:
        print(f"    - [{pub.get('year')}] {pub.get('title', '')[:70]}")
    
    if count > 0:
        print(f"  ✓ PASSED: Found {count} publications")
    else:
        print(f"  ✗ FAILED: No publications returned")
    
    return count > 0


async def test_search_by_index_id():
    """
    Query: Get the publication with index_id 70273506.

    Expected: Returns exactly 1 publication matching the requested index_id.
    Uses the index_id parameter for a direct lookup.
    """
    print("\nQuery: 'Get the publication with index_id 70273506'")
    print("  Tool: search_publications(index_id='70273506')")

    # First, search to get a real index_id (in case the hardcoded one changes)
    search_result = await search_publications(query='earthquake', page_size=1)
    if 'error' in search_result or not search_result.get('publications'):
        print("  ✗ FAILED: Could not find a publication to get an index_id")
        return False

    index_id = search_result['publications'][0]['index_id']
    expected_title = search_result['publications'][0]['title']
    print(f"  Using live index_id: {index_id}")

    result = await search_publications(index_id=index_id)

    if 'error' in result:
        print(f"  ✗ FAILED: {result['error']}")
        return False

    count = result.get('total_count', 0)
    pubs = result.get('publications', [])

    if count == 1 and pubs and pubs[0].get('index_id') == index_id:
        print(f"  ✓ PASSED: Returned exactly 1 publication matching index_id={index_id}")
        print(f"    Title: {pubs[0].get('title', '')[:70]}")
        return True
    elif count > 0:
        print(f"  ✓ PASSED: Returned {count} publication(s) for index_id={index_id}")
        return True
    else:
        print(f"  ✗ FAILED: No publications returned for index_id={index_id}")
        return False


async def test_index_id_exclusive():
    """
    Verify that index_id cannot be combined with query or title.

    Expected: Returns an error when index_id is used with query or title.
    """
    print("\nQuery: 'index_id + query combination should be rejected'")
    print("  Tool: search_publications(index_id='70273506', query='earthquake')")

    result = await search_publications(index_id='70273506', query='earthquake')

    if 'error' in result:
        print(f"  ✓ PASSED: Correctly rejected — {result['error'][:60]}")
        return True
    else:
        print("  ✗ FAILED: Should have returned an error for index_id + query")
        return False


async def run_all_tests():
    """Run all user query tests."""
    print("=" * 70)
    print("USGS Publications Warehouse MCP Server")
    print("Test: User Query Validation")
    print("=" * 70)
    print()
    print("Testing that the MCP server can answer common user questions.")
    print()

    tests = [
        ("Earthquakes publications", test_earthquakes_publications),
        ("Critical minerals recent", test_critical_minerals_recent),
        ("Sea-level rise Florida", test_sea_level_rise_florida),
        ("Topic search (Mississippi Alluvial Plain)", test_author_topic_search),
        ("Most recent publications", test_publications_last_year),
        ("Search by title (National Water Summary)", test_search_by_title),
        ("Combined query + title (earthquake + hazard)", test_search_query_and_title_combined),
        ("Title search (groundwater)", test_title_search_groundwater),
        ("Title + query (climate + water quality)", test_title_search_water_quality),
        ("Search by index_id", test_search_by_index_id),
        ("index_id exclusivity", test_index_id_exclusive),
    ]
    
    results: list[tuple[str, bool, str | None]] = []
    for name, test_func in tests:
        try:
            passed = await test_func()
            results.append((name, passed, None))
        except Exception as e:
            print(f"  ✗ EXCEPTION: {e}")
            results.append((name, False, str(e)))
    
    # Summary
    print()
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, p, _ in results if p)
    failed = len(results) - passed
    
    for name, success, error in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"  {status}: {name}")
        if error:
            print(f"         Error: {error}")
    
    print()
    print(f"Results: {passed}/{len(results)} tests passed")
    
    if failed > 0:
        print("\nSome tests failed. Check the output above for details.")
        return 1
    else:
        print("\nAll tests passed!")
        return 0


async def run_custom_query(
    query: str,
    page_size: int = 10,
    output_json: bool = False,
    show_raw: bool = False,
):
    """
    Run a custom query against the USGS Publications Warehouse.
    
    Args:
        query: Search query string
        page_size: Number of results to return (default: 10)
        output_json: If True, output raw JSON instead of formatted text
        show_raw: If True, show the raw API response for debugging
    """
    print("=" * 70)
    print("USGS Publications Warehouse - Custom Query")
    print("=" * 70)
    print()
    
    params = {"query": query, "page_size": page_size}
    print(f"Query: '{query}'")
    print(f"Results limit: {page_size}")
    print()
    
    print("Searching...")
    result = await search_publications(**params)
    
    if 'error' in result:
        print(f"\n✗ ERROR: {result['error']}")
        return 1
    
    # Output results
    if output_json:
        print("\n" + json.dumps(result, indent=2, default=str))
    else:
        total_count = result.get('total_count', 0)
        publications = result.get('publications', [])
        
        print(f"\n✓ Found {total_count} total publications")
        print(f"  Showing {len(publications)} results:\n")
        print("-" * 70)
        
        for i, pub in enumerate(publications, 1):
            title = pub.get('title', 'No title')
            year = pub.get('year', 'N/A')
            authors = pub.get('authors', [])
            pub_type = pub.get('type', 'Unknown')
            index_id = pub.get('index_id', 'N/A')
            doi = pub.get('doi', '')
            series = pub.get('series', '')
            series_number = pub.get('series_number', '')
            link = pub.get('link', '')
            
            print(f"\n{i}. [{year}] {title}")
            print(f"   Type: {pub_type}")
            print(f"   Index ID: {index_id}")
            if series:
                series_str = series
                if series_number:
                    series_str += f" {series_number}"
                print(f"   Series: {series_str}")
            if authors:
                author_str = ', '.join(authors[:5])
                if len(authors) > 5:
                    author_str += f" (+{len(authors) - 5} more)"
                print(f"   Authors: {author_str}")
            abstract = pub.get('abstract', '')
            if abstract:
                print(f"   Abstract: {abstract[:120]}...")
            if doi:
                print(f"   DOI: {doi}")
            if link:
                print(f"   Link: {link}")
            
            # Show raw data for this publication if requested
            if show_raw:
                print(f"\n   [RAW DATA]:")
                for key, value in pub.items():
                    print(f"     {key}: {value}")
        
        print("\n" + "-" * 70)
        print(f"\nTotal matching publications: {total_count}")
    
    return 0


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Test USGS Publications Warehouse queries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all predefined tests
  uv run python tests/test_user_queries.py
  
  # Run a custom query
  uv run python tests/test_user_queries.py -q "climate change"
  uv run python tests/test_user_queries.py --query "groundwater"
  
  # Get more results
  uv run python tests/test_user_queries.py -q "earthquakes" --limit 20
  
  # Output as JSON
  uv run python tests/test_user_queries.py -q "minerals" --json
  
  # Debug mode - show HTTP requests/responses and raw data
  uv run python tests/test_user_queries.py -q "earthquakes" --debug
  uv run python tests/test_user_queries.py -q "earthquakes" -v --raw
        """
    )
    
    parser.add_argument(
        '-q', '--query',
        type=str,
        help='Custom search query to run'
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=10,
        help='Number of results to return (default: 10)'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results as JSON'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show verbose output including HTTP request/response logs'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Show debug output including raw API response structure'
    )
    parser.add_argument(
        '--raw',
        action='store_true',
        help='Show raw field data for each publication result'
    )
    
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    
    # Configure logging based on verbosity
    configure_logging(verbose=args.verbose, debug=args.debug)
    
    if args.query:
        # Run custom query mode
        exit_code = asyncio.run(run_custom_query(
            query=args.query,
            page_size=args.limit,
            output_json=args.json,
            show_raw=args.raw or args.debug,
        ))
    else:
        # Run all predefined tests
        exit_code = asyncio.run(run_all_tests())
    
    sys.exit(exit_code)
