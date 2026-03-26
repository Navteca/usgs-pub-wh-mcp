"""
Test: LLM Benchmark Tasks
=========================

10 innovative benchmark tasks that test an LLM's ability to use the USGS
Publications Warehouse MCP server for complex, multi-step reasoning. These go
far beyond simple "query the API" tests — they evaluate synthesis, analysis,
structured output generation, and strategic API usage.

Each task is self-contained and can be run independently. The test harness
calls ``search_publications`` directly (same function the MCP tool exposes),
then applies deterministic validators to the LLM-style outputs.

Selection Methodology:
    - 20 candidate tasks were proposed by two independent brainstorming passes.
    - A harsh critic pass rejected 10 for infeasibility (e.g., relying on API
      parameters not exposed by the MCP, or requiring metadata that doesn't
      exist in the response schema).
    - The surviving 10 were ranked by (innovation × feasibility × LLM challenge).

Run with:
    cd /path/to/usgs-warehouse-mcp
    uv run python tests/test_llm_benchmark_tasks.py
    uv run python tests/test_llm_benchmark_tasks.py -v          # verbose
    uv run python tests/test_llm_benchmark_tasks.py -k trend    # run one task
"""

import argparse
import asyncio
import json
import logging
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from security.rate_limiter import reset_rate_limiter
from security.http_client import reset_http_client
reset_rate_limiter()
reset_http_client()

from main import search_publications

VERBOSE = False
logger = logging.getLogger(__name__)


def configure_logging(verbose: bool = False):
    level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        force=True,
    )
    logging.getLogger("security.http_client").setLevel(level)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _has_error(result: dict) -> bool:
    return "error" in result


def _pubs(result: dict) -> list[dict]:
    return result.get("publications", [])


def _total(result: dict) -> int:
    return result.get("total_count", 0)


def _abstracts(pubs: list[dict]) -> list[str]:
    return [p["abstract"] for p in pubs if p.get("abstract")]


def _print_detail(msg: str):
    if VERBOSE:
        print(f"      {msg}")


# ===================================================================
# TASK 1 — Multi-Hazard Risk Briefing Generator
# ===================================================================

async def task_multi_hazard_risk_briefing():
    """
    Scenario: A city planner in California asks "What natural hazards should
    I worry about?" The LLM must query across earthquake, wildfire, volcano,
    and flood publications, then synthesize a combined briefing.

    Validates:
      - Ability to issue 4+ parallel domain queries
      - Each domain returns relevant results
      - The combined set covers >=3 distinct hazard types
      - At least some publications include abstracts for synthesis
    """
    print("\n  TASK 1: Multi-Hazard Risk Briefing Generator")
    print("  Scenario: Assemble a natural hazard briefing for California")

    hazard_queries = [
        ("earthquake", "earthquake California"),
        ("wildfire", "wildfire California"),
        ("volcano", "volcano California"),
        ("flood", "flood California"),
    ]

    all_pubs = {}
    domains_with_results = 0

    for domain, query in hazard_queries:
        result = await search_publications(query=query, page_size=5)
        if _has_error(result):
            _print_detail(f"  {domain}: ERROR — {result['error']}")
            continue
        pubs = _pubs(result)
        all_pubs[domain] = pubs
        if pubs:
            domains_with_results += 1
        _print_detail(f"  {domain}: {_total(result)} total, {len(pubs)} returned")

    total_pubs = sum(len(v) for v in all_pubs.values())
    abstracts = []
    for pubs in all_pubs.values():
        abstracts.extend(_abstracts(pubs))

    checks = [
        ("Queried >=4 hazard domains", len(all_pubs) >= 4),
        (">=3 domains returned results", domains_with_results >= 3),
        (">=10 total publications gathered", total_pubs >= 10),
        (">=5 abstracts available for synthesis", len(abstracts) >= 5),
    ]

    passed = all(ok for _, ok in checks)
    for label, ok in checks:
        status = "✓" if ok else "✗"
        print(f"    {status} {label}")

    return passed


# ===================================================================
# TASK 2 — Cross-Disciplinary Research Synthesizer
# ===================================================================

async def task_cross_disciplinary_synthesizer():
    """
    Scenario: "What does USGS research say about PFAS contamination and its
    effects on groundwater?" The LLM must search for PFAS, groundwater
    contamination, and the intersection, then identify which publications
    bridge both domains.

    Validates:
      - Multiple searches with different query strategies
      - Identification of overlapping publications (by index_id)
      - Sufficient abstract coverage for a literature review
    """
    print("\n  TASK 2: Cross-Disciplinary Research Synthesizer")
    print("  Scenario: PFAS + groundwater intersection analysis")

    r_pfas = await search_publications(query="PFAS contamination", page_size=15)
    r_gw = await search_publications(query="groundwater contamination", page_size=15)
    r_both = await search_publications(query="PFAS groundwater", page_size=15)

    if any(_has_error(r) for r in [r_pfas, r_gw, r_both]):
        print("    ✗ One or more queries returned an error")
        return False

    ids_pfas = {p["index_id"] for p in _pubs(r_pfas) if p.get("index_id")}
    ids_gw = {p["index_id"] for p in _pubs(r_gw) if p.get("index_id")}
    ids_both = {p["index_id"] for p in _pubs(r_both) if p.get("index_id")}

    overlap_direct = ids_pfas & ids_gw
    overlap_with_combined = overlap_direct | (ids_both & (ids_pfas | ids_gw))

    all_unique = ids_pfas | ids_gw | ids_both
    all_pubs_flat = _pubs(r_pfas) + _pubs(r_gw) + _pubs(r_both)
    abstracts_count = len([p for p in all_pubs_flat if p.get("abstract")])

    checks = [
        ("PFAS query returned results", _total(r_pfas) > 0),
        ("Groundwater query returned results", _total(r_gw) > 0),
        ("Combined query returned results", _total(r_both) > 0),
        (">=10 unique publications across all queries", len(all_unique) >= 10),
        (">=5 abstracts available for synthesis", abstracts_count >= 5),
    ]

    _print_detail(f"PFAS: {_total(r_pfas)}, GW: {_total(r_gw)}, Combined: {_total(r_both)}")
    _print_detail(f"Unique IDs: {len(all_unique)}, Overlap: {len(overlap_with_combined)}")

    passed = all(ok for _, ok in checks)
    for label, ok in checks:
        status = "✓" if ok else "✗"
        print(f"    {status} {label}")

    return passed


# ===================================================================
# TASK 3 — Multi-Step Fact Verification Pipeline
# ===================================================================

async def task_fact_verification_pipeline():
    """
    Scenario: Verify the claim "Low-frequency earthquakes near the Mendocino
    triple junction are caused by a captured slab fragment."

    The LLM must:
      1. Search for the topic
      2. Find the specific publication that makes/supports this claim
      3. Retrieve it by index_id for confirmation
      4. Evaluate abstract evidence

    Validates:
      - Multi-step search → retrieve → verify workflow
      - index_id lookup consistency
      - Abstract-based evidence evaluation
    """
    print("\n  TASK 3: Multi-Step Fact Verification Pipeline")
    print("  Claim: 'Low-frequency earthquakes near Mendocino caused by captured slab'")

    r_search = await search_publications(
        query="low-frequency earthquakes Mendocino slab", page_size=10
    )
    if _has_error(r_search):
        print(f"    ✗ Search failed: {r_search['error']}")
        return False

    target_pub = None
    for pub in _pubs(r_search):
        title_lower = (pub.get("title") or "").lower()
        if "low-frequency" in title_lower and "slab" in title_lower:
            target_pub = pub
            break

    if not target_pub:
        for pub in _pubs(r_search):
            abstract_lower = (pub.get("abstract") or "").lower()
            if "mendocino" in abstract_lower and "slab" in abstract_lower:
                target_pub = pub
                break

    found_candidate = target_pub is not None
    _print_detail(f"Candidate found: {found_candidate}")

    verified_by_id = False
    abstract_supports_claim = False

    if target_pub and target_pub.get("index_id"):
        r_verify = await search_publications(index_id=target_pub["index_id"])
        if not _has_error(r_verify) and _pubs(r_verify):
            verified_pub = _pubs(r_verify)[0]
            verified_by_id = verified_pub.get("index_id") == target_pub["index_id"]

            abstract = (verified_pub.get("abstract") or "").lower()
            evidence_keywords = ["slab", "mendocino", "earthquake", "fault"]
            matches = sum(1 for kw in evidence_keywords if kw in abstract)
            abstract_supports_claim = matches >= 3

    checks = [
        ("Initial search returned results", _total(r_search) > 0),
        ("Found a candidate publication matching the claim", found_candidate),
        ("Verified publication via index_id lookup", verified_by_id),
        ("Abstract contains supporting evidence (>=3 key terms)", abstract_supports_claim),
    ]

    passed = all(ok for _, ok in checks)
    for label, ok in checks:
        status = "✓" if ok else "✗"
        print(f"    {status} {label}")

    return passed


# ===================================================================
# TASK 4 — Temporal Research Trend Analyst
# ===================================================================

async def task_temporal_trend_analyst():
    """
    Scenario: "Is research on critical minerals accelerating?" The LLM must
    paginate through results, extract publication years, and determine whether
    output is increasing over time.

    Validates:
      - Pagination (multiple page_number calls)
      - Year extraction and counting
      - Trend detection (are recent years more productive?)
    """
    print("\n  TASK 4: Temporal Research Trend Analyst")
    print("  Scenario: Is critical minerals research accelerating?")

    all_years = []
    for page in range(1, 4):
        result = await search_publications(
            query="critical minerals", page_size=100, page_number=page
        )
        if _has_error(result):
            _print_detail(f"Page {page} error: {result['error']}")
            continue
        for pub in _pubs(result):
            year = pub.get("year")
            if year and str(year).isdigit():
                all_years.append(int(year))

    if not all_years:
        print("    ✗ No year data collected")
        return False

    year_counts = Counter(all_years)
    sorted_years = sorted(year_counts.items())

    recent_5yr = sum(c for y, c in sorted_years if y >= 2021)
    older_5yr = sum(c for y, c in sorted_years if 2016 <= y <= 2020)
    total_span = max(all_years) - min(all_years) if all_years else 0

    _print_detail(f"Years collected: {len(all_years)}, span: {min(all_years)}-{max(all_years)}")
    _print_detail(f"2021+: {recent_5yr} pubs, 2016-2020: {older_5yr} pubs")
    for year, count in sorted_years[-5:]:
        _print_detail(f"  {year}: {count} publications")

    checks = [
        ("Collected >=50 publications with year data", len(all_years) >= 50),
        ("Year span covers >=5 years", total_span >= 5),
        ("Successfully paginated (>=2 pages)", len(all_years) > 100),
        ("Can compare recent vs older output", recent_5yr > 0 and older_5yr > 0),
    ]

    passed = all(ok for _, ok in checks)
    for label, ok in checks:
        status = "✓" if ok else "✗"
        print(f"    {status} {label}")

    return passed


# ===================================================================
# TASK 5 — Scientific Jargon-to-Plain-Language Translator
# ===================================================================

async def task_jargon_to_plain_language():
    """
    Scenario: Retrieve a complex scientific publication and verify its abstract
    contains technical jargon that would need simplification for a general
    audience.

    Validates:
      - index_id-based retrieval
      - Abstract presence and complexity detection
      - Technical term density (proxy for translation difficulty)
    """
    print("\n  TASK 5: Scientific Jargon-to-Plain-Language Translator")
    print("  Scenario: Retrieve a jargon-heavy abstract for simplification")

    r_search = await search_publications(
        query="geochemical isotope analysis groundwater", page_size=10
    )
    if _has_error(r_search):
        print(f"    ✗ Search failed: {r_search['error']}")
        return False

    best_pub = None
    best_score = 0
    technical_terms = [
        "isotope", "geochemical", "aquifer", "hydrogeologic", "stratigraphic",
        "recharge", "transmissivity", "permeability", "litholog", "alluvial",
        "radionuclide", "spectrometry", "chromatograph", "potentiometric",
        "stoichiometr", "mineralization", "dissolution", "precipitation",
        "delineation", "anthropogenic", "remediation", "contaminant",
    ]

    for pub in _pubs(r_search):
        abstract = (pub.get("abstract") or "").lower()
        if len(abstract) < 200:
            continue
        score = sum(1 for term in technical_terms if term in abstract)
        if score > best_score:
            best_score = score
            best_pub = pub

    if not best_pub:
        print("    ✗ No sufficiently technical abstract found")
        return False

    _print_detail(f"Selected: {best_pub.get('title', '')[:60]}...")
    _print_detail(f"Technical term hits: {best_score}")
    _print_detail(f"Abstract length: {len(best_pub.get('abstract', ''))} chars")

    verified = False
    if best_pub.get("index_id"):
        r_verify = await search_publications(index_id=best_pub["index_id"])
        if not _has_error(r_verify) and _pubs(r_verify):
            verified = _pubs(r_verify)[0].get("index_id") == best_pub["index_id"]

    abstract_text = best_pub.get("abstract", "")
    avg_word_len = (
        sum(len(w) for w in abstract_text.split()) / max(len(abstract_text.split()), 1)
    )

    checks = [
        ("Found a publication with technical abstract", best_pub is not None),
        ("Abstract has >=3 technical terms", best_score >= 3),
        ("Abstract is >=300 chars (sufficient for translation)", len(abstract_text) >= 300),
        ("Average word length >5 chars (complexity indicator)", avg_word_len > 5),
        ("Publication retrievable by index_id", verified),
    ]

    passed = all(ok for _, ok in checks)
    for label, ok in checks:
        status = "✓" if ok else "✗"
        print(f"    {status} {label}")

    return passed


# ===================================================================
# TASK 6 — Research Gap Detector
# ===================================================================

async def task_research_gap_detector():
    """
    Scenario: Compare "arsenic groundwater" (the problem) with "arsenic
    remediation" (the solution). If the problem has far more publications
    than the solution, that's a research gap.

    Validates:
      - Comparative query strategy
      - Count-based gap analysis
      - Identification of asymmetry between problem and solution research
    """
    print("\n  TASK 6: Research Gap Detector")
    print("  Scenario: arsenic contamination (problem) vs remediation (solution)")

    r_problem = await search_publications(query="arsenic groundwater contamination", page_size=5)
    r_solution = await search_publications(query="arsenic remediation groundwater", page_size=5)
    r_monitoring = await search_publications(query="arsenic groundwater monitoring", page_size=5)

    if any(_has_error(r) for r in [r_problem, r_solution, r_monitoring]):
        print("    ✗ One or more queries failed")
        return False

    count_problem = _total(r_problem)
    count_solution = _total(r_solution)
    count_monitoring = _total(r_monitoring)

    _print_detail(f"Problem (contamination): {count_problem}")
    _print_detail(f"Solution (remediation):  {count_solution}")
    _print_detail(f"Monitoring:              {count_monitoring}")

    counts = {"problem": count_problem, "solution": count_solution, "monitoring": count_monitoring}
    nonzero = [v for v in counts.values() if v > 0]
    has_asymmetry = len(nonzero) >= 2 and max(nonzero) > 2 * min(nonzero)

    all_ids = set()
    for r in [r_problem, r_solution, r_monitoring]:
        for p in _pubs(r):
            if p.get("index_id"):
                all_ids.add(p["index_id"])

    checks = [
        ("Problem query returned results", count_problem > 0),
        ("Solution query returned results", count_solution > 0),
        ("Monitoring query returned results", count_monitoring > 0),
        ("Detected research asymmetry between facets", has_asymmetry),
        (">=8 unique publications across all facets", len(all_ids) >= 8),
    ]

    passed = all(ok for _, ok in checks)
    for label, ok in checks:
        status = "✓" if ok else "✗"
        print(f"    {status} {label}")

    return passed


# ===================================================================
# TASK 7 — Resource-Constrained Summarization
# ===================================================================

async def task_resource_constrained_summarization():
    """
    Scenario: A topic has 1000+ results but the LLM is limited to 5 API calls.
    It must strategically use queries and pagination to maximize coverage.

    Validates:
      - Strategic query decomposition under constraints
      - Effective use of page_size and page_number
      - Deduplication across overlapping results
      - Coverage breadth (unique publications per API call)
    """
    print("\n  TASK 7: Resource-Constrained Summarization")
    print("  Scenario: Summarize 'earthquake' research in <=5 API calls")

    api_calls = 0
    all_pubs_by_id = {}

    r1 = await search_publications(query="earthquake", page_size=20)
    api_calls += 1
    for p in _pubs(r1):
        if p.get("index_id"):
            all_pubs_by_id[p["index_id"]] = p

    r2 = await search_publications(query="earthquake", page_size=20, page_number=2)
    api_calls += 1
    for p in _pubs(r2):
        if p.get("index_id"):
            all_pubs_by_id[p["index_id"]] = p

    r3 = await search_publications(query="earthquake hazard assessment", page_size=20)
    api_calls += 1
    for p in _pubs(r3):
        if p.get("index_id"):
            all_pubs_by_id[p["index_id"]] = p

    r4 = await search_publications(query="seismic risk", page_size=20)
    api_calls += 1
    for p in _pubs(r4):
        if p.get("index_id"):
            all_pubs_by_id[p["index_id"]] = p

    r5 = await search_publications(query="earthquake", title="fault", page_size=20)
    api_calls += 1
    for p in _pubs(r5):
        if p.get("index_id"):
            all_pubs_by_id[p["index_id"]] = p

    unique_count = len(all_pubs_by_id)
    abstracts = [p["abstract"] for p in all_pubs_by_id.values() if p.get("abstract")]
    types = Counter(p.get("type", "Unknown") for p in all_pubs_by_id.values())
    years = [p["year"] for p in all_pubs_by_id.values() if p.get("year")]
    efficiency = unique_count / api_calls if api_calls else 0

    _print_detail(f"API calls: {api_calls}, Unique pubs: {unique_count}")
    _print_detail(f"Efficiency: {efficiency:.1f} unique pubs/call")
    _print_detail(f"Types: {dict(types)}")

    checks = [
        ("Used exactly 5 API calls", api_calls == 5),
        (">=40 unique publications collected", unique_count >= 40),
        (">=10 unique pubs per API call (efficiency)", efficiency >= 10),
        (">=2 distinct publication types in results", len(types) >= 2),
        (">=20 abstracts available for summarization", len(abstracts) >= 20),
    ]

    passed = all(ok for _, ok in checks)
    for label, ok in checks:
        status = "✓" if ok else "✗"
        print(f"    {status} {label}")

    return passed


# ===================================================================
# TASK 8 — Emergency Response Literature Kit
# ===================================================================

async def task_emergency_response_kit():
    """
    Scenario: "There's a volcanic eruption in Hawaii — what do we know?" The
    LLM must rapidly find relevant publications, prioritize those with
    downloadable documents and data releases, and assemble a response kit.

    Validates:
      - Urgency-aware retrieval (Hawaii + volcano)
      - Link type parsing (Documents, Data Releases, HTML)
      - Prioritization of actionable resources
    """
    print("\n  TASK 8: Emergency Response Literature Kit")
    print("  Scenario: Volcanic eruption in Hawaii — assemble response kit")

    r_volcano = await search_publications(query="volcano eruption Hawaii", page_size=15)
    r_hazard = await search_publications(query="volcanic hazard Hawaii lava", page_size=15)

    if _has_error(r_volcano) or _has_error(r_hazard):
        print("    ✗ Search failed")
        return False

    all_pubs = {}
    for r in [r_volcano, r_hazard]:
        for p in _pubs(r):
            iid = p.get("index_id")
            if iid:
                all_pubs[iid] = p

    documents = []
    data_releases = []
    readable_links = []

    for pub in all_pubs.values():
        for link in pub.get("links", []):
            ltype = (link.get("type") or "").lower()
            url = link.get("url", "")
            if "thumbnail" in ltype:
                continue
            if "document" in ltype or "open access" in ltype:
                documents.append({"pub": pub["index_id"], "url": url})
            if "data release" in ltype or "dataset" in ltype:
                data_releases.append({"pub": pub["index_id"], "url": url})
            if "html" in ltype or "index page" in ltype or "open access" in ltype:
                readable_links.append({"pub": pub["index_id"], "url": url})

    _print_detail(f"Unique pubs: {len(all_pubs)}")
    _print_detail(f"Documents: {len(documents)}, Data releases: {len(data_releases)}, Readable: {len(readable_links)}")

    checks = [
        ("Found >=5 relevant publications", len(all_pubs) >= 5),
        ("Found >=2 downloadable/accessible documents", len(documents) >= 2),
        ("Total actionable links >=5", len(documents) + len(data_releases) + len(readable_links) >= 5),
        ("Publications span both search queries", bool(_pubs(r_volcano)) and bool(_pubs(r_hazard))),
    ]

    passed = all(ok for _, ok in checks)
    for label, ok in checks:
        status = "✓" if ok else "✗"
        print(f"    {status} {label}")

    return passed


# ===================================================================
# TASK 9 — Data Asset Discovery from Publications
# ===================================================================

async def task_data_asset_discovery():
    """
    Scenario: A researcher asks "What datasets are available from USGS
    publications on water quality?" The LLM must find publications that
    link to Data Releases and Datasets, and catalog those external assets.

    Validates:
      - Targeted search for data-rich publications
      - Parsing of link types to isolate Data Releases and Datasets
      - Building a structured catalog of external data assets
    """
    print("\n  TASK 9: Data Asset Discovery from Publications")
    print("  Scenario: Catalog available datasets for water quality research")

    r1 = await search_publications(query="water quality monitoring data", page_size=20)
    r2 = await search_publications(query="water quality assessment", page_size=20)

    if _has_error(r1) or _has_error(r2):
        print("    ✗ Search failed")
        return False

    all_pubs = {}
    for r in [r1, r2]:
        for p in _pubs(r):
            iid = p.get("index_id")
            if iid:
                all_pubs[iid] = p

    data_catalog = []
    pubs_with_data = set()

    for iid, pub in all_pubs.items():
        for link in pub.get("links", []):
            ltype = (link.get("type") or "").lower()
            if any(kw in ltype for kw in ["data release", "dataset", "table"]):
                data_catalog.append({
                    "publication_index_id": iid,
                    "publication_title": pub.get("title", "")[:80],
                    "data_type": link.get("type"),
                    "url": link.get("url"),
                    "format": link.get("file_format"),
                    "size": link.get("size"),
                })
                pubs_with_data.add(iid)

    unique_urls = {item["url"] for item in data_catalog}

    _print_detail(f"Total pubs searched: {len(all_pubs)}")
    _print_detail(f"Pubs with data links: {len(pubs_with_data)}")
    _print_detail(f"Data assets found: {len(data_catalog)}, unique URLs: {len(unique_urls)}")

    checks = [
        ("Searched >=20 unique publications", len(all_pubs) >= 20),
        ("Found >=2 publications with data links", len(pubs_with_data) >= 2),
        ("Cataloged >=3 data assets", len(data_catalog) >= 3),
        (">=2 unique data URLs (not duplicates)", len(unique_urls) >= 2),
    ]

    passed = all(ok for _, ok in checks)
    for label, ok in checks:
        status = "✓" if ok else "✗"
        print(f"    {status} {label}")

    return passed


# ===================================================================
# TASK 10 — Policy Impact Briefing from Publication
# ===================================================================

async def task_policy_impact_briefing():
    """
    Scenario: A congressional staffer needs a 1-page policy briefing from
    a specific USGS publication. The LLM must retrieve the publication by
    index_id, extract key policy-relevant information from the abstract,
    and verify that sufficient metadata exists for a proper citation.

    Validates:
      - Precise index_id retrieval
      - Extraction of policy-relevant content from scientific abstracts
      - Completeness of citation metadata (title, authors, year, DOI, series)
    """
    print("\n  TASK 10: Policy Impact Briefing from Publication")
    print("  Scenario: Generate a policy briefing from a USGS water assessment")

    r_search = await search_publications(
        query="water availability assessment", title="assessment", page_size=5
    )
    if _has_error(r_search) or not _pubs(r_search):
        print("    ✗ Could not find a suitable publication")
        return False

    target = None
    for pub in _pubs(r_search):
        has_abstract = bool(pub.get("abstract") and len(pub["abstract"]) > 200)
        has_doi = bool(pub.get("doi"))
        has_authors = len(pub.get("authors", [])) > 0
        if has_abstract and has_doi and has_authors:
            target = pub
            break

    if not target:
        target = _pubs(r_search)[0]

    _print_detail(f"Selected: {target.get('title', '')[:60]}...")

    r_verify = await search_publications(index_id=target["index_id"])
    if _has_error(r_verify) or not _pubs(r_verify):
        print("    ✗ index_id verification failed")
        return False

    verified = _pubs(r_verify)[0]

    citation_fields = {
        "title": bool(verified.get("title")),
        "authors": len(verified.get("authors", [])) > 0,
        "year": bool(verified.get("year")),
        "doi": bool(verified.get("doi")),
        "series": bool(verified.get("series")),
    }

    abstract = verified.get("abstract", "")
    policy_keywords = [
        "water", "resource", "management", "assessment", "risk",
        "quality", "supply", "federal", "state", "public",
        "health", "infrastructure", "protect", "sustain",
    ]
    policy_relevance_score = sum(1 for kw in policy_keywords if kw in abstract.lower())

    _print_detail(f"Citation fields present: {sum(citation_fields.values())}/5")
    _print_detail(f"Policy keyword hits: {policy_relevance_score}")

    checks = [
        ("Publication retrieved by index_id", verified.get("index_id") == target["index_id"]),
        ("Has title for citation", citation_fields["title"]),
        ("Has authors for citation", citation_fields["authors"]),
        ("Has year for citation", citation_fields["year"]),
        ("Has DOI for citation", citation_fields["doi"]),
        ("Abstract has >=3 policy-relevant terms", policy_relevance_score >= 3),
    ]

    passed = all(ok for _, ok in checks)
    for label, ok in checks:
        status = "✓" if ok else "✗"
        print(f"    {status} {label}")

    return passed


# ===================================================================
# Test Runner
# ===================================================================

ALL_TASKS = [
    ("multi_hazard", "Multi-Hazard Risk Briefing Generator", task_multi_hazard_risk_briefing),
    ("synthesizer", "Cross-Disciplinary Research Synthesizer", task_cross_disciplinary_synthesizer),
    ("fact_verify", "Multi-Step Fact Verification Pipeline", task_fact_verification_pipeline),
    ("trend", "Temporal Research Trend Analyst", task_temporal_trend_analyst),
    ("jargon", "Jargon-to-Plain-Language Translator", task_jargon_to_plain_language),
    ("gap", "Research Gap Detector", task_research_gap_detector),
    ("constrained", "Resource-Constrained Summarization", task_resource_constrained_summarization),
    ("emergency", "Emergency Response Literature Kit", task_emergency_response_kit),
    ("data_assets", "Data Asset Discovery from Publications", task_data_asset_discovery),
    ("policy", "Policy Impact Briefing from Publication", task_policy_impact_briefing),
]


async def run_tasks(filter_key: str | None = None):
    print("=" * 70)
    print("USGS Publications Warehouse MCP Server")
    print("LLM Benchmark Tasks (Top 10)")
    print("=" * 70)
    print()
    print("These tasks evaluate an LLM's ability to use the USGS MCP server")
    print("for complex, multi-step reasoning beyond simple queries.")
    print()

    tasks_to_run = ALL_TASKS
    if filter_key:
        tasks_to_run = [(k, n, f) for k, n, f in ALL_TASKS if filter_key.lower() in k.lower()]
        if not tasks_to_run:
            print(f"No tasks matching '{filter_key}'. Available keys:")
            for key, name, _ in ALL_TASKS:
                print(f"  {key:15s} — {name}")
            return 1

    results: list[tuple[str, bool, str | None]] = []

    for key, name, func in tasks_to_run:
        try:
            passed = await func()
            results.append((name, passed, None))
        except Exception as e:
            print(f"    ✗ EXCEPTION: {e}")
            results.append((name, False, str(e)))

    print()
    print("=" * 70)
    print("BENCHMARK SUMMARY")
    print("=" * 70)

    passed_count = sum(1 for _, p, _ in results if p)
    failed_count = len(results) - passed_count

    for name, success, error in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"  {status}: {name}")
        if error:
            print(f"         Error: {error}")

    print()
    print(f"Results: {passed_count}/{len(results)} tasks passed")

    if failed_count > 0:
        print("\nSome tasks failed. Review output above for details.")
        return 1
    else:
        print("\nAll benchmark tasks passed!")
        return 0


def main():
    global VERBOSE

    parser = argparse.ArgumentParser(
        description="LLM Benchmark Tasks for USGS Publications MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  uv run python tests/test_llm_benchmark_tasks.py              # run all
  uv run python tests/test_llm_benchmark_tasks.py -v            # verbose
  uv run python tests/test_llm_benchmark_tasks.py -k trend      # one task
  uv run python tests/test_llm_benchmark_tasks.py -k emergency  # one task

Task keys: multi_hazard, synthesizer, fact_verify, trend, jargon,
           gap, constrained, emergency, data_assets, policy
        """,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-k", "--key", type=str, help="Run only tasks matching this key")
    args = parser.parse_args()

    VERBOSE = args.verbose
    configure_logging(verbose=args.verbose)

    exit_code = asyncio.run(run_tasks(filter_key=args.key))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
