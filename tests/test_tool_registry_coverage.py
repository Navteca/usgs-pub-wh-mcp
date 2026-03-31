from security.tool_registry import ToolCategory, ToolRegistry, get_tool_registry


def test_get_all_summaries_covers_summary_path() -> None:
    registry = ToolRegistry()
    summaries = registry.get_all_summaries()

    assert summaries
    assert summaries[0]["name"] == "search_publications"
    assert summaries[0]["category"] == ToolCategory.SEARCH.value


def test_registry_singleton_instance_reused() -> None:
    first = get_tool_registry()
    second = get_tool_registry()
    assert first is second
