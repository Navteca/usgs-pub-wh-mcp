"""
Tool registry for progressive disclosure pattern.

Implements the code execution optimization from:
https://www.anthropic.com/engineering/code-execution-with-mcp

Instead of loading all tool definitions upfront, this allows agents to:
1. Discover available tools via search
2. Load only the tool definitions they need
3. Reduce context window usage
"""

import json
from dataclasses import dataclass, asdict
from typing import Optional
from enum import Enum


class ToolCategory(str, Enum):
    """Categories for tool organization."""
    SEARCH = "search"


@dataclass
class ToolDefinition:
    """
    Minimal tool definition for progressive disclosure.
    
    Agents can request different detail levels:
    - name_only: Just the tool name
    - summary: Name and description
    - full: Complete definition with parameters
    """
    name: str
    description: str
    category: ToolCategory
    parameters: dict
    examples: list[str]
    
    def to_summary(self) -> dict:
        """Return name and description only."""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
        }
    
    def to_full(self) -> dict:
        """Return complete definition."""
        return asdict(self) | {"category": self.category.value}


class ToolRegistry:
    """
    Registry of available tools with search and filtering.
    
    Supports progressive disclosure:
    - list_tools: Get all tool names
    - search_tools: Find tools by keyword
    - get_tool: Get full definition for specific tool
    """
    
    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}
        self._initialize_tools()
    
    def _initialize_tools(self) -> None:
        """Register all available tools."""
        
        self._tools["search_publications"] = ToolDefinition(
            name="search_publications",
            description=(
                "Search for USGS publications using various criteria including "
                "full-text search, title matching, or direct lookup by index_id."
            ),
            category=ToolCategory.SEARCH,
            parameters={
                "query": {
                    "type": "string",
                    "description": "Full-text search across all publication fields",
                },
                "title": {
                    "type": "string",
                    "description": "An exact match for the string within the title of a publication",
                },
                "index_id": {
                    "type": "string",
                    "description": (
                        "The unique publication index ID for retrieving a specific publication "
                        "(e.g., 'ofr20151076', '70273506'). Cannot be combined with query or title."
                    ),
                },
                "page_size": {
                    "type": "integer",
                    "description": "Results per page (default 10, max 100)",
                },
                "page_number": {
                    "type": "integer",
                    "description": "Page number for pagination",
                },
            },
            examples=[
                'search_publications(query="groundwater contamination")',
                'search_publications(title="National Water Summary")',
                'search_publications(query="earthquake", title="hazard")',
                'search_publications(index_id="ofr20151076")',
                'search_publications(query="sea-level rise Florida")',
            ],
        )
    
    def list_tools(self, category: Optional[ToolCategory] = None) -> list[str]:
        """
        List all tool names, optionally filtered by category.
        
        Args:
            category: Optional category filter
            
        Returns:
            List of tool names
        """
        if category:
            return [
                name for name, tool in self._tools.items()
                if tool.category == category
            ]
        return list(self._tools.keys())
    
    def search_tools(
        self, 
        query: str, 
        detail_level: str = "summary"
    ) -> list[dict]:
        """
        Search for tools by keyword.
        
        Args:
            query: Search query
            detail_level: One of "name_only", "summary", "full"
            
        Returns:
            List of matching tool definitions
        """
        query_lower = query.lower()
        matches = []
        
        for name, tool in self._tools.items():
            searchable = f"{name} {tool.description} {' '.join(tool.examples)}".lower()
            
            if query_lower in searchable:
                if detail_level == "name_only":
                    matches.append({"name": name})
                elif detail_level == "summary":
                    matches.append(tool.to_summary())
                else:  # full
                    matches.append(tool.to_full())
        
        return matches
    
    def get_tool(self, name: str) -> Optional[dict]:
        """
        Get full definition for a specific tool.
        
        Args:
            name: Tool name
            
        Returns:
            Full tool definition or None
        """
        tool = self._tools.get(name)
        return tool.to_full() if tool else None
    
    def get_all_summaries(self) -> list[dict]:
        """Get summary of all tools."""
        return [tool.to_summary() for tool in self._tools.values()]


# Global registry instance
_registry: Optional[ToolRegistry] = None


def get_tool_registry() -> ToolRegistry:
    """Get the singleton tool registry instance."""
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry
