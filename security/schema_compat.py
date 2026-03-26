"""
OpenAI-compatible JSON Schema Transformation

This module provides utilities to transform FastMCP/Pydantic-generated JSON schemas
into formats compatible with OpenAI's function calling API and other strict schema consumers.

OpenAI's function calling API has stricter requirements than standard JSON Schema:
1. The `required` field must always be present (even if empty array)
2. `anyOf` with null types is not supported - use optional parameters differently
3. Arrays must have an `items` field
4. Complex constructs like `prefixItems`, `minItems`, `maxItems` may not be supported

This transformation ensures MCP tool schemas work with OpenAI, Claude, and other LLM providers.
"""

from typing import Any
import copy
import logging

logger = logging.getLogger(__name__)


def transform_schema_for_openai(schema: dict[str, Any]) -> dict[str, Any]:
    """
    Transform a JSON schema to be OpenAI-compatible.
    
    Transformations applied:
    1. Ensure `required` array is always present
    2. Convert `anyOf` with null to simple type with nullable handling
    3. Ensure arrays have `items` field
    4. Remove unsupported constructs
    5. Add `additionalProperties: false` for strict mode
    
    Args:
        schema: The original JSON schema from Pydantic/FastMCP
        
    Returns:
        OpenAI-compatible JSON schema
    """
    schema = copy.deepcopy(schema)
    return _transform_object(schema)


def _transform_object(obj: dict[str, Any], strict_mode: bool = True) -> dict[str, Any]:
    """Recursively transform a schema object.
    
    Args:
        obj: The schema object to transform
        strict_mode: If True (default), all properties are added to required array
                    as OpenAI strict mode requires this. Optional parameters should
                    have a default value or accept null.
    """
    if not isinstance(obj, dict):
        return obj
    
    # Transform properties recursively
    if "properties" in obj:
        all_property_names = list(obj["properties"].keys())
        
        for prop_name, prop_schema in obj["properties"].items():
            # Transform the property schema
            transformed = _transform_property(prop_schema, strict_mode=strict_mode)
            obj["properties"][prop_name] = transformed
        
        # OpenAI strict mode requires ALL properties to be in the required array
        # Optional parameters are handled by having default values or accepting null
        if strict_mode:
            obj["required"] = all_property_names
        else:
            # Non-strict mode: only truly required fields
            required_fields = []
            for prop_name, prop_schema in obj["properties"].items():
                if not _is_optional(prop_schema):
                    required_fields.append(prop_name)
            if "required" not in obj:
                obj["required"] = required_fields
        
        # Add additionalProperties: false for OpenAI strict mode
        if "additionalProperties" not in obj:
            obj["additionalProperties"] = False
    
    return obj


def _transform_property(prop: dict[str, Any], strict_mode: bool = True) -> dict[str, Any]:
    """Transform a single property schema."""
    if not isinstance(prop, dict):
        return prop
    
    prop = copy.deepcopy(prop)
    
    # Handle anyOf with null (common Pydantic pattern for Optional types)
    if "anyOf" in prop:
        prop = _flatten_anyof_with_null(prop)
    
    # Handle oneOf similarly
    if "oneOf" in prop:
        prop = _flatten_oneof_with_null(prop)
    
    # Ensure arrays have items
    if prop.get("type") == "array" and "items" not in prop:
        prop["items"] = {"type": "string"}  # Default to string items
    
    # Recursively transform nested objects
    if prop.get("type") == "object" and "properties" in prop:
        prop = _transform_object(prop, strict_mode=strict_mode)
    
    # Transform items in arrays
    if "items" in prop and isinstance(prop["items"], dict):
        prop["items"] = _transform_property(prop["items"], strict_mode=strict_mode)
    
    # Remove unsupported fields
    unsupported_fields = ["prefixItems", "$ref", "$defs", "definitions"]
    for field in unsupported_fields:
        prop.pop(field, None)
    
    return prop


def _flatten_anyof_with_null(prop: dict[str, Any]) -> dict[str, Any]:
    """
    Convert anyOf with null to a simpler format.
    
    Pydantic generates: {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null}
    
    For OpenAI strict mode with nullable types, we need to use type arrays:
    {"type": ["string", "null"]}
    
    This allows the LLM to pass null values for optional parameters while still
    having all properties in the required array (as strict mode demands).
    """
    any_of = prop.get("anyOf", [])
    
    # Check if this is a simple nullable pattern
    non_null_types = [t for t in any_of if t.get("type") != "null"]
    has_null = any(t.get("type") == "null" for t in any_of)
    
    if len(non_null_types) == 1 and has_null:
        # Simple nullable type - extract the non-null type
        base_type = non_null_types[0]
        result = copy.deepcopy(base_type)
        
        # Preserve other fields from original prop
        for key in ["default", "title", "description"]:
            if key in prop:
                result[key] = prop[key]
        
        # For OpenAI strict mode: use type array to allow null values
        # This is critical because strict mode requires ALL fields in the required array,
        # so optional parameters must explicitly accept null in their type definition
        if "type" in result:
            base_type_value = result["type"]
            # Convert to type array: {"type": ["string", "null"]}
            if isinstance(base_type_value, str):
                result["type"] = [base_type_value, "null"]
            elif isinstance(base_type_value, list) and "null" not in base_type_value:
                result["type"] = base_type_value + ["null"]
        
        return result
    
    # Complex anyOf - try to simplify or keep as-is
    # Some providers may not support anyOf at all
    if len(non_null_types) == 1:
        result = copy.deepcopy(non_null_types[0])
        for key in ["default", "title", "description"]:
            if key in prop:
                result[key] = prop[key]
        # Also make this nullable since it came from an anyOf pattern
        if "type" in result and has_null:
            base_type_value = result["type"]
            if isinstance(base_type_value, str):
                result["type"] = [base_type_value, "null"]
            elif isinstance(base_type_value, list) and "null" not in base_type_value:
                result["type"] = base_type_value + ["null"]
        return result
    
    # Multiple non-null types - can't simplify easily
    # Return the first non-null type as a fallback
    if non_null_types:
        logger.warning(f"Complex anyOf pattern detected, using first type: {non_null_types}")
        result = copy.deepcopy(non_null_types[0])
        for key in ["default", "title", "description"]:
            if key in prop:
                result[key] = prop[key]
        # Also make nullable if original had null
        if "type" in result and has_null:
            base_type_value = result["type"]
            if isinstance(base_type_value, str):
                result["type"] = [base_type_value, "null"]
            elif isinstance(base_type_value, list) and "null" not in base_type_value:
                result["type"] = base_type_value + ["null"]
        return result
    
    return prop


def _flatten_oneof_with_null(prop: dict[str, Any]) -> dict[str, Any]:
    """Handle oneOf patterns similarly to anyOf.
    
    For OpenAI strict mode, nullable types must use type arrays: {"type": ["string", "null"]}
    """
    one_of = prop.get("oneOf", [])
    
    non_null_types = [t for t in one_of if t.get("type") != "null"]
    has_null = any(t.get("type") == "null" for t in one_of)
    
    if len(non_null_types) == 1 and has_null:
        result = copy.deepcopy(non_null_types[0])
        for key in ["default", "title", "description"]:
            if key in prop:
                result[key] = prop[key]
        # For OpenAI strict mode: use type array to allow null values
        if "type" in result:
            base_type_value = result["type"]
            if isinstance(base_type_value, str):
                result["type"] = [base_type_value, "null"]
            elif isinstance(base_type_value, list) and "null" not in base_type_value:
                result["type"] = base_type_value + ["null"]
        return result
    
    return prop


def _is_optional(prop: dict[str, Any]) -> bool:
    """Determine if a property is optional (has default or is nullable)."""
    # Has explicit default
    if "default" in prop:
        return True
    
    # anyOf with null type
    if "anyOf" in prop:
        if any(t.get("type") == "null" for t in prop["anyOf"]):
            return True
    
    # oneOf with null type  
    if "oneOf" in prop:
        if any(t.get("type") == "null" for t in prop["oneOf"]):
            return True
    
    return False


def make_openai_function_schema(
    name: str,
    description: str,
    parameters: dict[str, Any]
) -> dict[str, Any]:
    """
    Create a complete OpenAI function schema from MCP tool info.
    
    Args:
        name: Tool/function name
        description: Tool description
        parameters: The parameter schema (will be transformed)
        
    Returns:
        OpenAI-compatible function definition
    """
    transformed_params = transform_schema_for_openai(parameters)
    
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": transformed_params,
            "strict": True  # Enable strict mode for better validation
        }
    }


def get_openai_tools_from_mcp(mcp_tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Convert a list of MCP tools to OpenAI function calling format.
    
    Args:
        mcp_tools: List of MCP tool definitions from tools/list
        
    Returns:
        List of OpenAI-compatible function definitions
    """
    openai_tools = []
    
    for tool in mcp_tools:
        openai_tool = make_openai_function_schema(
            name=tool.get("name", ""),
            description=tool.get("description", ""),
            parameters=tool.get("inputSchema", {})
        )
        openai_tools.append(openai_tool)
    
    return openai_tools
