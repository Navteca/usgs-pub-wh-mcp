#!/bin/bash
# Installation script for USGS Publications Warehouse MCP Server

set -e

echo "=========================================="
echo "USGS Publications Warehouse MCP Server"
echo "Installation Script"
echo "=========================================="

# Check for uv
if ! command -v uv &> /dev/null; then
    echo "Installing uv package manager..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.cargo/bin:$PATH"
fi

echo "Installing dependencies..."
uv sync

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "To run the server:"
echo "  uv run main.py"
echo ""
echo "To run with HTTP/SSE transport (for remote access):"
echo "  uv run python main.py --transport sse --host 0.0.0.0 --port 8000"
echo ""
echo "To configure Claude Desktop, add to config:"
echo '  {
    "mcpServers": {
      "usgs-publications": {
        "command": "uv",
        "args": ["--directory", "'$(pwd)'", "run", "main.py"]
      }
    }
  }'
echo ""
