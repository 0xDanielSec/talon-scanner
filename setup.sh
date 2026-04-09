#!/usr/bin/env bash
set -euo pipefail

PYTHON=${PYTHON:-python}
VENV_DIR=".venv"

echo "==> Setting up Glasswing Scanner..."

# Check Python
if ! command -v "$PYTHON" &>/dev/null; then
    echo "Error: Python not found. Install Python 3.9+ and try again." >&2
    exit 1
fi

PY_VERSION=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "    Python $PY_VERSION detected"

# Create virtual environment
if [ ! -d "$VENV_DIR" ]; then
    echo "==> Creating virtual environment..."
    "$PYTHON" -m venv "$VENV_DIR"
fi

# Activate and install
echo "==> Installing dependencies..."
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo ""
echo "Setup complete."
echo "Activate your environment with:  source .venv/bin/activate"
echo "Run the scanner with:            python glasswing.py --help"
