#!/usr/bin/env bash
set -euo pipefail

# Creates a local virtualenv at .venv and installs scanner deps.
# Usage: ./scripts/setup_venv.sh [all]
#   no arg -> installs minimal deps required for iot_scanner (matplotlib, python-nmap, numpy)
#   all    -> installs full project requirements from requirements.txt

VENV_DIR=".venv"
PYTHON=${PYTHON:-python3}

echo "Creating virtualenv in $VENV_DIR using $PYTHON..."
$PYTHON -m venv "$VENV_DIR"
echo "Activating virtualenv and upgrading pip..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip setuptools wheel

if [ "${1:-}" = "all" ]; then
    echo "Installing full project requirements (this may take a while)..."
    pip install -r requirements.txt
else
    echo "Installing minimal scanner dependencies: matplotlib, python-nmap, numpy"
    pip install matplotlib python-nmap numpy
fi

echo "Virtualenv setup complete. To activate run: source $VENV_DIR/bin/activate"
