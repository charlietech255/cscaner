#!/usr/bin/env bash
# CSCAN Launcher - Automatically activates venv and runs cscan

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

if [ -d "venv" ]; then
    source venv/bin/activate
fi

python3 cscan.py "$@"
