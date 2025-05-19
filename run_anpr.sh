#!/bin/bash
# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
# Path to the NetSDK libraries within your venv
NETSDK_LIB_PATH="$SCRIPT_DIR/venv/lib/python3.11/site-packages/NetSDK/Libs/linux64"

export LD_LIBRARY_PATH="$NETSDK_LIB_PATH:$LD_LIBRARY_PATH"
# Activate venv and run script
source "$SCRIPT_DIR/venv/bin/activate"
python "$SCRIPT_DIR/get_plates.py"
deactivate
