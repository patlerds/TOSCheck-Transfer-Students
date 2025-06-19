#!/bin/bash

# Determine the operating system and set the output file path
if [ -d "/Users/" ]; then
  output_file="/Users/nt/Documents/all_project_code.txt"
else
  output_file="/tmp/all_project_code.txt"
fi

# Get the directory where the script is running from
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

find "$SCRIPT_DIR" -path "*/env" -prune -o -path "*/__pycache__" -prune -o \( -name "*.py" -o -name "*.html" -o -name "sw.js" -o -name "*.sh" -o -name "manifest.json" -o -name "*.wsgi" \) -print -exec echo "--- START OF FILE: {} ---" \; -exec cat {} \; -exec echo -e "\n--- END OF FILE: {} ---\n" \; > "$output_file"