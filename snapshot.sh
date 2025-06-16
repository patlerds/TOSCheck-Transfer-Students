#!/bin/bash

find /Users/nt/Documents/github/TOSCheck -path "*/env" -prune -o -path "*/__pycache__" -prune -o \( -name "*.py" -o -name "*.html" -o -name "sw.js" -o  -name "*.sh" -o -name "manifest.json" -o -name "*.wsgi" \) -print -exec echo "--- START OF FILE: {} ---" \; -exec cat {} \; -exec echo -e "\n--- END OF FILE: {} ---\n" \; > /Users/nt/Documents/all_project_code.txt
