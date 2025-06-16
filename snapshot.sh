#!/bin/bash

find /home/nish/web/TOSCheck -path "*/env" -prune -o -path "*/__pycache__" -prune -o \( -name "*.py" -o -name "*.html" -o -name "sw.js" -o  -name "*.sh" -o -name "manifest.json" -o -name "*.wsgi" \) -print -exec echo "--- START OF FILE: {} ---" \; -exec cat {} \; -exec echo -e "\n--- END OF FILE: {} ---\n" \; > /tmp/all_project_code.txt
