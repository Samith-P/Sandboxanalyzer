#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: sudo ./analyze.sh <executable>"
    exit 1
fi

TARGET="$1"

echo "[+] Starting SaMOSA..."

sudo ./sandbox_runner "$TARGET"

if [ $? -ne 0 ]; then
    echo "[!] Sandbox failed."
    exit 1
fi

LATEST_RUN=$(ls -td results/run_* 2>/dev/null | head -1)

if [ -z "$LATEST_RUN" ]; then
    echo "[!] No results directory found."
    exit 1
fi

CSV="$LATEST_RUN/syscall_log.csv"
REPORT="$LATEST_RUN/analysis_report.txt"

if [ ! -f "$CSV" ]; then
    echo "[!] Syscall log not found:"
    echo "    $CSV"
    exit 1
fi

echo ""
echo "[+] Analyzing:"
echo "    $CSV"

python3 analyzer.py "$CSV" "$REPORT"

if [ $? -ne 0 ]; then
    echo "[!] Analyzer failed."
    exit 1
fi

echo ""
echo "[+] Analysis complete."
echo "[+] Report:"
echo "    $REPORT"
