#!/bin/bash
# Generate ATT&CK Navigator layers using DeTTECT CLI
set -euo pipefail

DETTECT_EXEC="docker exec dettect"
INPUT_DIR="/opt/DeTTECT/input"

echo "=== Generating Visibility Layer ==="
$DETTECT_EXEC python dettect.py v \
    -ft "$INPUT_DIR/techniques-administration-endpoints.yaml" -l

echo ""
echo "=== Generating Detection Layer ==="
$DETTECT_EXEC python dettect.py d \
    -ft "$INPUT_DIR/techniques-administration-endpoints.yaml" -l

echo ""
echo "=== Generating Group Overlay (Lab Red Team) ==="
$DETTECT_EXEC python dettect.py g \
    -g "$INPUT_DIR/groups.yaml" \
    -o "$INPUT_DIR/techniques-administration-endpoints.yaml" \
    -t detection

echo ""
echo "=== Layer generation complete ==="
echo "Output files:"
ls -la "$(cd "$(dirname "$0")/.." && pwd)/dettect/output/" 2>/dev/null || echo "  (check dettect/output/)"
