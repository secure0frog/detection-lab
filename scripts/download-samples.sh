#!/bin/bash
# Download EICAR test files and Mordor/OTRF Security Datasets
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/data"
SAMPLES_DIR="$DATA_DIR/samples"
LOGS_DIR="$DATA_DIR/logs"

mkdir -p "$SAMPLES_DIR" "$LOGS_DIR"

echo "=== Downloading EICAR test files ==="
curl -sfL "https://secure.eicar.org/eicar.com" -o "$SAMPLES_DIR/eicar.com" && \
    echo "[+] eicar.com downloaded" || echo "[-] Failed to download eicar.com"
curl -sfL "https://secure.eicar.org/eicar.com.txt" -o "$SAMPLES_DIR/eicar.com.txt" && \
    echo "[+] eicar.com.txt downloaded" || echo "[-] Failed to download eicar.com.txt"

echo ""
echo "=== Downloading Mordor/OTRF Security Datasets ==="
BASE_URL="https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows"

DATASETS=(
    "credential-access/host/psh_mimikatz_lsadump_sam.zip"
    "execution/host/empire_launcher_vbs.zip"
    "defense-evasion/host/empire_powershell_launcher_bat.zip"
    "discovery/host/empire_net_domain_computers.zip"
    "persistence/host/empire_schtaskservice_stager.zip"
)

for ds in "${DATASETS[@]}"; do
    name=$(basename "$ds" .zip)
    echo -n "[*] Downloading ${name}... "
    if curl -sfL "${BASE_URL}/${ds}" -o "$LOGS_DIR/${name}.zip" 2>/dev/null; then
        if unzip -qo "$LOGS_DIR/${name}.zip" -d "$LOGS_DIR/" 2>/dev/null; then
            rm -f "$LOGS_DIR/${name}.zip"
            echo "OK"
        else
            echo "UNZIP FAILED"
            rm -f "$LOGS_DIR/${name}.zip"
        fi
    else
        echo "DOWNLOAD FAILED (URL may have changed)"
        rm -f "$LOGS_DIR/${name}.zip"
    fi
done

echo ""
echo "=== Download Summary ==="
echo "Samples directory: $SAMPLES_DIR"
ls -la "$SAMPLES_DIR/" 2>/dev/null || echo "  (empty)"
echo ""
echo "Logs directory: $LOGS_DIR"
ls -la "$LOGS_DIR/"*.json 2>/dev/null || echo "  (no JSON files yet - test-events.json should be in git)"
