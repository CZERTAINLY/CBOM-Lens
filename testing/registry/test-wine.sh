#!/usr/bin/env bash
# test-wine.sh — test the Windows registry scanner under Wine on Linux.
#
# Prerequisites:
#   - wine (wine64) installed
#   - Go toolchain for cross-compilation
#
# What it does:
#   0. Cleanup the special WINEPREFIX for testing
#   1. Cross-compiles cbom-lens for windows/amd64
#   2. Initialize the WINEPREFIX
#   3. Writes a self-signed PEM certificate into Wine's registry at WINEPREFIX
#   4. Runs the scanner via Wine and validates the CBOM output
#   5. Cleans up the test registry key
#
# Usage:
#   ./testing/registry/test-wine.sh [--keep]
#     --keep   keep the compiled binary and temp files after the run

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
KEEP=false
[[ "${1:-}" = "--keep" ]] && KEEP=true

WINE="${WINE:-wine}"
WINEPREFIX="${PROJECT_ROOT}/testing/registry/wine"
rm -rf "${WINEPREFIX}"
export WINEPREFIX

BINARY="$PROJECT_ROOT/cbom-lens-wine-test.exe"
CONFIG_FILE=""
OUTPUT_FILE=""
REG_KEY='HKCU\Software\CBOMLensTest'

cleanup() {
    echo "[*] Cleaning up..."
    # Remove test registry key (ignore errors if it doesn't exist)
    "$WINE" reg delete "$REG_KEY" /f 2>/dev/null || true

    [[ -n "$CONFIG_FILE" ]] && rm -f "$CONFIG_FILE"
    [[ -n "$OUTPUT_FILE" ]] && rm -f "$OUTPUT_FILE"

    if [[ "$KEEP" = false ]]; then
        rm -f "$BINARY"
    else
        echo "    Binary kept at: $BINARY"
    fi
    return 0
}
trap cleanup EXIT

# --- Preflight checks ---

if ! command -v "$WINE" &>/dev/null; then
    echo "ERROR: $WINE not found. Install wine (e.g. 'sudo zypper install wine' or 'sudo apt install wine64')." >&2
    exit 1
fi

if ! command -v go &>/dev/null; then
    echo "ERROR: go not found." >&2
    exit 1
fi

if ! command -v openssl &>/dev/null; then
    echo "ERROR: openssl not found." >&2
    exit 1
fi

# Initialise WINEPREFIX — suppress Mono/Gecko install dialogs.
if [[ ! -d "$WINEPREFIX" ]]; then
    echo "[*] Initialising WINEPREFIX at $WINEPREFIX..."
    WINEDLLOVERRIDES="mscoree=d;mshtml=d" DISPLAY= "$WINE" wineboot --init 2>/dev/null || true
fi

# --- Step 1: Cross-compile ---

if [[ ! -x "${BINARY}" ]]; then
    echo "[*] Cross-compiling cbom-lens for windows/amd64..."
    (cd "$PROJECT_ROOT" && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o "$BINARY" ./cmd/cbom-lens)
    echo "    -> $BINARY"
fi

# --- Step 2: Generate a certificate and write it to Wine's registry ---

echo "[*] Generating self-signed certificate..."
PEM_CERT="$(openssl req -x509 -newkey rsa:2048 -keyout /dev/null -nodes -days 1 -subj '/CN=cbom-lens-wine-test' 2>/dev/null)"
if [[ -z "$PEM_CERT" ]]; then
    echo "ERROR: failed to generate certificate." >&2
    exit 1
fi
echo "    -> $(echo "$PEM_CERT" | head -1)"

echo "[*] Writing PEM certificate to Wine registry at $REG_KEY..."
"$WINE" reg add "$REG_KEY" /v PEMCert /t REG_SZ /d "$PEM_CERT" /f 2>/dev/null
echo "    -> $REG_KEY\\PEMCert"

# --- Step 3: Run the scanner ---

CONFIG_FILE="$(mktemp /tmp/cbom-lens-wine-XXXXXX.yaml)"
cat > "$CONFIG_FILE" <<YAML
version: 0
service:
  mode: manual
registry:
  enabled: true
  paths:
    - hive: HKCU
      key: 'Software\\CBOMLensTest'
YAML

OUTPUT_FILE="$(mktemp /tmp/cbom-lens-wine-output-XXXXXX.json)"

# Convert Linux paths to Wine/Windows paths for the config file.
WIN_CONFIG="$(winepath -w "$CONFIG_FILE" 2>/dev/null)"

echo "[*] Running registry scan via Wine..."
echo "    Config: $CONFIG_FILE"
echo "    Wine config: $WIN_CONFIG"
"$WINE" "$BINARY" run --config "$WIN_CONFIG" > "$OUTPUT_FILE" 2>/dev/null

# --- Step 4: Validate output ---

echo "[*] Validating output..."

if [[ ! -s "$OUTPUT_FILE" ]]; then
    echo "FAIL: output file is empty."
    exit 1
fi

if ! command -v jq &>/dev/null; then
    echo "WARN: jq not installed, skipping JSON validation."
    echo "    Raw output (first 20 lines):"
    head -20 "$OUTPUT_FILE"
    exit 0
fi

BOM_FORMAT="$(jq -r '.bomFormat // empty' "$OUTPUT_FILE")"
if [[ -z "$BOM_FORMAT" ]]; then
    echo "FAIL: output is not valid CBOM (missing bomFormat)."
    echo "    Output:"
    cat "$OUTPUT_FILE"
    exit 1
fi

COMPONENT_COUNT="$(jq '.components | length' "$OUTPUT_FILE")"
echo "    bomFormat: $BOM_FORMAT"
echo "    components: $COMPONENT_COUNT"

if [[ "$COMPONENT_COUNT" -eq 0 ]]; then
    echo "FAIL: no components found — expected at least 1 from the PEM certificate."
    exit 1
fi
echo "PASS: registry scan produced $COMPONENT_COUNT component(s)."

# Show location URIs for debugging
echo ""
echo "[*] Detected locations:"
jq -r '.components[]?.properties[]? | select(.name == "internal:location") | .value' "$OUTPUT_FILE" 2>/dev/null || true

echo ""
echo "[*] Done."
