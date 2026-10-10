#!/usr/bin/env bash
#
# One-command KuGou credential capture workflow:
#   1. Connect Android device proxy to cap
#   2. Start cap proxy
#   3. Run the extraction script in watch mode
#   4. On exit (Ctrl+C), clear the device proxy
#
# Usage:
#   ./scripts/capture-kugou.sh [--port 8080] [--json]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CAP="${PROJECT_DIR}/cap"

PORT="8080"
JSON_FLAG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port) PORT="$2"; shift 2 ;;
        --json) JSON_FLAG="--json"; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if ! command -v adb &>/dev/null; then
    echo "error: adb not found in PATH" >&2
    exit 1
fi

if [[ ! -x "$CAP" ]]; then
    echo "Building cap..."
    (cd "$PROJECT_DIR" && go build -o cap ./cmd/cap)
fi

cleanup() {
    echo ""
    echo "cap: clearing device proxy..."
    "$CAP" android disconnect 2>/dev/null || true
    echo "cap: device proxy cleared, phone can access internet normally."

    if [[ -n "${EXTRACT_PID:-}" ]]; then
        kill "$EXTRACT_PID" 2>/dev/null || true
    fi
    if [[ -n "${CAP_PID:-}" ]]; then
        kill "$CAP_PID" 2>/dev/null || true
        wait "$CAP_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo "=== KuGou Credential Capture ==="
echo ""

echo "[1/3] Connecting Android device to cap proxy..."
"$CAP" android connect --proxy-port "$PORT"
echo ""

echo "[2/3] Starting cap proxy on port $PORT..."
"$CAP" start --addr "0.0.0.0:$PORT" &
CAP_PID=$!
sleep 1

echo "[3/3] Watching for KuGou play/download flows..."
echo "       Open KuGou app and play a song. Credentials will appear below."
echo "       Press Ctrl+C to stop."
echo ""

python3 "$SCRIPT_DIR/extract-kugou-creds.py" --watch $JSON_FLAG &
EXTRACT_PID=$!

wait "$CAP_PID"
