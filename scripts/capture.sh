#!/usr/bin/env bash
# =============================================================================
# capture.sh
# =============================================================================
# Helper to start/stop a tcpdump capture on F5 BIG-IP timed to the iRule
# session key logging window.
#
# USAGE (run on the BIG-IP TMOS shell):
#   ./capture.sh start  -i <client_ip> [-o <output.pcap>] [-V <vlan>]
#   ./capture.sh stop
#   ./capture.sh status
#
# EXAMPLES:
#   ./capture.sh start -i 10.0.0.42 -o /var/tmp/capture.pcap
#   ./capture.sh start -i 10.0.0.42 -V internal -o /var/tmp/capture.pcap
#   ./capture.sh stop
#
# After stopping, run scripts/extract_session_keys.sh to produce the .pms file.
# =============================================================================

set -euo pipefail

PIDFILE="/var/run/f5_capture.pid"
DEFAULT_OUTPUT="/var/tmp/capture_$(date +%Y%m%d_%H%M%S).pcap"
DEFAULT_SNAPLEN=0   # 0 = full packet capture
DEFAULT_INTERFACE="0.0:nnn"   # F5 combined interface (all VLANs)

usage() {
    grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \?//'
    exit 0
}

cmd_start() {
    local client_ip=""
    local output="$DEFAULT_OUTPUT"
    local iface="$DEFAULT_INTERFACE"
    local snaplen="$DEFAULT_SNAPLEN"

    while getopts "i:o:V:s:" opt; do
        case $opt in
            i) client_ip="$OPTARG" ;;
            o) output="$OPTARG" ;;
            V) iface="$OPTARG" ;;
            s) snaplen="$OPTARG" ;;
            *) echo "Unknown option: -$OPTARG" >&2; exit 1 ;;
        esac
    done

    if [[ -z "$client_ip" ]]; then
        echo "[ERROR] Client IP (-i) is required for start" >&2
        exit 1
    fi

    if [[ -f "$PIDFILE" ]]; then
        echo "[WARN] A capture may already be running (PID file exists: $PIDFILE)"
        echo "       Run '$0 stop' first, or remove $PIDFILE manually."
        exit 1
    fi

    local filter="host $client_ip"
    echo "[*] Starting tcpdump capture"
    echo "    Interface : $iface"
    echo "    Filter    : $filter"
    echo "    Output    : $output"
    echo "    Snap len  : $snaplen bytes (0 = full)"

    # Ensure output directory exists
    mkdir -p "$(dirname "$output")"

    # Launch tcpdump in background
    tcpdump -nni "$iface" -s "$snaplen" -w "$output" "$filter" &
    local pid=$!
    echo "$pid" > "$PIDFILE"
    echo "[+] tcpdump started (PID $pid)"
    echo "    Run '$0 stop' when traffic capture is complete."
}

cmd_stop() {
    if [[ ! -f "$PIDFILE" ]]; then
        echo "[WARN] No PID file found at $PIDFILE"
        echo "       Attempting to find and kill tcpdump processes..."
        pkill -SIGINT tcpdump 2>/dev/null && echo "[+] Sent SIGINT to tcpdump" || echo "[WARN] No tcpdump processes found"
        return
    fi

    local pid
    pid=$(cat "$PIDFILE")
    if kill -0 "$pid" 2>/dev/null; then
        echo "[*] Stopping tcpdump (PID $pid)..."
        kill -SIGINT "$pid"
        sleep 1
        echo "[+] tcpdump stopped"
    else
        echo "[WARN] PID $pid not running"
    fi
    rm -f "$PIDFILE"
    echo ""
    echo "Next: run scripts/extract_session_keys.sh to extract TLS secrets."
}

cmd_status() {
    if [[ -f "$PIDFILE" ]]; then
        local pid
        pid=$(cat "$PIDFILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "[+] Capture RUNNING (PID $pid)"
        else
            echo "[WARN] PID file exists but process $pid is not running (stale PID)"
        fi
    else
        echo "[*] No active capture (no PID file)"
    fi

    local procs
    procs=$(pgrep -a tcpdump 2>/dev/null || true)
    if [[ -n "$procs" ]]; then
        echo ""
        echo "Active tcpdump processes:"
        echo "$procs"
    fi
}

# -- Main --
if [[ $# -lt 1 ]]; then
    usage
fi

COMMAND="$1"
shift

case "$COMMAND" in
    start)  cmd_start "$@" ;;
    stop)   cmd_stop ;;
    status) cmd_status ;;
    help|-h|--help) usage ;;
    *) echo "[ERROR] Unknown command: $COMMAND" >&2; usage ;;
esac
