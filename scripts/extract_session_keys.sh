#!/usr/bin/env bash
# =============================================================================
# extract_session_keys.sh
# =============================================================================
# Extracts TLS pre-master session secrets logged by the hipaa_phi_scrubber
# iRule from /var/log/ltm into an NSS Key Log file that Wireshark can consume.
#
# USAGE:
#   ./extract_session_keys.sh [OPTIONS]
#
# OPTIONS:
#   -o FILE    Output .pms file path (default: ./session_keys.pms)
#   -l FILE    Source log file (default: /var/log/ltm)
#   -t MINS    Only extract entries from the last N minutes (default: all)
#   -h         Show this help
#
# WIRESHARK SETUP (after running this script):
#   Edit → Preferences → Protocols → TLS
#   → (Pre)-Master-Secret log filename → <path to .pms file>
#
# SECURITY:
#   The output .pms file is AS SENSITIVE as the pcap.
#   Restrict permissions, delete after analysis.
# =============================================================================

set -euo pipefail

LOG_FILE="/var/log/ltm"
OUTPUT_FILE="./session_keys.pms"
TIME_FILTER=""

usage() {
    grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \?//'
    exit 0
}

while getopts "o:l:t:h" opt; do
    case $opt in
        o) OUTPUT_FILE="$OPTARG" ;;
        l) LOG_FILE="$OPTARG" ;;
        t) TIME_FILTER="$OPTARG" ;;
        h) usage ;;
        *) echo "Unknown option: -$OPTARG" >&2; exit 1 ;;
    esac
done

if [[ ! -f "$LOG_FILE" ]]; then
    echo "[ERROR] Log file not found: $LOG_FILE" >&2
    exit 1
fi

echo "[*] Extracting TLS session keys from: $LOG_FILE"
echo "[*] Output file: $OUTPUT_FILE"

# Wipe or create output file
> "$OUTPUT_FILE"
chmod 600 "$OUTPUT_FILE"

# -------------------------------------------------------
# NSS Key Log format (TLS 1.2 ECDHE / TLS 1.3 / DHE)
# Wireshark format: CLIENT_RANDOM <hex_random> <hex_secret>
# -------------------------------------------------------
CLIENT_RANDOM_COUNT=$(grep -c "CLIENT_RANDOM" "$LOG_FILE" 2>/dev/null || true)
if [[ "$CLIENT_RANDOM_COUNT" -gt 0 ]]; then
    echo "[*] Found $CLIENT_RANDOM_COUNT CLIENT_RANDOM entries"
    grep "CLIENT_RANDOM" "$LOG_FILE" \
        | sed -e 's/^.*\(CLIENT_RANDOM\)/\1/' \
        >> "$OUTPUT_FILE"
fi

# -------------------------------------------------------
# Legacy RSA Session-ID format (TLS 1.2 RSA key exchange)
# Wireshark format: RSA Session-ID:<hex_id> Master-Key:<hex_key>
# -------------------------------------------------------
RSA_COUNT=$(grep -c "RSA Session-ID" "$LOG_FILE" 2>/dev/null || true)
if [[ "$RSA_COUNT" -gt 0 ]]; then
    echo "[*] Found $RSA_COUNT RSA Session-ID entries"
    grep "RSA Session-ID" "$LOG_FILE" \
        | sed -e 's/^.*\(RSA Session-ID\)/\1/' \
        >> "$OUTPUT_FILE"
fi

TOTAL=$(wc -l < "$OUTPUT_FILE")
echo "[+] Extracted $TOTAL total session key entries to: $OUTPUT_FILE"

if [[ "$TOTAL" -eq 0 ]]; then
    echo "[WARN] No session keys found. Verify the iRule is applied to the VS"
    echo "       and that TLS traffic occurred during the capture window."
fi

echo ""
echo "Next steps:"
echo "  1. Copy $OUTPUT_FILE and your .pcap to your analysis workstation"
echo "  2. In Wireshark: Edit → Preferences → Protocols → TLS"
echo "     → Set '(Pre)-Master-Secret log filename' to: $OUTPUT_FILE"
echo "  3. Delete both files when analysis is complete"
echo ""
echo "[!] REMINDER: Delete this key file when analysis is complete."
echo "    rm -f \"$OUTPUT_FILE\""
