# Operational Workflow

Step-by-step guide for using the `hipaa_phi_scrubber` iRule to perform a HIPAA-safe SSL/TLS decrypted packet capture on F5 BIG-IP.

---

## Prerequisites

- BIG-IP running TMOS 13.1 or later (iRule `SSL::clientrandom` / `SSL::sessionsecret` support)
- Root or Administrator access to the BIG-IP management shell
- Wireshark 3.0+ on your analysis workstation (NSS Key Log support)
- The target Virtual Server must have a Client SSL profile attached (for `CLIENTSSL_HANDSHAKE` events)
- Change management approval for applying a temporary iRule to a production VS

---

## Phase 1 — Pre-Capture Setup

### 1.1 Upload the iRule

**Via TMSH:**
```bash
# SCP the iRule file to BIG-IP first
scp irules/hipaa_phi_scrubber.tcl admin@<bigip-mgmt>:/var/tmp/

# Then on BIG-IP:
tmsh create ltm rule hipaa_phi_scrubber {
    $(cat /var/tmp/hipaa_phi_scrubber.tcl)
}
```

**Via GUI:**
Local Traffic → iRules → Create
- Name: `hipaa_phi_scrubber`
- Definition: paste contents of `irules/hipaa_phi_scrubber.tcl`

### 1.2 Configure the capture scope

Edit the iRule's `RULE_INIT` section **before uploading** to restrict the capture to only the client IP under test:

```tcl
set static::capture_client "10.0.0.42"   ;# Replace with actual client IP
```

Leaving this as `"any"` will log TLS secrets for **all** clients on the VS.

### 1.3 Apply the iRule to the Virtual Server

```bash
tmsh modify ltm virtual <vs-name> rules { hipaa_phi_scrubber }
```

Verify:
```bash
tmsh list ltm virtual <vs-name> rules
```

---

## Phase 2 — Capture

### 2.1 Start tcpdump

Using the provided helper script (from BIG-IP shell):
```bash
bash /path/to/scripts/capture.sh start -i <client_ip> -o /var/tmp/capture.pcap
```

Or manually:
```bash
# Capture all VLANs (0.0:nnn), full packet size (-s0)
tcpdump -nni 0.0:nnn -s0 -w /var/tmp/capture.pcap host <client_ip>
```

For a specific VLAN:
```bash
tcpdump -nni internal -s0 -w /var/tmp/capture.pcap host <client_ip>
```

For BIG-IP 15.x+ with native SSL provider (no iRule needed for key logging):
```bash
tmsh modify sys db tcpdump.sslprovider value enable
tcpdump -nni 0.0:nnn -s0 -w /var/tmp/capture.pcap host <client_ip> --f5 ssl
```

### 2.2 Reproduce the traffic

Generate or replay the HTTP/S transactions you need to capture.

### 2.3 Stop tcpdump

```bash
bash /path/to/scripts/capture.sh stop
# or: Ctrl+C if running tcpdump manually
```

---

## Phase 3 — Key Extraction

### 3.1 Extract session secrets from ltm log

```bash
bash /path/to/scripts/extract_session_keys.sh \
    -l /var/log/ltm \
    -o /var/tmp/session_keys.pms
```

Verify the output contains entries:
```bash
wc -l /var/tmp/session_keys.pms
head -3 /var/tmp/session_keys.pms
```

Expected output format:
```
CLIENT_RANDOM <64-char hex> <96-char hex>
RSA Session-ID:<hex> Master-Key:<hex>
```

If the file is empty, verify:
- The iRule was applied to the correct VS
- TLS traffic occurred during the capture window
- `/var/log/ltm` hasn't been rotated since the capture

---

## Phase 4 — Cleanup (CRITICAL)

### 4.1 Remove the iRule from the Virtual Server immediately

```bash
tmsh modify ltm virtual <vs-name> rules { }
```

Verify removal:
```bash
tmsh list ltm virtual <vs-name> rules
```

### 4.2 Secure the capture files

```bash
# Restrict permissions
chmod 600 /var/tmp/capture.pcap /var/tmp/session_keys.pms

# SCP to your analysis workstation
scp admin@<bigip-mgmt>:/var/tmp/capture.pcap ./
scp admin@<bigip-mgmt>:/var/tmp/session_keys.pms ./

# Delete from BIG-IP
rm -f /var/tmp/capture.pcap /var/tmp/session_keys.pms
```

---

## Phase 5 — Wireshark Analysis

### 5.1 Load the session key file

1. Open `capture.pcap` in Wireshark
2. Go to **Edit → Preferences → Protocols → TLS**
3. Set **(Pre)-Master-Secret log filename** to the path of `session_keys.pms`
4. Click **OK** — TLS sessions will decrypt inline

### 5.2 Verify PHI scrubbing

Search for redaction tokens in the decrypted payload:
- Wireshark → Edit → Find Packet → String → `[SSN-REDACTED]`
- Or use `tshark`:

```bash
tshark -r capture.pcap \
    -o "tls.keylog_file:session_keys.pms" \
    -Y "http" \
    -T fields -e http.file_data \
    | grep -o '\[.*-REDACTED\]' | sort | uniq -c
```

---

## Phase 6 — Post-Analysis Cleanup

```bash
# On your workstation — delete after analysis is complete
rm -f ./capture.pcap ./session_keys.pms
```

> The session key file allows anyone with the pcap to decrypt all captured sessions. Do not retain either file longer than necessary.

---

## Troubleshooting

### No CLIENT_RANDOM entries in ltm log

- Confirm the iRule is applied to the VS: `tmsh list ltm virtual <vs-name> rules`
- Confirm the VS has a Client SSL profile: `tmsh list ltm virtual <vs-name> profiles`
- TLS 1.3 with 0-RTT may require `tmsh modify sys db ssl.allowtls13 value enable`

### Wireshark shows "TLS: Application Data" but no decryption

- Ensure the `.pms` file path in Wireshark preferences is correct and readable
- Confirm the `CLIENT_RANDOM` value in the `.pms` matches what's in the pcap (check via `tshark -r capture.pcap -Y tls.handshake.type==1 -T fields -e tls.handshake.random`)
- For session-resumption traffic, the `RSA Session-ID` entries are used instead — confirm both are present

### PHI not being scrubbed

- Verify the response `Content-Type` header is a text-based type (JSON, XML, FHIR, text)
- Check `static::max_collect` — payloads larger than this threshold will not be fully collected
- Confirm `Accept-Encoding` removal is working: `tcpdump` should show uncompressed responses

### iRule causes connection resets

- Check `/var/log/ltm` for Tcl errors: `grep "TCL error" /var/log/ltm | tail -20`
- Reduce `static::max_collect` if TMM memory pressure is suspected
- Remove the iRule from the VS immediately if connection issues occur
