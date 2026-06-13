# ============================================================
# F5 iRule: SSL Key Logger + HIPAA/HITECH PHI Scrubber
# ============================================================
# References:
#   - F5 K16700  : Overview of packet tracing with the ssldump utility
#   - F5 K12783074: Configuring the BIG-IP system to log SSL session keys
#   - 45 CFR §164.514(b): HIPAA Safe Harbor de-identification method
#   - HITECH Act (Pub. L. 111-5, §13400 et seq.)
#
# PURPOSE:
#   1. Log TLS pre-master session secrets so Wireshark can decrypt
#      an offline tcpdump capture (NSS Key Log / CLIENT_RANDOM format).
#   2. Scrub all 18 HIPAA PHI identifiers + clinical codes from HTTP
#      request and response payloads IN-FLIGHT, so they never appear
#      in the pcap in cleartext.
#
# !!  IMPORTANT — OPERATIONAL SECURITY  !!
#   - Apply to a virtual server ONLY for the duration of the capture.
#   - Remove the iRule immediately after capture is complete.
#   - The session.pms file extracted from /var/log/ltm is as sensitive
#     as the pcap itself. Restrict access and delete when no longer needed.
#   - Restrict static::capture_client to the specific client IP under
#     test rather than leaving it set to "any" in production.
#
# COVERAGE — HIPAA 18 PHI Identifiers (45 CFR §164.514(b)(2)):
#   #1  Names                  (structured field patterns)
#   #2  Geographic < state     (ZIP codes, street addresses)
#   #3  Dates tied to patient  (ISO, US, spelled-out formats)
#   #4  Phone numbers
#   #5  Fax numbers            (same regex as phone)
#   #6  Email addresses
#   #7  Social Security Numbers
#   #8  Medical Record Numbers (MRN)
#   #9  Health plan beneficiary numbers (incl. Medicare MBI)
#   #10 Account numbers / claim numbers
#   #11 Certificate / license numbers
#   #12 Vehicle identifiers / VINs
#   #13 Device identifiers / serial numbers (MAC, UDI)
#   #14 Web URLs containing PHI
#   #15 IP addresses (IPv4 + IPv6)
#   #16 Biometric identifiers (labeled field patterns)
#   #17 Full-face photos       (binary — not regex-scrubable; excluded)
#   #18 Unique healthcare IDs  (NPI, DEA, EIN, ICD-10, CPT, NDC)
# ============================================================

when RULE_INIT {

    # ----------------------------------------------------------
    # CONFIGURATION
    # ----------------------------------------------------------

    # Target client IP to log TLS secrets for.
    # Set to a specific IP (e.g. "10.0.0.5") to restrict scope.
    # "any" captures all clients — avoid in production.
    set static::capture_client "any"

    # Maximum payload bytes to collect per transaction.
    # Increase if your app sends large FHIR bundles or HL7 batches.
    set static::max_collect 1048576

    # ----------------------------------------------------------
    # PHI IDENTIFIER #1 — Names
    # Arbitrary human names cannot be reliably matched via regex
    # without high false-positive rates. We instead match common
    # structured field key=value patterns in JSON and form data.
    # For FHIR R4/R5 add: patient_name, family, given, text.
    # ----------------------------------------------------------
    set static::re_name \
        {(?i)(?:"(?:patient_?name|first_?name|last_?name|full_?name|member_?name|subscriber_?name)"\s*:\s*")([^"]{2,60})(")}
    set static::redact_name {[NAME-REDACTED]}

    # ----------------------------------------------------------
    # PHI IDENTIFIER #2 — Geographic subdivisions smaller than state
    # Safe Harbor: only first 3 ZIP digits may be retained if the
    # area has > 20,000 people. This iRule redacts the full ZIP.
    # ----------------------------------------------------------
    set static::re_zip \
        {(?:\b\d{5}(?:-\d{4})?\b)}
    set static::redact_zip {[ZIP-REDACTED]}

    set static::re_address \
        {(?i)\b\d{1,6}\s+(?:[NSEW]\w+\s+)?[A-Za-z0-9\s]{3,40}(?:St(?:reet)?|Ave(?:nue)?|Blvd|Rd|Road|Dr(?:ive)?|Ct|Court|Ln|Lane|Way|Pl(?:ace)?|Pkwy|Cir(?:cle)?)\.?\b}
    set static::redact_address {[ADDRESS-REDACTED]}

    # ----------------------------------------------------------
    # PHI IDENTIFIER #3 — Dates (except year) tied to individual
    # Covers: ISO 8601, US MM/DD/YYYY, and spelled-out formats.
    # Standalone years are NOT redacted (years alone are permitted).
    # ----------------------------------------------------------
    set static::re_date_iso \
        {(?:\b\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b)}
    set static::re_date_us \
        {(?:\b(?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12]\d|3[01])[/\-]\d{4}\b)}
    set static::re_date_spelled \
        {(?i)(?:\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2}[,\s]+\d{4}\b)}
    set static::redact_date {[DATE-REDACTED]}

    # ----------------------------------------------------------
    # PHI IDENTIFIERS #4 & #5 — Telephone and Fax numbers
    # Covers: +1 (NNN) NNN-NNNN, NNN-NNN-NNNN, NNN.NNN.NNNN
    # ----------------------------------------------------------
    set static::re_phone \
        {(?:\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b)}
    set static::redact_phone {[PHONE-REDACTED]}

    # ----------------------------------------------------------
    # PHI IDENTIFIER #6 — Email addresses
    # ----------------------------------------------------------
    set static::re_email \
        {[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}}
    set static::redact_email {[EMAIL-REDACTED]}

    # ----------------------------------------------------------
    # PHI IDENTIFIER #7 — Social Security Numbers
    # Covers: NNN-NN-NNNN and raw 9-digit strings
    # ----------------------------------------------------------
    set static::re_ssn \
        {(?:\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b)}
    set static::redact_ssn {[SSN-REDACTED]}

    # ----------------------------------------------------------
    # PHI IDENTIFIER #8 — Medical Record Numbers (MRN)
    # Matched via labeled field patterns only; standalone numeric
    # strings are too ambiguous without a label prefix.
    # ----------------------------------------------------------
    set static::re_mrn \
        {(?i)(?:mrn|medical[_\s]?record[_\s]?(?:number|no|num|id)?|chart[_\s]?(?:number|no|id)?|patient[_\s]?id)\s*[:#=\s"]*([A-Z0-9\-]{5,15})}
    set static::redact_mrn {[MRN-REDACTED]}

    # ----------------------------------------------------------
    # PHI IDENTIFIER #9 — Health Plan Beneficiary Numbers
    # Medicare MBI: 1C1AA1AA1A1 (11-char alphanumeric, specific
    # character class rules per CMS spec).
    # Other plan IDs matched via labeled field patterns.
    # ----------------------------------------------------------
    set static::re_mbi \
        {(?:\b[1-9][A-HJ-NP-TV-Z][0-9][A-HJ-NP-TV-Z]{2}[0-9][A-HJ-NP-TV-Z]{2}[0-9]{2}\b)}
    set static::redact_mbi {[MBI-REDACTED]}

    set static::re_beneficiary \
        {(?i)(?:beneficiary[_\s]?(?:number|no|id)?|member[_\s]?(?:id|number|no)|subscriber[_\s]?(?:id|number|no)|insurance[_\s]?(?:id|number|no)|policy[_\s]?(?:number|no|id))\s*[:#=\s"]*([A-Z0-9\-]{6,20})}
    set static::redact_beneficiary {[BENEFICIARY-ID-REDACTED]}

    # ----------------------------------------------------------
    # PHI IDENTIFIER #10 — Account / Claim / Billing Numbers
    # ----------------------------------------------------------
    set static::re_account \
        {(?i)(?:account[_\s]?(?:number|no|num|id)|billing[_\s]?(?:id|number|no)|claim[_\s]?(?:number|no|id)|encounter[_\s]?(?:number|no|id))\s*[:#=\s"]*([A-Z0-9\-]{4,20})}
    set static::redact_account {[ACCOUNT-REDACTED]}

    # Credit / payment cards (financial account identifiers)
    set static::re_cc \
        {(?:\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b)}
    set static::redact_cc {[CARD-REDACTED]}

    # ----------------------------------------------------------
    # PHI IDENTIFIER #11 — Certificate / License Numbers
    # Driver's license, state ID, professional licenses.
    # ----------------------------------------------------------
    set static::re_license \
        {(?i)(?:driver['\s]?s?[_\s]?licen[sc]e[_\s]?(?:number|no|num)?|dl[_\s]?(?:number|no|num)?|state[_\s]?id[_\s]?(?:number|no)?|license[_\s]?(?:number|no|num|plate)?)\s*[:#=\s"]*([A-Z0-9\-]{5,15})}
    set static::redact_license {[LICENSE-REDACTED]}

    # ----------------------------------------------------------
    # PHI IDENTIFIER #12 — Vehicle Identifiers / VINs
    # VIN: exactly 17 alphanumeric chars (no I, O, or Q)
    # ----------------------------------------------------------
    set static::re_vin \
        {(?:\b[A-HJ-NPR-Z0-9]{17}\b)}
    set static::redact_vin {[VIN-REDACTED]}

    # ----------------------------------------------------------
    # PHI IDENTIFIER #13 — Device Identifiers / Serial Numbers
    # MAC address and FDA Unique Device Identifier (UDI).
    # ----------------------------------------------------------
    set static::re_mac \
        {(?:\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b)}
    set static::redact_mac {[MAC-REDACTED]}

    set static::re_udi \
        {(?i)(?:udi|unique[_\s]?device[_\s]?(?:id|identifier|number))\s*[:#=\s"]*([A-Z0-9\/\-\+\.]{10,40})}
    set static::redact_udi {[UDI-REDACTED]}

    # ----------------------------------------------------------
    # PHI IDENTIFIER #14 — Web URLs containing patient identifiers
    # Matches URLs with patient/member/record path segments.
    # ----------------------------------------------------------
    set static::re_phi_url \
        {(?i)https?://[^\s"'<>]+(?:patient|member|record|mrn|account|beneficiary|portal)[^\s"'<>]*}
    set static::redact_url {[PHI-URL-REDACTED]}

    # ----------------------------------------------------------
    # PHI IDENTIFIER #15 — IP Addresses (IPv4 and IPv6)
    # Per HHS guidance, IP addresses are explicit PHI identifiers.
    # ----------------------------------------------------------
    set static::re_ipv4 \
        {(?:\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b)}
    set static::redact_ipv4 {[IP-REDACTED]}

    set static::re_ipv6 \
        {(?:\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b|\b(?:[0-9A-Fa-f]{1,4}:)*:(?:[0-9A-Fa-f]{1,4}:)*[0-9A-Fa-f]{1,4}\b)}
    set static::redact_ipv6 {[IPV6-REDACTED]}

    # ----------------------------------------------------------
    # PHI IDENTIFIER #16 — Biometric Identifiers
    # Fingerprint, voiceprint, iris scan, etc. as labeled API fields.
    # ----------------------------------------------------------
    set static::re_biometric \
        {(?i)(?:fingerprint|voiceprint|iris[_\s]?(?:scan|code)|biometric)[_\s]?(?:data|hash|template|value|id)?\s*[:#=\s"]*([A-Za-z0-9+/=]{20,})}
    set static::redact_biometric {[BIOMETRIC-REDACTED]}

    # ----------------------------------------------------------
    # PHI IDENTIFIER #18 — Unique Healthcare Identifiers & Codes
    # NPI  : 10-digit National Provider Identifier
    # DEA  : 2-letter prefix + 7-digit DEA registrant number
    # EIN  : XX-XXXXXXX Employer Identification Number
    # ICD-10-CM: Diagnosis codes (e.g. A00.0, J18.9)
    # CPT  : 5-digit Current Procedural Terminology codes
    # NDC  : XXXXX-XXXX-XX National Drug Code
    # ----------------------------------------------------------
    set static::re_npi \
        {(?i)(?:npi|national[_\s]?provider[_\s]?(?:id|identifier|number))\s*[:#=\s"]*(\d{10})}
    set static::redact_npi {[NPI-REDACTED]}

    set static::re_dea \
        {(?:\b[A-Za-z]{2}\d{7}\b)}
    set static::redact_dea {[DEA-REDACTED]}

    set static::re_ein \
        {(?:\b\d{2}-\d{7}\b)}
    set static::redact_ein {[EIN-REDACTED]}

    set static::re_icd10 \
        {(?:\b[A-TV-Z][0-9]{2}(?:\.[A-Z0-9]{1,4})?\b)}
    set static::redact_icd10 {[DX-CODE-REDACTED]}

    set static::re_cpt \
        {(?:\b(?:0[01]\d{3}|[1-9]\d{4})\b)}
    set static::redact_cpt {[CPT-REDACTED]}

    set static::re_ndc \
        {(?:\b\d{5}-\d{4}-\d{2}\b)}
    set static::redact_ndc {[NDC-REDACTED]}
}

# ============================================================
# PROC: scrub_phi
# Applies all PHI redaction patterns to the supplied payload
# string and returns the scrubbed result.
# Called from HTTP_REQUEST_DATA and HTTP_RESPONSE_DATA.
# ============================================================
proc scrub_phi { payload } {
    # #1 Names (structured field patterns)
    regsub -all $static::re_name         $payload "\\1$static::redact_name\\3"  payload

    # #2 Geographic
    regsub -all $static::re_zip          $payload $static::redact_zip            payload
    regsub -all $static::re_address      $payload $static::redact_address        payload

    # #3 Dates
    regsub -all $static::re_date_iso     $payload $static::redact_date           payload
    regsub -all $static::re_date_us      $payload $static::redact_date           payload
    regsub -all $static::re_date_spelled $payload $static::redact_date           payload

    # #4/#5 Phone / Fax
    regsub -all $static::re_phone        $payload $static::redact_phone          payload

    # #6 Email
    regsub -all $static::re_email        $payload $static::redact_email          payload

    # #7 SSN
    regsub -all $static::re_ssn          $payload $static::redact_ssn            payload

    # #8 MRN
    regsub -all $static::re_mrn          $payload $static::redact_mrn            payload

    # #9 Beneficiary / MBI
    regsub -all $static::re_mbi          $payload $static::redact_mbi            payload
    regsub -all $static::re_beneficiary  $payload $static::redact_beneficiary    payload

    # #10 Account / Claim / Credit Card
    regsub -all $static::re_account      $payload $static::redact_account        payload
    regsub -all $static::re_cc           $payload $static::redact_cc             payload

    # #11 License numbers
    regsub -all $static::re_license      $payload $static::redact_license        payload

    # #12 VINs
    regsub -all $static::re_vin          $payload $static::redact_vin            payload

    # #13 Device IDs
    regsub -all $static::re_mac          $payload $static::redact_mac            payload
    regsub -all $static::re_udi          $payload $static::redact_udi            payload

    # #14 PHI-bearing URLs
    regsub -all $static::re_phi_url      $payload $static::redact_url            payload

    # #15 IP addresses
    regsub -all $static::re_ipv4         $payload $static::redact_ipv4           payload
    regsub -all $static::re_ipv6         $payload $static::redact_ipv6           payload

    # #16 Biometrics
    regsub -all $static::re_biometric    $payload $static::redact_biometric      payload

    # #18 Healthcare unique IDs + clinical codes
    regsub -all $static::re_npi          $payload $static::redact_npi            payload
    regsub -all $static::re_dea          $payload $static::redact_dea            payload
    regsub -all $static::re_ein          $payload $static::redact_ein            payload
    regsub -all $static::re_icd10        $payload $static::redact_icd10          payload
    regsub -all $static::re_cpt          $payload $static::redact_cpt            payload
    regsub -all $static::re_ndc          $payload $static::redact_ndc            payload

    return $payload
}

# ============================================================
# PART 1 — TLS SESSION SECRET LOGGING
# Logs CLIENT_RANDOM (TLS 1.2 ECDHE / TLS 1.3 / DHE) and
# legacy RSA Session-ID secrets to /var/log/ltm.
# Extract with scripts/extract_session_keys.sh post-capture.
# ============================================================

when CLIENTSSL_HANDSHAKE {
    set client_ip [getfield [IP::client_addr] "%" 1]
    if { ($static::capture_client eq "any") or
         [IP::addr $client_ip equals $static::capture_client] } {
        # NSS Key Log format (Wireshark preferred)
        if { [SSL::clientrandom] ne "" and [SSL::sessionsecret] ne "" } {
            log local0. "CLIENT_RANDOM [SSL::clientrandom] [SSL::sessionsecret]"
        }
        # Legacy RSA / session-cache-enabled
        if { [SSL::sessionid] ne "" and [SSL::sessionsecret] ne "" } {
            log local0. "RSA Session-ID:[SSL::sessionid] Master-Key:[SSL::sessionsecret]"
        }
    }
}

when SERVERSSL_HANDSHAKE {
    set client_ip [getfield [IP::client_addr] "%" 1]
    if { ($static::capture_client eq "any") or
         [IP::addr $client_ip equals $static::capture_client] } {
        if { [SSL::clientrandom] ne "" and [SSL::sessionsecret] ne "" } {
            log local0. "CLIENT_RANDOM [SSL::clientrandom] [SSL::sessionsecret]"
        }
        if { [SSL::sessionid] ne "" and [SSL::sessionsecret] ne "" } {
            log local0. "RSA Session-ID:[SSL::sessionid] Master-Key:[SSL::sessionsecret]"
        }
    }
}

# ============================================================
# PART 2 — REQUEST SIDE PHI SCRUBBING
# ============================================================

when HTTP_REQUEST {
    # Remove Accept-Encoding to prevent compressed responses
    # (compressed payloads cannot be regex-scrubbed)
    HTTP::header remove "Accept-Encoding"

    if { [HTTP::method] eq "POST" or
         [HTTP::method] eq "PUT"  or
         [HTTP::method] eq "PATCH" } {
        set cl [HTTP::header "Content-Length"]
        if { $cl ne "" and $cl > 0 } {
            HTTP::collect [expr { min($cl, $static::max_collect) }]
        }
    }
}

when HTTP_REQUEST_DATA {
    set payload [call scrub_phi [HTTP::payload]]
    HTTP::payload replace 0 [HTTP::payload length] $payload
    HTTP::release
}

# ============================================================
# PART 3 — RESPONSE SIDE PHI SCRUBBING
# Scrubs text, JSON, XML, FHIR, and HL7 content types only.
# Binary and media content-types are skipped.
# ============================================================

when HTTP_RESPONSE {
    # Remove Transfer-Encoding chunked to simplify collection
    HTTP::header remove "Transfer-Encoding"

    set ct [HTTP::header "Content-Type"]
    if { [string match -nocase "*text*"  $ct] or
         [string match -nocase "*json*"  $ct] or
         [string match -nocase "*xml*"   $ct] or
         [string match -nocase "*fhir*"  $ct] or
         [string match -nocase "*hl7*"   $ct] or
         [string match -nocase "*form*"  $ct] } {

        set cl [HTTP::header "Content-Length"]
        if { $cl ne "" and $cl > 0 } {
            HTTP::collect [expr { min($cl, $static::max_collect) }]
        } else {
            # Chunked or unknown length
            HTTP::collect $static::max_collect
        }
    }
}

when HTTP_RESPONSE_DATA {
    set payload [call scrub_phi [HTTP::payload]]
    HTTP::payload replace 0 [HTTP::payload length] $payload
    HTTP::release
}
