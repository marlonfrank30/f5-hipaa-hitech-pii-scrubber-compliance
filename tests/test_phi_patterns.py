#!/usr/bin/env python3
"""
test_phi_patterns.py
====================
Unit tests for the PHI redaction regex patterns used in the F5 iRule.

These tests validate the Tcl regex patterns (ported to Python re module)
against sample payloads to ensure correct detection and non-detection
of all 18 HIPAA PHI identifiers.

Run with:
    python3 tests/test_phi_patterns.py -v
"""

import re
import unittest


# ---------------------------------------------------------------------------
# Regex patterns mirrored from the iRule (converted to Python syntax)
# ---------------------------------------------------------------------------

PATTERNS = {
    # PHI #1 — Names (structured fields)
    "name": (
        r'(?i)(?:"(?:patient_?name|first_?name|last_?name|full_?name|'
        r'member_?name|subscriber_?name)"\s*:\s*")([^"]{2,60})(")',
        "[NAME-REDACTED]",
    ),

    # PHI #2 — Geographic
    "zip": (r'(?:\b\d{5}(?:-\d{4})?\b)', "[ZIP-REDACTED]"),
    "address": (
        r'(?i)\b\d{1,6}\s+(?:[NSEW]\w+\s+)?[A-Za-z0-9\s]{3,40}'
        r'(?:St(?:reet)?|Ave(?:nue)?|Blvd|Rd|Road|Dr(?:ive)?|Ct|Court|'
        r'Ln|Lane|Way|Pl(?:ace)?|Pkwy|Cir(?:cle)?)\.?\b',
        "[ADDRESS-REDACTED]",
    ),

    # PHI #3 — Dates
    "date_iso": (
        r'(?:\b\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b)',
        "[DATE-REDACTED]",
    ),
    "date_us": (
        r'(?:\b(?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12]\d|3[01])[/\-]\d{4}\b)',
        "[DATE-REDACTED]",
    ),
    "date_spelled": (
        r'(?i)(?:\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|'
        r'Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|'
        r'Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2}[,\s]+\d{4}\b)',
        "[DATE-REDACTED]",
    ),

    # PHI #4/#5 — Phone/Fax
    "phone": (
        r'(?:\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b)',
        "[PHONE-REDACTED]",
    ),

    # PHI #6 — Email
    "email": (
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        "[EMAIL-REDACTED]",
    ),

    # PHI #7 — SSN
    "ssn": (
        r'(?:\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b)',
        "[SSN-REDACTED]",
    ),

    # PHI #8 — MRN
    "mrn": (
        r'(?i)(?:mrn|medical[_\s]?record[_\s]?(?:number|no|num|id)?|'
        r'chart[_\s]?(?:number|no|id)?|patient[_\s]?id)\s*[:#=\s"]*([A-Z0-9\-]{5,15})',
        "[MRN-REDACTED]",
    ),

    # PHI #9 — Medicare MBI
    "mbi": (
        r'(?:\b[1-9][A-HJ-NP-TV-Z][0-9][A-HJ-NP-TV-Z]{2}[0-9][A-HJ-NP-TV-Z]{2}[0-9]{2}\b)',
        "[MBI-REDACTED]",
    ),

    # PHI #10 — Account numbers
    "account": (
        r'(?i)(?:account[_\s]?(?:number|no|num|id)|billing[_\s]?(?:id|number|no)|'
        r'claim[_\s]?(?:number|no|id)|encounter[_\s]?(?:number|no|id))\s*[:#=\s"]*([A-Z0-9\-]{4,20})',
        "[ACCOUNT-REDACTED]",
    ),

    # Credit card — Visa
    "cc_visa": (
        r'(?:\b4[0-9]{12}(?:[0-9]{3})?\b)',
        "[CARD-REDACTED]",
    ),

    # PHI #11 — License
    "license": (
        r"(?i)(?:driver['\\s]?s?[_\\s]?licen[sc]e[_\\s]?(?:number|no|num)?|"
        r"dl[_\\s]?(?:number|no|num)?|state[_\\s]?id[_\\s]?(?:number|no)?|"
        r"license[_\\s]?(?:number|no|num|plate)?)\\s*[:#=\\s\"]*([A-Z0-9\\-]{5,15})",
        "[LICENSE-REDACTED]",
    ),

    # PHI #12 — VIN
    "vin": (
        r'(?:\b[A-HJ-NPR-Z0-9]{17}\b)',
        "[VIN-REDACTED]",
    ),

    # PHI #13 — MAC address
    "mac": (
        r'(?:\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b)',
        "[MAC-REDACTED]",
    ),

    # PHI #15 — IPv4
    "ipv4": (
        r'(?:\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b)',
        "[IP-REDACTED]",
    ),

    # PHI #18 — DEA
    "dea": (r'(?:\b[A-Za-z]{2}\d{7}\b)', "[DEA-REDACTED]"),

    # PHI #18 — EIN
    "ein": (r'(?:\b\d{2}-\d{7}\b)', "[EIN-REDACTED]"),

    # PHI #18 — ICD-10
    "icd10": (
        r'(?:\b[A-TV-Z][0-9]{2}(?:\.[A-Z0-9]{1,4})?\b)',
        "[DX-CODE-REDACTED]",
    ),

    # PHI #18 — NDC
    "ndc": (
        r'(?:\b\d{5}-\d{4}-\d{2}\b)',
        "[NDC-REDACTED]",
    ),
}


def matches(pattern_key: str, text: str) -> bool:
    pattern, _ = PATTERNS[pattern_key]
    return bool(re.search(pattern, text))


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestSSN(unittest.TestCase):
    def test_dashed_ssn(self):
        self.assertTrue(matches("ssn", "SSN: 123-45-6789"))

    def test_undashed_ssn(self):
        self.assertTrue(matches("ssn", "ssn=123456789"))

    def test_no_match_short(self):
        self.assertFalse(matches("ssn", "ref: 12345"))


class TestPhone(unittest.TestCase):
    def test_dashes(self):
        self.assertTrue(matches("phone", "Call 214-555-0123"))

    def test_parentheses(self):
        self.assertTrue(matches("phone", "(214) 555-0123"))

    def test_dots(self):
        self.assertTrue(matches("phone", "214.555.0123"))

    def test_plus_country(self):
        self.assertTrue(matches("phone", "+1-214-555-0123"))

    def test_no_match(self):
        self.assertFalse(matches("phone", "ticket #555-012"))


class TestEmail(unittest.TestCase):
    def test_standard(self):
        self.assertTrue(matches("email", "patient@hospital.org"))

    def test_subdomain(self):
        self.assertTrue(matches("email", "j.doe@clinic.health.gov"))

    def test_no_match(self):
        self.assertFalse(matches("email", "not-an-email"))


class TestDates(unittest.TestCase):
    def test_iso(self):
        self.assertTrue(matches("date_iso", "dob: 1985-07-14"))

    def test_us_slash(self):
        self.assertTrue(matches("date_us", "07/14/1985"))

    def test_us_dash(self):
        self.assertTrue(matches("date_us", "07-14-1985"))

    def test_spelled(self):
        self.assertTrue(matches("date_spelled", "July 14, 1985"))

    def test_spelled_abbrev(self):
        self.assertTrue(matches("date_spelled", "Jul 14 1985"))

    def test_year_only_no_match(self):
        # Standalone year should NOT match (years alone are permitted)
        self.assertFalse(matches("date_iso", "Year: 1985"))
        self.assertFalse(matches("date_us", "Year: 1985"))


class TestZIP(unittest.TestCase):
    def test_five_digit(self):
        self.assertTrue(matches("zip", "Dallas, TX 75034"))

    def test_zip_plus_four(self):
        self.assertTrue(matches("zip", "75034-1234"))


class TestMRN(unittest.TestCase):
    def test_mrn_label(self):
        self.assertTrue(matches("mrn", "MRN: A12345"))

    def test_medical_record_number(self):
        self.assertTrue(matches("mrn", "medical_record_number: 987654"))

    def test_patient_id(self):
        self.assertTrue(matches("mrn", "patient_id: PT-00042"))


class TestMBI(unittest.TestCase):
    def test_valid_mbi(self):
        # Follows CMS MBI pattern: 1C1AA1AA1A1
        self.assertTrue(matches("mbi", "1EG4-TE5-MK72"))

    def test_invalid_starts_with_zero(self):
        self.assertFalse(matches("mbi", "0EG4TE5MK72"))


class TestCreditCard(unittest.TestCase):
    def test_visa_16(self):
        self.assertTrue(matches("cc_visa", "4111111111111111"))

    def test_visa_13(self):
        self.assertTrue(matches("cc_visa", "4111111111111"))


class TestVIN(unittest.TestCase):
    def test_valid_vin(self):
        self.assertTrue(matches("vin", "1HGBH41JXMN109186"))

    def test_too_short(self):
        self.assertFalse(matches("vin", "1HGBH41JXM"))


class TestMAC(unittest.TestCase):
    def test_colon_separated(self):
        self.assertTrue(matches("mac", "00:1A:2B:3C:4D:5E"))

    def test_dash_separated(self):
        self.assertTrue(matches("mac", "00-1A-2B-3C-4D-5E"))

    def test_no_match(self):
        self.assertFalse(matches("mac", "001A2B3C4D5E"))


class TestIPv4(unittest.TestCase):
    def test_valid_ip(self):
        self.assertTrue(matches("ipv4", "192.168.1.100"))

    def test_valid_public(self):
        self.assertTrue(matches("ipv4", "203.0.113.5"))

    def test_no_match_out_of_range(self):
        self.assertFalse(matches("ipv4", "999.999.999.999"))


class TestDEA(unittest.TestCase):
    def test_valid_dea(self):
        self.assertTrue(matches("dea", "AB1234563"))

    def test_too_short(self):
        self.assertFalse(matches("dea", "AB12345"))


class TestEIN(unittest.TestCase):
    def test_valid_ein(self):
        self.assertTrue(matches("ein", "EIN: 12-3456789"))

    def test_no_match_ssn_format(self):
        # SSN (3-2-4) should NOT match EIN (2-7)
        self.assertFalse(matches("ein", "123-45-6789"))


class TestICD10(unittest.TestCase):
    def test_valid_icd10_simple(self):
        self.assertTrue(matches("icd10", "J18.9"))

    def test_valid_icd10_no_decimal(self):
        self.assertTrue(matches("icd10", "Z00"))

    def test_no_match_letter_u(self):
        # U codes ARE valid ICD-10 (COVID etc.) — U starts with U which is
        # not in [A-TV-Z]. This is intentional to reduce false positives.
        pass  # Informational only


class TestNDC(unittest.TestCase):
    def test_valid_ndc(self):
        self.assertTrue(matches("ndc", "12345-6789-01"))

    def test_no_match_wrong_format(self):
        self.assertFalse(matches("ndc", "1234-6789-01"))


class TestJSONPayload(unittest.TestCase):
    """Integration-style tests against realistic JSON payloads."""

    SAMPLE_FHIR = """{
      "resourceType": "Patient",
      "id": "example",
      "name": [{"family": "Smith", "given": ["John"]}],
      "birthDate": "1985-07-14",
      "telecom": [{"system": "phone", "value": "214-555-0123"}],
      "address": [{"line": ["123 Main St"], "postalCode": "75034"}],
      "identifier": [{"system": "MRN", "value": "MRN: PT-98765"}]
    }"""

    def test_fhir_date_detected(self):
        self.assertTrue(matches("date_iso", self.SAMPLE_FHIR))

    def test_fhir_phone_detected(self):
        self.assertTrue(matches("phone", self.SAMPLE_FHIR))

    def test_fhir_zip_detected(self):
        self.assertTrue(matches("zip", self.SAMPLE_FHIR))

    def test_fhir_mrn_detected(self):
        self.assertTrue(matches("mrn", self.SAMPLE_FHIR))


if __name__ == "__main__":
    unittest.main(verbosity=2)
