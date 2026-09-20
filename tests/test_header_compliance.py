#!/usr/bin/env python3
"""
Unit Test Suite for Security Operations Automation & Header Compliance Tools

Author: Usman Masthan
Repository: secure-web-vapt-lab
"""

import os
import sys
import unittest

# Add scripts directory to module import path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))

from parse_zap_findings import (
    DEFAULT_FINDINGS,
    calculate_metrics,
    classify_finding_heuristics,
    to_splunk_cim,
)
from verify_headers import (
    MOCK_BASELINE_HEADERS,
    MOCK_HARDENED_HEADERS,
    evaluate_headers,
)


class TestHeaderCompliance(unittest.TestCase):
    """Test suite validating HTTP security header auditing logic."""

    def test_baseline_vulnerable_headers(self):
        """Verifies that baseline unhardened headers fail critical checks."""
        score, results, leaks = evaluate_headers(MOCK_BASELINE_HEADERS)
        self.assertLessEqual(score, 40, "Baseline headers should yield a low compliance score")
        self.assertIn("Exposed 'x-recruiting': /#/jobs", leaks)

        # Check CSP and HSTS failure
        result_map = {r["header"]: r["status"] for r in results}
        self.assertEqual(result_map["content-security-policy"], "FAIL")
        self.assertEqual(result_map["strict-transport-security"], "FAIL")
        self.assertEqual(result_map["x-frame-options"], "PASS")

    def test_hardened_headers(self):
        """Verifies that hardened configurations achieve full compliance."""
        score, results, leaks = evaluate_headers(MOCK_HARDENED_HEADERS)
        self.assertEqual(score, 100, "Hardened headers should achieve 100/100 score")
        self.assertEqual(len(leaks), 0, "Hardened configuration should have zero leaks")
        for r in results:
            self.assertEqual(r["status"], "PASS")


class TestTriageAndParser(unittest.TestCase):
    """Test suite validating false-positive heuristic rules and CIM transformations."""

    def test_socketio_false_positive_rejection(self):
        """Tests that Engine.IO/Socket.IO transport parameter is rejected as false positive."""
        raw_alert = {
            "id": "TEST-01",
            "name": "Session ID in URL Rewrite",
            "sample_url": "http://127.0.0.1:3000/socket.io/?EIO=4&transport=polling&sid=XYZ123",
            "evidence": "sid=XYZ123",
            "scanner_risk": "Medium",
        }
        triaged = classify_finding_heuristics(raw_alert)
        self.assertEqual(triaged["triage_status"], "Rejected (False Positive)")
        self.assertEqual(triaged["final_risk"], "None")
        self.assertEqual(triaged["cvss_score"], 0.0)

    def test_timestamp_false_positive_rejection(self):
        """Tests that static bundle numbers are rejected as Unix timestamp leaks."""
        raw_alert = {
            "id": "TEST-02",
            "name": "Timestamp Disclosure - Unix",
            "sample_url": "http://127.0.0.1:3000/dist/vendor.js",
            "evidence": "1722240000",
            "scanner_risk": "Low",
        }
        triaged = classify_finding_heuristics(raw_alert)
        self.assertEqual(triaged["triage_status"], "Rejected (False Positive)")

    def test_csp_true_positive_confirmation(self):
        """Tests that missing CSP alert is confirmed as a true positive vulnerability."""
        raw_alert = {
            "id": "TEST-03",
            "name": "Content Security Policy (CSP) Header Not Set",
            "sample_url": "http://127.0.0.1:3000/",
            "scanner_risk": "Medium",
        }
        triaged = classify_finding_heuristics(raw_alert)
        self.assertEqual(triaged["triage_status"], "Confirmed (True Positive)")
        self.assertEqual(triaged["final_risk"], "Medium")

    def test_operational_metrics(self):
        """Verifies calculation of False Positive Rate and counts."""
        triaged = [classify_finding_heuristics(f) for f in DEFAULT_FINDINGS]
        metrics = calculate_metrics(triaged)
        self.assertEqual(metrics["total_alerts"], 10)
        self.assertGreaterEqual(metrics["rejected_false_positives"], 2)
        self.assertGreaterEqual(metrics["false_positive_rate_pct"], 20.0)

    def test_splunk_cim_normalization(self):
        """Ensures generated events adhere to Splunk CIM Vulnerabilities model schema."""
        triaged = [classify_finding_heuristics(f) for f in DEFAULT_FINDINGS]
        events = to_splunk_cim(triaged, dest="juice-shop.lab")
        self.assertEqual(len(events), 10)

        required_keys = ["time", "dest", "signature", "vendor_product", "severity", "cvss", "status"]
        for ev in events:
            for k in required_keys:
                self.assertIn(k, ev, f"Missing required Splunk CIM field: {k}")
            self.assertEqual(ev["dest"], "juice-shop.lab")


if __name__ == "__main__":
    unittest.main()

