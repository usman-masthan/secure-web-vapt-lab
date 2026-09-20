#!/usr/bin/env python3
"""
ZAP Findings Parser & Security Operations Data Normalizer

Author: Usman Masthan
Repository: secure-web-vapt-lab

Description:
    Ingests vulnerability scanner telemetry (OWASP ZAP alerts), applies
    automated heuristic rules for false-positive detection, calculates
    operational SecOps metrics (False Positive Rate, Severity Distribution),
    and exports normalized records into JSON, CSV, and Splunk Common
    Information Model (CIM) Vulnerability data model format.
"""

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List

# Baseline findings dataset recorded during the OWASP Juice Shop assessment
DEFAULT_FINDINGS: List[Dict[str, Any]] = [
    {
        "id": "ZAP-001",
        "plugin_id": "10038",
        "name": "Content Security Policy (CSP) Header Not Set",
        "scanner_risk": "Medium",
        "confidence": "High",
        "instances": 3,
        "sample_url": "http://127.0.0.1:3000/",
        "evidence": "Missing Content-Security-Policy response header",
        "cwe_id": "693",
        "wasc_id": "15",
    },
    {
        "id": "ZAP-002",
        "plugin_id": "10098",
        "name": "Cross-Domain Misconfiguration",
        "scanner_risk": "Medium",
        "confidence": "Medium",
        "instances": 8,
        "sample_url": "http://127.0.0.1:3000/rest/products/search",
        "evidence": "Access-Control-Allow-Origin: *",
        "cwe_id": "264",
        "wasc_id": "14",
    },
    {
        "id": "ZAP-003",
        "plugin_id": "10020",
        "name": "Missing Anti-clickjacking Header",
        "scanner_risk": "Medium",
        "confidence": "Medium",
        "instances": 2,
        "sample_url": "http://127.0.0.1:3000/assets/i18n/en.json",
        "evidence": "Missing X-Frame-Options on sub-resource",
        "cwe_id": "1021",
        "wasc_id": "15",
    },
    {
        "id": "ZAP-004",
        "plugin_id": "10043",
        "name": "Session ID in URL Rewrite",
        "scanner_risk": "Medium",
        "confidence": "High",
        "instances": 4,
        "sample_url": "http://127.0.0.1:3000/socket.io/?EIO=4&transport=polling&sid=3t7N9fA3zYq0-L_HAAAB",
        "evidence": "sid=3t7N9fA3zYq0-L_HAAAB",
        "cwe_id": "598",
        "wasc_id": "13",
    },
    {
        "id": "ZAP-005",
        "plugin_id": "10036",
        "name": "Server Leaks Private IP Address",
        "scanner_risk": "Low",
        "confidence": "Medium",
        "instances": 1,
        "sample_url": "http://127.0.0.1:3000/",
        "evidence": "172.17.0.2",
        "cwe_id": "200",
        "wasc_id": "13",
    },
    {
        "id": "ZAP-006",
        "plugin_id": "10035",
        "name": "Strict-Transport-Security Header Not Set",
        "scanner_risk": "Low",
        "confidence": "High",
        "instances": 16,
        "sample_url": "http://127.0.0.1:3000/",
        "evidence": "Missing Strict-Transport-Security header",
        "cwe_id": "319",
        "wasc_id": "15",
    },
    {
        "id": "ZAP-007",
        "plugin_id": "10096",
        "name": "Timestamp Disclosure - Unix",
        "scanner_risk": "Low",
        "confidence": "Low",
        "instances": 12,
        "sample_url": "http://127.0.0.1:3000/frontend/dist/runtime.js",
        "evidence": "1722240000",
        "cwe_id": "200",
        "wasc_id": "13",
    },
    {
        "id": "ZAP-008",
        "plugin_id": "10021",
        "name": "X-Content-Type-Options Header Missing",
        "scanner_risk": "Low",
        "confidence": "Medium",
        "instances": 4,
        "sample_url": "http://127.0.0.1:3000/api-docs/",
        "evidence": "Missing X-Content-Type-Options header",
        "cwe_id": "693",
        "wasc_id": "15",
    },
    {
        "id": "ZAP-009",
        "plugin_id": "10109",
        "name": "Modern Web Application",
        "scanner_risk": "Informational",
        "confidence": "Medium",
        "instances": 1,
        "sample_url": "http://127.0.0.1:3000/",
        "evidence": "AJAX and SPA components detected",
        "cwe_id": "0",
        "wasc_id": "0",
    },
    {
        "id": "ZAP-010",
        "plugin_id": "10015",
        "name": "Re-examine Cache-control Directives",
        "scanner_risk": "Informational",
        "confidence": "Low",
        "instances": 1,
        "sample_url": "http://127.0.0.1:3000/",
        "evidence": "Cache-Control: public, max-age=0",
        "cwe_id": "525",
        "wasc_id": "13",
    },
]


def classify_finding_heuristics(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Applies automated heuristic rules to classify raw alerts into
    True Positive, Rejected False Positive, Environmental, or Informational.
    """
    name = finding.get("name", "")
    sample_url = finding.get("sample_url", "")
    evidence = finding.get("evidence", "")

    # Rule 1: Socket.IO / Engine.IO transport parameter != Auth Session
    if "Session ID in URL Rewrite" in name and ("socket.io" in sample_url or "sid=" in evidence):
        status = "Rejected (False Positive)"
        final_risk = "None"
        cvss = 0.0
        reason = "Socket.IO transport parameter misclassified by scanner regex; auth uses Bearer JWT."
    # Rule 2: Static asset timestamps in compiled bundles
    elif "Timestamp Disclosure" in name and (
        ".js" in sample_url or ".css" in sample_url or "dist" in sample_url
    ):
        status = "Rejected (False Positive)"
        final_risk = "None"
        cvss = 0.0
        reason = " Benign static asset hash or public review date; not sensitive server epoch."
    # Rule 3: Missing clickjacking on non-HTML sub-resources (JSON/API)
    elif "Missing Anti-clickjacking" in name and (
        ".json" in sample_url or "/api/" in sample_url or "/rest/" in sample_url
    ):
        status = "Contextual Nuance"
        final_risk = "Low"
        cvss = 3.1
        reason = "Sub-resource cannot be framed in HTML iframe; main portal has SAMEORIGIN."
    # Rule 4: HSTS missing over plaintext HTTP
    elif "Strict-Transport-Security" in name and sample_url.startswith("http://"):
        status = "Environmental Limitation"
        final_risk = "Low"
        cvss = 3.7
        reason = "RFC 6797 prohibits HSTS over unencrypted HTTP; requires edge TLS termination."
    # Rule 5: Private IP in local container bridge
    elif "Private IP" in name and (
        "172.17." in evidence or "127.0.0.1" in evidence or "10." in evidence
    ):
        status = "Environmental Nuance"
        final_risk = "Low"
        cvss = 2.6
        reason = "Internal Docker network bridge address in isolated test environment."
    # Rule 6: CSP missing
    elif "Content Security Policy" in name:
        status = "Confirmed (True Positive)"
        final_risk = "Medium"
        cvss = 5.4
        reason = "Missing browser sandbox defense; allows inline scripts and XSS execution."
    # Rule 7: CORS Wildcard
    elif "Cross-Domain" in name and "*" in evidence:
        status = "Confirmed (True Positive)"
        final_risk = "Medium"
        cvss = 6.5
        reason = "Wildcard origin reflected on API endpoints allows unauthorized cross-domain reads."
    # Rule 8: X-Content-Type-Options
    elif "X-Content-Type-Options" in name:
        status = "Confirmed (True Positive)"
        final_risk = "Low"
        cvss = 3.5
        reason = "Missing nosniff header allows MIME-sniffing vulnerabilities in legacy browsers."
    # Default to Informational or Scanner risk
    elif finding.get("scanner_risk") == "Informational":
        status = "Informational"
        final_risk = "Informational"
        cvss = 0.0
        reason = "Architecture or operational indicator; no direct security vulnerability."
    else:
        status = "Pending Validation"
        final_risk = finding.get("scanner_risk", "Unknown")
        cvss = 0.0
        reason = "Requires manual assessment."

    enriched = dict(finding)
    enriched["triage_status"] = status
    enriched["final_risk"] = final_risk
    enriched["cvss_score"] = cvss
    enriched["triage_reason"] = reason
    return enriched


def calculate_metrics(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculates operational vulnerability metrics and False Positive Rates."""
    total = len(findings)
    status_counts: Dict[str, int] = {}
    risk_counts: Dict[str, int] = {}

    for f in findings:
        st = f["triage_status"]
        rk = f["final_risk"]
        status_counts[st] = status_counts.get(st, 0) + 1
        risk_counts[rk] = risk_counts.get(rk, 0) + 1

    false_positives = status_counts.get("Rejected (False Positive)", 0)
    confirmed_tp = status_counts.get("Confirmed (True Positive)", 0)
    fpr_pct = (false_positives / total * 100) if total > 0 else 0.0

    return {
        "total_alerts": total,
        "confirmed_true_positives": confirmed_tp,
        "rejected_false_positives": false_positives,
        "false_positive_rate_pct": round(fpr_pct, 1),
        "status_breakdown": status_counts,
        "final_risk_breakdown": risk_counts,
    }


def to_splunk_cim(findings: List[Dict[str, Any]], dest: str = "127.0.0.1") -> List[Dict[str, Any]]:
    """
    Transforms findings into Splunk Common Information Model (CIM)
    Vulnerabilities data model events.
    """
    events = []
    now_iso = datetime.now(timezone.utc).isoformat()

    for f in findings:
        event = {
            "time": now_iso,
            "dest": dest,
            "signature": f["name"],
            "signature_id": f["plugin_id"],
            "vendor_product": "OWASP Zed Attack Proxy (ZAP)",
            "app": "OWASP Juice Shop",
            "url": f["sample_url"],
            "severity": f["final_risk"].lower(),
            "original_severity": f["scanner_risk"].lower(),
            "cvss": f["cvss_score"],
            "cwe": f"CWE-{f.get('cwe_id', '0')}",
            "status": "closed" if "Rejected" in f["triage_status"] else "open",
            "action": "blocked" if "Rejected" in f["triage_status"] else "alerted",
            "triage_verdict": f["triage_status"],
            "triage_reason": f["triage_reason"],
            "evidence": f.get("evidence", ""),
        }
        events.append(event)
    return events


def print_table(findings: List[Dict[str, Any]], metrics: Dict[str, Any]) -> None:
    """Renders a clean terminal summary table."""
    print("=" * 86)
    print("        OWASP ZAP TRIAGE & SECURITY OPERATIONS DATA NORMALIZATION")
    print("=" * 86)
    print(
        f"Total Alerts: {metrics['total_alerts']} | "
        f"Confirmed True Positives: {metrics['confirmed_true_positives']} | "
        f"Rejected False Positives: {metrics['rejected_false_positives']} | "
        f"FPR: {metrics['false_positive_rate_pct']}%"
    )
    print("-" * 86)
    print(
        f"{'ID':<8} {'Alert Name':<38} {'Scan Risk':<10} {'Final Risk':<10} {'Status':<20}"
    )
    print("-" * 86)
    for f in findings:
        print(
            f"{f['id']:<8} {f['name'][:36]:<38} {f['scanner_risk']:<10} "
            f"{f['final_risk']:<10} {f['triage_status']:<20}"
        )
    print("=" * 86)


def export_csv(findings: List[Dict[str, Any]], filepath: str) -> None:
    """Exports findings to CSV for Power BI / Excel operational reporting."""
    if not findings:
        return
    keys = [
        "id",
        "plugin_id",
        "name",
        "scanner_risk",
        "final_risk",
        "cvss_score",
        "triage_status",
        "sample_url",
        "evidence",
        "triage_reason",
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(findings)
    print(f"[+] Successfully exported CSV report to: {filepath}")


def export_json(data: Any, filepath: str) -> None:
    """Exports structured data to JSON format."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Successfully exported JSON output to: {filepath}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse OWASP ZAP vulnerability telemetry, triage false positives, and format for SecOps/SIEM."
    )
    parser.add_argument(
        "--input-json",
        help="Path to external ZAP JSON export file. Defaults to baseline lab findings.",
    )
    parser.add_argument(
        "--export-csv",
        help="Export triaged findings to CSV file (ideal for Power BI / Excel reporting).",
    )
    parser.add_argument(
        "--export-splunk",
        help="Export findings normalized to Splunk CIM format (JSON array of events).",
    )
    parser.add_argument(
        "--export-json",
        help="Export triaged findings and metrics to JSON file.",
    )

    args = parser.parse_args()

    raw_data = DEFAULT_FINDINGS
    if args.input_json:
        try:
            with open(args.input_json, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
        except Exception as e:
            print(f"[-] Error reading input JSON file {args.input_json}: {e}", file=sys.stderr)
            sys.exit(1)

    # Apply heuristics
    triaged = [classify_finding_heuristics(f) for f in raw_data]
    metrics = calculate_metrics(triaged)

    # Print summary table
    print_table(triaged, metrics)

    # Optional exports
    if args.export_csv:
        export_csv(triaged, args.export_csv)

    if args.export_splunk:
        splunk_events = to_splunk_cim(triaged)
        export_json(splunk_events, args.export_splunk)

    if args.export_json:
        payload = {"metrics": metrics, "findings": triaged}
        export_json(payload, args.export_json)


if __name__ == "__main__":
    main()

