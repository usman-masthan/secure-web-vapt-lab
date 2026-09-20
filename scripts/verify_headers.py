#!/usr/bin/env python3
"""
Automated HTTP Security Header Compliance Verification Tool

Author: Usman Masthan
Repository: secure-web-vapt-lab

Description:
    Performs automated compliance audits on HTTP response headers against
    the OWASP Secure Headers recommendations. Supports live endpoints as
    well as pre-recorded baseline / hardened fixtures for automated CI/CD
    and regression testing.
"""

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Tuple

# Pre-recorded headers observed during initial lab reconnaissance (Vulnerable Baseline)
MOCK_BASELINE_HEADERS: Dict[str, str] = {
    "Access-Control-Allow-Origin": "*",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Feature-Policy": "payment 'self'",
    "X-Recruiting": "/#/jobs",
    "Cache-Control": "public, max-age=0",
    "Content-Type": "text/html; charset=UTF-8",
    "Date": "Wed, 29 Jul 2026 04:55:59 GMT",
    "Connection": "close",
}

# Post-remediation hardened headers (Hardened State)
MOCK_HARDENED_HEADERS: Dict[str, str] = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; font-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'self';"
    ),
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=(), payment=('self')",
    "Cache-Control": "no-store, max-age=0",
    "Content-Type": "text/html; charset=UTF-8",
    "Connection": "close",
}

SECURITY_RULES: List[Dict[str, Any]] = [
    {
        "name": "Content-Security-Policy",
        "header": "content-security-policy",
        "weight": 25,
        "required": True,
        "description": "Prevents XSS, unauthorized framing, and data injection.",
        "validator": lambda val: bool(val and ("default-src" in val or "script-src" in val)),
        "recommendation": "Set strict CSP directives: default-src 'self'; frame-ancestors 'self'.",
    },
    {
        "name": "Strict-Transport-Security (HSTS)",
        "header": "strict-transport-security",
        "weight": 15,
        "required": True,
        "description": "Enforces TLS encryption and defends against SSL-stripping.",
        "validator": lambda val: bool(val and "max-age" in val),
        "recommendation": "Enforce in production HTTPS: max-age=31536000; includeSubDomains.",
    },
    {
        "name": "X-Frame-Options",
        "header": "x-frame-options",
        "weight": 15,
        "required": True,
        "description": "Defends against clickjacking UI redressing attacks.",
        "validator": lambda val: bool(val and val.upper() in ["DENY", "SAMEORIGIN"]),
        "recommendation": "Set X-Frame-Options to SAMEORIGIN or DENY.",
    },
    {
        "name": "X-Content-Type-Options",
        "header": "x-content-type-options",
        "weight": 15,
        "required": True,
        "description": "Prevents MIME-type confusion attacks in web browsers.",
        "validator": lambda val: bool(val and val.lower().strip() == "nosniff"),
        "recommendation": "Set X-Content-Type-Options: nosniff.",
    },
    {
        "name": "Referrer-Policy",
        "header": "referrer-policy",
        "weight": 10,
        "required": False,
        "description": "Protects sensitive URL parameters from leaking to external domains.",
        "validator": lambda val: bool(val and "strict-origin" in val.lower()),
        "recommendation": "Set Referrer-Policy: strict-origin-when-cross-origin.",
    },
    {
        "name": "Permissions-Policy",
        "header": "permissions-policy",
        "weight": 10,
        "required": False,
        "description": "Restricts browser device features (camera, microphone, geolocation).",
        "validator": lambda val: bool(val),
        "recommendation": "Define restricted browser features in Permissions-Policy.",
    },
    {
        "name": "CORS Origin Restriction",
        "header": "access-control-allow-origin",
        "weight": 10,
        "required": False,
        "is_negative": True,  # If present with wildcard '*', it is a penalty
        "description": "Restricts unauthorized cross-domain reads.",
        "validator": lambda val: not (val and val.strip() == "*"),
        "recommendation": "Avoid wildcard '*' on data-bearing APIs; whitelist explicit origins.",
    },
]

LEAKY_HEADERS = ["server", "x-powered-by", "x-recruiting", "x-aspnet-version"]


def fetch_live_headers(url: str, timeout: int = 5) -> Dict[str, str]:
    """Fetches HTTP response headers from a live target URL."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (Security-Header-Auditor/1.0)"},
        method="HEAD",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return dict(response.headers.items())
    except urllib.error.HTTPError as e:
        # Some servers return 404 or 403 on HEAD, grab headers from error response
        return dict(e.headers.items())
    except Exception as e:
        # Fallback to GET
        try:
            req.method = "GET"
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return dict(response.headers.items())
        except Exception as e2:
            raise RuntimeError(f"Failed to connect to target {url}: {e2}")


def evaluate_headers(headers: Dict[str, str]) -> Tuple[int, List[Dict[str, Any]], List[str]]:
    """
    Evaluates header dictionary against security rules.
    Returns (score, rule_results, information_leak_warnings).
    """
    normalized = {k.lower(): v for k, v in headers.items()}
    total_score = 0
    results = []

    for rule in SECURITY_RULES:
        h_name = rule["header"]
        val = normalized.get(h_name)
        weight = rule["weight"]
        is_passed = rule["validator"](val)

        if is_passed:
            total_score += weight
            status = "PASS"
        else:
            status = "FAIL" if rule["required"] else "WARN"

        results.append(
            {
                "rule": rule["name"],
                "header": rule["header"],
                "observed_value": val if val else "[NOT SET]",
                "status": status,
                "weight": weight,
                "description": rule["description"],
                "recommendation": rule["recommendation"],
            }
        )

    # Check for informational / leaking headers
    leaks = []
    for leaky in LEAKY_HEADERS:
        if leaky in normalized:
            leaks.append(f"Exposed '{leaky}': {normalized[leaky]}")

    return total_score, results, leaks


def print_audit_report(score: int, results: List[Dict[str, Any]], leaks: List[str]) -> None:
    """Renders human-readable audit report to standard output."""
    print("=" * 84)
    print("            AUTOMATED HTTP SECURITY HEADER COMPLIANCE AUDIT")
    print("=" * 84)
    print(f"Overall Compliance Score: {score}/100")
    if score >= 80:
        posture = "GOOD (Hardened Defense-in-Depth)"
    elif score >= 50:
        posture = "MODERATE (Partial Defenses Present)"
    else:
        posture = "POOR (Critical Security Controls Missing)"
    print(f"Security Posture Rating: {posture}")
    print("-" * 84)
    print(f"{'Security Control':<32} {'Status':<8} {'Weight':<8} {'Observed Value':<32}")
    print("-" * 84)

    for r in results:
        obs = r["observed_value"]
        if len(obs) > 30:
            obs = obs[:27] + "..."
        print(f"{r['rule']:<32} {r['status']:<8} {r['weight']:<8} {obs:<32}")

    if leaks:
        print("-" * 84)
        print("[!] Information Disclosure Warnings Detected:")
        for l in leaks:
            print(f"    - {l}")

    print("=" * 84)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify HTTP security header compliance against OWASP best practices."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="Live target URL (e.g. http://127.0.0.1:3000)")
    group.add_argument(
        "--mock-baseline",
        action="store_true",
        help="Audit the recorded pre-remediation Juice Shop reconnaissance headers.",
    )
    group.add_argument(
        "--mock-hardened",
        action="store_true",
        help="Audit the post-remediation hardened header configuration.",
    )

    parser.add_argument("--json", action="store_true", help="Output audit results in JSON format.")
    parser.add_argument(
        "--min-score",
        type=int,
        default=50,
        help="Minimum required compliance score for exit code 0 (default: 50).",
    )

    args = parser.parse_args()

    if args.mock_baseline:
        headers = MOCK_BASELINE_HEADERS
        target_name = "Juice Shop Initial Recon Baseline (Mock)"
    elif args.mock_hardened:
        headers = MOCK_HARDENED_HEADERS
        target_name = "Juice Shop Hardened Configuration (Mock)"
    else:
        target_name = args.url
        try:
            headers = fetch_live_headers(args.url)
        except Exception as e:
            print(f"[-] Error connecting to {args.url}: {e}", file=sys.stderr)
            sys.exit(2)

    score, results, leaks = evaluate_headers(headers)

    if args.json:
        output = {
            "target": target_name,
            "compliance_score": score,
            "min_required_score": args.min_score,
            "passed": score >= args.min_score,
            "results": results,
            "information_leaks": leaks,
        }
        print(json.dumps(output, indent=2))
    else:
        print_audit_report(score, results, leaks)

    sys.exit(0 if score >= args.min_score else 1)


if __name__ == "__main__":
    main()

