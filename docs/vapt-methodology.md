# Web Application Penetration Testing Methodology

## Standard Operating Procedure (SOP)

This document establishes the standardized testing methodology employed during the vulnerability assessment and penetration testing of the target environment. The framework adheres to the principles defined in:
- **OWASP Web Security Testing Guide (WSTG v4.2)**
- **NIST Special Publication 800-115 (Technical Guide to Information Security Testing and Assessment)**
- **Penetration Testing Execution Standard (PTES)**

---

## The 6-Phase Assessment Lifecycle

```
[ Phase 1: Planning & Scope ]
              |
              v
[ Phase 2: Reconnaissance & Discovery (Nmap) ]
              |
              v
[ Phase 3: Automated Proxy & Passive Inspection (OWASP ZAP) ]
              |
              v
[ Phase 4: Manual Exploitation & False Positive Triage ]
              |
              v
[ Phase 5: Technical & Executive Reporting ]
              |
              v
[ Phase 6: Remediation Verification & Retesting ]
```

---

## Phase Breakdown

### Phase 1: Planning, Scoping & Rules of Engagement
- Define authorized IP targets, domains, and port boundaries.
- Mandate test constraints: localhost binding (`127.0.0.1`), non-destructive payloads, exclusion of live customer data, and zero denial-of-service (DoS) testing.
- Secure explicit written authorization prior to initiating active scans.
- Reference: [scope.md](scope.md)

### Phase 2: Reconnaissance & Port Discovery
- Probe network endpoints to detect active services, open TCP/UDP ports, and daemon signatures.
- Execute non-intrusive service version detection via Nmap:
  ```bash
  nmap -sV -p 3000 -oN results/nmap-initial-scan.txt 127.0.0.1
  ```
- Correlate unclassified service banners (e.g. `ppp?`) with manual HTTP fingerprinting probes (`curl -I`).
- Reference: [../results/nmap-initial-scan.txt](../results/nmap-initial-scan.txt)

### Phase 3: Automated Proxy & Passive Vulnerability Inspection
- Route all HTTP/HTTPS browser interactions through an intercepting proxy (OWASP ZAP / Burp Suite).
- Exercise core user journeys: account registration, product search, cart manipulation, and checkout.
- Passive Inspection Engine monitors headers, cookies, query parameters, and responses in real-time without introducing hostile payloads.
- Compile automated findings inventory categorized by risk and confidence.
- Reference: [../results/zap-passive-findings.md](../results/zap-passive-findings.md)

### Phase 4: Manual Exploitation & False Positive Triage
- Automated scanner alerts are treated solely as hypotheses requiring verification.
- **Manual Verification Matrix**:
  - Test input fields for structured query injection (SQLi, NoSQLi).
  - Test origin headers (`Origin: https://attacker.com`) to evaluate cross-origin policy enforcement.
  - Review client-side JavaScript bundles for exposed secrets, routes, and debug endpoints.
- **False Positive Elimination Protocol**:
  - Verify underlying protocol mechanics (e.g. distinguishing WebSocket transport tokens from session identifiers).
  - Cross-reference findings against RFC standards (e.g. RFC 6797 regarding HSTS over plaintext HTTP).
  - Reject alerts where triggering data represents benign metadata or public content.
- Reference: [../results/manual-validation-report.md](../results/manual-validation-report.md) & [../results/false-positive-analysis.md](../results/false-positive-analysis.md)

### Phase 5: Technical & Executive Reporting
- Standardize risk ratings using Common Vulnerability Scoring System (CVSS v3.1).
- Deliver dual-audience reports:
  - **Executive Report**: High-level risk posture, business impact, and governance roadmap for leadership.
  - **Technical Remediation Report**: Concrete code diffs, configuration parameters, and proof-of-concept reproductions for developers.
- Reference: [executive-summary.md](executive-summary.md)

### Phase 6: Remediation Verification & Retesting
- Once developers implement defensive patches, execute targeted retests using identical payloads and edge cases.
- Run automated compliance scripts to confirm header reinforcement.
- Formal sign-off and ticket closure only upon verified mitigation.
- Reference: [../results/retesting-report.md](../results/retesting-report.md)

