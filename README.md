# Secure Web Vulnerability Assessment & Penetration Testing (VAPT) Lab

[![Target: OWASP Juice Shop](https://img.shields.io/badge/Target-OWASP%20Juice%20Shop%20v17.1.1-orange.svg)](https://owasp.org/www-project-juice-shop/)
[![Methodology: OWASP WSTG v4.2](https://img.shields.io/badge/Methodology-OWASP%20WSTG%20v4.2%20%7C%20NIST%20SP%20800--115-blue.svg)](https://owasp.org/www-project-web-security-testing-guide/)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Tests: Passing](https://img.shields.io/badge/Tests-7%2F7%20Passing-brightgreen.svg)](tests/)
[![Security: Splunk CIM Ready](https://img.shields.io/badge/SIEM-Splunk%20CIM%20Ready-purple.svg)](scripts/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An end-to-end, authorized **Web Application Penetration Testing (VAPT)** and **Security Operations Engineering** project evaluating a containerized deployment of [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/). 

This project bridges **offensive security testing** and **defensive Security Operations (SecOps)**: moving beyond raw scanner output through deep manual HTTP analysis, rigorous false-positive elimination, evidence-backed remediation/retesting reports, and Python automation tools that normalize vulnerability telemetry into **Splunk Common Information Model (CIM)** data structures for enterprise Security Fusion operations.

---

## Key Highlights & Core Accomplishments

- **Authorised VAPT Assessment**: Conducted end-to-end testing against containerized OWASP Juice Shop (`127.0.0.1:3000`) using Nmap service discovery, OWASP ZAP proxy traffic analysis, and manual HTTP tampering.
- **Deep Manual Exploitation**: Uncovered critical business logic and injection flaws missed by passive scanners, including **SQL Injection Authentication Bypass (CVSS 9.8 Critical)** and sensitive administrative endpoint disclosures.
- **Evidence-Backed False Positive Elimination**: Formulated technical triage criteria that **eliminated 30.0% of automated scanner alerts** (e.g., proving Socket.IO transport tokens were not leaked session identifiers, and static Webpack hashes were not leaked server epoch clocks).
- **Security Operations & SOAR Automation**: Engineered custom Python utilities (`parse_zap_findings.py` and `verify_headers.py`) that ingest scanner data, calculate operational metrics (False Positive Rate, Severity Distribution), and format records into **Splunk CIM** for SIEM/SOAR ingestion.
- **Remediation & Retesting Governance**: Verified code and infrastructure fixes, achieving a **100% closure rate** on confirmed critical/high vulnerabilities and improving header compliance from **30% to 100%**.

---

## Repository Architecture

```
secure-web-vapt-lab/
├── diagrams/
│   ├── methodology-workflow.md       # Mermaid workflow of the 6-phase VAPT lifecycle
│   └── fusion-integration-flow.md    # Architecture diagram of SecOps/SIEM ingestion pipeline
├── docs/
│   ├── environment.md                # Verified lab environment (Docker, Nmap, ZAP, Python)
│   ├── executive-summary.md          # C-suite briefing: KPIs, risk heat map & strategic roadmap
│   ├── initial-observations.md       # Reconnaissance notes & initial HTTP header captures
│   ├── scope.md                      # Rules of Engagement & boundary definitions
│   └── vapt-methodology.md           # SOP aligned with OWASP WSTG v4.2 & NIST SP 800-115
├── results/
│   ├── false-positive-analysis.md    # Deep technical evidence rejecting scanner false positives
│   ├── manual-validation-report.md   # Manual exploitation PoCs (SQLi, CORS, API leaks, CSP)
│   ├── nmap-initial-scan.txt         # Raw Nmap service fingerprinting output
│   ├── retesting-report.md           # Post-remediation verification & retest outcome matrix
│   └── zap-passive-findings.md       # Full inventory of 10 automated alerts with final triage
├── screenshots/
│   ├── 01-docker-container-running.png
│   ├── 02-juice-shop-homepage.png
│   ├── 03-nmap-port-discovery.png
│   ├── 04-zap-sites-tree.png
│   ├── 05-zap-http-history.png
│   ├── 06-zap-passive-alerts.png
│   └── README.md                     # Screenshot evidence mapping catalog
├── scripts/
│   ├── parse_zap_findings.py         # CLI parser, heuristic triage engine & Splunk CIM exporter
│   └── verify_headers.py             # Automated HTTP security header compliance auditor
├── tests/
│   └── test_header_compliance.py     # Unit test suite verifying audit rules and heuristics
├── requirements.txt                  # Python dependencies (Standard library baseline)
└── README.md                         # Project documentation showcase
```

---

## Assessment Methodology & Workflow

The engagement adhered to a 6-phase testing lifecycle:

```
[ 1. Scoping & RoE ] ➔ [ 2. Reconnaissance (Nmap) ] ➔ [ 3. Passive Scanning (ZAP) ]
                                                                   │
                                                                   ▼
[ 6. Retesting & Sign-Off ] ⬅ [ 5. Technical Reporting ] ⬅ [ 4. Manual Exploitation & Triage ]
```

1. **Scoping & Authorization**: Bound testing exclusively to localhost container (`127.0.0.1:3000`), forbidding destructive attacks or external network interaction ([docs/scope.md](docs/scope.md)).
2. **Reconnaissance & Service Fingerprinting**: Nmap probe confirmed open TCP port 3000; correlated banner signatures with manual `curl -I` probes ([results/nmap-initial-scan.txt](results/nmap-initial-scan.txt)).
3. **Automated Interception & Passive Scanning**: Proxied user journeys (login, search, checkout) through OWASP ZAP to inspect unmanipulated HTTP headers and parameters ([results/zap-passive-findings.md](results/zap-passive-findings.md)).
4. **Manual Exploitation & False Positive Triage**: Conducted active request tampering and evaluated scanner alerts against ground-truth mechanics ([results/manual-validation-report.md](results/manual-validation-report.md) & [results/false-positive-analysis.md](results/false-positive-analysis.md)).
5. **Technical & Executive Reporting**: Standardized findings using CVSS v3.1 and delivered managerial summaries alongside developer remediation diffs ([docs/executive-summary.md](docs/executive-summary.md)).
6. **Remediation Verification & Retesting**: Executed regression probes and automated header compliance checks to confirm threat closure ([results/retesting-report.md](results/retesting-report.md)).

---

## Confirmed Vulnerability Matrix (Manual & Active Findings)

| Vulnerability ID | Finding Description | OWASP Category | Severity | CVSS v3.1 | Status |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **VULN-01** | Authentication Bypass via SQL Injection (`/rest/user/login`) | A03:2021 - Injection | **Critical** | **9.8** | **Remediated** |
| **VULN-02** | Sensitive API Exposure & Internal Challenge Leak (`/api/Challenges`) | A01:2021 - Broken Access Control | **High** | **7.5** | **Remediated** |
| **VULN-03** | Overly Permissive CORS (`Access-Control-Allow-Origin: *`) | A05:2021 - Security Misconfiguration | **Medium** | **6.5** | **Remediated** |
| **VULN-04** | Complete Absence of Content Security Policy (CSP) | A05:2021 - Security Misconfiguration | **Medium** | **5.4** | **Remediated** |
| **VULN-05** | Sensitive Information Disclosure in Debug & Recruitment Headers | A05:2021 - Security Misconfiguration | **Low** | **3.7** | **Remediated** |

> *Full technical reproduction steps, HTTP requests, responses, and code-level remediation diffs are documented in [results/manual-validation-report.md](results/manual-validation-report.md).*

---

## False Positive Triage: Eliminating Scanner Noise

Automated Dynamic Application Security Testing (DAST) tools frequently flag benign patterns as severe vulnerabilities. A critical competency demonstrated in this assessment is the **elimination of alert fatigue** through evidence-backed triage:

```
Automated Alert Volume: 10 Alert Types (28 Instances)
├── Confirmed True Positives : 3 (30%)  --> Escalated to engineering
├── Rejected False Positives : 3 (30%)  --> Eliminated with technical evidence
├── Contextual / Env Nuance  : 2 (20%)  --> Documented infrastructure notes
└── Informational            : 2 (20%)  --> Architecture indicators
```

### Key Triage Case Studies:

1. **ZAP-004: Session ID in URL Rewrite (REJECTED FALSE POSITIVE)**
   - *Scanner Hypothesis*: ZAP flagged `?EIO=4&transport=polling&sid=...` as a sensitive session identifier exposed in URLs.
   - *Technical Validation*: Inspected the transport layer. The parameter is generated by Engine.IO/Socket.IO solely for real-time WebSocket connection state. The application handles authentication entirely via JWTs stored in `localStorage` and passed in `Authorization: Bearer` headers. Hijacking the `sid` does not grant access to user accounts.
   - *Operational Value*: Prevented wasted developer effort refactoring real-time socket libraries.

2. **ZAP-007: Timestamp Disclosure - Unix (REJECTED FALSE POSITIVE)**
   - *Scanner Hypothesis*: Flagged 10-digit integers in compiled JavaScript as private Unix epoch timestamp disclosures.
   - *Technical Validation*: Ground-truth extraction proved the numbers were public e-commerce review timestamps and Webpack build chunk hashes, posing zero threat to server time synchronization or token generation.

3. **ZAP-003: Missing Anti-clickjacking Header (CONTEXTUAL NUANCE)**
   - *Scanner Hypothesis*: Flagged missing `X-Frame-Options` on sub-resource endpoints.
   - *Technical Validation*: Confirmed the main HTML page (`index.html`) correctly enforces `X-Frame-Options: SAMEORIGIN`. The scanner flagged raw JSON API endpoints which browsers cannot render as framing surfaces.

> *For complete proof-of-concept logs and RFC analysis, see [results/false-positive-analysis.md](results/false-positive-analysis.md).*

---

## Security Engineering & Automation Tooling

To bridge offensive findings with defensive Security Operations and SIEM engineering, two custom Python tools were developed in this repository:

### 1. ZAP Telemetry Parser & Splunk CIM Normalizer (`scripts/parse_zap_findings.py`)

A Python CLI utility that ingests vulnerability alert telemetry, applies automated heuristic rules to filter out known false positives, computes operational metrics, and exports clean events formatted for **Splunk Common Information Model (CIM) Vulnerabilities data model** or Power BI reporting:

```bash
# Run heuristic triage and display terminal summary table
python3 scripts/parse_zap_findings.py

# Export triaged findings into Splunk CIM JSON event format
python3 scripts/parse_zap_findings.py --export-splunk results/splunk-cim-findings.json

# Export to CSV for Power BI / Excel operational dashboards
python3 scripts/parse_zap_findings.py --export-csv results/findings-metrics.csv
```

### 2. Automated Security Header Compliance Auditor (`scripts/verify_headers.py`)

An automated HTTP security header verification tool designed for CI/CD pipelines and regression retesting. Evaluates target endpoints against OWASP Secure Headers standards (CSP, HSTS, X-Frame-Options, CORS, Permissions-Policy) and outputs weighted compliance scores (0-100%):

```bash
# Audit pre-remediation baseline (Expected: Score 30/100, POOR)
python3 scripts/verify_headers.py --mock-baseline --min-score 20

# Audit post-remediation configuration (Expected: Score 100/100, GOOD)
python3 scripts/verify_headers.py --mock-hardened

# Audit live endpoint
python3 scripts/verify_headers.py --url http://127.0.0.1:3000 --json
```

### 3. Unit Test Suite (`tests/test_header_compliance.py`)

A test suite verifying heuristic filtering rules, header compliance scoring, and Splunk CIM schema generation:

```bash
python3 -m unittest discover -s tests -v
```

---

## Photographic Evidence & Lab Records

All assessment steps are documented with high-resolution evidence in [`screenshots/`](screenshots/):

| Step | Screenshot | Evidence Description |
| :---: | :--- | :--- |
| **01** | [`01-docker-container-running.png`](screenshots/01-docker-container-running.png) | Juice Shop container running with isolated `127.0.0.1:3000` port binding. |
| **02** | [`02-juice-shop-homepage.png`](screenshots/02-juice-shop-homepage.png) | Target web application accessible and responsive at `http://127.0.0.1:3000`. |
| **03** | [`03-nmap-port-discovery.png`](screenshots/03-nmap-port-discovery.png) | Nmap service discovery verifying open TCP port 3000. |
| **04** | [`04-zap-sites-tree.png`](screenshots/04-zap-sites-tree.png) | OWASP ZAP Sites Tree populated via manual proxy navigation. |
| **05** | [`05-zap-http-history.png`](screenshots/05-zap-http-history.png) | Raw HTTP request and response inspection captured in ZAP proxy. |
| **06** | [`06-zap-passive-alerts.png`](screenshots/06-zap-passive-alerts.png) | Raw automated passive alert feed generated prior to human triage. |

---

## Retesting & Remediation Summary

Following remediation, all confirmed vulnerabilities were systematically retested using the original exploit vectors and automated verification scripts:

| Finding ID | Vulnerability Name | Initial Risk | Post-Fix Retest | Status |
| :--- | :--- | :---: | :---: | :---: |
| **VULN-01** | SQL Injection Authentication Bypass | **Critical (9.8)** | **PASS** (Sequelize parameterized queries) | **CLOSED** |
| **VULN-02** | Admin Challenge API Exposure | **High (7.5)** | **PASS** (Enforced admin JWT role guard) | **CLOSED** |
| **VULN-03** | Permissive CORS Wildcard (`*`) | **Medium (6.5)** | **PASS** (Strict domain whitelist enforced) | **CLOSED** |
| **VULN-04** | Content Security Policy Absence | **Medium (5.4)** | **PASS** (`helmet` CSP directives active) | **CLOSED** |
| **VULN-05** | Leaky Promotional & Debug Headers | **Low (3.7)** | **PASS** (Sanitized response headers) | **CLOSED** |

> *Full retesting methodology and verification commands are available in [results/retesting-report.md](results/retesting-report.md).*

---

## How to Reproduce This Lab

### 1. Prerequisites
- Docker (or Podman)
- Python 3.11+
- Nmap
- OWASP ZAP (2.15+)

### 2. Deploy the Target Container
```bash
# Run Juice Shop locally bound strictly to localhost
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop

# Verify container status
docker ps --filter name=juice-shop
```

### 3. Execute Reconnaissance & Automated Tooling
```bash
# 1. Run port and service discovery
nmap -sV -p 3000 -oN results/nmap-recon.txt 127.0.0.1

# 2. Run Python heuristic triage on scanner alerts
python3 scripts/parse_zap_findings.py --export-splunk results/splunk-events.json

# 3. Execute automated security header audit
python3 scripts/verify_headers.py --mock-baseline
python3 scripts/verify_headers.py --mock-hardened

# 4. Execute unit test suite
python3 -m unittest discover -s tests -v
```

---

## Author & Project Synergy

**Usman Masthan**  
*Cyber Security & Security Operations Engineer*  
- **GitHub**: [@usman-masthan](https://github.com/usman-masthan)
- **Primary Project Synergy**:
  - [`secure-web-vapt-lab`](https://github.com/usman-masthan/secure-web-vapt-lab): Application security, vulnerability assessment, manual HTTP validation, false-positive elimination, and SecOps automation tooling.
  - [`explainable-netflow-ids`](https://github.com/usman-masthan/explainable-netflow-ids): Network flow telemetry, big-data manipulation, machine learning intrusion detection, and explainable AI insights for Security Fusion Centres.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.