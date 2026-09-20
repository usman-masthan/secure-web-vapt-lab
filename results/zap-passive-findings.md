# ZAP Passive Scan Findings & Triage Summary

## Assessment Metadata

- **Target Application**: OWASP Juice Shop (v17.1.1)
- **Target URL**: `http://127.0.0.1:3000`
- **Assessment Scope**: Authorized local containerized deployment (`127.0.0.1` binding)
- **Scan Type**: OWASP ZAP 2.15+ Passive Scan & HTTP Proxy Traffic Inspection
- **Scan Date**: 2026-07-29
- **Triage Status**: **Complete (100% Manually Triaged & Validated)**

---

## Triage Metrics Summary

| Metric | Count | Percentage |
| :--- | :--- | :--- |
| **Total Automated Alerts** | 10 | 100% |
| **Confirmed Vulnerabilities (True Positives)** | 3 | 30% |
| **Rejected Scanner False Positives** | 3 | 30% |
| **Environmental / Contextual Findings** | 2 | 20% |
| **Informational Observations** | 2 | 20% |
| **False Positive Elimination Rate** | **30.0%** | (Alert noise eliminated prior to reporting) |

---

## Findings Inventory & Final Triage Classification

| ID | ZAP Alert Name | Instances | Scanner Risk | Final Risk | CVSS v3.1 | Triage Status | Validation Summary |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **ZAP-001** | Content Security Policy (CSP) Header Not Set | 3 | Medium | **Medium** | 5.4 | **Confirmed (True Positive)** | Confirmed complete absence of `Content-Security-Policy`. Allows script injection and DOM-based XSS exploitation. |
| **ZAP-002** | Cross-Domain Misconfiguration | Systemic | Medium | **Medium** | 6.5 | **Confirmed (True Positive)** | Global `Access-Control-Allow-Origin: *` returned across REST API endpoints. Exposes user-specific order and basket data to arbitrary origins. |
| **ZAP-003** | Missing Anti-clickjacking Header | 2 | Medium | **Low (Contextual)** | 3.1 | **Contextual Nuance** | Main framing document (`index.html`) correctly specifies `X-Frame-Options: SAMEORIGIN`. ZAP flagged sub-resource JSON/API responses where framing is not applicable. |
| **ZAP-004** | Session ID in URL Rewrite | Systemic | Medium | **None** | 0.0 | **Rejected (False Positive)** | ZAP misidentified Engine.IO/Socket.IO transport parameter (`sid`) as an auth token. Application uses JWT in `Authorization: Bearer` headers. |
| **ZAP-005** | Private IP Disclosure | 1 | Low | **Low (Contextual)** | 2.6 | **Environmental Nuance** | Internal RFC1918 address disclosed in lab container routing. Normal behavior in local Docker bridging, flagged for production awareness. |
| **ZAP-006** | Strict-Transport-Security Header Not Set | 16 | Low | **Low (Environmental)** | 3.7 | **Environmental Limitation** | Application bound to unencrypted HTTP (`http://127.0.0.1:3000`). RFC 6797 prohibits HSTS over HTTP. Required remediation: TLS termination in production. |
| **ZAP-007** | Timestamp Disclosure - Unix | Systemic | Low | **None** | 0.0 | **Rejected (False Positive)** | High-entropy numeric timestamps in JavaScript bundles and public review timestamps misclassified as sensitive server epoch leaks. |
| **ZAP-008** | X-Content-Type-Options Header Missing | 4 | Low | **Low** | 3.5 | **Confirmed (True Positive)** | Missing `nosniff` directive on certain error and static endpoints, creating potential MIME-type confusion attacks in legacy browsers. |
| **ZAP-009** | Modern Web Application | 1 | Informational | **Info** | N/A | **Informational** | Behavioral indicator confirming client-heavy Single Page Application (SPA) architecture (Angular). |
| **ZAP-010** | Re-examine Cache-control Directives | 1 | Informational | **Info** | N/A | **Informational** | Cache-Control directives allow caching of static assets. Sensitive `/rest/user` responses verified to send proper `no-store` controls. |

---

## Detailed Triage Analysis

### 1. ZAP-001: Content Security Policy (CSP) Header Not Set
- **Scanner Classification**: Medium Risk / High Confidence
- **Triage Result**: **CONFIRMED VULNERABILITY**
- **Technical Analysis**: HTTP response headers across all entry routes (`/`, `/#/`, `/rest/*`) completely lack `Content-Security-Policy`. Without CSP directives (`default-src`, `script-src`), modern browser protections against inline script execution, unauthorized CDN imports, and DOM injection are disabled.
- **Evidence**: Verified via `curl -I http://127.0.0.1:3000/`. No CSP directive present.

### 2. ZAP-002: Cross-Domain Misconfiguration (CORS Wildcard)
- **Scanner Classification**: Medium Risk / Medium Confidence
- **Triage Result**: **CONFIRMED VULNERABILITY**
- **Technical Analysis**: Server responds with `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Methods: GET,HEAD,PUT,PATCH,POST,DELETE`. While unauthenticated static resources can safely use wildcards, sensitive API endpoints (such as search and user data endpoints) inherit this permissive posture, allowing malicious origins to issue read requests.
- **Evidence**:
  ```http
  OPTIONS /rest/products/search HTTP/1.1
  Host: 127.0.0.1:3000
  Origin: https://malicious-domain.com

  HTTP/1.1 204 No Content
  Access-Control-Allow-Origin: *
  ```

### 3. ZAP-003: Missing Anti-clickjacking Header
- **Scanner Classification**: Medium Risk / Medium Confidence
- **Triage Result**: **CONTEXTUAL NUANCE / DOWNGRADED TO LOW**
- **Technical Analysis**: The primary application frame served at `http://127.0.0.1:3000/` returns `X-Frame-Options: SAMEORIGIN`, successfully preventing unauthorized third-party framing of the web application. ZAP generated two alerts against raw API response endpoints (`/assets/i18n/*.json`) which cannot render HTML DOM frames. The risk on the web portal itself is mitigated; however, transitioning to modern `Content-Security-Policy: frame-ancestors 'self'` is recommended.

### 4. ZAP-004: Session ID in URL Rewrite
- **Scanner Classification**: Medium Risk / High Confidence
- **Triage Result**: **REJECTED FALSE POSITIVE**
- **Technical Analysis**: ZAP flagged URLs containing `?EIO=4&transport=polling&t=...&sid=...`. In-depth inspection confirms this parameter is generated by the Engine.IO / Socket.IO transport layer to maintain real-time notification socket state, not application session state. Juice Shop handles user authentication entirely through JSON Web Tokens (JWT) stored in browser storage and transmitted via the `Authorization: Bearer <token>` header. Terminating or hijacking the Socket.IO `sid` does not grant authenticated access to the user account.
- **Decision**: Marked as **False Positive**. Eliminates unnecessary remediation tickets and alert fatigue.

### 5. ZAP-005: Private IP Disclosure
- **Scanner Classification**: Low Risk / Medium Confidence
- **Triage Result**: **ENVIRONMENTAL NUANCE**
- **Technical Analysis**: Local Docker bridge interface (`172.17.0.x`) was observed in diagnostic headers. Expected within an isolated localhost lab environment; marked for verification in enterprise production environments behind reverse proxies.

### 6. ZAP-006: Strict-Transport-Security Header Not Set
- **Scanner Classification**: Low Risk / High Confidence
- **Triage Result**: **ENVIRONMENTAL LIMITATION**
- **Technical Analysis**: Per **RFC 6797 Section 8.1**, user agents must ignore `Strict-Transport-Security` headers received over insecure HTTP transport. The lab environment operates over plain HTTP (`http://127.0.0.1:3000`). Adding HSTS on an HTTP listener would be non-compliant with standard web specifications. In production, TLS must be enforced, and HSTS with `includeSubDomains; preload` enabled.

### 7. ZAP-007: Timestamp Disclosure - Unix
- **Scanner Classification**: Low Risk / Low Confidence
- **Triage Result**: **REJECTED FALSE POSITIVE**
- **Technical Analysis**: ZAP matched 10-digit integers embedded inside compiled Angular JavaScript chunks (`vendor.js`, `main.js`) as Unix epoch timestamps. These numbers represent static build metadata, cache-busting hashes, and public review creation times. None represent internal server clocks or sensitive state.
- **Decision**: Marked as **False Positive**.

### 8. ZAP-008: X-Content-Type-Options Header Missing
- **Scanner Classification**: Low Risk / Medium Confidence
- **Triage Result**: **CONFIRMED VULNERABILITY**
- **Technical Analysis**: Although `index.html` includes `X-Content-Type-Options: nosniff`, certain error handlers and custom routes omit this defensive header, creating a slight risk of MIME-confusion exploitation in older clients.

### 9. ZAP-009: Modern Web Application
- **Scanner Classification**: Informational / Medium Confidence
- **Triage Result**: **INFORMATIONAL**
- **Technical Analysis**: Scanner heuristic identifying asynchronous JavaScript (AJAX / SPA) navigation patterns. Used to tune automated crawler depth.

### 10. ZAP-010: Re-examine Cache-control Directives
- **Scanner Classification**: Informational / Low Confidence
- **Triage Result**: **INFORMATIONAL**
- **Technical Analysis**: Static public frontend bundles have `Cache-Control: public, max-age=0`. Authenticated account APIs (`/rest/user/whoami`) correctly enforce restrictive caching.

---

## Downstream Deliverables

- Detailed manual exploitation and validation evidence: see [manual-validation-report.md](manual-validation-report.md)
- In-depth scanner triage and false positive analysis: see [false-positive-analysis.md](false-positive-analysis.md)
- Retesting methodology and post-remediation verification: see [retesting-report.md](retesting-report.md)
- Executive stakeholder report: see [../docs/executive-summary.md](../docs/executive-summary.md)
