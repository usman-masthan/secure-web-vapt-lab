# ZAP Passive Scan Findings

## Assessment Information

- Target: `http://127.0.0.1:3000`
- Application: OWASP Juice Shop
- Environment: Local Docker container
- Scan type: Passive browsing
- Active scan performed: No
- Validation status: Pending manual review

## Findings Inventory

## Findings Inventory

| ID      | ZAP Alert                                   | Instances | Risk          | Confidence | Validation Status | Initial Interpretation                                         |
| :------ | :------------------------------------------ | --------: | :------------ | :--------- | :---------------- | :------------------------------------------------------------- |
| ZAP-001 | Content Security Policy (CSP) Header Not Set| 3         | Medium        | High       | Pending           | Missing CSP header leaves site open to XSS and injection attacks |
| ZAP-002 | Cross-Domain Misconfiguration               | Systemic  | Medium        | Medium     | Pending           | Overly permissive CORS settings require origin-restriction review |
| ZAP-003 | Missing Anti-clickjacking Header            | 2         | Medium        | Medium     | Pending           | Missing X-Frame-Options or CSP frame-ancestors directive      |
| ZAP-004 | Session ID in URL Rewrite                   | Systemic  | Medium        | High       | Pending           | Sensitive session tokens exposed in URL parameters and logs    |
| ZAP-005 | Private IP Disclosure                       | 1         | Low           | Medium     | Pending           | Internal IP leaked in headers or response body (typical in lab) |
| ZAP-006 | Strict-Transport-Security Header Not Set    | 16        | Low           | High       | Pending           | Target serving HTTP without forcing HTTPS via HSTS header      |
| ZAP-007 | Timestamp Disclosure - Unix                 | Systemic  | Low           | Low        | Pending           | Unix timestamps found in responses; low risk info leakage      |
| ZAP-008 | X-Content-Type-Options Header Missing       | 4         | Low           | Medium     | Pending           | Missing nosniff directive allows browsers to MIME-sniff        |
| ZAP-009 | Modern Web Application                      | 1         | Informational | Medium     | Pending           | Informational tag indicating AJAX/SPA architecture for scanner |
| ZAP-010 | Re-examine Cache-control Directives         | 1         | Informational | Low        | Pending           | Potential sensitive responses cached by browser/shared proxies |

## Important Note

Scanner alerts are treated as potential findings. Each alert must be manually reviewed before it is classified as confirmed, rejected or informational.
