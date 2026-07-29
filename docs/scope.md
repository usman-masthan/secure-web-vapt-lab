# Authorised Testing Scope

## Project

Secure Web VAPT Lab

## Target

- Application: OWASP Juice Shop
- Address: http://127.0.0.1:3000
- Environment: Local Docker container
- Purpose: Educational vulnerability assessment

## Included Activities

- Local service discovery
- HTTP request and response analysis
- Passive vulnerability scanning
- Controlled active scanning
- Manual validation of selected findings
- Security reporting
- Remediation recommendations

## Excluded Activities

- Public websites
- University systems
- Company systems
- Other devices on the local network
- Denial-of-service testing
- Destructive testing
- Real credentials
- Real personal or financial information

## Rules of Engagement

1. All testing must remain within the local Docker environment.
2. Only dummy accounts and synthetic information may be used.
3. Automated findings must be manually reviewed before being reported.
4. Destructive and availability-impacting tests are prohibited.
5. The application must remain bound to `127.0.0.1`.
6. The Docker container must be stopped when testing is finished.
