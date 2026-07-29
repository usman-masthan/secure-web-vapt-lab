# Development Environment

## System

- Operating system: macOS
- Architecture: x86_64
- Testing environment: Local Docker container
- Target exposure: Localhost only

## Verified Tools

| Tool | Version | Status |
|---|---:|---|
| Python | 3.11.9 | Working |
| Docker | 28.5.1 | Working |
| Git | 2.50.1 | Working |
| Nmap | 7.99 | Working |
| OWASP ZAP | Installed | Working |
| Java used by ZAP | 17.0.17 | Working |

## Verification Commands

```bash
python --version
docker --version
git --version
nmap --version
docker ps --filter name=juice-shop
curl -I http://127.0.0.1:3000
