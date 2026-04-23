# Roger XSS 🐰

[![Python 3.7+](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**Automated Cross-Site Scripting (XSS) vulnerability scanner for bug bounty hunting.**

Tests 30+ XSS payloads including reflected, DOM-based, and filter bypass techniques.

Part of the [Roger Toolkit](https://github.com/jrabbit00/roger-recon) - 14 free security tools for bug bounty hunters.

🔥 **[Get the complete toolkit on Gumroad](https://jrabbit00.gumroad.com)**

## Why XSS?

XSS is one of the most common web vulnerabilities:
- Cookie theft
- Session hijacking
- Keylogging
- Phishing
- Defacement

## Features

- Tests 30+ XSS payloads
- Reflected XSS detection
- Basic filter bypass testing
- DOM-based XSS detection
- Parameter injection

## Installation

```bash
git clone https://github.com/jrabbit00/roger-xss.git
cd roger-xss
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python3 xss.py https://target.com/search?q=test

# Save results
python3 xss.py target.com -o findings.txt
```

## What It Tests

- Basic script injection
- Event handler XSS
- Filter bypasses
- Quote escape XSS
- DOM-based XSS

## Important Notes

- XSS requires browser for full detection
- Manual testing always needed
- Check bug bounty scope first

## 🐰 Part of the Roger Toolkit

| Tool | Purpose |
|------|---------|
| [roger-recon](https://github.com/jrabbit00/roger-recon) | All-in-one recon suite |
| [roger-direnum](https://github.com/jrabbit00/roger-direnum) | Directory enumeration |
| [roger-jsgrab](https://github.com/jrabbit00/roger-jsgrab) | JavaScript analysis |
| [roger-sourcemap](https://github.com/jrabbit00/roger-sourcemap) | Source map extraction |
| [roger-paramfind](https://github.com/jrabbit00/roger-paramfind) | Parameter discovery |
| [roger-wayback](https://github.com/jrabbit00/roger-wayback) | Wayback URL enumeration |
| [roger-cors](https://github.com/jrabbit00/roger-cors) | CORS misconfigurations |
| [roger-jwt](https://github.com/jrabbit00/roger-jwt) | JWT security testing |
| [roger-headers](https://github.com/jrabbit00/roger-headers) | Security header scanner |
| [roger-xss](https://github.com/jrabbit00/roger-xss) | XSS vulnerability scanner |
| [roger-sqli](https://github.com/jrabbit00/roger-sqli) | SQL injection scanner |
| [roger-redirect](https://github.com/jrabbit00/roger-redirect) | Open redirect finder |
| [roger-idor](https://github.com/jrabbit00/roger-idor) | IDOR detection |
| [roger-ssrf](https://github.com/jrabbit00/roger-ssrf) | SSRF vulnerability scanner |

## ☕ Support

If Roger XSS helps you find vulnerabilities, consider [supporting the project](https://github.com/sponsors/jrabbit00)!

## License

MIT License - Created by [J Rabbit](https://github.com/jrabbit00)