# Roger XSS 🐰

Cross-Site Scripting vulnerability scanner for bug bounty hunting. Tests for XSS in web applications.

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

## License

MIT License