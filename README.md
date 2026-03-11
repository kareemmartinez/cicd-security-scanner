# CI/CD Pipeline Security Scanner

A Python-based static analysis tool that scans source code for security vulnerabilities before deployment. Designed to run as a **GitHub Actions step** — automatically blocking deploys when critical issues are detected.

---

## What It Detects

### Secrets and Credentials
- Hardcoded passwords, API keys, tokens, secrets
- AWS Access Key IDs
- Private keys embedded in source code
- SMTP passwords

### Dangerous Code Patterns
- eval() and exec() — arbitrary code execution risk
- subprocess with shell=True — command injection risk
- pickle.load() — unsafe deserialization
- yaml.load() without safe loader
- Weak hash functions (MD5, SHA-1)
- Non-cryptographic random module for security purposes
- SSL verification disabled
- Debug mode enabled in production

---

## Quick Start
```bash
git clone https://github.com/YOUR_USERNAME/cicd-security-scanner.git
cd cicd-security-scanner

# Scan current directory
python src/security_scanner.py .

# Scan and save JSON report
python src/security_scanner.py . --json
```

---

## CI/CD Gate

The scanner returns exit code 1 when CRITICAL issues are found,
which automatically fails the GitHub Actions pipeline:
```yaml
- name: Security Scan
  run: python src/security_scanner.py . --json
```

---

## Sample Output
```
=================================================================
  SECURITY SCAN RESULTS
=================================================================
  Files Scanned : 12
  Total Issues  : 3
  CRITICAL      : 1
  HIGH          : 1
  MEDIUM        : 1
=================================================================

  FINDINGS:

  [CRITICAL] SECRET — Hardcoded API key
             File: src/config.py (line 14)
             Code: api_key = "[REDACTED]"

  CRITICAL issues found — BLOCKING DEPLOYMENT.
=================================================================
```

Note: Secret values are always redacted in reports.

---

## Running Tests
```bash
pip install pytest
python -m pytest tests/ -v
```

8 unit tests covering detection accuracy, false negative prevention,
redaction, and gate logic.

---

## Project Structure
```
cicd-security-scanner/
├── src/
│   └── security_scanner.py  # Core scanner and CLI
├── tests/
│   └── test_security_scanner.py
├── sample_output/           # Reports saved here (git-ignored)
├── .github/
│   └── workflows/
│       └── ci.yml
├── .gitignore
└── README.md
```

---

## Skills Demonstrated

- Regular expressions for security pattern matching
- Recursive file system traversal with pathlib
- CI/CD pipeline integration via GitHub Actions
- Exit code based pipeline gating
- Security conscious output with secret redaction
- Argparse CLI interface

---

## Roadmap

- [ ] Baseline flag to suppress known accepted findings
- [ ] Sarif output for GitHub Security tab integration
- [ ] Dependency vulnerability check via pip-audit
- [ ] Docker image for use in any CI/CD platform

---

## Author

**Kareem Martinez** | Cybersecurity Professional | DOE Q Clearance
Pursuing: CCSP · CISSP · AWS Certified Cloud Practitioner
