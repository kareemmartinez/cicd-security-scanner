"""
security_scanner.py
-------------------
CI/CD Pipeline Security Scanner
Scans source code and config files for common security issues:
hardcoded secrets, insecure dependencies, dangerous patterns.

Author: Kareem Martinez
"""

import os
import re
import json
import datetime
import argparse
from pathlib import Path


SECRET_PATTERNS = [
    (r'(?i)password\s*=\s*["\'][^"\']{4,}["\']',        "Hardcoded password"),
    (r'(?i)api[_-]?key\s*=\s*["\'][^"\']{8,}["\']',     "Hardcoded API key"),
    (r'(?i)secret\s*=\s*["\'][^"\']{4,}["\']',          "Hardcoded secret"),
    (r'(?i)token\s*=\s*["\'][A-Za-z0-9_\-]{16,}["\']',  "Hardcoded token"),
    (r'AKIA[0-9A-Z]{16}',                                "AWS Access Key ID"),
    (r'(?i)private[_-]?key\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded private key"),
    (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',          "Private key in source"),
    (r'(?i)smtp.*password\s*=\s*["\'][^"\']+["\']',      "SMTP password"),
]

DANGER_PATTERNS = [
    (r'\beval\s*\(',                         "Use of eval() — arbitrary code execution risk"),
    (r'\bexec\s*\(',                         "Use of exec() — arbitrary code execution risk"),
    (r'subprocess\.call\(.*shell=True',      "shell=True in subprocess — command injection risk"),
    (r'os\.system\(',                        "os.system() — prefer subprocess with shell=False"),
    (r'pickle\.loads?\(',                    "pickle.load() — unsafe deserialization"),
    (r'yaml\.load\([^,)]*\)',               "yaml.load() without Loader — use yaml.safe_load()"),
    (r'hashlib\.(md5|sha1)\(',              "Weak hash function (MD5/SHA1) — use SHA-256+"),
    (r'random\.(random|randint|choice)\(',  "Non-cryptographic random — use secrets module"),
    (r'verify\s*=\s*False',                 "SSL verification disabled"),
    (r'DEBUG\s*=\s*True',                   "Debug mode enabled — disable in production"),
]

SCANNABLE_EXTENSIONS = {".py", ".js", ".ts", ".env", ".yml", ".yaml", ".json", ".sh", ".tf", ".cfg", ".ini"}
SKIP_PATTERNS        = {".git", "__pycache__", "node_modules", "venv", ".egg-info", "dist", "build", "tests"}


class SecurityScanner:
    """
    Scans a directory tree for security issues.
    Generates structured findings for CI/CD gate enforcement.
    """

    def __init__(self, scan_path="."):
        self.scan_path     = Path(scan_path).resolve()
        self.findings      = []
        self.files_scanned = 0

    def _should_skip(self, path):
        return any(skip in path.parts for skip in SKIP_PATTERNS)

    def _scan_file(self, filepath):
        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "<!--")):
                continue

            for pattern, description in SECRET_PATTERNS:
                if re.search(pattern, line):
                    self.findings.append({
                        "type":        "SECRET",
                        "severity":    "CRITICAL",
                        "file":        str(filepath.relative_to(self.scan_path)),
                        "line":        line_num,
                        "description": description,
                        "snippet":     self._redact(line.strip()),
                    })

            for pattern, description in DANGER_PATTERNS:
                if re.search(pattern, line):
                    self.findings.append({
                        "type":        "CODE_RISK",
                        "severity":    "HIGH" if "eval" in description or "exec" in description else "MEDIUM",
                        "file":        str(filepath.relative_to(self.scan_path)),
                        "line":        line_num,
                        "description": description,
                        "snippet":     line.strip()[:120],
                    })

    def _redact(self, line):
        redacted = re.sub(r'(["\'])[^"\']{4,}(["\'])', r'\1[REDACTED]\2', line)
        return redacted[:120]

    def scan(self):
        print(f"[+] Scanning: {self.scan_path}\n")

        for filepath in self.scan_path.rglob("*"):
            if filepath.is_file() and not self._should_skip(filepath):
                if filepath.suffix.lower() in SCANNABLE_EXTENSIONS:
                    self._scan_file(filepath)
                    self.files_scanned += 1

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.findings.sort(key=lambda x: severity_order.get(x["severity"], 4))

        print(f"[+] Scanned {self.files_scanned} files. Found {len(self.findings)} issues.\n")
        return self.findings


def print_report(findings, files_scanned):
    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high     = [f for f in findings if f["severity"] == "HIGH"]
    medium   = [f for f in findings if f["severity"] == "MEDIUM"]

    print("="*65)
    print("  SECURITY SCAN RESULTS")
    print("="*65)
    print(f"  Files Scanned : {files_scanned}")
    print(f"  Total Issues  : {len(findings)}")
    print(f"  CRITICAL      : {len(critical)}")
    print(f"  HIGH          : {len(high)}")
    print(f"  MEDIUM        : {len(medium)}")
    print("="*65)

    if findings:
        print("\n  FINDINGS:\n")
        for f in findings:
            print(f"  [{f['severity']:8}] {f['type']} — {f['description']}")
            print(f"             File: {f['file']} (line {f['line']})")
            print(f"             Code: {f['snippet']}\n")

    if not findings:
        print("\n  All clear — no security issues found.\n")
    elif critical:
        print("\n  CRITICAL issues found — BLOCKING DEPLOYMENT.\n")
    else:
        print("\n  Issues found — review before deploying.\n")

    print("="*65 + "\n")


def save_json_report(findings, files_scanned, output_dir="sample_output"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = os.path.join(output_dir, f"scan_report_{timestamp}.json")
    report = {
        "generated_at":  datetime.datetime.now().isoformat(),
        "files_scanned": files_scanned,
        "total_issues":  len(findings),
        "findings":      findings,
    }
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
    print(f"[+] JSON report saved: {filename}")
    return filename


def evaluate_gate(findings, block_on=("CRITICAL",)):
    blocking = [f for f in findings if f["severity"] in block_on]
    if blocking:
        print(f"[!] CI/CD GATE: FAILED — {len(blocking)} blocking issue(s) found.")
        return 1
    print("[+] CI/CD GATE: PASSED — No blocking issues.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Security Scanner for CI/CD pipelines")
    parser.add_argument("path",   nargs="?", default=".", help="Directory to scan")
    parser.add_argument("--json", action="store_true",    help="Save JSON report")
    args = parser.parse_args()

    scanner   = SecurityScanner(scan_path=args.path)
    findings  = scanner.scan()

    print_report(findings, scanner.files_scanned)

    if args.json:
        save_json_report(findings, scanner.files_scanned)

    exit_code = evaluate_gate(findings)
    exit(exit_code)
