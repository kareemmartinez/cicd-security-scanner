"""tests/test_security_scanner.py"""
import sys, os, tempfile, textwrap
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from security_scanner import SecurityScanner, evaluate_gate
from pathlib import Path


def make_temp_file(content, suffix=".py"):
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    tmp.write(textwrap.dedent(content))
    tmp.flush()
    return Path(tmp.name)


def test_detects_hardcoded_password():
    f = make_temp_file('password = "supersecret123"\n')
    scanner  = SecurityScanner(scan_path=f.parent)
    findings = scanner.scan()
    matches  = [x for x in findings if "password" in x["description"].lower()]
    assert len(matches) >= 1
    f.unlink()


def test_detects_aws_access_key():
    f = make_temp_file('key = "AKIAIOSFODNN7EXAMPLE"\n')
    scanner  = SecurityScanner(scan_path=f.parent)
    findings = scanner.scan()
    matches  = [x for x in findings if "AWS" in x["description"]]
    assert len(matches) >= 1
    f.unlink()


def test_detects_eval():
    f = make_temp_file('result = eval(user_input)\n')
    scanner  = SecurityScanner(scan_path=f.parent)
    findings = scanner.scan()
    matches  = [x for x in findings if "eval" in x["description"]]
    assert len(matches) >= 1
    f.unlink()


def test_clean_file_has_no_findings():
    f = make_temp_file('def add(a, b):\n    return a + b\n')
    scanner  = SecurityScanner(scan_path=f.parent)
    findings = scanner.scan()
    py_findings = [x for x in findings if x["file"].endswith(f.name.split("/")[-1])]
    assert len(py_findings) == 0
    f.unlink()


def test_secret_values_are_redacted():
    f = make_temp_file('api_key = "my-super-secret-api-key-12345"\n')
    scanner = SecurityScanner(scan_path=f.parent)
    scanner.scan()
    for finding in scanner.findings:
        assert "my-super-secret-api-key-12345" not in finding.get("snippet", "")
    f.unlink()


def test_gate_passes_with_no_findings():
    assert evaluate_gate([]) == 0


def test_gate_fails_with_critical():
    findings = [{"severity": "CRITICAL", "type": "SECRET", "description": "test"}]
    assert evaluate_gate(findings) == 1


def test_gate_passes_with_only_medium():
    findings = [{"severity": "MEDIUM", "type": "CODE_RISK", "description": "test"}]
    assert evaluate_gate(findings) == 0
