from backend.normalizer import normalize_finding, normalize_report


def test_normalizes_bandit_finding():
    result = normalize_finding({
        "test_id": "B602",
        "test_name": "subprocess_popen_with_shell_equals_true",
        "severity": "HIGH",
        "confidence": "HIGH",
        "message": "shell=True identified",
        "file": "backend/example.py",
        "line": 4,
    })

    assert result["rule_id"] == "B602"
    assert result["severity"] == "HIGH"
    assert result["remediation_status"] == "manual_review_required"
    assert result["id"]


def test_prioritizes_high_severity():
    report = {
        "scanner": "Bandit",
        "findings": [
            {
                "test_id": "B404",
                "severity": "LOW",
                "file": "example.py",
                "line": 1,
            },
            {
                "test_id": "B602",
                "severity": "HIGH",
                "file": "example.py",
                "line": 4,
            },
        ],
    }

    result = normalize_report(report)

    assert result["findings"][0]["rule_id"] == "B602"
    assert result["severity_summary"]["HIGH"] == 1
    assert result["severity_summary"]["LOW"] == 1


def test_finding_id_is_stable():
    finding = {
        "test_id": "B602",
        "file": "example.py",
        "line": 4,
    }

    first = normalize_finding(finding)
    second = normalize_finding(finding)

    assert first["id"] == second["id"]
