from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_DIR = PROJECT_ROOT / "sample_app"


def scan_sample() -> dict[str, Any]:
    """Scan only the bundled sample_app directory; do not accept arbitrary paths."""
    command = [
        sys.executable, "-m", "bandit",
        "-r", str(SAMPLE_DIR),
        "-f", "json",
        "-q",
    ]
    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env={"PATH": __import__("os").environ.get("PATH", ""), "PYTHONPATH": ""},
    )

    # Bandit commonly exits with code 1 when findings exist. Parse JSON regardless.
    try:
        report = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Bandit did not return valid JSON. "
            f"Exit code: {result.returncode}. stderr: {result.stderr[:1000]}"
        ) from exc

    findings = []
    for item in report.get("results", []):
        findings.append({
            "test_id": item.get("test_id"),
            "test_name": item.get("test_name"),
            "severity": item.get("issue_severity"),
            "confidence": item.get("issue_confidence"),
            "message": item.get("issue_text"),
            "file": Path(item.get("filename", "")).name,
            "line": item.get("line_number"),
            "code": item.get("code", "")[:1200],
        })

    return {
        "scanner": "Bandit",
        "scanner_exit_code": result.returncode,
        "finding_count": len(findings),
        "findings": findings,
    }
