from __future__ import annotations

import hashlib
from typing import Any


SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def normalize_finding(item: dict[str, Any]) -> dict[str, Any]:
    """Convert a raw Bandit finding into a common security finding."""

    rule_id = str(item.get("test_id") or "UNKNOWN")
    file_path = str(item.get("file") or "unknown")
    line = int(item.get("line") or 0)

    identity = f"{rule_id}:{file_path}:{line}"
    finding_id = hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()[:16]

    severity = str(item.get("severity") or "INFO").upper()
    if severity not in SEVERITY_RANK:
        severity = "INFO"

    remediation_status = (
        "manual_review_required"
        if rule_id == "B602"
        else "not_supported"
    )

    return {
        "id": finding_id,
        "rule_id": rule_id,
        "title": item.get("test_name") or rule_id,
        "severity": severity,
        "severity_rank": SEVERITY_RANK[severity],
        "confidence": str(item.get("confidence") or "UNDEFINED").upper(),
        "message": item.get("message") or "",
        "file": file_path,
        "line": line,
        "source": "Bandit",
        "remediation_status": remediation_status,
        "code": item.get("code") or "",
    }


def normalize_report(report: dict[str, Any]) -> dict[str, Any]:
    """Normalize, prioritize, and summarize a scanner report."""

    findings = [
        normalize_finding(item)
        for item in report.get("findings", [])
    ]

    findings.sort(
        key=lambda item: (
            -item["severity_rank"],
            item["file"],
            item["line"],
        )
    )

    summary = {
        severity: sum(
            1 for item in findings
            if item["severity"] == severity
        )
        for severity in SEVERITY_RANK
    }

    return {
        "scanner": report.get("scanner", "Unknown"),
        "scan_root": report.get("scan_root"),
        "total_findings": len(findings),
        "severity_summary": summary,
        "findings": findings,
    }
