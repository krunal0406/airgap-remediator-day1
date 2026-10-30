
from __future__ import annotations

import json
import os
import subprocess
import sys

from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_DIR = PROJECT_ROOT / "sample_app"

EXCLUDED_DIRECTORIES = [
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "node_modules",
    "dist",
    "build",
    ".idea",
    ".vscode",
]


def get_scan_root() -> Path:
    """Get the configured scan directory, defaulting to sample_app."""
    configured_path = os.environ.get("SCAN_ROOT")

    root = (
        Path(configured_path).expanduser()
        if configured_path
        else SAMPLE_DIR
    )

    try:
        root = root.resolve(strict=True)
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"Configured scan directory does not exist: {root}"
        ) from exc

    if not root.is_dir():
        raise RuntimeError(
            f"Configured scan path is not a directory: {root}"
        )

    return root


def scan_project(project_dir: Optional[Path] = None) -> dict[str, Any]:
    """Recursively scan a configured Python project using Bandit."""

    root = (
        project_dir.expanduser().resolve(strict=True)
        if project_dir is not None
        else get_scan_root()
    )

    if not root.is_dir():
        raise RuntimeError(f"Scan target is not a directory: {root}")

    exclusions = ",".join(EXCLUDED_DIRECTORIES)

    command = [
        sys.executable,
        "-m",
        "bandit",
        "-r",
        str(root),
        "-x",
        exclusions,
        "-f",
        "json",
        "-q",
    ]

    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": "",
            "HOME": os.environ.get("HOME", ""),
        },
    )

    try:
        report = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Bandit did not return valid JSON. "
            f"Exit code: {result.returncode}. "
            f"stderr: {result.stderr[:1000]}"
        ) from exc

    findings = []

    for item in report.get("results", []):
        filename = Path(item.get("filename", ""))

        try:
            relative_file = str(filename.resolve().relative_to(root))
        except (ValueError, OSError):
            relative_file = filename.name

        findings.append({
            "test_id": item.get("test_id"),
            "test_name": item.get("test_name"),
            "severity": item.get("issue_severity"),
            "confidence": item.get("issue_confidence"),
            "message": item.get("issue_text"),
            "file": relative_file,
            "line": item.get("line_number"),
            "code": item.get("code", "")[:1200],
        })

    return {
        "scanner": "Bandit",
        "scan_root": str(root),
        "scanner_exit_code": result.returncode,
        "finding_count": len(findings),
        "findings": findings,
    }


def scan_sample() -> dict[str, Any]:
    """Backward-compatible wrapper for the original demo."""
    return scan_project(SAMPLE_DIR)
