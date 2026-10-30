from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException

from backend.llm import explain_findings
from backend.scanner import (
    PROJECT_ROOT,
    SAMPLE_DIR,
    scan_sample,
    scan_project,
    get_scan_root,
)
from backend.remediator import remediate_sample
from backend.git_workflow import remediate_on_branch
from backend.normalizer import normalize_report

app = FastAPI(
    title="Air-Gapped Security Remediator — Day 1 MVP",
    version="0.1.0",
    description="Local demo: Bandit findings plus local Ollama explanation.",
)


@app.get("/health")
def health():
    return {"status": "ok", "mode": "local-demo"}


@app.get("/scan")
def scan():
    try:
        return scan_sample()
    except (RuntimeError, TimeoutError) as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

@app.get("/scan/project")
def scan_configured_project():
    try:
        return scan_project(get_scan_root())
    except (RuntimeError, TimeoutError, OSError) as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc


@app.post("/analyze")
def analyze():
    try:
        scan_report = scan_sample()
        source_path = SAMPLE_DIR / "vulnerable.py"
        source = source_path.read_text(encoding="utf-8")
        analysis = explain_findings(scan_report, source)
        return {"scan": scan_report, "ai_review": analysis}
    except (RuntimeError, TimeoutError, OSError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

@app.post("/remediate")
def remediate():
    try:
        return remediate_sample()
    except (RuntimeError, TimeoutError, OSError) as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        ) from exc

@app.post("/remediate/git")
def remediate_git():
    try:
        return remediate_on_branch()
    except (RuntimeError, TimeoutError, OSError, ValueError) as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc

@app.get("/scan/normalized")
def scan_normalized():
    try:
        raw_report = scan_project(get_scan_root())
        return normalize_report(raw_report)
    except (RuntimeError, TimeoutError, OSError) as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc