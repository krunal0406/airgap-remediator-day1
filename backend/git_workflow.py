"""Apply a verified remediation on a dedicated local Git branch."""

import subprocess
import tempfile
from pathlib import Path

from backend.remediator import remediate_sample, validate_patch, run_tests, rescan
from backend.scanner import PROJECT_ROOT, SAMPLE_DIR


EXPECTED_BRANCH = "remediation/fix-eval-b307"
TARGET_FILE = SAMPLE_DIR / "vulnerable.py"


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(PROJECT_ROOT), *args],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Git command failed: {' '.join(args)}\n{result.stderr[-1500:]}"
        )
    return result.stdout.strip()


def remediate_on_branch() -> dict:
    """Apply and commit only a verified fix on the expected clean branch."""

    branch = git("branch", "--show-current")
    if branch != EXPECTED_BRANCH:
        raise RuntimeError(
            f"Refusing to modify branch '{branch}'. "
            f"Switch to '{EXPECTED_BRANCH}' first."
        )

    if git("status", "--porcelain"):
        raise RuntimeError(
            "Working tree is not clean. Commit or safely set aside your "
            "changes before running remediation."
        )

    original_bytes = TARGET_FILE.read_bytes()
    original_source = original_bytes.decode("utf-8")

    # Generate and verify the candidate using the existing remediation engine.
    report = remediate_sample()

    if report.get("status") != "verified":
        return {
            "status": "rejected",
            "reason": "The existing remediation engine did not verify the patch.",
            "verification": report,
        }

    replacement = report.get("patch_preview")
    if not isinstance(replacement, str) or not replacement.strip():
        raise RuntimeError("No candidate patch was returned.")

    # Independently validate and test the exact candidate before applying it.
    try:
        validate_patch(replacement)
    except (SyntaxError, ValueError) as exc:
        raise RuntimeError(f"Candidate failed AST validation: {exc}") from exc

    with tempfile.TemporaryDirectory(prefix="git-remediation-") as temp:
        candidate = Path(temp) / "vulnerable.py"
        candidate.write_text(replacement, encoding="utf-8")

        tests = run_tests(candidate)
        candidate_scan = rescan(candidate)

        if not tests["passed"]:
            return {
                "status": "rejected",
                "reason": "Candidate functional tests failed.",
                "functional_tests": tests,
            }

        if any(f["test_id"] == "B307" for f in candidate_scan["findings"]):
            return {
                "status": "rejected",
                "reason": "Bandit still reports B307.",
                "rescan": candidate_scan,
            }

    # Ensure the original file has not changed since we read it.
    if TARGET_FILE.read_bytes() != original_bytes:
        raise RuntimeError("Target changed during remediation; refusing to apply.")

    committed = False
    staged = False

    try:
        TARGET_FILE.write_text(replacement, encoding="utf-8")

        # Re-test and rescan the actual file in the working tree.
        validate_patch(TARGET_FILE.read_text(encoding="utf-8"))
        actual_tests = run_tests(TARGET_FILE)
        actual_scan = rescan(TARGET_FILE)

        if not actual_tests["passed"]:
            raise RuntimeError("Tests failed after applying the candidate.")

        if any(f["test_id"] == "B307" for f in actual_scan["findings"]):
            raise RuntimeError("B307 remains after applying the candidate.")

        git("diff", "--check")
        git("add", "--", str(TARGET_FILE.relative_to(PROJECT_ROOT)))
        staged = True
        git("diff", "--cached", "--check")

        git(
            "commit",
            "-m",
            "fix(security): replace unsafe eval with literal_eval",
        )
        committed = True

        commit_hash = git("rev-parse", "--short", "HEAD")
        diff = git(
            "show",
            "--format=",
            "--no-ext-diff",
            "HEAD",
            "--",
            str(TARGET_FILE.relative_to(PROJECT_ROOT)),
        )

        return {
            "status": "committed",
            "branch": EXPECTED_BRANCH,
            "commit": commit_hash,
            "file": str(TARGET_FILE.relative_to(PROJECT_ROOT)),
            "functional_tests": actual_tests,
            "rescan": actual_scan,
            "diff": diff,
            "master_modified": False,
            "note": (
                "Local demo verification only; review the diff before "
                "opening or merging a pull request."
            ),
        }

    except Exception:
        # Roll back only this target file, and only before a successful commit.
        if not committed:
            TARGET_FILE.write_bytes(original_bytes)
            if staged:
                subprocess.run(
                    [
                        "git", "-C", str(PROJECT_ROOT),
                        "reset", "--",
                        str(TARGET_FILE.relative_to(PROJECT_ROOT)),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
        raise
