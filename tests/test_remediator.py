import pytest

from backend.remediator import validate_patch, run_tests


SAFE_SOURCE = """
import ast

def calculate(expression):
    return ast.literal_eval(expression)
"""


def test_accepts_expected_safe_patch():
    validate_patch(SAFE_SOURCE)


def test_rejects_eval_patch():
    unsafe_source = """
def calculate(expression):
    return eval(expression)
"""
    with pytest.raises((SyntaxError, ValueError)):
        validate_patch(unsafe_source)


def test_rejects_unexpected_import():
    unsafe_source = """
import os

def calculate(expression):
    return ast.literal_eval(expression)
"""
    with pytest.raises((SyntaxError, ValueError)):
        validate_patch(unsafe_source)


def test_rejects_executable_argument_annotation():
    unsafe_source = """
import ast

def calculate(expression: __import__('os').system('echo SHOULD_NOT_RUN')):
    return ast.literal_eval(expression)
"""
    with pytest.raises((SyntaxError, ValueError)):
        validate_patch(unsafe_source)


def test_safe_candidate_passes_functional_tests(tmp_path):
    candidate = tmp_path / "vulnerable.py"
    candidate.write_text(SAFE_SOURCE, encoding="utf-8")

    validate_patch(SAFE_SOURCE)
    result = run_tests(candidate)

    assert result["passed"], result
