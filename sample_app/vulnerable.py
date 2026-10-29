"""Intentionally vulnerable demo code. Never use this pattern in production."""

def calculate(expression: str):
    # Vulnerability: eval() can execute arbitrary Python expressions.
    return eval(expression)
