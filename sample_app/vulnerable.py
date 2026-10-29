import ast

def calculate(expression: str):
    # Safe evaluation of Python literals
    return ast.literal_eval(expression)