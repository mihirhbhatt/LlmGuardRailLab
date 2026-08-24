"""Demo tools for the agent — the equivalent of tools you'd register with
the AWS Strands SDK. Everything runs locally and is intentionally harmless."""

from __future__ import annotations

import ast
import datetime
import operator
import random

# ── Safe arithmetic evaluator (no eval!) ─────────────────────────────────
_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.Pow: operator.pow, ast.Mod: operator.mod,
    ast.FloorDiv: operator.floordiv, ast.USub: operator.neg, ast.UAdd: operator.pos,
}


def _safe_eval(node):
    if isinstance(node, ast.Expression):
        return _safe_eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_safe_eval(node.left), _safe_eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_safe_eval(node.operand))
    raise ValueError("unsupported expression")


def calculator(expression: str) -> str:
    """Evaluate a basic arithmetic expression."""
    try:
        return str(_safe_eval(ast.parse(expression, mode="eval")))
    except Exception as exc:
        return f"error: {exc}"


def current_time(timezone: str = "local") -> str:
    """Return the current date/time."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S (local)")


def get_weather(city: str) -> str:
    """Fake weather lookup (deterministic per city) — demo tool only."""
    rng = random.Random(city.lower().strip())
    temp = rng.randint(-10, 32)
    cond = rng.choice(["sunny", "cloudy", "rainy", "snowy", "windy", "foggy"])
    return f"{city}: {temp}°C and {cond} (simulated demo data)"


# Ollama tool-calling schemas (OpenAI-compatible format)
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "calculator",
            "description": "Evaluate a basic arithmetic expression, e.g. '2 * (3 + 4)'.",
            "parameters": {
                "type": "object",
                "properties": {"expression": {"type": "string"}},
                "required": ["expression"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "current_time",
            "description": "Get the current local date and time.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get the current weather for a city (demo data).",
            "parameters": {
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"],
            },
        },
    },
]

REGISTRY = {
    "calculator": calculator,
    "current_time": current_time,
    "get_weather": get_weather,
}
