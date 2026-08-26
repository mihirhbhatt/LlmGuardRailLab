"""Action guardrails for model-requested tool execution."""

from __future__ import annotations

import time

from .base import Finding, GuardResult, Verdict


class ActionGuard:
    """Enforces tool allowlists, schema checks, and escalation for risky actions."""

    name = "AI Guard (Action)"

    def __init__(self):
        self._allowed_tools = {
            "calculator": {"required": {"expression"}, "max_len": 200},
            "current_time": {"required": set(), "max_len": 0},
            "get_weather": {"required": {"city"}, "max_len": 120},
        }
        self._escalation_tool_tokens = (
            "execute",
            "shell",
            "command",
            "sql",
            "drop",
            "delete",
            "db",
        )

    def check_tool_call(self, name: str, args: dict) -> GuardResult:
        t0 = time.perf_counter()
        findings: list[Finding] = []
        tool = self._allowed_tools.get(name)
        if tool is None:
            lowered = name.lower()
            verdict = Verdict.BLOCK
            if any(token in lowered for token in self._escalation_tool_tokens):
                verdict = Verdict.ESCALATE
            findings.append(
                Finding(
                    category="tool_not_allowlisted",
                    rule="tool_allowlist",
                    detail=f"tool '{name}' is not approved",
                    severity="high",
                    evidence=name[:100],
                )
            )
            return GuardResult(
                guard_name=self.name,
                verdict=verdict,
                findings=findings,
                latency_ms=(time.perf_counter() - t0) * 1000,
            )

        required = tool["required"]
        missing = [field for field in required if field not in args]
        if missing:
            findings.append(
                Finding(
                    category="tool_schema_violation",
                    rule="required_arguments",
                    detail=f"missing required argument(s): {', '.join(missing)}",
                    severity="high",
                    evidence=str(args)[:100],
                )
            )

        for key, value in args.items():
            if isinstance(value, str) and tool["max_len"] and len(value) > tool["max_len"]:
                findings.append(
                    Finding(
                        category="tool_schema_violation",
                        rule="argument_bounds",
                        detail=f"argument '{key}' exceeds max length",
                        severity="high",
                        evidence=value[:100],
                    )
                )
            if isinstance(value, (dict, list)):
                findings.append(
                    Finding(
                        category="tool_schema_violation",
                        rule="argument_type",
                        detail=f"argument '{key}' must be scalar",
                        severity="high",
                        evidence=str(value)[:100],
                    )
                )

        verdict = Verdict.BLOCK if findings else Verdict.ALLOW
        return GuardResult(
            guard_name=self.name,
            verdict=verdict,
            findings=findings,
            latency_ms=(time.perf_counter() - t0) * 1000,
        )
