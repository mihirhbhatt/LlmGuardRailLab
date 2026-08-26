"""Shared guard verdict types (the Allow/Block boxes on the slide)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    SANITIZE = "SANITIZE"
    ESCALATE = "ESCALATE"


@dataclass
class Finding:
    """One rule/classifier hit inside a guard."""
    category: str          # e.g. "encoded_prompt", "unsafe_link"
    rule: str              # short machine name of the rule
    detail: str            # human-readable explanation
    severity: str = "high" # low | medium | high
    evidence: str = ""     # the offending snippet (truncated)


@dataclass
class GuardResult:
    guard_name: str                       # "AI Guard (Input)" / "AI Guard (Output)"
    verdict: Verdict
    findings: list[Finding] = field(default_factory=list)
    latency_ms: float = 0.0
    ml_verdict: str | None = None         # raw Llama Guard output, if used
    sanitized_text: str | None = None     # rewritten safe output for SANITIZE verdicts

    @property
    def blocked(self) -> bool:
        return self.verdict in (Verdict.BLOCK, Verdict.ESCALATE)

    def summary(self) -> str:
        if not self.findings:
            return "clean"
        return "; ".join(f"[{f.category}] {f.detail}" for f in self.findings)
