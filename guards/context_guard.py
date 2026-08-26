"""Context guardrails for pre-model retrieval/tool context handling."""

from __future__ import annotations

import re
import time
from urllib.parse import urlparse

from .base import Finding, GuardResult, Verdict

_INSTRUCTION_INJECTION = re.compile(
    r"(ignore\s+(all\s+)?previous\s+instructions|"
    r"reveal\s+(the\s+)?system\s+prompt|"
    r"override\s+(security|guardrails?|policy)|"
    r"you\s+are\s+now\s+dan)",
    re.IGNORECASE,
)


class ContextGuard:
    """Applies source trust checks and strips active instruction payloads."""

    name = "AI Guard (Context)"

    def __init__(self, trusted_sources: set[str] | None = None):
        self.trusted_sources = trusted_sources or {"local", "internal"}

    def check(
        self,
        contexts: list[dict[str, str]] | None,
    ) -> tuple[GuardResult, list[dict[str, str]]]:
        t0 = time.perf_counter()
        findings: list[Finding] = []
        cleaned: list[dict[str, str]] = []

        for ctx in contexts or []:
            source = (ctx.get("source") or "unknown").strip().lower()
            content = ctx.get("content", "")
            uri = (ctx.get("uri") or "").strip()
            if source not in self.trusted_sources:
                findings.append(
                    Finding(
                        category="untrusted_context_source",
                        rule="source_allowlist",
                        detail=f"context source '{source}' is not allowlisted",
                        severity="high",
                        evidence=(uri or source)[:100],
                    )
                )
                continue

            if uri:
                host = (urlparse(uri).hostname or "").lower()
                if host and (host.endswith(".zip") or host.startswith("xn--")):
                    findings.append(
                        Finding(
                            category="untrusted_context_source",
                            rule="context_uri_hygiene",
                            detail="context URI failed trust checks",
                            severity="high",
                            evidence=uri[:100],
                        )
                    )
                    continue

            stripped = _INSTRUCTION_INJECTION.sub("[removed-instruction]", content)
            if stripped != content:
                findings.append(
                    Finding(
                        category="context_instruction_stripped",
                        rule="active_instruction_strip",
                        detail="removed active instructions from retrieved context",
                        severity="medium",
                        evidence=content[:100],
                    )
                )
            cleaned.append(
                {
                    "source": source,
                    "content": stripped,
                    "uri": uri,
                }
            )

        verdict = Verdict.BLOCK if any(f.severity == "high" for f in findings) else (
            Verdict.SANITIZE if findings else Verdict.ALLOW
        )
        return (
            GuardResult(
                guard_name=self.name,
                verdict=verdict,
                findings=findings,
                latency_ms=(time.perf_counter() - t0) * 1000,
            ),
            cleaned,
        )
