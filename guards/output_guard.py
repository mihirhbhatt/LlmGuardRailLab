"""AI Guard — OUTPUT guardrails (right red box on the slide).

Scans the model's response before it reaches the user:
  1. Unsafe Links               — raw-IP URLs, shorteners, punycode, sketchy TLDs
  2. Malicious Code             — reverse shells, wipers, fork bombs, download cradles
  3. Agentic Tool Definitions   — leaked tool/function schemas or system prompt
  4. (optional) Llama Guard 3 ML classification via Ollama
"""

from __future__ import annotations

import re
import time

import config
from .base import Finding, GuardResult, Verdict
from . import llama_guard
from .content_safety_policy import find_content_safety_hits

_URL_RE = re.compile(r"https?://[^\s)\]}>\"']+", re.IGNORECASE)

_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc",
}
_SKETCHY_TLDS = (".zip", ".mov", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz")

_MALICIOUS_CODE = [
    (r"rm\s+-rf\s+(/|\$HOME|~)(\s|$|;)", "recursive filesystem wipe (rm -rf /)"),
    (r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;?\s*:", "bash fork bomb"),
    (r"\bmkfs(\.\w+)?\s+/dev/", "disk format command"),
    (r"\bdd\s+if=/dev/(zero|random|urandom)\s+of=/dev/[a-z]", "raw-disk overwrite"),
    (r"bash\s+-i\s+>&\s*/dev/tcp/", "bash reverse shell"),
    (r"\bnc(\.exe)?\s+(-[a-z]*e[a-z]*\s+)\S*(sh|cmd|bash|powershell)", "netcat reverse shell"),
    (r"python[23]?\s+-c\s+['\"]import\s+socket.{0,80}subprocess", "python reverse shell"),
    (r"(curl|wget)\s+[^\n|;]+\|\s*(sudo\s+)?(bash|sh|python)", "pipe-to-shell download cradle"),
    (r"powershell[^\n]*(-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}|downloadstring|iex\s*\()",
     "PowerShell download cradle / encoded command"),
    (r"\beval\s*\(\s*(base64_decode|atob|gzinflate|str_rot13)\s*\(", "obfuscated eval payload"),
    (r"\bexec\s*\(\s*__import__\s*\(\s*['\"]os['\"]", "python os-exec smuggling"),
    (r"(vssadmin\s+delete\s+shadows|bcdedit\s+/set\s+\{default\}|cipher\s+/w:)",
     "ransomware-style destructive command"),
    (r"\bdel\s+/[sq]\s+/[sq]?\s*[a-z]:\\\\?", "windows recursive delete"),
    (r"document\.cookie\s*.{0,40}(fetch|xhr|http)", "cookie-exfiltration javascript"),
]

# Signs the model is dumping its internal tool/function schemas
_TOOL_LEAK = [
    (r"\"(name|tool_name)\"\s*:\s*\"[\w.-]+\"\s*,\s*\"(description|parameters|input_schema)\"",
     "JSON tool/function schema in response"),
    (r"\"type\"\s*:\s*\"function\"\s*,\s*\"function\"\s*:", "OpenAI-style tool definition"),
    (r"\binput_schema\b.{0,60}\bproperties\b", "tool input_schema dump"),
    (r"(here\s+(are|is)|these\s+are)\s+(the\s+)?(my\s+)?(available\s+|internal\s+)?tools?\s+"
     r"(i|the\s+agent)\s+(have|has)\s+access\s+to.{0,200}(schema|parameters|json)",
     "narrated tool-inventory disclosure"),
    (r"(i\s+have\s+access\s+to\s+the\s+following\s+tools?|here\s+are\s+the\s+tools?\s+(i|the\s+agent)\s+(can|have|has)\s+use|list\s+the\s+tools?\s+you\s+have\s+access\s+to)"
     r".{0,200}(schema|json|parameters)",
     "tool inventory disclosure with schema hints"),
    (r"tools?\s+(with|and)\s+(their|the)\s+.*(json|schema)", "tool schema inventory disclosure"),
    (r"my\s+system\s+prompt\s+(is|says|reads)\s*[:\"']", "system-prompt disclosure"),
]

def _check_url(url: str) -> str | None:
    """Return a reason string if the URL looks unsafe, else None."""
    m = re.match(r"https?://([^/:\s]+)", url, re.IGNORECASE)
    if not m:
        return None
    host = m.group(1).lower()

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        return "raw IP address URL"
    if host in _SHORTENERS or any(host.endswith("." + s) for s in _SHORTENERS):
        return "link shortener (destination hidden)"
    if host.startswith("xn--") or ".xn--" in host:
        return "punycode/IDN homograph domain"
    if any(host.endswith(tld) for tld in _SKETCHY_TLDS):
        return f"high-risk TLD ({host.rsplit('.', 1)[-1]})"
    if url.lower().startswith("http://") and re.search(
            r"(login|signin|account|password|bank|verify|wallet)", url, re.IGNORECASE):
        return "credential page over plain HTTP"
    if re.search(r"@", host):
        return "userinfo-obfuscated URL"
    return None


class OutputGuard:
    """Rules + optional ML output guardrail. Returns ALLOW or BLOCK."""

    name = "AI Guard (Output)"

    def __init__(self, use_ml: bool = config.USE_ML_GUARD):
        self.use_ml = use_ml

    def check(self, response: str) -> GuardResult:
        t0 = time.perf_counter()
        findings: list[Finding] = []

        # 1) Unsafe links
        for url in _URL_RE.findall(response):
            reason = _check_url(url)
            if reason:
                findings.append(Finding(
                    category="unsafe_link", rule="url_heuristics",
                    detail=reason, evidence=url[:100],
                ))

        # 2) Malicious code
        for pattern, why in _MALICIOUS_CODE:
            m = re.search(pattern, response, re.IGNORECASE)
            if m:
                findings.append(Finding(
                    category="malicious_code", rule=pattern[:30],
                    detail=why, evidence=m.group(0)[:100],
                ))

        # 3) Agentic tool-definition leaks
        for pattern, why in _TOOL_LEAK:
            m = re.search(pattern, response, re.IGNORECASE | re.DOTALL)
            if m:
                findings.append(Finding(
                    category="tool_definition_leak", rule=pattern[:30],
                    detail=why, evidence=m.group(0)[:100],
                ))

        # 4) Content-safety violations in the response
        for hit in find_content_safety_hits(response):
            findings.append(Finding(
                category=hit["category"],
                rule=hit["pattern"][:30],
                detail=hit["reason"],
                evidence=hit["evidence"],
                severity=hit["severity"],
            ))

        # 5) Optional ML layer
        ml_verdict = None
        if self.use_ml:
            safe, label = llama_guard.classify(response, role="assistant")
            ml_verdict = label
            if not safe:
                findings.append(Finding(
                    category="ml_moderation", rule="llama_guard3",
                    detail=f"Llama Guard 3 flagged response: {label}",
                ))

        blocked = bool(findings)
        return GuardResult(
            guard_name=self.name,
            verdict=Verdict.BLOCK if blocked else Verdict.ALLOW,
            findings=findings,
            latency_ms=(time.perf_counter() - t0) * 1000,
            ml_verdict=ml_verdict,
        )
