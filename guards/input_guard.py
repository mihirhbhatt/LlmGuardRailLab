"""AI Guard — INPUT guardrails (left red box on the slide).

Detects, before the prompt ever reaches the model:
  1. Encoded Prompts            — base64 / hex / ROT13 / URL-encoded payloads
  2. Excessive Agency Attempts  — jailbreaks, privilege grants, persona escapes
  3. Zero-Day-style Injections  — prompt-injection markers, system-prompt exfil
  4. (optional) Llama Guard 3 ML classification via Ollama
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import time
import urllib.parse

import config
from .base import Finding, GuardResult, Verdict
from . import llama_guard
from .content_safety_policy import find_content_safety_hits

# ── Suspicious phrases we look for INSIDE decoded payloads ───────────────
_INJECTION_WORDS = re.compile(
    r"(ignore|disregard|override|bypass|jailbreak|system prompt|"
    r"instructions|reveal|exfiltrate|sudo|admin|no restrictions)",
    re.IGNORECASE,
)

# ── Excessive agency / jailbreak patterns ─────────────────────────────────
_EXCESSIVE_AGENCY = [
    (r"\bignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)\b",
     "attempts to override prior instructions"),
    (r"\byou\s+(are\s+now|have\s+become)\s+(DAN|unrestricted|free|jailbroken)\b",
     "DAN-style persona jailbreak"),
    (r"\byou\s+(have|are\s+under)\s+no\s+(restrictions|rules|guidelines|filters|limitations)\b",
     "claims the model has no restrictions"),
    (r"\b(developer|god|admin|root|sudo)\s+mode\b",
     "privilege-escalation persona request"),
    (r"\bpretend\s+(you\s+)?(are|to\s+be)\s+(an?\s+)?(ai|model|assistant)\s+without\b",
     "role-play escape from safety constraints"),
    (r"\b(grant|give)\s+(yourself|the\s+agent)\s+.{0,40}(access|permission|tool|capabilit)",
     "attempts to grant the agent new permissions/tools"),
    (r"\bact\s+as\s+if\s+you\s+can\s+(execute|run|access)\b",
     "coerces the agent into claiming new capabilities"),
    (r"\bdo\s+anything\s+now\b", "DAN jailbreak phrase"),
]

# ── Zero-day / prompt-injection exploit patterns ─────────────────────────
_INJECTION_PATTERNS = [
    (r"(reveal|show|print|repeat|output)\s+(me\s+)?(your|the)\s+(system\s+prompt|initial\s+instructions|hidden\s+instructions)",
     "system-prompt exfiltration attempt"),
    (r"<\|?(im_start|im_end|system|endoftext)\|?>",
     "special-token smuggling (chat-template escape)"),
    (r"\[/?(INST|SYS|SYSTEM)\]", "instruction-tag smuggling"),
    (r"###\s*(system|instruction)\s*:", "fake system-header injection"),
    (r"\bnew\s+system\s+(prompt|message|instruction)\s*:", "system-message spoofing"),
    (r"\b(above|previous)\s+(text|content)\s+(is|was)\s+(a\s+)?(test|joke|fake)\b",
     "context-nullification injection"),
    (r"\bBEGIN\s+(ADMIN|SYSTEM|PRIVILEGED)\b", "privileged-block injection"),
    (r"(delete|remove|wipe|destroy|erase)(s|d)?\s+(every|all)\s+(file|data|record)s?\b",
     "destructive-action request"),
    (r"\brm\s+-rf\s+[/~]", "destructive shell command in prompt"),
]

_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")
_HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){10,}\b")
_MOSTLY_PRINTABLE = re.compile(r"^[\x20-\x7e\s]+$")


def _looks_like_text(s: str) -> bool:
    if not s or not _MOSTLY_PRINTABLE.match(s):
        return False
    letters = sum(c.isalpha() for c in s)
    return letters >= config.MIN_DECODED_ALPHA_LEN


def _decode_candidates(text: str) -> list[tuple[str, str, str]]:
    """Yield (encoding, original_blob, decoded_text) for decodable payloads."""
    out: list[tuple[str, str, str]] = []

    for blob in _B64_RE.findall(text):
        try:
            pad = blob + "=" * (-len(blob) % 4)
            decoded = base64.b64decode(pad, validate=True).decode("utf-8", "strict")
            if _looks_like_text(decoded):
                out.append(("base64", blob, decoded))
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass

    for blob in _HEX_RE.findall(text):
        try:
            decoded = bytes.fromhex(blob).decode("utf-8", "strict")
            if _looks_like_text(decoded):
                out.append(("hex", blob, decoded))
        except (ValueError, UnicodeDecodeError):
            pass

    # ROT13 — only meaningful if it turns gibberish into injection words
    rot = codecs.decode(text, "rot13")
    if _INJECTION_WORDS.search(rot) and not _INJECTION_WORDS.search(text):
        out.append(("rot13", text[:60], rot))

    # URL-encoding
    if "%" in text:
        unq = urllib.parse.unquote(text)
        if unq != text and _INJECTION_WORDS.search(unq) and not _INJECTION_WORDS.search(text):
            out.append(("url-encoding", text[:60], unq))

    return out


class InputGuard:
    """Rules + optional ML input guardrail. Returns ALLOW or BLOCK."""

    name = "AI Guard (Input)"

    def __init__(self, use_ml: bool = config.USE_ML_GUARD):
        self.use_ml = use_ml

    def check(self, prompt: str) -> GuardResult:
        t0 = time.perf_counter()
        findings: list[Finding] = []

        # 1) Encoded prompts
        for enc, blob, decoded in _decode_candidates(prompt):
            suspicious = bool(_INJECTION_WORDS.search(decoded))
            findings.append(Finding(
                category="encoded_prompt",
                rule=f"{enc}_payload",
                detail=(f"{enc} payload decodes to "
                        f"{'suspicious instructions' if suspicious else 'hidden text'}"),
                severity="high" if suspicious else "medium",
                evidence=f"{blob[:40]}… → “{decoded[:60]}”",
            ))

        # 2) Excessive agency
        for pattern, why in _EXCESSIVE_AGENCY:
            m = re.search(pattern, prompt, re.IGNORECASE)
            if m:
                findings.append(Finding(
                    category="excessive_agency", rule=pattern[:30],
                    detail=why, evidence=m.group(0)[:80],
                ))

        # 3) Zero-day-style injections
        for pattern, why in _INJECTION_PATTERNS:
            m = re.search(pattern, prompt, re.IGNORECASE)
            if m:
                findings.append(Finding(
                    category="prompt_injection", rule=pattern[:30],
                    detail=why, evidence=m.group(0)[:80],
                ))

        # 4) Content-safety violations (hate, self-harm, sexual, violence)
        for hit in find_content_safety_hits(prompt):
            findings.append(Finding(
                category=hit["category"],
                rule=hit["pattern"][:30],
                detail=hit["reason"],
                evidence=hit["evidence"],
                severity=hit["severity"],
            ))

        # 5) Optional ML layer (Llama Guard 3 via Ollama)
        ml_verdict = None
        if self.use_ml:
            safe, label = llama_guard.classify(prompt, role="user")
            ml_verdict = label
            if not safe:
                findings.append(Finding(
                    category="ml_moderation", rule="llama_guard3",
                    detail=f"Llama Guard 3 flagged prompt: {label}",
                ))

        blocked = any(f.severity in ("high", "medium") for f in findings)
        return GuardResult(
            guard_name=self.name,
            verdict=Verdict.BLOCK if blocked else Verdict.ALLOW,
            findings=findings,
            latency_ms=(time.perf_counter() - t0) * 1000,
            ml_verdict=ml_verdict,
        )
