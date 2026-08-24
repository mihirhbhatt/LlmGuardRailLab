"""Optional ML moderation layer using Llama Guard 3 served by Ollama.

This is the closest local analog to Trend AI Guard's ML classifier.
Llama Guard 3 is trained to answer with:

    safe
or
    unsafe
    S<number>          (MLCommons hazard category, e.g. S14 = Code Interpreter Abuse)

Pull the model first:   ollama pull llama-guard3:1b
"""

from __future__ import annotations

import requests

import config

HAZARD_CATEGORIES = {
    "S1": "Violent Crimes",
    "S2": "Non-Violent Crimes",
    "S3": "Sex-Related Crimes",
    "S4": "Child Sexual Exploitation",
    "S5": "Defamation",
    "S6": "Specialized Advice",
    "S7": "Privacy",
    "S8": "Intellectual Property",
    "S9": "Indiscriminate Weapons",
    "S10": "Hate",
    "S11": "Suicide & Self-Harm",
    "S12": "Sexual Content",
    "S13": "Elections",
    "S14": "Code Interpreter Abuse",
}


def classify(text: str, role: str = "user") -> tuple[bool, str]:
    """Return (is_safe, raw_label).

    role="user"      -> classify a prompt   (input guardrail)
    role="assistant" -> classify a response (output guardrail)

    Fails open with a warning if the guard model isn't available, so the
    rules-based layer still protects the pipeline.
    """
    try:
        resp = requests.post(
            f"{config.OLLAMA_URL}/api/chat",
            json={
                "model": config.GUARD_MODEL,
                "messages": [{"role": role, "content": text}],
                "stream": False,
                "options": {"temperature": 0.0},
            },
            timeout=config.REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        raw = resp.json()["message"]["content"].strip()
    except Exception as exc:  # model missing / ollama down -> fail open
        return True, f"ml-guard-unavailable ({exc.__class__.__name__})"

    lines = [l.strip() for l in raw.splitlines() if l.strip()]
    if not lines:
        return True, "empty"

    if lines[0].lower().startswith("unsafe"):
        cat = lines[1] if len(lines) > 1 else "?"
        label = HAZARD_CATEGORIES.get(cat.upper(), cat)
        return False, f"unsafe ({cat}: {label})"

    return True, "safe"
