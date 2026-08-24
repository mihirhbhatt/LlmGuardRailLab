from __future__ import annotations

import json
import re
from pathlib import Path

_DEFAULT_POLICY: dict[str, list[dict[str, str]]] = {
    "hate_fairness": [
        {
            "pattern": r"\b(hate|hatred|slur|dehumanize|dehumanise|inferior|subhuman|segregat|exclud(e|ion))\b.*\b(race|religion|ethnicity|nationality|gender|immigrant|minority|tribe|sexual orientation)\b",
            "reason": "hate or discriminatory targeting",
            "severity": "high",
        },
        {
            "pattern": r"\b(white power|supremacist|racial purity|segregate.*people|should be excluded because of)\b",
            "reason": "explicit supremacist or exclusionary ideology",
            "severity": "high",
        },
    ],
    "self_harm": [
        {
            "pattern": r"\b(kill myself|kill yourself|end my life|end your life|hurt myself|hurt yourself|cut myself|cut yourself|self-harm|self harm|suicide|overdose|take pills to die|jump off)\b",
            "reason": "self-harm or suicide encouragement",
            "severity": "high",
        },
        {
            "pattern": r"\b(should die|life is not worth living|not worth living)\b",
            "reason": "suicide-normalizing language",
            "severity": "high",
        },
    ],
    "sexual_content": [
        {
            "pattern": r"\b(explicit sexual|graphic sexual|erotic|porn|nude|naked|sexual roleplay|sex scene|adult content)\b",
            "reason": "sexual content request",
            "severity": "medium",
        },
        {
            "pattern": r"\b(undress|seduce|sexualized|fetish)\b",
            "reason": "sexualized content generation",
            "severity": "medium",
        },
    ],
    "violence": [
        {
            "pattern": r"\b(kill|murder|assassinate|stab|shoot|bomb|attack|strangle|blow up|execute someone)\b",
            "reason": "violent harm instruction",
            "severity": "high",
        },
        {
            "pattern": r"\b(violent threat|attack plan|hurt someone|cause physical harm)\b",
            "reason": "violence facilitation",
            "severity": "high",
        },
    ],
    "system_manipulation": [
        {
            "pattern": r"\b(ignore|disregard|override|bypass)\s+(all\s+|any\s+)?(safety|policy|content|moderation|guardrails?|restrictions?|rules?)\b",
            "reason": "safety-policy override attempt",
            "severity": "high",
        },
        {
            "pattern": r"\b(reveal|show|print|output)\s+(hidden|private|system|internal)\s+(prompt|instructions?|policy|rules?)\b",
            "reason": "internal policy or hidden-instruction disclosure",
            "severity": "high",
        },
        {
            "pattern": r"\b(jailbreak|prompt injection|prompt smuggling|system prompt bypass)\b",
            "reason": "prompt or system manipulation",
            "severity": "high",
        },
    ],
}


def _load_policy() -> dict[str, list[dict[str, str]]]:
    policy_path = Path(__file__).with_name("content_safety_policy.json")
    if policy_path.exists():
        try:
            with policy_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict) and data:
                return data
        except (OSError, json.JSONDecodeError):
            pass
    return _DEFAULT_POLICY


CONTENT_SAFETY_RULES: dict[str, list[dict[str, str]]] = _load_policy()


def find_content_safety_hits(text: str) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for category, rules in CONTENT_SAFETY_RULES.items():
        for rule in rules:
            match = re.search(rule["pattern"], text, re.IGNORECASE)
            if match:
                hits.append(
                    {
                        "category": category,
                        "pattern": rule["pattern"],
                        "reason": rule["reason"],
                        "severity": rule.get("severity", "medium"),
                        "evidence": match.group(0)[:80],
                    }
                )
    return hits
