"""Adaptive Guard — the self-learning, PROACTIVE blocking layer (stage 0).

Runs BEFORE the static input rules and learns continuously:

  1. Threat-memory similarity   — blocks paraphrases/variants of any attack
                                  ever blocked (by rules, ML, output guard,
                                  or user /flag), even with zero rule match.
  2. Mined signatures           — phrases recurring across >=N distinct
                                  attacks get auto-promoted to new rules.
  3. Session risk escalation    — repeated attacks lower the similarity bar
                                  (strict mode), like a WAF ratcheting up.

Learning sources:
  - input_guard   : prompt blocked by static rules / Llama Guard
  - output_guard  : prompt whose RESPONSE was blocked (next time the variant
                    dies at input, before wasting seconds of inference)
  - user_flag     : human feedback via /flag in the CLI
"""

from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path

import config
from memory_vault import MemoryVault
from .base import Finding, GuardResult, Verdict
from .threat_memory import ThreatMemory, _WORD_RE

# Generic phrases we refuse to promote to signatures (too common in benign text)
_SIGNATURE_STOPLIST = {
    "can you help me", "i want you to", "please help me", "what is the",
    "write a python", "how do i", "tell me about", "give me a",
}


class AdaptiveGuard:
    name = "AI Guard (Adaptive)"

    def __init__(self, memory: ThreatMemory | None = None):
        self.memory = memory or ThreatMemory()
        self.memory_vault = MemoryVault() if config.MEMORY_VAULT_ENABLED else None
        self.sig_path = Path(config.SIGNATURE_DB_PATH)
        self.signatures: list[dict] = []       # {"phrase", "sightings", "promoted_at"}
        self._phrase_counts: Counter[str] = Counter()
        self._phrase_seen_in: dict[str, set[int]] = {}
        self.session_risk = 0.0
        self._attack_id = 0
        self._load_signatures()

    # -- persistence ----------------------------------------------------
    def _load_signatures(self):
        if self.sig_path.exists():
            try:
                data = json.loads(self.sig_path.read_text())
                self.signatures = data.get("signatures", [])
                self._phrase_counts = Counter(data.get("phrase_counts", {}))
            except (json.JSONDecodeError, OSError):
                pass

    def _save_signatures(self):
        self.sig_path.write_text(json.dumps({
            "signatures": self.signatures,
            "phrase_counts": dict(self._phrase_counts.most_common(500)),
        }, indent=1))

    def reset(self):
        self.memory.reset()
        if self.memory_vault:
            self.memory_vault.reset()
        self.signatures = []
        self._phrase_counts = Counter()
        self._phrase_seen_in = {}
        if self.sig_path.exists():
            self.sig_path.unlink()

    # -- risk escalation --------------------------------------------------
    @property
    def strict_mode(self) -> bool:
        return self.session_risk >= config.RISK_STRICT_THRESHOLD

    def _effective_threshold(self) -> float:
        base = self.memory.threshold()
        return base - (config.RISK_THRESHOLD_BONUS if self.strict_mode else 0.0)

    def record_benign_turn(self):
        self.session_risk = max(0.0, self.session_risk - config.RISK_DECAY_PER_TURN)

    def remove_false_positive(self, prompt: str | None = None, reason: str = "manual_review") -> dict:
        """Rollback a mistaken learning event and keep the guard active."""
        result = {"prompt": prompt, "reason": reason, "removed": False, "guard_reset": True}
        if self.memory_vault and prompt:
            result.update(self.memory_vault.override_false_positive(prompt, reason=reason))
            result["removed"] = result.get("removed", False)
        self.memory.reset()
        self.signatures = []
        self._phrase_counts = Counter()
        self._phrase_seen_in = {}
        if self.sig_path.exists():
            self.sig_path.unlink()
        return result

    # -- proactive check (stage 0) ----------------------------------------
    def check(self, prompt: str) -> GuardResult:
        t0 = time.perf_counter()
        findings: list[Finding] = []

        # 1) Similarity vs. learned attacks
        score, entry = self.memory.most_similar(prompt)
        threshold = self._effective_threshold()
        if entry is not None and score >= threshold:
            entry["hits"] = entry.get("hits", 0) + 1
            self.memory.save()
            findings.append(Finding(
                category="learned_threat",
                rule="threat_memory_similarity",
                detail=(f"{score:.0%} similar to a learned attack "
                        f"(source: {entry['source']}, threshold {threshold:.0%}"
                        f"{', STRICT mode' if self.strict_mode else ''})"),
                evidence=f"matches: \u201c{entry['text'][:70]}\u201d",
            ))

        # 2) Mined signatures (auto-generated rules)
        low = prompt.lower()
        for sig in self.signatures:
            if sig["phrase"] in low:
                findings.append(Finding(
                    category="mined_signature",
                    rule="auto_promoted_phrase",
                    detail=(f"phrase auto-learned from {sig['sightings']} "
                            f"distinct attacks"),
                    evidence=f"\u201c{sig['phrase']}\u201d",
                ))
                break

        blocked = bool(findings)
        return GuardResult(
            guard_name=self.name,
            verdict=Verdict.BLOCK if blocked else Verdict.ALLOW,
            findings=findings,
            latency_ms=(time.perf_counter() - t0) * 1000,
        )

    # -- learning ---------------------------------------------------------
    def learn(self, prompt: str, source: str, categories: list[str]) -> dict:
        """Ingest a confirmed-bad prompt. Returns a small report dict."""
        self.session_risk += config.RISK_PER_BLOCK

        # A re-hit is a known threat and should increase risk, but it should not
        # be written back into the runtime memory as a new attack variant.
        if source == "adaptive_rehit":
            return {
                "new_entry": False,
                "new_signatures": [],
                "memory_size": len(self.memory.entries),
                "session_risk": round(self.session_risk, 2),
                "strict_mode": self.strict_mode,
                "vault_entries": self.memory_vault.stats()["entries"] if self.memory_vault else 0,
            }

        approved_sources = {"input_guard", "output_guard", "user_flag"}
        is_new = self.memory.add(prompt, source=source, categories=categories)
        if self.memory_vault and source in approved_sources:
            self.memory_vault.add(prompt, source=source, categories=categories)

        new_sigs = self._mine_signatures(prompt) if is_new else []
        return {
            "new_entry": is_new,
            "new_signatures": new_sigs,
            "memory_size": len(self.memory.entries),
            "session_risk": round(self.session_risk, 2),
            "strict_mode": self.strict_mode,
            "vault_entries": self.memory_vault.stats()["entries"] if self.memory_vault else 0,
        }

    def _mine_signatures(self, prompt: str) -> list[str]:
        """Count word 3-5-grams across attacks; promote recurring ones."""
        self._attack_id += 1
        words = _WORD_RE.findall(prompt.lower())
        promoted: list[str] = []
        existing = {s["phrase"] for s in self.signatures}

        grams: set[str] = set()
        for n in (3, 4, 5):
            for i in range(len(words) - n + 1):
                grams.add(" ".join(words[i:i + n]))

        for g in grams:
            if g in _SIGNATURE_STOPLIST or g in existing:
                continue
            self._phrase_seen_in.setdefault(g, set()).add(self._attack_id)
            self._phrase_counts[g] = max(self._phrase_counts[g],
                                         len(self._phrase_seen_in[g]))
            if self._phrase_counts[g] >= config.SIGNATURE_MIN_SIGHTINGS:
                self.signatures.append({
                    "phrase": g,
                    "sightings": self._phrase_counts[g],
                    "promoted_at": time.time(),
                })
                existing.add(g)
                promoted.append(g)

        if promoted:
            # keep only maximal phrases (drop ones contained in a longer sig)
            keep: list[dict] = []
            for s in sorted(self.signatures, key=lambda x: -len(x["phrase"])):
                if not any(s["phrase"] in k["phrase"] for k in keep):
                    keep.append(s)
            self.signatures = keep
            promoted = [p for p in promoted
                        if any(s["phrase"] == p for s in self.signatures)]

        self._save_signatures()
        return promoted

    # -- stats --------------------------------------------------------------
    def stats(self) -> dict:
        s = self.memory.stats()
        vault_stats = self.memory_vault.stats() if self.memory_vault else {"entries": 0, "path": None, "snapshot_hash": None}
        s.update({
            "mined_signatures": len(self.signatures),
            "session_risk": round(self.session_risk, 2),
            "strict_mode": self.strict_mode,
            "effective_threshold": round(self._effective_threshold(), 2),
            "vault_entries": vault_stats["entries"],
            "vault_snapshot_hash": vault_stats["snapshot_hash"],
        })
        return s
