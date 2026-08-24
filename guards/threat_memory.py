"""Threat memory — persistent, similarity-searchable store of known attacks.

Every blocked prompt is vectorized and stored in threat_db.json. New prompts
are compared against the store; close matches are blocked PROACTIVELY, before
static rules, ML moderation, or inference ever run.

Vectorization strategy:
  1. Preferred: real embeddings from Ollama (config.EMBED_MODEL,
     e.g. `nomic-embed-text` — pull with `ollama pull nomic-embed-text`).
  2. Fallback (no Ollama / no embed model): a local bag-of-features vector
     (word unigrams + char trigrams), so the lab self-learns even offline.
"""

from __future__ import annotations

import json
import math
import re
import time
from collections import Counter
from pathlib import Path

import requests

import config

_WORD_RE = re.compile(r"[a-z0-9']+")


def _fallback_features(text: str) -> dict[str, float]:
    """Word unigrams + char trigrams, sublinear-weighted."""
    t = text.lower()
    words = _WORD_RE.findall(t)
    feats: Counter[str] = Counter(f"w:{w}" for w in words)
    squashed = re.sub(r"\s+", " ", t)
    feats.update(f"c:{squashed[i:i+3]}" for i in range(len(squashed) - 2))
    return {k: 1.0 + math.log(v) for k, v in feats.items()}


def _cosine_sparse(a: dict[str, float], b: dict[str, float]) -> float:
    if not a or not b:
        return 0.0
    if len(b) < len(a):
        a, b = b, a
    dot = sum(v * b[k] for k, v in a.items() if k in b)
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


def _cosine_dense(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


class ThreatMemory:
    """Persistent vector store of learned attack prompts."""

    def __init__(self, path: str | Path = None, use_embeddings: bool = True):
        self.path = Path(path or config.THREAT_DB_PATH)
        self.use_embeddings = use_embeddings
        self._embed_available: bool | None = None  # unknown until first try
        self.entries: list[dict] = []
        self._load()

    # ── persistence ───────────────────────────────────────────────────
    def _load(self):
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text())
                self.entries = data.get("entries", [])
            except (json.JSONDecodeError, OSError):
                self.entries = []

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"entries": self.entries}, indent=1))

    def reset(self):
        self.entries = []
        if self.path.exists():
            self.path.unlink()

    # ── embeddings ────────────────────────────────────────────────────
    def _embed(self, text: str) -> list[float] | None:
        if not self.use_embeddings or self._embed_available is False:
            return None
        try:
            resp = requests.post(
                f"{config.OLLAMA_URL}/api/embed",
                json={"model": config.EMBED_MODEL, "input": text},
                timeout=30,
            )
            resp.raise_for_status()
            vec = resp.json()["embeddings"][0]
            self._embed_available = True
            return vec
        except Exception:
            self._embed_available = False  # don't retry every call
            return None

    @property
    def backend(self) -> str:
        if self._embed_available:
            return f"embeddings ({config.EMBED_MODEL})"
        if self._embed_available is False:
            return "n-gram fallback (no embed model)"
        return "auto"

    # ── core API ──────────────────────────────────────────────────────
    def add(self, text: str, source: str, categories: list[str]) -> bool:
        """Learn an attack. Returns False if a near-duplicate already exists."""
        score, entry = self.most_similar(text)
        if entry is not None and score >= 0.95:
            entry["hits"] = entry.get("hits", 0) + 1
            entry["last_seen"] = time.time()
            self.save()
            return False

        self.entries.append({
            "text": text[:500],
            "vec": self._embed(text),
            "feats": _fallback_features(text),
            "source": source,                 # input_guard | output_guard | user_flag
            "categories": categories,
            "learned_at": time.time(),
            "hits": 0,
        })
        self.save()
        return True

    def most_similar(self, text: str) -> tuple[float, dict | None]:
        """Return (best_score, best_entry). Scores are cosine similarity."""
        if not self.entries:
            return 0.0, None

        qvec = self._embed(text)
        qfeats = _fallback_features(text) if qvec is None else None

        best_score, best_entry = 0.0, None
        for e in self.entries:
            if qvec is not None and e.get("vec"):
                s = _cosine_dense(qvec, e["vec"])
            else:
                qf = qfeats if qfeats is not None else _fallback_features(text)
                s = _cosine_sparse(qf, e.get("feats") or _fallback_features(e["text"]))
            if s > best_score:
                best_score, best_entry = s, e
        return best_score, best_entry

    def threshold(self) -> float:
        """Similarity threshold depends on vector quality."""
        return (config.SIM_THRESHOLD_EMBED if self._embed_available
                else config.SIM_THRESHOLD_FALLBACK)

    def stats(self) -> dict:
        by_source: Counter[str] = Counter(e["source"] for e in self.entries)
        return {
            "entries": len(self.entries),
            "by_source": dict(by_source),
            "total_proactive_hits": sum(e.get("hits", 0) for e in self.entries),
            "backend": self.backend,
        }
