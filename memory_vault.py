from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import config


def normalize_prompt(prompt: str) -> str:
    return re.sub(r"\s+", " ", prompt or "").strip().lower()


class MemoryVault:
    """Persistent, approved threat store with dedup + snapshot drift checks."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path or config.MEMORY_VAULT_PATH)
        self.override_path = Path(config.BENIGN_PROMPT_PATH)
        self.entries: list[dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                self.entries = [
                    json.loads(line)
                    for line in fh
                    if line.strip()
                ]
        except (OSError, ValueError, json.JSONDecodeError):
            self.entries = []

    def _write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as fh:
            for entry in self.entries:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")

    @staticmethod
    def _hash(prompt: str) -> str:
        return "sha256:" + hashlib.sha256(prompt.encode("utf-8")).hexdigest()

    def snapshot_hash(self) -> str:
        payload = json.dumps(self.entries, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def reset(self) -> None:
        self.entries = []
        if self.path.exists():
            self.path.unlink()

    def contains(self, prompt: str) -> bool:
        norm = normalize_prompt(prompt)
        digest = self._hash(norm)
        return any(entry.get("hash") == digest for entry in self.entries)

    def add(self, prompt: str, *, source: str, categories: list[str], risk: str = "high") -> bool:
        """Persist only confirmed threat prompts in the trusted vault."""
        if not prompt or not source:
            return False
        norm = normalize_prompt(prompt)
        digest = self._hash(norm)
        if any(entry.get("hash") == digest for entry in self.entries):
            return False

        entry = {
            "hash": digest,
            "normalized_prompt": norm,
            "prompt": prompt[:1000],
            "source": source,
            "categories": categories,
            "risk": risk,
            "approved": True,
            "approved_at": __import__("time").time(),
        }
        self.entries.append(entry)
        self._write()
        return True

    def remove(self, prompt: str) -> bool:
        norm = normalize_prompt(prompt)
        digest = self._hash(norm)
        before = len(self.entries)
        self.entries = [entry for entry in self.entries if entry.get("hash") != digest]
        if len(self.entries) != before:
            self._write()
            return True
        return False

    def override_false_positive(self, prompt: str, reason: str = "manual_review") -> dict[str, Any]:
        """Remove a mistaken threat memory entry and record the benign override separately."""
        norm = normalize_prompt(prompt)
        removed = self.remove(prompt)
        override_entry = {
            "hash": self._hash(norm),
            "normalized_prompt": norm,
            "prompt": prompt[:1000],
            "source": "manual_override",
            "categories": ["false_positive"],
            "risk": "benign",
            "approved": False,
            "reason": reason,
            "overridden_at": __import__("time").time(),
        }
        self.override_path.parent.mkdir(parents=True, exist_ok=True)
        with self.override_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(override_entry, sort_keys=True) + "\n")
        return {"removed": removed, "override": override_entry}

    def stats(self) -> dict[str, Any]:
        return {
            "entries": len(self.entries),
            "path": str(self.path),
            "snapshot_hash": self.snapshot_hash(),
        }
