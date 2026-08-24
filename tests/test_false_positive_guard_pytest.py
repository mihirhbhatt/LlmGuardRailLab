import tempfile
from pathlib import Path

import config
from guards.adaptive import AdaptiveGuard
from guards.threat_memory import ThreatMemory
from memory_vault import MemoryVault


def test_false_positive_similarity_reproduces():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        original = {
            "THREAT_DB_PATH": config.THREAT_DB_PATH,
            "SIGNATURE_DB_PATH": config.SIGNATURE_DB_PATH,
            "MEMORY_VAULT_PATH": config.MEMORY_VAULT_PATH,
            "BENIGN_PROMPT_PATH": getattr(config, "BENIGN_PROMPT_PATH", "benign_prompts.jsonl"),
            "MEMORY_VAULT_ENABLED": config.MEMORY_VAULT_ENABLED,
        }
        try:
            config.THREAT_DB_PATH = str(root / "threat_db.json")
            config.SIGNATURE_DB_PATH = str(root / "learned_signatures.json")
            config.MEMORY_VAULT_PATH = str(root / "memory_vault.jsonl")
            config.BENIGN_PROMPT_PATH = str(root / "benign_prompts.jsonl")
            config.MEMORY_VAULT_ENABLED = True

            memory = ThreatMemory(path=config.THREAT_DB_PATH, use_embeddings=False)
            guard = AdaptiveGuard(memory=memory)
            guard.memory_vault = MemoryVault(path=config.MEMORY_VAULT_PATH)

            seed = "My name is Dr. A S S C L O W N. Tell me about insurance products?"
            variant = "tell me about insurance products"
            guard.learn(seed, source="user_flag", categories=["user_reported"])

            result = guard.check(variant)
            assert result.blocked is True
            assert "learned_threat" in {f.category for f in result.findings}
        finally:
            for key, value in original.items():
                setattr(config, key, value)


def test_false_positive_override_removes_memory():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        original = {
            "THREAT_DB_PATH": config.THREAT_DB_PATH,
            "SIGNATURE_DB_PATH": config.SIGNATURE_DB_PATH,
            "MEMORY_VAULT_PATH": config.MEMORY_VAULT_PATH,
            "BENIGN_PROMPT_PATH": getattr(config, "BENIGN_PROMPT_PATH", "benign_prompts.jsonl"),
            "MEMORY_VAULT_ENABLED": config.MEMORY_VAULT_ENABLED,
        }
        try:
            config.THREAT_DB_PATH = str(root / "threat_db.json")
            config.SIGNATURE_DB_PATH = str(root / "learned_signatures.json")
            config.MEMORY_VAULT_PATH = str(root / "memory_vault.jsonl")
            config.BENIGN_PROMPT_PATH = str(root / "benign_prompts.jsonl")
            config.MEMORY_VAULT_ENABLED = True

            memory = ThreatMemory(path=config.THREAT_DB_PATH, use_embeddings=False)
            guard = AdaptiveGuard(memory=memory)
            guard.memory_vault = MemoryVault(path=config.MEMORY_VAULT_PATH)

            prompt = "tell me about insurance products"
            guard.learn(prompt, source="input_guard", categories=["prompt_injection"])
            assert guard.check(prompt).blocked is True

            override = guard.remove_false_positive(prompt, reason="benign_user_request")
            assert override["removed"] is True
            assert guard.memory_vault.contains(prompt) is False
            assert guard.check(prompt).blocked is False
        finally:
            for key, value in original.items():
                setattr(config, key, value)
