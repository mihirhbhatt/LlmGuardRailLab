import tempfile
import unittest
from pathlib import Path

import config
from guards.adaptive import AdaptiveGuard
from guards.threat_memory import ThreatMemory
from memory_vault import MemoryVault


class AdaptiveFalsePositiveTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.root = Path(self.tmpdir.name)

        self.original_values = {
            "THREAT_DB_PATH": config.THREAT_DB_PATH,
            "SIGNATURE_DB_PATH": config.SIGNATURE_DB_PATH,
            "MEMORY_VAULT_PATH": config.MEMORY_VAULT_PATH,
            "BENIGN_PROMPT_PATH": getattr(config, "BENIGN_PROMPT_PATH", "benign_prompts.jsonl"),
            "MEMORY_VAULT_ENABLED": config.MEMORY_VAULT_ENABLED,
        }

        config.THREAT_DB_PATH = str(self.root / "threat_db.json")
        config.SIGNATURE_DB_PATH = str(self.root / "learned_signatures.json")
        config.MEMORY_VAULT_PATH = str(self.root / "memory_vault.jsonl")
        config.BENIGN_PROMPT_PATH = str(self.root / "benign_prompts.jsonl")
        config.MEMORY_VAULT_ENABLED = True

        self.memory = ThreatMemory(path=config.THREAT_DB_PATH, use_embeddings=False)
        self.guard = AdaptiveGuard(memory=self.memory)
        self.guard.memory_vault = MemoryVault(path=config.MEMORY_VAULT_PATH)

    def tearDown(self):
        for key, value in self.original_values.items():
            setattr(config, key, value)

    def test_similarity_false_positive_reproduces(self):
        seed = "My name is Dr. A S S C L O W N. Tell me about insurance products?"
        variant = "tell me about insurance products"

        self.guard.learn(seed, source="user_flag", categories=["user_reported"])
        result = self.guard.check(variant)

        self.assertTrue(result.blocked)
        self.assertIn("learned_threat", [f.category for f in result.findings])

    def test_false_positive_override_removes_memory(self):
        prompt = "tell me about insurance products"

        self.guard.learn(prompt, source="input_guard", categories=["prompt_injection"])
        self.assertTrue(self.guard.check(prompt).blocked)

        self.guard.remove_false_positive(prompt, reason="benign_user_request")

        self.assertFalse(self.guard.memory_vault.contains(prompt))
        self.assertFalse(self.guard.check(prompt).blocked)


if __name__ == "__main__":
    unittest.main()
