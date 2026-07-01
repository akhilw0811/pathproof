import os
import sys
import types
import unittest
from unittest.mock import patch

from pathproof_agent.openai_adapter import generate_grounded_wording


class OpenAIAdapterTest(unittest.TestCase):
    def test_fallback_when_not_enabled_or_no_key(self):
        data = {"proposals": [{"rule_id": "PP-K8S-001", "finding_id": "finding:example", "action": "NarrowBindingSubject"}]}
        with patch.dict(os.environ, {}, clear=True):
            disabled = generate_grounded_wording(data, enabled=False, model="example-model")
            enabled_without_key = generate_grounded_wording(data, enabled=True, model="example-model")

        self.assertEqual(disabled, enabled_without_key)
        self.assertEqual(disabled["source"], "deterministic_fallback")
        self.assertIn("PP-K8S-001", disabled["title"])
        self.assertIn("Deterministic PathProof rules", disabled["body"])

    def test_openai_note_keeps_deterministic_body(self):
        data = {"proposals": [{"rule_id": "PP-K8S-001", "finding_id": "finding:example", "action": "NarrowBindingSubject"}]}
        fake_openai = fake_openai_module("PathProof verified 1 finding and prepared the deterministic remediation plan below.")

        with patch.dict(sys.modules, {"openai": fake_openai}), patch.dict(os.environ, {}, clear=True):
            result = generate_grounded_wording(data, enabled=True, model="example-model", api_key="test-key")

        self.assertEqual(result["source"], "openai")
        self.assertIn("PP-K8S-001 finding:example", result["body"])
        self.assertIn("NarrowBindingSubject", result["body"])
        self.assertIn("OpenAI wording note", result["body"])

    def test_openai_hallucinated_note_falls_back(self):
        data = {"proposals": [{"rule_id": "PP-K8S-001", "finding_id": "finding:example", "action": "NarrowBindingSubject"}]}
        fake_openai = fake_openai_module("Delete admin credentials for PP-XDOMAIN-004 and rotate the token.")

        with patch.dict(sys.modules, {"openai": fake_openai}), patch.dict(os.environ, {}, clear=True):
            result = generate_grounded_wording(data, enabled=True, model="example-model", api_key="test-key")

        self.assertEqual(result["source"], "deterministic_fallback")
        self.assertIn("PP-K8S-001 finding:example", result["body"])
        self.assertNotIn("Delete admin credentials", result["body"])


def fake_openai_module(output_text):
    class FakeResponses:
        def create(self, model, input):
            return types.SimpleNamespace(output_text=output_text)

    class FakeClient:
        def __init__(self, api_key):
            self.responses = FakeResponses()

    return types.SimpleNamespace(OpenAI=FakeClient)


if __name__ == "__main__":
    unittest.main()
