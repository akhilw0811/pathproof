from pathlib import Path
import unittest

from pathproof_agent.graph import OptionalDependencyError, run_workflow


try:
    import langgraph  # noqa: F401
except ImportError:
    LANGGRAPH_AVAILABLE = False
else:
    LANGGRAPH_AVAILABLE = True


@unittest.skipUnless(LANGGRAPH_AVAILABLE, "langgraph is not installed")
class GraphFlowTest(unittest.TestCase):
    def test_flow_produces_dry_run_pr_summary(self):
        fixture = Path(__file__).resolve().parents[3] / "examples" / "python-agent" / "pathproof_findings.json"
        try:
            result = run_workflow({"findings_path": str(fixture), "dry_run": True, "repo_root": "."})
        except OptionalDependencyError as exc:
            self.skipTest(str(exc))

        self.assertEqual(len(result["supported_findings"]), 1)
        self.assertEqual(len(result["proposals"]), 1)
        self.assertEqual(result["patch_plan"]["mode"], "dry-run")
        self.assertEqual(result["validation"]["mode"], "dry-run")
        self.assertFalse(result["pr_result"]["opened"])
        self.assertIn("PP-K8S-001", result["pr"]["title"])
        self.assertEqual(result["pr"]["wording_source"], "deterministic_fallback")


if __name__ == "__main__":
    unittest.main()
