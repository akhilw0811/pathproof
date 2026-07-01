import unittest

from pathproof_agent import pr


class PullRequestHelperTest(unittest.TestCase):
    def test_branch_title_body_are_deterministic(self):
        proposals = [
            {
                "finding_id": "finding:PP-K8S-001:example",
                "rule_id": "PP-K8S-001",
                "action": "NarrowBindingSubject",
                "summary": "Remove the affected ServiceAccount from a multi-subject binding.",
                "patch_supported": True,
            }
        ]

        first = pr.prepare_pr(proposals)
        second = pr.prepare_pr(proposals)

        self.assertEqual(first, second)
        self.assertTrue(first["branch"].startswith("pathproof/remediate-pp-k8s-001-"))
        self.assertEqual(first["title"], "PathProof remediation for PP-K8S-001")
        self.assertIn("Deterministic PathProof rules", first["body"])
        self.assertEqual(first["dry_run_command"][0:3], ["gh", "pr", "create"])

    def test_dry_run_default_does_not_call_runner(self):
        prepared = pr.prepare_pr([])

        def fail_runner(command):
            raise AssertionError(f"runner should not be called: {command}")

        result = pr.create_pull_request(prepared, open_pr=False, runner=fail_runner)

        self.assertFalse(result["opened"])
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["command"], prepared["dry_run_command"])


if __name__ == "__main__":
    unittest.main()
