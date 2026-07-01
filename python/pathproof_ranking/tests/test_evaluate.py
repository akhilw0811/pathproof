import unittest

from pathproof_ranking.evaluate import evaluate_dataset


try:
    import sklearn  # noqa: F401
except ImportError:
    SKLEARN_AVAILABLE = False
else:
    SKLEARN_AVAILABLE = True


@unittest.skipUnless(SKLEARN_AVAILABLE, "scikit-learn is not installed")
class EvaluateTest(unittest.TestCase):
    def test_evaluation_metrics_are_deterministic(self):
        first = evaluate_dataset()
        second = evaluate_dataset()

        self.assertEqual(first, second)
        self.assertEqual(first["records"], 9)
        self.assertEqual(first["positive_labels"], 5)
        self.assertGreaterEqual(first["learned_top_k_recall"], first["severity_top_k_recall"])
        self.assertGreaterEqual(first["learned_pairwise_accuracy"], 0.0)
        self.assertLessEqual(first["learned_pairwise_accuracy"], 1.0)


if __name__ == "__main__":
    unittest.main()
