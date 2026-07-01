import copy
import unittest

from pathproof_ranking.features import (
    FEATURE_NAMES,
    extract_feature_dict,
    extract_feature_rows,
    finding_from_record,
    load_dataset,
)


class FeatureExtractionTest(unittest.TestCase):
    def test_fixture_feature_extraction(self):
        records = load_dataset()
        finding_ids, rows, labels = extract_feature_rows(records)

        self.assertEqual(len(records), 9)
        self.assertEqual(len(rows), 9)
        self.assertEqual(len(labels), 9)
        self.assertEqual(len(rows[0]), len(FEATURE_NAMES))
        self.assertEqual(finding_ids[0], "finding:PP-K8S-001:synthetic-public-secret")

        features = extract_feature_dict(finding_from_record(records[0]))
        self.assertEqual(features["public_exposure"], 1)
        self.assertEqual(features["kubernetes_secret_access"], 1)
        self.assertEqual(features["patch_available"], 1)

        sensitive_s3 = extract_feature_dict(finding_from_record(records[-1]))
        self.assertEqual(sensitive_s3["oidc_role_assumption"], 1)
        self.assertEqual(sensitive_s3["s3_access"], 1)
        self.assertEqual(sensitive_s3["sensitive_resource"], 1)
        self.assertGreaterEqual(sensitive_s3["cross_domain_boundary_count"], 1)

    def test_feature_extraction_does_not_parse_prose_or_evidence(self):
        finding = finding_from_record(load_dataset()[1])
        before = extract_feature_dict(finding)

        modified = copy.deepcopy(finding)
        modified["summary"] = "Misleading prose says PP-XDOMAIN-004 sensitive S3 admin path."
        modified["evidence"] = [
            {
                "detail": "Misleading evidence prose says public Secret and OIDC admin access.",
                "source": "relative/path.yaml#document=1",
            }
        ]

        self.assertEqual(extract_feature_dict(modified), before)

    def test_feature_order_is_deterministic(self):
        records = load_dataset()
        self.assertEqual(extract_feature_rows(records), extract_feature_rows(records))


if __name__ == "__main__":
    unittest.main()
