"""Feature extraction for the experimental PathProof priority ranker.

This module consumes PathProof-style structured JSON findings. It intentionally
does not parse raw source files, raw evidence prose, workflow YAML, Terraform,
Kubernetes manifests, or policy JSON. Deterministic PathProof rules remain the
source of truth for whether a finding exists.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


RULE_CATEGORY = {
    "PP-K8S-001": "kubernetes",
    "PP-GHA-001": "github-actions",
    "PP-GHA-002": "github-actions",
    "PP-GHA-003": "github-actions",
    "PP-AWS-001": "aws",
    "PP-XDOMAIN-001": "cross-domain",
    "PP-XDOMAIN-002": "cross-domain",
    "PP-XDOMAIN-003": "cross-domain",
    "PP-XDOMAIN-004": "cross-domain",
}

RULE_SEVERITY = {
    "PP-K8S-001": "High",
    "PP-GHA-001": "Medium",
    "PP-GHA-002": "High",
    "PP-GHA-003": "High",
    "PP-AWS-001": "High",
    "PP-XDOMAIN-001": "High",
    "PP-XDOMAIN-002": "High",
    "PP-XDOMAIN-003": "High",
    "PP-XDOMAIN-004": "High",
}

SEVERITY_SCORE = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0,
    "Informational": 0,
}

NODE_DOMAIN = {
    "PublicEndpoint": "kubernetes",
    "Workload": "kubernetes",
    "ServiceAccount": "kubernetes",
    "Role": "kubernetes",
    "Permission": "kubernetes",
    "Secret": "kubernetes",
    "Workflow": "github-actions",
    "WorkflowJob": "github-actions",
    "GitHubAction": "github-actions",
    "OIDCTokenCapability": "github-actions",
    "AWSIAMRole": "aws",
    "AWSPermission": "aws",
    "AWSS3Bucket": "aws",
}

FEATURE_NAMES = [
    "severity_score",
    "category_kubernetes",
    "category_github_actions",
    "category_aws",
    "category_cross_domain",
    "path_length",
    "cross_domain_boundary_count",
    "public_exposure",
    "pull_request_target_risk",
    "dangerous_token_permissions",
    "oidc_role_assumption",
    "aws_admin_role",
    "s3_access",
    "sensitive_resource",
    "kubernetes_secret_access",
    "baseline_new",
    "baseline_existing",
    "remediation_available",
    "patch_available",
]


def default_fixture_path() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "ranking_dataset.json"


def load_dataset(path: str | Path | None = None) -> list[dict[str, Any]]:
    fixture_path = Path(path) if path is not None else default_fixture_path()
    with fixture_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    records = data.get("records")
    if not isinstance(records, list):
        raise ValueError("ranking dataset must contain a records array")
    return records


def finding_from_record(record: dict[str, Any]) -> dict[str, Any]:
    finding = record.get("finding")
    if not isinstance(finding, dict):
        raise ValueError("ranking dataset record must contain a finding object")
    return finding


def label_from_record(record: dict[str, Any]) -> int:
    label = record.get("priority_label")
    if label not in (0, 1):
        raise ValueError("priority_label must be 0 or 1")
    return int(label)


def extract_feature_dict(finding: dict[str, Any]) -> dict[str, int]:
    rule_id = str(finding.get("rule_id", ""))
    severity = str(finding.get("severity") or RULE_SEVERITY.get(rule_id, ""))
    category = RULE_CATEGORY.get(rule_id, "")
    path = finding.get("path") if isinstance(finding.get("path"), list) else []
    path_kinds = [str(node.get("kind", "")) for node in path if isinstance(node, dict)]
    risk_signal = finding.get("risk_signal") if isinstance(finding.get("risk_signal"), dict) else {}
    risk_rule_id = str(risk_signal.get("rule_id", ""))
    baseline_status = str(finding.get("baseline_status", ""))

    features = {
        "severity_score": SEVERITY_SCORE.get(severity, 0),
        "category_kubernetes": int(category == "kubernetes"),
        "category_github_actions": int(category == "github-actions"),
        "category_aws": int(category == "aws"),
        "category_cross_domain": int(category == "cross-domain"),
        "path_length": len(path_kinds),
        "cross_domain_boundary_count": _cross_domain_boundary_count(path_kinds, category),
        "public_exposure": int(rule_id == "PP-K8S-001" or "PublicEndpoint" in path_kinds),
        "pull_request_target_risk": int(_has_pull_request_target_risk(rule_id, risk_rule_id)),
        "dangerous_token_permissions": int(_has_dangerous_permissions(rule_id, risk_rule_id)),
        "oidc_role_assumption": int(rule_id.startswith("PP-XDOMAIN-") or "OIDCTokenCapability" in path_kinds),
        "aws_admin_role": int(rule_id in {"PP-AWS-001", "PP-XDOMAIN-002"} or "AWSPermission" in path_kinds),
        "s3_access": int(rule_id in {"PP-XDOMAIN-003", "PP-XDOMAIN-004"} or "AWSS3Bucket" in path_kinds),
        "sensitive_resource": int(_has_sensitive_resource(rule_id, path_kinds, finding)),
        "kubernetes_secret_access": int(rule_id == "PP-K8S-001" or "Secret" in path_kinds),
        "baseline_new": int(baseline_status == "new"),
        "baseline_existing": int(baseline_status == "existing"),
        "remediation_available": int(_has_remediation(finding)),
        "patch_available": int(_has_patch_available(finding)),
    }
    return features


def extract_feature_row(finding: dict[str, Any]) -> list[int]:
    features = extract_feature_dict(finding)
    return [features[name] for name in FEATURE_NAMES]


def extract_feature_rows(records: list[dict[str, Any]]) -> tuple[list[str], list[list[int]], list[int]]:
    finding_ids: list[str] = []
    rows: list[list[int]] = []
    labels: list[int] = []
    for record in records:
        finding = finding_from_record(record)
        finding_ids.append(str(finding.get("id", "")))
        rows.append(extract_feature_row(finding))
        labels.append(label_from_record(record))
    return finding_ids, rows, labels


def severity_baseline_scores(records: list[dict[str, Any]]) -> list[int]:
    scores: list[int] = []
    for record in records:
        finding = finding_from_record(record)
        severity = str(finding.get("severity") or RULE_SEVERITY.get(str(finding.get("rule_id", "")), ""))
        scores.append(SEVERITY_SCORE.get(severity, 0))
    return scores


def _cross_domain_boundary_count(path_kinds: list[str], category: str) -> int:
    domains = [NODE_DOMAIN.get(kind, "") for kind in path_kinds]
    count = 0
    for index in range(1, len(domains)):
        if domains[index - 1] and domains[index] and domains[index - 1] != domains[index]:
            count += 1
    if category == "cross-domain" and count == 0:
        return 1
    return count


def _has_pull_request_target_risk(rule_id: str, risk_rule_id: str) -> bool:
    return rule_id in {"PP-GHA-002", "PP-GHA-003"} or risk_rule_id in {"PP-GHA-002", "PP-GHA-003"}


def _has_dangerous_permissions(rule_id: str, risk_rule_id: str) -> bool:
    return rule_id == "PP-GHA-003" or risk_rule_id == "PP-GHA-003"


def _has_sensitive_resource(rule_id: str, path_kinds: list[str], finding: dict[str, Any]) -> bool:
    if rule_id in {"PP-K8S-001", "PP-XDOMAIN-004"}:
        return True
    sensitivity = finding.get("bucket_sensitivity")
    return isinstance(sensitivity, dict) and sensitivity.get("sensitivity_level") == "sensitive"


def _has_remediation(finding: dict[str, Any]) -> bool:
    remediation = finding.get("remediation")
    return isinstance(remediation, dict) and bool(remediation.get("options"))


def _has_patch_available(finding: dict[str, Any]) -> bool:
    remediation = finding.get("remediation")
    if not isinstance(remediation, dict):
        return False
    options = remediation.get("options")
    if not isinstance(options, list):
        return False
    for option in options:
        if not isinstance(option, dict):
            continue
        changes = option.get("changes")
        if isinstance(changes, list):
            for change in changes:
                if isinstance(change, dict) and change.get("patch_supported") is True:
                    return True
        previews = option.get("patch_previews")
        if isinstance(previews, list):
            for preview in previews:
                if isinstance(preview, dict) and preview.get("status") == "generated":
                    return True
    return False
