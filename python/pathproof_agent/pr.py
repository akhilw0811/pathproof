"""Dry-run-first pull request helper for PathProof remediation summaries."""

from __future__ import annotations

import hashlib
import subprocess
from typing import Any, Callable


Runner = Callable[[list[str]], Any]


def branch_name_for_findings(finding_ids: list[str], prefix: str = "pathproof/remediate") -> str:
    cleaned = [finding_id for finding_id in sorted(finding_ids) if finding_id]
    digest = hashlib.sha256("\n".join(cleaned).encode("utf-8")).hexdigest()[:12]
    rule_hint = "findings"
    if cleaned:
        parts = cleaned[0].split(":")
        if len(parts) >= 2 and parts[1]:
            rule_hint = _branch_safe(parts[1].lower())
    return f"{prefix}-{rule_hint}-{digest}"


def pr_title(proposals: list[dict[str, Any]]) -> str:
    if len(proposals) == 1:
        rule_id = proposals[0].get("rule_id", "finding")
        return f"PathProof remediation for {rule_id}"
    if len(proposals) > 1:
        return f"PathProof remediation for {len(proposals)} verified findings"
    return "PathProof remediation plan"


def pr_body(proposals: list[dict[str, Any]], validation: dict[str, Any] | None = None) -> str:
    lines = [
        "This draft was generated from PathProof structured JSON findings.",
        "",
        "Deterministic PathProof rules and graph evidence remain the source of truth.",
        "",
        "Remediation plan:",
    ]
    if not proposals:
        lines.append("- No supported remediation proposals were found in the input report.")
    for proposal in proposals:
        finding_id = proposal.get("finding_id", "")
        rule_id = proposal.get("rule_id", "")
        action = proposal.get("action", "")
        summary = proposal.get("summary", "")
        patch = "patch-supported" if proposal.get("patch_supported") else "plan-only"
        lines.append(f"- {rule_id} {finding_id}: {action} ({patch}). {summary}")
    if validation:
        lines.extend(["", "Validation:"])
        lines.append(f"- Mode: {validation.get('mode', 'dry-run')}")
        if validation.get("summary"):
            lines.append(f"- Summary: {validation['summary']}")
    return "\n".join(lines).strip() + "\n"


def gh_pr_create_args(
    branch: str,
    title: str,
    body: str,
    base: str = "main",
    repo: str | None = None,
    draft: bool = True,
) -> list[str]:
    args = ["gh", "pr", "create", "--base", base, "--head", branch, "--title", title, "--body", body]
    if draft:
        args.append("--draft")
    if repo:
        args.extend(["--repo", repo])
    return args


def prepare_pr(
    proposals: list[dict[str, Any]],
    validation: dict[str, Any] | None = None,
    base: str = "main",
    repo: str | None = None,
) -> dict[str, Any]:
    finding_ids = [str(proposal.get("finding_id", "")) for proposal in proposals]
    branch = branch_name_for_findings(finding_ids)
    title = pr_title(proposals)
    body = pr_body(proposals, validation)
    command = gh_pr_create_args(branch=branch, title=title, body=body, base=base, repo=repo)
    return {
        "branch": branch,
        "title": title,
        "body": body,
        "dry_run_command": command,
    }


def create_pull_request(
    prepared: dict[str, Any],
    open_pr: bool = False,
    runner: Runner | None = None,
) -> dict[str, Any]:
    command = list(prepared.get("dry_run_command", []))
    if not open_pr:
        return {"opened": False, "dry_run": True, "command": command}
    if not command:
        raise ValueError("dry_run_command is required to open a pull request")
    runner = runner or _default_runner
    result = runner(command)
    return {"opened": True, "dry_run": False, "command": command, "result": result}


def _default_runner(command: list[str]) -> dict[str, Any]:
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    return {"stdout": completed.stdout, "stderr": completed.stderr, "returncode": completed.returncode}


def _branch_safe(value: str) -> str:
    out = []
    for char in value:
        if char.isalnum() or char in {"-", "_"}:
            out.append(char)
        else:
            out.append("-")
    cleaned = "".join(out).strip("-")
    return cleaned or "finding"
