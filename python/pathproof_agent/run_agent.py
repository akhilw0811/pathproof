"""Run the experimental PathProof remediation agent locally."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .graph import OptionalDependencyError, run_workflow


def default_findings_path() -> Path:
    return Path(__file__).resolve().parents[2] / "examples" / "python-agent" / "pathproof_findings.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the experimental PathProof remediation agent")
    parser.add_argument("--findings", default=str(default_findings_path()), help="PathProof JSON report file")
    parser.add_argument("--repo-root", default=".", help="repository root used for dry-run command text")
    parser.add_argument("--scan-root", default="", help="scan root used for dry-run patch preview command text")
    parser.add_argument("--base-branch", default="main")
    parser.add_argument("--repo", default="", help="optional GitHub owner/repo for gh pr create")
    parser.add_argument("--enable-openai-wording", action="store_true")
    parser.add_argument("--openai-model", default="", help="explicit OpenAI model for wording when enabled")
    parser.add_argument("--open-pr", action="store_true", help="explicitly run gh pr create")
    args = parser.parse_args()

    state = {
        "findings_path": args.findings,
        "repo_root": args.repo_root,
        "scan_root": args.scan_root,
        "base_branch": args.base_branch,
        "repo": args.repo,
        "enable_openai_wording": args.enable_openai_wording,
        "openai_model": args.openai_model,
        "open_pr": args.open_pr,
        "dry_run": not args.open_pr,
    }
    try:
        result = run_workflow(state)
    except OptionalDependencyError as exc:
        print(str(exc))
        return 2
    print(json.dumps({"pr": result.get("pr"), "pr_result": result.get("pr_result")}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
