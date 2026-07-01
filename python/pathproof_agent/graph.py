"""LangGraph remediation workflow over PathProof structured JSON reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TypedDict

from . import openai_adapter
from . import pr


class OptionalDependencyError(RuntimeError):
    pass


class AgentState(TypedDict, total=False):
    findings_path: str
    report: dict[str, Any]
    findings: list[dict[str, Any]]
    supported_findings: list[dict[str, Any]]
    proposals: list[dict[str, Any]]
    patch_plan: dict[str, Any]
    validation: dict[str, Any]
    pr: dict[str, Any]
    pr_result: dict[str, Any]
    repo_root: str
    scan_root: str
    base_branch: str
    repo: str
    dry_run: bool
    open_pr: bool
    enable_openai_wording: bool
    openai_model: str


def load_findings(state: AgentState) -> AgentState:
    report = state.get("report")
    if report is None:
        path = state.get("findings_path")
        if not path:
            raise ValueError("findings_path or report is required")
        with Path(path).open("r", encoding="utf-8") as handle:
            report = json.load(handle)
    findings = report.get("findings", []) if isinstance(report, dict) else []
    if not isinstance(findings, list):
        raise ValueError("PathProof report must contain a findings array")
    next_state = dict(state)
    next_state["report"] = report
    next_state["findings"] = [finding for finding in findings if isinstance(finding, dict)]
    return next_state


def select_supported_findings(state: AgentState) -> AgentState:
    supported = []
    for finding in state.get("findings", []):
        remediation = finding.get("remediation")
        if isinstance(remediation, dict) and remediation.get("options"):
            supported.append(finding)
    supported.sort(key=lambda item: str(item.get("id", "")))
    next_state = dict(state)
    next_state["supported_findings"] = supported
    return next_state


def propose_remediation(state: AgentState) -> AgentState:
    proposals = []
    for finding in state.get("supported_findings", []):
        remediation = finding.get("remediation", {})
        options = remediation.get("options", []) if isinstance(remediation, dict) else []
        option = _first_option(options)
        if option is None:
            continue
        changes = option.get("changes", []) if isinstance(option.get("changes"), list) else []
        proposals.append(
            {
                "finding_id": finding.get("id", ""),
                "rule_id": finding.get("rule_id", ""),
                "title": finding.get("title", ""),
                "action": option.get("action", ""),
                "summary": option.get("summary", remediation.get("summary", "")),
                "change_count": len(changes),
                "patch_supported": any(isinstance(change, dict) and change.get("patch_supported") is True for change in changes),
            }
        )
    next_state = dict(state)
    next_state["proposals"] = proposals
    return next_state


def run_patch_preview_or_plan(state: AgentState) -> AgentState:
    scan_root = state.get("scan_root") or state.get("repo_root") or "."
    command = ["pathproof", "scan", "--format", "json", "--preview-patches", scan_root]
    next_state = dict(state)
    next_state["patch_plan"] = {
        "mode": "dry-run",
        "summary": "Prepared local PathProof patch preview command; no patch command was executed.",
        "command": command,
    }
    return next_state


def validate_sandbox_branch_or_dry_run(state: AgentState) -> AgentState:
    proposals = state.get("proposals", [])
    branch = pr.branch_name_for_findings([str(proposal.get("finding_id", "")) for proposal in proposals])
    next_state = dict(state)
    next_state["validation"] = {
        "mode": "dry-run",
        "branch": branch,
        "summary": "Sandbox branch validation was not executed in dry-run mode.",
    }
    return next_state


def prepare_pr_summary(state: AgentState) -> AgentState:
    proposals = state.get("proposals", [])
    prepared = pr.prepare_pr(
        proposals,
        validation=state.get("validation"),
        base=state.get("base_branch", "main"),
        repo=state.get("repo") or None,
    )
    wording = openai_adapter.generate_grounded_wording(
        {"proposals": proposals, "validation": state.get("validation")},
        enabled=bool(state.get("enable_openai_wording", False)),
        model=state.get("openai_model", ""),
    )
    prepared["title"] = wording["title"]
    prepared["body"] = wording["body"]
    prepared["wording_source"] = wording["source"]
    prepared["dry_run_command"] = pr.gh_pr_create_args(
        branch=prepared["branch"],
        title=prepared["title"],
        body=prepared["body"],
        base=state.get("base_branch", "main"),
        repo=state.get("repo") or None,
    )
    result = pr.create_pull_request(prepared, open_pr=bool(state.get("open_pr", False)))
    next_state = dict(state)
    next_state["pr"] = prepared
    next_state["pr_result"] = result
    return next_state


def build_workflow() -> Any:
    try:
        from langgraph.graph import END, StateGraph
    except ImportError as exc:
        raise OptionalDependencyError(
            "langgraph is required for the remediation agent prototype; install python/requirements.txt"
        ) from exc

    graph = StateGraph(AgentState)
    graph.add_node("load_findings", load_findings)
    graph.add_node("select_supported_findings", select_supported_findings)
    graph.add_node("propose_remediation", propose_remediation)
    graph.add_node("run_patch_preview_or_plan", run_patch_preview_or_plan)
    graph.add_node("validate_sandbox_branch_or_dry_run", validate_sandbox_branch_or_dry_run)
    graph.add_node("prepare_pr_summary", prepare_pr_summary)

    graph.set_entry_point("load_findings")
    graph.add_edge("load_findings", "select_supported_findings")
    graph.add_edge("select_supported_findings", "propose_remediation")
    graph.add_edge("propose_remediation", "run_patch_preview_or_plan")
    graph.add_edge("run_patch_preview_or_plan", "validate_sandbox_branch_or_dry_run")
    graph.add_edge("validate_sandbox_branch_or_dry_run", "prepare_pr_summary")
    graph.add_edge("prepare_pr_summary", END)
    return graph.compile()


def run_workflow(initial_state: AgentState) -> AgentState:
    workflow = build_workflow()
    return workflow.invoke(initial_state)


def _first_option(options: Any) -> dict[str, Any] | None:
    if not isinstance(options, list):
        return None
    candidates = [option for option in options if isinstance(option, dict)]
    if not candidates:
        return None
    candidates.sort(key=lambda item: (int(item.get("priority", 999)), str(item.get("action", ""))))
    return candidates[0]
