"""Optional OpenAI wording adapter for grounded PathProof summaries."""

from __future__ import annotations

import json
import os
from typing import Any


def deterministic_fallback_wording(data: dict[str, Any]) -> dict[str, str]:
    proposals = data.get("proposals")
    count = len(proposals) if isinstance(proposals, list) else 0
    title = "PathProof remediation plan"
    if count == 1 and isinstance(proposals[0], dict):
        title = f"PathProof remediation for {proposals[0].get('rule_id', 'finding')}"
    elif count > 1:
        title = f"PathProof remediation for {count} verified findings"
    body = [
        "Generated from structured PathProof findings.",
        "Deterministic PathProof rules and graph evidence remain authoritative.",
    ]
    if count == 0:
        body.append("No supported remediation proposals were found.")
    else:
        for proposal in proposals:
            if not isinstance(proposal, dict):
                continue
            body.append(
                f"- {proposal.get('rule_id', '')} {proposal.get('finding_id', '')}: "
                f"{proposal.get('action', '')}. {proposal.get('summary', '')}"
            )
    return {"title": title, "body": "\n".join(body).strip() + "\n", "source": "deterministic_fallback"}


def generate_grounded_wording(
    data: dict[str, Any],
    enabled: bool = False,
    model: str | None = None,
    api_key: str | None = None,
) -> dict[str, str]:
    api_key = api_key if api_key is not None else os.environ.get("OPENAI_API_KEY", "")
    model = model or os.environ.get("PATHPROOF_OPENAI_MODEL", "")
    fallback = deterministic_fallback_wording(data)
    if not enabled or not api_key or not model:
        return fallback

    try:
        from openai import OpenAI
    except ImportError:
        return fallback

    prompt = (
        "Return exactly one short sentence for a non-authoritative pull request "
        "wording note. It must describe only that PathProof verified the count "
        "of findings in the structured data and prepared the deterministic "
        "remediation plan below. Do not include rule IDs, finding IDs, resource "
        "names, file paths, commands, credentials, secrets, new remediation "
        "steps, vulnerability claims, or markdown.\n\n"
        + json.dumps(data, sort_keys=True)
    )
    client = OpenAI(api_key=api_key)
    response = client.responses.create(model=model, input=prompt)
    text = getattr(response, "output_text", "") or ""
    note = _validated_openai_note(text, data)
    if not note:
        return fallback
    body = fallback["body"].rstrip() + "\n\nOpenAI wording note (non-authoritative):\n" + note + "\n"
    return {"title": fallback["title"], "body": body, "source": "openai"}


def _validated_openai_note(text: str, data: dict[str, Any]) -> str:
    note = " ".join(text.strip().split())
    if not note or len(note) > 240:
        return ""
    proposals = data.get("proposals")
    count = len(proposals) if isinstance(proposals, list) else 0
    lowered = note.lower()
    if str(count) not in lowered or "pathproof" not in lowered or "verified" not in lowered:
        return ""
    forbidden = [
        "\n",
        "```",
        "pp-",
        "finding:",
        "secret",
        "token",
        "credential",
        "password",
        "exploit",
        "compromise",
        "delete",
        "rotate",
        "revoke",
        "grant",
        "admin",
        "assume",
        "s3",
        "kubernetes://",
        "githubactions://",
        "aws://",
        ".yml",
        ".yaml",
        ".tf",
    ]
    if any(value in lowered for value in forbidden):
        return ""
    return note
