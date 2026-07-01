# PathProof Agent Prototype

This is an experimental local LangGraph remediation-agent prototype. It
consumes PathProof JSON findings and prepares a deterministic dry-run
remediation and pull request summary.

It does not detect vulnerabilities, decide finding truth, invent findings, or
patch source files itself. The Go PathProof engine remains the source of
deterministic findings, remediation metadata, patch previews, and validation
output.

Run from the `python/` directory after installing optional dependencies:

```sh
python -m pip install -r requirements.txt
python -m pathproof_agent.run_agent --findings ../examples/python-agent/pathproof_findings.json
```

By default the agent produces a dry-run `gh pr create` command. It opens a pull
request only when `--open-pr` is explicitly supplied.

OpenAI wording is optional and non-authoritative. It is used only when
`--enable-openai-wording`, `OPENAI_API_KEY`, and an explicit model via
`--openai-model` or `PATHPROOF_OPENAI_MODEL` are all present. Otherwise the
agent uses deterministic fallback wording.
