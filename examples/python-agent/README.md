# Python Agent Example

This directory contains a sanitized PathProof JSON-style report for the
experimental Python remediation agent.

From the repository root:

```sh
cd python
python -m pip install -r requirements.txt
python -m pathproof_agent.run_agent --findings ../examples/python-agent/pathproof_findings.json
```

The agent consumes existing PathProof findings and remediation metadata. It
does not detect vulnerabilities or invent remediation. By default it prints a
dry-run `gh pr create` command. It opens a pull request only when `--open-pr`
is explicitly supplied.

OpenAI wording is optional. It is used only with `--enable-openai-wording`, an
`OPENAI_API_KEY`, and an explicit model supplied through `--openai-model` or
`PATHPROOF_OPENAI_MODEL`.
