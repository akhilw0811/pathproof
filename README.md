# PathProof

PathProof is a defensive attack-path verification engine for local Kubernetes,
GitHub Actions, and Terraform/AWS evidence. The core scanner is written in Go
and builds an in-memory graph from source-controlled infrastructure files. It
then emits deterministic findings with stable IDs, ordered paths, and
source-backed evidence.

PathProof also includes Python workflows for priority ranking and remediation
planning. The ranking workflow trains a scikit-learn model on PathProof-style
finding features, and the remediation workflow uses LangGraph to consume
PathProof JSON, prepare remediation summaries, produce pull request text, and
use the configured OpenAI API for grounded wording.

## What It Verifies

PathProof detects implemented local attack-path and supply-chain conditions:

- `PP-K8S-001`: public Kubernetes workload can read a Kubernetes Secret.
- `PP-GHA-001`: GitHub Actions workflow uses an action ref that is not pinned
  to a full commit SHA.
- `PP-GHA-002`: `pull_request_target` workflow checks out untrusted pull
  request head code.
- `PP-GHA-003`: `pull_request_target` workflow grants dangerous token
  permissions.
- `PP-AWS-001`: local Terraform AWS IAM role grants obvious administrative
  permissions.
- `PP-XDOMAIN-001`: risky GitHub Actions OIDC path can assume a modeled AWS
  IAM role.
- `PP-XDOMAIN-002`: risky GitHub Actions OIDC path can assume an
  administrative AWS IAM role.
- `PP-XDOMAIN-003`: risky GitHub Actions OIDC path can access a modeled AWS S3
  bucket.
- `PP-XDOMAIN-004`: the same verified S3 path reaches a modeled sensitive S3
  bucket.

The scanner is local-first. It does not need Kubernetes, AWS, or GitHub
credentials to run the core checks. OpenAI API credentials are supplied through
the local environment for the Python wording workflow and are not stored in the
repository.

## Repository Layout

```text
cmd/pathproof/        Go CLI entrypoint
internal/             Go parsers, graph, analysis, remediation, SARIF, ranking
examples/             Local fixtures and runnable examples
python/               Python ranking and remediation workflows
```

The Go engine is the source of deterministic security truth. Python workflows
consume structured PathProof output and do not change finding IDs, rule
behavior, SARIF output, or scanner exit codes.

## Quick Start

Build the CLI:

```sh
go build -o ./bin/pathproof ./cmd/pathproof
```

Scan the Kubernetes demo fixture:

```sh
./bin/pathproof scan ./examples/kubernetes/public-secret-path
```

Expected shape:

```text
Finding count: 1
Rule: PP-K8S-001
Title: Public workload can read Kubernetes Secret
```

Get JSON output:

```sh
./bin/pathproof scan --format json ./examples/kubernetes/public-secret-path
```

Generate SARIF output:

```sh
./bin/pathproof scan --format sarif ./examples/kubernetes/public-secret-path
```

Scan a cross-domain GitHub Actions OIDC to AWS fixture:

```sh
./bin/pathproof scan --repo owner/repo ./examples/cross-domain/github-oidc-s3-access
```

## Remediation

PathProof produces deterministic remediation plans for supported findings.
For Kubernetes Secret access, it can preview and write safe patched copies to a
separate output directory, then validate the result by rescanning a complete
temporary overlay.

Preview a patch:

```sh
./bin/pathproof scan --preview-patches ./examples/kubernetes/public-secret-path
```

Write patched copies:

```sh
rm -rf ./pathproof-out
./bin/pathproof scan --write-patches ./pathproof-out ./examples/kubernetes/public-secret-path
```

Write and validate:

```sh
rm -rf ./pathproof-out
./bin/pathproof scan --write-patches ./pathproof-out --validate-patches ./examples/kubernetes/public-secret-path
```

For unpinned GitHub Actions, PathProof can use a local trusted mapping from
exact action refs to full commit SHAs:

```sh
cat > /tmp/pathproof-action-pins.json <<'JSON'
{
  "actions/checkout@v4": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
JSON

./bin/pathproof scan \
  --github-action-pins /tmp/pathproof-action-pins.json \
  --preview-patches \
  ./examples/github-actions/unpinned-action
```

## Ranking

The Go CLI includes deterministic heuristic priority scoring:

```sh
./bin/pathproof scan --rank heuristic ./examples/kubernetes/public-secret-path
```

The Python ranking workflow trains and evaluates a scikit-learn model over
structured PathProof finding features:

```sh
python3 -m pip install -r python/requirements.txt
PYTHONPATH=python python3 -m pathproof_ranking.train_ranker
PYTHONPATH=python python3 -m pathproof_ranking.evaluate
```

Ranking features are extracted from structured findings, paths, remediation
metadata, baseline status, and resource categories. Labels represent priority
for ordering verified findings; deterministic rules still decide whether a
finding exists.

## Remediation Agent

The Python remediation agent consumes PathProof JSON and produces a structured
remediation and pull request plan:

```sh
PYTHONPATH=python python3 -m pathproof_agent.run_agent \
  --findings examples/python-agent/pathproof_findings.json
```

The default mode is dry-run. It prints pull request content and a `gh pr
create` command without opening a pull request. Use `--open-pr` only when the
branch and GitHub CLI environment are ready.

OpenAI wording is configured through local environment credentials:

- `OPENAI_API_KEY`
- an explicit model through `--openai-model` or `PATHPROOF_OPENAI_MODEL`

The agent keeps deterministic local wording as the fallback path for test and
offline runs.

## Baselines And Config

Generate a local baseline config from current findings:

```sh
./bin/pathproof scan \
  --write-baseline ./pathproof-baseline.json \
  ./examples/kubernetes/public-secret-path
```

Compare a scan against a baseline:

```sh
./bin/pathproof scan \
  --baseline ./pathproof-baseline.json \
  ./examples/kubernetes/public-secret-path
```

Use `--config <file>` for explicit local rule controls, exact finding
suppressions, and path exclusions.

## Testing

Run the Go validation suite:

```sh
make check
```

Run Python workflow tests:

```sh
PYTHONPATH=python python3 -m unittest discover -s python
```

Python tests use `unittest`. Tests that need optional Python dependencies skip
cleanly when those dependencies are not installed.

## Safety Model

PathProof is defensive and local-first:

- Secret values are not ingested from Kubernetes Secret payloads.
- The Go scanner does not call cloud provider APIs.
- Terraform support is static and local; PathProof does not execute Terraform
  or simulate IAM.
- GitHub Actions analysis is static; PathProof does not execute workflows.
- Patch output is written to a separate output directory, not in place.
- Pull request creation is explicit and opt-in through the Python helper.
- OpenAI credentials are read from the local environment and are not committed.

## Exit Codes

- `0`: scan succeeded with no findings.
- `1`: scan succeeded and found one or more findings.
- `2`: usage, parsing, routing, patch, validation, baseline, or internal scan
  error.

## Tech Stack

- Go security graph engine and CLI
- Kubernetes YAML parsing
- GitHub Actions workflow analysis
- Terraform/AWS IAM and S3 modeling
- SARIF output for code-scanning integrations
- Python ranking workflow with scikit-learn
- LangGraph remediation workflow
- OpenAI API wording adapter
- Dry-run-first GitHub PR helper
