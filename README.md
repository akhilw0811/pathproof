# PathProof

PathProof is a Go-based security graph engine that scans local Kubernetes
manifests, local GitHub Actions workflows, and a narrow local Terraform slice
for AWS IAM role OIDC trust policies. It models the smallest current
Kubernetes slice for public exposure, workloads, ServiceAccounts, RBAC, and
Secret metadata, detects the `PP-K8S-001` path from a public workload to a
readable Secret, proposes deterministic remediation, previews and writes
patched copies, and validates the fix with a rescan. It also detects
`PP-GHA-001` when a GitHub Actions `uses:` reference is not pinned to a full
40-character commit SHA, `PP-GHA-002` when a `pull_request_target` workflow
checks out untrusted pull request head code with `actions/checkout`, and
`PP-GHA-003` when a `pull_request_target` workflow explicitly grants dangerous
workflow-level or job-level token permissions, and detects `PP-XDOMAIN-001`
when one of those risky GitHub Actions conditions has a modeled OIDC path to a
locally parsed AWS IAM role trust. It also models a narrow local Terraform
slice for static AWS IAM role permissions, reports `PP-AWS-001` when an
`aws_iam_role` has an inline wildcard admin policy or a literal
AdministratorAccess attachment, and reports `PP-XDOMAIN-002` when a risky
GitHub Actions OIDC path can assume such an administrative role. It also
models static local `aws_s3_bucket` resources and explicit exact S3 grants in
inline role policies, and reports `PP-XDOMAIN-003` when a risky GitHub Actions
OIDC path can assume an AWS IAM role that can access a modeled S3 bucket.
Terraform-modeled `AWSS3Bucket` graph nodes can also carry conservative local
sensitivity metadata derived only from literal bucket-name tokens and
allowlisted static tags on the same `aws_s3_bucket` resource. `PP-XDOMAIN-004`
reports the higher-signal version of the same verified OIDC-to-S3 path when
the modeled bucket is classified sensitive by that existing conservative
metadata.

PathProof is currently a defensive Go CLI focused on two small, tested local
slices. It scans local YAML manifests and workflows, builds an in-memory graph,
reports `PP-K8S-001` when an internet-facing workload runs as a ServiceAccount
that can read a Kubernetes Secret, and reports `PP-GHA-001` for unpinned
GitHub Actions action references, `PP-GHA-002` for unsafe
`pull_request_target` checkout of pull request head code, and `PP-GHA-003` for
explicit dangerous token permissions under `pull_request_target`. It also
models explicit GitHub Actions OIDC token request capability in the internal
graph when a workflow or job grants `id-token: write` or
`permissions: write-all`; this graph-only capability can be connected to a
statically parsed AWS IAM role trust policy when `--repo OWNER/REPO` is
supplied. A matched AWS role trust edge does not produce a finding by itself;
`PP-XDOMAIN-001` requires the GitHub Actions workflow or job to also have a
modeled `PP-GHA-002` or `PP-GHA-003` risk signal.
Static Terraform AWS IAM role permissions are modeled only for supported local
`aws_iam_role_policy` and AdministratorAccess `aws_iam_role_policy_attachment`
forms; this is not IAM simulation.
`PP-XDOMAIN-002` reports the current local cross-domain admin slice: a risky
`pull_request_target` workflow or job with modeled OIDC capability can assume
an AWS IAM role that also has a supported static administrative permission.
`PP-GHA-001` findings include advisory remediation to pin the action to a full
40-character commit SHA. When `--github-action-pins <file>` points to a local
JSON mapping from exact action refs to exact commit SHAs, PathProof can preview
and write deterministic patched workflow copies for safe static action uses.
It never calls GitHub, resolves tags or branches, guesses SHAs, clones action
repositories, or trusts mutable refs.
`PP-XDOMAIN-003` reports one narrow local cross-domain S3 slice: the same
risky OIDC context reaches an AWS IAM role with explicit static read or write
access to a locally modeled `aws_s3_bucket`. Modeled S3 buckets may carry
graph-only `unknown` or `sensitive` metadata from conservative local
Terraform literals. `PP-XDOMAIN-004` reports the same verified explicit S3
access path only when that modeled bucket is `sensitive` and has sanitized
sensitivity reasons. PathProof does not perform S3 content discovery or cloud
data classification.
An explicit local JSON config can be supplied with `--config <file>` to
deterministically enable or disable implemented rules and suppress exact
finding IDs with a required human reason. Config can also exclude explicit
relative files or trailing-slash directory prefixes from the scan before
parsing. Config files are local-only and are not discovered automatically.
`pathproof scan --write-baseline <file>` can generate a local JSON config
containing finding-ID suppressions for the current unsuppressed findings.

Cloud provider APIs, full CI/CD attack-path modeling, exact GitHub workflow
permission inheritance/override modeling, broad Terraform/HCL parsing,
Terraform execution, module or variable evaluation, reusable workflow
resolution, action source inspection, broader sensitive-resource types, live
cluster scanning, cloud validation, IAM simulation, broad cross-domain
analysis, S3 bucket policies, KMS modeling, public access block modeling,
object modeling, full data discovery, DLP-style classification, broad
sensitivity-based findings, glob or regex exclusions, baseline diffing, newly
introduced findings mode, pull request creation, AI/ML ranking, and dashboards
are not implemented.

Vulnerable scans exit `1` by design because findings were found. Usage,
parsing, patch, validation, baseline write, and internal scan errors exit `2`.
Baseline generation exits `0` when the baseline file is written successfully,
even if findings were added to it.

## Quick demo

Build the CLI:

```sh
go build -o ./bin/pathproof ./cmd/pathproof
```

Scan the public demo fixture:

```sh
./bin/pathproof scan ./examples/kubernetes/public-secret-path
```

Expected shape:

```text
Finding count: 1
Rule: PP-K8S-001
Title: Public workload can read Kubernetes Secret
Path:
  1. PublicEndpoint kubernetes://prod/service/public-api ...
  2. Workload kubernetes://prod/deployment/api ...
  3. ServiceAccount kubernetes://prod/serviceaccount/api ...
  4. Secret kubernetes://prod/secret/database-password ...
```

Preview a deterministic remediation patch without writing files:

```sh
./bin/pathproof scan --preview-patches ./examples/kubernetes/public-secret-path
```

Expected shape:

```text
Option 1: NarrowBindingSubject (priority 1)
Patch Preview:
  Status: generated
  File: rbac.yaml
  Diff:
    --- rbac.yaml
    +++ rbac.yaml
```

Write patched copies to a separate output directory:

```sh
rm -rf ./pathproof-out
./bin/pathproof scan --write-patches ./pathproof-out ./examples/kubernetes/public-secret-path
```

Expected shape:

```text
Patch Output:
Written files: 1
  - Status: generated
    Source: rbac.yaml
    Output: pathproof-out/rbac.yaml
```

Validate the written patch by rescanning a complete temporary overlay:

```sh
rm -rf ./pathproof-out
./bin/pathproof scan --write-patches ./pathproof-out --validate-patches ./examples/kubernetes/public-secret-path
```

Expected shape:

```text
Validation:
Finding finding:PP-K8S-001:...: remediated
Summary: PP-K8S-001 no longer appears in patched output.
```

Get structured JSON output:

```sh
rm -rf ./pathproof-out
./bin/pathproof scan --format json --write-patches ./pathproof-out --validate-patches ./examples/kubernetes/public-secret-path
```

Expected excerpt:

```jsonc
{
  "findings": [
    {
      "rule_id": "PP-K8S-001",
      "remediation": {
        "options": [
          { "action": "NarrowBindingSubject" }
        ]
      }
    }
  ],
  "finding_count": 1,
  "patch_outputs": [
    {
      "source": "rbac.yaml",
      "output": "pathproof-out/rbac.yaml",
      "status": "generated"
    },
    // ...additional unsupported patch outputs for non-previewable remediation options
  ],
  "validation": [
    { "rule_id": "PP-K8S-001", "status": "remediated" }
  ]
}
```

Get SARIF output for code-scanning-style integrations:

```sh
./bin/pathproof scan --format sarif ./examples/kubernetes/public-secret-path
```

SARIF export from the CLI is local stdout only. The GitHub Actions workflow
generates a SARIF file from the public demo fixture and uploads it as a
workflow artifact.

Use an explicit local JSON config:

```sh
./bin/pathproof scan --config ./pathproof.json ./examples/kubernetes/public-secret-path
```

Minimal config example:

```json
{
  "rules": {
    "disable": ["PP-GHA-001"],
    "enable": ["PP-K8S-001", "PP-XDOMAIN-003"]
  },
  "suppressions": [
    {
      "finding_id": "finding:PP-K8S-001:...",
      "reason": "Accepted risk for this test fixture"
    }
  ],
  "path_exclusions": [
    "vendor/",
    "third_party/",
    "testdata/ignored/",
    ".github/workflows/ignored.yml",
    "infra/generated.tf"
  ]
}
```

By default all implemented rules are enabled. If `rules.enable` is present and
nonempty, only those rule IDs are enabled; `rules.disable` then removes listed
rules, and disable wins on conflicts. Unknown rule IDs are config errors.
Suppressions match exact stable finding IDs only and require a nonempty
reason. Suppressed findings are omitted from human, JSON, and SARIF results,
do not produce remediation or patches, and do not make the scan exit `1`.
Suppression reasons are validated but not printed.

`path_exclusions` entries are relative to the scan root. A trailing slash
means a directory-prefix exclusion: `vendor/` excludes `vendor/a.yaml` and
`vendor/nested/b.tf`. Without a trailing slash, the entry is an exact file
path: `.github/workflows/ignored.yml` excludes only that workflow file, and
`infra/generated.tf` excludes only that Terraform file. `vendor` does not mean
`vendor/`. Path exclusions are applied before Kubernetes YAML, GitHub Actions
workflow, and Terraform parsing, so excluded files are not parsed and produce
no parse errors, findings, remediation, patches, validation rows, JSON output,
human output, or SARIF results. Glob patterns, `**`, regex, environment
expansion, absolute paths, Windows drive paths, URL-like paths, backslashes,
and outside-root paths are not supported. Config errors exit `2` with
sanitized stderr and no scan output.

Generate a local baseline config from the current unsuppressed findings:

```sh
./bin/pathproof scan --write-baseline ./pathproof-baseline.json ./examples/kubernetes/public-secret-path
```

Expected shape:

```text
Baseline written.
Suppressions generated: 1
```

The generated file uses the same config shape and contains only deterministic
finding-ID suppressions:

```json
{
  "suppressions": [
    {
      "finding_id": "finding:PP-K8S-001:...",
      "reason": "Baseline accepted at generation time"
    }
  ]
}
```

Rerun with the generated baseline:

```sh
./bin/pathproof scan --config ./pathproof-baseline.json ./examples/kubernetes/public-secret-path
```

If `--config` is supplied while writing a baseline, rule controls, path
exclusions, and existing suppressions are applied before baseline generation.
Already-suppressed and stale suppression entries are not copied into the new
baseline. The baseline writer is local-only, does not overwrite existing
files, does not create parent directories, and may write inside the scan root
because scanning has already completed before the file is created. Baseline
diffing and newly introduced finding mode are not implemented yet.

Scan the GitHub Actions demo fixture:

```sh
./bin/pathproof scan ./examples/github-actions/unpinned-action
```

Expected shape:

```text
Finding count: 1
Rule: PP-GHA-001
Title: GitHub Actions workflow uses an action that is not pinned to a full commit SHA
Severity: Medium
Remediation:
  Option 1: PinGitHubActionToSHA ...
```

Preview an action-pinning patch only when a local pin mapping supplies the
exact SHA:

```sh
cat > /tmp/pathproof-action-pins.json <<'JSON'
{
  "actions/checkout@v4": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
JSON
./bin/pathproof scan --github-action-pins /tmp/pathproof-action-pins.json --preview-patches ./examples/github-actions/unpinned-action
```

Expected shape:

```text
Patch Preview:
  Status: generated
  File: .github/workflows/unpinned.yml
  Diff:
    --- .github/workflows/unpinned.yml
    +++ .github/workflows/unpinned.yml
```

Scan the cross-domain GitHub Actions OIDC to AWS IAM role demo fixture:

```sh
./bin/pathproof scan --repo owner/repo ./examples/cross-domain/github-oidc-aws-role
```

Expected shape:

```text
Finding count: 2
Rule: PP-GHA-003
Rule: PP-XDOMAIN-001
Title: Risky GitHub Actions workflow can assume AWS IAM role
Severity: High
```

Scan the cross-domain GitHub Actions OIDC to administrative AWS IAM role demo
fixture:

```sh
./bin/pathproof scan --repo owner/repo ./examples/cross-domain/github-oidc-admin-role
```

Expected shape:

```text
Rule: PP-XDOMAIN-002
Title: Risky GitHub Actions workflow can assume administrative AWS IAM role
Severity: High
```

Scan the cross-domain GitHub Actions OIDC to AWS S3 bucket demo fixture:

```sh
./bin/pathproof scan --repo owner/repo ./examples/cross-domain/github-oidc-s3-access
```

Expected shape:

```text
Rule: PP-XDOMAIN-003
Title: Risky GitHub Actions workflow can access AWS S3 bucket
Severity: High
```

## GitHub Actions Security

PathProof currently implements three small local GitHub Actions checks plus
narrow local cross-domain OIDC findings:

- `PP-GHA-001`: a workflow `uses:` reference is not pinned to a full
  40-character commit SHA.
- `PP-GHA-002`: a `pull_request_target` workflow uses `actions/checkout` with
  sanitized PR-head selectors such as
  `github.event.pull_request.head.sha`, `github.head_ref`, or
  `github.event.pull_request.head.repo.full_name`.
- `PP-GHA-003`: a `pull_request_target` workflow explicitly grants dangerous
  workflow-level or job-level token permissions: `contents: write`,
  `pull-requests: write`, `actions: write`, `checks: write`,
  `deployments: write`, `id-token: write`, `security-events: write`, or
  `permissions: write-all`.
- Graph-only OIDC capability modeling: workflow-level or job-level
  `id-token: write`, including `permissions: write-all`, is represented as an
  internal OIDC token request capability.
- `PP-XDOMAIN-001`: a risky `pull_request_target` workflow or job with a
  `PP-GHA-002` or `PP-GHA-003` risk signal has a modeled local OIDC path to a
  statically parsed AWS IAM role trust.
- `PP-XDOMAIN-002`: the same risky OIDC path reaches a statically modeled AWS
  IAM role that grants an obvious administrative permission in the supported
  local Terraform slice.
- `PP-XDOMAIN-003`: the same risky OIDC path reaches a statically modeled AWS
  IAM role with explicit exact S3 read or write access to a modeled
  `aws_s3_bucket`.
- `PP-XDOMAIN-004`: the same verified PP-XDOMAIN-003 path reaches a modeled
  `aws_s3_bucket` classified `sensitive` by conservative local bucket-name or
  allowlisted static tag metadata.

These checks are static and local. PathProof does not execute workflows, call
GitHub APIs, evaluate expressions, inspect action source, model workflow
permission inheritance or overrides, broadly ingest cloud trust policies,
contact cloud providers, or claim full CI/CD attack-path coverage. Exact GitHub
permission inheritance/override modeling is future work.

## Terraform AWS IAM OIDC Trust

PathProof scans local `.tf` files under the scan root for only static
`aws_iam_role` resources whose `assume_role_policy` is a literal heredoc JSON
string or simple quoted JSON string. It parses the extracted JSON locally with
Go's standard library and records sanitized AWS IAM role trust metadata for
GitHub Actions OIDC trust statements.

When `pathproof scan --repo OWNER/REPO <directory>` is used, PathProof can add
a graph `OIDCTokenCapability --CanAssumeRole--> AWSIAMRole` edge if a
parsed workflow/job OIDC capability has a static subject candidate that
matches the role trust conditions. Without `--repo`, Terraform trust metadata
is still modeled, but cross-domain `CanAssumeRole` edges are not created.
`PP-XDOMAIN-001` is emitted only when that edge is reachable from an explicitly
modeled workflow-level or job-level OIDC capability and the same workflow/job
has a modeled PP-GHA-002 or PP-GHA-003 risk signal.
`PP-XDOMAIN-002` additionally requires that the same AWS role has a modeled
`AWSIAMRole --GrantsPermission--> AWSPermission` edge whose permission metadata
is administrative. Both cross-domain rules require the matched OIDC subject to
be the pull request subject for the risky `pull_request_target` context; branch
or environment trust matches are modeled for future rules but do not trigger
these findings.
`PP-XDOMAIN-003` additionally requires an explicit
`AWSIAMRole --CanReadObject/CanWriteObject--> AWSS3Bucket` edge from exact
static S3 action/resource pairs. It does not expand AdministratorAccess,
`Action "*" Resource "*"`, or `s3:* Resource "*"` into bucket access.
`PP-XDOMAIN-004` additionally requires the same explicit S3 access path to
target an `AWSS3Bucket` with `sensitivity_level` `sensitive` and at least one
sanitized sensitivity reason. `PP-XDOMAIN-003` does not require sensitivity
and still reports unknown-sensitivity buckets.

This slice does not execute Terraform, parse modules, evaluate variables,
locals, functions, `jsonencode`, interpolations, or
`aws_iam_policy_document`, call AWS or GitHub APIs, verify ARNs or accounts,
simulate IAM permissions, inspect unsupported role policies, parse S3 bucket
policies, model S3 objects, model KMS, or provide remediation.

## Terraform AWS IAM Permissions

PathProof also scans local `.tf` files for a narrow static AWS IAM role
permission slice. It recognizes inline `aws_iam_role_policy` JSON attached to
a parsed role by `aws_iam_role.<name>.id`, `aws_iam_role.<name>.name`, or a
literal role name only when exactly one parsed role has an explicit static
`name` matching that literal. It recognizes
`aws_iam_role_policy_attachment` only for the literal AWS managed policy ARN
`arn:aws:iam::aws:policy/AdministratorAccess`.

`PP-AWS-001` is emitted only for obviously administrative permissions:
`Allow` with `Action "*" Resource "*"`, `Allow` with
`Action "*:*" Resource "*"`, or the literal AdministratorAccess attachment.
PathProof does not evaluate conditions, `NotAction`, variables, modules,
locals, `jsonencode`, customer-managed policies, unknown managed policies,
permission boundaries, SCPs, or resource-level IAM semantics, and it provides
no AWS remediation or patching in this slice.

## CI / SARIF

The GitHub Actions workflow builds and tests PathProof, then runs the built CLI
against the intentionally vulnerable demo fixture:

```sh
./bin/pathproof scan --format sarif ./examples/kubernetes/public-secret-path > pathproof.sarif
```

The demo fixture is expected to produce `PP-K8S-001`, so CI handles exit code
`1` explicitly instead of hiding failures with `|| true`. Scan exit codes are:

- `0`: scan succeeded and found zero findings.
- `1`: scan succeeded and found one or more findings.
- `2`: usage, parsing, routing, patch output, validation, baseline write, or
  internal scan error.

When `--write-baseline` succeeds, the scan exits `0` even if findings were
written into the generated baseline.

CI verifies that `pathproof.sarif` exists, is non-empty, contains SARIF version
`2.1.0`, and contains `PP-K8S-001`, then uploads it with
`actions/upload-artifact`.

GitHub code scanning upload is not enabled by default. Repositories that want
code scanning can add GitHub's `upload-sarif` action later, but this workflow
only publishes the SARIF file as an artifact.

## What this proves

- Deterministic graph modeling with stable IDs and ordered evidence.
- Kubernetes Service, Ingress, Deployment, ServiceAccount, RBAC, and Secret
  metadata modeling.
- Attack-path detection from public exposure to Secret read access.
- Evidence-backed remediation planning from typed RBAC authorization metadata.
- Safe read-only patch previews.
- Patched-copy output to a separate directory, never in-place edits.
- Validation by rescanning a complete temporary patched manifest set.
- Local baseline generation as JSON config suppressions for current
  unsuppressed findings.
- SARIF 2.1.0 finding export for implemented Kubernetes, GitHub Actions, AWS,
  and cross-domain rules.
- Local GitHub Actions workflow parsing under `.github/workflows`.
- `PP-GHA-001` detection for GitHub Actions `uses:` references that are not
  pinned to a full 40-character commit SHA.
- `PP-GHA-002` detection for `pull_request_target` workflows that configure
  `actions/checkout` to check out pull request head code.
- `PP-GHA-003` detection for `pull_request_target` workflows that explicitly
  grant dangerous workflow-level or job-level token permissions.
- Internal graph-only modeling for GitHub Actions OIDC token request
  capability from explicit `id-token: write` or `permissions: write-all`.
- `PP-AWS-001` detection for static local Terraform AWS IAM role permissions
  that are obviously administrative.
- `PP-XDOMAIN-001` detection for the first local cross-domain GitHub Actions
  OIDC to AWS IAM role trust path, gated by modeled PP-GHA-002 or PP-GHA-003
  risk signals.
- `PP-XDOMAIN-002` detection for the local cross-domain GitHub Actions OIDC to
  administrative AWS IAM role path, gated by the same modeled risk signals and
  supported static AWS admin permission metadata.
- `PP-XDOMAIN-003` detection for the local cross-domain GitHub Actions OIDC to
  AWS S3 bucket access path, gated by the same modeled risk signals and
  explicit exact static S3 access to modeled buckets.
- `PP-XDOMAIN-004` detection for the higher-signal version of that path when
  the modeled S3 bucket has conservative sanitized sensitivity metadata.
- No Secret value ingestion or printing.

## Architecture

PathProof keeps parsing, graph storage, routing, analysis, remediation, patch
generation, and CLI presentation separate.

The scan loop is:

1. Parse local Kubernetes YAML manifests.
2. Parse local GitHub Actions workflow YAML files under `.github/workflows`.
3. Parse local Terraform `.tf` files for static AWS IAM role OIDC trust
   metadata, narrow static AWS IAM role permission facts, and static S3 bucket
   names.
4. Build an in-memory evidence graph.
5. Add deterministic Kubernetes routing and RBAC-derived Secret read edges.
6. Add deterministic GitHub Actions workflow/job/action-use edges and
   graph-only OIDC token capability edges.
7. Add deterministic AWS IAM role trust nodes, AWS permission nodes, S3 bucket
   nodes, permission edges, exact S3 access edges, and optional
   `CanAssumeRole` edges when `--repo OWNER/REPO` supplies repository identity
   for static subject matching.
8. Analyze the graph for `PP-K8S-001`, `PP-GHA-001`, `PP-GHA-002`,
   `PP-GHA-003`, `PP-AWS-001`, `PP-XDOMAIN-001`, `PP-XDOMAIN-002`,
   `PP-XDOMAIN-003`, and `PP-XDOMAIN-004`.
9. Optionally write a local baseline config for current unsuppressed findings
   after configured rule filtering and suppressions.
10. Build advisory remediation plans from structured graph metadata for
   supported Kubernetes findings only.
11. Optionally generate read-only `NarrowBindingSubject` patch previews.
12. Optionally write patched copies to a separate output directory.
13. Optionally validate by rescanning a complete temporary overlay that replaces
   original files with generated patched copies.

PathProof does not contact a live cluster, run `kubectl`, apply patches in
place, execute GitHub Actions workflows, call GitHub APIs, create pull
requests, persist the graph, or use AI/ML ranking.

## Current scope

Implemented:

- Local Kubernetes YAML scanning.
- Local GitHub Actions workflow scanning under `.github/workflows`.
- Public endpoint to workload routing.
- ServiceAccount identity modeling.
- RBAC Secret read analysis.
- `PP-K8S-001` finding.
- `PP-GHA-001` finding for action references not pinned to a full commit SHA.
- `PP-GHA-002` finding for unsafe `pull_request_target` checkout of pull
  request head code.
- `PP-GHA-003` finding for dangerous `pull_request_target` token permissions.
- Narrow local Terraform S3 bucket parsing and exact IAM role S3 access
  modeling for modeled buckets.
- `PP-XDOMAIN-003` finding for risky GitHub Actions OIDC access to a modeled
  AWS S3 bucket.
- `PP-XDOMAIN-004` finding for risky GitHub Actions OIDC access to a
  sensitive Terraform-modeled AWS S3 bucket.
- SARIF 2.1.0 finding export.
- Local baseline generation for current unsuppressed findings.
- Deterministic remediation planning.
- `NarrowBindingSubject` patch preview and patched-copy output.
- Validation rescan.

Not implemented:

- Live cluster scanning.
- Cloud provider APIs.
- Full CI/CD attack-path modeling.
- Exact GitHub workflow permission inheritance/override modeling.
- OIDC trust analysis.
- Reusable workflow resolution.
- Action source inspection.
- Automatic action pinning patches.
- Automatic remediation for unsafe `pull_request_target` checkout patterns.
- Baseline diffing or newly introduced finding mode.
- PR creation.
- In-place edits.
- Broad RBAC patching.
- AI/ML ranking.
- Dashboard.

## Resume summary

- Built PathProof, a Go-based Kubernetes security graph engine that models
  public exposure, workloads, service accounts, RBAC, and Secrets to detect
  verified attack paths from internet-facing workloads to sensitive resources.
- Implemented deterministic remediation planning with read-only patch previews,
  patched-copy generation, and validation rescans that prove whether a proposed
  fix removes the original attack path.
- Designed security-focused regression tests for graph determinism, RBAC edge
  cases, Secret-value exclusion, patch safety, symlink/path traversal
  protections, and remediation correctness.

## Development

```sh
make check
make build
```

The built binary is written to `bin/pathproof`.

Useful local commands:

```sh
go run ./cmd/pathproof version
go run ./cmd/pathproof scan ./cmd/pathproof/testdata/scan-safe
go run ./cmd/pathproof scan --format json ./cmd/pathproof/testdata/scan-vulnerable
go run ./cmd/pathproof scan --format sarif ./cmd/pathproof/testdata/scan-vulnerable
go run ./cmd/pathproof scan --preview-patches ./examples/kubernetes/public-secret-path
go run ./cmd/pathproof scan ./examples/github-actions/unpinned-action
go run ./cmd/pathproof scan ./examples/github-actions/dangerous-permissions
```

Scan exit codes are stable:

- `0`: scan succeeded and found zero findings.
- `1`: scan succeeded and found one or more findings.
- `2`: usage, parsing, routing, patch output, validation, baseline write, or
  internal scan error.

Baseline generation exits `0` when the baseline file is written successfully,
even if suppressions were generated.
