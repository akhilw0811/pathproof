# Architecture

PathProof is a small Go CLI with early in-memory graph domain logic. The
current executable lives at `cmd/pathproof` and supports `pathproof version`
and local directory scans with:

- `pathproof scan <directory>`
- `pathproof scan --format json <directory>`
- `pathproof scan --format=json <directory>`
- `pathproof scan --format sarif <directory>`
- `pathproof scan --config <file> <directory>`
- `pathproof scan --repo OWNER/REPO <directory>`
- `pathproof scan --github-action-pins <file> <directory>`
- `pathproof scan --write-baseline <file> <directory>`
- `pathproof scan --preview-patches <directory>`
- `pathproof scan --write-patches <output-directory> <directory>`
- `pathproof scan --write-patches <output-directory> --validate-patches <directory>`

The scan command is intentionally only an orchestration layer. It validates the
local directory input, optionally loads one explicit local JSON config file
from `--config <file>`, applies configured path exclusions to scan input
selection before parsing, parses non-excluded Kubernetes manifests and local
GitHub Actions workflows under `.github/workflows`, parses non-excluded local
Terraform `.tf` files for a narrow static AWS IAM role OIDC trust-policy
slice, constructs the in-memory graph, runs deterministic analysis, applies
configured rule filtering and exact finding-ID suppressions, optionally writes
a local baseline config for the remaining unsuppressed findings, builds
advisory remediation plans for supported unsuppressed Kubernetes findings and
`PP-GHA-001` unpinned action findings when baseline mode is not active,
optionally builds read-only patch previews for supported remediation changes,
optionally writes patched copies for supported generated previews to a
separate output directory, optionally validates written Kubernetes patches by
rescanning a temporary complete patched manifest overlay with the same
effective scan exclusions, projects findings, plans, previews, patch output
summaries, and validation results into a private CLI report shape, and writes
human-readable output, JSON, or SARIF.
GitHub Actions pinning patches are local-only: PathProof reads only an
optional local JSON pin mapping supplied with `--github-action-pins`, never
calls GitHub, never resolves tags or branches, never guesses SHAs, and does
not validate `PP-GHA-001` patches in this slice. It does not persist the graph
or expose graph internals beyond the ordered finding path, evidence,
remediation plan fields, optional preview fields, optional patch output
summaries, optional validation results, and SARIF finding projection.

Config loading and baseline writing live under `internal/config` and use only
Go standard library JSON parsing. Config is explicit-flag-only: there is no
per-directory discovery, environment expansion, remote URL loading, includes,
inheritance, YAML, TOML, glob patterns, or regex patterns. Config supports
literal relative path exclusions and trailing-slash directory-prefix
exclusions. Exclusions are normalized to slash-separated
clean relative paths, rejected if they can escape the scan root or use
unsupported pattern syntax, and matched against lexical paths under the scan
root before parser file opening. Rule controls are applied after analysis and
before remediation, patch preview, patch writing, validation, JSON, human
output, and SARIF. Suppressions are exact finding-ID matches applied after
rule filtering; suppressed findings are omitted from output and downstream
remediation/patch/validation behavior. Suppression reasons are required and
validated but are not printed.

Baseline generation is local-only and writes a JSON config containing only
`suppressions` entries with stable finding IDs and the deterministic reason
`Baseline accepted at generation time`. It consumes the findings that remain
after path exclusions, rule filtering, and existing suppressions, so disabled,
excluded, stale, and already-suppressed findings are not written. Baseline
writing does not change graph construction, analysis, rule semantics, finding
IDs, or suppression matching. It does not build remediation plans, patch
previews, patch outputs, validation results, or GitHub Action pinning metadata.
The writer refuses to overwrite existing files, does not create parent
directories, uses a local non-executable file mode, and may write inside the
scan root because the scan has already completed before the baseline file is
created.

Implemented Kubernetes parsing lives under `internal/parser/kubernetes`.
It reads local YAML manifests and emits explicit Go types for supported
resources:

- `Service`
- `Deployment`
- `networking.k8s.io/v1` `Ingress`
- `ServiceAccount`
- core `v1` `Secret` metadata
- `rbac.authorization.k8s.io/v1` `Role`
- `rbac.authorization.k8s.io/v1` `ClusterRole`
- `rbac.authorization.k8s.io/v1` `RoleBinding`
- `rbac.authorization.k8s.io/v1` `ClusterRoleBinding`

Secret parsing intentionally reads only namespace, name, and source location.
Secret `data`, `stringData`, and Secret values are never ingested, stored,
logged, serialized, or exposed by parser or graph output.

Implemented GitHub Actions parsing lives under
`internal/parser/githubactions`. It reads only `.github/workflows/*.yml` and
`.github/workflows/*.yaml` under the scan root and emits explicit Go types for
workflow name, workflow source, `pull_request` and `pull_request_target`
trigger presence, static push branch literals for OIDC subject matching,
sanitized workflow-level and job-level permission grants, job IDs, static job
environment names for OIDC subject matching, step indexes, optional step
names, sanitized static action identity components, and precise `uses:` scalar
line/column positions for safe local patch planning.
For `actions/checkout` steps only, it also records sanitized matches for the
PR-head selector expressions used by `PP-GHA-002`. It does not require a Git
repository, call GitHub APIs, execute workflows, evaluate expressions, resolve
reusable workflows, inspect action source code, model exact workflow
permission inheritance or overrides, infer branch names, expand matrices, or
retain `env`, arbitrary `with` values, `secrets`, token values, run scripts,
expression-only `uses:` values, unknown permission values, or raw workflow
documents. It records only a coarse unsupported-patch reason when secret-like
workflow context makes GitHub Actions patch output unsafe. Ordinary non-secret
`env`, `with`, and `run` keys do not by themselves disable action pin patches.
A `uses:` value that is
entirely an expression is ignored because it is not a statically recognizable
action reference. If a `uses:` value has a static `owner/repo` shape but an
expression in the ref, the ref is stored as a sanitized expression marker and
treated as unpinned.

Implemented Terraform parsing lives under `internal/parser/terraform`. It
walks local `.tf` files under the scan root and recognizes only top-level
static `aws_iam_role`, `aws_iam_role_policy`, and
`aws_iam_role_policy_attachment` resources needed for the current AWS IAM
trust and permission slices, plus static `aws_s3_bucket` resources for the
current S3 access slice. For role trust, it supports `assume_role_policy`
as a static literal heredoc JSON string or simple quoted JSON string and parses
only the extracted trust-policy JSON using `encoding/json`. For role
permissions, it supports inline `aws_iam_role_policy` JSON attached by
`aws_iam_role.<name>.id`, `aws_iam_role.<name>.name`, or a literal role name
only when exactly one parsed role has an explicit static `name` matching that
literal. It also supports `aws_iam_role_policy_attachment` only for the
literal AWS managed policy ARN
`arn:aws:iam::aws:policy/AdministratorAccess`.
For S3, it supports only `aws_s3_bucket` with a safe literal `bucket` name,
conservative graph-only sensitivity facts from full bucket-name tokens and
allowlisted static literal tags on the same bucket resource, and inline
role-policy statements using exact action strings `s3:GetObject`,
`s3:ListBucket`, `s3:PutObject`, `s3:DeleteObject`, or `s3:*` with exact
bucket or object ARNs for modeled buckets.

The Terraform parser ignores variables, locals, modules, data sources,
`jsonencode`, function calls, interpolation, dynamic blocks, references to
`aws_iam_policy_document`, nonliteral trust or permission policies, unknown
managed policy ARNs, `NotAction`, `NotResource`, conditions, unsupported
actions/resources,
ambiguous literal role-name matches, wildcard S3 bucket ARNs, wildcard S3
prefixes, and non-role IAM resources. It does not
execute Terraform, evaluate HCL, call AWS, call GitHub, parse remote state, or
retain raw Terraform files, raw policy JSON, provider credentials, variable
values, access keys, unrelated tags, secret-like strings, unsupported tag
values, or unsupported condition values.
Malformed supported Terraform syntax and malformed extracted JSON return
deterministic sanitized errors with file or resource context and no raw policy
content.

Implemented Kubernetes routing lives under `internal/routing/kubernetes`.
It builds deterministic graph relationships for:

- public Service or Ingress routes to Deployment workloads,
- Deployment `serviceAccountName` relationships to ServiceAccounts.
- ServiceAccount RBAC bindings to Roles or ClusterRoles,
- reachable observed Role or ClusterRole resource rules to canonical
  Permissions,
- static RBAC-derived ServiceAccount access to parsed Secrets.

RBAC non-resource URL authorization rules are parsed only so they can be
recognized as unsupported and skipped during resource Permission construction.
They do not create Secret access.

Secret access is a static authorization model, not observed runtime behavior.
PathProof creates `CanRead` edges only when canonical parsed RBAC rules,
resolved binding scope, resolved ServiceAccount identity, and observed Secret
metadata show that a supported rule can read a parsed Secret. It does not claim
that a workload actually issued a Secret read request.

`CanRead` edges also carry typed Kubernetes authorization metadata for the
chains that produced the edge. This metadata is narrow and deterministic:
binding identity and source, affected ServiceAccount, role identity and source,
canonical permission, matched verb, effective scope, and parsed Secret identity
and source references. It does not include Secret values, raw manifests, YAML
snippets, or arbitrary metadata maps.

Implemented GitHub Actions routing lives under
`internal/routing/githubactions`. It builds the graph needed for the current
rules and graph-only OIDC capability modeling: `Workflow` nodes, `WorkflowJob`
nodes, `GitHubAction` step-use nodes, `OIDCTokenCapability` nodes,
`DefinesJob` edges, `UsesAction` edges, and `CanRequestOIDCToken` edges.
`Workflow` node metadata stores sanitized workflow identity,
`pull_request_target` trigger presence, and explicit workflow-level permission
grants. `DefinesJob` metadata stores the same workflow identity plus job ID
and explicit job-level permission grants. `UsesAction` metadata stores the
workflow source reference, relative workflow file, workflow name or file
fallback, `pull_request_target` trigger presence, job ID, step index, optional
step name, canonical sanitized action display string, parsed owner, repo,
path, and ref, and sanitized checkout PR-head selector matches when present.
`CanRequestOIDCToken` edges are created only for explicit workflow-level or
job-level `id-token: write`, including `permissions: write-all`, and preserve
whether the capability came from explicit `id-token: write` or from
`permissions: write-all` evidence. This OIDC modeling is static graph
structure only and does not create a finding by itself. It does not model
CI/CD identities, exact workflow permission inheritance or overrides, OIDC
trust policies, reusable workflow calls, cloud trust, or runtime behavior.

Implemented Terraform routing lives under `internal/routing/terraform`. It
adds `AWSIAMRole` nodes for statically parsed local `aws_iam_role` resources
and stores only sanitized trust metadata: provider, resource name, source
reference, trusted issuer, supported subject patterns, audience values, and
statement indexes. It also adds `AWSPermission` nodes and
`AWSIAMRole --GrantsPermission--> AWSPermission` edges for supported static
role permissions. AWS permission metadata is limited to provider, source
reference, policy or attachment resource name, attached role resource name,
sanitized supported action/resource lists, the literal AdministratorAccess ARN
when applicable, and precise admin reason identities.
It also adds `AWSS3Bucket` nodes with sanitized bucket identity and optional
conservative sensitivity metadata. Sensitivity metadata is limited to
`unknown` or `sensitive` plus deterministic sanitized reasons from local
Terraform bucket-name tokens or allowlisted static tags; it is not a rule
input for the current findings.
It also adds exact
`AWSIAMRole --CanReadObject/CanWriteObject--> AWSS3Bucket` edges when a
supported inline role policy grants `s3:ListBucket` to the exact bucket ARN,
`s3:GetObject` to the exact object ARN, `s3:PutObject` or `s3:DeleteObject` to
the exact object ARN, or `s3:*` to the exact bucket/object ARN. `s3:*` on a
bucket ARN creates read access only; `s3:*` on an object ARN creates read and
write access. `Resource "*"`, wildcard bucket ARNs, wildcard prefixes,
AdministratorAccess, and administrative permission metadata do not create S3
access edges. Multiple matching grants for the same role, bucket, and access
mode are deduplicated and aggregated on one edge.

When the optional CLI flag
`--repo OWNER/REPO` is supplied, routing generates a limited set of GitHub
Actions OIDC subject candidates from parsed workflow data and adds
`OIDCTokenCapability --CanAssumeRole--> AWSIAMRole` only when a candidate
matches a supported trust statement. Without `--repo`, role trust metadata is
modeled but no cross-domain edge is created. The routing layer does not infer
repository identity from Git remotes, call GitHub, call AWS, validate accounts
or ARNs remotely, simulate IAM, evaluate permission boundaries/SCPs/conditions,
or emit findings.

Graph storage lives under `internal/graph` and remains in memory. Parsing,
graph storage, routing construction, analysis, and CLI presentation remain
separate. The CLI report projection is private to `cmd/pathproof`; it resolves
analysis finding node IDs back to graph node ID/kind/name values and preserves
finding edge evidence as edge ID/kind/source/detail values. If a finding cannot
be projected against the graph, the scan is treated as an internal scan error.

Implemented graph analysis lives under `internal/analysis`. It is read-only:
it consumes the in-memory graph and emits structured findings without changing
nodes, edges, parser output, or routing behavior. `PP-K8S-001` requires this
exact directed chain:

`PublicEndpoint --RoutesTo--> Workload --RunsAs--> ServiceAccount --CanRead--> Secret`

The rule does not infer missing relationships. Unresolved roles and unsupported
authorization inputs create no findings unless routing already produced the
required `CanRead` edge. Severity is fixed at `High` for this rule and is not
ML-ranked or score-based.

`PP-GHA-001` requires this exact directed chain:

`Workflow --DefinesJob--> WorkflowJob --UsesAction--> GitHubAction`

The `UsesAction` edge must have static GitHub action metadata with nonempty
owner and repo fields, and the ref must be missing or not exactly 40
hexadecimal characters. Local actions beginning with `./`, Docker actions
beginning with `docker://`, and `uses:` values that are entirely expressions do
not produce findings. Severity is fixed at `Medium`.

`PP-GHA-002` uses the same directed chain. It requires `UsesAction` metadata
showing that the workflow trigger includes `pull_request_target`, the action
identity is exactly `actions/checkout`, and the checkout step has at least one
sanitized PR-head selector match in `with.ref` or `with.repository`. Severity
is fixed at `High`. The rule does not evaluate expressions, inspect run
scripts, execute workflows, or require the checkout action to be unpinned.

`PP-GHA-003` requires a `Workflow` node with sanitized workflow metadata or a
`Workflow --DefinesJob--> WorkflowJob` path with sanitized job metadata. It
requires `pull_request_target` and one explicit dangerous permission grant:
`contents: write`, `pull-requests: write`, `actions: write`, `checks: write`,
`deployments: write`, `id-token: write`, `security-events: write`, or
`permissions: write-all`. Workflow-level and job-level dangerous grants are
reported independently. `permissions: read-all`, `permissions: {}`, read/none
access values, omitted permissions, unknown values, and expression-based
permission values do not produce findings. Exact GitHub permission
inheritance/override modeling is future work.

`PP-AWS-001` requires this exact directed chain:

`AWSIAMRole --GrantsPermission--> AWSPermission`

The `AWSPermission` metadata must be administrative with one of the precise
supported reason identities: `action_star_resource_star`,
`action_service_star_resource_star`, or
`administrator_access_managed_policy`. Inline admin findings require
`Effect: Allow` with `Action "*" Resource "*"` or `Action "*:*" Resource "*"`;
managed-policy findings require the literal AdministratorAccess ARN. The rule
does not evaluate IAM conditions, `NotAction`, variables, modules, locals,
unknown managed policies, customer-managed policies, permission boundaries,
SCPs, or resource-level semantics. Severity is fixed at `High`.

GitHub Actions OIDC token capability modeling is graph-only in this slice.
The analyzer does not emit a finding for `CanRequestOIDCToken` alone because
`id-token: write` is not necessarily vulnerable without additional unsafe
trigger context or cloud trust-policy evidence. Existing `PP-GHA-003` behavior
continues to report `id-token: write` under `pull_request_target`.
`CanAssumeRole` is also not a finding by itself because OIDC trust is not
automatically a vulnerability. `PP-XDOMAIN-001` is emitted only when an
explicitly modeled workflow-level or job-level OIDC capability reaches a
matched AWS IAM role trust and the same workflow/job has a structured
GitHub Actions risk signal from `PP-GHA-002` or `PP-GHA-003`. `PP-XDOMAIN-002`
adds one required graph hop from that same risky pull request OIDC context to
an administrative AWS permission. `PP-XDOMAIN-003` adds one required graph hop
from that same risky pull request OIDC context to explicit modeled S3 bucket
access. The supported `PP-XDOMAIN-001` paths are:

`Workflow --CanRequestOIDCToken--> OIDCTokenCapability --CanAssumeRole--> AWSIAMRole`

and:

`Workflow --DefinesJob--> WorkflowJob --CanRequestOIDCToken--> OIDCTokenCapability --CanAssumeRole--> AWSIAMRole`

The supported `PP-XDOMAIN-002` paths are:

`Workflow --CanRequestOIDCToken--> OIDCTokenCapability --CanAssumeRole--> AWSIAMRole --GrantsPermission--> AWSPermission`

and:

`Workflow --DefinesJob--> WorkflowJob --CanRequestOIDCToken--> OIDCTokenCapability --CanAssumeRole--> AWSIAMRole --GrantsPermission--> AWSPermission`

The supported `PP-XDOMAIN-003` paths are:

`Workflow --CanRequestOIDCToken--> OIDCTokenCapability --CanAssumeRole--> AWSIAMRole --CanReadObject/CanWriteObject--> AWSS3Bucket`

and:

`Workflow --DefinesJob--> WorkflowJob --CanRequestOIDCToken--> OIDCTokenCapability --CanAssumeRole--> AWSIAMRole --CanReadObject/CanWriteObject--> AWSS3Bucket`

Workflow-level dangerous permission risk pairs only with workflow-level OIDC.
Job-level dangerous permission risk pairs only with same-job OIDC. Unsafe
checkout risk is a job/step risk and pairs with same-job OIDC when modeled; it
also pairs with explicit workflow-level OIDC when that workflow-level
capability is modeled. PathProof does not infer exact GitHub permission
inheritance or override behavior. Because the current risk signals are
`pull_request_target` risks, the matched role-assumption edge must use the
`repo:OWNER/REPO:pull_request` subject candidate; branch-only, environment-only,
or other subject matches on the same OIDC capability do not produce these
findings. `PP-XDOMAIN-002` also requires the `AWSPermission` metadata to be
administrative with one of the same supported admin reason identities used by
`PP-AWS-001`.
`PP-XDOMAIN-003` also requires S3 access edge metadata with access mode
`read` or `write` and at least one sanitized matched grant. Admin permissions
alone do not imply S3 access in this slice.

Secret values are excluded by Kubernetes parsing and graph construction.
Analysis preserves graph edge evidence as-is and does not implement generic
redaction.

Implemented remediation planning lives under `internal/remediation`. It is
read-only: it consumes the graph and analysis findings, validates supported
`PP-K8S-001` finding shape and edge continuity, inspects structured `CanRead`
authorization metadata, emits complete advisory Kubernetes options, and emits
advisory `PP-GHA-001` action-pinning options from structured GitHub Actions
action metadata. It does not parse human-readable evidence prose and does not
modify source manifests or workflows. The
implemented actions are `RemoveSecretsResource`, `RemoveSecretReadVerb`, and
`NarrowBindingSubject` for Kubernetes and `PinGitHubActionToSHA` for
`PP-GHA-001`. GitHub Actions action pinning is advisory unless a local
`--github-action-pins` JSON mapping provides the exact original action ref and
an exact 40-character commit SHA. `PP-GHA-002`, `PP-GHA-003`, `PP-AWS-001`,
`PP-XDOMAIN-001`, `PP-XDOMAIN-002`, and `PP-XDOMAIN-003` receive no
remediation plan, patch preview, patch output, or validation result in this
slice.

Optional patch preview generation lives under `internal/patchpreview`. It is
also read-only: it consumes the scan root and remediation plans, resolves
existing `filename#document=N` source references, reads source YAML or
workflow files, and emits deterministic unified diffs only for supported
`NarrowBindingSubject` and safe `PinGitHubActionToSHA` changes. Kubernetes
previews edit only the referenced YAML document in memory. GitHub Actions
previews are text-only replacements at parsed `uses:` scalar coordinates and
replace only the ref after `@`, with no surrounding workflow context in the
diff. Preview generation never writes source files. Unsupported actions,
mismatched source references, namespace-less subjects, single-subject
bindings, source files containing core `v1` Secret payload fields, GitHub
Actions expression refs, imprecise `uses:` source locations, same-line
comments on the patched `uses:` scalar, `uses:` scalars sharing a physical line
with unsafe workflow fields, and workflow files with unsupported or secret-like
context produce `unsupported` preview entries. Harmless workflow `env`, `with`,
and `run` content on other lines does not block no-context `uses:` diffs.

Optional patch output generation also lives under `internal/patchpreview`. It
uses the same in-memory edit logic as preview generation, groups compatible
generated changes by source-relative path, and writes one patched copy per
changed source file under a separate output directory. Kubernetes output uses
the existing YAML document edit path; GitHub Actions output uses the text-only
`uses:` scalar replacement path. It validates input/output directory
relationships before preparing patches, resolving symlinks and nearest
existing parents so output paths cannot write into or under the scan root. It
prepares all patched file contents before creating output files and does not
create the output directory when no generated patch files exist. Source
references may be absolute internally, but scan-root-local source references
are projected as stable relative paths across the CLI report, including
findings, evidence, remediation changes, previews, and patch output summaries.
Unsupported previews are reported but not written. Source files containing
core `v1` Secret payload fields and unsafe workflow files are not copied or
written.

Optional patch validation is private to the CLI orchestration layer. It runs
only after patch output succeeds and remains scoped to `PP-K8S-001`
`NarrowBindingSubject` output. It creates a temporary directory containing the
same top-level YAML/YML files that the Kubernetes parser scans, substitutes
generated Kubernetes patched files by source-relative path, rescans that
complete logical manifest set with the existing parse, route, and analyze
pipeline, and removes the temporary directory before returning. `PP-GHA-001`
patch outputs are not validated in this slice. Validation never scans only the
partial patch output directory, never writes copied input files to the
user-visible output directory, and never prints temporary paths or manifest
contents.

SARIF output is a findings-only CLI projection. `pathproof scan --format sarif`
emits SARIF 2.1.0 with one PathProof tool driver, deterministic rule entries
for `PP-K8S-001`, `PP-GHA-001`, `PP-GHA-002`, `PP-GHA-003`, `PP-AWS-001`,
`PP-XDOMAIN-001`, `PP-XDOMAIN-002`, and `PP-XDOMAIN-003`, and one result per
finding.
SARIF stdout
omits patch previews, patch output
summaries, validation results, unified diffs, patched file contents, temporary
paths, and raw manifests even when patch flags are supplied. Patch
write/validation side effects still follow the same scan flag contract. When
`--write-baseline` is supplied with SARIF output, the baseline file is still
written as a local side effect and SARIF stdout remains findings-only with no
baseline metadata. SARIF
locations use only clean structured `filename#document=N` source-reference
fields; embedded references in prose are ignored. Artifact URIs are relative
to the scan root and URI-encoded, while display source references in result
properties remain relative display strings. SARIF does not guess line numbers
because parser source tracking is currently file/document scoped.

No live Kubernetes authorization evaluation, GitHub API integration, workflow
execution, expression evaluation, reusable workflow resolution, action source
inspection, exact GitHub workflow permission inheritance/override modeling,
full CI/CD attack-path modeling beyond the current GitHub Actions OIDC to AWS
IAM role trust and administrative-role findings, cloud provider integration,
Terraform execution, broad HCL parsing, module or variable evaluation, IAM
simulation, S3 bucket policy analysis, KMS modeling, provider default tag
expansion, S3 object/content discovery, broad data classification,
sensitivity-based findings, live validation, in-place patch application,
persistence, AI, dashboard, plugin system, external service integration, pull
request creation, or live Kubernetes cluster integration is implemented.
