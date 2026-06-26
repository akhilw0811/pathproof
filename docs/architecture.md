# Architecture

PathProof is a small Go CLI with early in-memory graph domain logic. The
current executable lives at `cmd/pathproof` and supports `pathproof version`
and local directory scans with:

- `pathproof scan <directory>`
- `pathproof scan --format json <directory>`
- `pathproof scan --format=json <directory>`
- `pathproof scan --format sarif <directory>`
- `pathproof scan --preview-patches <directory>`
- `pathproof scan --write-patches <output-directory> <directory>`
- `pathproof scan --write-patches <output-directory> --validate-patches <directory>`

The scan command is intentionally only an orchestration layer. It validates the
local directory input, parses Kubernetes manifests and local GitHub Actions
workflows under `.github/workflows`, constructs the in-memory graph, runs
deterministic analysis, builds advisory remediation plans for supported
Kubernetes findings, optionally builds read-only patch previews for supported
remediation changes, optionally writes patched copies for supported generated
previews to a separate output directory, optionally validates written patches
by rescanning a temporary complete patched manifest overlay, projects findings,
plans, previews, patch output summaries, and validation results into a private
CLI report shape, and writes human-readable output, JSON, or SARIF. It does
not persist the graph or expose graph internals beyond the ordered finding
path, evidence, remediation plan fields, optional preview fields, optional
patch output summaries, optional validation results, and SARIF finding
projection.

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
workflow name, workflow source, `pull_request_target` trigger presence,
sanitized workflow-level and job-level permission grants, job IDs, step
indexes, optional step names, and sanitized static action identity components.
For `actions/checkout` steps only, it also records sanitized matches for the
PR-head selector expressions used by `PP-GHA-002`. It does not require a Git
repository, call GitHub APIs, execute workflows, evaluate expressions, resolve
reusable workflows, inspect action source code, model exact workflow
permission inheritance or overrides, expand matrices, or retain `env`,
arbitrary `with` values, `secrets`, token values, run scripts,
expression-only `uses:` values, unknown permission values, or raw workflow
documents. A `uses:` value that is entirely an expression is ignored because it
is not a statically recognizable action reference. If a `uses:` value has a
static `owner/repo` shape but an expression in the ref, the ref is stored as a
sanitized expression marker and treated as unpinned.

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

GitHub Actions OIDC token capability modeling is graph-only in this slice.
The analyzer does not emit a finding for `CanRequestOIDCToken` alone because
`id-token: write` is not necessarily vulnerable without additional unsafe
trigger context or cloud trust-policy evidence. Existing `PP-GHA-003` behavior
continues to report `id-token: write` under `pull_request_target`.

Secret values are excluded by Kubernetes parsing and graph construction.
Analysis preserves graph edge evidence as-is and does not implement generic
redaction.

Implemented remediation planning lives under `internal/remediation`. It is
read-only: it consumes the graph and analysis findings, validates supported
`PP-K8S-001` finding shape and edge continuity, inspects structured `CanRead`
authorization metadata, and emits complete advisory options. It does not parse
human-readable evidence prose and does not modify source manifests. The
implemented actions are `RemoveSecretsResource`, `RemoveSecretReadVerb`, and
`NarrowBindingSubject`. `PP-GHA-001`, `PP-GHA-002`, and `PP-GHA-003` receive
no remediation plan, patch preview, patch output, or validation result in this
slice.

Optional patch preview generation lives under `internal/patchpreview`. It is
also read-only: it consumes the scan root and remediation plans, resolves
existing `filename#document=N` source references, reads source YAML, and emits
deterministic unified diffs only for `NarrowBindingSubject` changes that remove
one exact ServiceAccount subject from a multi-subject `RoleBinding` or
`ClusterRoleBinding`. It edits only the referenced YAML document in memory and
never writes source files. Unsupported actions, mismatched source references,
namespace-less subjects, single-subject bindings, and source files containing
core `v1` Secret payload fields produce `unsupported` preview entries.

Optional patch output generation also lives under `internal/patchpreview`. It
uses the same in-memory YAML edit logic as preview generation, groups
compatible generated `NarrowBindingSubject` changes by source-relative path,
and writes one patched copy per changed source file under a separate output
directory. It validates input/output directory relationships before preparing
patches, resolving symlinks and nearest existing parents so output paths cannot
write into or under the scan root. It prepares all patched file contents before
creating output files and does not create the output directory when no
generated patch files exist. Source references may be absolute internally, but
scan-root-local source references are projected as stable relative paths across
the CLI report, including findings, evidence, remediation changes, previews,
and patch output summaries. Unsupported previews are reported but not written.
Source files containing core `v1` Secret payload fields are not copied or
written.

Optional patch validation is private to the CLI orchestration layer. It runs
only after patch output succeeds, creates a temporary directory containing the
same top-level YAML/YML files that the parser scans, substitutes generated
patched files by source-relative path, rescans that complete logical manifest
set with the existing parse, route, and analyze pipeline, and removes the
temporary directory before returning. Validation never scans only the partial
patch output directory, never writes copied input files to the user-visible
output directory, and never prints temporary paths or manifest contents.

SARIF output is a findings-only CLI projection. `pathproof scan --format sarif`
emits SARIF 2.1.0 with one PathProof tool driver, deterministic rule entries
for `PP-K8S-001`, `PP-GHA-001`, `PP-GHA-002`, and `PP-GHA-003`, and one result
per finding.
SARIF stdout
omits patch previews, patch output
summaries, validation results, unified diffs, patched file contents, temporary
paths, and raw manifests even when patch flags are supplied. Patch
write/validation side effects still follow the same scan flag contract. SARIF
locations use only clean structured `filename#document=N` source-reference
fields; embedded references in prose are ignored. Artifact URIs are relative
to the scan root and URI-encoded, while display source references in result
properties remain relative display strings. SARIF does not guess line numbers
because parser source tracking is currently file/document scoped.

No live Kubernetes authorization evaluation, GitHub API integration, workflow
execution, expression evaluation, reusable workflow resolution, action source
inspection, exact GitHub workflow permission inheritance/override modeling,
OIDC trust-policy modeling, full CI/CD attack-path modeling, cloud provider
integration, Terraform parsing, live validation, in-place patch application,
persistence, AI, dashboard, plugin system, external service integration, pull
request creation, or live Kubernetes cluster integration is implemented.
