# Architecture

PathProof is a small Go CLI with early in-memory graph domain logic. The
current executable lives at `cmd/pathproof` and supports `pathproof version`
and local Kubernetes YAML directory scans with:

- `pathproof scan <directory>`
- `pathproof scan --format json <directory>`
- `pathproof scan --format=json <directory>`
- `pathproof scan --preview-patches <directory>`
- `pathproof scan --write-patches <output-directory> <directory>`

The scan command is intentionally only an orchestration layer. It validates the
local directory input, parses Kubernetes manifests, constructs the in-memory
graph, runs deterministic analysis, builds advisory remediation plans for
supported findings, optionally builds read-only patch previews for supported
remediation changes, optionally writes patched copies for supported generated
previews to a separate output directory, projects findings, plans, previews,
and patch output summaries into a private CLI report shape, and writes either
human-readable output or JSON. It does not persist the graph or expose graph
internals beyond the ordered finding path, evidence, remediation plan fields,
optional preview fields, and optional patch output summaries.

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

Graph storage lives under `internal/graph` and remains in memory. Parsing,
graph storage, routing construction, analysis, and CLI presentation remain
separate. The CLI report projection is private to `cmd/pathproof`; it resolves
analysis finding node IDs back to graph node ID/kind/name values and preserves
finding edge evidence as edge ID/kind/source/detail values. If a finding cannot
be projected against the graph, the scan is treated as an internal scan error.

Implemented graph analysis lives under `internal/analysis`. It is read-only:
it consumes the in-memory graph and emits structured findings without changing
nodes, edges, parser output, or routing behavior. The only implemented rule is
`PP-K8S-001`, which requires this exact directed chain:

`PublicEndpoint --RoutesTo--> Workload --RunsAs--> ServiceAccount --CanRead--> Secret`

The rule does not infer missing relationships. Unresolved roles and unsupported
authorization inputs create no findings unless routing already produced the
required `CanRead` edge. Severity is fixed at `High` for this rule and is not
ML-ranked or score-based.

Secret values are excluded by Kubernetes parsing and graph construction.
Analysis preserves graph edge evidence as-is and does not implement generic
redaction.

Implemented remediation planning lives under `internal/remediation`. It is
read-only: it consumes the graph and analysis findings, validates supported
`PP-K8S-001` finding shape and edge continuity, inspects structured `CanRead`
authorization metadata, and emits complete advisory options. It does not parse
human-readable evidence prose and does not modify source manifests. The
implemented actions are `RemoveSecretsResource`, `RemoveSecretReadVerb`, and
`NarrowBindingSubject`.

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

No live Kubernetes authorization evaluation, verification rescans, in-place
patch application, persistence, AI, dashboard, plugin system, external service
integration, pull request creation, or live Kubernetes cluster integration is
implemented.
