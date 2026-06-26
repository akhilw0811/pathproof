# Architecture

PathProof is a small Go CLI with early in-memory graph domain logic. The
current executable lives at `cmd/pathproof` and supports `pathproof version`
and local Kubernetes YAML directory scans with:

- `pathproof scan <directory>`
- `pathproof scan --format json <directory>`
- `pathproof scan --format=json <directory>`

The scan command is intentionally only an orchestration layer. It validates the
local directory input, parses Kubernetes manifests, constructs the in-memory
graph, runs deterministic analysis, projects findings into a private CLI report
shape, and writes either human-readable output or JSON. It does not persist the
graph or expose graph internals beyond the ordered finding path and evidence.

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
redaction. No live Kubernetes authorization evaluation, verification,
remediation, persistence, AI, dashboard, plugin system, external service
integration, or live Kubernetes cluster integration is implemented.
