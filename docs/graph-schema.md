# Graph Schema

The graph is currently in-memory and JSON-serializable. Node and edge IDs are
stable deterministic hashes of typed identities.

## Node Kinds

- `PublicEndpoint`: a public Kubernetes Service or Ingress endpoint.
- `Workload`: a Kubernetes Deployment.
- `ServiceAccount`: a Kubernetes ServiceAccount, observed from a manifest or
  inferred from a Deployment reference.
- `Role`: a Kubernetes Role or ClusterRole reachable from a supported
  ServiceAccount RBAC binding. Namespaced Roles use
  `kubernetes://<namespace>/role/<name>`. ClusterRoles use
  `kubernetes://cluster/clusterrole/<name>`.
- `Permission`: a canonical Kubernetes RBAC resource permission. Permission IDs
  are based on a SHA-256 hash of deterministic JSON containing `apiGroups`,
  `resources`, `resourceNames`, and `verbs`.
- `Secret`: a parsed Kubernetes core `v1` Secret metadata object. Secret node
  names use `kubernetes://<namespace>/secret/<name>`. Secret values are never
  ingested or represented in graph nodes.

## Edge Kinds

- `RoutesTo`: a public endpoint routes to a Deployment workload.
- `RunsAs`: a Deployment workload runs as a ServiceAccount.
- `BoundTo`: a ServiceAccount is bound to a Role or ClusterRole by a supported
  RoleBinding or ClusterRoleBinding.
- `GrantsPermission`: an observed Role or ClusterRole rule grants a canonical
  Permission.
- `CanRead`: a ServiceAccount can read a parsed Secret under PathProof's static
  RBAC authorization model.

## Evidence

Nodes store source evidence entries. Edges store one source evidence entry.
Kubernetes routing preserves deterministic source references using
`filename#document=N`.

Secret node evidence preserves every distinct source file and document index
for duplicate manifests with the same namespace/name. Fully identical Secret
source evidence records are deduplicated, and evidence is sorted
deterministically. Secret `data`, `stringData`, and values are never included.

Observed ServiceAccounts use ServiceAccount manifest evidence. Missing
ServiceAccount manifests are represented by inferred ServiceAccount nodes with
Deployment reference evidence. When multiple Deployments reference the same
missing ServiceAccount, inference evidence is deduplicated and sorted
deterministically.

Only ServiceAccounts referenced by Deployments are emitted as graph nodes.
Unreferenced ServiceAccount manifests are parsed but do not create graph nodes
unless they are explicitly named by a supported RBAC binding subject.

RBAC Permission node evidence describes only the canonical permission. If
multiple Roles or ClusterRoles declare the same canonical permission, the graph
contains one shared Permission node and one `GrantsPermission` edge from each
reachable role. Role-specific source evidence is stored on each
`GrantsPermission` edge.

`BoundTo` edge identity is still only the edge kind, ServiceAccount node ID,
and Role node ID. When multiple RoleBindings or ClusterRoleBindings bind the
same ServiceAccount to the same Role or ClusterRole, the graph emits one
canonical `BoundTo` edge with one deterministic evidence record per distinct
binding relationship. Semantically identical duplicate binding manifests are
accepted, and each distinct source occurrence is retained as a separate
evidence record; fully identical evidence records, including source, are
deduplicated. RoleBinding records include
`binding_kind=RoleBinding`, `binding_namespace=<namespace>`,
`binding_name=<name>`, `scope_kind=namespace`, `scope_name=<namespace>`, and
`binding_source=<filename#document=N>`. ClusterRoleBinding records include
`binding_kind=ClusterRoleBinding`, `binding_name=<name>`,
`scope_kind=cluster`, and `binding_source=<filename#document=N>`.

Effective authorization requires combining the Permission reached through the
role's `GrantsPermission` edge with the scope recorded on the ServiceAccount's
`BoundTo` edge. PathProof does not evaluate live Kubernetes authorization.

`CanRead` edges are created directly from canonical parsed RBAC rules, resolved
binding type and scope, resolved ServiceAccount identity, and observed Secret
metadata. Evidence is generated from that decision; evidence strings and
serialized graph output are not inputs to authorization. One canonical
`CanRead` edge is emitted per ServiceAccount/Secret pair. All independent
authorization chains are aggregated into that edge as sorted, deduplicated
evidence records. Each record identifies the binding, role, canonical
permission hash and JSON, matched verb, effective scope, and all observed
source records for the Secret.

PathProof's static Secret read model is:

- `get` or `*` with empty `resourceNames` matches every parsed Secret in the
  effective scope.
- `get` or `*` with nonempty `resourceNames` matches parsed Secrets whose names
  exactly match one listed name.
- `list` or `watch` with empty `resourceNames` matches every parsed Secret in
  the effective scope.
- `list` or `watch` with nonempty `resourceNames` creates no `CanRead` edge
  because request field selectors are not modeled.
- unrelated verbs create no Secret access.

This is static authorization modeling only. It does not claim that a workload
actually issued a Secret read request.

## Findings

Findings are produced by read-only analysis over the in-memory graph. The first
implemented rule is:

- Rule ID: `PP-K8S-001`
- Title: `Public workload can read Kubernetes Secret`
- Severity: fixed `High`
- Required path:
  `PublicEndpoint --RoutesTo--> Workload --RunsAs--> ServiceAccount --CanRead--> Secret`

A finding is emitted only when all four nodes exist with the expected kinds and
all three directed edges exist with the expected kinds. The ordered finding
chain stores the four node IDs followed by the three edge IDs in path order.
Multiple public endpoints, workloads, or Secrets create distinct findings when
they form distinct chains. Multiple independent RBAC authorization records on a
single `CanRead` edge remain attached to the same finding through that edge's
aggregated evidence.

Finding IDs are deterministic and stable. They are SHA-256 hashes of a
canonical JSON identity containing only fixed field names for `rule_id`,
ordered `node_ids`, and ordered `edge_ids`. Evidence, source references,
summary text, title, and severity are not part of finding identity.

Finding evidence preserves the complete ordered edge evidence for `RoutesTo`,
`RunsAs`, and `CanRead`. `source_references` are derived from those edge
evidence sources in chain order, omit empty strings, and deduplicate exact
repeated references while preserving first appearance. They are not globally
sorted.

Secret values are absent from findings because Secret values are never ingested
into parser output or graph evidence. The analyzer does not redact arbitrary
strings from graph evidence.

The scan CLI uses a private presentation projection and does not change the
internal graph or analysis schemas. JSON scan output has this stable top-level
shape:

```json
{
  "findings": [],
  "finding_count": 0
}
```

Each CLI JSON finding includes the finding `id`, `rule_id`, `title`,
`severity`, `summary`, ordered `path`, ordered `evidence`, and
`source_references`. Each path entry contains the graph node `id`, `kind`, and
`name`. Each evidence entry contains `edge_id`, `kind`, `source`, and `detail`.
Path and evidence order match the deterministic analysis chain order.

Observed Roles or ClusterRoles with empty `rules` can still appear as reachable
Role nodes and have `BoundTo` edges, but they create no Permission nodes and no
`GrantsPermission` edges. Missing role references create unresolved Role nodes
only when a supported binding has an explicit ServiceAccount subject namespace;
their evidence is marked unresolved from `roleRef`, and they never create
Permission nodes or `GrantsPermission` edges.

Rules with `nonResourceURLs` are unsupported and skipped entirely for resource
Permission construction. Rules with no `resources` are also skipped. Supported
resource rules in the same Role or ClusterRole are still modeled.

## Current Limitations

The graph and analysis do not model Kubernetes User or Group RBAC subjects,
non-resource URLs, aggregated ClusterRoles, Secret values, live-cluster state,
remediation, or attack-path rules beyond `PP-K8S-001`. The scan CLI currently
supports local Kubernetes YAML directories only.
