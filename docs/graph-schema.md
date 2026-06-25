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
- `Secret`: graph type exists for path tests; Kubernetes Secret parsing and
  routing are not implemented.

## Edge Kinds

- `RoutesTo`: a public endpoint routes to a Deployment workload.
- `RunsAs`: a Deployment workload runs as a ServiceAccount.
- `BoundTo`: a ServiceAccount is bound to a Role or ClusterRole by a supported
  RoleBinding or ClusterRoleBinding.
- `GrantsPermission`: an observed Role or ClusterRole rule grants a canonical
  Permission.
- `CanRead`: graph type exists for path tests; Kubernetes Secret read modeling
  is not implemented.

## Evidence

Nodes store source evidence entries. Edges store one source evidence entry.
Kubernetes routing preserves deterministic source references using
`filename#document=N`.

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

The graph does not model Kubernetes User or Group RBAC subjects, non-resource
URLs, aggregated ClusterRoles, Secrets, live-cluster state, remediation, or
attack-path rules.
