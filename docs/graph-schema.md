# Graph Schema

The graph is currently in-memory and JSON-serializable. Node and edge IDs are
stable deterministic hashes of typed identities.

## Node Kinds

- `PublicEndpoint`: a public Kubernetes Service or Ingress endpoint.
- `Workload`: a Kubernetes Deployment.
- `ServiceAccount`: a Kubernetes ServiceAccount, observed from a manifest or
  inferred from a Deployment reference.
- `Secret`: graph type exists for path tests; Kubernetes Secret parsing and
  routing are not implemented.

## Edge Kinds

- `RoutesTo`: a public endpoint routes to a Deployment workload.
- `RunsAs`: a Deployment workload runs as a ServiceAccount.
- `CanRead`: graph type exists for path tests; Kubernetes RBAC and Secret read
  modeling are not implemented.

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
in the current routing slice.

## Current Limitations

The graph does not model Kubernetes Roles, ClusterRoles, RoleBindings,
ClusterRoleBindings, permissions, Secrets, live-cluster state, remediation, or
attack-path rules.
