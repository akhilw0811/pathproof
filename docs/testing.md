# Testing

Run the standard local checks before reporting a completed change:

```sh
make fmt
make test
make test-race
make lint
make test-integration
make check
make build
```

The bootstrap CLI is tested through `cmd/pathproof` unit tests and a minimal
integration check that runs `go run ./cmd/pathproof version`.

Kubernetes parser tests cover supported manifest parsing, defaulting,
multi-document source tracking, deterministic ordering, malformed YAML errors,
and `rbac.authorization.k8s.io/v1` RBAC parsing for Roles, ClusterRoles,
RoleBindings, ClusterRoleBindings, ServiceAccount-only subjects, roleRefs, and
canonical resource permission fields. Parser coverage also verifies
deterministic parsing of unsupported `nonResourceURLs` so routing can skip
those rules. Secret parser tests cover core `v1` metadata-only parsing,
default namespaces, unsupported Secret API version skipping before typed
decoding, deterministic ordering, duplicate source preservation, and regression
checks that Secret `data`, `stringData`, and values are absent from serialized
parser output and parse errors.

Kubernetes routing tests cover deterministic graph construction, source
evidence, duplicate conflict rejection before graph mutation, namespace-scoped
matching, observed and inferred ServiceAccount provenance, and preservation of
existing Service and Ingress exposure behavior. RBAC routing tests cover
ServiceAccount bindings to Roles and ClusterRoles, cross-namespace
RoleBinding subjects with explicit namespaces, unresolved namespace-less
subjects, unsupported roleRefs, unresolved roles, scoped `BoundTo` evidence,
canonical Permission IDs, shared Permission nodes, empty observed roles,
multi-scope `BoundTo` evidence aggregation, skipped non-resource URL rules,
empty-resource rules, semantic duplicate binding source preservation, and RBAC
duplicate conflict handling. Secret access routing tests cover Secret node
source aggregation, static RBAC `CanRead` authorization for `get`, `list`,
`watch`, and `*`, `resourceNames` limits, RoleBinding and ClusterRoleBinding
scope, unsupported inputs, deterministic evidence aggregation, duplicate
evidence deduplication, conflict atomicity, and regression checks that Secret
values are absent from graph JSON and evidence.

Tests must cover positive and negative behavior for changed packages. Do not
skip, remove, or weaken tests to make a change pass.
