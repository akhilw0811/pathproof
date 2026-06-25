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
those rules.

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
duplicate conflict handling.

Tests must cover positive and negative behavior for changed packages. Do not
skip, remove, or weaken tests to make a change pass.
