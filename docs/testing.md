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
multi-document source tracking, deterministic ordering, and malformed YAML
errors.

Kubernetes routing tests cover deterministic graph construction, source
evidence, duplicate conflict rejection before graph mutation, namespace-scoped
matching, observed and inferred ServiceAccount provenance, and preservation of
existing Service and Ingress exposure behavior.

Tests must cover positive and negative behavior for changed packages. Do not
skip, remove, or weaken tests to make a change pass.
