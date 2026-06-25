# Architecture

PathProof is a small Go CLI with early in-memory graph domain logic. The
current executable lives at `cmd/pathproof` and supports `pathproof version`.

Implemented Kubernetes parsing lives under `internal/parser/kubernetes`.
It reads local YAML manifests and emits explicit Go types for supported
resources:

- `Service`
- `Deployment`
- `networking.k8s.io/v1` `Ingress`
- `ServiceAccount`

Implemented Kubernetes routing lives under `internal/routing/kubernetes`.
It builds deterministic graph relationships for:

- public Service or Ingress routes to Deployment workloads,
- Deployment `serviceAccountName` relationships to ServiceAccounts.

Graph storage lives under `internal/graph` and remains in memory. Parsing,
graph storage, and routing construction are separate packages. No attack-path
analysis, verification, remediation, persistence, AI, dashboard, plugin system,
external service integration, or live Kubernetes cluster integration is
implemented.
