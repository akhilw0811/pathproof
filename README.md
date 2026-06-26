# PathProof

PathProof is a defensive, cloud-agnostic attack-path verification engine.

It ingests infrastructure and software-supply-chain artifacts, models security
relationships as an evidence-backed graph, detects attack paths, and will later
prove through rescanning that paths were broken.

## Current milestone

Build a tested Go CLI with the first deterministic, evidence-backed in-memory
graph slice for Kubernetes routing.

Implemented Kubernetes support is intentionally small:

- Parse `Service`, `Deployment`, `networking.k8s.io/v1` `Ingress`, and
  `ServiceAccount` manifests from local YAML files.
- Parse core `v1` `Secret` metadata from local YAML files. Secret `data` and
  `stringData` values are never ingested.
- Parse `rbac.authorization.k8s.io/v1` `Role`, `ClusterRole`,
  `RoleBinding`, and `ClusterRoleBinding` manifests from local YAML files.
- Resolve public Services and Ingresses to Deployment workloads.
- Model each Deployment as running as a ServiceAccount, using observed
  ServiceAccount manifests when present and inferred accounts when missing.
- Model ServiceAccount RBAC bindings to Roles or ClusterRoles and the
  deterministic resource permissions granted by reachable observed roles.
- Model static RBAC-derived `CanRead` relationships from ServiceAccounts to
  parsed Secrets when scoped rules allow supported Secret read access.
- Analyze the in-memory graph for `PP-K8S-001`, which reports when a public
  Kubernetes endpoint routes to a workload, that workload runs as a
  ServiceAccount, and that ServiceAccount can read a parsed Secret.

`PP-K8S-001` findings use fixed rule-based `High` severity. Finding IDs are
deterministic hashes of the rule ID, ordered node IDs, and ordered edge IDs.
Secret values are excluded by Kubernetes parsing and graph construction; the
analysis layer preserves graph evidence and does not redact arbitrary content.

## Usage

```sh
go run ./cmd/pathproof version
```

Expected output:

```text
pathproof dev
```

## Development

```sh
make check
make build
```

The built binary is written to `bin/pathproof`.

## Not currently in scope

- Terraform parsing
- GitHub Actions parsing
- SBOM parsing
- Kubernetes Secret values, live-cluster verification, or remediation
- CLI integration for attack-path analysis
- Kubernetes RBAC User and Group subjects, non-resource URLs, aggregated
  ClusterRoles, and live authorization evaluation
- AI agents
- Machine learning
- Dashboard
- Graph database
- GitHub pull request creation
