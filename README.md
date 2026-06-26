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
- Run the local scan pipeline from the CLI for Kubernetes YAML directories.

`PP-K8S-001` findings use fixed rule-based `High` severity. Finding IDs are
deterministic hashes of the rule ID, ordered node IDs, and ordered edge IDs.
Secret values are excluded by Kubernetes parsing and graph construction; the
analysis layer preserves graph evidence and does not redact arbitrary content.

## Usage

```sh
go run ./cmd/pathproof version
go run ./cmd/pathproof scan ./cmd/pathproof/testdata/scan-safe
go run ./cmd/pathproof scan --format json ./cmd/pathproof/testdata/scan-vulnerable
go run ./cmd/pathproof scan --format=json ./cmd/pathproof/testdata/scan-vulnerable
```

`pathproof scan` currently supports only local directories containing
Kubernetes YAML manifests. Human-readable output is the default. JSON output
uses a stable top-level shape:

```json
{
  "findings": [],
  "finding_count": 0
}
```

Each JSON finding contains the finding ID, rule ID, title, severity, summary,
ordered `path`, ordered `evidence`, and source references. Each path entry
contains node `id`, `kind`, and `name`. Each evidence entry contains `edge_id`,
`kind`, `source`, and `detail`.

Scan exit codes are stable:

- `0`: scan succeeded and found zero findings.
- `1`: scan succeeded and found one or more findings.
- `2`: usage, parsing, routing, output, or internal scan error.

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
- Kubernetes RBAC User and Group subjects, non-resource URLs, aggregated
  ClusterRoles, and live authorization evaluation
- AI agents
- Machine learning
- Dashboard
- Graph database
- GitHub pull request creation
