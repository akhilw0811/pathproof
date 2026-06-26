# Roadmap

## Current

- Tested Go CLI bootstrap.
- Deterministic `pathproof version` command.
- Local Makefile checks and GitHub Actions CI.
- In-memory graph with deterministic IDs and evidence-backed nodes and edges.
- Local Kubernetes YAML parsing for Services, Deployments,
  `networking.k8s.io/v1` Ingresses, ServiceAccounts, core `v1` Secret
  metadata, and
  `rbac.authorization.k8s.io/v1` RBAC Roles, ClusterRoles, RoleBindings, and
  ClusterRoleBindings.
- Kubernetes routing graph construction for public endpoint routes to
  Deployments and Deployment `RunsAs` ServiceAccount relationships.
- Kubernetes RBAC graph construction for explicit ServiceAccount subjects,
  reachable Roles and ClusterRoles, scoped bindings, and deterministic
  resource Permissions.
- Kubernetes Secret graph construction for parsed Secret metadata and static
  RBAC-derived ServiceAccount `CanRead` edges. Secret values are never
  ingested.
- Read-only deterministic attack-path analysis for `PP-K8S-001`: public
  endpoint to workload to ServiceAccount to Secret read access, with fixed
  rule-based `High` severity and deterministic finding IDs.

## Later

- CLI integration for attack-path analysis.
- Additional deterministic attack-path rules.
- Parsers for additional infrastructure and supply-chain artifacts.
- Remediation verification.
- Kubernetes RBAC User and Group subjects, non-resource URLs, aggregated
  ClusterRoles, Secret values, broader Secret attack-path coverage,
  live-cluster authorization verification, and remediation when a concrete task
  requires them.

AI, machine learning, dashboards, graph databases, and pull request automation
remain out of scope until explicitly requested.
