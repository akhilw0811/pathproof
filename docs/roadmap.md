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
- Read-only deterministic remediation planning for `PP-K8S-001`, using typed
  structured `CanRead` authorization metadata. Implemented advisory actions are
  `RemoveSecretsResource`, `RemoveSecretReadVerb`, and `NarrowBindingSubject`.
  Plans contain only complete options; multi-chain Secret read access requires
  coordinated changes in one option.
- Opt-in read-only patch previews for `NarrowBindingSubject`, limited to exact
  ServiceAccount subject removal from the referenced RoleBinding or
  ClusterRoleBinding source document. Secret-bearing source files are
  intentionally unsupported for previews.
- Local Kubernetes YAML scan CLI for `pathproof scan <directory>` with
  human-readable finding, remediation, and optional patch preview output, JSON
  output, and stable exit codes.

## Later

- Additional deterministic attack-path rules.
- Parsers for additional infrastructure and supply-chain artifacts.
- Remediation verification.
- Patch application, validation rescans, and pull request creation.
- Patch previews for RBAC rule edits, wildcard resources or verbs,
  multi-resource rule splitting, API-group splitting, ClusterRoleBinding scope
  changes, `resourceNames`, Secret-bearing source files, and broader patch
  types.
- Kubernetes RBAC User and Group subjects, non-resource URLs, aggregated
  ClusterRoles, Secret values, broader Secret attack-path coverage,
  live-cluster authorization verification, and remediation when a concrete task
  requires them.

AI, machine learning, dashboards, graph databases, and pull request automation
remain out of scope until explicitly requested.
