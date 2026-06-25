# Roadmap

## Current

- Tested Go CLI bootstrap.
- Deterministic `pathproof version` command.
- Local Makefile checks and GitHub Actions CI.
- In-memory graph with deterministic IDs and evidence-backed nodes and edges.
- Local Kubernetes YAML parsing for Services, Deployments,
  `networking.k8s.io/v1` Ingresses, and ServiceAccounts.
- Kubernetes routing graph construction for public endpoint routes to
  Deployments and Deployment `RunsAs` ServiceAccount relationships.

## Later

- Deterministic attack-path analysis.
- Parsers for additional infrastructure and supply-chain artifacts.
- Remediation verification.
- Kubernetes RBAC, Secrets, permissions, and live-cluster verification when a
  concrete task requires them.

AI, machine learning, dashboards, graph databases, and pull request automation
remain out of scope until explicitly requested.
