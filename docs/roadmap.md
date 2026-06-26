# Roadmap

## Current

- Tested Go CLI bootstrap.
- Deterministic `pathproof version` command.
- Local Makefile checks and GitHub Actions CI that builds, tests, generates a
  demo `pathproof.sarif`, and uploads it as a workflow artifact.
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
- Local GitHub Actions workflow parsing under `.github/workflows` for
  workflow name, `pull_request` and `pull_request_target` trigger presence,
  static push branch literals and static job environment names for OIDC
  subject matching, sanitized workflow-level and job-level permission grants,
  job IDs, step indexes, optional step names, sanitized static action
  identities, and sanitized `actions/checkout` PR-head selector matches.
  Workflow env values, arbitrary with values, secrets, token values, run
  scripts, expression-only `uses:` values, unknown or expression-based
  permission values, dynamic branch/environment expressions, and raw workflow
  documents are not retained.
- Minimal GitHub Actions graph construction with `Workflow`, `WorkflowJob`,
  `GitHubAction`, `DefinesJob`, and `UsesAction`. `Workflow` and `DefinesJob`
  metadata preserve sanitized explicit permission grants for the current
  GitHub Actions rules.
- Graph-only GitHub Actions OIDC token capability modeling with
  `OIDCTokenCapability` nodes and `CanRequestOIDCToken` edges for explicit
  workflow-level or job-level `id-token: write`, including
  `permissions: write-all`. This does not create a finding by itself.
- Local static Terraform parsing for `aws_iam_role` resources whose
  `assume_role_policy` is a literal heredoc or simple quoted JSON trust
  policy. The parser extracts only sanitized GitHub Actions OIDC trust
  metadata and ignores variables, locals, modules, data sources, `jsonencode`,
  function calls, interpolation, dynamic blocks, nonliteral policies, and
  `aws_iam_policy_document`.
- Local static Terraform parsing for a narrow AWS IAM role permission slice:
  supported `aws_iam_role_policy` JSON attached to parsed roles by direct
  resource reference or an unambiguous explicit static role name, plus
  `aws_iam_role_policy_attachment` only for the literal AWS managed
  AdministratorAccess policy ARN. Raw policy JSON, unsupported managed
  policies, variables, conditions, `NotAction`, provider credentials, access
  keys, and secret-like values are not retained.
- AWS IAM OIDC trust modeling with `AWSIAMRole` nodes and optional
  `OIDCTokenCapability --CanAssumeRole--> AWSIAMRole` edges when
  `pathproof scan --repo OWNER/REPO` supplies repository identity and a static
  GitHub Actions subject candidate matches the trust policy. This trust edge
  does not create a finding by itself.
- AWS IAM role permission modeling with `AWSPermission` nodes and
  `AWSIAMRole --GrantsPermission--> AWSPermission` edges for supported static
  local Terraform permission facts.
- Read-only deterministic attack-path analysis for `PP-K8S-001`: public
  endpoint to workload to ServiceAccount to Secret read access, with fixed
  rule-based `High` severity and deterministic finding IDs.
- Read-only deterministic GitHub Actions analysis for `PP-GHA-001`: workflow
  action references not pinned to exactly 40 hexadecimal commit characters,
  with fixed rule-based `Medium` severity and deterministic finding IDs.
- Read-only deterministic GitHub Actions analysis for `PP-GHA-002`:
  `pull_request_target` workflows that configure `actions/checkout` to check
  out pull request head code, with fixed rule-based `High` severity and
  deterministic finding IDs.
- Read-only deterministic GitHub Actions analysis for `PP-GHA-003`:
  `pull_request_target` workflows that explicitly grant dangerous
  workflow-level or job-level token permissions, with fixed rule-based `High`
  severity and deterministic finding IDs. Exact GitHub permission
  inheritance/override modeling is not implemented.
- Read-only deterministic AWS IAM analysis for `PP-AWS-001`: local Terraform
  AWS IAM roles with obviously administrative static permissions, limited to
  inline `Allow` `Action "*"` or `"*:*"` with `Resource "*"`, or the literal
  AdministratorAccess managed policy attachment. This calls no cloud APIs,
  performs no IAM simulation, and has no remediation.
- Read-only deterministic cross-domain analysis for `PP-XDOMAIN-001`: risky
  GitHub Actions workflow or job OIDC capability can assume a locally modeled
  AWS IAM role through a statically parsed OIDC trust. This first slice uses
  only existing graph edges and structured PP-GHA-002/PP-GHA-003 risk metadata,
  calls no cloud APIs, performs no IAM simulation, and has no remediation.
- Read-only deterministic remediation planning for `PP-K8S-001`, using typed
  structured `CanRead` authorization metadata. Implemented advisory actions are
  `RemoveSecretsResource`, `RemoveSecretReadVerb`, and `NarrowBindingSubject`.
  Plans contain only complete options; multi-chain Secret read access requires
  coordinated changes in one option.
- Opt-in read-only patch previews for `NarrowBindingSubject`, limited to exact
  ServiceAccount subject removal from the referenced RoleBinding or
  ClusterRoleBinding source document. Secret-bearing source files are
  intentionally unsupported for previews.
- Opt-in patch output for generated `NarrowBindingSubject` previews. Patched
  copies are written only to a separate new or empty output directory, input
  files are never modified, unsupported actions are reported but not written,
  and Secret-bearing source files are not copied or written.
- Opt-in validation rescan for written `NarrowBindingSubject` patch output.
  Validation builds a temporary complete patched manifest set from the input
  directory plus generated patch files, rescans it locally, and reports
  remediated, failed, or skipped results for supported `PP-K8S-001` findings.
- Local Kubernetes YAML, GitHub Actions workflow, and narrow Terraform scan CLI for
  `pathproof scan <directory>` with human-readable finding, supported
  Kubernetes remediation and optional patch preview output, optional
  `--repo OWNER/REPO` OIDC trust matching, JSON output, SARIF 2.1.0 finding
  output, and stable exit codes.
- Local findings-only SARIF export for `PP-K8S-001`, `PP-GHA-001`, and
  `PP-GHA-002`, `PP-GHA-003`, `PP-AWS-001`, and `PP-XDOMAIN-001`. SARIF
  artifact locations use safe relative URIs when clean structured source
  references are available.

## Later

- Additional deterministic attack-path rules.
- Parsers for additional infrastructure and supply-chain artifacts.
- Full CI/CD attack-path modeling.
- Exact GitHub Actions workflow permission inheritance/override modeling.
- Broad Terraform/HCL support, modules, variables, locals, functions,
  interpolation, `jsonencode`, and `aws_iam_policy_document`.
- Cloud provider API validation for OIDC providers, accounts, ARNs, and roles.
- IAM simulation, broad IAM condition evaluation, permission boundaries, SCPs,
  full managed-policy catalogs, customer-managed policy resolution, and
  resource-level IAM evaluation.
- Additional GitHub Actions OIDC trust findings beyond the first
  PP-XDOMAIN-001 slice.
- Broader cloud trust-policy ingestion for GitHub Actions OIDC.
- Reusable workflow resolution.
- CI/CD-to-cloud path analysis.
- Cross-domain admin-path finding from risky GitHub Actions workflow to AWS
  IAM role administrative permissions.
- Action source inspection.
- Automatic GitHub Actions action pinning patches.
- Automatic GitHub Actions remediation for unsafe `pull_request_target`
  checkout patterns.
- Automatic GitHub Actions remediation for dangerous workflow permissions.
- Remediation verification.
- In-place patch application, live validation, force/clobber behavior, Git
  commits, and pull request creation.
- GitHub code scanning upload, automatic PR comments, enforced policy gates, or
  other SARIF upload integrations.
- Patch previews for RBAC rule edits, wildcard resources or verbs,
  multi-resource rule splitting, API-group splitting, ClusterRoleBinding scope
  changes, `resourceNames`, Secret-bearing source files, and broader patch
  types.
- Patch output for RBAC rule edits, wildcard resources or verbs,
  multi-resource rule splitting, API-group splitting, ClusterRoleBinding scope
  changes, `resourceNames`, Secret-bearing source files, and broader patch
  types.
- Kubernetes RBAC User and Group subjects, non-resource URLs, aggregated
  ClusterRoles, Secret values, broader Secret attack-path coverage,
  live-cluster authorization verification, and remediation when a concrete task
  requires them.

AI, machine learning, dashboards, graph databases, and pull request automation
remain out of scope until explicitly requested.
