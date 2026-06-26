# Graph Schema

The graph is currently in-memory and JSON-serializable. Node and edge IDs are
stable deterministic hashes of typed identities.

## Node Kinds

- `PublicEndpoint`: a public Kubernetes Service or Ingress endpoint.
- `Workload`: a Kubernetes Deployment.
- `ServiceAccount`: a Kubernetes ServiceAccount, observed from a manifest or
  inferred from a Deployment reference.
- `Role`: a Kubernetes Role or ClusterRole reachable from a supported
  ServiceAccount RBAC binding. Namespaced Roles use
  `kubernetes://<namespace>/role/<name>`. ClusterRoles use
  `kubernetes://cluster/clusterrole/<name>`.
- `Permission`: a canonical Kubernetes RBAC resource permission. Permission IDs
  are based on a SHA-256 hash of deterministic JSON containing `apiGroups`,
  `resources`, `resourceNames`, and `verbs`.
- `Secret`: a parsed Kubernetes core `v1` Secret metadata object. Secret node
  names use `kubernetes://<namespace>/secret/<name>`. Secret values are never
  ingested or represented in graph nodes.
- `Workflow`: a local GitHub Actions workflow file under `.github/workflows`.
  Workflow node names use `githubactions://<relative-workflow-path>`.
- `WorkflowJob`: a GitHub Actions job in a parsed workflow. Job node names use
  `githubactions://<relative-workflow-path>/job/<job_id>`.
- `GitHubAction`: one parsed workflow step with a `uses:` value. Action node
  names include the relative workflow path, job ID, step index, and raw
  `uses:` value.
- `OIDCTokenCapability`: a local GitHub Actions workflow or job capability to
  request an OIDC token. Workflow-level node names use
  `githubactions://<relative-workflow-path>/oidc-token/workflow`. Job-level
  node names use
  `githubactions://<relative-workflow-path>/job/<job_id>/oidc-token`.

## Edge Kinds

- `RoutesTo`: a public endpoint routes to a Deployment workload.
- `RunsAs`: a Deployment workload runs as a ServiceAccount.
- `BoundTo`: a ServiceAccount is bound to a Role or ClusterRole by a supported
  RoleBinding or ClusterRoleBinding.
- `GrantsPermission`: an observed Role or ClusterRole rule grants a canonical
  Permission.
- `CanRead`: a ServiceAccount can read a parsed Secret under PathProof's static
  RBAC authorization model.
- `DefinesJob`: a GitHub Actions workflow defines a job.
- `UsesAction`: a GitHub Actions job step uses an action reference.
- `CanRequestOIDCToken`: a GitHub Actions workflow or job can request an OIDC
  token because it explicitly grants `id-token: write` or
  `permissions: write-all`.

## Evidence

Nodes store source evidence entries. Edges store one source evidence entry.
Kubernetes routing preserves deterministic source references using
`filename#document=N`.

Secret node evidence preserves every distinct source file and document index
for duplicate manifests with the same namespace/name. Fully identical Secret
source evidence records are deduplicated, and evidence is sorted
deterministically. Secret `data`, `stringData`, and values are never included.

Observed ServiceAccounts use ServiceAccount manifest evidence. Missing
ServiceAccount manifests are represented by inferred ServiceAccount nodes with
Deployment reference evidence. When multiple Deployments reference the same
missing ServiceAccount, inference evidence is deduplicated and sorted
deterministically.

Only ServiceAccounts referenced by Deployments are emitted as graph nodes.
Unreferenced ServiceAccount manifests are parsed but do not create graph nodes
unless they are explicitly named by a supported RBAC binding subject.

RBAC Permission node evidence describes only the canonical permission. If
multiple Roles or ClusterRoles declare the same canonical permission, the graph
contains one shared Permission node and one `GrantsPermission` edge from each
reachable role. Role-specific source evidence is stored on each
`GrantsPermission` edge.

`BoundTo` edge identity is still only the edge kind, ServiceAccount node ID,
and Role node ID. When multiple RoleBindings or ClusterRoleBindings bind the
same ServiceAccount to the same Role or ClusterRole, the graph emits one
canonical `BoundTo` edge with one deterministic evidence record per distinct
binding relationship. Semantically identical duplicate binding manifests are
accepted, and each distinct source occurrence is retained as a separate
evidence record; fully identical evidence records, including source, are
deduplicated. RoleBinding records include
`binding_kind=RoleBinding`, `binding_namespace=<namespace>`,
`binding_name=<name>`, `scope_kind=namespace`, `scope_name=<namespace>`, and
`binding_source=<filename#document=N>`. ClusterRoleBinding records include
`binding_kind=ClusterRoleBinding`, `binding_name=<name>`,
`scope_kind=cluster`, and `binding_source=<filename#document=N>`.

Effective authorization requires combining the Permission reached through the
role's `GrantsPermission` edge with the scope recorded on the ServiceAccount's
`BoundTo` edge. PathProof does not evaluate live Kubernetes authorization.

`CanRead` edges are created directly from canonical parsed RBAC rules, resolved
binding type and scope, resolved ServiceAccount identity, and observed Secret
metadata. Evidence is generated from that decision; evidence strings and
serialized graph output are not inputs to authorization. One canonical
`CanRead` edge is emitted per ServiceAccount/Secret pair. All independent
authorization chains are aggregated into that edge as sorted, deduplicated
evidence records. Each record identifies the binding, role, canonical
permission hash and JSON, matched verb, effective scope, and all observed
source records for the Secret.

`CanRead` edges also include optional typed metadata:

```json
{
  "metadata": {
    "kubernetes_can_read_authorizations": [
      {
        "binding_kind": "RoleBinding",
        "binding_namespace": "prod",
        "binding_name": "read-secrets",
        "binding_source_reference": "resources.yaml#document=6",
        "binding_supported_service_account_count": 1,
        "service_account_namespace": "prod",
        "service_account_name": "api",
        "role_kind": "Role",
        "role_namespace": "prod",
        "role_name": "secret-reader",
        "role_source_reference": "resources.yaml#document=5",
        "permission_sha256": "...",
        "permission": {
          "apiGroups": [""],
          "resources": ["secrets"],
          "resourceNames": null,
          "verbs": ["get"]
        },
        "matched_verb": "get",
        "scope_kind": "namespace",
        "scope_name": "prod",
        "secret_namespace": "prod",
        "secret_name": "database-password",
        "secret_source_references": ["resources.yaml#document=4"]
      }
    ]
  }
}
```

This metadata is the remediation planner's input. The planner does not parse
the aggregated evidence prose. Metadata contains only deterministic identities,
source references, canonical permission fields, and matched authorization
facts. It never includes Secret values, raw manifests, YAML snippets, or
arbitrary metadata maps.

`UsesAction` edges include optional typed metadata:

```json
{
  "metadata": {
    "github_action_use": {
      "workflow_source_reference": ".github/workflows/build.yml#document=1",
      "workflow_file": ".github/workflows/build.yml",
      "workflow_name": "Build",
      "triggers_pull_request_target": true,
      "job_id": "test",
      "step_index": 0,
      "step_name": "Checkout",
      "uses": "actions/checkout@v4",
      "owner": "actions",
      "repo": "checkout",
      "path": "",
      "ref": "v4",
      "checkout_head_selectors": [
        {
          "field": "ref",
          "matched_expression": "github.event.pull_request.head.sha"
        }
      ]
    }
  }
}
```

This metadata is the input for `PP-GHA-001` and `PP-GHA-002`. It contains only
deterministic workflow source identity, sanitized static action identity, the
`pull_request_target` trigger boolean, and sanitized checkout selector matches.
GitHub Actions parsing does not retain or serialize `env` values, arbitrary
`with` values, `secrets`, token values, run scripts, expression-only `uses:`
values, or raw workflow documents. PathProof does not evaluate GitHub
expressions. A `uses:` value that is entirely an expression is not modeled as a
static action reference; a static `owner/repo` with an expression in the ref is
modeled with a sanitized expression marker and treated as unpinned.

`Workflow` nodes include optional typed GitHub Actions metadata:

```json
{
  "metadata": {
    "github_actions_workflow": {
      "workflow_source_reference": ".github/workflows/build.yml#document=1",
      "workflow_file": ".github/workflows/build.yml",
      "workflow_name": "Build",
      "triggers_pull_request_target": true,
      "permission_grants": [
        {
          "scope": "workflow",
          "permission": "all",
          "access": "write-all"
        }
      ]
    }
  }
}
```

`DefinesJob` edges include optional typed GitHub Actions job metadata:

```json
{
  "metadata": {
    "github_actions_workflow_job": {
      "workflow_source_reference": ".github/workflows/build.yml#document=1",
      "workflow_file": ".github/workflows/build.yml",
      "workflow_name": "Build",
      "triggers_pull_request_target": true,
      "job_id": "test",
      "permission_grants": [
        {
          "scope": "job",
          "job_id": "test",
          "permission": "contents",
          "access": "write"
        }
      ]
    }
  }
}
```

This metadata is the input for `PP-GHA-003`. It contains only deterministic
workflow source identity, `pull_request_target` trigger presence, job identity
when applicable, and sanitized permission key/access pairs. Scalar
`permissions: write-all` is represented as `permission="all"` and
`access="write-all"`; `permissions: read-all` is represented as
`permission="all"` and `access="read-all"`. User-facing summaries and SARIF
messages render these scalar forms as `permissions: write-all` or
`permissions: read-all`, not as `all: write`. GitHub Actions parsing does not
retain or serialize unknown permission values, expression-based permission
values, `env`, arbitrary `with`, `secrets`, token values, run scripts, or raw
workflow documents.

`OIDCTokenCapability` nodes include optional typed GitHub Actions OIDC
capability metadata:

```json
{
  "metadata": {
    "github_actions_oidc_token_capability": {
      "provider": "github-actions",
      "workflow_source_reference": ".github/workflows/deploy.yml#document=1",
      "workflow_file": ".github/workflows/deploy.yml",
      "workflow_name": "Deploy",
      "scope": "job",
      "job_id": "deploy"
    }
  }
}
```

`CanRequestOIDCToken` edges include optional typed request metadata:

```json
{
  "metadata": {
    "github_actions_oidc_token_request": {
      "provider": "github-actions",
      "workflow_source_reference": ".github/workflows/deploy.yml#document=1",
      "workflow_file": ".github/workflows/deploy.yml",
      "workflow_name": "Deploy",
      "scope": "job",
      "job_id": "deploy",
      "permission": "id-token",
      "access": "write"
    }
  }
}
```

The edge evidence detail preserves the source of the capability. Explicit
`id-token: write` evidence says the workflow or job can request an OIDC token
with `id-token: write`. `permissions: write-all` evidence says the workflow or
job can request an OIDC token because `permissions: write-all` includes
`id-token: write`; it is not rendered as though `id-token: write` was
explicitly declared. This metadata contains only sanitized workflow identity,
scope, job identity when applicable, provider, and modeled permission/access.
It does not include secrets, environment values, arbitrary `with` values, run
scripts, raw YAML, OIDC claims, JWTs, cloud trust policies, or unknown
permission values.

PathProof's static Secret read model is:

- `get` or `*` with empty `resourceNames` matches every parsed Secret in the
  effective scope.
- `get` or `*` with nonempty `resourceNames` matches parsed Secrets whose names
  exactly match one listed name.
- `list` or `watch` with empty `resourceNames` matches every parsed Secret in
  the effective scope.
- `list` or `watch` with nonempty `resourceNames` creates no `CanRead` edge
  because request field selectors are not modeled.
- unrelated verbs create no Secret access.

This is static authorization modeling only. It does not claim that a workload
actually issued a Secret read request.

## Findings

Findings are produced by read-only analysis over the in-memory graph.
Implemented rules are:

- Rule ID: `PP-K8S-001`
- Title: `Public workload can read Kubernetes Secret`
- Severity: fixed `High`
- Required path:
  `PublicEndpoint --RoutesTo--> Workload --RunsAs--> ServiceAccount --CanRead--> Secret`

- Rule ID: `PP-GHA-001`
- Title:
  `GitHub Actions workflow uses an action that is not pinned to a full commit SHA`
- Severity: fixed `Medium`
- Required path:
  `Workflow --DefinesJob--> WorkflowJob --UsesAction--> GitHubAction`

- Rule ID: `PP-GHA-002`
- Title:
  `pull_request_target workflow checks out untrusted pull request head code`
- Severity: fixed `High`
- Required path:
  `Workflow --DefinesJob--> WorkflowJob --UsesAction--> GitHubAction`

- Rule ID: `PP-GHA-003`
- Title:
  `pull_request_target workflow grants dangerous token permissions`
- Severity: fixed `High`
- Required path:
  workflow-level grants use `Workflow`; job-level grants use
  `Workflow --DefinesJob--> WorkflowJob`

`PP-K8S-001` is emitted only when all four Kubernetes nodes exist with the
expected kinds and all three directed edges exist with the expected kinds. The
ordered finding chain stores the four node IDs followed by the three edge IDs
in path order. Multiple public endpoints, workloads, or Secrets create
distinct findings when they form distinct chains. Multiple independent RBAC
authorization records on a single `CanRead` edge remain attached to the same
finding through that edge's aggregated evidence.

`PP-GHA-001` is emitted only when the workflow, job, and action nodes exist
with the expected kinds, the two directed edges exist with the expected kinds,
and the `UsesAction` metadata describes a static remote GitHub action
reference whose ref is missing or is not exactly 40 hexadecimal characters.
Local actions beginning with `./`, Docker actions beginning with `docker://`,
unrecognized action references, and `uses:` values that are entirely
expressions do not create findings. Tags, branches, semver refs, and sanitized
expression refs on an otherwise static `owner/repo` action are unpinned.
PathProof does not verify whether a commit SHA exists.

`PP-GHA-002` is emitted only when the same workflow/job/action path exists and
the `UsesAction` metadata shows all of the following: the workflow trigger
includes `pull_request_target`, the static action identity is exactly
`actions/checkout`, and the checkout step has one or more sanitized PR-head
selector matches from `with.ref` or `with.repository`. Non-checkout actions
with PR-head-looking `with` fields do not create PP-GHA-002 findings.

`PP-GHA-003` is emitted only when the workflow trigger includes
`pull_request_target` and sanitized workflow-level or job-level metadata
contains an explicit dangerous grant: `contents: write`,
`pull-requests: write`, `actions: write`, `checks: write`,
`deployments: write`, `id-token: write`, `security-events: write`, or
`permissions: write-all`. PathProof reports explicit workflow-level and
job-level dangerous permission grants independently. It does not flag
`permissions: read-all`, `permissions: {}`, read/none access values, omitted
permissions, unknown values, or expression-based values. Exact GitHub
permission inheritance/override modeling is future work.

`CanRequestOIDCToken` does not produce a finding by itself. OIDC capability is
represented only as graph structure until PathProof has modeled cloud trust
policies or another deterministic unsafe condition.

Finding IDs are deterministic and stable. `PP-K8S-001` IDs are SHA-256 hashes of a
canonical JSON identity containing only fixed field names for `rule_id`,
ordered `node_ids`, and ordered `edge_ids`. Evidence, source references,
summary text, title, and severity are not part of finding identity.
`PP-GHA-001` IDs are SHA-256 hashes of a canonical JSON identity containing
`rule_id`, workflow file, job ID, step index, action owner, repo, path, and
ref.
`PP-GHA-002` IDs are SHA-256 hashes of a canonical JSON identity containing
`rule_id`, workflow file, job ID, step index, action owner, repo, path, ref,
and ordered selector field/expression identities.
`PP-GHA-003` IDs are SHA-256 hashes of a canonical JSON identity containing
`rule_id`, workflow file, scope, job ID when scope is `job`, permission name,
and access value.

Finding evidence preserves the complete ordered edge evidence for the matched
path. `source_references` are derived from those edge evidence sources in
chain order, omit empty strings, and deduplicate exact repeated references
while preserving first appearance. They are not globally sorted.

Secret values are absent from findings because Secret values are never
ingested into parser output or graph evidence. GitHub Actions env, arbitrary
with, secret, token, run, and expression-only uses values are absent from
findings because they are never retained by the workflow parser or graph
builder. PP-GHA-002 evidence includes only workflow source references, job ID,
step index, sanitized action identity, selector field names, and matched
expression names. PP-GHA-003 evidence and summaries include only workflow
source references, workflow name or file fallback, scope, job ID when
applicable, sanitized permission name, sanitized access value, and the
`pull_request_target` trigger. The analyzer does not redact arbitrary strings
from graph evidence.

The scan CLI uses a private presentation projection and does not change the
internal graph or analysis schemas. JSON scan output has this stable top-level
shape:

```json
{
  "findings": [],
  "finding_count": 0
}
```

SARIF scan output is also a private CLI projection, not a graph schema. It is
selected with `pathproof scan --format sarif <directory>` and emits SARIF 2.1.0
with one PathProof run, deterministic rule entries for `PP-K8S-001`,
`PP-GHA-001`, `PP-GHA-002`, and `PP-GHA-003`, and one result per finding.
Result properties include finding ID, severity, ordered node IDs, ordered edge
IDs, and clean display source references when available.

SARIF locations are derived only from structured source-reference fields whose
entire value is a clean `filename#document=N` reference. PathProof does not
parse arbitrary prose, evidence details, summaries, or remediation text to find
embedded source references. Malformed references and references outside the
scan root are omitted. SARIF artifact URIs are relative to the scan root and
URI-encoded, while `properties.source_references` keeps display-safe relative
strings such as `resources file.yaml#document=1`. Line numbers and regions are
not emitted because the parser currently tracks file/document source location,
not line ranges.

SARIF remains findings-only even when patch flags are supplied. Patch previews,
patch output summaries, validation results, unified diffs, patched file
contents, temporary paths, raw manifests, and Secret values are not represented
in SARIF.

Each CLI JSON finding includes the finding `id`, `rule_id`, `title`,
`severity`, `summary`, ordered `path`, ordered `evidence`, and
`source_references`. Each path entry contains the graph node `id`, `kind`, and
`name`. Each evidence entry contains `edge_id`, `kind`, `source`, and `detail`.
Path and evidence order match the deterministic analysis chain order.

When a complete remediation plan exists, the CLI finding also includes:

```json
{
  "remediation": {
    "id": "plan:...",
    "finding_id": "finding:...",
    "rule_id": "PP-K8S-001",
    "summary": "...",
    "options": [
      {
        "priority": 2,
        "action": "RemoveSecretsResource",
        "summary": "...",
        "rationale": "...",
        "requires_all_changes": false,
        "changes": [
          {
            "action": "RemoveSecretsResource",
            "target": {
              "kind": "Role",
              "namespace": "prod",
              "name": "secret-reader"
            },
            "summary": "...",
            "source_reference": "resources.yaml#document=5",
            "permission_sha256": "..."
          }
        ],
        "patch_previews": [
          {
            "plan_id": "plan:...",
            "option_index": 0,
            "option_action": "NarrowBindingSubject",
            "change_index": 0,
            "status": "generated",
            "summary": "...",
            "file": "resources.yaml",
            "diff": "--- resources.yaml\n+++ resources.yaml\n@@ ...\n"
          }
        ]
      }
    ]
  }
}
```

`patch_previews` appears only when `pathproof scan --preview-patches` is used.
It is omitted from default human and JSON output. Preview entries are attached
to the remediation option that produced them and use zero-based
`option_index` and `change_index` values to preserve the option/change
relationship without adding persistent option IDs to remediation plans.
Generated previews contain relative file paths and timestamp-free unified
diffs. Unsupported previews use `status: "unsupported"` with a deterministic
`reason` and no `diff`.

When `pathproof scan --write-patches <output-directory>` is used, CLI JSON
also includes top-level `patch_outputs`. This is a CLI projection, not part of
the graph schema, and it never includes patched file contents:

```json
{
  "patch_outputs": [
    {
      "source": "resources.yaml",
      "output": "patched/resources.yaml",
      "status": "generated"
    },
    {
      "source": "",
      "status": "unsupported",
      "reason": "patch previews support only NarrowBindingSubject"
    }
  ]
}
```

`source` is the source-relative path. `output` is a display-safe relative path
for written files. Unsupported entries omit `output` and explain why no file
was written. If no supported patches exist, `patch_outputs` is present when
write mode is requested but no patch files are written.

When `pathproof scan --write-patches <output-directory> --validate-patches` is
used, CLI JSON also includes top-level `validation` results. This is a CLI
projection, not part of the graph schema:

```json
{
  "validation": [
    {
      "finding_id": "finding:...",
      "rule_id": "PP-K8S-001",
      "status": "remediated",
      "summary": "PP-K8S-001 no longer appears in patched output."
    }
  ]
}
```

Validation statuses are `remediated`, `failed`, and `skipped`.
`remediated` means the original supported finding ID was absent after
rescanning the complete temporary patched manifest set. `failed` means the
same finding ID remained. `skipped` means no generated patch output was
written for that finding. Validation uses the same local parse, route, and
analyze pipeline as the original scan and does not use live-cluster state.

Implemented remediation actions are:

- `RemoveSecretsResource`
- `RemoveSecretReadVerb`
- `NarrowBindingSubject`

`RemoveSecretsResource` is emitted only for core-only `apiGroups: [""]`
permissions where removing or splitting the non-wildcard `secrets` resource
entry can remove all modeled Secret-resource access for the contributing
chain. A rule that still contains `resources: ["*"]`, `apiGroups: ["*"]`, or a
mixed/non-core API group is not treated as remediated by removing only a
literal `secrets` entry. `RemoveSecretReadVerb` is emitted only for core-only
`apiGroups: [""]`, Secret-only resource rules. For multi-resource,
wildcard-resource, wildcard API-group, or mixed API-group rules, PathProof
prefers `RemoveSecretsResource` split/remove guidance when that guidance is
complete, otherwise it omits the unsafe option. Future patch planning may add
explicit API-group split/narrow guidance.

Plans are advisory. The planner does not edit YAML, apply changes, rescan
files, or create pull requests. The planner returns only complete options:
applying all changes in one option would break the modeled `CanRead` edge for
that finding. If multiple independent authorization chains contribute to one
`CanRead` edge, a complete option contains one required change per chain and
marks that all listed changes must be applied together. If no complete option
can be generated from structured metadata, no plan is reported for that
finding.

Patch previews are a separate opt-in CLI projection step, not part of the graph
schema. The initial implementation supports only `NarrowBindingSubject` for
`rbac.authorization.k8s.io/v1` `RoleBinding` and `ClusterRoleBinding`
documents. It resolves the existing source reference exactly, edits only that
referenced document in memory, and emits one preview per remediation change.
Preview generation is intentionally unsupported for source files containing a
core `v1` Secret with payload fields, unsupported remediation actions, missing
or malformed source references, mismatched target documents, namespace-less
subjects, and changes that would leave `subjects` empty.

Plan IDs are stable SHA-256 hashes over canonical JSON containing the finding
ID and ordered canonical option identities. Option identities contain priority,
action, and ordered canonical change identities. Change identities contain the
action, target kind/namespace/name, permission SHA-256 when applicable,
binding or role source reference, matched verb or subject when applicable, and
other canonical action parameters. Summary, rationale, constraints prose, and
evidence string ordering are excluded from identity.

Observed Roles or ClusterRoles with empty `rules` can still appear as reachable
Role nodes and have `BoundTo` edges, but they create no Permission nodes and no
`GrantsPermission` edges. Missing role references create unresolved Role nodes
only when a supported binding has an explicit ServiceAccount subject namespace;
their evidence is marked unresolved from `roleRef`, and they never create
Permission nodes or `GrantsPermission` edges.

Rules with `nonResourceURLs` are unsupported and skipped entirely for resource
Permission construction. Rules with no `resources` are also skipped. Supported
resource rules in the same Role or ClusterRole are still modeled.

## Current Limitations

The graph and analysis do not model Kubernetes User or Group RBAC subjects,
non-resource URLs, aggregated ClusterRoles, Secret values, live-cluster state,
workflow execution, GitHub API state, expression evaluation, workflow
permissions, OIDC trust, reusable workflow resolution, action source
inspection, CI/CD-to-cloud attack paths, in-place patch application, live
validation, or attack-path rules beyond `PP-K8S-001`, `PP-GHA-001`, and
`PP-GHA-002`. The
scan CLI currently supports local Kubernetes YAML directories and local
GitHub Actions workflow files under `.github/workflows`. Patch previews and
patch output are limited to Kubernetes `NarrowBindingSubject` and do not cover
`PP-GHA-001`, `PP-GHA-002`, RBAC rule edits, Secret-bearing source files, or
broader YAML patch types.
