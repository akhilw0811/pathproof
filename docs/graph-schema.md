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

## Edge Kinds

- `RoutesTo`: a public endpoint routes to a Deployment workload.
- `RunsAs`: a Deployment workload runs as a ServiceAccount.
- `BoundTo`: a ServiceAccount is bound to a Role or ClusterRole by a supported
  RoleBinding or ClusterRoleBinding.
- `GrantsPermission`: an observed Role or ClusterRole rule grants a canonical
  Permission.
- `CanRead`: a ServiceAccount can read a parsed Secret under PathProof's static
  RBAC authorization model.

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

Findings are produced by read-only analysis over the in-memory graph. The first
implemented rule is:

- Rule ID: `PP-K8S-001`
- Title: `Public workload can read Kubernetes Secret`
- Severity: fixed `High`
- Required path:
  `PublicEndpoint --RoutesTo--> Workload --RunsAs--> ServiceAccount --CanRead--> Secret`

A finding is emitted only when all four nodes exist with the expected kinds and
all three directed edges exist with the expected kinds. The ordered finding
chain stores the four node IDs followed by the three edge IDs in path order.
Multiple public endpoints, workloads, or Secrets create distinct findings when
they form distinct chains. Multiple independent RBAC authorization records on a
single `CanRead` edge remain attached to the same finding through that edge's
aggregated evidence.

Finding IDs are deterministic and stable. They are SHA-256 hashes of a
canonical JSON identity containing only fixed field names for `rule_id`,
ordered `node_ids`, and ordered `edge_ids`. Evidence, source references,
summary text, title, and severity are not part of finding identity.

Finding evidence preserves the complete ordered edge evidence for `RoutesTo`,
`RunsAs`, and `CanRead`. `source_references` are derived from those edge
evidence sources in chain order, omit empty strings, and deduplicate exact
repeated references while preserving first appearance. They are not globally
sorted.

Secret values are absent from findings because Secret values are never ingested
into parser output or graph evidence. The analyzer does not redact arbitrary
strings from graph evidence.

The scan CLI uses a private presentation projection and does not change the
internal graph or analysis schemas. JSON scan output has this stable top-level
shape:

```json
{
  "findings": [],
  "finding_count": 0
}
```

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

Plans are advisory and read-only. They do not edit YAML, apply changes, rescan
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
patch application, validation rescans, or attack-path rules beyond
`PP-K8S-001`. The scan CLI currently supports local Kubernetes YAML
directories only. Patch previews are limited to `NarrowBindingSubject` and do
not cover RBAC rule edits or broader YAML patch types.
