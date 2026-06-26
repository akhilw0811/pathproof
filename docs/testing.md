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

The CLI is tested through `cmd/pathproof` unit tests and an integration check
that builds a temporary binary. Integration coverage asserts `version`, a safe
scan exit code `0`, a vulnerable scan exit code `1`, and an invalid scan exit
code `2`. Exit code `1` is expected success-with-findings behavior, so the
shell test captures and checks it explicitly.

Scan command tests cover argument validation, deterministic controlled flag
errors, accepted `--format json` and `--format=json` syntax, accepted
`--preview-patches` syntax, missing and non-directory path errors, human
output, JSON output, exactly one trailing newline, stderr-only errors, output
write failures, deterministic repeated output, deterministic input file
ordering, and Secret-value absence from stdout and stderr. CLI projection tests
verify that finding path entries preserve node ID/kind/name, evidence entries
preserve edge ID/kind/source/detail, and inconsistent finding-to-graph
projection is treated as an internal scan error without partial stdout.

Kubernetes parser tests cover supported manifest parsing, defaulting,
multi-document source tracking, deterministic ordering, malformed YAML errors,
and `rbac.authorization.k8s.io/v1` RBAC parsing for Roles, ClusterRoles,
RoleBindings, ClusterRoleBindings, ServiceAccount-only subjects, roleRefs, and
canonical resource permission fields. Parser coverage also verifies
deterministic parsing of unsupported `nonResourceURLs` so routing can skip
those rules. Secret parser tests cover core `v1` metadata-only parsing,
default namespaces, unsupported Secret API version skipping before typed
decoding, deterministic ordering, duplicate source preservation, and regression
checks that Secret `data`, `stringData`, and values are absent from serialized
parser output and parse errors.

Kubernetes routing tests cover deterministic graph construction, source
evidence, duplicate conflict rejection before graph mutation, namespace-scoped
matching, observed and inferred ServiceAccount provenance, and preservation of
existing Service and Ingress exposure behavior. RBAC routing tests cover
ServiceAccount bindings to Roles and ClusterRoles, cross-namespace
RoleBinding subjects with explicit namespaces, unresolved namespace-less
subjects, unsupported roleRefs, unresolved roles, scoped `BoundTo` evidence,
canonical Permission IDs, shared Permission nodes, empty observed roles,
multi-scope `BoundTo` evidence aggregation, skipped non-resource URL rules,
empty-resource rules, semantic duplicate binding source preservation, and RBAC
duplicate conflict handling. Secret access routing tests cover Secret node
source aggregation, static RBAC `CanRead` authorization for `get`, `list`,
`watch`, and `*`, `resourceNames` limits, RoleBinding and ClusterRoleBinding
scope, unsupported inputs, deterministic evidence aggregation, duplicate
evidence deduplication, conflict atomicity, typed structured `CanRead`
authorization metadata, deterministic metadata ordering, and regression checks
that Secret values are absent from graph JSON, metadata, and evidence.

Analysis tests cover `PP-K8S-001` positive and negative matching, exact directed
edge semantics, exact required node and edge kind validation, unrelated graph
noise, cycles, deterministic finding IDs and ordering, ordered node and edge
chains, endpoint/workload/ServiceAccount/Secret path cardinality, complete edge
evidence preservation, evidence-independent finding IDs, direct edge-ID
participation in finding identity, source-reference ordering and deduplication,
independent returned finding slices verified by JSON snapshots, overwrite and
append mutation checks, read-only graph snapshots across repeated analysis with
node and edge evidence preservation, nil and empty graph behavior, and fixed
`High` severity. The Secret-value regression for analysis runs through the real
Kubernetes parser and routing pipeline before marshalling findings; analysis
preserves graph evidence and does not perform generic redaction.

Remediation tests cover the read-only `internal/remediation.Build` API for
`PP-K8S-001`. Coverage asserts complete advisory options for
`RemoveSecretsResource`, `RemoveSecretReadVerb`, and `NarrowBindingSubject`;
multi-resource rule summaries that preserve unrelated access; omission of
unsafe wildcard-resource `RemoveSecretsResource` options; `RemoveSecretReadVerb`
only for core-only Secret-only resource rules; omission of resource-removal and
verb-removal options for wildcard, mixed, empty, and non-core API groups;
wildcard verb guidance that replaces `*` with explicit least-privilege verbs;
omission of single-subject binding narrowing; coordinated multi-chain options
with one required change per contributing authorization chain; duplicate
authorization deduplication; deterministic plan ordering and byte-identical
JSON across repeated and reversed inputs; stable plan IDs; plan ID changes when
canonical identity inputs change; plan ID stability when evidence prose
changes; graph and finding immutability; unsupported rule skipping; malformed
supported finding errors; and Secret-value exclusion from plan JSON and errors.

CLI remediation tests cover human remediation sections under findings,
structured JSON remediation output, safe scans with no remediation plans,
multiple findings with matching deterministic plans, planning/projection
errors that leave stdout empty and return exit code `2`, unchanged successful
scan exit codes, and Secret-value exclusion from human output, JSON output,
and stderr.

Patch preview tests cover the read-only `internal/patchpreview.Build` API for
the initial `NarrowBindingSubject` slice. Coverage asserts generated unified
diffs for multi-subject RoleBindings and ClusterRoleBindings; exact
`filename#document=N` source-reference resolution; one preview per remediation
change; deterministic preview ordering and byte-identical JSON across repeated
builds; relative file paths; source file immutability; generated YAML
parseability; stable diff headers, hunk markers, line endings, and trailing
newline; preservation of other subjects and unrelated YAML documents; and
unsupported previews for malformed references, absolute or escaping paths,
missing files, out-of-range documents, malformed YAML, mismatched referenced
documents, single remaining subjects, missing target subjects, namespace-less
subjects, unsupported actions, and source files containing Secret payload
fields. Tests also verify unsupported reasons do not include Secret keys or
values.

CLI patch preview tests cover default output remaining free of
`patch_previews`, generated human and JSON previews when `--preview-patches` is
enabled, visible unsupported previews, safe scans with no previews, unchanged
exit codes, preview-builder errors that leave stdout empty and return exit code
`2`, deterministic repeated preview output, and Secret-value exclusion from
stdout and stderr.

Tests must cover positive and negative behavior for changed packages. Do not
skip, remove, or weaken tests to make a change pass.
