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

GitHub Actions runs the repository check suite, builds `./bin/pathproof`, and
generates `pathproof.sarif` from the intentionally vulnerable public demo
fixture. The workflow captures the demo scan exit code and accepts only `1`,
because findings are expected for that fixture. Exit code `0` would mean the
demo no longer reports the expected `PP-K8S-001` finding, and exit code `2` or
any other code is treated as a scan failure. The workflow verifies that the
SARIF file exists, is non-empty, contains SARIF version `2.1.0`, and contains
`PP-K8S-001`, then uploads it as a workflow artifact.

Scan command tests cover argument validation, deterministic controlled flag
errors, accepted `--format json` and `--format=json` syntax, accepted
`--format sarif` and `--format=sarif` syntax, accepted `--repo OWNER/REPO`
syntax, invalid `--repo` errors with empty stdout, accepted
`--config <file>` syntax, accepted `--preview-patches` syntax, missing and
non-directory path errors, human output, JSON output, SARIF output, exactly one
trailing newline, stderr-only errors, output write failures, deterministic
repeated output, deterministic input file ordering, and Secret-value absence
from stdout and stderr.
Config parser coverage asserts that the explicit local JSON file format parses
empty configs, disabled rule lists, enable allowlists, disable-over-enable
conflicts, duplicate rule IDs, exact finding suppressions, and
`path_exclusions`; rejects malformed JSON, non-object JSON, unknown top-level
and nested fields, unknown rule IDs, empty suppression fields, control
characters, malformed path exclusion shapes, null entries, non-string entries,
empty exclusions, absolute paths, Windows drive paths, outside-root paths,
root exclusions, URL-like schemes, backslashes, and unsupported glob syntax;
deduplicates and sorts exclusions deterministically while preserving exact-file
and trailing-slash directory-prefix semantics; and does not echo raw config
content or secret-like values in errors. CLI config coverage asserts that path
exclusions happen before parsing, rule filtering happens after analysis and
before remediation and output, exact suppressions happen after rule filtering
and before remediation and output, stale suppressions do not fail scans,
all-suppressed or fully excluded scans exit `0`, mixed excluded, suppressed,
and unsuppressed scans exit `1`, malformed configs exit `2` with empty stdout,
JSON config metadata is deterministic, human suppressed counts appear only
when findings are actually suppressed, and finding IDs do not change merely
because config was supplied.
Baseline writer coverage asserts suppressions-only JSON output, deterministic
finding-ID sorting, duplicate finding-ID deduplication, the exact default
reason, empty suppression arrays when no unsuppressed findings remain,
round-trip loading through the existing config parser, no raw finding title,
evidence, source-reference, path, secret-like, config, or patch data in the
generated file, rejection of existing files, directories, missing parents,
remote-like paths, and invalid parents, deterministic repeated output, and
sanitized cleanup behavior on injected write failures. CLI baseline coverage
asserts that `--write-baseline` exits `0` after successful writes even when
findings were present, generated baselines suppress the same findings when
reused through `--config`, existing `--config` rule controls, path exclusions,
and suppressions are applied before baseline generation, stale suppressions
are not copied, malformed configs and write errors exit `2` with empty stdout,
and secret-like source or config values do not leak to stdout, stderr, JSON,
SARIF, or baseline files.
GitHub Actions CLI coverage
asserts safe pinned workflows exit `0`, unpinned `uses:` workflows exit `1`,
unsafe `pull_request_target` checkout workflows exit `1`, mixed Kubernetes and
GitHub Actions findings are deterministic, `PP-GHA-001`, `PP-GHA-002`, and
`PP-GHA-003` appear in human and JSON output, `PP-GHA-001` includes advisory
`PinGitHubActionToSHA` remediation, `PP-GHA-002` and `PP-GHA-003` still have
no remediation, and a push workflow with only `id-token: write` exits `0`
with no findings in human, JSON, and SARIF output.
GitHub Actions pinning CLI coverage asserts that `--github-action-pins`
accepts a local JSON object mapping exact static action refs to exact
40-character lowercase or uppercase hex SHAs, rejects malformed JSON, short
SHAs, non-hex SHAs, and invalid action refs with sanitized errors, does not
print raw mapping content, and exits `2` with empty stdout for malformed
mapping files. It also asserts that no mapping remains advisory-only, a valid
mapping produces deterministic patch-supported JSON metadata for safe static
uses values, `--preview-patches` emits a deterministic no-context unified diff,
`--write-patches` writes patched workflow copies only under the output
directory while leaving input workflows unchanged, quoted static action refs
preserve their quotes, harmless `env`, `run`, and `with` context does not block
safe pin patches, secret-like workflow context such as tokens, passwords, or
credentials, same-line unsafe fields, and same-line comments stay unsupported,
and `permissions: id-token` is not treated as a secret-bearing key.
`--validate-patches` produces no `PP-GHA-001` validation result.
Config-specific remediation and patch coverage asserts that disabled or
suppressed `PP-K8S-001` findings produce no Kubernetes remediation, patch
previews, written patch files, or validation rows, and disabled or suppressed
`PP-GHA-001` findings produce no GitHub Actions remediation, patch previews,
or written patch files. Path-exclusion coverage asserts the same behavior for
excluded `PP-K8S-001` and `PP-GHA-001` source files, and asserts validation
rescans do not reintroduce excluded malformed Kubernetes files.
Baseline-specific side-effect coverage asserts that baseline mode does not
build remediation, patch previews, patch outputs, validation rows, diffs,
patched contents, or GitHub Action pin SHA metadata, ignores
`--github-action-pins`, and rejects combinations with `--preview-patches`,
`--write-patches`, and `--validate-patches` before writing any baseline or
patch output.
Graph-only OIDC capability text is not emitted in scan output. Terraform AWS
OIDC trust graph-only coverage asserts that a matching trust policy plus
`--repo` can create a graph edge while human no-finding output remains
unchanged, JSON findings remain empty, SARIF results remain empty, and no
Terraform graph internals appear in CLI output. Secret-like
workflow env, with, run, permission expressions, and expression-only `uses:`
values are absent from stdout, stderr, JSON, SARIF, and errors. CLI projection
tests verify that finding path entries preserve node ID/kind/name, evidence
entries preserve edge ID/kind/source/detail, one-node workflow-level findings
project safely, malformed one-node findings are rejected, generic multi-node
path edge continuity is enforced, and inconsistent finding-to-graph projection
is treated as an internal scan error without partial stdout.
Cross-domain CLI coverage asserts that `PP-XDOMAIN-001` appears only when a
modeled risky GitHub Actions workflow/job OIDC path reaches a matching AWS IAM
role trust with `--repo OWNER/REPO`, that missing or nonmatching `--repo`
omits the cross-domain finding, that safe OIDC trust alone exits `0`, that
human and JSON output include sanitized workflow/job, OIDC capability, AWS role,
and risk-signal data, and that patch/write/validation flags do not attach
remediation, patch previews, or validation results to `PP-XDOMAIN-001`.
Additional cross-domain admin-role CLI coverage asserts that `PP-XDOMAIN-002`
appears only when the risky OIDC path uses the pull request subject and reaches
an administrative AWS permission, that missing or nonmatching `--repo`,
non-admin permissions, push-only workflows, branch-only trust, and
environment-only trust omit `PP-XDOMAIN-002`, and that remediation, patch
preview, patch output, validation, raw policy/trust content, and secret-like
values are not attached or printed.
Cross-domain S3 CLI coverage asserts that `PP-XDOMAIN-003` appears only when
the risky OIDC path uses the pull request subject and reaches explicit exact
S3 read or write access to a modeled bucket, that missing or nonmatching
`--repo` and nonmatching bucket policies omit `PP-XDOMAIN-003`, and that
remediation, patch preview, patch output, validation, raw policy/trust content,
and secret-like values are not attached or printed. It also asserts that
graph-only S3 sensitivity metadata does not create findings and is not exposed
through the public findings-only JSON report.
AWS IAM CLI coverage asserts that static Terraform inline admin role policies
and literal AdministratorAccess role-policy attachments emit `PP-AWS-001` in
human, JSON, and SARIF output, that non-admin policies exit `0`, that malformed
inline policy JSON with trailing secret-like content returns a sanitized error,
and that remediation, patch preview, patch output, and validation are not
attached to `PP-AWS-001`.

SARIF tests assert valid JSON with SARIF 2.1.0 version and schema, one
PathProof driver run, deterministic rule entries for `PP-K8S-001`,
`PP-GHA-001`, `PP-GHA-002`, `PP-GHA-003`, `PP-AWS-001`,
`PP-XDOMAIN-001`, `PP-XDOMAIN-002`, and `PP-XDOMAIN-003`, one result for
vulnerable fixtures, zero results for safe fixtures, deterministic rule/result
fields, byte-identical repeated scans, and unchanged exit codes. GitHub Actions
SARIF
coverage asserts `PP-GHA-001` severity maps to `warning`, `PP-GHA-002` and
`PP-GHA-003` severities map to `error`, workflow artifact URIs are relative
and URI-safe, line numbers are not guessed, rule text avoids the old inaccurate
scope wording, sanitized selector and permission evidence is present, and
secret-like workflow values are absent. Cross-domain SARIF coverage asserts
`PP-XDOMAIN-001` rule metadata, `error` level, finding-summary messages,
workflow source as the primary URI-safe location, stable
`pathproofFindingId` fingerprints, and absence of raw Terraform trust policy
content and secret-like values. Cross-domain admin-role SARIF coverage asserts
the same for `PP-XDOMAIN-002`, plus administrative-permission summary text and
deterministic rule presence without relying only on total rule counts.
Config SARIF coverage asserts disabled, suppressed, and path-excluded findings
are omitted from SARIF results, SARIF remains findings-focused and valid 2.1.0,
and config content, suppression reasons, and raw exclusion lists are not
emitted.
Baseline SARIF coverage asserts that `--format=sarif --write-baseline` writes
the baseline as a side effect, exits `0`, keeps SARIF valid and findings-only,
and omits baseline metadata, remediation, patch previews, patch outputs,
validation arrays, diffs, patched contents, mapping data, raw source, and
secret-like values.
Cross-domain S3 SARIF coverage asserts the same for `PP-XDOMAIN-003`, plus S3
bucket name, access mode, sanitized matched grant evidence, and no remediation
or raw policy text. It also asserts that existing SARIF findings remain
findings-only when bucket sensitivity metadata exists.
Source-location
tests cover URI-encoded relative artifact URIs for paths with spaces,
display-safe relative `properties.source_references`, omission of malformed
document suffixes, strict Terraform `#resource=aws_iam_role_policy.<name>` and
`#resource=aws_iam_role_policy_attachment.<name>` handling, omission of
malformed Terraform resource suffixes, omission of outside-root references, and
refusal to parse source references embedded in arbitrary prose. SARIF patch flag tests verify
that write-patch and validation side effects still occur under the existing
flag contract while SARIF stdout remains findings-only and omits patch
previews, patch outputs, validation arrays, diffs, patched contents, temporary
paths, raw manifests, GitHub action pin metadata, local mapping data,
replacement SHAs, and Secret or workflow secret-like values.

The public demo fixture under `examples/kubernetes/public-secret-path` is
covered by a CLI smoke test. It asserts the documented loop: vulnerable scan
exit code `1`, `PP-K8S-001` output, generated `NarrowBindingSubject` preview,
patched-copy output, validation status `remediated`, structured JSON
validation, and absence of Secret payload fields in output.

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
parser output and parse errors. Exclusion option tests assert selected
top-level YAML files are skipped before parsing, excluded malformed YAML files
do not return parse errors, and filenames with spaces match deterministically.

GitHub Actions parser tests cover workflow file discovery under
`.github/workflows`, `.yml` and `.yaml` filtering, one-job workflows, multiple
jobs sorted by job ID, run-only step omission, deterministic file ordering,
`pull_request` and `pull_request_target` trigger detection for unquoted and
quoted `on`, scalar `on`, sequence `on`, and mapping `on` forms, static
`on.push.branches` literals for OIDC subject matching, static job environment
names for OIDC subject matching, checkout PR-head selector detection, minimal
workflow-level and job-level `permissions` parsing,
`permissions: write-all`, `permissions: read-all`, `permissions: {}`,
deterministic permission grant ordering, malformed workflow errors with
filenames, paths with spaces, missing workflow directories, and regression
checks that static `uses:` values have precise source coordinates for patch
planning, unsupported patch context is represented only by coarse reason
strings, and env values, arbitrary with values, secret-like tokens, run scripts,
unknown or expression-based permission values, expression-only `uses:` values,
and raw workflow documents are absent from serialized parser output and errors.
Exclusion option tests assert selected workflow files under `.github/workflows`
are skipped before parsing, excluded malformed workflows do not return parse
errors, and workflow filenames with spaces match deterministically.

Terraform parser tests cover deterministic local `.tf` file walking, top-level
`aws_iam_role` resource extraction, literal heredoc and quoted JSON
`assume_role_policy` values, ignored dynamic and nonliteral policy values,
ignored non-role resources, malformed supported Terraform syntax with
sanitized filename errors, malformed extracted trust JSON with sanitized
resource errors, trust detection for GitHub Actions OIDC federated principals,
`sts:AssumeRoleWithWebIdentity`, `StringEquals` and `StringLike`
`sub`/`aud` conditions, string and array condition values, missing
issuer/action/sub/aud negatives, simple `*` wildcard pattern support, static
`aws_iam_role_policy` heredoc and quoted JSON permissions, AdministratorAccess
role-policy attachments, conservative literal role-name matching against
explicit static role names only, ambiguous literal role-name negatives,
ignored unsupported managed policy ARNs, ignored dynamic policies, ignored
`NotAction` and conditioned policies, deterministic permission ordering,
malformed inline policy JSON with sanitized resource errors, and regression
checks that variables, provider credentials, raw trust or permission JSON,
unsupported managed policy ARNs, and secret-like Terraform values are absent
from parser output and errors.
S3 parser coverage adds static `aws_s3_bucket` literal bucket names,
conservative sensitivity classification from full bucket-name tokens and
allowlisted direct static literal tags, substring false-positive negatives
such as `myproduct-assets`, `catalogs`, `dbbackup`, and `customerdb`, dynamic
and interpolated bucket-name negatives, unsupported/dynamic/interpolated tag
negatives, provider/default tag exclusion, non-bucket tag exclusion,
unrelated tag exclusion, exact S3 read/write inline policy actions,
wildcard/dynamic ARN negatives, `NotAction`/`NotResource`/condition
negatives, malformed S3 policy JSON sanitization, deterministic
bucket/resource ordering, deterministic sensitivity reason deduplication and
sorting, and raw Terraform/tag/provider value exclusion.
Terraform exclusion option tests assert selected `.tf` files are skipped
before parsing, excluded malformed Terraform files do not return parse errors,
trailing-slash directory exclusions prune nested Terraform files, exact-file
exclusions leave siblings in the same directory, and paths with spaces match
deterministically.

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

GitHub Actions routing tests cover deterministic `Workflow`, `WorkflowJob`,
`GitHubAction`, and `OIDCTokenCapability` node construction, `DefinesJob`,
`UsesAction`, and `CanRequestOIDCToken` edges, source evidence, repeated
action uses remaining distinct by step index, sanitized owner/repo/path/ref
metadata, `pull_request_target` trigger metadata, sanitized checkout selector
metadata, sanitized workflow-level and job-level permission metadata,
workflow-level and job-level OIDC capability metadata, `id-token: write`,
`permissions: write-all`, read/read-all/none/omitted permission negatives,
distinct workflow and job OIDC capabilities, deterministic graph JSON across
repeated and reversed workflow/job inputs, local and Docker action exclusion
from static action metadata, expression handling, metadata cloning, and
regression checks that ignored workflow values are absent from graph JSON.

Terraform routing tests cover deterministic `AWSIAMRole` node construction,
sanitized trust metadata, `AWSPermission` node construction,
`AWSIAMRole --GrantsPermission--> AWSPermission` edges, sanitized AWS
permission metadata, AdministratorAccess metadata, `CanAssumeRole` edge
construction only when `--repo OWNER/REPO` supplies repository identity and a
static subject candidate matches, no cross-domain edge without `--repo`, no
edge without a static candidate, nonmatching repo/ref negatives,
`StringEquals` exact matching, simple `StringLike` wildcard matching, metadata
cloning, deterministic graph JSON, and regression checks that raw Terraform,
raw trust or permission policy JSON, provider credentials, unsupported
condition values, unsupported managed policy ARNs, and secret-like values are
absent from graph JSON.
S3 routing coverage adds deterministic `AWSS3Bucket` nodes, graph-only
`sensitivity_level` and sanitized `sensitivity_reasons` metadata, unknown and
sensitive bucket cases, deterministic reason aggregation and deduplication,
metadata cloning, graph JSON determinism, exact
`CanReadObject`/`CanWriteObject` edges for `GetObject`, `ListBucket`,
`PutObject`, `DeleteObject`, and `s3:*` bucket/object semantics, negatives for
`Resource "*"`, `Action "*" Resource "*"`, `s3:*Object`, wildcard bucket or
prefix ARNs, admin-to-S3 expansion, nonmatching buckets, duplicate grant
deduplication, deterministic multi-grant aggregation, metadata cloning, and
secret/raw-policy/unrelated-tag/provider-value exclusion.

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

GitHub Actions analysis tests cover `PP-GHA-001` positives for action refs
such as `actions/checkout@v4`, `docker/login-action@main`,
`owner/repo/path@v1.2.3`, missing refs, and sanitized expression refs on static
`owner/repo` actions. Negative tests cover local actions, Docker actions,
entire expression `uses:` values, and refs pinned to exactly 40 hexadecimal
characters including uppercase hex. Coverage also asserts fixed `Medium`
severity, deterministic repeated analysis, stable finding IDs, finding ID
changes when action refs change, absence of the old inaccurate scope wording,
and secret-like workflow values absent from finding JSON. `PP-GHA-002` tests
cover `pull_request_target` workflows with `actions/checkout` PR-head SHA,
head ref, and head repository selectors; negatives for `pull_request` only,
checkout without head override, non-checkout actions with PR-head-looking
fields, expression-only `uses`, and no checkout step; stable and selector-
sensitive finding IDs; sanitized evidence; secret exclusion; and both
`PP-GHA-001` and `PP-GHA-002` firing on the same unpinned unsafe checkout.
`PP-GHA-003` tests cover `pull_request_target` workflows with dangerous
workflow-level and job-level permission grants, `permissions: write-all`,
negatives for read/read-all/none/omitted permissions and `pull_request` only,
distinct workflow-level and job-level findings, stable finding IDs, ID changes
when identity inputs change, sanitized summaries/evidence for
`permissions: write-all`, secret exclusion, and PP-GHA-002 and PP-GHA-003
firing on the same workflow. Analysis coverage also asserts that a push
workflow with graph-only OIDC token capability does not create a finding.
AWS analysis tests cover `PP-AWS-001` positives for inline `Action "*"
Resource "*"` and `Action "*:*" Resource "*"` permissions and the literal
AdministratorAccess attachment, negatives for non-admin permissions and
unsupported admin reasons, stable and sensitive finding IDs, exact path shape,
sanitized evidence, and absence of raw Terraform, raw policy JSON, and
secret-like values from finding JSON.
Cross-domain analysis tests cover workflow-level OIDC plus workflow-level risk,
job-level OIDC plus job-level risk, explicit workflow-level and job-level OIDC
paths to the same AWS role both emitting when both are modeled, exact duplicate
identity deduplication, PP-GHA-001 alone not triggering, safe OIDC trust alone
not triggering, risk without `CanAssumeRole` not triggering, unsafe checkout
risk pairing with same-job and explicit workflow-level OIDC, stable and
sensitive finding IDs, repeated-analysis determinism, strict path evidence, and
sanitized optional `risk_signal` data that is omitted from existing rule JSON.
Regression coverage asserts that a `pull_request_target` risk does not produce
`PP-XDOMAIN-001` when the only role trust match is for a different OIDC subject,
such as a push branch ref.
`PP-XDOMAIN-002` analysis coverage adds the administrative permission hop:
positive workflow-level, job-level, and unsafe-checkout risk cases; negatives
for no risk, no `CanAssumeRole`, non-admin permission, PP-GHA-001 alone,
branch-only trust, and environment-only trust; multiple admin permissions
producing distinct deterministic findings; ID changes when admin reason
changes; distinct IDs from `PP-XDOMAIN-001`; ordered path evidence through
`GrantsPermission`; and secret exclusion from finding JSON.
`PP-XDOMAIN-003` analysis coverage adds the S3 access hop: positive
workflow-level read and job-level write cases; negatives for no risk, no
`CanAssumeRole`, no S3 access, nonmatching buckets, PP-GHA-001 alone,
branch-only trust, environment-only trust, and admin permission alone; read
and write access to the same bucket producing distinct findings; stable and
sensitive IDs; ordered path evidence through `CanReadObject` or
`CanWriteObject`; finding ID stability when only S3 bucket sensitivity metadata
changes; no finding for a sensitive bucket alone; and secret/raw-policy
exclusion from finding JSON.

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

Patch output tests cover the opt-in `internal/patchpreview.Write` API for the
same `NarrowBindingSubject` slice. Coverage asserts output directory safety,
preparation-before-write behavior, cleanup after controlled write failures,
missing output directory creation only when generated files exist, no writes
when every preview is unsupported, one deterministic output file for multiple
compatible changes to the same source file, duplicate same-subject removal
deduplication, byte-identical repeated and reversed-order writes, stable
display-safe output paths, source file immutability, Secret-bearing source
file exclusion, symlink-resolved output-root containment checks, absolute
source references that must resolve inside the scan root, symlink source escape
rejection, and unsupported actions being reported but not written.

CLI patch preview tests cover default output remaining free of
`patch_previews`, generated human and JSON previews when `--preview-patches` is
enabled, visible unsupported previews, safe scans with no previews, unchanged
exit codes, preview-builder errors that leave stdout empty and return exit code
`2`, deterministic repeated preview output, and Secret-value exclusion from
stdout and stderr.

CLI patch output tests cover `--write-patches` argument validation, unsafe
input/output directory relationship rejection, output path conflicts returning
exit code `2` with empty stdout, supported `NarrowBindingSubject` writes,
unsupported-only vulnerable scans writing no files while preserving exit code
`1`, safe scans writing no files with exit code `0`, `--preview-patches` alone
writing nothing, combined preview and write output, JSON `patch_outputs`
appearing only when requested, stable display-safe paths without temp prefixes,
absolute-input scan-root-local source references displayed relative to the scan
root throughout human and JSON reports, input file immutability, and no full
patched file contents in human or JSON output.

Validation rescan tests cover the opt-in `--validate-patches` flag requiring
`--write-patches`, boolean flag parsing, extra positional argument rejection,
and validation running only after patch output succeeds. Coverage asserts that
validation builds a complete temporary patched manifest set instead of scanning
only the partial patch output directory, reports `remediated` when the complete
patched logical set removes the original `PP-K8S-001` finding, reports
`failed` while preserving exit code `1` when the original finding remains,
reports `skipped` when no generated patch output was written for a finding,
and returns exit code `2` with empty stdout when validation scanning fails.
Tests also verify deterministic human and JSON validation output, temporary
overlay cleanup, absence of temporary or machine-specific absolute paths in
output, input file immutability, user-visible output directories containing
only normal patched copies, and Secret-value absence from stdout, stderr, JSON,
validation summaries, and validation errors.

Tests must cover positive and negative behavior for changed packages. Do not
skip, remove, or weaken tests to make a change pass.
