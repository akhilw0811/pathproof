package githubactions

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseDirParsesWorkflowWithOneJobAndUsesStep(t *testing.T) {
	root := t.TempDir()
	path := writeWorkflow(t, root, "build.yml", `name: Build
on: push
jobs:
  test:
    steps:
      - name: Checkout
        uses: actions/checkout@v4
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := Resources{Workflows: []Workflow{{
		Name:   "Build",
		Source: Source{Filename: path, RelativePath: ".github/workflows/build.yml", Document: 1},
		Jobs: []Job{{
			ID: "test",
			Steps: []Step{{
				Index: 0,
				Name:  "Checkout",
				Uses:  "actions/checkout@v4",
				Owner: "actions",
				Repo:  "checkout",
				Ref:   "v4",
			}},
		}},
	}}}
	if !reflect.DeepEqual(resources, want) {
		t.Fatalf("resources = %#v, want %#v", resources, want)
	}
}

func TestParseDirSortsFilesAndJobsDeterministically(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "z.yml", `jobs:
  z:
    steps:
      - uses: owner/z@main
`)
	writeWorkflow(t, root, "a.yaml", `jobs:
  z:
    steps:
      - uses: owner/z@main
  a:
    steps:
      - uses: owner/a@main
`)

	first, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse first: %v", err)
	}
	second, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse second: %v", err)
	}

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("parse output differs:\nfirst=%#v\nsecond=%#v", first, second)
	}
	gotFiles := []string{first.Workflows[0].Source.RelativePath, first.Workflows[1].Source.RelativePath}
	wantFiles := []string{".github/workflows/a.yaml", ".github/workflows/z.yml"}
	if !reflect.DeepEqual(gotFiles, wantFiles) {
		t.Fatalf("files = %#v, want %#v", gotFiles, wantFiles)
	}
	gotJobs := []string{first.Workflows[0].Jobs[0].ID, first.Workflows[0].Jobs[1].ID}
	if !reflect.DeepEqual(gotJobs, []string{"a", "z"}) {
		t.Fatalf("jobs = %#v, want sorted IDs", gotJobs)
	}
}

func TestParseDirIgnoresRunOnlySteps(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "run.yml", `jobs:
  test:
    steps:
      - name: Test
        run: go test ./...
      - uses: actions/setup-go@v5
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	steps := resources.Workflows[0].Jobs[0].Steps
	if len(steps) != 1 || steps[0].Index != 1 || steps[0].Uses != "actions/setup-go@v5" || steps[0].Owner != "actions" || steps[0].Repo != "setup-go" {
		t.Fatalf("steps = %#v, want only uses step at original index 1", steps)
	}
}

func TestParseDirParsesWorkflowLevelPermissionsMap(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "permissions.yml", `permissions:
  pull-requests: read
  contents: write
  id-token: none
  packages: write
  actions: ${{ matrix.access }}
jobs:
  test:
    steps:
      - uses: owner/repo@main
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []PermissionGrant{
		{Scope: "workflow", Permission: "contents", Access: "write"},
		{Scope: "workflow", Permission: "id-token", Access: "none"},
		{Scope: "workflow", Permission: "pull-requests", Access: "read"},
	}
	if !reflect.DeepEqual(resources.Workflows[0].PermissionGrants, want) {
		t.Fatalf("permission grants = %#v, want %#v", resources.Workflows[0].PermissionGrants, want)
	}
	data, err := json.Marshal(resources)
	if err != nil {
		t.Fatalf("marshal resources: %v", err)
	}
	for _, forbidden := range []string{"packages", "matrix.access", "${{"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("parser output contains %q: %s", forbidden, data)
		}
	}
}

func TestParseDirParsesJobLevelPermissionsMap(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "permissions.yml", `jobs:
  test:
    permissions:
      checks: write
      deployments: read
      id-token: none
    steps:
      - uses: owner/repo@main
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []PermissionGrant{
		{Scope: "job", JobID: "test", Permission: "checks", Access: "write"},
		{Scope: "job", JobID: "test", Permission: "deployments", Access: "read"},
		{Scope: "job", JobID: "test", Permission: "id-token", Access: "none"},
	}
	if !reflect.DeepEqual(resources.Workflows[0].Jobs[0].PermissionGrants, want) {
		t.Fatalf("job permission grants = %#v, want %#v", resources.Workflows[0].Jobs[0].PermissionGrants, want)
	}
}

func TestParseDirIgnoresInvalidMapPermissionAccessValues(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "permissions.yml", `permissions:
  contents: write-all
  actions: unknown
  checks: ${{ inputs.permission }}
  deployments: ""
jobs:
  test:
    permissions:
      contents: read-all
      id-token: ${{ inputs.job_permission }}
      security-events: admin
    steps:
      - uses: owner/repo@main
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	if len(resources.Workflows[0].PermissionGrants) != 0 {
		t.Fatalf("workflow permission grants = %#v, want none", resources.Workflows[0].PermissionGrants)
	}
	if len(resources.Workflows[0].Jobs[0].PermissionGrants) != 0 {
		t.Fatalf("job permission grants = %#v, want none", resources.Workflows[0].Jobs[0].PermissionGrants)
	}
	data, err := json.Marshal(resources)
	if err != nil {
		t.Fatalf("marshal resources: %v", err)
	}
	for _, forbidden := range []string{"write-all", "read-all", "unknown", "inputs.permission", "inputs.job_permission", "${{", "admin"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("parser output contains %q: %s", forbidden, data)
		}
	}
}

func TestParseDirParsesScalarPermissions(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		access  string
		wantLen int
	}{
		{name: "write all", value: "write-all", access: "write-all", wantLen: 1},
		{name: "read all", value: "read-all", access: "read-all", wantLen: 1},
		{name: "unknown", value: "admin-all", wantLen: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeWorkflow(t, root, "permissions.yml", `permissions: `+tt.value+`
jobs:
  test:
    steps:
      - uses: owner/repo@main
`)

			resources, err := ParseDir(root)
			if err != nil {
				t.Fatalf("parse dir: %v", err)
			}
			grants := resources.Workflows[0].PermissionGrants
			if len(grants) != tt.wantLen {
				t.Fatalf("grant count = %d, want %d: %#v", len(grants), tt.wantLen, grants)
			}
			if tt.wantLen == 0 {
				return
			}
			want := PermissionGrant{Scope: "workflow", Permission: "all", Access: tt.access}
			if !reflect.DeepEqual(grants[0], want) {
				t.Fatalf("grant = %#v, want %#v", grants[0], want)
			}
		})
	}
}

func TestParseDirEmptyPermissionsMapProducesNoGrants(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "permissions.yml", `permissions: {}
jobs:
  test:
    permissions: {}
    steps:
      - uses: owner/repo@main
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if len(resources.Workflows[0].PermissionGrants) != 0 {
		t.Fatalf("workflow grants = %#v, want none", resources.Workflows[0].PermissionGrants)
	}
	if len(resources.Workflows[0].Jobs[0].PermissionGrants) != 0 {
		t.Fatalf("job grants = %#v, want none", resources.Workflows[0].Jobs[0].PermissionGrants)
	}
}

func TestParseDirPermissionGrantsAreDeterministic(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "permissions.yml", `permissions:
  security-events: write
  contents: read
  actions: write
jobs:
  z:
    permissions:
      id-token: write
  a:
    permissions:
      deployments: write
`)

	first, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse first: %v", err)
	}
	second, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse second: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("parse output differs:\nfirst=%#v\nsecond=%#v", first, second)
	}
	wantWorkflow := []PermissionGrant{
		{Scope: "workflow", Permission: "actions", Access: "write"},
		{Scope: "workflow", Permission: "contents", Access: "read"},
		{Scope: "workflow", Permission: "security-events", Access: "write"},
	}
	if !reflect.DeepEqual(first.Workflows[0].PermissionGrants, wantWorkflow) {
		t.Fatalf("workflow grants = %#v, want %#v", first.Workflows[0].PermissionGrants, wantWorkflow)
	}
	gotJobs := []string{first.Workflows[0].Jobs[0].ID, first.Workflows[0].Jobs[1].ID}
	if !reflect.DeepEqual(gotJobs, []string{"a", "z"}) {
		t.Fatalf("jobs = %#v, want sorted IDs", gotJobs)
	}
}

func TestParseDirDetectsPullRequestTargetTriggers(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name: "unquoted scalar on",
			content: `on: pull_request_target
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`,
			want: true,
		},
		{
			name: "quoted scalar on",
			content: `"on": pull_request_target
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`,
			want: true,
		},
		{
			name: "sequence on",
			content: `on: [pull_request_target, push]
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`,
			want: true,
		},
		{
			name: "mapping on",
			content: `on:
  pull_request_target:
    branches: [main]
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`,
			want: true,
		},
		{
			name: "pull request is not pull request target",
			content: `on: pull_request
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeWorkflow(t, root, "workflow.yml", tt.content)

			resources, err := ParseDir(root)
			if err != nil {
				t.Fatalf("parse dir: %v", err)
			}
			got := resources.Workflows[0].TriggersPullRequestTarget
			if got != tt.want {
				t.Fatalf("TriggersPullRequestTarget = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseDirParsesSanitizedCheckoutHeadSelectors(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "unsafe.yml", `on:
  pull_request_target:
jobs:
  test:
    steps:
      - name: Head SHA
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          token: FAKE_GHA_WITH_SECRET_DO_NOT_RETAIN
      - name: Head ref
        uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
        with:
          ref: ${{ github.head_ref }}
      - name: Head repository and ref
        uses: actions/checkout
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
          ref: ${{ github.event.pull_request.head.ref }}
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	steps := resources.Workflows[0].Jobs[0].Steps
	if len(steps) != 3 {
		t.Fatalf("step count = %d, want 3: %#v", len(steps), steps)
	}
	want := [][]CheckoutHeadSelector{
		{{Field: "ref", MatchedExpression: "github.event.pull_request.head.sha"}},
		{{Field: "ref", MatchedExpression: "github.head_ref"}},
		{
			{Field: "ref", MatchedExpression: "github.event.pull_request.head.ref"},
			{Field: "repository", MatchedExpression: "github.event.pull_request.head.repo.full_name"},
		},
	}
	for i := range want {
		if !reflect.DeepEqual(steps[i].CheckoutHeadSelectors, want[i]) {
			t.Fatalf("step %d selectors = %#v, want %#v", i, steps[i].CheckoutHeadSelectors, want[i])
		}
	}
	data, err := json.Marshal(resources)
	if err != nil {
		t.Fatalf("marshal resources: %v", err)
	}
	for _, forbidden := range []string{"FAKE_GHA_WITH_SECRET_DO_NOT_RETAIN", "token"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("parser output contains %q: %s", forbidden, data)
		}
	}
}

func TestParseDirDoesNotParseLiteralOrFieldMismatchedCheckoutHeadSelectors(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "safe.yml", `on: pull_request_target
jobs:
  test:
    steps:
      - name: Literal ref text
        uses: actions/checkout@v4
        with:
          ref: refs/heads/github.event.pull_request.head.sha
      - name: SHA is not repository
        uses: actions/checkout@v4
        with:
          repository: ${{ github.event.pull_request.head.sha }}
      - name: Repository is not ref
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.repo.full_name }}
      - name: Larger expression is not selector identity
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
      - name: Whitespace around exact selector is accepted
        uses: actions/checkout@v4
        with:
          ref: refs/heads/${{   github.head_ref   }}
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	steps := resources.Workflows[0].Jobs[0].Steps
	if len(steps) != 5 {
		t.Fatalf("step count = %d, want 5: %#v", len(steps), steps)
	}
	for i := 0; i < 4; i++ {
		if len(steps[i].CheckoutHeadSelectors) != 0 {
			t.Fatalf("step %d selectors = %#v, want none", i, steps[i].CheckoutHeadSelectors)
		}
	}
	want := []CheckoutHeadSelector{{Field: "ref", MatchedExpression: "github.head_ref"}}
	if !reflect.DeepEqual(steps[4].CheckoutHeadSelectors, want) {
		t.Fatalf("step 4 selectors = %#v, want %#v", steps[4].CheckoutHeadSelectors, want)
	}
}

func TestParseDirDoesNotRetainExpressionOnlyUsesValues(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "expression.yml", `jobs:
  test:
    steps:
      - uses: ${{ secrets.ACTION_REF }}
      - uses: ${{ matrix.action }}
      - uses: owner/repo@${{ matrix.ref }}
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	steps := resources.Workflows[0].Jobs[0].Steps
	if len(steps) != 1 {
		t.Fatalf("step count = %d, want only static owner/repo expression-ref step: %#v", len(steps), steps)
	}
	if got := steps[0].Uses; got != "owner/repo@<expression>" {
		t.Fatalf("uses = %q, want sanitized expression ref", got)
	}
	data, err := json.Marshal(resources)
	if err != nil {
		t.Fatalf("marshal resources: %v", err)
	}
	for _, forbidden := range []string{"secrets.ACTION_REF", "matrix.action", "matrix.ref", "${{"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("parser output contains %q: %s", forbidden, data)
		}
	}
}

func TestParseDirDoesNotRetainIgnoredSecretLikeValues(t *testing.T) {
	root := t.TempDir()
	const envSecret = "FAKE_GHA_ENV_SECRET_DO_NOT_RETAIN"
	const withSecret = "FAKE_GHA_WITH_SECRET_DO_NOT_RETAIN"
	const runSecret = "FAKE_GHA_RUN_SECRET_DO_NOT_RETAIN"
	writeWorkflow(t, root, "secrets.yml", `name: Secret safety
env:
  API_TOKEN: FAKE_GHA_ENV_SECRET_DO_NOT_RETAIN
jobs:
  test:
    steps:
      - name: Run secret-like command
        run: echo FAKE_GHA_RUN_SECRET_DO_NOT_RETAIN
      - name: Login
        uses: owner/repo@main
        with:
          password: FAKE_GHA_WITH_SECRET_DO_NOT_RETAIN
        env:
          STEP_TOKEN: FAKE_GHA_ENV_SECRET_DO_NOT_RETAIN
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	data, err := json.Marshal(resources)
	if err != nil {
		t.Fatalf("marshal resources: %v", err)
	}
	for _, forbidden := range []string{envSecret, withSecret, runSecret, "password", "API_TOKEN", "STEP_TOKEN"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("parser output contains %q: %s", forbidden, data)
		}
	}
	if !strings.Contains(string(data), "owner/repo@main") {
		t.Fatalf("parser output does not contain uses value: %s", data)
	}
}

func TestParseDirMalformedWorkflowReturnsDeterministicFilenameError(t *testing.T) {
	root := t.TempDir()
	const fakeSecret = "FAKE_GHA_MALFORMED_SECRET_DO_NOT_RETAIN"
	writeWorkflow(t, root, "bad.yml", `name: bad
env:
  TOKEN: FAKE_GHA_MALFORMED_SECRET_DO_NOT_RETAIN
jobs: [
`)

	resources, err := ParseDir(root)
	if err == nil {
		t.Fatal("parse error = nil, want malformed YAML error")
	}
	if !reflect.DeepEqual(resources, Resources{}) {
		t.Fatalf("resources = %#v, want empty result on error", resources)
	}
	message := err.Error()
	if !strings.Contains(message, ".github/workflows/bad.yml") || !strings.Contains(message, "document 1") || !strings.Contains(message, "invalid YAML") {
		t.Fatalf("error = %q, want controlled filename, document, and invalid YAML message", message)
	}
	if strings.Contains(message, fakeSecret) {
		t.Fatalf("error contains secret-like value: %q", message)
	}
	if strings.Contains(message, "jobs:") || strings.Contains(message, "TOKEN:") {
		t.Fatalf("error contains raw workflow YAML: %q", message)
	}
}

func TestParseDirMalformedWorkflowUndefinedAliasErrorIsSanitized(t *testing.T) {
	root := t.TempDir()
	const fakeAlias = "FAKE_GHA_ALIAS_TOKEN_DO_NOT_RETAIN"
	writeWorkflow(t, root, "bad-alias.yml", `name: bad alias
jobs:
  test:
    steps:
      - uses: owner/repo@main
        with:
          token: *FAKE_GHA_ALIAS_TOKEN_DO_NOT_RETAIN
`)

	resources, err := ParseDir(root)
	if err == nil {
		t.Fatal("parse error = nil, want malformed YAML error")
	}
	if !reflect.DeepEqual(resources, Resources{}) {
		t.Fatalf("resources = %#v, want empty result on error", resources)
	}
	message := err.Error()
	if !strings.Contains(message, ".github/workflows/bad-alias.yml") || !strings.Contains(message, "document 1") || !strings.Contains(message, "invalid YAML") {
		t.Fatalf("error = %q, want controlled filename, document, and invalid YAML message", message)
	}
	for _, forbidden := range []string{fakeAlias, "unknown anchor", "token:", "with:", "owner/repo@main"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("error contains %q: %q", forbidden, message)
		}
	}
}

func TestParseDirMalformedSecondDocumentErrorIsSanitized(t *testing.T) {
	root := t.TempDir()
	const fakeAlias = "FAKE_GHA_SECOND_DOC_ALIAS_DO_NOT_RETAIN"
	writeWorkflow(t, root, "bad-second.yml", `name: valid
jobs:
  test:
    steps:
      - uses: owner/repo@0123456789abcdef0123456789abcdef01234567
---
with:
  token: *FAKE_GHA_SECOND_DOC_ALIAS_DO_NOT_RETAIN
`)

	resources, err := ParseDir(root)
	if err == nil {
		t.Fatal("parse error = nil, want malformed YAML error")
	}
	if !reflect.DeepEqual(resources, Resources{}) {
		t.Fatalf("resources = %#v, want empty result on error", resources)
	}
	message := err.Error()
	if !strings.Contains(message, ".github/workflows/bad-second.yml") || !strings.Contains(message, "document 2") || !strings.Contains(message, "invalid YAML") {
		t.Fatalf("error = %q, want controlled filename, document, and invalid YAML message", message)
	}
	for _, forbidden := range []string{fakeAlias, "unknown anchor", "token:", "with:", "owner/repo@"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("error contains %q: %q", forbidden, message)
		}
	}
}

func TestParseDirMalformedThirdDocumentErrorIsSanitized(t *testing.T) {
	root := t.TempDir()
	const fakeAlias = "FAKE_GHA_THIRD_DOC_ALIAS_DO_NOT_RETAIN"
	writeWorkflow(t, root, "bad-third.yml", `name: valid
jobs:
  test:
    steps:
      - uses: owner/repo@0123456789abcdef0123456789abcdef01234567
---
name: ignored second document
env:
  TOKEN: FAKE_GHA_IGNORED_DOC_VALUE_DO_NOT_RETAIN
---
with:
  token: *FAKE_GHA_THIRD_DOC_ALIAS_DO_NOT_RETAIN
`)

	resources, err := ParseDir(root)
	if err == nil {
		t.Fatal("parse error = nil, want malformed YAML error")
	}
	if !reflect.DeepEqual(resources, Resources{}) {
		t.Fatalf("resources = %#v, want empty result on error", resources)
	}
	message := err.Error()
	if !strings.Contains(message, ".github/workflows/bad-third.yml") || !strings.Contains(message, "document 3") || !strings.Contains(message, "invalid YAML") {
		t.Fatalf("error = %q, want controlled filename, document, and invalid YAML message", message)
	}
	for _, forbidden := range []string{fakeAlias, "FAKE_GHA_IGNORED_DOC_VALUE_DO_NOT_RETAIN", "unknown anchor", "token:", "with:", "env:"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("error contains %q: %q", forbidden, message)
		}
	}
}

func TestParseDirMultipleValidDocumentsUsesFirstDocumentDeterministically(t *testing.T) {
	root := t.TempDir()
	writeWorkflow(t, root, "multi.yml", `name: First
jobs:
  first:
    steps:
      - uses: owner/first@main
---
name: Ignored
env:
  TOKEN: FAKE_GHA_IGNORED_VALID_DOC_VALUE_DO_NOT_RETAIN
jobs:
  ignored:
    steps:
      - uses: owner/ignored@main
---
run: echo FAKE_GHA_IGNORED_RUN_VALUE_DO_NOT_RETAIN
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if len(resources.Workflows) != 1 || resources.Workflows[0].Name != "First" || len(resources.Workflows[0].Jobs) != 1 {
		t.Fatalf("resources = %#v, want first document workflow only", resources)
	}
	if got := resources.Workflows[0].Jobs[0].ID; got != "first" {
		t.Fatalf("job ID = %q, want first", got)
	}
	data, err := json.Marshal(resources)
	if err != nil {
		t.Fatalf("marshal resources: %v", err)
	}
	for _, forbidden := range []string{"FAKE_GHA_IGNORED_VALID_DOC_VALUE_DO_NOT_RETAIN", "FAKE_GHA_IGNORED_RUN_VALUE_DO_NOT_RETAIN", "owner/ignored@main"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("parser output contains %q: %s", forbidden, data)
		}
	}
}

func TestParseDirHandlesWorkflowPathsWithSpaces(t *testing.T) {
	root := t.TempDir()
	path := writeWorkflow(t, root, "release build.yml", `jobs:
  release:
    steps:
      - uses: owner/repo@main
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	source := resources.Workflows[0].Source
	if source.Filename != path || source.RelativePath != ".github/workflows/release build.yml" {
		t.Fatalf("source = %#v, want path with spaces preserved safely", source)
	}
}

func TestParseDirMissingWorkflowDirectoryReturnsEmptyResources(t *testing.T) {
	resources, err := ParseDir(t.TempDir())
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if !reflect.DeepEqual(resources, Resources{}) {
		t.Fatalf("resources = %#v, want empty", resources)
	}
}

func writeWorkflow(t *testing.T, root, name, content string) string {
	t.Helper()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir workflows: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}
	return path
}
