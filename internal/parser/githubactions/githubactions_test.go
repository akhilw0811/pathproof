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
	if len(steps) != 1 || steps[0].Index != 1 || steps[0].Uses != "actions/setup-go@v5" {
		t.Fatalf("steps = %#v, want only uses step at original index 1", steps)
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
        uses: docker/login-action@v3
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
	if !strings.Contains(string(data), "docker/login-action@v3") {
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
