package patchpreview

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"pathproof/internal/remediation"

	"gopkg.in/yaml.v3"
)

func TestBuildRoleBindingMultiSubjectPreviewGenerated(t *testing.T) {
	root := t.TempDir()
	original := configMapDocument() + "---\n" + roleBindingDocument("read-secrets", "prod", []string{"api", "worker"}) + "---\n" + serviceAccountDocument("worker", "prod")
	writeFile(t, root, "bindings.yaml", original)
	plan := planWithChanges("plan:b", remediation.NarrowBindingSubject, []remediation.Change{narrowChange("bindings.yaml#document=2", "RoleBinding", "prod", "read-secrets", "prod/api")})

	previews := mustBuild(t, root, []remediation.Plan{plan})

	if len(previews) != 1 {
		t.Fatalf("preview count = %d, want 1: %#v", len(previews), previews)
	}
	preview := previews[0]
	if preview.Status != StatusGenerated || preview.File != "bindings.yaml" || preview.Diff == "" {
		t.Fatalf("preview = %#v, want generated diff for bindings.yaml", preview)
	}
	assertDiffShape(t, preview.Diff, "bindings.yaml")
	assertContains(t, preview.Diff, "-  name: api\n")
	assertContains(t, preview.Diff, "   name: worker\n")
	if strings.Contains(preview.Diff, "/var/") || strings.Contains(preview.Diff, root) {
		t.Fatalf("diff contains machine-specific path: %s", preview.Diff)
	}
	patched := applyUnifiedDiff(t, original, preview.Diff)
	assertYAMLParses(t, patched)
	assertContains(t, patched, "kind: ConfigMap")
	assertContains(t, patched, "name: worker")
	if strings.Contains(patched, "name: api\n  namespace: prod") {
		t.Fatalf("patched YAML still contains removed ServiceAccount subject:\n%s", patched)
	}
	assertFileUnchanged(t, root, "bindings.yaml", original)
}

func TestBuildRoleBindingOmittedNamespaceDefaultsToDefaultForTargetMatching(t *testing.T) {
	root := t.TempDir()
	original := roleBindingDocumentWithoutNamespace("read-secrets", []subject{{namespace: "default", name: "vulnerable-sa"}, {namespace: "default", name: "safe-sa"}})
	writeFile(t, root, "default-binding.yaml", original)
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{narrowChange("default-binding.yaml#document=1", "RoleBinding", "default", "read-secrets", "default/vulnerable-sa")})

	previews := mustBuild(t, root, []remediation.Plan{plan})

	if len(previews) != 1 {
		t.Fatalf("preview count = %d, want 1: %#v", len(previews), previews)
	}
	preview := previews[0]
	if preview.Status != StatusGenerated {
		t.Fatalf("preview status = %q reason = %q, want generated", preview.Status, preview.Reason)
	}
	assertDiffShape(t, preview.Diff, "default-binding.yaml")
	assertContains(t, preview.Diff, "-  name: vulnerable-sa\n")
	assertContains(t, preview.Diff, "   name: safe-sa\n")
	if strings.Contains(preview.Diff, "+  namespace: default") {
		t.Fatalf("diff writes metadata namespace default into YAML:\n%s", preview.Diff)
	}
	patched := applyUnifiedDiff(t, original, preview.Diff)
	assertYAMLParses(t, patched)
	if strings.Contains(patched, "name: vulnerable-sa\n  namespace: default") {
		t.Fatalf("patched YAML still contains removed ServiceAccount subject:\n%s", patched)
	}
	assertContains(t, patched, "name: safe-sa")
	assertContains(t, patched, "namespace: default")
	if strings.Contains(patched, "metadata:\n  name: read-secrets\n  namespace: default") {
		t.Fatalf("patched YAML added metadata namespace default:\n%s", patched)
	}
	assertFileUnchanged(t, root, "default-binding.yaml", original)
}

func TestBuildRoleBindingExplicitDefaultNamespaceStillGeneratesPreview(t *testing.T) {
	root := t.TempDir()
	original := roleBindingDocument("read-secrets", "default", []string{"vulnerable-sa", "safe-sa"})
	writeFile(t, root, "explicit-default-binding.yaml", original)
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{narrowChange("explicit-default-binding.yaml#document=1", "RoleBinding", "default", "read-secrets", "default/vulnerable-sa")})

	previews := mustBuild(t, root, []remediation.Plan{plan})

	if len(previews) != 1 || previews[0].Status != StatusGenerated {
		t.Fatalf("previews = %#v, want generated explicit-default RoleBinding preview", previews)
	}
	assertContains(t, previews[0].Diff, "-  name: vulnerable-sa\n")
	assertContains(t, previews[0].Diff, "   name: safe-sa\n")
	assertYAMLParses(t, applyUnifiedDiff(t, original, previews[0].Diff))
	assertFileUnchanged(t, root, "explicit-default-binding.yaml", original)
}

func TestBuildRoleBindingOmittedNamespaceRejectsNonDefaultTarget(t *testing.T) {
	root := t.TempDir()
	original := roleBindingDocumentWithoutNamespace("read-secrets", []subject{{namespace: "default", name: "vulnerable-sa"}, {namespace: "default", name: "safe-sa"}})
	writeFile(t, root, "default-binding.yaml", original)
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{narrowChange("default-binding.yaml#document=1", "RoleBinding", "prod", "read-secrets", "default/vulnerable-sa")})

	previews := mustBuild(t, root, []remediation.Plan{plan})

	if len(previews) != 1 {
		t.Fatalf("preview count = %d, want 1", len(previews))
	}
	if previews[0].Status != StatusUnsupported {
		t.Fatalf("preview status = %q, want unsupported: %#v", previews[0].Status, previews[0])
	}
	assertContains(t, previews[0].Reason, "referenced document")
	if previews[0].Diff != "" {
		t.Fatalf("diff = %q, want empty", previews[0].Diff)
	}
	assertFileUnchanged(t, root, "default-binding.yaml", original)
}

func TestBuildClusterRoleBindingMultiSubjectPreviewGenerated(t *testing.T) {
	root := t.TempDir()
	original := clusterRoleBindingDocument("read-secrets", []subject{{namespace: "prod", name: "api"}, {namespace: "prod", name: "worker"}})
	writeFile(t, root, "cluster-binding.yaml", original)
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{narrowChange("cluster-binding.yaml#document=1", "ClusterRoleBinding", "", "read-secrets", "prod/api")})

	previews := mustBuild(t, root, []remediation.Plan{plan})

	if len(previews) != 1 || previews[0].Status != StatusGenerated {
		t.Fatalf("previews = %#v, want generated ClusterRoleBinding preview", previews)
	}
	assertContains(t, previews[0].Diff, "-  name: api\n")
	assertContains(t, previews[0].Diff, "   name: worker\n")
	assertYAMLParses(t, applyUnifiedDiff(t, original, previews[0].Diff))
}

func TestBuildClusterRoleBindingNamespaceBehaviorUnchanged(t *testing.T) {
	root := t.TempDir()
	original := clusterRoleBindingDocument("read-secrets", []subject{{namespace: "default", name: "vulnerable-sa"}, {namespace: "default", name: "safe-sa"}})
	writeFile(t, root, "cluster-binding.yaml", original)
	generatedPlan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{narrowChange("cluster-binding.yaml#document=1", "ClusterRoleBinding", "", "read-secrets", "default/vulnerable-sa")})
	unsupportedPlan := planWithChanges("plan:b", remediation.NarrowBindingSubject, []remediation.Change{narrowChange("cluster-binding.yaml#document=1", "ClusterRoleBinding", "default", "read-secrets", "default/vulnerable-sa")})

	generated := mustBuild(t, root, []remediation.Plan{generatedPlan})
	unsupported := mustBuild(t, root, []remediation.Plan{unsupportedPlan})

	if len(generated) != 1 || generated[0].Status != StatusGenerated {
		t.Fatalf("generated = %#v, want ClusterRoleBinding preview without target namespace", generated)
	}
	if len(unsupported) != 1 || unsupported[0].Status != StatusUnsupported {
		t.Fatalf("unsupported = %#v, want unsupported ClusterRoleBinding preview with target namespace", unsupported)
	}
	assertContains(t, unsupported[0].Reason, "referenced document")
	if unsupported[0].Diff != "" {
		t.Fatalf("diff = %q, want empty", unsupported[0].Diff)
	}
}

func TestBuildRoleBindingExplicitDifferentNamespaceRejectsDefaultTarget(t *testing.T) {
	root := t.TempDir()
	original := roleBindingDocument("read-secrets", "prod", []string{"api", "worker"})
	writeFile(t, root, "prod-binding.yaml", original)
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{narrowChange("prod-binding.yaml#document=1", "RoleBinding", "default", "read-secrets", "prod/api")})

	previews := mustBuild(t, root, []remediation.Plan{plan})

	if len(previews) != 1 || previews[0].Status != StatusUnsupported {
		t.Fatalf("previews = %#v, want unsupported explicit namespace mismatch", previews)
	}
	assertContains(t, previews[0].Reason, "referenced document")
	if previews[0].Diff != "" {
		t.Fatalf("diff = %q, want empty", previews[0].Diff)
	}
	assertFileUnchanged(t, root, "prod-binding.yaml", original)
}

func TestBuildRejectsSourceFileContainingSecretPayload(t *testing.T) {
	root := t.TempDir()
	const secretKey = "password"
	const secretValue = "FAKE_PATCH_PREVIEW_SECRET_VALUE_DO_NOT_RETAIN"
	original := `apiVersion: v1
kind: Secret
metadata:
  name: database-password
  namespace: prod
data:
  password: FAKE_PATCH_PREVIEW_SECRET_VALUE_DO_NOT_RETAIN
---
` + roleBindingDocument("read-secrets", "prod", []string{"api", "worker"})
	writeFile(t, root, "with-secret.yaml", original)
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{narrowChange("with-secret.yaml#document=2", "RoleBinding", "prod", "read-secrets", "prod/api")})

	previews := mustBuild(t, root, []remediation.Plan{plan})

	if got := previews[0].Status; got != StatusUnsupported {
		t.Fatalf("status = %q, want unsupported", got)
	}
	if previews[0].Diff != "" {
		t.Fatalf("diff = %q, want empty", previews[0].Diff)
	}
	for _, forbidden := range []string{secretKey, secretValue, "data", "stringData"} {
		if strings.Contains(previews[0].Reason, forbidden) {
			t.Fatalf("reason leaks forbidden Secret content %q: %q", forbidden, previews[0].Reason)
		}
	}
}

func TestBuildRequiresExactReferencedDocument(t *testing.T) {
	root := t.TempDir()
	original := roleBindingDocument("read-secrets", "prod", []string{"api", "worker"}) + "---\n" + configMapDocument()
	writeFile(t, root, "bindings.yaml", original)
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{narrowChange("bindings.yaml#document=2", "RoleBinding", "prod", "read-secrets", "prod/api")})

	previews := mustBuild(t, root, []remediation.Plan{plan})

	if previews[0].Status != StatusUnsupported {
		t.Fatalf("status = %q, want unsupported for mismatched referenced document", previews[0].Status)
	}
	assertContains(t, previews[0].Reason, "referenced document")
}

func TestBuildUnsupportedCases(t *testing.T) {
	tests := []struct {
		name       string
		filename   string
		content    string
		change     remediation.Change
		action     remediation.Action
		wantReason string
	}{
		{
			name:       "out of range document",
			filename:   "bindings.yaml",
			content:    roleBindingDocument("read-secrets", "prod", []string{"api", "worker"}),
			change:     narrowChange("bindings.yaml#document=2", "RoleBinding", "prod", "read-secrets", "prod/api"),
			action:     remediation.NarrowBindingSubject,
			wantReason: "outside",
		},
		{
			name:       "missing source file",
			change:     narrowChange("missing.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/api"),
			action:     remediation.NarrowBindingSubject,
			wantReason: "cannot be read",
		},
		{
			name:       "malformed YAML",
			filename:   "bad.yaml",
			content:    "apiVersion: [\n",
			change:     narrowChange("bad.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/api"),
			action:     remediation.NarrowBindingSubject,
			wantReason: "cannot be parsed",
		},
		{
			name:       "single remaining subject",
			filename:   "bindings.yaml",
			content:    roleBindingDocument("read-secrets", "prod", []string{"api"}),
			change:     narrowChange("bindings.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/api"),
			action:     remediation.NarrowBindingSubject,
			wantReason: "empty",
		},
		{
			name:       "target subject missing",
			filename:   "bindings.yaml",
			content:    roleBindingDocument("read-secrets", "prod", []string{"worker", "other"}),
			change:     narrowChange("bindings.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/api"),
			action:     remediation.NarrowBindingSubject,
			wantReason: "not found",
		},
		{
			name:       "namespace-less subject unsupported",
			filename:   "bindings.yaml",
			content:    roleBindingDocumentWithNamespaceLessSubject(),
			change:     narrowChange("bindings.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/api"),
			action:     remediation.NarrowBindingSubject,
			wantReason: "not found",
		},
		{
			name:       "unsupported action",
			filename:   "bindings.yaml",
			content:    roleBindingDocument("read-secrets", "prod", []string{"api", "worker"}),
			change:     remediation.Change{Action: remediation.RemoveSecretsResource, SourceReference: "bindings.yaml#document=1", Summary: "unsupported"},
			action:     remediation.RemoveSecretsResource,
			wantReason: "NarrowBindingSubject",
		},
		{
			name:       "malformed source reference",
			filename:   "bindings.yaml",
			content:    roleBindingDocument("read-secrets", "prod", []string{"api", "worker"}),
			change:     narrowChange("bindings.yaml", "RoleBinding", "prod", "read-secrets", "prod/api"),
			action:     remediation.NarrowBindingSubject,
			wantReason: "filename#document=N",
		},
		{
			name:       "absolute source reference",
			filename:   "bindings.yaml",
			content:    roleBindingDocument("read-secrets", "prod", []string{"api", "worker"}),
			change:     narrowChange(filepath.Join(string(filepath.Separator), "tmp", "bindings.yaml")+"#document=1", "RoleBinding", "prod", "read-secrets", "prod/api"),
			action:     remediation.NarrowBindingSubject,
			wantReason: "relative",
		},
		{
			name:       "escaping source reference",
			filename:   "bindings.yaml",
			content:    roleBindingDocument("read-secrets", "prod", []string{"api", "worker"}),
			change:     narrowChange("../bindings.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/api"),
			action:     remediation.NarrowBindingSubject,
			wantReason: "escapes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			if tt.filename != "" {
				writeFile(t, root, tt.filename, tt.content)
			}
			plan := planWithChanges("plan:a", tt.action, []remediation.Change{tt.change})

			previews := mustBuild(t, root, []remediation.Plan{plan})

			if len(previews) != 1 {
				t.Fatalf("preview count = %d, want 1", len(previews))
			}
			if previews[0].Status != StatusUnsupported {
				t.Fatalf("status = %q, want unsupported: %#v", previews[0].Status, previews[0])
			}
			assertContains(t, previews[0].Reason, tt.wantReason)
			if previews[0].Diff != "" {
				t.Fatalf("diff = %q, want empty for unsupported", previews[0].Diff)
			}
		})
	}
}

func TestBuildMultipleChangesProduceDeterministicPreviews(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.yaml", roleBindingDocument("read-a", "prod", []string{"api", "worker"}))
	writeFile(t, root, "b.yaml", roleBindingDocument("read-b", "prod", []string{"api", "worker"}))
	planB := planWithChanges("plan:b", remediation.NarrowBindingSubject, []remediation.Change{narrowChange("b.yaml#document=1", "RoleBinding", "prod", "read-b", "prod/api")})
	planA := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{
		narrowChange("a.yaml#document=1", "RoleBinding", "prod", "read-a", "prod/api"),
		narrowChange("b.yaml#document=1", "RoleBinding", "prod", "read-b", "prod/api"),
	})

	first := mustBuild(t, root, []remediation.Plan{planB, planA})
	second := mustBuild(t, root, []remediation.Plan{planB, planA})

	if string(mustJSON(t, first)) != string(mustJSON(t, second)) {
		t.Fatalf("repeated Build differs:\nfirst: %s\nsecond: %s", mustJSON(t, first), mustJSON(t, second))
	}
	gotOrder := []string{
		string(first[0].PlanID) + ":" + first[0].File,
		string(first[1].PlanID) + ":" + first[1].File,
		string(first[2].PlanID) + ":" + first[2].File,
	}
	wantOrder := []string{"plan:a:a.yaml", "plan:a:b.yaml", "plan:b:b.yaml"}
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("order = %#v, want %#v", gotOrder, wantOrder)
	}
	if first[1].ChangeIndex != 1 {
		t.Fatalf("second plan:a preview change_index = %d, want 1", first[1].ChangeIndex)
	}
}

func TestBuildAcceptsCurrentRelativeSourceConvention(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	writeFile(t, root, "bindings.yaml", roleBindingDocument("read-secrets", "prod", []string{"api", "worker"}))
	sourceReference := filepath.Join("scan", "bindings.yaml") + "#document=1"
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{narrowChange(sourceReference, "RoleBinding", "prod", "read-secrets", "prod/api")})
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(parent); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		if err := os.Chdir(cwd); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	}()

	previews := mustBuild(t, "scan", []remediation.Plan{plan})

	if previews[0].Status != StatusGenerated || previews[0].File != "bindings.yaml" {
		t.Fatalf("preview = %#v, want generated with relative file path", previews[0])
	}
}

func mustBuild(t *testing.T, root string, plans []remediation.Plan) []Preview {
	t.Helper()
	previews, err := Build(root, plans)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return previews
}

func planWithChanges(id remediation.PlanID, action remediation.Action, changes []remediation.Change) remediation.Plan {
	return remediation.Plan{
		ID: id,
		Options: []remediation.Option{{
			Action:  action,
			Summary: string(action),
			Changes: changes,
		}},
	}
}

func narrowChange(sourceReference, kind, namespace, name, serviceAccount string) remediation.Change {
	return remediation.Change{
		Action:          remediation.NarrowBindingSubject,
		Target:          remediation.Target{Kind: kind, Namespace: namespace, Name: name},
		SourceReference: sourceReference,
		Subject:         serviceAccount,
		Summary:         "Remove only ServiceAccount " + serviceAccount + ".",
	}
}

func writeFile(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func assertFileUnchanged(t *testing.T, root, name, want string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if string(data) != want {
		t.Fatalf("source file changed:\ngot:\n%s\nwant:\n%s", data, want)
	}
}

func assertDiffShape(t *testing.T, diff, path string) {
	t.Helper()
	assertContains(t, diff, "--- "+path+"\n")
	assertContains(t, diff, "+++ "+path+"\n")
	assertContains(t, diff, "@@")
	if strings.Contains(diff, "\t") {
		t.Fatalf("diff contains a tab, possible timestamp: %q", diff)
	}
	if !strings.HasSuffix(diff, "\n") || strings.HasSuffix(strings.TrimSuffix(diff, "\n"), "\n") {
		t.Fatalf("diff must have exactly one trailing newline: %q", diff)
	}
}

func applyUnifiedDiff(t *testing.T, original, diff string) string {
	t.Helper()
	oldLines := splitLines(ensureTrailingNewline(original))
	diffLines := splitLines(diff)
	if len(diffLines) < 3 || !strings.HasPrefix(diffLines[0], "--- ") || !strings.HasPrefix(diffLines[1], "+++ ") {
		t.Fatalf("invalid diff headers:\n%s", diff)
	}
	oldIndex := 0
	var patched []string
	for i := 2; i < len(diffLines); {
		if !strings.HasPrefix(diffLines[i], "@@ ") {
			t.Fatalf("missing hunk header at line %d: %q", i, diffLines[i])
		}
		var oldStart, oldCount, newStart, newCount int
		if _, err := fmt.Sscanf(diffLines[i], "@@ -%d,%d +%d,%d @@", &oldStart, &oldCount, &newStart, &newCount); err != nil {
			t.Fatalf("parse hunk header %q: %v", diffLines[i], err)
		}
		for oldIndex < oldStart-1 {
			patched = append(patched, oldLines[oldIndex])
			oldIndex++
		}
		i++
		for i < len(diffLines) && !strings.HasPrefix(diffLines[i], "@@ ") {
			line := diffLines[i]
			if line == "" {
				t.Fatalf("empty diff line")
			}
			switch line[0] {
			case ' ':
				patched = append(patched, line[1:])
				oldIndex++
			case '-':
				oldIndex++
			case '+':
				patched = append(patched, line[1:])
			default:
				t.Fatalf("unexpected diff line: %q", line)
			}
			i++
		}
	}
	patched = append(patched, oldLines[oldIndex:]...)
	return strings.Join(patched, "")
}

func assertYAMLParses(t *testing.T, content string) {
	t.Helper()
	decoder := yaml.NewDecoder(strings.NewReader(content))
	for {
		var document yaml.Node
		err := decoder.Decode(&document)
		if err != nil {
			if err == io.EOF {
				return
			}
			t.Fatalf("patched YAML does not parse: %v\n%s", err, content)
		}
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return data
}

func assertContains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("got %q, want substring %q", got, want)
	}
}

type subject struct {
	namespace string
	name      string
}

func configMapDocument() string {
	return `apiVersion: v1
kind: ConfigMap
metadata:
  name: unrelated
  namespace: prod
data:
  setting: enabled
`
}

func serviceAccountDocument(name, namespace string) string {
	return `apiVersion: v1
kind: ServiceAccount
metadata:
  name: ` + name + `
  namespace: ` + namespace + `
`
}

func roleBindingDocument(name, namespace string, subjects []string) string {
	var out strings.Builder
	out.WriteString(`apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ` + name + `
  namespace: ` + namespace + `
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: secret-reader
subjects:
`)
	for _, subject := range subjects {
		out.WriteString(`- kind: ServiceAccount
  name: ` + subject + `
  namespace: ` + namespace + `
`)
	}
	return out.String()
}

func roleBindingDocumentWithoutNamespace(name string, subjects []subject) string {
	var out strings.Builder
	out.WriteString(`apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ` + name + `
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: secret-reader
subjects:
`)
	for _, subject := range subjects {
		out.WriteString(`- kind: ServiceAccount
  name: ` + subject.name + `
  namespace: ` + subject.namespace + `
`)
	}
	return out.String()
}

func clusterRoleBindingDocument(name string, subjects []subject) string {
	var out strings.Builder
	out.WriteString(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ` + name + `
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: secret-reader
subjects:
`)
	for _, subject := range subjects {
		out.WriteString(`- kind: ServiceAccount
  name: ` + subject.name + `
  namespace: ` + subject.namespace + `
`)
	}
	return out.String()
}

func roleBindingDocumentWithNamespaceLessSubject() string {
	return `apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-secrets
  namespace: prod
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: secret-reader
subjects:
- kind: ServiceAccount
  name: api
- kind: ServiceAccount
  name: worker
  namespace: prod
`
}
