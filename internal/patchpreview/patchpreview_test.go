package patchpreview

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
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
			wantReason: "escapes",
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

func TestWriteRoleBindingPatchWritesCopyAndLeavesInputUnchanged(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	outputRoot := filepath.Join(parent, "patched")
	original := roleBindingDocument("read-secrets", "prod", []string{"api", "worker"})
	writeFile(t, root, "nested/bindings.yaml", original)
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{narrowChange("nested/bindings.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/api")})

	written, previews, err := Write(root, outputRoot, []remediation.Plan{plan})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	if len(previews) != 1 || previews[0].Status != StatusGenerated {
		t.Fatalf("previews = %#v, want one generated preview", previews)
	}
	if len(written) != 1 || written[0].PreviewStatus != StatusGenerated {
		t.Fatalf("written = %#v, want one generated output", written)
	}
	if written[0].Source != "nested/bindings.yaml" || written[0].Output != "patched/nested/bindings.yaml" {
		t.Fatalf("written paths = %#v, want stable relative paths", written[0])
	}
	if filepath.IsAbs(written[0].Output) || strings.Contains(written[0].Output, parent) {
		t.Fatalf("written output path is not display-safe: %#v", written[0])
	}
	patched := readFile(t, outputRoot, "nested/bindings.yaml")
	assertYAMLParses(t, patched)
	if strings.Contains(patched, "name: api\n  namespace: prod") {
		t.Fatalf("patched output still contains removed subject:\n%s", patched)
	}
	assertContains(t, patched, "name: worker")
	assertFileUnchanged(t, root, "nested/bindings.yaml", original)
}

func TestWriteUnsupportedOnlyDoesNotCreateOutputRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	outputRoot := filepath.Join(parent, "patched")
	writeFile(t, root, "bindings.yaml", roleBindingDocument("read-secrets", "prod", []string{"api", "worker"}))
	plan := planWithChanges("plan:a", remediation.RemoveSecretsResource, []remediation.Change{{Action: remediation.RemoveSecretsResource, SourceReference: "bindings.yaml#document=1", Summary: "unsupported"}})

	written, previews, err := Write(root, outputRoot, []remediation.Plan{plan})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	if len(previews) != 1 || previews[0].Status != StatusUnsupported {
		t.Fatalf("previews = %#v, want unsupported preview", previews)
	}
	if len(written) != 1 || written[0].PreviewStatus != StatusUnsupported {
		t.Fatalf("written = %#v, want unsupported output summary", written)
	}
	if _, err := os.Stat(outputRoot); !os.IsNotExist(err) {
		t.Fatalf("outputRoot stat err = %v, want not exist", err)
	}
}

func TestWriteRejectsUnsafeOutputRootsBeforeWriting(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeFile(t, root, "bindings.yaml", roleBindingDocument("read-secrets", "prod", []string{"api", "worker"}))
	nonEmpty := filepath.Join(parent, "non-empty")
	writeFile(t, nonEmpty, "existing.yaml", "kind: ConfigMap\n")
	fileOutput := filepath.Join(parent, "file-output")
	if err := os.WriteFile(fileOutput, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write file output: %v", err)
	}
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{narrowChange("bindings.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/api")})

	tests := []struct {
		name       string
		outputRoot string
		want       string
	}{
		{name: "same as input", outputRoot: root, want: "differ"},
		{name: "output inside input", outputRoot: filepath.Join(root, "patched"), want: "must not be inside scan"},
		{name: "input inside output", outputRoot: parent, want: "scan directory must not be inside"},
		{name: "existing file", outputRoot: fileOutput, want: "not a directory"},
		{name: "non-empty", outputRoot: nonEmpty, want: "must be empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Write(root, tt.outputRoot, []remediation.Plan{plan})
			if err == nil {
				t.Fatal("Write error = nil, want validation error")
			}
			assertContains(t, err.Error(), tt.want)
			assertFileUnchanged(t, root, "bindings.yaml", roleBindingDocument("read-secrets", "prod", []string{"api", "worker"}))
		})
	}
}

func TestWriteRejectsSymlinkedOutputRootInsideInput(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	original := roleBindingDocument("read-secrets", "prod", []string{"api", "worker"})
	writeFile(t, root, "bindings.yaml", original)
	insideTarget := filepath.Join(root, "target-output")
	if err := os.Mkdir(insideTarget, 0o700); err != nil {
		t.Fatalf("mkdir inside target: %v", err)
	}
	outputRoot := filepath.Join(parent, "linked-output")
	if err := os.Symlink(insideTarget, outputRoot); err != nil {
		t.Fatalf("symlink output root: %v", err)
	}
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{narrowChange("bindings.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/api")})

	_, _, err := Write(root, outputRoot, []remediation.Plan{plan})
	if err == nil {
		t.Fatal("Write error = nil, want symlinked output root rejection")
	}
	assertContains(t, err.Error(), "must not be inside scan")
	if _, statErr := os.Stat(filepath.Join(insideTarget, "bindings.yaml")); !os.IsNotExist(statErr) {
		t.Fatalf("inside target output stat err = %v, want not exist", statErr)
	}
	assertFileUnchanged(t, root, "bindings.yaml", original)
}

func TestWriteRejectsSymlinkedOutputParentInsideInput(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	original := roleBindingDocument("read-secrets", "prod", []string{"api", "worker"})
	writeFile(t, root, "bindings.yaml", original)
	insideParent := filepath.Join(root, "target-parent")
	if err := os.Mkdir(insideParent, 0o700); err != nil {
		t.Fatalf("mkdir inside parent: %v", err)
	}
	linkedParent := filepath.Join(parent, "linked-parent")
	if err := os.Symlink(insideParent, linkedParent); err != nil {
		t.Fatalf("symlink output parent: %v", err)
	}
	outputRoot := filepath.Join(linkedParent, "patched")
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{narrowChange("bindings.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/api")})

	_, _, err := Write(root, outputRoot, []remediation.Plan{plan})
	if err == nil {
		t.Fatal("Write error = nil, want symlinked output parent rejection")
	}
	assertContains(t, err.Error(), "must not be inside scan")
	if _, statErr := os.Stat(filepath.Join(insideParent, "patched")); !os.IsNotExist(statErr) {
		t.Fatalf("inside parent patched stat err = %v, want not exist", statErr)
	}
	assertFileUnchanged(t, root, "bindings.yaml", original)
}

func TestWriteAcceptsSymlinkedOutputRootToSafeEmptyDirectory(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	original := roleBindingDocument("read-secrets", "prod", []string{"api", "worker"})
	writeFile(t, root, "bindings.yaml", original)
	safeTarget := filepath.Join(parent, "safe-target")
	if err := os.Mkdir(safeTarget, 0o700); err != nil {
		t.Fatalf("mkdir safe target: %v", err)
	}
	outputRoot := filepath.Join(parent, "linked-safe")
	if err := os.Symlink(safeTarget, outputRoot); err != nil {
		t.Fatalf("symlink safe output root: %v", err)
	}
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{narrowChange("bindings.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/api")})

	written, previews, err := Write(root, outputRoot, []remediation.Plan{plan})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	if len(previews) != 1 || previews[0].Status != StatusGenerated {
		t.Fatalf("previews = %#v, want generated", previews)
	}
	if len(written) != 1 || written[0].Output != "linked-safe/bindings.yaml" {
		t.Fatalf("written = %#v, want stable symlink-root display output", written)
	}
	patched := readFile(t, safeTarget, "bindings.yaml")
	if strings.Contains(patched, "name: api\n  namespace: prod") {
		t.Fatalf("patched output still contains removed subject:\n%s", patched)
	}
	assertFileUnchanged(t, root, "bindings.yaml", original)
}

func TestWriteRejectsSymlinkResolvedInputInsideOutput(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeFile(t, root, "bindings.yaml", roleBindingDocument("read-secrets", "prod", []string{"api", "worker"}))
	outputRoot := filepath.Join(parent, "linked-parent")
	if err := os.Symlink(parent, outputRoot); err != nil {
		t.Fatalf("symlink parent output root: %v", err)
	}
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{narrowChange("bindings.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/api")})

	_, _, err := Write(root, outputRoot, []remediation.Plan{plan})
	if err == nil {
		t.Fatal("Write error = nil, want input-inside-resolved-output rejection")
	}
	assertContains(t, err.Error(), "scan directory must not be inside")
}

func TestBuildAndWriteAcceptAbsoluteSourceReferenceInsideRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	outputRoot := filepath.Join(parent, "patched")
	original := roleBindingDocument("read-secrets", "prod", []string{"api", "worker"})
	writeFile(t, root, "nested/bindings.yaml", original)
	sourceReference := filepath.Join(root, "nested", "bindings.yaml") + "#document=1"
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{narrowChange(sourceReference, "RoleBinding", "prod", "read-secrets", "prod/api")})

	previews := mustBuild(t, root, []remediation.Plan{plan})
	written, writePreviews, err := Write(root, outputRoot, []remediation.Plan{plan})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	if len(previews) != 1 || previews[0].Status != StatusGenerated || previews[0].File != "nested/bindings.yaml" {
		t.Fatalf("Build previews = %#v, want generated relative file", previews)
	}
	if len(writePreviews) != 1 || writePreviews[0].File != "nested/bindings.yaml" {
		t.Fatalf("Write previews = %#v, want relative file", writePreviews)
	}
	if len(written) != 1 || written[0].Source != "nested/bindings.yaml" || written[0].Output != "patched/nested/bindings.yaml" {
		t.Fatalf("written = %#v, want stable relative paths", written)
	}
	assertContains(t, readFile(t, outputRoot, "nested/bindings.yaml"), "name: worker")
	assertFileUnchanged(t, root, "nested/bindings.yaml", original)
}

func TestWriteRejectsAbsoluteSourceReferenceOutsideRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	outputRoot := filepath.Join(parent, "patched")
	writeFile(t, root, "bindings.yaml", roleBindingDocument("read-secrets", "prod", []string{"api", "worker"}))
	outside := filepath.Join(parent, "outside.yaml")
	if err := os.WriteFile(outside, []byte(roleBindingDocument("read-secrets", "prod", []string{"api", "worker"})), 0o600); err != nil {
		t.Fatalf("write outside source: %v", err)
	}
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{narrowChange(outside+"#document=1", "RoleBinding", "prod", "read-secrets", "prod/api")})

	written, previews, err := Write(root, outputRoot, []remediation.Plan{plan})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	if len(previews) != 1 || previews[0].Status != StatusUnsupported {
		t.Fatalf("previews = %#v, want unsupported", previews)
	}
	assertContains(t, previews[0].Reason, "escapes")
	if len(written) != 1 || written[0].PreviewStatus != StatusUnsupported {
		t.Fatalf("written = %#v, want unsupported", written)
	}
	if _, statErr := os.Stat(outputRoot); !os.IsNotExist(statErr) {
		t.Fatalf("outputRoot stat err = %v, want not exist", statErr)
	}
}

func TestWriteRejectsAbsoluteSourceReferenceSymlinkEscape(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	outputRoot := filepath.Join(parent, "patched")
	writeFile(t, root, "placeholder.yaml", roleBindingDocument("read-secrets", "prod", []string{"api", "worker"}))
	outside := filepath.Join(parent, "outside.yaml")
	if err := os.WriteFile(outside, []byte(roleBindingDocument("read-secrets", "prod", []string{"api", "worker"})), 0o600); err != nil {
		t.Fatalf("write outside source: %v", err)
	}
	link := filepath.Join(root, "linked-outside.yaml")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("symlink outside source: %v", err)
	}
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{narrowChange(link+"#document=1", "RoleBinding", "prod", "read-secrets", "prod/api")})

	written, previews, err := Write(root, outputRoot, []remediation.Plan{plan})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	if len(previews) != 1 || previews[0].Status != StatusUnsupported {
		t.Fatalf("previews = %#v, want unsupported", previews)
	}
	assertContains(t, previews[0].Reason, "escapes")
	if len(written) != 1 || written[0].PreviewStatus != StatusUnsupported {
		t.Fatalf("written = %#v, want unsupported", written)
	}
	if _, statErr := os.Stat(outputRoot); !os.IsNotExist(statErr) {
		t.Fatalf("outputRoot stat err = %v, want not exist", statErr)
	}
}

func TestWriteRejectsRelativeSourceReferenceSymlinkEscape(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	outputRoot := filepath.Join(parent, "patched")
	writeFile(t, root, "placeholder.yaml", roleBindingDocument("read-secrets", "prod", []string{"api", "worker"}))
	outside := filepath.Join(parent, "outside.yaml")
	if err := os.WriteFile(outside, []byte(roleBindingDocument("read-secrets", "prod", []string{"api", "worker"})), 0o600); err != nil {
		t.Fatalf("write outside source: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked-outside.yaml")); err != nil {
		t.Fatalf("symlink outside source: %v", err)
	}
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{narrowChange("linked-outside.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/api")})

	written, previews, err := Write(root, outputRoot, []remediation.Plan{plan})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	if len(previews) != 1 || previews[0].Status != StatusUnsupported {
		t.Fatalf("previews = %#v, want unsupported", previews)
	}
	assertContains(t, previews[0].Reason, "escapes")
	if len(written) != 1 || written[0].PreviewStatus != StatusUnsupported {
		t.Fatalf("written = %#v, want unsupported", written)
	}
	if _, statErr := os.Stat(outputRoot); !os.IsNotExist(statErr) {
		t.Fatalf("outputRoot stat err = %v, want not exist", statErr)
	}
}

func TestWriteSameFileMultipleChangesProduceOneDeterministicOutput(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	outputRoot := filepath.Join(parent, "patched")
	original := roleBindingDocument("read-secrets", "prod", []string{"api", "worker", "other"})
	writeFile(t, root, "bindings.yaml", original)
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{
		narrowChange("bindings.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/worker"),
		narrowChange("bindings.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/api"),
	})

	written, previews, err := Write(root, outputRoot, []remediation.Plan{plan})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	if len(previews) != 2 {
		t.Fatalf("preview count = %d, want 2: %#v", len(previews), previews)
	}
	if len(written) != 1 || written[0].Source != "bindings.yaml" {
		t.Fatalf("written = %#v, want one source output", written)
	}
	if entries := listFiles(t, outputRoot); !reflect.DeepEqual(entries, []string{"bindings.yaml"}) {
		t.Fatalf("output files = %#v, want one bindings.yaml", entries)
	}
	patched := readFile(t, outputRoot, "bindings.yaml")
	if strings.Contains(patched, "name: api\n  namespace: prod") || strings.Contains(patched, "name: worker\n  namespace: prod") {
		t.Fatalf("patched output retained removed subjects:\n%s", patched)
	}
	assertContains(t, patched, "name: other")
	assertYAMLParses(t, patched)
	assertFileUnchanged(t, root, "bindings.yaml", original)
}

func TestWriteDuplicateSameSubjectRemovalDoesNotDuplicateWrites(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	outputRoot := filepath.Join(parent, "patched")
	original := roleBindingDocument("read-secrets", "prod", []string{"api", "worker"})
	writeFile(t, root, "bindings.yaml", original)
	change := narrowChange("bindings.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/api")
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{change, change})

	written, previews, err := Write(root, outputRoot, []remediation.Plan{plan})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	if len(previews) != 2 {
		t.Fatalf("preview count = %d, want 2", len(previews))
	}
	if len(written) != 1 || written[0].PreviewStatus != StatusGenerated {
		t.Fatalf("written = %#v, want one generated output", written)
	}
	patched := readFile(t, outputRoot, "bindings.yaml")
	if got := strings.Count(patched, "kind: ServiceAccount"); got != 1 {
		t.Fatalf("ServiceAccount subject count = %d, want 1:\n%s", got, patched)
	}
}

func TestWriteConflictingSameFileChangesWriteNothing(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	outputRoot := filepath.Join(parent, "patched")
	original := roleBindingDocument("read-secrets", "prod", []string{"api", "worker"})
	writeFile(t, root, "bindings.yaml", original)
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{
		narrowChange("bindings.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/api"),
		narrowChange("bindings.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/worker"),
	})

	written, previews, err := Write(root, outputRoot, []remediation.Plan{plan})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	if len(previews) != 2 || previews[0].Status != StatusGenerated || previews[1].Status != StatusGenerated {
		t.Fatalf("previews = %#v, want individual generated previews", previews)
	}
	if len(written) != 1 || written[0].PreviewStatus != StatusUnsupported {
		t.Fatalf("written = %#v, want unsupported output summary", written)
	}
	assertContains(t, written[0].Reason, "conflict")
	if _, err := os.Stat(outputRoot); !os.IsNotExist(err) {
		t.Fatalf("outputRoot stat err = %v, want not exist", err)
	}
	assertFileUnchanged(t, root, "bindings.yaml", original)
}

func TestWriteFailureAfterDirectoryCreationCleansUpCreatedOutput(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	outputRoot := filepath.Join(parent, "patched")
	original := roleBindingDocument("read-secrets", "prod", []string{"api", "worker"})
	writeFile(t, root, "nested/bindings.yaml", original)
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{narrowChange("nested/bindings.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/api")})
	originalOpenOutputFile := openOutputFile
	openOutputFile = func(string, int, os.FileMode) (*os.File, error) {
		return nil, errors.New("controlled write failure")
	}
	defer func() {
		openOutputFile = originalOpenOutputFile
	}()

	_, _, err := Write(root, outputRoot, []remediation.Plan{plan})
	if err == nil {
		t.Fatal("Write error = nil, want controlled write failure")
	}
	assertContains(t, err.Error(), "write patch output")
	if _, statErr := os.Stat(outputRoot); !os.IsNotExist(statErr) {
		t.Fatalf("outputRoot stat err = %v, want cleanup to remove created directories", statErr)
	}
	assertFileUnchanged(t, root, "nested/bindings.yaml", original)
}

func TestWriteSecretBearingSourceIsNotWrittenOrCopied(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	outputRoot := filepath.Join(parent, "patched")
	const secretValue = "FAKE_PATCH_WRITE_SECRET_VALUE_DO_NOT_RETAIN"
	original := `apiVersion: v1
kind: Secret
metadata:
  name: database-password
  namespace: prod
data:
  password: FAKE_PATCH_WRITE_SECRET_VALUE_DO_NOT_RETAIN
---
` + roleBindingDocument("read-secrets", "prod", []string{"api", "worker"})
	writeFile(t, root, "with-secret.yaml", original)
	plan := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{narrowChange("with-secret.yaml#document=2", "RoleBinding", "prod", "read-secrets", "prod/api")})

	written, previews, err := Write(root, outputRoot, []remediation.Plan{plan})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	if len(previews) != 1 || previews[0].Status != StatusUnsupported {
		t.Fatalf("previews = %#v, want unsupported", previews)
	}
	if len(written) != 1 || written[0].PreviewStatus != StatusUnsupported {
		t.Fatalf("written = %#v, want unsupported", written)
	}
	if strings.Contains(string(mustJSON(t, written)), secretValue) {
		t.Fatalf("written summary leaks secret value: %#v", written)
	}
	if _, err := os.Stat(outputRoot); !os.IsNotExist(err) {
		t.Fatalf("outputRoot stat err = %v, want not exist", err)
	}
}

func TestWriteRepeatedAndReversedInputsAreDeterministic(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	original := roleBindingDocument("read-secrets", "prod", []string{"api", "worker", "other"})
	writeFile(t, root, "bindings.yaml", original)
	planForward := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{
		narrowChange("bindings.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/api"),
		narrowChange("bindings.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/worker"),
	})
	planReverse := planWithChanges("plan:a", remediation.NarrowBindingSubject, []remediation.Change{
		narrowChange("bindings.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/worker"),
		narrowChange("bindings.yaml#document=1", "RoleBinding", "prod", "read-secrets", "prod/api"),
	})

	firstWritten, _, err := Write(root, filepath.Join(parent, "patched-a"), []remediation.Plan{planForward})
	if err != nil {
		t.Fatalf("first Write: %v", err)
	}
	secondWritten, _, err := Write(root, filepath.Join(parent, "patched-b"), []remediation.Plan{planReverse})
	if err != nil {
		t.Fatalf("second Write: %v", err)
	}

	firstOutput := readFile(t, filepath.Join(parent, "patched-a"), "bindings.yaml")
	secondOutput := readFile(t, filepath.Join(parent, "patched-b"), "bindings.yaml")
	if secondOutput != firstOutput {
		t.Fatalf("patched output differs:\nfirst:\n%s\nsecond:\n%s", firstOutput, secondOutput)
	}
	firstWritten[0].Output = "patched/bindings.yaml"
	secondWritten[0].Output = "patched/bindings.yaml"
	if string(mustJSON(t, firstWritten)) != string(mustJSON(t, secondWritten)) {
		t.Fatalf("written summaries differ:\nfirst: %s\nsecond: %s", mustJSON(t, firstWritten), mustJSON(t, secondWritten))
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

func readFile(t *testing.T, root, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

func listFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Strings(files)
	return files
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
