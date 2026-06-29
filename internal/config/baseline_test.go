package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"pathproof/internal/analysis"
)

func TestBaselineJSONWritesSuppressionsOnlySortedAndDeduped(t *testing.T) {
	findings := []analysis.Finding{
		{
			ID:               "finding:PP-GHA-001:z",
			RuleID:           analysis.RuleGitHubActionsUnpinnedAction,
			Title:            "FAKE_BASELINE_TITLE_SECRET_DO_NOT_RETAIN",
			Summary:          "FAKE_BASELINE_SUMMARY_SECRET_DO_NOT_RETAIN",
			SourceReferences: []string{"source-secret.yaml#document=1"},
		},
		{
			ID:       "finding:PP-K8S-001:a",
			RuleID:   analysis.RulePublicWorkloadCanReadSecret,
			Evidence: []analysis.FindingEvidence{{}},
		},
		{ID: "finding:PP-GHA-001:z"},
	}

	data, count, err := baselineJSON(findings)
	if err != nil {
		t.Fatalf("baselineJSON: %v", err)
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}

	want := "{\n  \"suppressions\": [\n    {\n      \"finding_id\": \"finding:PP-GHA-001:z\",\n      \"reason\": \"Baseline accepted at generation time\"\n    },\n    {\n      \"finding_id\": \"finding:PP-K8S-001:a\",\n      \"reason\": \"Baseline accepted at generation time\"\n    }\n  ]\n}\n"
	if string(data) != want {
		t.Fatalf("baseline JSON = %s, want %s", data, want)
	}
	for _, forbidden := range []string{
		"FAKE_BASELINE_TITLE_SECRET_DO_NOT_RETAIN",
		"FAKE_BASELINE_SUMMARY_SECRET_DO_NOT_RETAIN",
		"source-secret.yaml",
		"rule_id",
		"title",
		"summary",
		"source_references",
		"evidence",
		"path",
		"patch",
	} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("baseline JSON contains forbidden content %q: %s", forbidden, data)
		}
	}
}

func TestBaselineJSONWritesEmptySuppressionsArray(t *testing.T) {
	data, count, err := baselineJSON(nil)
	if err != nil {
		t.Fatalf("baselineJSON: %v", err)
	}
	if count != 0 {
		t.Fatalf("count = %d, want 0", count)
	}
	if string(data) != "{\n  \"suppressions\": []\n}\n" {
		t.Fatalf("baseline JSON = %s", data)
	}
}

func TestWriteBaselineGeneratedConfigLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	count, err := WriteBaseline(path, []analysis.Finding{{ID: "finding:PP-K8S-001:abc"}})
	if err != nil {
		t.Fatalf("WriteBaseline: %v", err)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat baseline: %v", err)
	}
	if info.Mode().Perm()&0o111 != 0 {
		t.Fatalf("baseline mode = %v, want non-executable", info.Mode().Perm())
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load generated baseline: %v", err)
	}
	suppression, ok := cfg.Suppressions["finding:PP-K8S-001:abc"]
	if !ok {
		t.Fatalf("generated suppression missing: %#v", cfg.Suppressions)
	}
	if suppression.Reason != BaselineDefaultReason {
		t.Fatalf("reason = %q, want %q", suppression.Reason, BaselineDefaultReason)
	}
}

func TestBaselineJSONDeterministicRepeatedOutput(t *testing.T) {
	findings := []analysis.Finding{{ID: "finding:b"}, {ID: "finding:a"}}
	first, firstCount, err := baselineJSON(findings)
	if err != nil {
		t.Fatalf("first baselineJSON: %v", err)
	}
	second, secondCount, err := baselineJSON(findings)
	if err != nil {
		t.Fatalf("second baselineJSON: %v", err)
	}
	if firstCount != secondCount || !reflect.DeepEqual(first, second) {
		t.Fatalf("baseline output differs:\nfirst=%s\nsecond=%s", first, second)
	}
}

func TestWriteBaselineRejectsUnsafeOutputPaths(t *testing.T) {
	dir := t.TempDir()
	existingFile := filepath.Join(dir, "existing.json")
	if err := os.WriteFile(existingFile, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write existing file: %v", err)
	}
	existingDir := filepath.Join(dir, "existing-dir")
	if err := os.Mkdir(existingDir, 0o700); err != nil {
		t.Fatalf("mkdir existing dir: %v", err)
	}
	parentFile := filepath.Join(dir, "parent-file")
	if err := os.WriteFile(parentFile, []byte("not a dir"), 0o600); err != nil {
		t.Fatalf("write parent file: %v", err)
	}

	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "empty", path: "", want: "path is empty"},
		{name: "remote", path: "https://example.invalid/baseline.json", want: "local file path"},
		{name: "url-like scheme", path: "s3:bucket/baseline.json", want: "local file path"},
		{name: "existing file", path: existingFile, want: "already exists"},
		{name: "existing directory", path: existingDir, want: "is a directory"},
		{name: "missing parent", path: filepath.Join(dir, "missing", "baseline.json"), want: "parent directory does not exist"},
		{name: "parent not directory", path: filepath.Join(parentFile, "baseline.json"), want: "parent path is not a directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := WriteBaseline(tt.path, nil)
			if err == nil {
				t.Fatal("WriteBaseline error = nil")
			}
			assertErrorContains(t, err, tt.want)
			assertErrorDoesNotContain(t, err, "example.invalid")
			assertErrorDoesNotContain(t, err, "bucket")
			assertErrorDoesNotContain(t, err, dir)
		})
	}
}

func TestWriteBaselineWriteFailureIsSanitizedAndCleansUp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	original := openBaselineFile
	openBaselineFile = func(name string, flag int, perm os.FileMode) (baselineFile, error) {
		file, err := os.OpenFile(name, flag, perm)
		if err != nil {
			return nil, err
		}
		return failingBaselineFile{File: file}, nil
	}
	defer func() {
		openBaselineFile = original
	}()

	_, err := WriteBaseline(path, []analysis.Finding{{ID: "finding:PP-K8S-001:abc"}})
	if err == nil {
		t.Fatal("WriteBaseline error = nil")
	}
	assertErrorContains(t, err, "write baseline output file")
	assertErrorDoesNotContain(t, err, path)
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("baseline path exists after write failure or unexpected stat error: %v", statErr)
	}
}

type failingBaselineFile struct {
	*os.File
}

func (f failingBaselineFile) Write([]byte) (int, error) {
	return 0, errors.New("FAKE_BASELINE_WRITE_SECRET_DO_NOT_RETAIN")
}
