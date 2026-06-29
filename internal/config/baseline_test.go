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
	ghaID := testBaselineFindingID(analysis.RuleGitHubActionsUnpinnedAction, "b")
	k8sID := testBaselineFindingID(analysis.RulePublicWorkloadCanReadSecret, "a")
	findings := []analysis.Finding{
		{
			ID:               ghaID,
			RuleID:           analysis.RuleGitHubActionsUnpinnedAction,
			Title:            "FAKE_BASELINE_TITLE_SECRET_DO_NOT_RETAIN",
			Summary:          "FAKE_BASELINE_SUMMARY_SECRET_DO_NOT_RETAIN",
			SourceReferences: []string{"source-secret.yaml#document=1"},
		},
		{
			ID:       k8sID,
			RuleID:   analysis.RulePublicWorkloadCanReadSecret,
			Evidence: []analysis.FindingEvidence{{}},
		},
		{ID: ghaID},
	}

	data, count, err := baselineJSON(findings)
	if err != nil {
		t.Fatalf("baselineJSON: %v", err)
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}

	want := "{\n  \"suppressions\": [\n    {\n      \"finding_id\": \"" + string(ghaID) + "\",\n      \"reason\": \"Baseline accepted at generation time\"\n    },\n    {\n      \"finding_id\": \"" + string(k8sID) + "\",\n      \"reason\": \"Baseline accepted at generation time\"\n    }\n  ]\n}\n"
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
	findingID := testBaselineFindingID(analysis.RulePublicWorkloadCanReadSecret, "a")

	count, err := WriteBaseline(path, []analysis.Finding{{ID: findingID}})
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
	suppression, ok := cfg.Suppressions[findingID]
	if !ok {
		t.Fatalf("generated suppression missing: %#v", cfg.Suppressions)
	}
	if suppression.Reason != BaselineDefaultReason {
		t.Fatalf("reason = %q, want %q", suppression.Reason, BaselineDefaultReason)
	}
}

func TestLoadBaselineIDsUsesConfigSuppressionsOnlySortedAndDeduped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	ghaID := testBaselineFindingID(analysis.RuleGitHubActionsUnpinnedAction, "b")
	k8sID := testBaselineFindingID(analysis.RulePublicWorkloadCanReadSecret, "a")
	if err := os.WriteFile(path, []byte(`{
		"rules": {"disable": ["PP-K8S-001"]},
		"suppressions": [
			{"finding_id": "`+string(ghaID)+`", "reason": "FAKE_BASELINE_REASON_SECRET_DO_NOT_RETAIN"},
			{"finding_id": "`+string(k8sID)+`", "reason": "Accepted"},
			{"finding_id": "`+string(ghaID)+`", "reason": "Duplicate"}
		],
		"path_exclusions": ["ignored/"]
	}`), 0o600); err != nil {
		t.Fatalf("write baseline: %v", err)
	}

	ids, err := LoadBaselineIDs(path)
	if err != nil {
		t.Fatalf("LoadBaselineIDs: %v", err)
	}

	want := []analysis.FindingID{ghaID, k8sID}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("baseline IDs = %#v, want %#v", ids, want)
	}
}

func TestCompareBaselineIDsClassifiesAndResolvesDeterministically(t *testing.T) {
	existingID := testBaselineFindingID(analysis.RulePublicWorkloadCanReadSecret, "a")
	newID := testBaselineFindingID(analysis.RuleGitHubActionsUnpinnedAction, "b")
	resolvedAID := testBaselineFindingID(analysis.RuleGitHubActionsUnpinnedAction, "c")
	resolvedBID := testBaselineFindingID(analysis.RuleGitHubActionsUnpinnedAction, "d")
	comparison := CompareBaselineIDs(
		[]analysis.FindingID{
			existingID,
			resolvedBID,
			resolvedAID,
			resolvedBID,
		},
		[]analysis.Finding{
			{ID: existingID},
			{ID: newID},
		},
	)

	if comparison.NewFindingsCount != 1 || comparison.ExistingFindingsCount != 1 {
		t.Fatalf("comparison counts = %#v, want one new and one existing", comparison)
	}
	if comparison.StatusByFindingID[existingID] != BaselineStatusExisting {
		t.Fatalf("existing status = %q", comparison.StatusByFindingID[existingID])
	}
	if comparison.StatusByFindingID[newID] != BaselineStatusNew {
		t.Fatalf("new status = %q", comparison.StatusByFindingID[newID])
	}
	wantResolved := []analysis.FindingID{resolvedAID, resolvedBID}
	if !reflect.DeepEqual(comparison.ResolvedFindingIDs, wantResolved) {
		t.Fatalf("resolved IDs = %#v, want %#v", comparison.ResolvedFindingIDs, wantResolved)
	}
}

func TestCompareBaselineIDsEmptyBaselineMarksAllCurrentFindingsNew(t *testing.T) {
	comparison := CompareBaselineIDs(nil, []analysis.Finding{
		{ID: testBaselineFindingID(analysis.RulePublicWorkloadCanReadSecret, "a")},
		{ID: testBaselineFindingID(analysis.RuleGitHubActionsUnpinnedAction, "b")},
	})

	if comparison.NewFindingsCount != 2 || comparison.ExistingFindingsCount != 0 || len(comparison.ResolvedFindingIDs) != 0 {
		t.Fatalf("comparison = %#v, want all current findings new", comparison)
	}
}

func TestLoadBaselineIDsRejectsInvalidInputsWithSanitizedErrors(t *testing.T) {
	dir := t.TempDir()
	malformed := filepath.Join(dir, "malformed.json")
	if err := os.WriteFile(malformed, []byte(`{"suppressions":[{"finding_id":"finding:PP-K8S-001:abc","reason":"FAKE_BASELINE_PARSE_SECRET_DO_NOT_RETAIN"}`), 0o600); err != nil {
		t.Fatalf("write malformed baseline: %v", err)
	}
	nonObject := filepath.Join(dir, "non-object.json")
	if err := os.WriteFile(nonObject, []byte(`["FAKE_BASELINE_ARRAY_SECRET_DO_NOT_RETAIN"]`), 0o600); err != nil {
		t.Fatalf("write non-object baseline: %v", err)
	}
	unknown := filepath.Join(dir, "unknown.json")
	if err := os.WriteFile(unknown, []byte(`{"unknown":"FAKE_BASELINE_UNKNOWN_SECRET_DO_NOT_RETAIN"}`), 0o600); err != nil {
		t.Fatalf("write unknown baseline: %v", err)
	}
	unsafeID := filepath.Join(dir, "unsafe-id.json")
	if err := os.WriteFile(unsafeID, []byte(`{"suppressions":[{"finding_id":"finding:PP-GHA-001:/tmp/FAKE_BASELINE_ID_SECRET_DO_NOT_RETAIN","reason":"Accepted"}]}`), 0o600); err != nil {
		t.Fatalf("write unsafe ID baseline: %v", err)
	}
	tokenID := filepath.Join(dir, "token-id.json")
	if err := os.WriteFile(tokenID, []byte(`{"suppressions":[{"finding_id":"finding:PP-GHA-001:FAKE_BASELINE_TOKEN_SECRET_DO_NOT_RETAIN","reason":"Accepted"}]}`), 0o600); err != nil {
		t.Fatalf("write token ID baseline: %v", err)
	}

	tests := []struct {
		name      string
		path      string
		want      string
		forbidden []string
	}{
		{name: "empty", path: "", want: "path is empty"},
		{name: "remote", path: "https://example.invalid/baseline.json", want: "local file path", forbidden: []string{"example.invalid"}},
		{name: "url-like", path: "s3:bucket/baseline.json", want: "local file path", forbidden: []string{"bucket"}},
		{name: "missing", path: filepath.Join(dir, "missing.json"), want: "read baseline file", forbidden: []string{dir, "missing.json"}},
		{name: "directory", path: dir, want: "path is a directory", forbidden: []string{dir}},
		{name: "malformed", path: malformed, want: "not valid JSON", forbidden: []string{"FAKE_BASELINE_PARSE_SECRET_DO_NOT_RETAIN"}},
		{name: "non object", path: nonObject, want: "must be a JSON object", forbidden: []string{"FAKE_BASELINE_ARRAY_SECRET_DO_NOT_RETAIN"}},
		{name: "unknown field", path: unknown, want: "unknown or unsupported field", forbidden: []string{"FAKE_BASELINE_UNKNOWN_SECRET_DO_NOT_RETAIN"}},
		{name: "unsafe id", path: unsafeID, want: "unsupported format", forbidden: []string{"FAKE_BASELINE_ID_SECRET_DO_NOT_RETAIN", dir, "/tmp/"}},
		{name: "token id", path: tokenID, want: "unsupported format", forbidden: []string{"FAKE_BASELINE_TOKEN_SECRET_DO_NOT_RETAIN"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadBaselineIDs(tt.path)
			if err == nil {
				t.Fatal("LoadBaselineIDs error = nil")
			}
			assertErrorContains(t, err, tt.want)
			for _, forbidden := range tt.forbidden {
				assertErrorDoesNotContain(t, err, forbidden)
			}
		})
	}
}

func TestBaselineJSONDeterministicRepeatedOutput(t *testing.T) {
	findings := []analysis.Finding{
		{ID: testBaselineFindingID(analysis.RuleGitHubActionsUnpinnedAction, "b")},
		{ID: testBaselineFindingID(analysis.RuleGitHubActionsUnpinnedAction, "a")},
	}
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

	_, err := WriteBaseline(path, []analysis.Finding{{ID: testBaselineFindingID(analysis.RulePublicWorkloadCanReadSecret, "a")}})
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

func testBaselineFindingID(ruleID analysis.RuleID, hexDigit string) analysis.FindingID {
	return analysis.FindingID("finding:" + string(ruleID) + ":" + strings.Repeat(hexDigit, 64))
}
