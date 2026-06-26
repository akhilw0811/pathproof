package validation

import (
	"encoding/json"
	"reflect"
	"testing"

	"pathproof/internal/analysis"
	"pathproof/internal/graph"
)

func TestValidatePatchedOutputRemediatedWhenOriginalFindingAbsent(t *testing.T) {
	original := []analysis.Finding{testFinding("finding:a", analysis.RulePublicWorkloadCanReadSecret)}

	results := ValidatePatchedOutput(original, nil, map[analysis.FindingID]bool{"finding:a": true})

	want := []Result{{
		FindingID: "finding:a",
		RuleID:    analysis.RulePublicWorkloadCanReadSecret,
		Status:    StatusRemediated,
		Summary:   "PP-K8S-001 no longer appears in patched output.",
	}}
	if !reflect.DeepEqual(results, want) {
		t.Fatalf("results = %#v, want %#v", results, want)
	}
}

func TestValidatePatchedOutputFailedWhenOriginalFindingStillPresent(t *testing.T) {
	original := []analysis.Finding{testFinding("finding:a", analysis.RulePublicWorkloadCanReadSecret)}
	patched := []analysis.Finding{testFinding("finding:a", analysis.RulePublicWorkloadCanReadSecret)}

	results := ValidatePatchedOutput(original, patched, map[analysis.FindingID]bool{"finding:a": true})

	if len(results) != 1 || results[0].Status != StatusFailed {
		t.Fatalf("results = %#v, want failed", results)
	}
	if results[0].Summary != "PP-K8S-001 still appears after rescanning patched output." {
		t.Fatalf("summary = %q", results[0].Summary)
	}
}

func TestValidatePatchedOutputSkippedWhenNoPatchWasWrittenForFinding(t *testing.T) {
	original := []analysis.Finding{testFinding("finding:a", analysis.RulePublicWorkloadCanReadSecret)}

	results := ValidatePatchedOutput(original, nil, nil)

	if len(results) != 1 || results[0].Status != StatusSkipped {
		t.Fatalf("results = %#v, want skipped", results)
	}
}

func TestValidatePatchedOutputMixedFindingsAreDeterministic(t *testing.T) {
	original := []analysis.Finding{
		testFinding("finding:c", analysis.RulePublicWorkloadCanReadSecret),
		testFinding("finding:a", analysis.RulePublicWorkloadCanReadSecret),
		testFinding("finding:b", analysis.RulePublicWorkloadCanReadSecret),
	}
	patched := []analysis.Finding{
		testFinding("finding:b", analysis.RulePublicWorkloadCanReadSecret),
	}
	patchedFindingIDs := map[analysis.FindingID]bool{
		"finding:a": true,
		"finding:b": true,
	}

	results := ValidatePatchedOutput(original, patched, patchedFindingIDs)

	got := []struct {
		id     analysis.FindingID
		status Status
	}{
		{results[0].FindingID, results[0].Status},
		{results[1].FindingID, results[1].Status},
		{results[2].FindingID, results[2].Status},
	}
	want := []struct {
		id     analysis.FindingID
		status Status
	}{
		{"finding:a", StatusRemediated},
		{"finding:b", StatusFailed},
		{"finding:c", StatusSkipped},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order/status = %#v, want %#v", got, want)
	}
}

func TestValidatePatchedOutputIgnoresUnsupportedRuleIDs(t *testing.T) {
	original := []analysis.Finding{
		testFinding("finding:a", analysis.RuleID("PP-OTHER")),
		testFinding("finding:b", analysis.RulePublicWorkloadCanReadSecret),
	}
	patched := []analysis.Finding{
		testFinding("finding:a", analysis.RuleID("PP-OTHER")),
	}

	results := ValidatePatchedOutput(original, patched, map[analysis.FindingID]bool{"finding:b": true})

	if len(results) != 1 || results[0].FindingID != "finding:b" || results[0].Status != StatusRemediated {
		t.Fatalf("results = %#v, want only supported rule result", results)
	}
}

func TestValidatePatchedOutputRepeatedJSONIsByteIdentical(t *testing.T) {
	original := []analysis.Finding{
		testFinding("finding:b", analysis.RulePublicWorkloadCanReadSecret),
		testFinding("finding:a", analysis.RulePublicWorkloadCanReadSecret),
	}
	patched := []analysis.Finding{testFinding("finding:b", analysis.RulePublicWorkloadCanReadSecret)}
	patchedFindingIDs := map[analysis.FindingID]bool{"finding:a": true, "finding:b": true}

	first := mustMarshal(t, ValidatePatchedOutput(original, patched, patchedFindingIDs))
	second := mustMarshal(t, ValidatePatchedOutput(original, patched, patchedFindingIDs))

	if string(second) != string(first) {
		t.Fatalf("validation JSON differs:\nfirst: %s\nsecond: %s", first, second)
	}
}

func TestValidatePatchedOutputDoesNotMutateFindingSlices(t *testing.T) {
	original := []analysis.Finding{testFinding("finding:a", analysis.RulePublicWorkloadCanReadSecret)}
	patched := []analysis.Finding{testFinding("finding:a", analysis.RulePublicWorkloadCanReadSecret)}
	originalJSON := mustMarshal(t, original)
	patchedJSON := mustMarshal(t, patched)

	_ = ValidatePatchedOutput(original, patched, map[analysis.FindingID]bool{"finding:a": true})

	if got := mustMarshal(t, original); string(got) != string(originalJSON) {
		t.Fatalf("original mutated:\nbefore: %s\nafter:  %s", originalJSON, got)
	}
	if got := mustMarshal(t, patched); string(got) != string(patchedJSON) {
		t.Fatalf("patched mutated:\nbefore: %s\nafter:  %s", patchedJSON, got)
	}
}

func testFinding(id analysis.FindingID, ruleID analysis.RuleID) analysis.Finding {
	return analysis.Finding{
		ID:      id,
		RuleID:  ruleID,
		NodeIDs: []graph.NodeID{"node:endpoint", "node:workload", "node:serviceaccount", "node:secret"},
		EdgeIDs: []graph.EdgeID{"edge:route", "edge:runs-as", "edge:can-read"},
	}
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	return data
}
