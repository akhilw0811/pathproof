package rules

import (
	"reflect"
	"testing"
)

var expectedRuleIDs = []string{
	"PP-K8S-001",
	"PP-GHA-001",
	"PP-GHA-002",
	"PP-GHA-003",
	"PP-AWS-001",
	"PP-XDOMAIN-001",
	"PP-XDOMAIN-002",
	"PP-XDOMAIN-003",
	"PP-XDOMAIN-004",
}

func TestAllRulesAreCompleteUniqueAndOrdered(t *testing.T) {
	all := All()
	if len(all) != len(expectedRuleIDs) {
		t.Fatalf("All len = %d, want %d", len(all), len(expectedRuleIDs))
	}
	seen := make(map[string]struct{}, len(all))
	for i, rule := range all {
		if rule.ID != expectedRuleIDs[i] {
			t.Fatalf("All()[%d].ID = %q, want %q", i, rule.ID, expectedRuleIDs[i])
		}
		if _, ok := seen[rule.ID]; ok {
			t.Fatalf("duplicate rule ID %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		if rule.ID == "" || rule.Title == "" || rule.Severity == "" || rule.SARIFLevel == "" || rule.Category == "" || rule.Description == "" {
			t.Fatalf("rule has empty metadata: %#v", rule)
		}
	}
}

func TestIDsAreDeterministicAndOrdered(t *testing.T) {
	if got := IDs(); !reflect.DeepEqual(got, expectedRuleIDs) {
		t.Fatalf("IDs = %#v, want %#v", got, expectedRuleIDs)
	}
	if got := IDs(); !reflect.DeepEqual(got, expectedRuleIDs) {
		t.Fatalf("second IDs = %#v, want %#v", got, expectedRuleIDs)
	}
}

func TestAllReturnsDefensiveCopy(t *testing.T) {
	first := All()
	first[0].ID = "PP-CHANGED"
	if got := All()[0].ID; got != expectedRuleIDs[0] {
		t.Fatalf("All returned mutable backing storage; first ID = %q", got)
	}
}

func TestIDsReturnsDefensiveCopy(t *testing.T) {
	first := IDs()
	first[0] = "PP-CHANGED"
	if got := IDs()[0]; got != expectedRuleIDs[0] {
		t.Fatalf("IDs returned mutable backing storage; first ID = %q", got)
	}
}

func TestLookupAndMustLookup(t *testing.T) {
	for _, id := range expectedRuleIDs {
		rule, ok := Lookup(id)
		if !ok {
			t.Fatalf("Lookup(%q) failed", id)
		}
		if rule.ID != id {
			t.Fatalf("Lookup(%q).ID = %q", id, rule.ID)
		}
		if got := MustLookup(id); got != rule {
			t.Fatalf("MustLookup(%q) = %#v, want %#v", id, got, rule)
		}
	}
	if _, ok := Lookup("PP-UNKNOWN-001"); ok {
		t.Fatalf("Lookup unknown rule succeeded")
	}
}

func TestSARIFLevelsAndSeverities(t *testing.T) {
	wantSeverity := map[string]Severity{
		"PP-K8S-001":     SeverityHigh,
		"PP-GHA-001":     SeverityMedium,
		"PP-GHA-002":     SeverityHigh,
		"PP-GHA-003":     SeverityHigh,
		"PP-AWS-001":     SeverityHigh,
		"PP-XDOMAIN-001": SeverityHigh,
		"PP-XDOMAIN-002": SeverityHigh,
		"PP-XDOMAIN-003": SeverityHigh,
		"PP-XDOMAIN-004": SeverityHigh,
	}
	validSARIFLevel := map[string]bool{"error": true, "warning": true, "note": true, "none": true}
	for _, rule := range All() {
		if !validSARIFLevel[rule.SARIFLevel] {
			t.Fatalf("%s SARIFLevel = %q, want current SARIF level value", rule.ID, rule.SARIFLevel)
		}
		if rule.Severity != wantSeverity[rule.ID] {
			t.Fatalf("%s Severity = %q, want %q", rule.ID, rule.Severity, wantSeverity[rule.ID])
		}
	}
}
