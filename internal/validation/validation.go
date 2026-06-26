package validation

import (
	"sort"

	"pathproof/internal/analysis"
)

type Status string

const (
	StatusRemediated Status = "remediated"
	StatusFailed     Status = "failed"
	StatusSkipped    Status = "skipped"
)

type Result struct {
	FindingID analysis.FindingID `json:"finding_id"`
	RuleID    analysis.RuleID    `json:"rule_id"`
	Status    Status             `json:"status"`
	Summary   string             `json:"summary"`
}

func ValidatePatchedOutput(original []analysis.Finding, patched []analysis.Finding, patchedFindingIDs map[analysis.FindingID]bool) []Result {
	patchedByID := make(map[analysis.FindingID]struct{}, len(patched))
	for _, finding := range patched {
		if finding.RuleID != analysis.RulePublicWorkloadCanReadSecret {
			continue
		}
		patchedByID[finding.ID] = struct{}{}
	}

	results := make([]Result, 0)
	for _, finding := range original {
		if finding.RuleID != analysis.RulePublicWorkloadCanReadSecret {
			continue
		}
		result := Result{
			FindingID: finding.ID,
			RuleID:    finding.RuleID,
		}
		if !patchedFindingIDs[finding.ID] {
			result.Status = StatusSkipped
			result.Summary = "No written patch output was available to validate this finding."
		} else if _, exists := patchedByID[finding.ID]; exists {
			result.Status = StatusFailed
			result.Summary = "PP-K8S-001 still appears after rescanning patched output."
		} else {
			result.Status = StatusRemediated
			result.Summary = "PP-K8S-001 no longer appears in patched output."
		}
		results = append(results, result)
	}

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].FindingID != results[j].FindingID {
			return results[i].FindingID < results[j].FindingID
		}
		return results[i].RuleID < results[j].RuleID
	})
	return results
}
