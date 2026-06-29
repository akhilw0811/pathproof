package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"pathproof/internal/analysis"
)

const BaselineDefaultReason = "Baseline accepted at generation time"

type baselineOutput struct {
	Suppressions []baselineSuppression `json:"suppressions"`
}

type baselineSuppression struct {
	FindingID string `json:"finding_id"`
	Reason    string `json:"reason"`
}

type BaselineStatus string

const (
	BaselineStatusNew      BaselineStatus = "new"
	BaselineStatusExisting BaselineStatus = "existing"
)

type BaselineComparison struct {
	NewFindingsCount      int
	ExistingFindingsCount int
	ResolvedFindingIDs    []analysis.FindingID
	StatusByFindingID     map[analysis.FindingID]BaselineStatus
}

type baselineFile interface {
	Write([]byte) (int, error)
	Close() error
}

var openBaselineFile = func(name string, flag int, perm os.FileMode) (baselineFile, error) {
	return os.OpenFile(name, flag, perm)
}

func WriteBaseline(path string, findings []analysis.Finding) (int, error) {
	data, count, err := baselineJSON(findings)
	if err != nil {
		return 0, err
	}
	if err := validateBaselineOutputPath(path); err != nil {
		return 0, err
	}
	if err := writeBaselineBytes(path, data); err != nil {
		return 0, err
	}
	return count, nil
}

func LoadBaselineIDs(path string) ([]analysis.FindingID, error) {
	if path == "" {
		return nil, fmt.Errorf("baseline path is empty")
	}
	if isRemotePath(path) || hasURLLikeScheme(path) {
		return nil, fmt.Errorf("baseline path must be a local file path")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline file")
	}
	if info.IsDir() {
		return nil, fmt.Errorf("baseline path is a directory")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline file")
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, err
	}

	ordered := make([]string, 0, len(cfg.Suppressions))
	for id := range cfg.Suppressions {
		ordered = append(ordered, string(id))
	}
	sort.Strings(ordered)

	out := make([]analysis.FindingID, 0, len(ordered))
	for _, id := range ordered {
		if err := validateBaselineFindingID(id); err != nil {
			return nil, err
		}
		out = append(out, analysis.FindingID(id))
	}
	return out, nil
}

func validateBaselineFindingID(id string) error {
	const prefix = "finding:"
	if !strings.HasPrefix(id, prefix) {
		return fmt.Errorf("baseline suppression finding_id has unsupported format")
	}
	rest := strings.TrimPrefix(id, prefix)
	ruleValue, digest, ok := strings.Cut(rest, ":")
	if !ok || ruleValue == "" || digest == "" || strings.Contains(digest, ":") {
		return fmt.Errorf("baseline suppression finding_id has unsupported format")
	}
	ruleID := analysis.RuleID(ruleValue)
	if _, ok := knownRules[ruleID]; !ok {
		return fmt.Errorf("baseline suppression finding_id has unsupported rule ID")
	}
	if len(digest) != 64 {
		return fmt.Errorf("baseline suppression finding_id has unsupported format")
	}
	for _, r := range digest {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return fmt.Errorf("baseline suppression finding_id has unsupported format")
	}
	return nil
}

func CompareBaselineIDs(baselineIDs []analysis.FindingID, findings []analysis.Finding) BaselineComparison {
	baselineSet := make(map[analysis.FindingID]struct{}, len(baselineIDs))
	for _, id := range baselineIDs {
		if id == "" {
			continue
		}
		baselineSet[id] = struct{}{}
	}

	currentSet := make(map[analysis.FindingID]struct{}, len(findings))
	statusByFindingID := make(map[analysis.FindingID]BaselineStatus, len(findings))
	newCount := 0
	existingCount := 0
	for _, finding := range findings {
		currentSet[finding.ID] = struct{}{}
		if _, ok := baselineSet[finding.ID]; ok {
			statusByFindingID[finding.ID] = BaselineStatusExisting
			existingCount++
			continue
		}
		statusByFindingID[finding.ID] = BaselineStatusNew
		newCount++
	}

	resolved := make([]string, 0)
	for id := range baselineSet {
		if _, ok := currentSet[id]; !ok {
			resolved = append(resolved, string(id))
		}
	}
	sort.Strings(resolved)

	resolvedIDs := make([]analysis.FindingID, 0, len(resolved))
	for _, id := range resolved {
		resolvedIDs = append(resolvedIDs, analysis.FindingID(id))
	}

	return BaselineComparison{
		NewFindingsCount:      newCount,
		ExistingFindingsCount: existingCount,
		ResolvedFindingIDs:    resolvedIDs,
		StatusByFindingID:     statusByFindingID,
	}
}

func baselineJSON(findings []analysis.Finding) ([]byte, int, error) {
	ids := make(map[analysis.FindingID]struct{}, len(findings))
	for _, finding := range findings {
		if finding.ID == "" {
			continue
		}
		ids[finding.ID] = struct{}{}
	}

	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, string(id))
	}
	sort.Strings(ordered)

	out := baselineOutput{
		Suppressions: make([]baselineSuppression, 0, len(ordered)),
	}
	for _, id := range ordered {
		out.Suppressions = append(out.Suppressions, baselineSuppression{
			FindingID: id,
			Reason:    BaselineDefaultReason,
		})
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, 0, fmt.Errorf("build baseline JSON")
	}
	data = append(data, '\n')
	return data, len(out.Suppressions), nil
}

func validateBaselineOutputPath(path string) error {
	if path == "" {
		return fmt.Errorf("baseline output path is empty")
	}
	if isRemotePath(path) || hasURLLikeScheme(path) {
		return fmt.Errorf("baseline output path must be a local file path")
	}
	parent := filepath.Dir(path)
	if parent == "" {
		parent = "."
	}
	info, err := os.Stat(parent)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("baseline output parent directory does not exist")
		}
		return fmt.Errorf("inspect baseline output parent directory")
	}
	if !info.IsDir() {
		return fmt.Errorf("baseline output parent path is not a directory")
	}
	if info, err := os.Stat(path); err == nil {
		if info.IsDir() {
			return fmt.Errorf("baseline output path is a directory")
		}
		return fmt.Errorf("baseline output file already exists")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect baseline output path")
	}
	return nil
}

func writeBaselineBytes(path string, data []byte) error {
	file, err := openBaselineFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create baseline output file")
	}
	removeOnError := true
	defer func() {
		if removeOnError {
			_ = os.Remove(path)
		}
	}()

	n, err := file.Write(data)
	if err != nil || n != len(data) {
		_ = file.Close()
		return fmt.Errorf("write baseline output file")
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close baseline output file")
	}
	removeOnError = false
	return nil
}
