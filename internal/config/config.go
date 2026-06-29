package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"pathproof/internal/analysis"
)

type Config struct {
	EnabledRules     map[analysis.RuleID]bool
	DisabledRules    []analysis.RuleID
	Suppressions     map[analysis.FindingID]Suppression
	SuppressionCount int
	PathExclusions   PathExclusions
}

type Suppression struct {
	FindingID analysis.FindingID
	Reason    string
}

type PathExclusion struct {
	Path      string
	Directory bool
}

type PathExclusions []PathExclusion

type rawConfig struct {
	Rules          *rawRules        `json:"rules,omitempty"`
	Suppressions   []rawSuppression `json:"suppressions,omitempty"`
	PathExclusions json.RawMessage  `json:"path_exclusions,omitempty"`
}

type rawRules struct {
	Disable []string `json:"disable,omitempty"`
	Enable  []string `json:"enable,omitempty"`
}

type rawSuppression struct {
	FindingID string `json:"finding_id"`
	Reason    string `json:"reason"`
}

var allRules = []analysis.RuleID{
	analysis.RuleAWSIAMRoleAdministrativePermissions,
	analysis.RuleGitHubActionsUnpinnedAction,
	analysis.RuleGitHubActionsUnsafePullRequestTargetCheckout,
	analysis.RuleGitHubActionsDangerousPermissions,
	analysis.RulePublicWorkloadCanReadSecret,
	analysis.RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole,
	analysis.RuleCrossDomainRiskyGitHubActionsCanAssumeAWSAdminRole,
	analysis.RuleCrossDomainRiskyGitHubActionsCanAccessAWSS3Bucket,
	analysis.RuleCrossDomainRiskyGitHubActionsCanAccessSensitiveAWSS3Bucket,
}

var knownRules = func() map[analysis.RuleID]struct{} {
	out := make(map[analysis.RuleID]struct{}, len(allRules))
	for _, ruleID := range allRules {
		out[ruleID] = struct{}{}
	}
	return out
}()

func Load(path string) (Config, error) {
	if path == "" {
		return Config{}, fmt.Errorf("config path is empty")
	}
	if isRemotePath(path) {
		return Config{}, fmt.Errorf("config path must be a local file path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config file")
	}
	parsed, err := Parse(data)
	if err != nil {
		return Config{}, err
	}
	return parsed, nil
}

func isRemotePath(path string) bool {
	return strings.Contains(path, "://")
}

func Parse(data []byte) (Config, error) {
	if !isJSONObject(data) {
		return Config{}, fmt.Errorf("pathproof config file must be a JSON object")
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var raw rawConfig
	if err := decoder.Decode(&raw); err != nil {
		return Config{}, sanitizedJSONError(err)
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return Config{}, err
	}
	return normalize(raw)
}

func normalize(raw rawConfig) (Config, error) {
	enabled := make(map[analysis.RuleID]bool, len(allRules))
	for _, ruleID := range allRules {
		enabled[ruleID] = true
	}

	if raw.Rules != nil {
		if len(raw.Rules.Enable) > 0 {
			enabled = make(map[analysis.RuleID]bool, len(raw.Rules.Enable))
			for i, value := range raw.Rules.Enable {
				ruleID, err := validateRuleID(value, fmt.Sprintf("rules.enable[%d]", i))
				if err != nil {
					return Config{}, err
				}
				enabled[ruleID] = true
			}
		}
		for i, value := range raw.Rules.Disable {
			ruleID, err := validateRuleID(value, fmt.Sprintf("rules.disable[%d]", i))
			if err != nil {
				return Config{}, err
			}
			delete(enabled, ruleID)
		}
	}

	disabledRules := make([]analysis.RuleID, 0)
	for _, ruleID := range allRules {
		if !enabled[ruleID] {
			disabledRules = append(disabledRules, ruleID)
		}
	}

	suppressions := make(map[analysis.FindingID]Suppression, len(raw.Suppressions))
	for i, rawSuppression := range raw.Suppressions {
		findingID, reason, err := validateSuppression(rawSuppression, i)
		if err != nil {
			return Config{}, err
		}
		suppressions[findingID] = Suppression{
			FindingID: findingID,
			Reason:    reason,
		}
	}

	pathExclusions, err := parsePathExclusions(raw.PathExclusions)
	if err != nil {
		return Config{}, err
	}

	return Config{
		EnabledRules:     enabled,
		DisabledRules:    disabledRules,
		Suppressions:     suppressions,
		SuppressionCount: len(suppressions),
		PathExclusions:   pathExclusions,
	}, nil
}

func validateRuleID(value, field string) (analysis.RuleID, error) {
	if value == "" {
		return "", fmt.Errorf("pathproof config %s contains an empty rule ID", field)
	}
	ruleID := analysis.RuleID(value)
	if _, ok := knownRules[ruleID]; !ok {
		return "", fmt.Errorf("pathproof config %s contains an unknown rule ID", field)
	}
	return ruleID, nil
}

func validateSuppression(raw rawSuppression, index int) (analysis.FindingID, string, error) {
	if strings.TrimSpace(raw.FindingID) == "" {
		return "", "", fmt.Errorf("pathproof config suppressions[%d].finding_id is required", index)
	}
	if containsControl(raw.FindingID) {
		return "", "", fmt.Errorf("pathproof config suppressions[%d].finding_id contains a control character", index)
	}
	if strings.TrimSpace(raw.Reason) == "" {
		return "", "", fmt.Errorf("pathproof config suppressions[%d].reason is required", index)
	}
	if containsControl(raw.Reason) {
		return "", "", fmt.Errorf("pathproof config suppressions[%d].reason contains a control character", index)
	}
	return analysis.FindingID(raw.FindingID), raw.Reason, nil
}

func parsePathExclusions(raw json.RawMessage) (PathExclusions, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, fmt.Errorf("pathproof config path_exclusions must be an array of strings")
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("pathproof config path_exclusions must be an array of strings")
	}

	seen := make(map[string]PathExclusion, len(entries))
	for i, entry := range entries {
		if bytes.Equal(bytes.TrimSpace(entry), []byte("null")) {
			return nil, fmt.Errorf("pathproof config path_exclusions[%d] must be a string", i)
		}
		var value string
		if err := json.Unmarshal(entry, &value); err != nil {
			return nil, fmt.Errorf("pathproof config path_exclusions[%d] must be a string", i)
		}
		exclusion, err := normalizePathExclusion(value, i)
		if err != nil {
			return nil, err
		}
		seen[pathExclusionKey(exclusion)] = exclusion
	}

	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make(PathExclusions, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out, nil
}

func normalizePathExclusion(value string, index int) (PathExclusion, error) {
	field := fmt.Sprintf("path_exclusions[%d]", index)
	if value == "" {
		return PathExclusion{}, fmt.Errorf("pathproof config %s is empty", field)
	}
	if containsControl(value) {
		return PathExclusion{}, fmt.Errorf("pathproof config %s contains a control character", field)
	}
	if filepath.IsAbs(value) {
		return PathExclusion{}, fmt.Errorf("pathproof config %s must be relative to the scan root", field)
	}
	if hasWindowsDrivePrefix(value) {
		return PathExclusion{}, fmt.Errorf("pathproof config %s must be relative to the scan root", field)
	}
	if strings.Contains(value, "\\") {
		return PathExclusion{}, fmt.Errorf("pathproof config %s contains an unsupported path separator", field)
	}
	if hasURLLikeScheme(value) {
		return PathExclusion{}, fmt.Errorf("pathproof config %s must be a local relative path", field)
	}
	if strings.ContainsAny(value, "*?[]") {
		return PathExclusion{}, fmt.Errorf("pathproof config %s contains unsupported pattern syntax", field)
	}

	directory := strings.HasSuffix(value, "/")
	clean := filepath.ToSlash(filepath.Clean(value))
	if clean == "." {
		return PathExclusion{}, fmt.Errorf("pathproof config %s must not target the scan root", field)
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return PathExclusion{}, fmt.Errorf("pathproof config %s must stay within the scan root", field)
	}
	return PathExclusion{Path: clean, Directory: directory}, nil
}

func hasWindowsDrivePrefix(value string) bool {
	if len(value) < 2 || value[1] != ':' {
		return false
	}
	r := rune(value[0])
	return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
}

func hasURLLikeScheme(value string) bool {
	colon := strings.IndexByte(value, ':')
	if colon <= 0 {
		return false
	}
	for i, r := range value[:colon] {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
			continue
		}
		if i > 0 && ((r >= '0' && r <= '9') || r == '+' || r == '-' || r == '.') {
			continue
		}
		return false
	}
	return true
}

func pathExclusionKey(exclusion PathExclusion) string {
	if exclusion.Directory {
		return exclusion.Path + "/"
	}
	return exclusion.Path
}

func (exclusions PathExclusions) Excludes(rel string) bool {
	directoryCandidate := strings.HasSuffix(rel, "/")
	clean := filepath.ToSlash(filepath.Clean(rel))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return false
	}
	for _, exclusion := range exclusions {
		if exclusion.Directory {
			if (directoryCandidate && clean == exclusion.Path) || strings.HasPrefix(clean, exclusion.Path+"/") {
				return true
			}
			continue
		}
		if !directoryCandidate && clean == exclusion.Path {
			return true
		}
	}
	return false
}

func containsControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func isJSONObject(data []byte) bool {
	trimmed := bytes.TrimSpace(data)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

func rejectTrailingJSON(decoder *json.Decoder) error {
	var extra struct{}
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return sanitizedJSONError(err)
	}
	return fmt.Errorf("pathproof config file must contain exactly one JSON object")
}

func sanitizedJSONError(err error) error {
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return fmt.Errorf("pathproof config file is not valid JSON at byte %d", syntaxErr.Offset)
	}
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		if typeErr.Field != "" {
			return fmt.Errorf("pathproof config field %q has the wrong JSON type", typeErr.Field)
		}
		return fmt.Errorf("pathproof config file has the wrong JSON type")
	}
	if strings.HasPrefix(err.Error(), "json: unknown field ") {
		return fmt.Errorf("pathproof config contains an unknown or unsupported field")
	}
	return fmt.Errorf("pathproof config file is not valid JSON")
}
