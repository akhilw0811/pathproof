package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"pathproof/internal/analysis"
)

type Config struct {
	EnabledRules     map[analysis.RuleID]bool
	DisabledRules    []analysis.RuleID
	Suppressions     map[analysis.FindingID]Suppression
	SuppressionCount int
}

type Suppression struct {
	FindingID analysis.FindingID
	Reason    string
}

type rawConfig struct {
	Rules        *rawRules        `json:"rules,omitempty"`
	Suppressions []rawSuppression `json:"suppressions,omitempty"`
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

	return Config{
		EnabledRules:     enabled,
		DisabledRules:    disabledRules,
		Suppressions:     suppressions,
		SuppressionCount: len(suppressions),
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
