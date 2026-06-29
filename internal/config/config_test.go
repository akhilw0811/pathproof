package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"pathproof/internal/analysis"
)

func TestParseEmptyConfigEnablesAllRules(t *testing.T) {
	cfg := mustParse(t, `{}`)

	for _, ruleID := range []analysis.RuleID{
		analysis.RulePublicWorkloadCanReadSecret,
		analysis.RuleGitHubActionsUnpinnedAction,
		analysis.RuleGitHubActionsUnsafePullRequestTargetCheckout,
		analysis.RuleGitHubActionsDangerousPermissions,
		analysis.RuleAWSIAMRoleAdministrativePermissions,
		analysis.RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole,
		analysis.RuleCrossDomainRiskyGitHubActionsCanAssumeAWSAdminRole,
		analysis.RuleCrossDomainRiskyGitHubActionsCanAccessAWSS3Bucket,
	} {
		if !cfg.EnabledRules[ruleID] {
			t.Fatalf("%s enabled = false, want true", ruleID)
		}
	}
	if len(cfg.DisabledRules) != 0 || len(cfg.Suppressions) != 0 || cfg.SuppressionCount != 0 {
		t.Fatalf("config = %#v, want no disabled rules or suppressions", cfg)
	}
}

func TestParseDisabledRules(t *testing.T) {
	cfg := mustParse(t, `{"rules":{"disable":["PP-GHA-001","PP-K8S-001"]}}`)

	if cfg.EnabledRules[analysis.RuleGitHubActionsUnpinnedAction] || cfg.EnabledRules[analysis.RulePublicWorkloadCanReadSecret] {
		t.Fatalf("disabled rules are still enabled: %#v", cfg.EnabledRules)
	}
	wantDisabled := []analysis.RuleID{analysis.RuleGitHubActionsUnpinnedAction, analysis.RulePublicWorkloadCanReadSecret}
	if !reflect.DeepEqual(cfg.DisabledRules, wantDisabled) {
		t.Fatalf("disabled rules = %#v, want %#v", cfg.DisabledRules, wantDisabled)
	}
	if !cfg.EnabledRules[analysis.RuleGitHubActionsDangerousPermissions] {
		t.Fatalf("unlisted rule disabled unexpectedly")
	}
}

func TestParseEnableAllowlist(t *testing.T) {
	cfg := mustParse(t, `{"rules":{"enable":["PP-GHA-001"]}}`)

	if !cfg.EnabledRules[analysis.RuleGitHubActionsUnpinnedAction] {
		t.Fatalf("PP-GHA-001 enabled = false, want true")
	}
	if cfg.EnabledRules[analysis.RulePublicWorkloadCanReadSecret] || cfg.EnabledRules[analysis.RuleGitHubActionsDangerousPermissions] {
		t.Fatalf("non-allowlisted rules enabled: %#v", cfg.EnabledRules)
	}
	if len(cfg.DisabledRules) != 7 {
		t.Fatalf("disabled rules = %#v, want all non-allowlisted rules", cfg.DisabledRules)
	}
}

func TestParseDisableWinsOverEnableConflict(t *testing.T) {
	cfg := mustParse(t, `{"rules":{"enable":["PP-GHA-001","PP-K8S-001"],"disable":["PP-GHA-001"]}}`)

	if cfg.EnabledRules[analysis.RuleGitHubActionsUnpinnedAction] {
		t.Fatalf("disable did not win over enable: %#v", cfg.EnabledRules)
	}
	if !cfg.EnabledRules[analysis.RulePublicWorkloadCanReadSecret] {
		t.Fatalf("non-conflicting enabled rule disabled unexpectedly")
	}
	if len(cfg.DisabledRules) != 7 {
		t.Fatalf("disabled rules = %#v, want conflicted rule and non-allowlisted rules", cfg.DisabledRules)
	}
}

func TestParseDuplicateRuleIDsDedupe(t *testing.T) {
	cfg := mustParse(t, `{"rules":{"disable":["PP-K8S-001","PP-K8S-001"]}}`)

	if cfg.EnabledRules[analysis.RulePublicWorkloadCanReadSecret] {
		t.Fatalf("deduped disabled rule still enabled")
	}
	wantDisabled := []analysis.RuleID{analysis.RulePublicWorkloadCanReadSecret}
	if !reflect.DeepEqual(cfg.DisabledRules, wantDisabled) {
		t.Fatalf("disabled rules = %#v, want %#v", cfg.DisabledRules, wantDisabled)
	}
}

func TestParseUnknownRuleIDErrorsDeterministically(t *testing.T) {
	err := parseError(t, `{"rules":{"disable":["FAKE_CONFIG_RULE_SECRET_DO_NOT_RETAIN"]}}`)

	assertErrorContains(t, err, "unknown rule ID")
	assertErrorDoesNotContain(t, err, "FAKE_CONFIG_RULE_SECRET_DO_NOT_RETAIN")
}

func TestParseValidSuppressions(t *testing.T) {
	cfg := mustParse(t, `{"suppressions":[{"finding_id":"finding:PP-K8S-001:abc","reason":"Accepted risk for fixture"}]}`)

	suppression, ok := cfg.Suppressions[analysis.FindingID("finding:PP-K8S-001:abc")]
	if !ok {
		t.Fatalf("suppression missing: %#v", cfg.Suppressions)
	}
	if suppression.Reason != "Accepted risk for fixture" || cfg.SuppressionCount != 1 {
		t.Fatalf("suppression = %#v count=%d", suppression, cfg.SuppressionCount)
	}
}

func TestParseRejectsInvalidSuppressions(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "empty finding id",
			content: `{"suppressions":[{"finding_id":"","reason":"Accepted"}]}`,
			want:    "finding_id is required",
		},
		{
			name:    "empty reason",
			content: `{"suppressions":[{"finding_id":"finding:PP-K8S-001:abc","reason":"   "}]}`,
			want:    "reason is required",
		},
		{
			name:    "control in finding id",
			content: "{\"suppressions\":[{\"finding_id\":\"finding:PP-K8S-001:\\u0001\",\"reason\":\"Accepted\"}]}",
			want:    "finding_id contains a control character",
		},
		{
			name:    "control in reason",
			content: "{\"suppressions\":[{\"finding_id\":\"finding:PP-K8S-001:abc\",\"reason\":\"Accepted\\u0001\"}]}",
			want:    "reason contains a control character",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseError(t, tt.content)
			assertErrorContains(t, err, tt.want)
		})
	}
}

func TestParseRejectsMalformedJSONWithSanitizedError(t *testing.T) {
	content := `{"rules":{"disable":["FAKE_CONFIG_JSON_SECRET_DO_NOT_RETAIN"]}`
	err := parseError(t, content)

	assertErrorContains(t, err, "not valid JSON")
	assertErrorDoesNotContain(t, err, content)
	assertErrorDoesNotContain(t, err, "FAKE_CONFIG_JSON_SECRET_DO_NOT_RETAIN")
}

func TestParseRejectsNonObjectJSON(t *testing.T) {
	for _, content := range []string{`null`, `[]`, `"bad"`, `42`, `true`} {
		t.Run(content, func(t *testing.T) {
			err := parseError(t, content)
			assertErrorContains(t, err, "must be a JSON object")
		})
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{name: "top level", content: `{"unknown":true}`},
		{name: "path exclusions unsupported", content: `{"path_exclusions":["vendor/**"]}`},
		{name: "rules", content: `{"rules":{"extra":[]}}`},
		{name: "suppression", content: `{"suppressions":[{"finding_id":"finding:PP-K8S-001:abc","reason":"Accepted","owner":"team"}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseError(t, tt.content)
			assertErrorContains(t, err, "unknown or unsupported field")
		})
	}
}

func TestParseErrorDoesNotPrintRawConfigContentOrSecretLikeValues(t *testing.T) {
	content := `{"rules":{"enable":["FAKE_CONFIG_ENABLE_SECRET_DO_NOT_RETAIN"]},"suppressions":[{"finding_id":"finding:PP-K8S-001:abc","reason":"FAKE_CONFIG_REASON_SECRET_DO_NOT_RETAIN"}]}`
	err := parseError(t, content)

	assertErrorDoesNotContain(t, err, content)
	assertErrorDoesNotContain(t, err, "FAKE_CONFIG_ENABLE_SECRET_DO_NOT_RETAIN")
	assertErrorDoesNotContain(t, err, "FAKE_CONFIG_REASON_SECRET_DO_NOT_RETAIN")
}

func TestLoadReadsExplicitConfigPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pathproof.json")
	if err := os.WriteFile(path, []byte(`{"rules":{"disable":["PP-GHA-001"]}}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.EnabledRules[analysis.RuleGitHubActionsUnpinnedAction] {
		t.Fatalf("PP-GHA-001 enabled after loading disabled config")
	}
}

func TestLoadRejectsRemoteURL(t *testing.T) {
	_, err := Load("https://example.invalid/pathproof.json")
	if err == nil {
		t.Fatal("Load error = nil, want remote URL rejection")
	}
	assertErrorContains(t, err, "local file path")
	assertErrorDoesNotContain(t, err, "example.invalid")
}

func TestLoadReadErrorIsSanitized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "FAKE_CONFIG_PATH_SECRET_DO_NOT_RETAIN.json")

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load error = nil, want read error")
	}
	assertErrorContains(t, err, "read config file")
	assertErrorDoesNotContain(t, err, path)
	assertErrorDoesNotContain(t, err, "FAKE_CONFIG_PATH_SECRET_DO_NOT_RETAIN")
}

func mustParse(t *testing.T, content string) Config {
	t.Helper()
	cfg, err := Parse([]byte(content))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return cfg
}

func parseError(t *testing.T, content string) error {
	t.Helper()
	_, err := Parse([]byte(content))
	if err == nil {
		t.Fatalf("Parse error = nil, want error for %s", content)
	}
	return err
}

func assertErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want substring %q", err.Error(), want)
	}
}

func assertErrorDoesNotContain(t *testing.T, err error, forbidden string) {
	t.Helper()
	if strings.Contains(err.Error(), forbidden) {
		t.Fatalf("error = %q, contains forbidden %q", err.Error(), forbidden)
	}
}
