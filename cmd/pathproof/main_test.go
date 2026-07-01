package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"pathproof/internal/analysis"
	"pathproof/internal/config"
	"pathproof/internal/graph"
)

const (
	safeFixture                        = "testdata/scan-safe"
	vulnerableFixture                  = "testdata/scan-vulnerable"
	invalidFixture                     = "testdata/scan-invalid"
	publicDemoFixture                  = "../../examples/kubernetes/public-secret-path"
	ghaDemoFixture                     = "../../examples/github-actions/unpinned-action"
	ghaDangerousPermissionsDemoFixture = "../../examples/github-actions/dangerous-permissions"
)

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run([]string{"version"}, &stdout, &stderr)

	assertCode(t, code, 0)
	assertString(t, "stdout", stdout.String(), "pathproof dev\n")
	assertString(t, "stderr", stderr.String(), "")
}

func TestRunVersionRejectsExtraArgs(t *testing.T) {
	stdout, stderr, code := runCommand("version", "--json")

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "version accepts no arguments")
}

func TestRunNoArgs(t *testing.T) {
	stdout, stderr, code := runCommand()

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "missing command")
}

func TestRunUnknownCommand(t *testing.T) {
	stdout, stderr, code := runCommand("unknown")

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "unknown command")
}

func TestRunScanRequiresExactlyOneDirectory(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing", args: []string{"scan"}, want: "got 0"},
		{name: "extra", args: []string{"scan", safeFixture, vulnerableFixture}, want: "got 2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, code := runCommand(tt.args...)

			assertCode(t, code, 2)
			assertString(t, "stdout", stdout, "")
			assertOneLineStderr(t, stderr)
			assertContains(t, stderr, "scan requires exactly one directory argument")
			assertContains(t, stderr, tt.want)
		})
	}
}

func TestRunScanAcceptsJSONFormatForms(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "--format", "json", safeFixture},
		{"scan", "--format=json", safeFixture},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, stderr, code := runCommand(args...)

			assertCode(t, code, 0)
			assertString(t, "stderr", stderr, "")
			assertValidJSONReport(t, stdout)
		})
	}
}

func TestRunScanRejectsUnsupportedFormat(t *testing.T) {
	stdout, stderr, code := runCommand("scan", "--format", "xml", safeFixture)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "unsupported scan format \"xml\"")
}

func TestRunScanRejectsInvalidRepoFlag(t *testing.T) {
	tests := []string{
		"owner",
		"owner/",
		"/repo",
		"owner/repo/extra",
		"own er/repo",
		"owner/re:po",
		"owner/re*po",
	}
	for _, repo := range tests {
		t.Run(repo, func(t *testing.T) {
			stdout, stderr, code := runCommand("scan", "--repo", repo, safeFixture)

			assertCode(t, code, 2)
			assertString(t, "stdout", stdout, "")
			assertOneLineStderr(t, stderr)
			assertContains(t, stderr, "invalid --repo")
		})
	}
}

func TestRunScanTerraformOIDCTrustGraphOnlyOutputUnchanged(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "deploy.yml", `on:
  pull_request:
permissions:
  id-token: write
jobs:
  deploy:
    steps:
      - run: echo test
`)
	writeTerraformForTest(t, dir, "main.tf", terraformOIDCRole("deploy", "repo:owner/repo:pull_request"))

	humanStdout, humanStderr, humanCode := runCommand("scan", "--repo", "owner/repo", dir)
	jsonStdout, jsonStderr, jsonCode := runCommand("scan", "--repo", "owner/repo", "--format=json", dir)
	sarifStdout, sarifStderr, sarifCode := runCommand("scan", "--repo", "owner/repo", "--format=sarif", dir)

	assertCode(t, humanCode, 0)
	assertString(t, "human stderr", humanStderr, "")
	assertString(t, "human stdout", humanStdout, "Finding count: 0\nNo findings.\n")

	assertCode(t, jsonCode, 0)
	assertString(t, "json stderr", jsonStderr, "")
	report := assertValidJSONReport(t, jsonStdout)
	if report.FindingCount != 0 || len(report.Findings) != 0 {
		t.Fatalf("JSON report = %#v, want no findings", report)
	}
	assertString(t, "json stdout", jsonStdout, "{\"findings\":[],\"finding_count\":0}\n")

	assertCode(t, sarifCode, 0)
	assertString(t, "sarif stderr", sarifStderr, "")
	sarif := assertValidSARIFReport(t, sarifStdout)
	if len(sarif.Runs[0].Results) != 0 {
		t.Fatalf("SARIF results = %#v, want none", sarif.Runs[0].Results)
	}

	for _, output := range []string{humanStdout, jsonStdout, sarifStdout} {
		for _, forbidden := range []string{"AWSIAMRole", "CanAssumeRole", "assume_role_policy", "Principal", "Condition", "arn:aws:iam"} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("scan output contains graph-only Terraform text %q: %s", forbidden, output)
			}
		}
	}
}

func TestRunScanCrossDomainWorkflowLevelOIDCAndRiskEmitsFinding(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "unsafe.yml", `name: Cross domain
on: pull_request_target
permissions: write-all
env:
  TOKEN: FAKE_CLI_XDOMAIN_GHA_ENV_SECRET_DO_NOT_RETAIN
jobs:
  audit:
    steps:
      - run: echo FAKE_CLI_XDOMAIN_GHA_RUN_SECRET_DO_NOT_RETAIN
`)
	writeTerraformForTest(t, dir, "infra/iam.tf", terraformOIDCRole("deploy", "repo:owner/repo:pull_request"))

	stdout, stderr, code := runCommand("scan", "--repo", "owner/repo", dir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Rule: PP-XDOMAIN-001\n")
	assertContains(t, stdout, "Title: Risky GitHub Actions workflow can assume AWS IAM role\n")
	assertContains(t, stdout, "Severity: High\n")
	assertContains(t, stdout, "workflow-level OIDC token capability")
	assertContains(t, stdout, "OIDCTokenCapability githubactions://.github/workflows/unsafe.yml/oidc-token/workflow")
	assertContains(t, stdout, "AWSIAMRole aws://terraform/aws_iam_role/infra/iam.tf/deploy")
	assertContains(t, stdout, "permissions: write-all")
	assertContains(t, stdout, "infra/iam.tf#resource=aws_iam_role.deploy")
	if strings.Contains(stdout, "Remediation:") || strings.Contains(stdout, "Patch Preview:") || strings.Contains(stdout, "Validation:") {
		t.Fatalf("PP-XDOMAIN-001 received unsupported remediation/patch/validation output: %s", stdout)
	}
	assertDoesNotContainCrossDomainSecretValues(t, stdout, stderr)
	if strings.Contains(stdout, dir) || strings.Contains(stderr, dir) {
		t.Fatalf("output contains absolute temp path\nstdout:%s\nstderr:%s", stdout, stderr)
	}
}

func TestRunScanCrossDomainJSONRiskSignalAndRepoMatching(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "unsafe.yml", `on: pull_request_target
permissions:
  id-token: write
jobs:
  deploy:
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
        with:
          token: FAKE_CLI_XDOMAIN_GHA_WITH_SECRET_DO_NOT_RETAIN
          ref: ${{ github.event.pull_request.head.sha }}
`)
	writeTerraformForTest(t, dir, "infra/iam.tf", terraformOIDCRole("deploy", "repo:owner/repo:pull_request"))

	stdout, stderr, code := runCommand("scan", "--format=json", "--repo", "owner/repo", dir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	var crossDomain []cliJSONFinding
	for _, finding := range report.Findings {
		if finding.RuleID == "PP-XDOMAIN-001" {
			crossDomain = append(crossDomain, finding)
			if finding.RiskSignal == nil {
				t.Fatalf("risk_signal = nil for PP-XDOMAIN-001: %#v", finding)
			}
			if finding.Remediation != nil {
				t.Fatalf("remediation = %#v, want nil", finding.Remediation)
			}
		} else if finding.RiskSignal != nil {
			t.Fatalf("%s JSON finding has risk_signal: %#v", finding.RuleID, finding)
		}
	}
	if len(crossDomain) != 2 {
		t.Fatalf("PP-XDOMAIN-001 count = %d, want PP-GHA-002 and PP-GHA-003 risk findings: %#v", len(crossDomain), report.Findings)
	}
	seenRisk := map[string]bool{}
	for _, finding := range crossDomain {
		seenRisk[finding.RiskSignal.RuleID] = true
		if len(finding.Path) != 3 || len(finding.Evidence) != 2 {
			t.Fatalf("path/evidence lengths = %d/%d, want workflow-level cross-domain path", len(finding.Path), len(finding.Evidence))
		}
		if finding.RiskSignal.RuleID == "PP-GHA-002" {
			if finding.RiskSignal.JobID != "deploy" || finding.RiskSignal.StepIndex == nil || len(finding.RiskSignal.Selectors) != 1 {
				t.Fatalf("PP-GHA-002 risk_signal = %#v", finding.RiskSignal)
			}
		}
		if strings.Contains(finding.SourceReferences[0], dir) {
			t.Fatalf("source reference contains temp dir: %#v", finding.SourceReferences)
		}
	}
	if !seenRisk["PP-GHA-002"] || !seenRisk["PP-GHA-003"] {
		t.Fatalf("risk signals = %#v, want PP-GHA-002 and PP-GHA-003", seenRisk)
	}
	assertDoesNotContainCrossDomainSecretValues(t, stdout, stderr)
	for _, forbidden := range []string{"${{", "assume_role_policy", "Principal", "Condition", "arn:aws:iam"} {
		if strings.Contains(stdout, forbidden) || strings.Contains(stderr, forbidden) {
			t.Fatalf("output contains %q\nstdout:%s\nstderr:%s", forbidden, stdout, stderr)
		}
	}

	noRepoStdout, noRepoStderr, noRepoCode := runCommand("scan", "--format=json", dir)
	assertCode(t, noRepoCode, 1)
	assertString(t, "no repo stderr", noRepoStderr, "")
	assertNoRuleInJSONReport(t, noRepoStdout, "PP-XDOMAIN-001")

	nonmatchingStdout, nonmatchingStderr, nonmatchingCode := runCommand("scan", "--format=json", "--repo", "other/repo", dir)
	assertCode(t, nonmatchingCode, 1)
	assertString(t, "nonmatching stderr", nonmatchingStderr, "")
	assertNoRuleInJSONReport(t, nonmatchingStdout, "PP-XDOMAIN-001")
}

func TestRunScanCrossDomainSafeOIDCTrustAloneExitsZero(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "deploy.yml", `on: pull_request
permissions:
  id-token: write
jobs:
  deploy:
    steps:
      - run: echo deploy
`)
	writeTerraformForTest(t, dir, "infra/iam.tf", terraformOIDCRole("deploy", "repo:owner/repo:pull_request"))

	stdout, stderr, code := runCommand("scan", "--repo", "owner/repo", dir)

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	assertString(t, "stdout", stdout, "Finding count: 0\nNo findings.\n")
}

func TestRunScanCrossDomainPatchFlagsDoNotPatchOrValidateFinding(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir scan root: %v", err)
	}
	writeGitHubActionsWorkflowForTest(t, root, "unsafe.yml", `on: pull_request_target
permissions: write-all
`)
	writeTerraformForTest(t, root, "infra/iam.tf", terraformOIDCRole("deploy", "repo:owner/repo:pull_request"))

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--repo", "owner/repo", "--write-patches", "patched", "--validate-patches", "scan")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Rule: PP-XDOMAIN-001\n")
	assertContains(t, stdout, "Patch Output:")
	assertContains(t, stdout, "Written files: 0")
	if strings.Contains(stdout, "Remediation:") || strings.Contains(stdout, "Patch Preview:") || strings.Contains(stdout, "Validation:") {
		t.Fatalf("PP-XDOMAIN-001 received unsupported remediation/patch/validation output: %s", stdout)
	}
	if _, err := os.Stat(filepath.Join(parent, "patched")); !os.IsNotExist(err) {
		t.Fatalf("patched output directory exists or stat failed unexpectedly: %v", err)
	}
}

func TestRunScanCrossDomainAdminRoleHumanOutput(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "unsafe-admin.yml", `name: Cross domain admin
on: pull_request_target
permissions: write-all
env:
  TOKEN: FAKE_CLI_XDOMAIN2_GHA_ENV_SECRET_DO_NOT_RETAIN
jobs:
  audit:
    steps:
      - run: echo FAKE_CLI_XDOMAIN2_GHA_RUN_SECRET_DO_NOT_RETAIN
`)
	writeTerraformForTest(t, dir, "infra/iam.tf", terraformOIDCAdminRole("deploy", "repo:owner/repo:pull_request", "admin", "*", "*")+"\n# FAKE_CLI_XDOMAIN2_TF_SECRET_DO_NOT_RETAIN\n")

	stdout, stderr, code := runCommand("scan", "--repo", "owner/repo", dir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Rule: PP-XDOMAIN-002\n")
	assertContains(t, stdout, "Title: Risky GitHub Actions workflow can assume administrative AWS IAM role\n")
	assertContains(t, stdout, "Severity: High\n")
	assertContains(t, stdout, "workflow-level OIDC token capability")
	assertContains(t, stdout, "OIDCTokenCapability githubactions://.github/workflows/unsafe-admin.yml/oidc-token/workflow")
	assertContains(t, stdout, "AWSIAMRole aws://terraform/aws_iam_role/infra/iam.tf/deploy")
	assertContains(t, stdout, "AWSPermission aws://terraform/aws_permission/")
	assertContains(t, stdout, "action_star_resource_star")
	assertContains(t, stdout, "permissions: write-all")
	if strings.Contains(stdout, "Remediation:") || strings.Contains(stdout, "Patch Preview:") || strings.Contains(stdout, "Validation:") {
		t.Fatalf("PP-XDOMAIN-002 received unsupported remediation/patch/validation output: %s", stdout)
	}
	assertDoesNotContainCrossDomainAdminSecretValues(t, stdout, stderr)
	for _, forbidden := range []string{"assume_role_policy", "Principal", "Condition", "Statement", "policy ="} {
		if strings.Contains(stdout, forbidden) || strings.Contains(stderr, forbidden) {
			t.Fatalf("output contains %q\nstdout:%s\nstderr:%s", forbidden, stdout, stderr)
		}
	}
}

func TestRunScanCrossDomainAdminRoleJSONRepoMatchingAndNegatives(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "unsafe-admin.yml", `on: pull_request_target
permissions:
  id-token: write
jobs:
  deploy:
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
        with:
          token: FAKE_CLI_XDOMAIN2_GHA_WITH_SECRET_DO_NOT_RETAIN
          ref: ${{ github.event.pull_request.head.sha }}
`)
	writeTerraformForTest(t, dir, "infra/iam.tf", terraformOIDCAdminRole("deploy", "repo:owner/repo:pull_request", "admin", "*", "*"))

	stdout, stderr, code := runCommand("scan", "--format=json", "--repo", "owner/repo", dir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	var crossDomainAdmin []cliJSONFinding
	for _, finding := range report.Findings {
		if finding.RuleID == "PP-XDOMAIN-002" {
			crossDomainAdmin = append(crossDomainAdmin, finding)
			if finding.RiskSignal == nil {
				t.Fatalf("risk_signal = nil for PP-XDOMAIN-002: %#v", finding)
			}
			if finding.Remediation != nil {
				t.Fatalf("remediation = %#v, want nil", finding.Remediation)
			}
			if len(finding.Path) != 4 || len(finding.Evidence) != 3 {
				t.Fatalf("path/evidence lengths = %d/%d, want workflow-level admin path", len(finding.Path), len(finding.Evidence))
			}
			if finding.Path[2].Kind != "AWSIAMRole" || finding.Path[3].Kind != "AWSPermission" {
				t.Fatalf("path = %#v, want AWS role to permission suffix", finding.Path)
			}
		}
	}
	if len(crossDomainAdmin) != 2 {
		t.Fatalf("PP-XDOMAIN-002 count = %d, want PP-GHA-002 and PP-GHA-003 risk findings: %#v", len(crossDomainAdmin), report.Findings)
	}
	seenRisk := map[string]bool{}
	for _, finding := range crossDomainAdmin {
		seenRisk[finding.RiskSignal.RuleID] = true
	}
	if !seenRisk["PP-GHA-002"] || !seenRisk["PP-GHA-003"] {
		t.Fatalf("risk signals = %#v, want PP-GHA-002 and PP-GHA-003", seenRisk)
	}
	assertDoesNotContainCrossDomainAdminSecretValues(t, stdout, stderr)
	for _, forbidden := range []string{"${{", "assume_role_policy", "Principal", "Condition", "Statement", "policy ="} {
		if strings.Contains(stdout, forbidden) || strings.Contains(stderr, forbidden) {
			t.Fatalf("output contains %q\nstdout:%s\nstderr:%s", forbidden, stdout, stderr)
		}
	}

	noRepoStdout, noRepoStderr, noRepoCode := runCommand("scan", "--format=json", dir)
	assertCode(t, noRepoCode, 1)
	assertString(t, "no repo stderr", noRepoStderr, "")
	assertNoRuleInJSONReport(t, noRepoStdout, "PP-XDOMAIN-002")

	nonmatchingStdout, nonmatchingStderr, nonmatchingCode := runCommand("scan", "--format=json", "--repo", "other/repo", dir)
	assertCode(t, nonmatchingCode, 1)
	assertString(t, "nonmatching stderr", nonmatchingStderr, "")
	assertNoRuleInJSONReport(t, nonmatchingStdout, "PP-XDOMAIN-002")
}

func TestRunScanCrossDomainAdminRoleMixedTrustEmitsFinding(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "mixed-admin.yml", `on: pull_request_target
permissions: write-all
jobs:
  deploy:
    environment: prod
`)
	writeTerraformForTest(t, dir, "infra/iam.tf", terraformOIDCSubjectsAdminRole("deploy", []string{
		"repo:owner/repo:environment:prod",
		"repo:owner/repo:pull_request",
	}, "admin", "*", "*")+"\n# FAKE_CLI_XDOMAIN2_TF_SECRET_DO_NOT_RETAIN\n")

	humanStdout, humanStderr, humanCode := runCommand("scan", "--repo", "owner/repo", dir)
	jsonStdout, jsonStderr, jsonCode := runCommand("scan", "--format=json", "--repo", "owner/repo", dir)

	assertCode(t, humanCode, 1)
	assertString(t, "human stderr", humanStderr, "")
	assertContains(t, humanStdout, "Rule: PP-XDOMAIN-002\n")
	assertContains(t, humanStdout, "repo:owner/repo:pull_request")
	assertContains(t, humanStdout, "repo:owner/repo:environment:prod")
	assertDoesNotContainCrossDomainAdminSecretValues(t, humanStdout, humanStderr)
	for _, forbidden := range []string{"assume_role_policy", "Principal", "Condition", "Statement", "policy =", "arn:aws:iam"} {
		if strings.Contains(humanStdout, forbidden) || strings.Contains(humanStderr, forbidden) {
			t.Fatalf("human output contains %q\nstdout:%s\nstderr:%s", forbidden, humanStdout, humanStderr)
		}
	}

	assertCode(t, jsonCode, 1)
	assertString(t, "json stderr", jsonStderr, "")
	report := assertValidJSONReport(t, jsonStdout)
	found := false
	for _, finding := range report.Findings {
		if finding.RuleID == "PP-XDOMAIN-002" {
			found = true
		}
	}
	if !found {
		t.Fatalf("JSON report missing PP-XDOMAIN-002: %#v", report.Findings)
	}
	if strings.Contains(jsonStdout, dir) {
		t.Fatalf("JSON output leaked absolute path %q: %s", dir, jsonStdout)
	}
	assertDoesNotContainCrossDomainAdminSecretValues(t, jsonStdout, jsonStderr)
}

func TestRunScanCrossDomainAdminRoleNegatives(t *testing.T) {
	tests := []struct {
		name      string
		workflow  string
		terraform string
		repo      string
	}{
		{
			name: "non admin permission",
			workflow: `on: pull_request_target
permissions: write-all
`,
			terraform: terraformOIDCPolicyRole("deploy", "repo:owner/repo:pull_request", "read", "s3:GetObject", "*"),
			repo:      "owner/repo",
		},
		{
			name: "push workflow admin trust no risk",
			workflow: `on:
  push:
    branches: [main]
permissions:
  id-token: write
`,
			terraform: terraformOIDCAdminRole("deploy", "repo:owner/repo:ref:refs/heads/main", "admin", "*", "*"),
			repo:      "owner/repo",
		},
		{
			name: "branch-only trust with risky workflow",
			workflow: `on:
  push:
    branches: [main]
  pull_request_target:
permissions: write-all
`,
			terraform: terraformOIDCAdminRole("deploy", "repo:owner/repo:ref:refs/heads/main", "admin", "*", "*"),
			repo:      "owner/repo",
		},
		{
			name: "environment-only trust with risky workflow",
			workflow: `on: pull_request_target
permissions: write-all
jobs:
  deploy:
    environment: prod
`,
			terraform: terraformOIDCAdminRole("deploy", "repo:owner/repo:environment:prod", "admin", "*", "*"),
			repo:      "owner/repo",
		},
		{
			name: "environment-only trust named pull_request with risky workflow",
			workflow: `on: pull_request_target
permissions: write-all
jobs:
  deploy:
    environment: pull_request
`,
			terraform: terraformOIDCAdminRole("deploy", "repo:owner/repo:environment:pull_request", "admin", "*", "*"),
			repo:      "owner/repo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeGitHubActionsWorkflowForTest(t, dir, "workflow.yml", tt.workflow)
			writeTerraformForTest(t, dir, "infra/iam.tf", tt.terraform)

			stdout, stderr, code := runCommand("scan", "--format=json", "--repo", tt.repo, dir)

			assertCode(t, code, 1)
			assertString(t, "stderr", stderr, "")
			assertNoRuleInJSONReport(t, stdout, "PP-XDOMAIN-002")
		})
	}
}

func TestRunScanCrossDomainAdminRolePatchFlagsDoNotPatchOrValidateFinding(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir scan root: %v", err)
	}
	writeGitHubActionsWorkflowForTest(t, root, "unsafe-admin.yml", `on: pull_request_target
permissions: write-all
`)
	writeTerraformForTest(t, root, "infra/iam.tf", terraformOIDCAdminRole("deploy", "repo:owner/repo:pull_request", "admin", "*", "*"))

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--repo", "owner/repo", "--write-patches", "patched", "--validate-patches", "scan")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Rule: PP-XDOMAIN-002\n")
	assertContains(t, stdout, "Patch Output:")
	assertContains(t, stdout, "Written files: 0")
	if strings.Contains(stdout, "Remediation:") || strings.Contains(stdout, "Patch Preview:") || strings.Contains(stdout, "Validation:") {
		t.Fatalf("PP-XDOMAIN-002 received unsupported remediation/patch/validation output: %s", stdout)
	}
	if _, err := os.Stat(filepath.Join(parent, "patched")); !os.IsNotExist(err) {
		t.Fatalf("patched output directory exists or stat failed unexpectedly: %v", err)
	}
}

func TestRunScanCrossDomainS3HumanOutput(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "unsafe-s3.yml", `name: Cross domain S3
on: pull_request_target
permissions: write-all
env:
  TOKEN: FAKE_CLI_XDOMAIN3_GHA_ENV_SECRET_DO_NOT_RETAIN
jobs:
  audit:
    steps:
      - run: echo FAKE_CLI_XDOMAIN3_GHA_RUN_SECRET_DO_NOT_RETAIN
`)
	writeTerraformForTest(t, dir, "infra/iam.tf", terraformOIDCS3Role("deploy", "repo:owner/repo:pull_request", "artifacts", "prod-artifacts", "read", "s3:GetObject", "arn:aws:s3:::prod-artifacts/*")+"\n# FAKE_CLI_XDOMAIN3_TF_SECRET_DO_NOT_RETAIN\n")

	stdout, stderr, code := runCommand("scan", "--repo", "owner/repo", dir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Rule: PP-XDOMAIN-003\n")
	assertContains(t, stdout, "Title: Risky GitHub Actions workflow can access AWS S3 bucket\n")
	assertContains(t, stdout, "Severity: High\n")
	assertContains(t, stdout, "workflow-level OIDC token capability")
	assertContains(t, stdout, "AWSIAMRole aws://terraform/aws_iam_role/infra/iam.tf/deploy")
	assertContains(t, stdout, "AWSS3Bucket aws://terraform/aws_s3_bucket/infra/iam.tf/artifacts")
	assertContains(t, stdout, "prod-artifacts")
	assertContains(t, stdout, "read access")
	assertContains(t, stdout, "get_object action=s3:GetObject resource=arn:aws:s3:::prod-artifacts/*")
	if strings.Contains(stdout, "Remediation:") || strings.Contains(stdout, "Patch Preview:") || strings.Contains(stdout, "Validation:") {
		t.Fatalf("PP-XDOMAIN-003 received unsupported remediation/patch/validation output: %s", stdout)
	}
	assertDoesNotContainCrossDomainS3SecretValues(t, stdout, stderr)
	if strings.Contains(stdout, dir) || strings.Contains(stderr, dir) {
		t.Fatalf("output contains absolute temp path\nstdout:%s\nstderr:%s", stdout, stderr)
	}
}

func TestRunScanCrossDomainS3JSONRepoMatchingAndNegatives(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "unsafe-s3.yml", `on: pull_request_target
permissions: write-all
`)
	writeTerraformForTest(t, dir, "infra/iam.tf", terraformOIDCS3Role("deploy", "repo:owner/repo:pull_request", "artifacts", "prod-artifacts", "read", "s3:ListBucket", "arn:aws:s3:::prod-artifacts"))

	stdout, stderr, code := runCommand("scan", "--format=json", "--repo", "owner/repo", dir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	var s3Findings []cliJSONFinding
	for _, finding := range report.Findings {
		if finding.RuleID == "PP-XDOMAIN-003" {
			s3Findings = append(s3Findings, finding)
			if finding.RiskSignal == nil || finding.RiskSignal.RuleID != "PP-GHA-003" {
				t.Fatalf("risk_signal = %#v, want PP-GHA-003", finding.RiskSignal)
			}
			if finding.Remediation != nil {
				t.Fatalf("remediation = %#v, want nil", finding.Remediation)
			}
			if len(finding.Path) != 4 || len(finding.Evidence) != 3 {
				t.Fatalf("path/evidence lengths = %d/%d, want workflow-level S3 path", len(finding.Path), len(finding.Evidence))
			}
			if finding.Path[2].Kind != "AWSIAMRole" || finding.Path[3].Kind != "AWSS3Bucket" {
				t.Fatalf("path = %#v, want AWS role to S3 bucket suffix", finding.Path)
			}
			assertContains(t, finding.Summary, "read access")
			assertContains(t, finding.Summary, "prod-artifacts")
		}
	}
	if len(s3Findings) != 1 {
		t.Fatalf("PP-XDOMAIN-003 count = %d, want 1: %#v", len(s3Findings), report.Findings)
	}
	assertDoesNotContainCrossDomainS3SecretValues(t, stdout, stderr)
	for _, forbidden := range []string{"assume_role_policy", "Principal", "Condition", "Statement", "policy ="} {
		if strings.Contains(stdout, forbidden) || strings.Contains(stderr, forbidden) {
			t.Fatalf("output contains %q\nstdout:%s\nstderr:%s", forbidden, stdout, stderr)
		}
	}

	noRepoStdout, noRepoStderr, noRepoCode := runCommand("scan", "--format=json", dir)
	assertCode(t, noRepoCode, 1)
	assertString(t, "no repo stderr", noRepoStderr, "")
	assertNoRuleInJSONReport(t, noRepoStdout, "PP-XDOMAIN-003")

	nonmatchingStdout, nonmatchingStderr, nonmatchingCode := runCommand("scan", "--format=json", "--repo", "other/repo", dir)
	assertCode(t, nonmatchingCode, 1)
	assertString(t, "nonmatching stderr", nonmatchingStderr, "")
	assertNoRuleInJSONReport(t, nonmatchingStdout, "PP-XDOMAIN-003")

	nonmatchingBucketDir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, nonmatchingBucketDir, "unsafe-s3.yml", `on: pull_request_target
permissions: write-all
`)
	writeTerraformForTest(t, nonmatchingBucketDir, "infra/iam.tf", terraformOIDCS3Role("deploy", "repo:owner/repo:pull_request", "artifacts", "prod-artifacts", "read", "s3:GetObject", "arn:aws:s3:::other-artifacts/*"))
	nonmatchingBucketStdout, nonmatchingBucketStderr, nonmatchingBucketCode := runCommand("scan", "--format=json", "--repo", "owner/repo", nonmatchingBucketDir)
	assertCode(t, nonmatchingBucketCode, 1)
	assertString(t, "nonmatching bucket stderr", nonmatchingBucketStderr, "")
	assertNoRuleInJSONReport(t, nonmatchingBucketStdout, "PP-XDOMAIN-003")
}

func TestRunScanCrossDomainSensitiveS3HumanAndJSONOutput(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "unsafe-sensitive-s3.yml", `name: Sensitive S3
on: pull_request_target
permissions: write-all
env:
  TOKEN: FAKE_CLI_XDOMAIN3_GHA_ENV_SECRET_DO_NOT_RETAIN
jobs:
  audit:
    steps:
      - run: echo FAKE_CLI_XDOMAIN3_GHA_RUN_SECRET_DO_NOT_RETAIN
`)
	writeTerraformForTest(t, dir, "infra/iam.tf", terraformOIDCSensitiveS3Role("deploy", "repo:owner/repo:pull_request", "artifacts", "assets", "read", "s3:GetObject", "arn:aws:s3:::assets/*")+"\n# FAKE_CLI_XDOMAIN3_TF_SECRET_DO_NOT_RETAIN\n")

	humanStdout, humanStderr, humanCode := runCommand("scan", "--repo", "owner/repo", dir)
	jsonStdout, jsonStderr, jsonCode := runCommand("scan", "--format=json", "--repo", "owner/repo", dir)

	assertCode(t, humanCode, 1)
	assertString(t, "human stderr", humanStderr, "")
	assertContains(t, humanStdout, "Rule: PP-XDOMAIN-003\n")
	assertContains(t, humanStdout, "Rule: PP-XDOMAIN-004\n")
	assertContains(t, humanStdout, "Title: Risky GitHub Actions workflow can access sensitive AWS S3 bucket\n")
	assertContains(t, humanStdout, "read access")
	assertContains(t, humanStdout, "assets")
	assertContains(t, humanStdout, "dangerous pull_request_target permission grant")
	assertContains(t, humanStdout, "Bucket sensitivity: sensitive from tag DataClassification=sensitive")
	if strings.Contains(humanStdout, "Remediation:") || strings.Contains(humanStdout, "Patch Preview:") || strings.Contains(humanStdout, "Validation:") {
		t.Fatalf("PP-XDOMAIN-004 received unsupported remediation/patch/validation output: %s", humanStdout)
	}
	assertDoesNotContainCrossDomainS3SecretValues(t, humanStdout, humanStderr)
	if strings.Contains(humanStdout, dir) || strings.Contains(humanStderr, dir) {
		t.Fatalf("human output contains absolute temp path\nstdout:%s\nstderr:%s", humanStdout, humanStderr)
	}

	assertCode(t, jsonCode, 1)
	assertString(t, "json stderr", jsonStderr, "")
	report := assertValidJSONReport(t, jsonStdout)
	var sensitive []cliJSONFinding
	for _, finding := range report.Findings {
		if finding.RuleID == "PP-XDOMAIN-004" {
			sensitive = append(sensitive, finding)
		}
	}
	if len(sensitive) != 1 {
		t.Fatalf("PP-XDOMAIN-004 count = %d, want 1: %#v", len(sensitive), report.Findings)
	}
	finding := sensitive[0]
	if finding.RiskSignal == nil || finding.RiskSignal.RuleID != "PP-GHA-003" {
		t.Fatalf("risk_signal = %#v, want PP-GHA-003", finding.RiskSignal)
	}
	if finding.BucketSensitivity == nil || finding.BucketSensitivity.SensitivityLevel != "sensitive" || len(finding.BucketSensitivity.Reasons) != 1 {
		t.Fatalf("bucket_sensitivity = %#v, want sensitive evidence", finding.BucketSensitivity)
	}
	reason := finding.BucketSensitivity.Reasons[0]
	if reason.Source != "tag" || reason.Key != "DataClassification" || reason.Value != "sensitive" || reason.SourceRef != "infra/iam.tf#resource=aws_s3_bucket.artifacts" {
		t.Fatalf("bucket sensitivity reason = %#v, want sanitized tag evidence", reason)
	}
	if finding.Remediation != nil {
		t.Fatalf("remediation = %#v, want nil", finding.Remediation)
	}
	if got := countCLIFindingsByRule(report.Findings, "PP-XDOMAIN-003"); got != 1 {
		t.Fatalf("PP-XDOMAIN-003 count = %d, want sibling finding", got)
	}
	assertDoesNotContainCrossDomainS3SecretValues(t, jsonStdout, jsonStderr)
	for _, forbidden := range []string{"assume_role_policy", "Principal", "Condition", "Statement", "policy =", "Owner"} {
		if strings.Contains(jsonStdout, forbidden) || strings.Contains(jsonStderr, forbidden) {
			t.Fatalf("JSON output contains %q\nstdout:%s\nstderr:%s", forbidden, jsonStdout, jsonStderr)
		}
	}
}

func TestRunScanCrossDomainSensitiveS3Negatives(t *testing.T) {
	unknownDir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, unknownDir, "unsafe-s3.yml", `on: pull_request_target
permissions: write-all
`)
	writeTerraformForTest(t, unknownDir, "infra/iam.tf", terraformOIDCS3Role("deploy", "repo:owner/repo:pull_request", "artifacts", "assets", "read", "s3:GetObject", "arn:aws:s3:::assets/*"))
	unknownStdout, unknownStderr, unknownCode := runCommand("scan", "--format=json", "--repo", "owner/repo", unknownDir)
	assertCode(t, unknownCode, 1)
	assertString(t, "unknown stderr", unknownStderr, "")
	assertNoRuleInJSONReport(t, unknownStdout, "PP-XDOMAIN-004")
	if got := countCLIFindingsByRule(assertValidJSONReport(t, unknownStdout).Findings, "PP-XDOMAIN-003"); got != 1 {
		t.Fatalf("unknown sensitivity PP-XDOMAIN-003 count = %d, want 1", got)
	}

	branchDir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, branchDir, "unsafe-s3.yml", `on:
  push:
    branches: [main]
  pull_request_target:
permissions: write-all
`)
	writeTerraformForTest(t, branchDir, "infra/iam.tf", terraformOIDCSensitiveS3Role("deploy", "repo:owner/repo:ref:refs/heads/main", "artifacts", "assets", "read", "s3:GetObject", "arn:aws:s3:::assets/*"))
	branchStdout, branchStderr, branchCode := runCommand("scan", "--format=json", "--repo", "owner/repo", branchDir)
	assertCode(t, branchCode, 1)
	assertString(t, "branch stderr", branchStderr, "")
	assertNoRuleInJSONReport(t, branchStdout, "PP-XDOMAIN-004")
}

func TestRunScanCrossDomainS3PatchFlagsDoNotPatchOrValidateFinding(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir scan root: %v", err)
	}
	outputDir := filepath.Join(parent, "patches")
	writeGitHubActionsWorkflowForTest(t, root, "unsafe-s3.yml", `on: pull_request_target
permissions: write-all
`)
	writeTerraformForTest(t, root, "infra/iam.tf", terraformOIDCS3Role("deploy", "repo:owner/repo:pull_request", "artifacts", "prod-artifacts", "write", "s3:PutObject", "arn:aws:s3:::prod-artifacts/*"))

	stdout, stderr, code := runCommand("scan", "--repo", "owner/repo", "--preview-patches", "--write-patches", outputDir, "--validate-patches", root)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Rule: PP-XDOMAIN-003\n")
	assertContains(t, stdout, "write access")
	if strings.Contains(stdout, "Remediation:") || strings.Contains(stdout, "Patch Preview:") || strings.Contains(stdout, "Validation:") {
		t.Fatalf("PP-XDOMAIN-003 received unsupported remediation/patch/validation output: %s", stdout)
	}
	assertDoesNotContainCrossDomainS3SecretValues(t, stdout, stderr)
}

func TestRunScanS3SensitivityMetadataDoesNotCreateFindingsOrPublicJSONGraphMetadata(t *testing.T) {
	dir := t.TempDir()
	writeTerraformForTest(t, dir, "infra/s3.tf", `provider "aws" {
  access_key = "FAKE_CLI_S3_SENSITIVITY_ACCESS_KEY_DO_NOT_RETAIN"
}

resource "aws_s3_bucket" "backups" {
  bucket = "prod-data-backups"
  tags = {
    DataClassification = "Sensitive"
    Owner = "FAKE_CLI_S3_SENSITIVITY_TAG_SECRET_DO_NOT_RETAIN"
  }
}
`)

	humanStdout, humanStderr, humanCode := runCommand("scan", dir)
	assertCode(t, humanCode, 0)
	assertString(t, "human stderr", humanStderr, "")
	assertString(t, "human stdout", humanStdout, "Finding count: 0\nNo findings.\n")

	jsonStdout, jsonStderr, jsonCode := runCommand("scan", "--format=json", dir)
	assertCode(t, jsonCode, 0)
	assertString(t, "json stderr", jsonStderr, "")
	report := assertValidJSONReport(t, jsonStdout)
	if report.FindingCount != 0 || len(report.Findings) != 0 {
		t.Fatalf("JSON report = %#v, want no findings", report)
	}
	for _, forbidden := range []string{"sensitivity", "prod-data-backups", "DataClassification", "Owner", "FAKE_CLI_S3_SENSITIVITY"} {
		if strings.Contains(jsonStdout, forbidden) || strings.Contains(jsonStderr, forbidden) || strings.Contains(humanStdout, forbidden) || strings.Contains(humanStderr, forbidden) {
			t.Fatalf("public output contains graph metadata or secret-like value %q\nhuman stdout:%s\njson stdout:%s", forbidden, humanStdout, jsonStdout)
		}
	}

	sarifStdout, sarifStderr, sarifCode := runCommand("scan", "--format=sarif", dir)
	assertCode(t, sarifCode, 0)
	assertString(t, "sarif stderr", sarifStderr, "")
	sarif := assertValidSARIFReport(t, sarifStdout)
	if len(sarif.Runs[0].Results) != 0 {
		t.Fatalf("SARIF results = %#v, want none", sarif.Runs[0].Results)
	}
	for _, forbidden := range []string{"prod-data-backups", "DataClassification", "Owner", "FAKE_CLI_S3_SENSITIVITY"} {
		if strings.Contains(sarifStdout, forbidden) || strings.Contains(sarifStderr, forbidden) {
			t.Fatalf("SARIF output contains graph metadata or secret-like value %q\nstdout:%s", forbidden, sarifStdout)
		}
	}
}

func TestScanDirectoryWithRepoCreatesTerraformCanAssumeRoleGraphEdge(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "deploy.yml", `on:
  push:
    branches: [main]
jobs:
  deploy:
    environment: prod
    permissions:
      id-token: write
`)
	writeTerraformForTest(t, dir, "main.tf", terraformOIDCRole("deploy", "repo:owner/repo:environment:prod"))

	findings, g, err := scanDirectoryWithRepo(dir, "owner/repo")
	if err != nil {
		t.Fatalf("scan directory: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none", findings)
	}
	if countGraphEdges(g, graph.CanAssumeRole) != 1 {
		t.Fatalf("CanAssumeRole edge count = %d, want 1", countGraphEdges(g, graph.CanAssumeRole))
	}

	_, noRepoGraph, err := scanDirectory(dir)
	if err != nil {
		t.Fatalf("scan directory without repo: %v", err)
	}
	if countGraphEdges(noRepoGraph, graph.CanAssumeRole) != 0 {
		t.Fatalf("CanAssumeRole without repo = %d, want 0", countGraphEdges(noRepoGraph, graph.CanAssumeRole))
	}
}

func TestRunScanTerraformTrustTrailingContentErrorIsSanitized(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "deploy.yml", `on:
  pull_request:
permissions:
  id-token: write
`)
	writeTerraformForTest(t, dir, "main.tf", terraformOIDCRoleWithSuffix("deploy", "repo:owner/repo:pull_request", " FAKE_TF_TRAILING_SECRET_DO_NOT_RETAIN"))

	stdout, stderr, code := runCommand("scan", "--repo", "owner/repo", dir)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "aws_iam_role.deploy")
	assertContains(t, stderr, "invalid assume_role_policy JSON")
	for _, forbidden := range []string{"FAKE_TF_TRAILING_SECRET_DO_NOT_RETAIN", "Statement", "Principal", "Condition", "arn:aws:iam"} {
		if strings.Contains(stderr, forbidden) {
			t.Fatalf("stderr contains %q: %s", forbidden, stderr)
		}
	}
}

func TestRunScanAWSIAMRoleAdminPolicyHumanOutput(t *testing.T) {
	dir := t.TempDir()
	writeTerraformForTest(t, dir, "infra/iam.tf", `variable "token" {
  default = "FAKE_CLI_AWS_TF_VARIABLE_SECRET_DO_NOT_RETAIN"
}

resource "aws_iam_role" "deploy" {
}

resource "aws_iam_role_policy" "admin" {
  role = aws_iam_role.deploy.id
  policy = <<EOF
{
  "Statement": {
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }
}
EOF
}
`)

	stdout, stderr, code := runCommand("scan", dir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Finding count: 1\n")
	assertContains(t, stdout, "Rule: PP-AWS-001\n")
	assertContains(t, stdout, "Title: AWS IAM role grants administrative permissions\n")
	assertContains(t, stdout, "Severity: High\n")
	assertContains(t, stdout, "AWSIAMRole aws://terraform/aws_iam_role/infra/iam.tf/deploy")
	assertContains(t, stdout, "AWSPermission aws://terraform/aws_permission/")
	assertContains(t, stdout, "action_star_resource_star")
	assertContains(t, stdout, "infra/iam.tf#resource=aws_iam_role_policy.admin")
	if strings.Contains(stdout, "Remediation:") || strings.Contains(stdout, "Patch Preview:") || strings.Contains(stdout, "Validation:") {
		t.Fatalf("PP-AWS-001 received unsupported remediation/patch/validation output: %s", stdout)
	}
	assertDoesNotContainTerraformAWSSecretValues(t, stdout, stderr)
	for _, forbidden := range []string{"Statement", "assume_role_policy", "policy ="} {
		if strings.Contains(stdout, forbidden) || strings.Contains(stderr, forbidden) {
			t.Fatalf("output contains %q\nstdout:%s\nstderr:%s", forbidden, stdout, stderr)
		}
	}
}

func TestRunScanAWSIAMRoleAdministratorAccessJSONOutput(t *testing.T) {
	dir := t.TempDir()
	writeTerraformForTest(t, dir, "iam.tf", `resource "aws_iam_role" "deploy" {
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.deploy.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.deploy.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}
`)

	stdout, stderr, code := runCommand("scan", "--format=json", dir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.FindingCount != 1 || len(report.Findings) != 1 {
		t.Fatalf("report = %#v, want one finding", report)
	}
	finding := report.Findings[0]
	if finding.RuleID != "PP-AWS-001" || finding.Severity != "High" {
		t.Fatalf("finding = %#v, want PP-AWS-001 High", finding)
	}
	if finding.Remediation != nil {
		t.Fatalf("remediation = %#v, want nil", finding.Remediation)
	}
	if len(finding.Path) != 2 || len(finding.Evidence) != 1 {
		t.Fatalf("path/evidence lengths = %d/%d, want 2/1", len(finding.Path), len(finding.Evidence))
	}
	assertContains(t, stdout, "administrator_access_managed_policy")
	assertContains(t, stdout, "arn:aws:iam::aws:policy/AdministratorAccess")
	for _, forbidden := range []string{"ReadOnlyAccess", "Statement", "policy ="} {
		if strings.Contains(stdout, forbidden) || strings.Contains(stderr, forbidden) {
			t.Fatalf("output contains %q\nstdout:%s\nstderr:%s", forbidden, stdout, stderr)
		}
	}
}

func TestRunScanAWSIAMRoleNonAdminPolicyExitsZero(t *testing.T) {
	dir := t.TempDir()
	writeTerraformForTest(t, dir, "iam.tf", `resource "aws_iam_role" "deploy" {
}

resource "aws_iam_role_policy" "read" {
  role = aws_iam_role.deploy.id
  policy = "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\"}}"
}
`)

	stdout, stderr, code := runCommand("scan", dir)

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	assertString(t, "stdout", stdout, "Finding count: 0\nNo findings.\n")
}

func TestRunScanAWSIAMRoleDynamicRoleExpressionIsIgnoredAndSanitized(t *testing.T) {
	dir := t.TempDir()
	writeTerraformForTest(t, dir, "iam.tf", `resource "aws_iam_role" "deploy" {
}

resource "aws_iam_role_policy" "admin" {
  role = aws_iam_role.deploy.id[count.index]
  policy = "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}}"
}
`)

	findings, g, err := scanDirectory(dir)
	if err != nil {
		t.Fatalf("scan directory: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none", findings)
	}
	if countGraphNodes(g, graph.AWSPermission) != 0 || countGraphEdges(g, graph.GrantsPermission) != 0 {
		t.Fatalf("graph modeled dynamic role permission: nodes=%#v edges=%#v", g.Nodes(), g.Edges())
	}

	humanStdout, humanStderr, humanCode := runCommand("scan", dir)
	jsonStdout, jsonStderr, jsonCode := runCommand("scan", "--format=json", dir)
	sarifStdout, sarifStderr, sarifCode := runCommand("scan", "--format=sarif", dir)

	assertCode(t, humanCode, 0)
	assertCode(t, jsonCode, 0)
	assertCode(t, sarifCode, 0)
	assertString(t, "human stderr", humanStderr, "")
	assertString(t, "json stderr", jsonStderr, "")
	assertString(t, "sarif stderr", sarifStderr, "")
	assertString(t, "human stdout", humanStdout, "Finding count: 0\nNo findings.\n")
	assertString(t, "json stdout", jsonStdout, "{\"findings\":[],\"finding_count\":0}\n")
	sarif := assertValidSARIFReport(t, sarifStdout)
	if len(sarif.Runs[0].Results) != 0 {
		t.Fatalf("SARIF results = %#v, want none", sarif.Runs[0].Results)
	}
	for _, output := range []string{humanStdout, humanStderr, jsonStdout, jsonStderr, sarifStdout, sarifStderr} {
		for _, forbidden := range []string{"AWSPermission", "count.index", "aws_iam_role.deploy.id[count.index]"} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("output contains dynamic role expression text %q: %s", forbidden, output)
			}
		}
	}
	for _, output := range []string{humanStdout, humanStderr, jsonStdout, jsonStderr} {
		if strings.Contains(output, "PP-AWS-001") {
			t.Fatalf("non-SARIF output contains PP-AWS-001 for ignored dynamic role expression: %s", output)
		}
	}
}

func TestScanAWSIAMRolePermissionIDsStableAcrossDifferentRoots(t *testing.T) {
	firstRoot := t.TempDir()
	secondRoot := t.TempDir()
	terraform := `resource "aws_iam_role" "deploy" {
}

resource "aws_iam_role_policy" "admin" {
  role = aws_iam_role.deploy.id
  policy = "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}}"
}
`
	writeTerraformForTest(t, firstRoot, "infra/iam.tf", terraform)
	writeTerraformForTest(t, secondRoot, "infra/iam.tf", terraform)

	firstFindings, firstGraph, err := scanDirectory(firstRoot)
	if err != nil {
		t.Fatalf("scan first directory: %v", err)
	}
	secondFindings, secondGraph, err := scanDirectory(secondRoot)
	if err != nil {
		t.Fatalf("scan second directory: %v", err)
	}
	firstPermissionID := onlyGraphNodeIDOfKind(t, firstGraph, graph.AWSPermission)
	secondPermissionID := onlyGraphNodeIDOfKind(t, secondGraph, graph.AWSPermission)
	if firstPermissionID != secondPermissionID {
		t.Fatalf("AWSPermission IDs differ across roots:\nfirst: %s\nsecond:%s", firstPermissionID, secondPermissionID)
	}
	firstAWS := onlyCLIFindingByRule(t, firstFindings, analysis.RuleAWSIAMRoleAdministrativePermissions)
	secondAWS := onlyCLIFindingByRule(t, secondFindings, analysis.RuleAWSIAMRoleAdministrativePermissions)
	if firstAWS.ID != secondAWS.ID {
		t.Fatalf("PP-AWS-001 finding IDs differ across roots:\nfirst: %s\nsecond:%s", firstAWS.ID, secondAWS.ID)
	}

	stdout, stderr, code := runCommand("scan", firstRoot)
	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	if strings.Contains(stdout, firstRoot) || strings.Contains(stderr, firstRoot) {
		t.Fatalf("CLI output leaked scan root\nstdout:%s\nstderr:%s", stdout, stderr)
	}
}

func TestRunScanAWSIAMRoleMalformedPolicyJSONErrorIsSanitized(t *testing.T) {
	dir := t.TempDir()
	writeTerraformForTest(t, dir, "iam.tf", `resource "aws_iam_role" "deploy" {
}

resource "aws_iam_role_policy" "admin" {
  role = aws_iam_role.deploy.id
  policy = <<EOF
{"Statement": []} FAKE_CLI_AWS_TF_TRAILING_SECRET_DO_NOT_RETAIN
EOF
}
`)

	stdout, stderr, code := runCommand("scan", dir)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "aws_iam_role_policy.admin")
	assertContains(t, stderr, "iam.tf#resource=aws_iam_role_policy.admin")
	assertContains(t, stderr, "invalid policy JSON")
	if strings.Contains(stderr, dir) {
		t.Fatalf("stderr leaked absolute scan root %q: %s", dir, stderr)
	}
	for _, forbidden := range []string{"FAKE_CLI_AWS_TF_TRAILING_SECRET_DO_NOT_RETAIN", "Statement", "policy ="} {
		if strings.Contains(stderr, forbidden) {
			t.Fatalf("stderr contains %q: %s", forbidden, stderr)
		}
	}
}

func TestRunScanRejectsUnknownFlagsWithControlledError(t *testing.T) {
	stdout, stderr, code := runCommand("scan", "--bogus", safeFixture)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "invalid scan arguments")
	assertContains(t, stderr, "flag provided but not defined")
	if strings.Contains(stderr, "Usage of scan") {
		t.Fatalf("stderr contains duplicated Go flag usage: %q", stderr)
	}
}

func TestRunScanRejectsMissingAndNonDirectoryPaths(t *testing.T) {
	file := filepath.Join(t.TempDir(), "manifest.yaml")
	if err := os.WriteFile(file, []byte("apiVersion: v1\nkind: Service\n"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "missing", path: filepath.Join(t.TempDir(), "missing"), want: "no such file"},
		{name: "file", path: file, want: "not a directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, code := runCommand("scan", tt.path)

			assertCode(t, code, 2)
			assertString(t, "stdout", stdout, "")
			assertOneLineStderr(t, stderr)
			assertContains(t, stderr, tt.want)
		})
	}
}

func TestRunScanSafeFixtureReturnsZeroAndNoFindings(t *testing.T) {
	stdout, stderr, code := runCommand("scan", safeFixture)

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	assertString(t, "stdout", stdout, "Finding count: 0\nNo findings.\n")
	assertExactlyOneTrailingNewline(t, stdout)
}

func TestRunScanVulnerableFixtureReturnsOneAndHumanFinding(t *testing.T) {
	stdout, stderr, code := runCommand("scan", vulnerableFixture)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Finding count: 1\n")
	assertContains(t, stdout, "Rule: PP-K8S-001\n")
	assertContains(t, stdout, "Severity: High\n")
	assertContains(t, stdout, "Path:\n  1. PublicEndpoint kubernetes://prod/service/public-api")
	assertContains(t, stdout, "  2. Workload kubernetes://prod/deployment/api")
	assertContains(t, stdout, "  3. ServiceAccount kubernetes://prod/serviceaccount/api")
	assertContains(t, stdout, "  4. Secret kubernetes://prod/secret/database-password")
	assertContains(t, stdout, "Evidence:\n  - RoutesTo edge:")
	assertContains(t, stdout, "  - CanRead edge:")
	assertContains(t, stdout, "Sources:")
	assertContains(t, stdout, "Remediation:")
	assertContains(t, stdout, "Option 1: RemoveSecretsResource")
	assertContains(t, stdout, "Option 2: RemoveSecretReadVerb")
	assertContains(t, stdout, "Changes:")
	if strings.Contains(stdout, "Patch Preview:") {
		t.Fatalf("default human output contains patch preview: %s", stdout)
	}
	assertExactlyOneTrailingNewline(t, stdout)
}

func TestRunScanRankDefaultOutputHasNoRankingMetadata(t *testing.T) {
	humanStdout, humanStderr, humanCode := runCommand("scan", vulnerableFixture)
	jsonStdout, jsonStderr, jsonCode := runCommand("scan", "--format=json", vulnerableFixture)

	assertCode(t, humanCode, 1)
	assertCode(t, jsonCode, 1)
	assertString(t, "human stderr", humanStderr, "")
	assertString(t, "json stderr", jsonStderr, "")
	if strings.Contains(humanStdout, "Priority score:") {
		t.Fatalf("default human output contains ranking metadata: %s", humanStdout)
	}
	report := assertValidJSONReport(t, jsonStdout)
	if len(report.Findings) != 1 {
		t.Fatalf("finding count = %d, want 1", len(report.Findings))
	}
	if report.Findings[0].Ranking != nil || strings.Contains(jsonStdout, `"ranking"`) {
		t.Fatalf("default JSON output contains ranking metadata: %s", jsonStdout)
	}
}

func TestRunScanRankHeuristicAddsHumanAndJSONRanking(t *testing.T) {
	humanStdout, humanStderr, humanCode := runCommand("scan", "--rank", "heuristic", vulnerableFixture)
	jsonStdout, jsonStderr, jsonCode := runCommand("scan", "--format=json", "--rank=heuristic", vulnerableFixture)

	assertCode(t, humanCode, 1)
	assertCode(t, jsonCode, 1)
	assertString(t, "human stderr", humanStderr, "")
	assertString(t, "json stderr", jsonStderr, "")
	assertContains(t, humanStdout, "Priority score: 105 (heuristic, critical_priority)\n")

	report := assertValidJSONReport(t, jsonStdout)
	if len(report.Findings) != 1 || report.Findings[0].Ranking == nil {
		t.Fatalf("ranking JSON finding = %#v, want one ranked finding", report.Findings)
	}
	ranking := report.Findings[0].Ranking
	wantReasons := []string{
		"high severity +50",
		"public exposure +15",
		"sensitive resource +20",
		"Kubernetes Secret access +15",
		"remediation available +5",
	}
	if ranking.Method != "heuristic" || ranking.Score != 105 || ranking.Band != "critical_priority" || !reflect.DeepEqual(ranking.Reasons, wantReasons) {
		t.Fatalf("ranking = %#v, want heuristic score 105 with stable reasons", ranking)
	}
}

func TestRunScanRankHeuristicDoesNotChangeExitCodesFindingIDsOrOrder(t *testing.T) {
	stdout, stderr, code := runCommand("scan", "--format=json", vulnerableFixture)
	rankedStdout, rankedStderr, rankedCode := runCommand("scan", "--format=json", "--rank", "heuristic", vulnerableFixture)

	assertCode(t, code, 1)
	assertCode(t, rankedCode, 1)
	assertString(t, "stderr", stderr, "")
	assertString(t, "ranked stderr", rankedStderr, "")
	report := assertValidJSONReport(t, stdout)
	rankedReport := assertValidJSONReport(t, rankedStdout)
	if len(report.Findings) != len(rankedReport.Findings) {
		t.Fatalf("ranked finding count = %d, want %d", len(rankedReport.Findings), len(report.Findings))
	}
	for i := range report.Findings {
		if rankedReport.Findings[i].ID != report.Findings[i].ID || rankedReport.Findings[i].Severity != report.Findings[i].Severity || rankedReport.Findings[i].RuleID != report.Findings[i].RuleID {
			t.Fatalf("rank changed finding identity/order/severity:\nbase:%#v\nrank:%#v", report.Findings, rankedReport.Findings)
		}
	}
}

func TestRunScanRankHeuristicDoesNotChangeSARIF(t *testing.T) {
	stdout, stderr, code := runCommand("scan", "--format=sarif", vulnerableFixture)
	rankedStdout, rankedStderr, rankedCode := runCommand("scan", "--format=sarif", "--rank", "heuristic", vulnerableFixture)

	assertCode(t, code, 1)
	assertCode(t, rankedCode, 1)
	assertString(t, "stderr", stderr, "")
	assertString(t, "ranked stderr", rankedStderr, "")
	assertString(t, "ranked SARIF stdout", rankedStdout, stdout)
	if strings.Contains(rankedStdout, "ranking") || strings.Contains(rankedStdout, "priority") {
		t.Fatalf("ranked SARIF contains ranking metadata: %s", rankedStdout)
	}
}

func TestRunScanRejectsInvalidRankFlag(t *testing.T) {
	stdout, stderr, code := runCommand("scan", "--rank", "ml", safeFixture)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "unsupported --rank \"ml\"")
}

func TestRunScanWriteBaselineRejectsRank(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeSplitVulnerableFixture(t, root, []string{"service.yaml", "deployment.yaml", "secret.yaml", "rbac.yaml"})

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--write-baseline", "baseline.json", "--rank", "heuristic", "scan")

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "--write-baseline cannot be combined with --rank")
	assertPathDoesNotExist(t, filepath.Join(parent, "baseline.json"))
}

func TestRunScanRankHeuristicWorksWithConfigFiltering(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeSplitVulnerableFixture(t, root, []string{"service.yaml", "deployment.yaml", "secret.yaml", "rbac.yaml"})
	writeFileForTest(t, parent, "pathproof.json", `{"rules":{"disable":["PP-K8S-001"]}}`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--rank", "heuristic", "--config", "pathproof.json", "scan")

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Finding count: 0\n")
	if strings.Contains(stdout, "Priority score:") {
		t.Fatalf("ranked config-filtered output contains ranking for hidden finding: %s", stdout)
	}
}

func TestRunScanRankHeuristicWorksWithBaselineComparison(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	initialOut, initialErr, initialCode := runCommandInDir(t, parent, "scan", "--format=json", "scan")
	assertCode(t, initialCode, 1)
	assertString(t, "initial stderr", initialErr, "")
	finding := firstCLIFindingByRule(t, assertValidJSONReport(t, initialOut).Findings, "PP-GHA-001")
	staleID := testCLIBaselineFindingID("PP-GHA-001", "c")
	writeFileForTest(t, parent, "baseline.json", `{"suppressions":[{"finding_id":"`+finding.ID+`","reason":"Accepted"},{"finding_id":"`+staleID+`","reason":"Accepted stale"}]}`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--rank", "heuristic", "--baseline", "baseline.json", "scan")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.BaselineComparison == nil || report.BaselineComparison.ResolvedFindingsCount != 1 {
		t.Fatalf("baseline comparison = %#v, want one resolved ID", report.BaselineComparison)
	}
	if len(report.Findings) != 1 || report.Findings[0].BaselineStatus != "existing" || report.Findings[0].Ranking == nil {
		t.Fatalf("ranked baseline finding = %#v, want existing ranked finding", report.Findings)
	}
	for _, reason := range report.Findings[0].Ranking.Reasons {
		if reason == "new baseline status +10" {
			t.Fatalf("existing baseline finding has new-status score reason: %#v", report.Findings[0].Ranking)
		}
	}
	if strings.Count(stdout, `"ranking"`) != 1 {
		t.Fatalf("ranking count in stdout = %d, want only visible current finding ranked: %s", strings.Count(stdout, `"ranking"`), stdout)
	}
}

func TestRunScanRankHeuristicDoesNotCreateSideEffectsOrLeakRawValues(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "unsafe.yml", `on: pull_request_target
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          token: FAKE_RANK_SECRET_DO_NOT_RETAIN
      - run: echo FAKE_RANK_RUN_SCRIPT_DO_NOT_RETAIN
`)

	stdout, stderr, code := runCommand("scan", "--rank", "heuristic", dir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Priority score:")
	for _, forbidden := range []string{
		"FAKE_RANK_SECRET_DO_NOT_RETAIN",
		"FAKE_RANK_RUN_SCRIPT_DO_NOT_RETAIN",
		"Patch Output:",
		"Patch Preview:",
		"Validation:",
		"replacement_sha",
	} {
		if strings.Contains(stdout, forbidden) || strings.Contains(stderr, forbidden) {
			t.Fatalf("rank output contains forbidden value %q\nstdout:%s\nstderr:%s", forbidden, stdout, stderr)
		}
	}
}

func TestRunScanSafeGitHubActionsWorkflowReturnsZero(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "safe.yml", `name: Safe
jobs:
  test:
    steps:
      - uses: owner/repo@0123456789abcdef0123456789ABCDEF01234567
      - uses: ./local-action
      - uses: docker://alpine:3.19
      - uses: ${{ matrix.action }}
`)

	stdout, stderr, code := runCommand("scan", dir)

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	assertString(t, "stdout", stdout, "Finding count: 0\nNo findings.\n")
}

func TestRunScanGitHubActionsOIDCTokenCapabilityOnlyReturnsNoFindings(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "oidc.yml", `name: OIDC only
on: push
permissions:
  id-token: write
env:
  TOKEN: FAKE_CLI_GHA_ENV_SECRET_DO_NOT_RETAIN
jobs:
  deploy:
    steps:
      - run: echo FAKE_CLI_GHA_RUN_SECRET_DO_NOT_RETAIN
`)

	humanStdout, humanStderr, humanCode := runCommand("scan", dir)
	jsonStdout, jsonStderr, jsonCode := runCommand("scan", "--format=json", dir)
	sarifStdout, sarifStderr, sarifCode := runCommand("scan", "--format=sarif", dir)

	assertCode(t, humanCode, 0)
	assertString(t, "human stderr", humanStderr, "")
	assertString(t, "human stdout", humanStdout, "Finding count: 0\nNo findings.\n")

	assertCode(t, jsonCode, 0)
	assertString(t, "json stderr", jsonStderr, "")
	report := assertValidJSONReport(t, jsonStdout)
	if report.FindingCount != 0 || len(report.Findings) != 0 {
		t.Fatalf("JSON report = %#v, want no findings", report)
	}
	assertString(t, "json stdout", jsonStdout, "{\"findings\":[],\"finding_count\":0}\n")

	assertCode(t, sarifCode, 0)
	assertString(t, "sarif stderr", sarifStderr, "")
	sarif := assertValidSARIFReport(t, sarifStdout)
	if len(sarif.Runs[0].Results) != 0 {
		t.Fatalf("SARIF results = %#v, want none", sarif.Runs[0].Results)
	}

	for _, output := range []string{humanStdout, jsonStdout, sarifStdout} {
		for _, forbidden := range []string{"OIDCTokenCapability", "CanRequestOIDCToken", "github_actions_oidc", "id-token: write"} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("scan output contains graph-only OIDC text %q: %s", forbidden, output)
			}
		}
	}
	assertDoesNotContainGitHubActionsSecretValues(t, humanStdout, humanStderr, jsonStdout, jsonStderr, sarifStdout, sarifStderr)
}

func TestRunScanGitHubActionsUnpinnedWorkflowReturnsOneAndFindingOnly(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "unpinned.yml", `name: Unpinned
env:
  TOKEN: FAKE_CLI_GHA_ENV_SECRET_DO_NOT_RETAIN
jobs:
  test:
    steps:
      - name: Build
        run: echo FAKE_CLI_GHA_RUN_SECRET_DO_NOT_RETAIN
      - name: Checkout
        uses: actions/checkout@v4
        with:
          token: FAKE_CLI_GHA_WITH_SECRET_DO_NOT_RETAIN
`)

	stdout, stderr, code := runCommand("scan", dir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Finding count: 1\n")
	assertContains(t, stdout, "Rule: PP-GHA-001\n")
	assertContains(t, stdout, "Title: GitHub Actions workflow uses an action that is not pinned to a full commit SHA\n")
	assertContains(t, stdout, "Severity: Medium\n")
	assertContains(t, stdout, "Workflow githubactions://.github/workflows/unpinned.yml")
	assertContains(t, stdout, "WorkflowJob githubactions://.github/workflows/unpinned.yml/job/test")
	assertContains(t, stdout, "GitHubAction githubactions://.github/workflows/unpinned.yml/job/test/step/1/action/actions/checkout@v4")
	assertContains(t, stdout, "UsesAction")
	assertContains(t, stdout, "actions/checkout@v4")
	assertContains(t, stdout, "Remediation:")
	assertContains(t, stdout, "PinGitHubActionToSHA")
	assertContains(t, stdout, "no local SHA mapping")
	for _, forbidden := range []string{"permission_sha256=", "matched_verb=", "subject="} {
		if strings.Contains(stdout, forbidden) {
			t.Fatalf("GitHub Actions human output contains K8S-only field %q: %s", forbidden, stdout)
		}
	}
	if strings.Contains(stdout, legacyGitHubActionsRuleWording()) || strings.Contains(stdout, "Patch Preview:") || strings.Contains(stdout, "Validation:") {
		t.Fatalf("GitHub Actions finding output contains unsupported text: %s", stdout)
	}
	assertDoesNotContainGitHubActionsSecretValues(t, stdout, stderr)
}

func TestRunScanGitHubActionsJSONOutputIncludesFindingWithoutRemediation(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "unpinned.yml", `jobs:
  release:
    steps:
      - uses: owner/repo/path@v1.2.3
        env:
          TOKEN: FAKE_CLI_GHA_ENV_SECRET_DO_NOT_RETAIN
        with:
          password: FAKE_CLI_GHA_WITH_SECRET_DO_NOT_RETAIN
      - run: echo FAKE_CLI_GHA_RUN_SECRET_DO_NOT_RETAIN
`)

	stdout, stderr, code := runCommand("scan", "--format=json", dir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.FindingCount != 1 || len(report.Findings) != 1 {
		t.Fatalf("finding count = %d len = %d, want 1", report.FindingCount, len(report.Findings))
	}
	finding := report.Findings[0]
	if finding.RuleID != "PP-GHA-001" || finding.Severity != "Medium" {
		t.Fatalf("finding = %#v, want PP-GHA-001 Medium", finding)
	}
	if finding.Remediation == nil {
		t.Fatal("remediation = nil, want advisory PP-GHA-001 remediation")
	}
	if len(finding.Remediation.Options) != 1 || finding.Remediation.Options[0].Action != "PinGitHubActionToSHA" {
		t.Fatalf("remediation = %#v, want PinGitHubActionToSHA option", finding.Remediation)
	}
	change := finding.Remediation.Options[0].Changes[0]
	if !change.Advisory || change.PatchSupported || change.ActionRef != "owner/repo/path@v1.2.3" || change.ReplacementSHA != "" {
		t.Fatalf("remediation change = %#v, want advisory-only action pinning", change)
	}
	if len(finding.Path) != 3 || len(finding.Evidence) != 2 {
		t.Fatalf("path/evidence lengths = %d/%d, want 3/2", len(finding.Path), len(finding.Evidence))
	}
	assertContains(t, stdout, "owner/repo/path@v1.2.3")
	if strings.Contains(stdout, legacyGitHubActionsRuleWording()) {
		t.Fatalf("JSON output contains old inaccurate rule wording: %s", stdout)
	}
	assertDoesNotContainGitHubActionsSecretValues(t, stdout, stderr)
}

func TestRunScanGitHubActionsUnsafePullRequestTargetCheckoutHumanOutput(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "unsafe.yml", `name: Unsafe
on: pull_request_target
env:
  TOKEN: FAKE_CLI_GHA_ENV_SECRET_DO_NOT_RETAIN
jobs:
  test:
    steps:
      - run: echo FAKE_CLI_GHA_RUN_SECRET_DO_NOT_RETAIN
      - name: Checkout
        uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
        with:
          token: FAKE_CLI_GHA_WITH_SECRET_DO_NOT_RETAIN
          ref: ${{ github.event.pull_request.head.sha }}
`)

	stdout, stderr, code := runCommand("scan", dir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Finding count: 1\n")
	assertContains(t, stdout, "Rule: PP-GHA-002\n")
	assertContains(t, stdout, "Title: pull_request_target workflow checks out untrusted pull request head code\n")
	assertContains(t, stdout, "Severity: High\n")
	assertContains(t, stdout, "Workflow githubactions://.github/workflows/unsafe.yml")
	assertContains(t, stdout, "WorkflowJob githubactions://.github/workflows/unsafe.yml/job/test")
	assertContains(t, stdout, "GitHubAction githubactions://.github/workflows/unsafe.yml/job/test/step/1/action/actions/checkout@0123456789abcdef0123456789abcdef01234567")
	assertContains(t, stdout, "pull_request_target")
	assertContains(t, stdout, "ref=github.event.pull_request.head.sha")
	if strings.Contains(stdout, "Remediation:") || strings.Contains(stdout, "Patch Preview:") || strings.Contains(stdout, "Validation:") || strings.Contains(stdout, "${{") {
		t.Fatalf("PP-GHA-002 output contains unsupported or raw expression text: %s", stdout)
	}
	assertDoesNotContainGitHubActionsSecretValues(t, stdout, stderr)
}

func TestRunScanGitHubActionsUnsafePullRequestTargetCheckoutJSONOutput(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "unsafe.yml", `on:
  pull_request_target:
jobs:
  test:
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
          ref: ${{ github.event.pull_request.head.ref }}
          password: FAKE_CLI_GHA_WITH_SECRET_DO_NOT_RETAIN
`)

	stdout, stderr, code := runCommand("scan", "--format=json", dir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.FindingCount != 1 || len(report.Findings) != 1 {
		t.Fatalf("finding count = %d len = %d, want 1", report.FindingCount, len(report.Findings))
	}
	finding := report.Findings[0]
	if finding.RuleID != "PP-GHA-002" || finding.Severity != "High" {
		t.Fatalf("finding = %#v, want PP-GHA-002 High", finding)
	}
	if finding.Remediation != nil {
		t.Fatalf("remediation = %#v, want nil", finding.Remediation)
	}
	if len(finding.Path) != 3 || len(finding.Evidence) != 2 {
		t.Fatalf("path/evidence lengths = %d/%d, want 3/2", len(finding.Path), len(finding.Evidence))
	}
	assertContains(t, stdout, "repository=github.event.pull_request.head.repo.full_name")
	assertContains(t, stdout, "ref=github.event.pull_request.head.ref")
	for _, forbidden := range []string{"FAKE_CLI_GHA_WITH_SECRET_DO_NOT_RETAIN", "password", "${{"} {
		if strings.Contains(stdout, forbidden) || strings.Contains(stderr, forbidden) {
			t.Fatalf("output contains %q\nstdout:%s\nstderr:%s", forbidden, stdout, stderr)
		}
	}
}

func TestRunScanGitHubActionsDangerousPermissionsHumanOutput(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "permissions.yml", `name: Dangerous permissions
on: pull_request_target
permissions: write-all
env:
  TOKEN: FAKE_CLI_GHA_ENV_SECRET_DO_NOT_RETAIN
jobs:
  test:
    steps:
      - run: echo FAKE_CLI_GHA_RUN_SECRET_DO_NOT_RETAIN
      - uses: owner/repo@0123456789abcdef0123456789abcdef01234567
        with:
          token: FAKE_CLI_GHA_WITH_SECRET_DO_NOT_RETAIN
`)

	stdout, stderr, code := runCommand("scan", dir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Finding count: 1\n")
	assertContains(t, stdout, "Rule: PP-GHA-003\n")
	assertContains(t, stdout, "Title: pull_request_target workflow grants dangerous token permissions\n")
	assertContains(t, stdout, "Severity: High\n")
	assertContains(t, stdout, "Summary: GitHub Actions workflow Dangerous permissions (.github/workflows/permissions.yml) grants permissions: write-all at workflow scope under pull_request_target.\n")
	assertContains(t, stdout, "Workflow githubactions://.github/workflows/permissions.yml")
	if strings.Contains(stdout, "all: write") || strings.Contains(stdout, "Remediation:") || strings.Contains(stdout, "Patch Preview:") || strings.Contains(stdout, "Validation:") {
		t.Fatalf("PP-GHA-003 output contains unsupported or confusing text: %s", stdout)
	}
	assertDoesNotContainGitHubActionsSecretValues(t, stdout, stderr)
}

func TestRunScanGitHubActionsDangerousPermissionsJSONOutput(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "permissions.yml", `on:
  pull_request_target:
jobs:
  deploy:
    permissions:
      id-token: write
    steps:
      - uses: owner/repo@0123456789abcdef0123456789abcdef01234567
`)

	stdout, stderr, code := runCommand("scan", "--format=json", dir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.FindingCount != 1 || len(report.Findings) != 1 {
		t.Fatalf("finding count = %d len = %d, want 1", report.FindingCount, len(report.Findings))
	}
	finding := report.Findings[0]
	if finding.RuleID != "PP-GHA-003" || finding.Severity != "High" {
		t.Fatalf("finding = %#v, want PP-GHA-003 High", finding)
	}
	if finding.Remediation != nil {
		t.Fatalf("remediation = %#v, want nil", finding.Remediation)
	}
	if len(finding.Path) != 2 || len(finding.Evidence) != 1 {
		t.Fatalf("path/evidence lengths = %d/%d, want 2/1", len(finding.Path), len(finding.Evidence))
	}
	assertContains(t, stdout, "job deploy")
	assertContains(t, stdout, "id-token: write")
	assertContains(t, stdout, "pull_request_target")
	assertDoesNotContainGitHubActionsSecretValues(t, stdout, stderr)
}

func TestRunScanGitHubActionsExpressionOnlyUsesValueIsNotRetained(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "expression.yml", `on: pull_request_target
jobs:
  test:
    steps:
      - uses: ${{ secrets.ACTION_REF }}
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`)

	for _, args := range [][]string{
		{"scan", dir},
		{"scan", "--format=json", dir},
		{"scan", "--format=sarif", dir},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, stderr, code := runCommand(args...)

			assertCode(t, code, 0)
			assertString(t, "stderr", stderr, "")
			for _, forbidden := range []string{"secrets.ACTION_REF", "${{ secrets.ACTION_REF }}"} {
				if strings.Contains(stdout, forbidden) || strings.Contains(stderr, forbidden) {
					t.Fatalf("output contains expression-only uses value %q\nstdout:%s\nstderr:%s", forbidden, stdout, stderr)
				}
			}
		})
	}
}

func TestRunScanGitHubActionsNonCheckoutHeadSelectorDoesNotEmitPPGHA002(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "unsafe-looking.yml", `on: pull_request_target
jobs:
  test:
    steps:
      - uses: evil/action@v1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`)

	stdout, stderr, code := runCommand("scan", "--format=json", dir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.FindingCount != 1 || len(report.Findings) != 1 {
		t.Fatalf("findings = %#v, count = %d; want one PP-GHA-001 finding", report.Findings, report.FindingCount)
	}
	if report.Findings[0].RuleID != "PP-GHA-001" {
		t.Fatalf("rule_id = %q, want PP-GHA-001 only", report.Findings[0].RuleID)
	}
	if strings.Contains(stdout, "PP-GHA-002") || strings.Contains(stdout, "${{") {
		t.Fatalf("output contains unexpected PP-GHA-002 or raw expression: %s", stdout)
	}
}

func TestRunScanGitHubActionsMixedFindingsAreDeterministic(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "unsafe.yml", `on: pull_request_target
permissions:
  contents: write
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`)

	firstOut, firstErr, firstCode := runCommand("scan", "--format=json", dir)
	secondOut, secondErr, secondCode := runCommand("scan", "--format=json", dir)

	assertCode(t, firstCode, 1)
	assertCode(t, secondCode, 1)
	assertString(t, "first stderr", firstErr, "")
	assertString(t, "second stderr", secondErr, "")
	assertString(t, "stdout", secondOut, firstOut)
	report := assertValidJSONReport(t, firstOut)
	if report.FindingCount != 3 || len(report.Findings) != 3 {
		t.Fatalf("finding count = %d len = %d, want 3", report.FindingCount, len(report.Findings))
	}
	seen := map[string]bool{}
	for i, finding := range report.Findings {
		seen[finding.RuleID] = true
		if finding.RuleID == "PP-GHA-001" {
			if finding.Remediation == nil {
				t.Fatalf("PP-GHA-001 remediation = nil, want advisory plan")
			}
		} else if finding.Remediation != nil {
			t.Fatalf("finding %s remediation = %#v, want nil", finding.RuleID, finding.Remediation)
		}
		if i > 0 && report.Findings[i-1].ID > finding.ID {
			t.Fatalf("findings are not sorted by deterministic ID: %#v", report.Findings)
		}
	}
	if !seen["PP-GHA-001"] || !seen["PP-GHA-002"] || !seen["PP-GHA-003"] {
		t.Fatalf("rules seen = %#v, want PP-GHA-001, PP-GHA-002, and PP-GHA-003", seen)
	}
}

func TestRunScanGitHubActionsInvalidPermissionMapValuesAreIgnoredAndExcluded(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "permissions.yml", `on: pull_request_target
permissions:
  contents: write-all
  actions: ${{ inputs.permission }}
jobs:
  test:
    permissions:
      contents: read-all
      checks: unknown
`)

	for _, args := range [][]string{
		{"scan", dir},
		{"scan", "--format=json", dir},
		{"scan", "--format=sarif", dir},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, stderr, code := runCommand(args...)

			assertCode(t, code, 0)
			assertString(t, "stderr", stderr, "")
			for _, forbidden := range []string{"contents: write-all", "contents: read-all", "inputs.permission", "${{", "unknown"} {
				if strings.Contains(stdout, forbidden) || strings.Contains(stderr, forbidden) {
					t.Fatalf("output contains %q\nstdout:%s\nstderr:%s", forbidden, stdout, stderr)
				}
			}
		})
	}
}

func TestRunScanGitHubActionsExistingFindingsDoNotIncludeJobPermissionEvidence(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "unsafe.yml", `on: pull_request_target
jobs:
  test:
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`)

	humanStdout, humanStderr, humanCode := runCommand("scan", dir)
	jsonStdout, jsonStderr, jsonCode := runCommand("scan", "--format=json", dir)
	sarifStdout, sarifStderr, sarifCode := runCommand("scan", "--format=sarif", dir)

	assertCode(t, humanCode, 1)
	assertString(t, "human stderr", humanStderr, "")
	for _, block := range strings.Split(humanStdout, "\nFinding:") {
		if strings.Contains(block, "Rule: PP-GHA-001") || strings.Contains(block, "Rule: PP-GHA-002") {
			if strings.Contains(block, "contents: write") {
				t.Fatalf("existing GitHub Actions finding block contains permission text:\n%s", block)
			}
		}
	}
	assertContains(t, humanStdout, "Rule: PP-GHA-003\n")
	assertContains(t, humanStdout, "contents: write")

	assertCode(t, jsonCode, 1)
	assertString(t, "json stderr", jsonStderr, "")
	report := assertValidJSONReport(t, jsonStdout)
	for _, finding := range report.Findings {
		if finding.RuleID == "PP-GHA-001" || finding.RuleID == "PP-GHA-002" {
			data, err := json.Marshal(finding)
			if err != nil {
				t.Fatalf("marshal finding: %v", err)
			}
			if strings.Contains(string(data), "contents: write") {
				t.Fatalf("%s JSON finding contains permission text: %s", finding.RuleID, data)
			}
		}
		if finding.RuleID == "PP-GHA-003" && !strings.Contains(finding.Summary, "contents: write") {
			t.Fatalf("PP-GHA-003 summary = %q, want permission text", finding.Summary)
		}
	}

	assertCode(t, sarifCode, 1)
	assertString(t, "sarif stderr", sarifStderr, "")
	sarif := assertValidSARIFReport(t, sarifStdout)
	for _, result := range sarif.Runs[0].Results {
		if result.RuleID == "PP-GHA-001" || result.RuleID == "PP-GHA-002" {
			data, err := json.Marshal(result)
			if err != nil {
				t.Fatalf("marshal SARIF result: %v", err)
			}
			if strings.Contains(string(data), "contents: write") {
				t.Fatalf("%s SARIF result contains permission text: %s", result.RuleID, data)
			}
		}
		if result.RuleID == "PP-GHA-003" && !strings.Contains(result.Message.Text, "contents: write") {
			t.Fatalf("PP-GHA-003 SARIF message = %q, want permission text", result.Message.Text)
		}
	}
}

func TestRunScanGitHubActionsDangerousPermissionsPatchFlagsDoNotPatchOrValidateFinding(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir scan root: %v", err)
	}
	writeGitHubActionsWorkflowForTest(t, root, "permissions.yml", `on: pull_request_target
permissions:
  contents: write
`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--write-patches", "patched", "--validate-patches", "scan")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Rule: PP-GHA-003\n")
	assertContains(t, stdout, "Patch Output:")
	assertContains(t, stdout, "Written files: 0")
	if strings.Contains(stdout, "Remediation:") || strings.Contains(stdout, "Patch Preview:") || strings.Contains(stdout, "Validation:") {
		t.Fatalf("PP-GHA-003 received unsupported remediation/patch/validation output: %s", stdout)
	}
	if _, err := os.Stat(filepath.Join(parent, "patched")); !os.IsNotExist(err) {
		t.Fatalf("patched output directory exists or stat failed unexpectedly: %v", err)
	}
}

func TestRunScanGitHubActionsUnsafeCheckoutPatchFlagsDoNotPatchOrValidateFinding(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir scan root: %v", err)
	}
	writeGitHubActionsWorkflowForTest(t, root, "unsafe.yml", `on: pull_request_target
jobs:
  test:
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--write-patches", "patched", "--validate-patches", "scan")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Rule: PP-GHA-002\n")
	assertContains(t, stdout, "Patch Output:")
	assertContains(t, stdout, "Written files: 0")
	if strings.Contains(stdout, "Remediation:") || strings.Contains(stdout, "Patch Preview:") || strings.Contains(stdout, "Validation:") {
		t.Fatalf("PP-GHA-002 received unsupported remediation/patch/validation output: %s", stdout)
	}
	if _, err := os.Stat(filepath.Join(parent, "patched")); !os.IsNotExist(err) {
		t.Fatalf("patched output directory exists or stat failed unexpectedly: %v", err)
	}
}

func TestRunScanMixedKubernetesAndGitHubActionsFindingsAreDeterministic(t *testing.T) {
	dir := t.TempDir()
	writeSplitVulnerableFixture(t, dir, []string{"service.yaml", "deployment.yaml", "secret.yaml", "rbac.yaml"})
	writeGitHubActionsWorkflowForTest(t, dir, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: docker/login-action@v3
`)

	firstOut, firstErr, firstCode := runCommand("scan", "--format=json", dir)
	secondOut, secondErr, secondCode := runCommand("scan", "--format=json", dir)

	assertCode(t, firstCode, 1)
	assertCode(t, secondCode, 1)
	assertString(t, "first stderr", firstErr, "")
	assertString(t, "second stderr", secondErr, "")
	assertString(t, "stdout", secondOut, firstOut)
	report := assertValidJSONReport(t, firstOut)
	if report.FindingCount != 2 || len(report.Findings) != 2 {
		t.Fatalf("finding count = %d len = %d, want 2", report.FindingCount, len(report.Findings))
	}
	seen := map[string]bool{}
	for i, finding := range report.Findings {
		seen[finding.RuleID] = true
		if i > 0 && report.Findings[i-1].ID > finding.ID {
			t.Fatalf("findings are not sorted by deterministic ID: %#v", report.Findings)
		}
	}
	if !seen["PP-K8S-001"] || !seen["PP-GHA-001"] {
		t.Fatalf("rules seen = %#v, want both PP-K8S-001 and PP-GHA-001", seen)
	}
}

func TestRunScanConfigDisablesGitHubActionsRule(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	writeFileForTest(t, parent, "pathproof.json", `{"rules":{"disable":["PP-GHA-001"]}}`)

	humanStdout, humanStderr, humanCode := runCommandInDir(t, parent, "scan", "--config", "pathproof.json", "scan")
	jsonStdout, jsonStderr, jsonCode := runCommandInDir(t, parent, "scan", "--format=json", "--config", "pathproof.json", "scan")

	assertCode(t, humanCode, 0)
	assertString(t, "human stderr", humanStderr, "")
	assertString(t, "human stdout", humanStdout, "Finding count: 0\nNo findings.\n")

	assertCode(t, jsonCode, 0)
	assertString(t, "json stderr", jsonStderr, "")
	report := assertValidJSONReport(t, jsonStdout)
	if !report.ConfigApplied || report.SuppressedFindingsCount == nil || *report.SuppressedFindingsCount != 0 {
		t.Fatalf("config metadata = applied:%t suppressed:%v", report.ConfigApplied, report.SuppressedFindingsCount)
	}
	if !reflect.DeepEqual(report.DisabledRules, []string{"PP-GHA-001"}) {
		t.Fatalf("disabled_rules = %#v, want PP-GHA-001", report.DisabledRules)
	}
	if report.FindingCount != 0 || len(report.Findings) != 0 {
		t.Fatalf("findings = %#v count=%d, want none", report.Findings, report.FindingCount)
	}
}

func TestRunScanConfigEnableAllowlistEmitsOnlyAllowedRule(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeSplitVulnerableFixture(t, root, []string{"service.yaml", "deployment.yaml", "secret.yaml", "rbac.yaml"})
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: docker/login-action@v3
`)
	writeFileForTest(t, parent, "pathproof.json", `{"rules":{"enable":["PP-GHA-001"]}}`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--config", "pathproof.json", "scan")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.FindingCount != 1 || len(report.Findings) != 1 || report.Findings[0].RuleID != "PP-GHA-001" {
		t.Fatalf("findings = %#v count=%d, want only PP-GHA-001", report.Findings, report.FindingCount)
	}
	if len(report.DisabledRules) != 8 {
		t.Fatalf("disabled_rules = %#v, want eight non-allowlisted rules", report.DisabledRules)
	}
	assertNoRuleInJSONReport(t, stdout, "PP-K8S-001")
}

func TestRunScanConfigControlsCrossDomainSensitiveS3Rule(t *testing.T) {
	t.Run("disable omits PP-XDOMAIN-004 only", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "scan")
		writeGitHubActionsWorkflowForTest(t, root, "unsafe-sensitive-s3.yml", `on: pull_request_target
permissions: write-all
`)
		writeTerraformForTest(t, root, "infra/iam.tf", terraformOIDCSensitiveS3Role("deploy", "repo:owner/repo:pull_request", "artifacts", "assets", "read", "s3:GetObject", "arn:aws:s3:::assets/*"))
		writeFileForTest(t, parent, "pathproof.json", `{"rules":{"disable":["PP-XDOMAIN-004"]}}`)

		stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--repo", "owner/repo", "--config", "pathproof.json", "scan")

		assertCode(t, code, 1)
		assertString(t, "stderr", stderr, "")
		assertNoRuleInJSONReport(t, stdout, "PP-XDOMAIN-004")
		if got := countCLIFindingsByRule(assertValidJSONReport(t, stdout).Findings, "PP-XDOMAIN-003"); got != 1 {
			t.Fatalf("PP-XDOMAIN-003 count = %d, want sibling still enabled", got)
		}
	})

	t.Run("enable allowlist emits only PP-XDOMAIN-004", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "scan")
		writeGitHubActionsWorkflowForTest(t, root, "unsafe-sensitive-s3.yml", `on: pull_request_target
permissions: write-all
`)
		writeTerraformForTest(t, root, "infra/iam.tf", terraformOIDCSensitiveS3Role("deploy", "repo:owner/repo:pull_request", "artifacts", "assets", "read", "s3:GetObject", "arn:aws:s3:::assets/*"))
		writeFileForTest(t, parent, "pathproof.json", `{"rules":{"enable":["PP-XDOMAIN-004"]}}`)

		stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--repo", "owner/repo", "--config", "pathproof.json", "scan")

		assertCode(t, code, 1)
		assertString(t, "stderr", stderr, "")
		report := assertValidJSONReport(t, stdout)
		if report.FindingCount != 1 || len(report.Findings) != 1 || report.Findings[0].RuleID != "PP-XDOMAIN-004" {
			t.Fatalf("findings = %#v count=%d, want only PP-XDOMAIN-004", report.Findings, report.FindingCount)
		}
	})
}

func TestRunScanConfigSuppressesAndExcludesCrossDomainSensitiveS3Rule(t *testing.T) {
	t.Run("suppression by finding ID", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "scan")
		writeGitHubActionsWorkflowForTest(t, root, "unsafe-sensitive-s3.yml", `on: pull_request_target
permissions: write-all
`)
		writeTerraformForTest(t, root, "infra/iam.tf", terraformOIDCSensitiveS3Role("deploy", "repo:owner/repo:pull_request", "artifacts", "assets", "read", "s3:GetObject", "arn:aws:s3:::assets/*"))
		baselineStdout, baselineStderr, baselineCode := runCommandInDir(t, parent, "scan", "--format=json", "--repo", "owner/repo", "scan")
		assertCode(t, baselineCode, 1)
		assertString(t, "baseline stderr", baselineStderr, "")
		finding := firstCLIFindingByRule(t, assertValidJSONReport(t, baselineStdout).Findings, "PP-XDOMAIN-004")
		writeFileForTest(t, parent, "pathproof.json", `{"suppressions":[{"finding_id":"`+finding.ID+`","reason":"Accepted sensitive S3 path"}]}`)

		stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--repo", "owner/repo", "--config", "pathproof.json", "scan")

		assertCode(t, code, 1)
		assertString(t, "stderr", stderr, "")
		assertNoRuleInJSONReport(t, stdout, "PP-XDOMAIN-004")
		if got := countCLIFindingsByRule(assertValidJSONReport(t, stdout).Findings, "PP-XDOMAIN-003"); got != 1 {
			t.Fatalf("PP-XDOMAIN-003 count = %d, want sibling still unsuppressed", got)
		}
		if strings.Contains(stdout, "Accepted sensitive S3 path") {
			t.Fatalf("stdout contains suppression reason: %s", stdout)
		}
	})

	t.Run("path exclusion", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "scan")
		writeGitHubActionsWorkflowForTest(t, root, "unsafe-sensitive-s3.yml", `on: pull_request_target
permissions: write-all
`)
		writeTerraformForTest(t, root, "infra/iam.tf", terraformOIDCSensitiveS3Role("deploy", "repo:owner/repo:pull_request", "artifacts", "assets", "read", "s3:GetObject", "arn:aws:s3:::assets/*"))
		writeFileForTest(t, parent, "pathproof.json", `{"path_exclusions":[".github/workflows/unsafe-sensitive-s3.yml"]}`)

		stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--repo", "owner/repo", "--config", "pathproof.json", "scan")

		assertCode(t, code, 0)
		assertString(t, "stderr", stderr, "")
		report := assertValidJSONReport(t, stdout)
		if report.FindingCount != 0 || len(report.Findings) != 0 {
			t.Fatalf("findings = %#v, want excluded PP-XDOMAIN-004 path", report.Findings)
		}
	})
}

func TestRunScanConfigDisableWinsOverEnable(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	writeFileForTest(t, parent, "pathproof.json", `{"rules":{"enable":["PP-GHA-001"],"disable":["PP-GHA-001"]}}`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--config", "pathproof.json", "scan")

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.FindingCount != 0 || len(report.Findings) != 0 {
		t.Fatalf("findings = %#v count=%d, want disabled conflict to emit none", report.Findings, report.FindingCount)
	}
	for _, ruleID := range report.DisabledRules {
		if ruleID == "PP-GHA-001" {
			return
		}
	}
	t.Fatalf("disabled_rules = %#v, want PP-GHA-001 included", report.DisabledRules)
}

func TestRunScanConfigUnknownRuleExitsTwoWithSanitizedError(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	writeFileForTest(t, parent, "pathproof.json", `{"rules":{"disable":["FAKE_CLI_CONFIG_RULE_SECRET_DO_NOT_RETAIN"]}}`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--config", "pathproof.json", "scan")

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "unknown rule ID")
	if strings.Contains(stderr, "FAKE_CLI_CONFIG_RULE_SECRET_DO_NOT_RETAIN") {
		t.Fatalf("stderr leaks secret-like config value: %s", stderr)
	}
}

func TestRunScanConfigLoadAndParseErrorsExitTwoWithEmptyStdout(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "scan")
		writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)

		stdout, stderr, code := runCommandInDir(t, parent, "scan", "--config", "missing.json", "scan")

		assertCode(t, code, 2)
		assertString(t, "stdout", stdout, "")
		assertOneLineStderr(t, stderr)
		assertContains(t, stderr, "read config file")
	})

	t.Run("malformed json", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "scan")
		writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
		content := `{"rules":{"disable":["FAKE_CLI_CONFIG_JSON_SECRET_DO_NOT_RETAIN"]}`
		writeFileForTest(t, parent, "pathproof.json", content)

		stdout, stderr, code := runCommandInDir(t, parent, "scan", "--config", "pathproof.json", "scan")

		assertCode(t, code, 2)
		assertString(t, "stdout", stdout, "")
		assertOneLineStderr(t, stderr)
		assertContains(t, stderr, "not valid JSON")
		if strings.Contains(stderr, content) || strings.Contains(stderr, "FAKE_CLI_CONFIG_JSON_SECRET_DO_NOT_RETAIN") {
			t.Fatalf("stderr leaks raw config content: %s", stderr)
		}
	})
}

func TestRunScanConfigSuppressesExactFindingID(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	baselineStdout, baselineStderr, baselineCode := runCommandInDir(t, parent, "scan", "--format=json", "scan")
	assertCode(t, baselineCode, 1)
	assertString(t, "baseline stderr", baselineStderr, "")
	baseline := assertValidJSONReport(t, baselineStdout)
	if baseline.FindingCount != 1 || len(baseline.Findings) != 1 {
		t.Fatalf("baseline findings = %#v", baseline.Findings)
	}
	writeFileForTest(t, parent, "pathproof.json", `{"suppressions":[{"finding_id":"`+baseline.Findings[0].ID+`","reason":"Accepted risk for fixture"}]}`)

	humanStdout, humanStderr, humanCode := runCommandInDir(t, parent, "scan", "--config", "pathproof.json", "scan")
	jsonStdout, jsonStderr, jsonCode := runCommandInDir(t, parent, "scan", "--format=json", "--config", "pathproof.json", "scan")

	assertCode(t, humanCode, 0)
	assertString(t, "human stderr", humanStderr, "")
	assertContains(t, humanStdout, "Finding count: 0\n")
	assertContains(t, humanStdout, "Suppressed findings: 1\n")
	if strings.Contains(humanStdout, "Accepted risk") || strings.Contains(humanStdout, "Rule: PP-GHA-001") {
		t.Fatalf("human output exposes suppression reason or finding: %s", humanStdout)
	}

	assertCode(t, jsonCode, 0)
	assertString(t, "json stderr", jsonStderr, "")
	report := assertValidJSONReport(t, jsonStdout)
	if report.FindingCount != 0 || len(report.Findings) != 0 || report.SuppressedFindingsCount == nil || *report.SuppressedFindingsCount != 1 {
		t.Fatalf("suppressed JSON report = %#v", report)
	}
	if strings.Contains(jsonStdout, "Accepted risk") {
		t.Fatalf("JSON output exposes suppression reason: %s", jsonStdout)
	}
}

func TestRunScanConfigStaleSuppressionDoesNotFail(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "safe.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
`)
	writeFileForTest(t, parent, "pathproof.json", `{"suppressions":[{"finding_id":"finding:PP-GHA-001:stale","reason":"Accepted stale baseline entry"}]}`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--config", "pathproof.json", "scan")

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.FindingCount != 0 || report.SuppressedFindingsCount == nil || *report.SuppressedFindingsCount != 0 {
		t.Fatalf("stale suppression report = %#v", report)
	}
}

func TestRunScanConfigSuppressesOneFindingButLeavesUnsuppressedFindings(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "unsafe.yml", `on: pull_request_target
permissions:
  contents: write
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`)
	baselineStdout, baselineStderr, baselineCode := runCommandInDir(t, parent, "scan", "--format=json", "scan")
	assertCode(t, baselineCode, 1)
	assertString(t, "baseline stderr", baselineStderr, "")
	baseline := assertValidJSONReport(t, baselineStdout)
	if baseline.FindingCount != 3 {
		t.Fatalf("baseline finding count = %d, want 3", baseline.FindingCount)
	}
	suppressed := firstCLIFindingByRule(t, baseline.Findings, "PP-GHA-001")
	writeFileForTest(t, parent, "pathproof.json", `{"suppressions":[{"finding_id":"`+suppressed.ID+`","reason":"Accepted risk for one action"}]}`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--config", "pathproof.json", "scan")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.FindingCount != 2 || len(report.Findings) != 2 || report.SuppressedFindingsCount == nil || *report.SuppressedFindingsCount != 1 {
		t.Fatalf("mixed suppression report = %#v", report)
	}
	assertNoRuleInJSONReport(t, stdout, "PP-GHA-001")
	if !jsonReportHasRule(report, "PP-GHA-002") || !jsonReportHasRule(report, "PP-GHA-003") {
		t.Fatalf("remaining findings = %#v, want PP-GHA-002 and PP-GHA-003", report.Findings)
	}
}

func TestRunScanConfigDoesNotChangeUnsuppressedFindingIDs(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	writeFileForTest(t, parent, "pathproof.json", `{}`)

	baselineStdout, baselineStderr, baselineCode := runCommandInDir(t, parent, "scan", "--format=json", "scan")
	configStdout, configStderr, configCode := runCommandInDir(t, parent, "scan", "--format=json", "--config", "pathproof.json", "scan")

	assertCode(t, baselineCode, 1)
	assertString(t, "baseline stderr", baselineStderr, "")
	assertCode(t, configCode, 1)
	assertString(t, "config stderr", configStderr, "")
	baseline := assertValidJSONReport(t, baselineStdout)
	configured := assertValidJSONReport(t, configStdout)
	if len(baseline.Findings) != len(configured.Findings) {
		t.Fatalf("finding lengths = %d/%d", len(baseline.Findings), len(configured.Findings))
	}
	for i := range baseline.Findings {
		if baseline.Findings[i].ID != configured.Findings[i].ID {
			t.Fatalf("finding ID changed at %d: %q -> %q", i, baseline.Findings[i].ID, configured.Findings[i].ID)
		}
	}
}

func TestRunScanWriteBaselineWritesConfigAndRoundTrips(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--write-baseline", "baseline.json", "scan")

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	assertString(t, "stdout", stdout, "Baseline written.\nSuppressions generated: 1\n")
	baseline := readGeneratedBaselineForTest(t, filepath.Join(parent, "baseline.json"))
	if len(baseline.Suppressions) != 1 {
		t.Fatalf("suppressions = %#v, want one", baseline.Suppressions)
	}
	if baseline.Suppressions[0].Reason != config.BaselineDefaultReason {
		t.Fatalf("reason = %q, want %q", baseline.Suppressions[0].Reason, config.BaselineDefaultReason)
	}
	if !strings.Contains(baseline.Suppressions[0].FindingID, "PP-GHA-001") {
		t.Fatalf("finding_id = %q, want PP-GHA-001", baseline.Suppressions[0].FindingID)
	}

	secondStdout, secondStderr, secondCode := runCommandInDir(t, parent, "scan", "--format=json", "--config", "baseline.json", "scan")
	assertCode(t, secondCode, 0)
	assertString(t, "second stderr", secondStderr, "")
	report := assertValidJSONReport(t, secondStdout)
	if report.FindingCount != 0 || report.SuppressedFindingsCount == nil || *report.SuppressedFindingsCount != 1 {
		t.Fatalf("round-trip report = %#v, want generated baseline to suppress finding", report)
	}
	if after, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "unpinned.yml")); err != nil || !strings.Contains(string(after), "actions/checkout@v4") {
		t.Fatalf("input workflow changed or could not be read: %v\n%s", err, after)
	}
}

func TestRunScanWriteBaselineIncludesCrossDomainSensitiveS3Finding(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "unsafe-sensitive-s3.yml", `on: pull_request_target
permissions: write-all
`)
	writeTerraformForTest(t, root, "infra/iam.tf", terraformOIDCSensitiveS3Role("deploy", "repo:owner/repo:pull_request", "artifacts", "assets", "read", "s3:GetObject", "arn:aws:s3:::assets/*"))

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--repo", "owner/repo", "--write-baseline", "baseline.json", "scan")

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Baseline written.")
	baseline := readGeneratedBaselineForTest(t, filepath.Join(parent, "baseline.json"))
	var hasSensitiveS3 bool
	for _, suppression := range baseline.Suppressions {
		if strings.Contains(suppression.FindingID, "PP-XDOMAIN-004") {
			hasSensitiveS3 = true
		}
		if strings.Contains(suppression.FindingID, "FAKE_CLI_XDOMAIN4_TAG_SECRET_DO_NOT_RETAIN") {
			t.Fatalf("baseline leaked tag secret: %#v", baseline.Suppressions)
		}
	}
	if !hasSensitiveS3 {
		t.Fatalf("baseline suppressions = %#v, want PP-XDOMAIN-004 finding ID", baseline.Suppressions)
	}

	secondStdout, secondStderr, secondCode := runCommandInDir(t, parent, "scan", "--format=json", "--repo", "owner/repo", "--config", "baseline.json", "scan")
	assertCode(t, secondCode, 0)
	assertString(t, "second stderr", secondStderr, "")
	assertNoRuleInJSONReport(t, secondStdout, "PP-XDOMAIN-004")
}

func TestRunScanWriteBaselineNoFindingsWritesEmptySuppressions(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "baseline.json")

	stdout, stderr, code := runCommand("scan", "--write-baseline", path, safeFixture)

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	assertString(t, "stdout", stdout, "Baseline written.\nSuppressions generated: 0\n")
	baseline := readGeneratedBaselineForTest(t, path)
	if len(baseline.Suppressions) != 0 {
		t.Fatalf("suppressions = %#v, want empty", baseline.Suppressions)
	}
}

func TestRunScanWriteBaselineAppliesConfigBeforeGeneratingSuppressions(t *testing.T) {
	t.Run("disabled rules", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "scan")
		writeSplitVulnerableFixture(t, root, []string{"service.yaml", "deployment.yaml", "secret.yaml", "rbac.yaml"})
		writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
		writeFileForTest(t, parent, "pathproof.json", `{"rules":{"disable":["PP-GHA-001"]}}`)

		stdout, stderr, code := runCommandInDir(t, parent, "scan", "--config", "pathproof.json", "--write-baseline", "baseline.json", "scan")

		assertCode(t, code, 0)
		assertString(t, "stderr", stderr, "")
		assertString(t, "stdout", stdout, "Baseline written.\nSuppressions generated: 1\n")
		baseline := readGeneratedBaselineForTest(t, filepath.Join(parent, "baseline.json"))
		if len(baseline.Suppressions) != 1 || !strings.Contains(baseline.Suppressions[0].FindingID, "PP-K8S-001") {
			t.Fatalf("baseline suppressions = %#v, want only PP-K8S-001", baseline.Suppressions)
		}
	})

	t.Run("path exclusions", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "scan")
		writeSplitVulnerableFixture(t, root, []string{"service.yaml", "deployment.yaml", "secret.yaml", "rbac.yaml"})
		writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
		writeFileForTest(t, parent, "pathproof.json", `{"path_exclusions":["rbac.yaml"]}`)

		stdout, stderr, code := runCommandInDir(t, parent, "scan", "--config", "pathproof.json", "--write-baseline", "baseline.json", "scan")

		assertCode(t, code, 0)
		assertString(t, "stderr", stderr, "")
		assertString(t, "stdout", stdout, "Baseline written.\nSuppressions generated: 1\n")
		baseline := readGeneratedBaselineForTest(t, filepath.Join(parent, "baseline.json"))
		if len(baseline.Suppressions) != 1 || !strings.Contains(baseline.Suppressions[0].FindingID, "PP-GHA-001") {
			t.Fatalf("baseline suppressions = %#v, want only PP-GHA-001", baseline.Suppressions)
		}
	})

	t.Run("existing suppressions and stale suppressions", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "scan")
		writeSplitVulnerableFixture(t, root, []string{"service.yaml", "deployment.yaml", "secret.yaml", "rbac.yaml"})
		writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
		initialStdout, initialStderr, initialCode := runCommandInDir(t, parent, "scan", "--format=json", "scan")
		assertCode(t, initialCode, 1)
		assertString(t, "initial stderr", initialStderr, "")
		suppressed := firstCLIFindingByRule(t, assertValidJSONReport(t, initialStdout).Findings, "PP-GHA-001")
		writeFileForTest(t, parent, "pathproof.json", `{"suppressions":[{"finding_id":"`+suppressed.ID+`","reason":"FAKE_BASELINE_INPUT_REASON_SECRET_DO_NOT_RETAIN"},{"finding_id":"finding:PP-GHA-001:stale","reason":"Accepted stale"}]}`)

		stdout, stderr, code := runCommandInDir(t, parent, "scan", "--config", "pathproof.json", "--write-baseline", "baseline.json", "scan")

		assertCode(t, code, 0)
		assertString(t, "stderr", stderr, "")
		assertString(t, "stdout", stdout, "Baseline written.\nSuppressions generated: 1\n")
		baselineContent, err := os.ReadFile(filepath.Join(parent, "baseline.json"))
		if err != nil {
			t.Fatalf("read baseline: %v", err)
		}
		baseline := readGeneratedBaselineForTest(t, filepath.Join(parent, "baseline.json"))
		if len(baseline.Suppressions) != 1 || !strings.Contains(baseline.Suppressions[0].FindingID, "PP-K8S-001") {
			t.Fatalf("baseline suppressions = %#v, want only unsuppressed PP-K8S-001", baseline.Suppressions)
		}
		for _, forbidden := range []string{string(suppressed.ID), "stale", "FAKE_BASELINE_INPUT_REASON_SECRET_DO_NOT_RETAIN", "Accepted stale"} {
			if strings.Contains(string(baselineContent), forbidden) || strings.Contains(stdout, forbidden) || strings.Contains(stderr, forbidden) {
				t.Fatalf("baseline mode copied suppressed/stale/config value %q\nstdout:%s\nstderr:%s\nbaseline:%s", forbidden, stdout, stderr, baselineContent)
			}
		}
	})
}

func TestRunScanWriteBaselineConfigErrorsDoNotWriteFile(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	writeFileForTest(t, parent, "pathproof.json", `{"rules":{"disable":["FAKE_BASELINE_CONFIG_SECRET_DO_NOT_RETAIN"]}}`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--config", "pathproof.json", "--write-baseline", "baseline.json", "scan")

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "unknown rule ID")
	if strings.Contains(stderr, "FAKE_BASELINE_CONFIG_SECRET_DO_NOT_RETAIN") {
		t.Fatalf("stderr leaks config value: %s", stderr)
	}
	if _, err := os.Stat(filepath.Join(parent, "baseline.json")); !os.IsNotExist(err) {
		t.Fatalf("baseline exists after config error or unexpected stat error: %v", err)
	}
}

func TestRunScanWriteBaselineRejectsExistingOutputWithEmptyStdout(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	writeFileForTest(t, parent, "baseline.json", `{}`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--write-baseline", "baseline.json", "scan")

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "already exists")
	if strings.Contains(stderr, parent) {
		t.Fatalf("stderr contains temp directory prefix: %s", stderr)
	}
}

func TestRunScanWriteBaselineWriteErrorHasEmptyStdoutAndNoPartialFile(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	original := writeBaselineConfig
	writeBaselineConfig = func(path string, findings []analysis.Finding) (int, error) {
		return 0, errors.New("write baseline output file")
	}
	defer func() {
		writeBaselineConfig = original
	}()

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--write-baseline", "baseline.json", "scan")

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "write baseline output file")
	if _, err := os.Stat(filepath.Join(parent, "baseline.json")); !os.IsNotExist(err) {
		t.Fatalf("baseline exists after write error or unexpected stat error: %v", err)
	}
}

func TestRunScanWriteBaselineJSONOutputMetadataAndNoRemediation(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	sha := strings.Repeat("a", 40)
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	writeFileForTest(t, parent, "pins.json", `{"actions/checkout@v4":"`+sha+`"}`)

	firstOut, firstErr, firstCode := runCommandInDir(t, parent, "scan", "--format=json", "--github-action-pins", "pins.json", "--write-baseline", "baseline-a.json", "scan")
	secondOut, secondErr, secondCode := runCommandInDir(t, parent, "scan", "--format=json", "--github-action-pins", "pins.json", "--write-baseline", "baseline-b.json", "scan")

	assertCode(t, firstCode, 0)
	assertCode(t, secondCode, 0)
	assertString(t, "first stderr", firstErr, "")
	assertString(t, "second stderr", secondErr, "")
	assertString(t, "deterministic JSON stdout", secondOut, firstOut)
	report := assertValidJSONReport(t, firstOut)
	if report.BaselineWritten == nil || report.BaselineWritten.SuppressionsGenerated != 1 {
		t.Fatalf("baseline_written = %#v, want one generated suppression", report.BaselineWritten)
	}
	if report.FindingCount != 1 || len(report.Findings) != 1 {
		t.Fatalf("report findings = %#v count=%d, want one current finding", report.Findings, report.FindingCount)
	}
	if report.Findings[0].Remediation != nil {
		t.Fatalf("baseline JSON finding has remediation: %#v", report.Findings[0].Remediation)
	}
	for _, forbidden := range []string{"baseline-a.json", "baseline-b.json", sha, "PinGitHubActionToSHA", "patch_previews", "patch_outputs", "validation", "diff"} {
		if strings.Contains(firstOut, forbidden) || strings.Contains(firstErr, forbidden) {
			t.Fatalf("baseline JSON output contains forbidden value %q\nstdout:%s\nstderr:%s", forbidden, firstOut, firstErr)
		}
	}
}

func TestRunScanWriteBaselineIgnoresInvalidGitHubActionPins(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	writeFileForTest(t, parent, "pins.json", `{"actions/checkout@v4":"FAKE_BASELINE_PIN_SECRET_DO_NOT_RETAIN"`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--github-action-pins", "pins.json", "--write-baseline", "baseline.json", "scan")

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	assertString(t, "stdout", stdout, "Baseline written.\nSuppressions generated: 1\n")
	content, err := os.ReadFile(filepath.Join(parent, "baseline.json"))
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	if strings.Contains(string(content), "FAKE_BASELINE_PIN_SECRET_DO_NOT_RETAIN") || strings.Contains(stdout, "FAKE_BASELINE_PIN_SECRET_DO_NOT_RETAIN") || strings.Contains(stderr, "FAKE_BASELINE_PIN_SECRET_DO_NOT_RETAIN") {
		t.Fatalf("baseline mode used or leaked invalid pin mapping\nstdout:%s\nstderr:%s\nbaseline:%s", stdout, stderr, content)
	}
}

func TestRunScanWriteBaselineSARIFOutputIsFindingsOnly(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=sarif", "--write-baseline", "baseline.json", "scan")

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	report := assertValidSARIFReport(t, stdout)
	if got := countSARIFResultsByRule(report, "PP-GHA-001"); got != 1 {
		t.Fatalf("PP-GHA-001 SARIF result count = %d, want 1", got)
	}
	if _, err := os.Stat(filepath.Join(parent, "baseline.json")); err != nil {
		t.Fatalf("baseline was not written: %v", err)
	}
	for _, forbidden := range []string{"baseline_written", "patch_outputs", "validation", "diff", "PinGitHubActionToSHA"} {
		if strings.Contains(stdout, forbidden) || strings.Contains(stderr, forbidden) {
			t.Fatalf("SARIF baseline output contains forbidden value %q\nstdout:%s\nstderr:%s", forbidden, stdout, stderr)
		}
	}
}

func TestRunScanWriteBaselineRejectsPatchAndValidationCombinations(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "preview patches",
			args: []string{"scan", "--write-baseline", "baseline.json", "--preview-patches", "scan"},
			want: "--write-baseline cannot be combined with --preview-patches",
		},
		{
			name: "write patches",
			args: []string{"scan", "--write-baseline", "baseline.json", "--write-patches", "patched", "scan"},
			want: "--write-baseline cannot be combined with --write-patches",
		},
		{
			name: "validate patches",
			args: []string{"scan", "--write-baseline", "baseline.json", "--validate-patches", "scan"},
			want: "--write-baseline cannot be combined with --validate-patches",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := t.TempDir()
			writeGitHubActionsWorkflowForTest(t, filepath.Join(parent, "scan"), "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)

			stdout, stderr, code := runCommandInDir(t, parent, tt.args...)

			assertCode(t, code, 2)
			assertString(t, "stdout", stdout, "")
			assertOneLineStderr(t, stderr)
			assertContains(t, stderr, tt.want)
			if _, err := os.Stat(filepath.Join(parent, "baseline.json")); !os.IsNotExist(err) {
				t.Fatalf("baseline exists after rejected flags or unexpected stat error: %v", err)
			}
			if _, err := os.Stat(filepath.Join(parent, "patched")); !os.IsNotExist(err) {
				t.Fatalf("patch output exists after rejected flags or unexpected stat error: %v", err)
			}
		})
	}
}

func TestRunScanWriteBaselineDoesNotLeakSecretLikeSourceOrConfigValues(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `name: Baseline
env:
  TOKEN: FAKE_BASELINE_WORKFLOW_ENV_SECRET_DO_NOT_RETAIN
jobs:
  test:
    steps:
      - run: echo FAKE_BASELINE_WORKFLOW_RUN_SECRET_DO_NOT_RETAIN
      - uses: actions/checkout@v4
        with:
          token: FAKE_BASELINE_WORKFLOW_WITH_SECRET_DO_NOT_RETAIN
`)
	writeFileForTest(t, parent, "pathproof.json", `{"suppressions":[{"finding_id":"finding:PP-GHA-001:stale","reason":"FAKE_BASELINE_CONFIG_REASON_SECRET_DO_NOT_RETAIN"}]}`)

	jsonStdout, jsonStderr, jsonCode := runCommandInDir(t, parent, "scan", "--format=json", "--config", "pathproof.json", "--write-baseline", "baseline.json", "scan")
	sarifStdout, sarifStderr, sarifCode := runCommandInDir(t, parent, "scan", "--format=sarif", "--config", "pathproof.json", "--write-baseline", "baseline-sarif.json", "scan")

	assertCode(t, jsonCode, 0)
	assertCode(t, sarifCode, 0)
	assertString(t, "json stderr", jsonStderr, "")
	assertString(t, "sarif stderr", sarifStderr, "")
	baselineContent, err := os.ReadFile(filepath.Join(parent, "baseline.json"))
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	for _, output := range []string{jsonStdout, jsonStderr, sarifStdout, sarifStderr, string(baselineContent)} {
		for _, forbidden := range []string{
			"FAKE_BASELINE_WORKFLOW_ENV_SECRET_DO_NOT_RETAIN",
			"FAKE_BASELINE_WORKFLOW_RUN_SECRET_DO_NOT_RETAIN",
			"FAKE_BASELINE_WORKFLOW_WITH_SECRET_DO_NOT_RETAIN",
			"FAKE_BASELINE_CONFIG_REASON_SECRET_DO_NOT_RETAIN",
			"env:",
			"run:",
			"with:",
			"token:",
		} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("baseline mode leaked forbidden value %q in output: %s", forbidden, output)
			}
		}
	}
}

func TestRunScanBaselineJSONComparisonDoesNotSuppressFindings(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	initialOut, initialErr, initialCode := runCommandInDir(t, parent, "scan", "--format=json", "scan")
	assertCode(t, initialCode, 1)
	assertString(t, "initial stderr", initialErr, "")
	finding := firstCLIFindingByRule(t, assertValidJSONReport(t, initialOut).Findings, "PP-GHA-001")

	staleID := testCLIBaselineFindingID("PP-GHA-001", "c")
	writeFileForTest(t, parent, "new-baseline.json", `{"suppressions":[{"finding_id":"`+staleID+`","reason":"FAKE_BASELINE_REASON_SECRET_DO_NOT_RETAIN"}]}`)
	newOut, newErr, newCode := runCommandInDir(t, parent, "scan", "--format=json", "--baseline", "new-baseline.json", "scan")

	assertCode(t, newCode, 1)
	assertString(t, "new stderr", newErr, "")
	newReport := assertValidJSONReport(t, newOut)
	if newReport.BaselineComparison == nil {
		t.Fatalf("baseline_comparison = nil")
	}
	if newReport.BaselineComparison.NewFindingsCount != 1 || newReport.BaselineComparison.ExistingFindingsCount != 0 || newReport.BaselineComparison.ResolvedFindingsCount != 1 {
		t.Fatalf("new baseline comparison = %#v, want one new and one resolved", newReport.BaselineComparison)
	}
	if len(newReport.Findings) != 1 || newReport.Findings[0].BaselineStatus != "new" {
		t.Fatalf("finding baseline status = %#v, want new", newReport.Findings)
	}
	if strings.Contains(newOut, "FAKE_BASELINE_REASON_SECRET_DO_NOT_RETAIN") || strings.Contains(newErr, "FAKE_BASELINE_REASON_SECRET_DO_NOT_RETAIN") {
		t.Fatalf("baseline reason leaked\nstdout:%s\nstderr:%s", newOut, newErr)
	}

	writeFileForTest(t, parent, "existing-baseline.json", `{"suppressions":[{"finding_id":"`+finding.ID+`","reason":"Accepted"},{"finding_id":"`+staleID+`","reason":"Accepted stale"}]}`)
	existingOut, existingErr, existingCode := runCommandInDir(t, parent, "scan", "--format=json", "--baseline", "existing-baseline.json", "scan")

	assertCode(t, existingCode, 1)
	assertString(t, "existing stderr", existingErr, "")
	existingReport := assertValidJSONReport(t, existingOut)
	if existingReport.BaselineComparison == nil {
		t.Fatalf("baseline_comparison = nil")
	}
	if existingReport.BaselineComparison.NewFindingsCount != 0 || existingReport.BaselineComparison.ExistingFindingsCount != 1 || existingReport.BaselineComparison.ResolvedFindingsCount != 1 {
		t.Fatalf("existing baseline comparison = %#v, want one existing and one resolved", existingReport.BaselineComparison)
	}
	wantResolved := []string{staleID}
	if !reflect.DeepEqual(existingReport.BaselineComparison.ResolvedFindingIDs, wantResolved) {
		t.Fatalf("resolved IDs = %#v, want %#v", existingReport.BaselineComparison.ResolvedFindingIDs, wantResolved)
	}
	if len(existingReport.Findings) != 1 || existingReport.Findings[0].BaselineStatus != "existing" {
		t.Fatalf("finding baseline status = %#v, want existing", existingReport.Findings)
	}
}

func TestRunScanBaselineHumanSummaryIsDeterministicAndSanitized(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	initialOut, initialErr, initialCode := runCommandInDir(t, parent, "scan", "--format=json", "scan")
	assertCode(t, initialCode, 1)
	assertString(t, "initial stderr", initialErr, "")
	finding := firstCLIFindingByRule(t, assertValidJSONReport(t, initialOut).Findings, "PP-GHA-001")
	staleID := testCLIBaselineFindingID("PP-GHA-001", "c")
	writeFileForTest(t, parent, "baseline.json", `{"suppressions":[{"finding_id":"`+finding.ID+`","reason":"FAKE_BASELINE_HUMAN_REASON_SECRET_DO_NOT_RETAIN"},{"finding_id":"`+staleID+`","reason":"Accepted stale"}]}`)

	firstOut, firstErr, firstCode := runCommandInDir(t, parent, "scan", "--baseline", "baseline.json", "scan")
	secondOut, secondErr, secondCode := runCommandInDir(t, parent, "scan", "--baseline", "baseline.json", "scan")

	assertCode(t, firstCode, 1)
	assertCode(t, secondCode, 1)
	assertString(t, "first stderr", firstErr, "")
	assertString(t, "second stderr", secondErr, "")
	assertString(t, "deterministic human baseline output", secondOut, firstOut)
	assertContains(t, firstOut, "Finding count: 1\n")
	assertContains(t, firstOut, "Baseline comparison:\n")
	assertContains(t, firstOut, "New findings: 0\n")
	assertContains(t, firstOut, "Existing findings: 1\n")
	assertContains(t, firstOut, "Resolved findings: 1\n")
	assertContains(t, firstOut, "Resolved finding IDs:\n  - "+staleID+"\n")
	assertContains(t, firstOut, "Baseline status: existing\n")
	if strings.Contains(firstOut, "FAKE_BASELINE_HUMAN_REASON_SECRET_DO_NOT_RETAIN") || strings.Contains(firstErr, "FAKE_BASELINE_HUMAN_REASON_SECRET_DO_NOT_RETAIN") {
		t.Fatalf("human baseline output leaked reason\nstdout:%s\nstderr:%s", firstOut, firstErr)
	}
}

func TestRunScanBaselineWithConfigSuppressionComparesBeforeSuppressing(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	initialOut, initialErr, initialCode := runCommandInDir(t, parent, "scan", "--format=json", "scan")
	assertCode(t, initialCode, 1)
	assertString(t, "initial stderr", initialErr, "")
	finding := firstCLIFindingByRule(t, assertValidJSONReport(t, initialOut).Findings, "PP-GHA-001")
	writeFileForTest(t, parent, "baseline.json", `{"suppressions":[{"finding_id":"`+finding.ID+`","reason":"Accepted baseline"}]}`)
	writeFileForTest(t, parent, "pathproof.json", `{"suppressions":[{"finding_id":"`+finding.ID+`","reason":"FAKE_BASELINE_CONFIG_SUPPRESSION_REASON_SECRET_DO_NOT_RETAIN"}]}`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--config", "pathproof.json", "--baseline", "baseline.json", "scan")

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.FindingCount != 0 || len(report.Findings) != 0 {
		t.Fatalf("findings = %#v count=%d, want suppressed output", report.Findings, report.FindingCount)
	}
	if report.SuppressedFindingsCount == nil || *report.SuppressedFindingsCount != 1 {
		t.Fatalf("suppressed count = %#v, want 1", report.SuppressedFindingsCount)
	}
	if report.BaselineComparison == nil || report.BaselineComparison.NewFindingsCount != 0 || report.BaselineComparison.ExistingFindingsCount != 1 || report.BaselineComparison.ResolvedFindingsCount != 0 {
		t.Fatalf("baseline comparison = %#v, want one existing before suppression", report.BaselineComparison)
	}
	if strings.Contains(stdout, string(finding.ID)) || strings.Contains(stdout, "FAKE_BASELINE_CONFIG_SUPPRESSION_REASON_SECRET_DO_NOT_RETAIN") {
		t.Fatalf("suppressed finding ID or reason leaked in JSON: %s", stdout)
	}
}

func TestRunScanBaselineComparisonUsesActiveRuleAndPathScope(t *testing.T) {
	t.Run("disabled rule", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "scan")
		writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
		initialOut, initialErr, initialCode := runCommandInDir(t, parent, "scan", "--format=json", "scan")
		assertCode(t, initialCode, 1)
		assertString(t, "initial stderr", initialErr, "")
		finding := firstCLIFindingByRule(t, assertValidJSONReport(t, initialOut).Findings, "PP-GHA-001")
		writeFileForTest(t, parent, "baseline.json", `{"suppressions":[{"finding_id":"`+finding.ID+`","reason":"Accepted"}]}`)
		writeFileForTest(t, parent, "pathproof.json", `{"rules":{"disable":["PP-GHA-001"]}}`)

		stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--config", "pathproof.json", "--baseline", "baseline.json", "scan")

		assertCode(t, code, 0)
		assertString(t, "stderr", stderr, "")
		report := assertValidJSONReport(t, stdout)
		if report.BaselineComparison == nil || report.BaselineComparison.NewFindingsCount != 0 || report.BaselineComparison.ExistingFindingsCount != 0 || report.BaselineComparison.ResolvedFindingsCount != 1 {
			t.Fatalf("baseline comparison = %#v, want disabled finding resolved in active scope", report.BaselineComparison)
		}
	})

	t.Run("path excluded", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "scan")
		writeGitHubActionsWorkflowForTest(t, root, "ignored.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
		initialOut, initialErr, initialCode := runCommandInDir(t, parent, "scan", "--format=json", "scan")
		assertCode(t, initialCode, 1)
		assertString(t, "initial stderr", initialErr, "")
		finding := firstCLIFindingByRule(t, assertValidJSONReport(t, initialOut).Findings, "PP-GHA-001")
		writeFileForTest(t, parent, "baseline.json", `{"suppressions":[{"finding_id":"`+finding.ID+`","reason":"Accepted"}]}`)
		writeFileForTest(t, parent, "pathproof.json", `{"path_exclusions":[".github/workflows/ignored.yml"]}`)

		stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--config", "pathproof.json", "--baseline", "baseline.json", "scan")

		assertCode(t, code, 0)
		assertString(t, "stderr", stderr, "")
		report := assertValidJSONReport(t, stdout)
		if report.BaselineComparison == nil || report.BaselineComparison.NewFindingsCount != 0 || report.BaselineComparison.ExistingFindingsCount != 0 || report.BaselineComparison.ResolvedFindingsCount != 1 {
			t.Fatalf("baseline comparison = %#v, want excluded finding resolved in active scope", report.BaselineComparison)
		}
		if strings.Contains(stdout, "ignored.yml") {
			t.Fatalf("JSON output contains excluded source: %s", stdout)
		}
	})
}

func TestRunScanBaselineRejectsInvalidInputsAndWriteBaselineCombination(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	writeFileForTest(t, parent, "malformed.json", `{"suppressions":[{"finding_id":"finding:PP-GHA-001:abc","reason":"FAKE_BASELINE_CLI_PARSE_SECRET_DO_NOT_RETAIN"}`)
	writeFileForTest(t, parent, "non-object.json", `["FAKE_BASELINE_CLI_ARRAY_SECRET_DO_NOT_RETAIN"]`)
	writeFileForTest(t, parent, "unsafe-id.json", `{"suppressions":[{"finding_id":"finding:PP-GHA-001:/tmp/FAKE_BASELINE_CLI_ID_SECRET_DO_NOT_RETAIN","reason":"Accepted"}]}`)

	tests := []struct {
		name      string
		args      []string
		want      string
		forbidden []string
	}{
		{name: "missing", args: []string{"scan", "--baseline", "missing.json", "scan"}, want: "read baseline file", forbidden: []string{"missing.json", parent}},
		{name: "directory", args: []string{"scan", "--baseline", ".", "scan"}, want: "path is a directory", forbidden: []string{parent}},
		{name: "malformed", args: []string{"scan", "--baseline", "malformed.json", "scan"}, want: "not valid JSON", forbidden: []string{"FAKE_BASELINE_CLI_PARSE_SECRET_DO_NOT_RETAIN"}},
		{name: "non object", args: []string{"scan", "--baseline", "non-object.json", "scan"}, want: "must be a JSON object", forbidden: []string{"FAKE_BASELINE_CLI_ARRAY_SECRET_DO_NOT_RETAIN"}},
		{name: "unsafe id", args: []string{"scan", "--baseline", "unsafe-id.json", "scan"}, want: "unsupported format", forbidden: []string{"FAKE_BASELINE_CLI_ID_SECRET_DO_NOT_RETAIN", "/tmp/", parent}},
		{name: "write baseline", args: []string{"scan", "--baseline", "missing.json", "--write-baseline", "out.json", "scan"}, want: "--baseline cannot be combined with --write-baseline"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, code := runCommandInDir(t, parent, tt.args...)

			assertCode(t, code, 2)
			assertString(t, "stdout", stdout, "")
			assertOneLineStderr(t, stderr)
			assertContains(t, stderr, tt.want)
			for _, forbidden := range tt.forbidden {
				if strings.Contains(stderr, forbidden) {
					t.Fatalf("stderr contains forbidden value %q: %s", forbidden, stderr)
				}
			}
			if _, err := os.Stat(filepath.Join(parent, "out.json")); !os.IsNotExist(err) {
				t.Fatalf("baseline output exists after rejected comparison/write combination or unexpected stat error: %v", err)
			}
		})
	}
}

func TestRunScanBaselineDoesNotChangeRemediationPatchOrValidation(t *testing.T) {
	t.Run("kubernetes", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "scan")
		writeSplitVulnerableFixture(t, root, []string{"service.yaml", "deployment.yaml", "secret.yaml", "rbac.yaml"})
		initialOut, initialErr, initialCode := runCommandInDir(t, parent, "scan", "--format=json", "scan")
		assertCode(t, initialCode, 1)
		assertString(t, "initial stderr", initialErr, "")
		finding := firstCLIFindingByRule(t, assertValidJSONReport(t, initialOut).Findings, "PP-K8S-001")
		writeFileForTest(t, parent, "baseline.json", `{"suppressions":[{"finding_id":"`+finding.ID+`","reason":"Accepted"},{"finding_id":"`+testCLIBaselineFindingID("PP-K8S-001", "c")+`","reason":"Accepted stale"}]}`)

		stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--baseline", "baseline.json", "--preview-patches", "--write-patches", "patched", "--validate-patches", "scan")

		assertCode(t, code, 1)
		assertString(t, "stderr", stderr, "")
		report := assertValidJSONReport(t, stdout)
		gotFinding := firstCLIFindingByRule(t, report.Findings, "PP-K8S-001")
		if gotFinding.BaselineStatus != "existing" || gotFinding.Remediation == nil {
			t.Fatalf("finding = %#v, want existing with remediation", gotFinding)
		}
		if report.PatchOutputs == nil || len(*report.PatchOutputs) == 0 {
			t.Fatalf("patch_outputs = %#v, want baseline to preserve patch output", report.PatchOutputs)
		}
		if len(report.Validation) != 1 || report.Validation[0].FindingID != finding.ID {
			t.Fatalf("validation = %#v, want only current finding validation", report.Validation)
		}
	})

	t.Run("github actions", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "scan")
		sha := strings.Repeat("a", 40)
		writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
		writeFileForTest(t, parent, "pins.json", `{"actions/checkout@v4":"`+sha+`"}`)
		initialOut, initialErr, initialCode := runCommandInDir(t, parent, "scan", "--format=json", "scan")
		assertCode(t, initialCode, 1)
		assertString(t, "initial stderr", initialErr, "")
		finding := firstCLIFindingByRule(t, assertValidJSONReport(t, initialOut).Findings, "PP-GHA-001")
		writeFileForTest(t, parent, "baseline.json", `{"suppressions":[{"finding_id":"`+finding.ID+`","reason":"Accepted"},{"finding_id":"`+testCLIBaselineFindingID("PP-GHA-001", "c")+`","reason":"Accepted stale"}]}`)

		stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--baseline", "baseline.json", "--github-action-pins", "pins.json", "--preview-patches", "--write-patches", "patched", "scan")

		assertCode(t, code, 1)
		assertString(t, "stderr", stderr, "")
		report := assertValidJSONReport(t, stdout)
		gotFinding := firstCLIFindingByRule(t, report.Findings, "PP-GHA-001")
		if gotFinding.BaselineStatus != "existing" || gotFinding.Remediation == nil {
			t.Fatalf("finding = %#v, want existing with remediation", gotFinding)
		}
		if report.PatchOutputs == nil || len(*report.PatchOutputs) == 0 {
			t.Fatalf("patch_outputs = %#v, want baseline to preserve GitHub Actions patch output", report.PatchOutputs)
		}
		if len(report.Validation) != 0 {
			t.Fatalf("validation = %#v, want no PP-GHA-001 validation", report.Validation)
		}
	})
}

func TestRunScanConfigPathExclusionsExcludeOnlyFinding(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "ignored.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	writeFileForTest(t, parent, "pathproof.json", `{"path_exclusions":[".github/workflows/ignored.yml"]}`)

	humanStdout, humanStderr, humanCode := runCommandInDir(t, parent, "scan", "--config", "pathproof.json", "scan")
	jsonStdout, jsonStderr, jsonCode := runCommandInDir(t, parent, "scan", "--format=json", "--config", "pathproof.json", "scan")

	assertCode(t, humanCode, 0)
	assertString(t, "human stderr", humanStderr, "")
	assertString(t, "human stdout", humanStdout, "Finding count: 0\nNo findings.\n")
	assertCode(t, jsonCode, 0)
	assertString(t, "json stderr", jsonStderr, "")
	report := assertValidJSONReport(t, jsonStdout)
	if !report.ConfigApplied || report.FindingCount != 0 || len(report.Findings) != 0 {
		t.Fatalf("JSON report = %#v, want config metadata with no findings", report)
	}
	for _, output := range []string{humanStdout, jsonStdout} {
		if strings.Contains(output, "ignored.yml") || strings.Contains(output, "path_exclusions") {
			t.Fatalf("output lists excluded file or config field: %s", output)
		}
	}
}

func TestRunScanConfigPathExclusionsExcludeOneFindingWhileAnotherRemains(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeSplitVulnerableFixture(t, root, []string{"service.yaml", "deployment.yaml", "secret.yaml", "rbac.yaml"})
	writeGitHubActionsWorkflowForTest(t, root, "ignored.yml", `jobs:
  test:
    steps:
      - uses: docker/login-action@v3
`)
	writeFileForTest(t, parent, "pathproof.json", `{"path_exclusions":[".github/workflows/ignored.yml"]}`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--config", "pathproof.json", "scan")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.FindingCount != 1 || len(report.Findings) != 1 || report.Findings[0].RuleID != "PP-K8S-001" {
		t.Fatalf("findings = %#v count=%d, want only PP-K8S-001", report.Findings, report.FindingCount)
	}
	assertNoRuleInJSONReport(t, stdout, "PP-GHA-001")
	if strings.Contains(stdout, "ignored.yml") {
		t.Fatalf("JSON output contains excluded workflow: %s", stdout)
	}
}

func TestRunScanConfigPathExclusionsMalformedConfigIsSanitized(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	writeFileForTest(t, parent, "pathproof.json", `{"path_exclusions":["../FAKE_CONFIG_EXCLUSION_SECRET_DO_NOT_RETAIN.yml"]}`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--config", "pathproof.json", "scan")

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "path_exclusions[0]")
	assertContains(t, stderr, "scan root")
	if strings.Contains(stderr, "FAKE_CONFIG_EXCLUSION_SECRET_DO_NOT_RETAIN") || strings.Contains(stderr, "../") {
		t.Fatalf("stderr leaks raw exclusion value: %s", stderr)
	}
}

func TestRunScanConfigPathExclusionsExcludedMalformedSourcesDoNotErrorOrLeak(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "bad.yml", `name: bad
env:
  TOKEN: FAKE_EXCLUDED_WORKFLOW_SECRET_DO_NOT_RETAIN
jobs: [
`)
	writeTerraformForTest(t, root, "bad.tf", `resource "aws_iam_role" "bad" {
  assume_role_policy = <<EOF
  FAKE_EXCLUDED_TERRAFORM_SECRET_DO_NOT_RETAIN
`)
	writeFileForTest(t, root, "bad.yaml", `apiVersion: v1
kind: Service
metadata: [
`)
	writeFileForTest(t, parent, "pathproof.json", `{"path_exclusions":[".github/workflows/bad.yml","bad.tf","bad.yaml"]}`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--config", "pathproof.json", "scan")

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	assertString(t, "stdout", stdout, "Finding count: 0\nNo findings.\n")
	for _, forbidden := range []string{"FAKE_EXCLUDED_WORKFLOW_SECRET_DO_NOT_RETAIN", "FAKE_EXCLUDED_TERRAFORM_SECRET_DO_NOT_RETAIN", "metadata: [", "jobs: [", "assume_role_policy"} {
		if strings.Contains(stdout, forbidden) || strings.Contains(stderr, forbidden) {
			t.Fatalf("output leaks excluded source value %q\nstdout:%s\nstderr:%s", forbidden, stdout, stderr)
		}
	}
}

func TestRunScanConfigPathExclusionsWorkWithRuleControlsAndSuppressions(t *testing.T) {
	t.Run("rule controls", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "scan")
		writeSplitVulnerableFixture(t, root, []string{"service.yaml", "deployment.yaml", "secret.yaml", "rbac.yaml"})
		writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
		writeFileForTest(t, parent, "pathproof.json", `{"path_exclusions":["rbac.yaml"],"rules":{"disable":["PP-GHA-001"]}}`)

		stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--config", "pathproof.json", "scan")

		assertCode(t, code, 0)
		assertString(t, "stderr", stderr, "")
		report := assertValidJSONReport(t, stdout)
		if report.FindingCount != 0 || len(report.Findings) != 0 {
			t.Fatalf("findings = %#v count=%d, want none", report.Findings, report.FindingCount)
		}
	})

	t.Run("suppression", func(t *testing.T) {
		parent := t.TempDir()
		root := filepath.Join(parent, "scan")
		writeSplitVulnerableFixture(t, root, []string{"service.yaml", "deployment.yaml", "secret.yaml", "rbac.yaml"})
		writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
		baselineStdout, baselineStderr, baselineCode := runCommandInDir(t, parent, "scan", "--format=json", "scan")
		assertCode(t, baselineCode, 1)
		assertString(t, "baseline stderr", baselineStderr, "")
		finding := firstCLIFindingByRule(t, assertValidJSONReport(t, baselineStdout).Findings, "PP-GHA-001")
		writeFileForTest(t, parent, "pathproof.json", `{"path_exclusions":["rbac.yaml"],"suppressions":[{"finding_id":"`+finding.ID+`","reason":"Accepted risk for fixture"}]}`)

		stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--config", "pathproof.json", "scan")

		assertCode(t, code, 0)
		assertString(t, "stderr", stderr, "")
		report := assertValidJSONReport(t, stdout)
		if report.FindingCount != 0 || report.SuppressedFindingsCount == nil || *report.SuppressedFindingsCount != 1 {
			t.Fatalf("report = %#v, want excluded K8S and one suppressed GHA finding", report)
		}
		if strings.Contains(stdout, "Accepted risk") || strings.Contains(stdout, "rbac.yaml") {
			t.Fatalf("JSON output exposes suppression reason or excluded file: %s", stdout)
		}
	})
}

func TestRunScanGitHubActionsPatchFlagsDoNotPatchOrValidateFinding(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir scan root: %v", err)
	}
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: owner/repo@main
`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--write-patches", "patched", "--validate-patches", "scan")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Rule: PP-GHA-001\n")
	assertContains(t, stdout, "Remediation:")
	assertContains(t, stdout, "Patch Output:")
	assertContains(t, stdout, "Written files: 0")
	if strings.Contains(stdout, "Patch Preview:") || strings.Contains(stdout, "Validation:") {
		t.Fatalf("PP-GHA-001 received unsupported preview or validation output: %s", stdout)
	}
	if _, err := os.Stat(filepath.Join(parent, "patched")); !os.IsNotExist(err) {
		t.Fatalf("patched output directory exists or stat failed unexpectedly: %v", err)
	}
}

func TestRunScanConfigDisabledAndSuppressedKubernetesFindingsDoNotPatchOrValidate(t *testing.T) {
	tests := []struct {
		name          string
		configContent func(t *testing.T, parent string) string
	}{
		{
			name: "disabled",
			configContent: func(t *testing.T, parent string) string {
				return `{"rules":{"disable":["PP-K8S-001"]}}`
			},
		},
		{
			name: "suppressed",
			configContent: func(t *testing.T, parent string) string {
				baselineStdout, baselineStderr, baselineCode := runCommandInDir(t, parent, "scan", "--format=json", "scan")
				assertCode(t, baselineCode, 1)
				assertString(t, "baseline stderr", baselineStderr, "")
				finding := firstCLIFindingByRule(t, assertValidJSONReport(t, baselineStdout).Findings, "PP-K8S-001")
				return `{"suppressions":[{"finding_id":"` + finding.ID + `","reason":"Accepted risk for fixture"}]}`
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "scan")
			writeSplitVulnerableFixture(t, root, []string{"service.yaml", "deployment.yaml", "secret.yaml", "rbac.yaml"})
			writeFileForTest(t, parent, "pathproof.json", tt.configContent(t, parent))

			stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--config", "pathproof.json", "--preview-patches", "--write-patches", "patched", "--validate-patches", "scan")

			assertCode(t, code, 0)
			assertString(t, "stderr", stderr, "")
			report := assertValidJSONReport(t, stdout)
			if report.FindingCount != 0 || len(report.Findings) != 0 {
				t.Fatalf("findings = %#v count=%d, want none", report.Findings, report.FindingCount)
			}
			if report.PatchOutputs == nil || len(*report.PatchOutputs) != 0 {
				t.Fatalf("patch_outputs = %#v, want empty output list", report.PatchOutputs)
			}
			if len(report.Validation) != 0 {
				t.Fatalf("validation = %#v, want none", report.Validation)
			}
			if strings.Contains(stdout, "remediation") || strings.Contains(stdout, "patch_previews") || strings.Contains(stdout, "diff") {
				t.Fatalf("JSON output contains remediation or patch data: %s", stdout)
			}
			if _, err := os.Stat(filepath.Join(parent, "patched")); !os.IsNotExist(err) {
				t.Fatalf("patched output directory exists or stat failed unexpectedly: %v", err)
			}
		})
	}
}

func TestRunScanConfigDisabledAndSuppressedGitHubActionsFindingsDoNotPatch(t *testing.T) {
	tests := []struct {
		name          string
		configContent func(t *testing.T, parent string) string
	}{
		{
			name: "disabled",
			configContent: func(t *testing.T, parent string) string {
				return `{"rules":{"disable":["PP-GHA-001"]}}`
			},
		},
		{
			name: "suppressed",
			configContent: func(t *testing.T, parent string) string {
				baselineStdout, baselineStderr, baselineCode := runCommandInDir(t, parent, "scan", "--format=json", "scan")
				assertCode(t, baselineCode, 1)
				assertString(t, "baseline stderr", baselineStderr, "")
				finding := firstCLIFindingByRule(t, assertValidJSONReport(t, baselineStdout).Findings, "PP-GHA-001")
				return `{"suppressions":[{"finding_id":"` + finding.ID + `","reason":"Accepted risk for fixture"}]}`
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "scan")
			sha := strings.Repeat("a", 40)
			writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
			writeFileForTest(t, parent, "pins.json", `{"actions/checkout@v4":"`+sha+`"}`)
			writeFileForTest(t, parent, "pathproof.json", tt.configContent(t, parent))

			stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--config", "pathproof.json", "--github-action-pins", "pins.json", "--preview-patches", "--write-patches", "patched", "scan")

			assertCode(t, code, 0)
			assertString(t, "stderr", stderr, "")
			report := assertValidJSONReport(t, stdout)
			if report.FindingCount != 0 || len(report.Findings) != 0 {
				t.Fatalf("findings = %#v count=%d, want none", report.Findings, report.FindingCount)
			}
			if report.PatchOutputs == nil || len(*report.PatchOutputs) != 0 {
				t.Fatalf("patch_outputs = %#v, want empty output list", report.PatchOutputs)
			}
			if strings.Contains(stdout, "PinGitHubActionToSHA") || strings.Contains(stdout, sha) || strings.Contains(stdout, "patch_previews") {
				t.Fatalf("JSON output contains GitHub Actions remediation or patch data: %s", stdout)
			}
			if _, err := os.Stat(filepath.Join(parent, "patched")); !os.IsNotExist(err) {
				t.Fatalf("patched output directory exists or stat failed unexpectedly: %v", err)
			}
		})
	}
}

func TestRunScanConfigPathExcludedKubernetesFindingDoesNotPatchOrValidate(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeSplitVulnerableFixture(t, root, []string{"service.yaml", "deployment.yaml", "secret.yaml", "rbac.yaml"})
	writeFileForTest(t, parent, "pathproof.json", `{"path_exclusions":["rbac.yaml"]}`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--config", "pathproof.json", "--preview-patches", "--write-patches", "patched", "--validate-patches", "scan")

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.FindingCount != 0 || len(report.Findings) != 0 {
		t.Fatalf("findings = %#v count=%d, want none", report.Findings, report.FindingCount)
	}
	if report.PatchOutputs == nil || len(*report.PatchOutputs) != 0 {
		t.Fatalf("patch_outputs = %#v, want empty output list", report.PatchOutputs)
	}
	if len(report.Validation) != 0 {
		t.Fatalf("validation = %#v, want none", report.Validation)
	}
	if strings.Contains(stdout, "remediation") || strings.Contains(stdout, "patch_previews") || strings.Contains(stdout, "diff") || strings.Contains(stdout, "rbac.yaml") {
		t.Fatalf("JSON output contains remediation, patch data, or excluded file: %s", stdout)
	}
	if _, err := os.Stat(filepath.Join(parent, "patched")); !os.IsNotExist(err) {
		t.Fatalf("patched output directory exists or stat failed unexpectedly: %v", err)
	}
}

func TestRunScanConfigPathExcludedGitHubActionsFindingDoesNotPatch(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	sha := strings.Repeat("a", 40)
	writeGitHubActionsWorkflowForTest(t, root, "ignored.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	writeFileForTest(t, parent, "pins.json", `{"actions/checkout@v4":"`+sha+`"}`)
	writeFileForTest(t, parent, "pathproof.json", `{"path_exclusions":[".github/workflows/ignored.yml"]}`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--config", "pathproof.json", "--github-action-pins", "pins.json", "--preview-patches", "--write-patches", "patched", "scan")

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.FindingCount != 0 || len(report.Findings) != 0 {
		t.Fatalf("findings = %#v count=%d, want none", report.Findings, report.FindingCount)
	}
	if report.PatchOutputs == nil || len(*report.PatchOutputs) != 0 {
		t.Fatalf("patch_outputs = %#v, want empty output list", report.PatchOutputs)
	}
	if strings.Contains(stdout, "PinGitHubActionToSHA") || strings.Contains(stdout, sha) || strings.Contains(stdout, "ignored.yml") || strings.Contains(stdout, "patch_previews") {
		t.Fatalf("JSON output contains GitHub Actions remediation, patch data, or excluded file: %s", stdout)
	}
	if _, err := os.Stat(filepath.Join(parent, "patched")); !os.IsNotExist(err) {
		t.Fatalf("patched output directory exists or stat failed unexpectedly: %v", err)
	}
}

func TestRunScanConfigPathExclusionsValidationDoesNotReintroduceExcludedMalformedFiles(t *testing.T) {
	parent := t.TempDir()
	writeSplitPreviewFixture(t, parent, "scan")
	root := filepath.Join(parent, "scan")
	writeFileForTest(t, root, "ignored-bad.yaml", `apiVersion: v1
kind: Service
metadata: [
`)
	writeFileForTest(t, parent, "pathproof.json", `{"path_exclusions":["ignored-bad.yaml"]}`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--config", "pathproof.json", "--write-patches", "patched", "--validate-patches", "scan")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if len(report.Validation) != 1 || report.Validation[0].RuleID != "PP-K8S-001" || report.Validation[0].Status != "remediated" {
		t.Fatalf("validation = %#v, want remediated PP-K8S-001 without excluded parse error", report.Validation)
	}
	if strings.Contains(stdout, "ignored-bad.yaml") || strings.Contains(stderr, "ignored-bad.yaml") || strings.Contains(stderr, "invalid YAML") {
		t.Fatalf("output contains excluded malformed source or parse error\nstdout:%s\nstderr:%s", stdout, stderr)
	}
}

func TestRunScanGitHubActionsPreviewPatchesWithLocalPinMapping(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	sha := strings.Repeat("a", 40)
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	writeFileForTest(t, parent, "pins.json", `{"actions/checkout@v4":"`+sha+`"}`)

	firstOut, firstErr, firstCode := runCommandInDir(t, parent, "scan", "--github-action-pins", "pins.json", "--preview-patches", "scan")
	secondOut, secondErr, secondCode := runCommandInDir(t, parent, "scan", "--github-action-pins", "pins.json", "--preview-patches", "scan")

	assertCode(t, firstCode, 1)
	assertCode(t, secondCode, 1)
	assertString(t, "first stderr", firstErr, "")
	assertString(t, "second stderr", secondErr, "")
	assertString(t, "stdout", secondOut, firstOut)
	assertContains(t, firstOut, "PinGitHubActionToSHA")
	assertContains(t, firstOut, "Patch Preview:")
	assertContains(t, firstOut, "-      - uses: actions/checkout@v4\n")
	assertContains(t, firstOut, "+      - uses: actions/checkout@"+sha+"\n")
	if strings.Contains(firstOut, " jobs:") || strings.Contains(firstOut, " test:") {
		t.Fatalf("GitHub Actions patch preview leaked surrounding workflow context: %s", firstOut)
	}
}

func TestRunScanGitHubActionsPatchesQuotedActionRefsWithLocalPinMapping(t *testing.T) {
	tests := []struct {
		name      string
		quote     string
		padding   string
		outputDir string
	}{
		{name: "double quoted", quote: `"`, outputDir: "patched-double"},
		{name: "single quoted", quote: `'`, outputDir: "patched-single"},
		{name: "double quoted with whitespace", quote: `"`, padding: " ", outputDir: "patched-double-spaced"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "scan")
			sha := strings.Repeat("d", 40)
			originalRef := tt.padding + "actions/checkout@v4" + tt.padding
			replacementRef := tt.padding + "actions/checkout@" + sha + tt.padding
			original := "jobs:\n  test:\n    steps:\n      - uses: " + tt.quote + originalRef + tt.quote + "\n"
			writeGitHubActionsWorkflowForTest(t, root, "quoted.yml", original)
			writeFileForTest(t, parent, "pins.json", `{"actions/checkout@v4":"`+sha+`"}`)

			previewOut, previewErr, previewCode := runCommandInDir(t, parent, "scan", "--github-action-pins", "pins.json", "--preview-patches", "scan")
			writeOut, writeErr, writeCode := runCommandInDir(t, parent, "scan", "--github-action-pins", "pins.json", "--write-patches", tt.outputDir, "scan")

			assertCode(t, previewCode, 1)
			assertString(t, "preview stderr", previewErr, "")
			assertContains(t, previewOut, "-      - uses: "+tt.quote+originalRef+tt.quote+"\n")
			assertContains(t, previewOut, "+      - uses: "+tt.quote+replacementRef+tt.quote+"\n")
			assertCode(t, writeCode, 1)
			assertString(t, "write stderr", writeErr, "")
			assertContains(t, writeOut, "Written files: 1")
			patched := readFileForTest(t, filepath.Join(parent, tt.outputDir), ".github/workflows/quoted.yml")
			assertContains(t, patched, "uses: "+tt.quote+replacementRef+tt.quote)
			assertString(t, "input workflow", readFileForTest(t, root, ".github/workflows/quoted.yml"), original)
		})
	}
}

func TestRunScanGitHubActionsIDTokenPermissionDoesNotBlockPinPatch(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	sha := strings.Repeat("f", 40)
	original := `permissions:
  id-token: write
  contents: read
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`
	writeGitHubActionsWorkflowForTest(t, root, "oidc.yml", original)
	writeFileForTest(t, parent, "pins.json", `{"actions/checkout@v4":"`+sha+`"}`)

	previewOut, previewErr, previewCode := runCommandInDir(t, parent, "scan", "--github-action-pins", "pins.json", "--preview-patches", "scan")
	writeOut, writeErr, writeCode := runCommandInDir(t, parent, "scan", "--github-action-pins", "pins.json", "--write-patches", "patched", "scan")

	assertCode(t, previewCode, 1)
	assertString(t, "preview stderr", previewErr, "")
	assertContains(t, previewOut, "-      - uses: actions/checkout@v4\n")
	assertContains(t, previewOut, "+      - uses: actions/checkout@"+sha+"\n")
	assertCode(t, writeCode, 1)
	assertString(t, "write stderr", writeErr, "")
	assertContains(t, writeOut, "Written files: 1")
	patched := readFileForTest(t, filepath.Join(parent, "patched"), ".github/workflows/oidc.yml")
	assertContains(t, patched, "actions/checkout@"+sha)
	assertString(t, "input workflow", readFileForTest(t, root, ".github/workflows/oidc.yml"), original)
}

func TestRunScanGitHubActionsHarmlessWorkflowContextDoesNotBlockPinPatch(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	sha := strings.Repeat("e", 40)
	original := `jobs:
  test:
    env:
      SAFE_ENV: local
    steps:
      - run: go test ./...
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
        env:
          CACHE_NAME: gomod
`
	writeGitHubActionsWorkflowForTest(t, root, "context.yml", original)
	writeFileForTest(t, parent, "pins.json", `{"actions/setup-go@v5":"`+sha+`"}`)

	previewOut, previewErr, previewCode := runCommandInDir(t, parent, "scan", "--github-action-pins", "pins.json", "--preview-patches", "scan")
	writeOut, writeErr, writeCode := runCommandInDir(t, parent, "scan", "--github-action-pins", "pins.json", "--write-patches", "patched", "scan")

	assertCode(t, previewCode, 1)
	assertString(t, "preview stderr", previewErr, "")
	assertContains(t, previewOut, "-      - uses: actions/setup-go@v5\n")
	assertContains(t, previewOut, "+      - uses: actions/setup-go@"+sha+"\n")
	if strings.Contains(previewOut, "go-version") || strings.Contains(previewOut, "go test") || strings.Contains(previewOut, "SAFE_ENV") || strings.Contains(previewOut, "CACHE_NAME") {
		t.Fatalf("GitHub Actions patch preview leaked harmless workflow context: %s", previewOut)
	}
	assertCode(t, writeCode, 1)
	assertString(t, "write stderr", writeErr, "")
	assertContains(t, writeOut, "Written files: 1")
	patched := readFileForTest(t, filepath.Join(parent, "patched"), ".github/workflows/context.yml")
	assertContains(t, patched, "actions/setup-go@"+sha)
	assertString(t, "input workflow", readFileForTest(t, root, ".github/workflows/context.yml"), original)
}

func TestRunScanGitHubActionsSameLineRunContextDoesNotLeakOrPatch(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	sha := strings.Repeat("a", 40)
	const runScript = "FAKE_CLI_GHA_SAME_LINE_RUN_SECRET_DO_NOT_RETAIN"
	original := `jobs:
  test:
    steps: [{run: echo FAKE_CLI_GHA_SAME_LINE_RUN_SECRET_DO_NOT_RETAIN, uses: actions/checkout@v4}]
`
	writeGitHubActionsWorkflowForTest(t, root, "flow.yml", original)
	writeFileForTest(t, parent, "pins.json", `{"actions/checkout@v4":"`+sha+`"}`)

	previewOut, previewErr, previewCode := runCommandInDir(t, parent, "scan", "--github-action-pins", "pins.json", "--preview-patches", "scan")
	writeOut, writeErr, writeCode := runCommandInDir(t, parent, "scan", "--github-action-pins", "pins.json", "--write-patches", "patched", "scan")
	jsonOut, jsonErr, jsonCode := runCommandInDir(t, parent, "scan", "--format=json", "--github-action-pins", "pins.json", "scan")

	assertCode(t, previewCode, 1)
	assertString(t, "preview stderr", previewErr, "")
	assertContains(t, previewOut, "Remediation:")
	assertContains(t, previewOut, "Status: unsupported")
	assertContains(t, previewOut, "source line")
	assertCode(t, writeCode, 1)
	assertString(t, "write stderr", writeErr, "")
	assertContains(t, writeOut, "Written files: 0")
	if _, err := os.Stat(filepath.Join(parent, "patched")); !os.IsNotExist(err) {
		t.Fatalf("patched output directory exists or stat failed unexpectedly: %v", err)
	}
	assertCode(t, jsonCode, 1)
	assertString(t, "json stderr", jsonErr, "")
	report := assertValidJSONReport(t, jsonOut)
	change := report.Findings[0].Remediation.Options[0].Changes[0]
	if !change.Advisory || change.PatchSupported {
		t.Fatalf("change = %#v, want advisory unsupported remediation", change)
	}
	for _, output := range []string{previewOut, previewErr, writeOut, writeErr, jsonOut, jsonErr} {
		if strings.Contains(output, runScript) || strings.Contains(output, "echo "+runScript) {
			t.Fatalf("output leaks same-line run script: %s", output)
		}
	}
	assertString(t, "input workflow", readFileForTest(t, root, ".github/workflows/flow.yml"), original)
}

func TestRunScanGitHubActionsHyphenatedSecretKeysDoNotWritePatchedCopy(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	sha := strings.Repeat("a", 40)
	const accessKey = "AKIAIOSFODNN7EXAMPLE"
	const privateKey = "opaque-key-material"
	original := `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
        with:
          access-key: AKIAIOSFODNN7EXAMPLE
          private-key: opaque-key-material
`
	writeGitHubActionsWorkflowForTest(t, root, "secret-keys.yml", original)
	writeFileForTest(t, parent, "pins.json", `{"actions/checkout@v4":"`+sha+`"}`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--github-action-pins", "pins.json", "--write-patches", "patched", "scan")
	jsonOut, jsonErr, jsonCode := runCommandInDir(t, parent, "scan", "--format=json", "--github-action-pins", "pins.json", "scan")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Written files: 0")
	if _, err := os.Stat(filepath.Join(parent, "patched")); !os.IsNotExist(err) {
		t.Fatalf("patched output directory exists or stat failed unexpectedly: %v", err)
	}
	assertCode(t, jsonCode, 1)
	assertString(t, "json stderr", jsonErr, "")
	report := assertValidJSONReport(t, jsonOut)
	change := report.Findings[0].Remediation.Options[0].Changes[0]
	if !change.Advisory || change.PatchSupported {
		t.Fatalf("change = %#v, want advisory unsupported remediation", change)
	}
	for _, output := range []string{stdout, stderr, jsonOut, jsonErr} {
		for _, forbidden := range []string{accessKey, privateKey, "access-key", "private-key"} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("output leaks %q: %s", forbidden, output)
			}
		}
	}
	assertString(t, "input workflow", readFileForTest(t, root, ".github/workflows/secret-keys.yml"), original)
}

func TestRunScanGitHubActionsBlockStyleUsesReportsAdvisoryOnly(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	sha := strings.Repeat("a", 40)
	writeGitHubActionsWorkflowForTest(t, root, "block.yml", `jobs:
  test:
    steps:
      - uses: >
          actions/checkout@v4
`)
	writeFileForTest(t, parent, "pins.json", `{"actions/checkout@v4":"`+sha+`"}`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--github-action-pins", "pins.json", "--preview-patches", "scan")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	change := report.Findings[0].Remediation.Options[0].Changes[0]
	if !change.Advisory || change.PatchSupported {
		t.Fatalf("change = %#v, want advisory unsupported remediation", change)
	}
	if len(report.Findings[0].Remediation.Options[0].PatchPreviews) != 1 || report.Findings[0].Remediation.Options[0].PatchPreviews[0].Status != "unsupported" {
		t.Fatalf("patch previews = %#v, want one unsupported preview", report.Findings[0].Remediation.Options[0].PatchPreviews)
	}
}

func TestRunScanGitHubActionsPinMappingSkipsUnsafeWorkflowPatch(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	sha := strings.Repeat("a", 40)
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - run: echo FAKE_CLI_GHA_RUN_SECRET_DO_NOT_RETAIN
      - uses: actions/checkout@v4
        with:
          token: FAKE_CLI_GHA_WITH_SECRET_DO_NOT_RETAIN
`)
	writeFileForTest(t, parent, "pins.json", `{"actions/checkout@v4":"`+sha+`"}`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--github-action-pins", "pins.json", "--preview-patches", "scan")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Remediation:")
	assertContains(t, stdout, "Status: unsupported")
	assertContains(t, stdout, "workflow contains unsupported or secret-like context")
	if strings.Contains(stdout, "Diff:") {
		t.Fatalf("unsafe workflow produced patch diff: %s", stdout)
	}
	assertDoesNotContainGitHubActionsSecretValues(t, stdout, stderr)
}

func TestRunScanGitHubActionsWritePatchesWithLocalPinMapping(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	sha := strings.Repeat("b", 40)
	original := `jobs:
  test:
    steps:
      - uses: owner/repo/path@v1
`
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", original)
	writeFileForTest(t, parent, "pins.json", `{"owner/repo/path@v1":"`+sha+`"}`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--github-action-pins", "pins.json", "--write-patches", "patched", "--validate-patches", "scan")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Patch Output:")
	assertContains(t, stdout, "Written files: 1")
	assertContains(t, stdout, "Source: .github/workflows/unpinned.yml")
	if strings.Contains(stdout, "Validation:") {
		t.Fatalf("PP-GHA-001 write-patches produced validation output: %s", stdout)
	}
	patched := readFileForTest(t, filepath.Join(parent, "patched"), ".github/workflows/unpinned.yml")
	assertContains(t, patched, "owner/repo/path@"+sha)
	assertString(t, "input workflow", readFileForTest(t, root, ".github/workflows/unpinned.yml"), original)
}

func TestRunScanGitHubActionsJSONIncludesPinRemediationMetadata(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	sha := strings.Repeat("c", 40)
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	writeFileForTest(t, parent, "pins.json", `{"actions/checkout@v4":"`+sha+`"}`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--github-action-pins", "pins.json", "scan")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if len(report.Findings) != 1 || report.Findings[0].Remediation == nil {
		t.Fatalf("report = %#v, want PP-GHA-001 remediation", report)
	}
	change := report.Findings[0].Remediation.Options[0].Changes[0]
	if !change.Advisory || !change.PatchSupported || change.ActionRef != "actions/checkout@v4" || change.ReplacementSHA != sha || change.ReplacementRef != "actions/checkout@"+sha {
		t.Fatalf("change = %#v, want patch-supported pin metadata", change)
	}
	if strings.Contains(stdout, parent) || strings.Contains(stdout, "pins.json") {
		t.Fatalf("JSON output leaks local path or mapping filename: %s", stdout)
	}
}

func TestRunScanGitHubActionsMalformedPinMappingIsSanitized(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	writeFileForTest(t, parent, "pins.json", `{"actions/checkout@v4":"FAKE_MAPPING_SECRET_DO_NOT_RETAIN"`)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--github-action-pins", "pins.json", "scan")

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "github action pins file is not valid JSON")
	for _, forbidden := range []string{"FAKE_MAPPING_SECRET_DO_NOT_RETAIN", "actions/checkout@v4", "pins.json", parent} {
		if strings.Contains(stdout, forbidden) || strings.Contains(stderr, forbidden) {
			t.Fatalf("pin mapping error leaks %q\nstdout:%s\nstderr:%s", forbidden, stdout, stderr)
		}
	}
}

func TestRunScanGitHubActionsNonObjectPinMappingIsSanitized(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{name: "null", content: `null`},
		{name: "array", content: `[]`},
		{name: "string", content: `"bad"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "scan")
			writeGitHubActionsWorkflowForTest(t, root, "unpinned.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
			writeFileForTest(t, parent, "pins.json", tt.content)

			stdout, stderr, code := runCommandInDir(t, parent, "scan", "--github-action-pins", "pins.json", "scan")

			assertCode(t, code, 2)
			assertString(t, "stdout", stdout, "")
			assertOneLineStderr(t, stderr)
			assertContains(t, stderr, "github action pins file must be a JSON object")
			for _, forbidden := range []string{tt.content, "actions/checkout@v4", "pins.json", parent} {
				if strings.Contains(stdout, forbidden) || strings.Contains(stderr, forbidden) {
					t.Fatalf("pin mapping error leaks %q\nstdout:%s\nstderr:%s", forbidden, stdout, stderr)
				}
			}
		})
	}
}

func TestRunScanGitHubActionsMalformedWorkflowErrorExcludesValues(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "bad.yml", `name: bad
env:
  TOKEN: FAKE_CLI_GHA_MALFORMED_SECRET_DO_NOT_RETAIN
jobs: [
`)

	stdout, stderr, code := runCommand("scan", dir)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, ".github")
	assertContains(t, stderr, "document 1")
	assertContains(t, stderr, "invalid YAML")
	assertDoesNotContainGitHubActionsSecretValues(t, stdout, stderr)
}

func TestRunScanGitHubActionsMalformedAliasErrorIsSanitized(t *testing.T) {
	dir := t.TempDir()
	const fakeAlias = "FAKE_CLI_GHA_ALIAS_TOKEN_DO_NOT_RETAIN"
	writeGitHubActionsWorkflowForTest(t, dir, "bad-alias.yml", `name: bad alias
jobs:
  test:
    steps:
      - uses: owner/repo@main
        with:
          token: *FAKE_CLI_GHA_ALIAS_TOKEN_DO_NOT_RETAIN
`)

	stdout, stderr, code := runCommand("scan", dir)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, ".github/workflows/bad-alias.yml")
	assertContains(t, stderr, "document 1")
	assertContains(t, stderr, "invalid YAML")
	for _, forbidden := range []string{fakeAlias, "unknown anchor", "token:", "with:", "owner/repo@main"} {
		if strings.Contains(stderr, forbidden) {
			t.Fatalf("stderr contains %q: %s", forbidden, stderr)
		}
	}
}

func TestRunScanGitHubActionsMalformedThirdDocumentErrorIsSanitized(t *testing.T) {
	dir := t.TempDir()
	const fakeAlias = "FAKE_CLI_GHA_THIRD_DOC_ALIAS_DO_NOT_RETAIN"
	writeGitHubActionsWorkflowForTest(t, dir, "bad-third.yml", `name: valid
jobs:
  test:
    steps:
      - uses: owner/repo@0123456789abcdef0123456789abcdef01234567
---
name: ignored second document
env:
  TOKEN: FAKE_CLI_GHA_IGNORED_DOC_VALUE_DO_NOT_RETAIN
---
with:
  token: *FAKE_CLI_GHA_THIRD_DOC_ALIAS_DO_NOT_RETAIN
`)

	stdout, stderr, code := runCommand("scan", dir)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, ".github/workflows/bad-third.yml")
	assertContains(t, stderr, "document 3")
	assertContains(t, stderr, "invalid YAML")
	for _, forbidden := range []string{fakeAlias, "FAKE_CLI_GHA_IGNORED_DOC_VALUE_DO_NOT_RETAIN", "unknown anchor", "token:", "with:", "env:"} {
		if strings.Contains(stderr, forbidden) {
			t.Fatalf("stderr contains %q: %s", forbidden, stderr)
		}
	}
}

func TestRunScanPublicDemoFixtureEndToEnd(t *testing.T) {
	demoDir, err := filepath.Abs(publicDemoFixture)
	if err != nil {
		t.Fatalf("resolve public demo fixture: %v", err)
	}

	stdout, stderr, code := runCommand("scan", demoDir)
	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Finding count: 1\n")
	assertContains(t, stdout, "Rule: PP-K8S-001\n")
	assertContains(t, stdout, "PublicEndpoint kubernetes://prod/service/public-api")
	assertContains(t, stdout, "Workload kubernetes://prod/deployment/api")
	assertContains(t, stdout, "ServiceAccount kubernetes://prod/serviceaccount/api")
	assertContains(t, stdout, "Secret kubernetes://prod/secret/database-password")
	assertDoesNotContainSecretPayloadFields(t, stdout, stderr)

	stdout, stderr, code = runCommand("scan", "--preview-patches", demoDir)
	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Option 1: NarrowBindingSubject")
	assertContains(t, stdout, "Parameters: permission_sha256=")
	assertContains(t, stdout, "matched_verb=")
	assertContains(t, stdout, "subject=")
	for _, forbidden := range []string{"action_ref=", "replacement_sha=", "replacement_ref=", "patch_supported=", "advisory="} {
		if strings.Contains(stdout, forbidden) {
			t.Fatalf("K8S human output contains GHA-only field %q: %s", forbidden, stdout)
		}
	}
	assertContains(t, stdout, "Patch Preview:")
	assertContains(t, stdout, "Status: generated")
	assertContains(t, stdout, "File: rbac.yaml")
	assertContains(t, stdout, "--- rbac.yaml\n")
	assertContains(t, stdout, "+++ rbac.yaml\n")
	assertDoesNotContainSecretPayloadFields(t, stdout, stderr)

	parent := t.TempDir()
	stdout, stderr, code = runCommandInDir(t, parent, "scan", "--write-patches", "patched", demoDir)
	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Patch Output:")
	assertContains(t, stdout, "Written files: 1")
	assertContains(t, stdout, "Source: rbac.yaml")
	assertContains(t, stdout, "Output: patched/rbac.yaml")
	assertDoesNotContainSecretPayloadFields(t, stdout, stderr)
	if got := listDirNames(t, filepath.Join(parent, "patched")); !reflect.DeepEqual(got, []string{"rbac.yaml"}) {
		t.Fatalf("patched output entries = %#v, want only rbac.yaml", got)
	}
	patched, err := os.ReadFile(filepath.Join(parent, "patched", "rbac.yaml"))
	if err != nil {
		t.Fatalf("read patched demo output: %v", err)
	}
	if strings.Contains(string(patched), "name: api\n  namespace: prod") {
		t.Fatalf("patched output still contains removed ServiceAccount subject:\n%s", patched)
	}
	assertContains(t, string(patched), "name: worker")

	stdout, stderr, code = runCommandInDir(t, parent, "scan", "--write-patches", "validated", "--validate-patches", demoDir)
	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Validation:")
	assertContains(t, stdout, ": remediated\n")
	assertContains(t, stdout, "Summary: PP-K8S-001 no longer appears in patched output.")
	assertDoesNotContainSecretPayloadFields(t, stdout, stderr)

	stdout, stderr, code = runCommandInDir(t, parent, "scan", "--format=json", "--write-patches", "json-patched", "--validate-patches", demoDir)
	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.FindingCount != 1 || len(report.Findings) != 1 {
		t.Fatalf("demo JSON findings = %#v, count = %d; want one finding", report.Findings, report.FindingCount)
	}
	if report.Findings[0].RuleID != "PP-K8S-001" {
		t.Fatalf("demo JSON rule_id = %q, want PP-K8S-001", report.Findings[0].RuleID)
	}
	if report.PatchOutputs == nil || len(*report.PatchOutputs) == 0 {
		t.Fatalf("demo JSON patch_outputs = %#v, want generated output", report.PatchOutputs)
	}
	if len(report.Validation) != 1 || report.Validation[0].RuleID != "PP-K8S-001" || report.Validation[0].Status != "remediated" {
		t.Fatalf("demo JSON validation = %#v, want one remediated PP-K8S-001 result", report.Validation)
	}
	assertDoesNotContainSecretPayloadFields(t, stdout, stderr)
}

func TestRunScanGitHubActionsDemoFixture(t *testing.T) {
	demoDir, err := filepath.Abs(ghaDemoFixture)
	if err != nil {
		t.Fatalf("resolve GitHub Actions demo fixture: %v", err)
	}

	stdout, stderr, code := runCommand("scan", demoDir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Finding count: 1\n")
	assertContains(t, stdout, "Rule: PP-GHA-001\n")
	assertContains(t, stdout, "actions/checkout@v4")
	assertContains(t, stdout, "Remediation:")
	if strings.Contains(stdout, legacyGitHubActionsRuleWording()) {
		t.Fatalf("GitHub Actions demo output contains unsupported text: %s", stdout)
	}
}

func TestRunScanGitHubActionsDangerousPermissionsDemoFixture(t *testing.T) {
	demoDir, err := filepath.Abs(ghaDangerousPermissionsDemoFixture)
	if err != nil {
		t.Fatalf("resolve GitHub Actions dangerous permissions demo fixture: %v", err)
	}

	stdout, stderr, code := runCommand("scan", demoDir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Finding count: 1\n")
	assertContains(t, stdout, "Rule: PP-GHA-003\n")
	assertContains(t, stdout, "permissions: write-all")
	if strings.Contains(stdout, "all: write") || strings.Contains(stdout, "Remediation:") {
		t.Fatalf("GitHub Actions dangerous permissions demo output contains unsupported text: %s", stdout)
	}
}

func TestRunScanInvalidFixtureReturnsTwoAndWritesErrorToStderr(t *testing.T) {
	stdout, stderr, code := runCommand("scan", invalidFixture)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "parse scan directory")
	assertContains(t, stderr, "document 1")
}

func TestRunScanJSONOutputIsStructured(t *testing.T) {
	stdout, stderr, code := runCommand("scan", "--format=json", vulnerableFixture)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.FindingCount != 1 || len(report.Findings) != 1 {
		t.Fatalf("finding count = %d len = %d, want 1", report.FindingCount, len(report.Findings))
	}
	finding := report.Findings[0]
	if finding.RuleID != "PP-K8S-001" {
		t.Fatalf("rule_id = %q, want PP-K8S-001", finding.RuleID)
	}
	if finding.Severity != "High" {
		t.Fatalf("severity = %q, want High", finding.Severity)
	}
	if len(finding.Path) != 4 {
		t.Fatalf("path len = %d, want 4", len(finding.Path))
	}
	for i, node := range finding.Path {
		if node.ID == "" {
			t.Fatalf("path[%d] id is empty: %#v", i, node)
		}
	}
	if got := finding.Path[0].Kind; got != "PublicEndpoint" {
		t.Fatalf("path[0].kind = %q, want PublicEndpoint", got)
	}
	if len(finding.Evidence) != 3 {
		t.Fatalf("evidence len = %d, want 3", len(finding.Evidence))
	}
	for i, evidence := range finding.Evidence {
		if evidence.EdgeID == "" {
			t.Fatalf("evidence[%d] edge_id is empty: %#v", i, evidence)
		}
		if evidence.Kind == "" || evidence.Detail == "" || evidence.Source == "" {
			t.Fatalf("evidence[%d] missing fields: %#v", i, evidence)
		}
	}
	if finding.Remediation == nil {
		t.Fatal("remediation = nil, want structured remediation plan")
	}
	if finding.Remediation.ID == "" || finding.Remediation.FindingID != finding.ID || finding.Remediation.RuleID != finding.RuleID {
		t.Fatalf("remediation identity = %#v, finding = %#v", finding.Remediation, finding)
	}
	if len(finding.Remediation.Options) == 0 {
		t.Fatalf("remediation options empty: %#v", finding.Remediation)
	}
	for _, option := range finding.Remediation.Options {
		if option.Action == "" || option.Priority == 0 || option.Summary == "" || option.Rationale == "" {
			t.Fatalf("remediation option missing fields: %#v", option)
		}
		if len(option.Changes) == 0 {
			t.Fatalf("remediation option has no changes: %#v", option)
		}
		for _, change := range option.Changes {
			if change.Action == "" || change.Target.Kind == "" || change.Target.Name == "" || change.Summary == "" || change.SourceReference == "" {
				t.Fatalf("remediation change missing fields: %#v", change)
			}
		}
	}
	assertExactlyOneTrailingNewline(t, stdout)
	if strings.Contains(stdout, "Finding count:") || strings.Contains(stdout, "Rule:") {
		t.Fatalf("json stdout contains human text: %q", stdout)
	}
	if strings.Contains(stdout, "patch_previews") {
		t.Fatalf("default JSON output contains patch previews: %s", stdout)
	}
}

func TestRunScanSafeFixtureJSONContainsNoRemediationPlans(t *testing.T) {
	stdout, stderr, code := runCommand("scan", "--format=json", safeFixture)

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.FindingCount != 0 || len(report.Findings) != 0 {
		t.Fatalf("safe report = %#v, want no findings", report)
	}
	assertString(t, "stdout", stdout, "{\"findings\":[],\"finding_count\":0}\n")
	if strings.Contains(stdout, "remediation") {
		t.Fatalf("safe stdout contains remediation: %s", stdout)
	}
}

func TestRunScanOutputIsDeterministic(t *testing.T) {
	firstOut, firstErr, firstCode := runCommand("scan", vulnerableFixture)
	secondOut, secondErr, secondCode := runCommand("scan", vulnerableFixture)

	assertCode(t, firstCode, 1)
	assertCode(t, secondCode, 1)
	assertString(t, "first stderr", firstErr, "")
	assertString(t, "second stderr", secondErr, "")
	assertString(t, "stdout", secondOut, firstOut)

	firstJSON, firstJSONErr, firstJSONCode := runCommand("scan", "--format=json", vulnerableFixture)
	secondJSON, secondJSONErr, secondJSONCode := runCommand("scan", "--format=json", vulnerableFixture)
	assertCode(t, firstJSONCode, 1)
	assertCode(t, secondJSONCode, 1)
	assertString(t, "first json stderr", firstJSONErr, "")
	assertString(t, "second json stderr", secondJSONErr, "")
	assertString(t, "json stdout", secondJSON, firstJSON)
}

func TestRunScanPreviewPatchesHumanOutputIncludesGeneratedPreview(t *testing.T) {
	parent := t.TempDir()
	writePreviewFixture(t, parent, "scan-preview", false)
	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--preview-patches", "scan-preview")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Patch Preview:")
	assertContains(t, stdout, "Status: generated")
	assertContains(t, stdout, "File: resources.yaml")
	assertContains(t, stdout, "Diff:")
	assertContains(t, stdout, "--- resources.yaml\n")
	assertContains(t, stdout, "+++ resources.yaml\n")
	assertContains(t, stdout, "@@")
	assertContains(t, stdout, "-  name: api\n")
	assertContains(t, stdout, "   name: worker\n")
	assertExactlyOneTrailingNewline(t, stdout)
}

func TestRunScanPreviewPatchesJSONOutputIncludesStructuredPreview(t *testing.T) {
	parent := t.TempDir()
	writePreviewFixture(t, parent, "scan-preview", false)
	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--preview-patches", "scan-preview")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.Findings[0].Remediation == nil {
		t.Fatal("remediation = nil, want remediation with patch previews")
	}
	previewCount := 0
	for _, option := range report.Findings[0].Remediation.Options {
		for _, preview := range option.PatchPreviews {
			previewCount++
			if preview.Status == "generated" {
				if preview.File != "resources.yaml" || preview.Diff == "" || preview.OptionAction != "NarrowBindingSubject" {
					t.Fatalf("generated preview = %#v", preview)
				}
			}
		}
	}
	if previewCount == 0 {
		t.Fatalf("no patch previews in JSON remediation: %#v", report.Findings[0].Remediation)
	}
	assertContains(t, stdout, `"patch_previews"`)
	assertExactlyOneTrailingNewline(t, stdout)
}

func TestRunScanPreviewPatchesShowsUnsupportedPreview(t *testing.T) {
	stdout, stderr, code := runCommand("scan", "--preview-patches", vulnerableFixture)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Patch Preview:")
	assertContains(t, stdout, "Status: unsupported")
	assertContains(t, stdout, "NarrowBindingSubject")
}

func TestRunScanPreviewPatchesJSONFlagForms(t *testing.T) {
	parent := t.TempDir()
	writePreviewFixture(t, parent, "scan-preview", false)

	for _, args := range [][]string{
		{"scan", "--format", "json", "--preview-patches", "scan-preview"},
		{"scan", "--format=json", "--preview-patches", "scan-preview"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, stderr, code := runCommandInDir(t, parent, args...)

			assertCode(t, code, 1)
			assertString(t, "stderr", stderr, "")
			report := assertValidJSONReport(t, stdout)
			if report.Findings[0].Remediation == nil {
				t.Fatal("remediation = nil")
			}
			assertContains(t, stdout, `"patch_previews"`)
		})
	}
}

func TestRunScanPreviewPatchesSafeScanHasNoPreviews(t *testing.T) {
	stdout, stderr, code := runCommand("scan", "--preview-patches", safeFixture)

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	assertString(t, "stdout", stdout, "Finding count: 0\nNo findings.\n")
}

func TestWriteScanResultPreviewBuilderDoesNotRunWithoutFlag(t *testing.T) {
	fixture := projectionFixtureWithValidFinding(t)
	var stdout, stderr bytes.Buffer

	code := writeScanResult([]analysis.Finding{fixture.finding}, fixture.graph, "", scanFormatHuman, false, "", false, nil, &stdout, &stderr)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr.String(), "")
	assertContains(t, stdout.String(), "Finding count: 1\n")
	if strings.Contains(stdout.String(), "Patch Preview:") {
		t.Fatalf("output contains patch preview without flag: %s", stdout.String())
	}
}

func TestWriteScanResultPreviewInternalErrorLeavesStdoutEmpty(t *testing.T) {
	fixture := projectionFixtureWithValidFinding(t)
	var stdout, stderr bytes.Buffer

	code := writeScanResult([]analysis.Finding{fixture.finding}, fixture.graph, "", scanFormatHuman, true, "", false, nil, &stdout, &stderr)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout.String(), "")
	assertOneLineStderr(t, stderr.String())
	assertContains(t, stderr.String(), "build patch previews")
}

func TestRunScanPreviewPatchesOutputIsDeterministicAndExcludesSecretValues(t *testing.T) {
	parent := t.TempDir()
	writePreviewFixture(t, parent, "scan-preview", true)
	firstOut, firstErr, firstCode := runCommandInDir(t, parent, "scan", "--preview-patches", "scan-preview")
	secondOut, secondErr, secondCode := runCommandInDir(t, parent, "scan", "--preview-patches", "scan-preview")

	assertCode(t, firstCode, 1)
	assertCode(t, secondCode, 1)
	assertString(t, "first stderr", firstErr, "")
	assertString(t, "second stderr", secondErr, "")
	assertString(t, "stdout", secondOut, firstOut)
	for _, value := range []string{
		"FAKE_PREVIEW_CLI_SECRET_DATA_VALUE_DO_NOT_RETAIN",
		"FAKE_PREVIEW_CLI_SECRET_STRINGDATA_VALUE_DO_NOT_RETAIN",
	} {
		if strings.Contains(firstOut, value) || strings.Contains(firstErr, value) {
			t.Fatalf("preview output contains secret value %q\nstdout:%s\nstderr:%s", value, firstOut, firstErr)
		}
	}
	assertContains(t, firstOut, "Status: unsupported")
}

func TestRunScanWritePatchesRequiresOutputAndInputDirectories(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing output value", args: []string{"scan", "--write-patches"}, want: "flag needs an argument"},
		{name: "missing input", args: []string{"scan", "--write-patches", "patched"}, want: "got 0"},
		{name: "extra input", args: []string{"scan", "--write-patches", "patched", safeFixture, vulnerableFixture}, want: "got 2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, code := runCommand(tt.args...)

			assertCode(t, code, 2)
			assertString(t, "stdout", stdout, "")
			assertOneLineStderr(t, stderr)
			assertContains(t, stderr, tt.want)
		})
	}
}

func TestRunScanWritePatchesRejectsUnsafeOutputDirectories(t *testing.T) {
	parent := t.TempDir()
	writePreviewFixture(t, parent, "scan-preview", false)
	nonEmpty := filepath.Join(parent, "non-empty")
	if err := os.Mkdir(nonEmpty, 0o700); err != nil {
		t.Fatalf("mkdir non-empty: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nonEmpty, "existing.yaml"), []byte("kind: ConfigMap\n"), 0o600); err != nil {
		t.Fatalf("write existing output: %v", err)
	}
	fileOutput := filepath.Join(parent, "file-output")
	if err := os.WriteFile(fileOutput, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write file output: %v", err)
	}

	tests := []struct {
		name   string
		output string
		input  string
		want   string
	}{
		{name: "same as input", output: "scan-preview", input: "scan-preview", want: "differ"},
		{name: "output inside input", output: filepath.Join("scan-preview", "patched"), input: "scan-preview", want: "must not be inside scan"},
		{name: "input inside output", output: ".", input: "scan-preview", want: "scan directory must not be inside"},
		{name: "file output", output: "file-output", input: "scan-preview", want: "not a directory"},
		{name: "non-empty output", output: "non-empty", input: "scan-preview", want: "must be empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, code := runCommandInDir(t, parent, "scan", "--write-patches", tt.output, tt.input)

			assertCode(t, code, 2)
			assertString(t, "stdout", stdout, "")
			assertOneLineStderr(t, stderr)
			assertContains(t, stderr, tt.want)
			if strings.Contains(stderr, parent) {
				t.Fatalf("stderr contains temp directory prefix: %q", stderr)
			}
		})
	}
}

func TestRunScanWritePatchesSupportedNarrowBindingSubject(t *testing.T) {
	parent := t.TempDir()
	writePreviewFixture(t, parent, "scan-preview", false)
	inputPath := filepath.Join(parent, "scan-preview", "resources.yaml")
	original, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatalf("read input fixture: %v", err)
	}

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--write-patches", "patched", "scan-preview")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Patch Output:")
	assertContains(t, stdout, "Written files: 1")
	assertContains(t, stdout, "Source: resources.yaml")
	assertContains(t, stdout, "Output: patched/resources.yaml")
	if strings.Contains(stdout, "Patch Preview:") || strings.Contains(stdout, "Diff:") {
		t.Fatalf("write-only output contains preview diff text: %s", stdout)
	}
	if strings.Contains(stdout, parent) || strings.Contains(stderr, parent) {
		t.Fatalf("output contains temp directory prefix\nstdout:%s\nstderr:%s", stdout, stderr)
	}
	patched, err := os.ReadFile(filepath.Join(parent, "patched", "resources.yaml"))
	if err != nil {
		t.Fatalf("read patched output: %v", err)
	}
	if strings.Contains(string(patched), "    name: api\n    namespace: prod") {
		t.Fatalf("patched output still contains removed ServiceAccount subject:\n%s", patched)
	}
	assertContains(t, string(patched), "name: worker")
	after, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatalf("read input after scan: %v", err)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("input file changed:\nafter:\n%s\nbefore:\n%s", after, original)
	}
}

func TestRunScanWriteAndPreviewPatchesIncludesDiffAndOutputSummary(t *testing.T) {
	parent := t.TempDir()
	writePreviewFixture(t, parent, "scan-preview", false)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--preview-patches", "--write-patches", "patched", "scan-preview")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Patch Preview:")
	assertContains(t, stdout, "Diff:")
	assertContains(t, stdout, "Patch Output:")
	assertContains(t, stdout, "Written files: 1")
}

func TestRunScanWritePatchesUnsupportedOnlyWritesNoFiles(t *testing.T) {
	parent := t.TempDir()
	outputRoot := filepath.Join(parent, "patched")

	stdout, stderr, code := runCommand("scan", "--write-patches", outputRoot, vulnerableFixture)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Patch Output:")
	assertContains(t, stdout, "Written files: 0")
	assertContains(t, stdout, "Status: unsupported")
	if _, err := os.Stat(outputRoot); !os.IsNotExist(err) {
		t.Fatalf("outputRoot stat err = %v, want not exist", err)
	}
	if strings.Contains(stdout, parent) || strings.Contains(stderr, parent) {
		t.Fatalf("output contains temp directory prefix\nstdout:%s\nstderr:%s", stdout, stderr)
	}
}

func TestRunScanWritePatchesSafeScanWritesNoFiles(t *testing.T) {
	parent := t.TempDir()
	outputRoot := filepath.Join(parent, "patched")

	stdout, stderr, code := runCommand("scan", "--write-patches", outputRoot, safeFixture)

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Finding count: 0\nNo findings.\n")
	assertContains(t, stdout, "Patch Output:")
	assertContains(t, stdout, "Written files: 0")
	if _, err := os.Stat(outputRoot); !os.IsNotExist(err) {
		t.Fatalf("outputRoot stat err = %v, want not exist", err)
	}
}

func TestRunScanPreviewPatchesAloneDoesNotWriteFiles(t *testing.T) {
	parent := t.TempDir()
	writePreviewFixture(t, parent, "scan-preview", false)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--preview-patches", "scan-preview")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Patch Preview:")
	if _, err := os.Stat(filepath.Join(parent, "patched")); !os.IsNotExist(err) {
		t.Fatalf("unexpected patched directory stat err = %v", err)
	}
}

func TestRunScanWritePatchesJSONOutputIncludesPatchOutputsOnlyWhenRequested(t *testing.T) {
	parent := t.TempDir()
	writePreviewFixture(t, parent, "scan-preview", false)

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--write-patches", "patched", "scan-preview")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.PatchOutputs == nil {
		t.Fatal("patch_outputs = nil, want output summaries")
	}
	generatedCount := 0
	for _, output := range *report.PatchOutputs {
		if output.Status == "generated" {
			generatedCount++
			if output.Source != "resources.yaml" || output.Output != "patched/resources.yaml" {
				t.Fatalf("generated patch output = %#v, want resources output", output)
			}
		}
	}
	if generatedCount != 1 {
		t.Fatalf("generated patch output count = %d, want 1: %#v", generatedCount, *report.PatchOutputs)
	}
	if strings.Contains(stdout, `"patch_previews"`) || strings.Contains(stdout, `"diff"`) {
		t.Fatalf("write-only JSON contains patch previews or diffs: %s", stdout)
	}
	if strings.Contains(stdout, parent) || strings.Contains(stderr, parent) {
		t.Fatalf("JSON output contains temp directory prefix\nstdout:%s\nstderr:%s", stdout, stderr)
	}

	defaultStdout, _, _ := runCommandInDir(t, parent, "scan", "--format=json", "scan-preview")
	if strings.Contains(defaultStdout, "patch_outputs") {
		t.Fatalf("default JSON contains patch_outputs: %s", defaultStdout)
	}
}

func TestRunScanWritePatchesWithAbsoluteInputDirectory(t *testing.T) {
	parent := t.TempDir()
	writePreviewFixture(t, parent, "scan-preview", false)
	inputDir := filepath.Join(parent, "scan-preview")
	outputDir := filepath.Join(parent, "patched")

	stdout, stderr, code := runCommand("scan", "--write-patches", outputDir, inputDir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Patch Output:")
	assertContains(t, stdout, "Written files: 1")
	assertContains(t, stdout, "Source: resources.yaml")
	assertContains(t, stdout, "Output: patched/resources.yaml")
	if strings.Contains(stdout, inputDir) || strings.Contains(stdout, parent) || strings.Contains(stderr, parent) {
		t.Fatalf("output contains absolute temp path\nstdout:%s\nstderr:%s", stdout, stderr)
	}
	assertContains(t, stdout, "[resources.yaml#document=6]")
	patched, err := os.ReadFile(filepath.Join(outputDir, "resources.yaml"))
	if err != nil {
		t.Fatalf("read patched output: %v", err)
	}
	if strings.Contains(string(patched), "    name: api\n    namespace: prod") {
		t.Fatalf("patched output still contains removed subject:\n%s", patched)
	}
}

func TestRunScanWritePatchesJSONWithAbsoluteInputDirectoryUsesRelativeSources(t *testing.T) {
	parent := t.TempDir()
	writePreviewFixture(t, parent, "scan-preview", false)
	inputDir := filepath.Join(parent, "scan-preview")
	outputDir := filepath.Join(parent, "patched")

	stdout, stderr, code := runCommand("scan", "--format=json", "--write-patches", outputDir, inputDir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	if strings.Contains(stdout, inputDir) || strings.Contains(stdout, parent) || strings.Contains(stderr, parent) {
		t.Fatalf("JSON output contains absolute temp path\nstdout:%s\nstderr:%s", stdout, stderr)
	}
	report := assertValidJSONReport(t, stdout)
	if len(report.Findings) != 1 || report.Findings[0].Remediation == nil {
		t.Fatalf("report missing finding/remediation: %#v", report)
	}
	for _, source := range report.Findings[0].SourceReferences {
		if strings.Contains(source, inputDir) || !strings.Contains(source, "resources.yaml#document=") {
			t.Fatalf("source reference not relative: %q", source)
		}
	}
	for _, evidence := range report.Findings[0].Evidence {
		if strings.Contains(evidence.Source, inputDir) || strings.Contains(evidence.Detail, inputDir) {
			t.Fatalf("evidence contains absolute input path: %#v", evidence)
		}
	}
	for _, option := range report.Findings[0].Remediation.Options {
		for _, change := range option.Changes {
			if strings.Contains(change.SourceReference, inputDir) || !strings.Contains(change.SourceReference, "resources.yaml#document=") {
				t.Fatalf("change source reference not relative: %#v", change)
			}
		}
	}
	if report.PatchOutputs == nil {
		t.Fatal("patch_outputs = nil")
	}
	for _, output := range *report.PatchOutputs {
		if strings.Contains(output.Source, inputDir) || strings.Contains(output.Output, inputDir) {
			t.Fatalf("patch output contains absolute input path: %#v", output)
		}
	}
}

func TestRunScanValidatePatchesRequiresWritePatchesAndRejectsExtraArgs(t *testing.T) {
	stdout, stderr, code := runCommand("scan", "--validate-patches", safeFixture)
	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "--validate-patches requires --write-patches")

	parent := t.TempDir()
	writeSplitPreviewFixture(t, parent, "scan-preview")
	stdout, stderr, code = runCommandInDir(t, parent, "scan", "--write-patches", "patched", "--validate-patches", "scan-preview", "extra")
	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "scan requires exactly one directory argument")
}

func TestRunScanValidatePatchesUsesCompleteOverlayAndReportsRemediated(t *testing.T) {
	parent := t.TempDir()
	writeSplitPreviewFixture(t, parent, "scan-preview")
	inputPath := filepath.Join(parent, "scan-preview", "rbac.yaml")
	original, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatalf("read input: %v", err)
	}

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--write-patches", "patched", "--validate-patches", "scan-preview")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Patch Output:")
	assertContains(t, stdout, "Written files: 1")
	assertContains(t, stdout, "Validation:")
	assertContains(t, stdout, ": remediated\n")
	assertContains(t, stdout, "Summary: PP-K8S-001 no longer appears in patched output.")
	if strings.Contains(stdout, parent) || strings.Contains(stderr, parent) {
		t.Fatalf("validation output contains temp path\nstdout:%s\nstderr:%s", stdout, stderr)
	}
	for _, value := range []string{
		"FAKE_CLI_SECRET_DATA_VALUE_DO_NOT_RETAIN",
		"FAKE_CLI_SECRET_STRINGDATA_VALUE_DO_NOT_RETAIN",
	} {
		if strings.Contains(stdout, value) || strings.Contains(stderr, value) {
			t.Fatalf("validation output contains secret value %q\nstdout:%s\nstderr:%s", value, stdout, stderr)
		}
	}
	after, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatalf("read input after scan: %v", err)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("input file changed:\nafter:\n%s\nbefore:\n%s", after, original)
	}
	if got := listDirNames(t, filepath.Join(parent, "patched")); !reflect.DeepEqual(got, []string{"rbac.yaml"}) {
		t.Fatalf("patched output entries = %#v, want only rbac.yaml", got)
	}
}

func TestRunScanValidatePatchesJSONOutputIsStructured(t *testing.T) {
	parent := t.TempDir()
	writeSplitPreviewFixture(t, parent, "scan-preview")

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--write-patches", "patched", "--validate-patches", "scan-preview")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if len(report.Validation) != 1 {
		t.Fatalf("validation = %#v, want one result", report.Validation)
	}
	result := report.Validation[0]
	if result.RuleID != "PP-K8S-001" || result.Status != "remediated" || result.Summary == "" {
		t.Fatalf("validation result = %#v", result)
	}
	if strings.Contains(stdout, parent) || strings.Contains(stderr, parent) {
		t.Fatalf("JSON validation output contains temp path\nstdout:%s\nstderr:%s", stdout, stderr)
	}
	for _, value := range []string{
		"FAKE_CLI_SECRET_DATA_VALUE_DO_NOT_RETAIN",
		"FAKE_CLI_SECRET_STRINGDATA_VALUE_DO_NOT_RETAIN",
	} {
		if strings.Contains(stdout, value) || strings.Contains(stderr, value) {
			t.Fatalf("JSON validation output contains secret value %q\nstdout:%s\nstderr:%s", value, stdout, stderr)
		}
	}
	assertExactlyOneTrailingNewline(t, stdout)
}

func TestRunScanValidatePatchesDoesNotAcceptPartialPatchOutputAsProof(t *testing.T) {
	parent := t.TempDir()
	writePartialValidationFixture(t, parent, "scan-partial")

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--write-patches", "patched", "--validate-patches", "scan-partial")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Validation:")
	assertContains(t, stdout, ": failed\n")
	assertContains(t, stdout, "Summary: PP-K8S-001 still appears after rescanning patched output.")
	if strings.Contains(stdout, "FAKE_VALIDATION_OVERLAY_SECRET_VALUE_DO_NOT_RETAIN") || strings.Contains(stderr, "FAKE_VALIDATION_OVERLAY_SECRET_VALUE_DO_NOT_RETAIN") {
		t.Fatalf("validation output contains overlay Secret value\nstdout:%s\nstderr:%s", stdout, stderr)
	}
	partialFindings, _, err := scanDirectory(filepath.Join(parent, "patched"))
	if err != nil {
		t.Fatalf("scan partial output: %v", err)
	}
	if len(partialFindings) != 0 {
		t.Fatalf("partial patch output findings = %#v, want none to prove partial scan would be misleading", partialFindings)
	}
	if got := listDirNames(t, filepath.Join(parent, "patched")); !reflect.DeepEqual(got, []string{"binding-a.yaml"}) {
		t.Fatalf("patched output entries = %#v, want only generated patched copy", got)
	}
}

func TestRunScanValidatePatchesSkippedWhenNoPatchesWritten(t *testing.T) {
	parent := t.TempDir()
	outputRoot := filepath.Join(parent, "patched")

	stdout, stderr, code := runCommand("scan", "--write-patches", outputRoot, "--validate-patches", vulnerableFixture)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Validation:")
	assertContains(t, stdout, ": skipped\n")
	assertContains(t, stdout, "Summary: No written patch output was available to validate this finding.")
	if _, err := os.Stat(outputRoot); !os.IsNotExist(err) {
		t.Fatalf("outputRoot stat err = %v, want not exist", err)
	}
}

func TestRunScanValidatePatchesScanErrorLeavesStdoutEmptyAndCleansOverlay(t *testing.T) {
	parent := t.TempDir()
	writeSplitPreviewFixture(t, parent, "scan-preview")
	originalScanValidationDirectory := scanValidationDirectory
	var overlay string
	scanValidationDirectory = func(dir string) ([]analysis.Finding, *graph.Graph, error) {
		overlay = dir
		return nil, nil, errors.New("controlled validation scan failure")
	}
	defer func() {
		scanValidationDirectory = originalScanValidationDirectory
	}()

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--write-patches", "patched", "--validate-patches", "scan-preview")

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "validate patch output")
	assertContains(t, stderr, "controlled validation scan failure")
	if overlay == "" {
		t.Fatal("validation scan was not called")
	}
	if _, err := os.Stat(overlay); !os.IsNotExist(err) {
		t.Fatalf("validation overlay stat err = %v, want cleaned up", err)
	}
	if strings.Contains(stderr, overlay) || strings.Contains(stderr, parent) {
		t.Fatalf("stderr contains temp path: %q", stderr)
	}
}

func TestRunScanValidatePatchesCombinedWithPreviewIsDeterministic(t *testing.T) {
	parent := t.TempDir()
	writeSplitPreviewFixture(t, parent, "scan-preview")
	firstOut, firstErr, firstCode := runCommandInDir(t, parent, "scan", "--preview-patches", "--write-patches", "patched-a", "--validate-patches", "scan-preview")
	secondOut, secondErr, secondCode := runCommandInDir(t, parent, "scan", "--preview-patches", "--write-patches", "patched-b", "--validate-patches", "scan-preview")

	assertCode(t, firstCode, 1)
	assertCode(t, secondCode, 1)
	assertString(t, "first stderr", firstErr, "")
	assertString(t, "second stderr", secondErr, "")
	normalizedSecond := strings.ReplaceAll(secondOut, "patched-b/", "patched-a/")
	assertString(t, "stdout", normalizedSecond, firstOut)
	assertContains(t, firstOut, "Patch Preview:")
	assertContains(t, firstOut, "Validation:")
}

func TestRunScanWritePatchesWithAbsoluteInputDirectoryAndSpacedFilenameUsesRelativeSources(t *testing.T) {
	parent := t.TempDir()
	writePreviewFixture(t, parent, "scan-preview", false)
	renameFixtureFile(t, filepath.Join(parent, "scan-preview"), "resources.yaml", "resources file.yaml")
	inputDir := filepath.Join(parent, "scan-preview")
	outputDir := filepath.Join(parent, "patched")

	stdout, stderr, code := runCommand("scan", "--write-patches", outputDir, inputDir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	if strings.Contains(stdout, inputDir) || strings.Contains(stdout, parent) || strings.Contains(stderr, parent) {
		t.Fatalf("output contains absolute temp path\nstdout:%s\nstderr:%s", stdout, stderr)
	}
	assertContains(t, stdout, "Source: resources file.yaml")
	assertContains(t, stdout, "Output: patched/resources file.yaml")
	assertContains(t, stdout, "[resources file.yaml#document=6]")
	if _, err := os.Stat(filepath.Join(outputDir, "resources file.yaml")); err != nil {
		t.Fatalf("stat spaced patched output: %v", err)
	}

	jsonStdout, jsonStderr, jsonCode := runCommand("scan", "--format=json", "--write-patches", filepath.Join(parent, "patched-json"), inputDir)
	assertCode(t, jsonCode, 1)
	assertString(t, "json stderr", jsonStderr, "")
	if strings.Contains(jsonStdout, inputDir) || strings.Contains(jsonStdout, parent) || strings.Contains(jsonStderr, parent) {
		t.Fatalf("JSON output contains absolute temp path\nstdout:%s\nstderr:%s", jsonStdout, jsonStderr)
	}
	report := assertValidJSONReport(t, jsonStdout)
	if len(report.Findings) != 1 || report.Findings[0].Remediation == nil {
		t.Fatalf("report missing finding/remediation: %#v", report)
	}
	for _, source := range report.Findings[0].SourceReferences {
		if strings.Contains(source, inputDir) || !strings.Contains(source, "resources file.yaml#document=") {
			t.Fatalf("source reference not relative for spaced filename: %q", source)
		}
	}
	for _, option := range report.Findings[0].Remediation.Options {
		for _, change := range option.Changes {
			if strings.Contains(change.SourceReference, inputDir) || !strings.Contains(change.SourceReference, "resources file.yaml#document=") {
				t.Fatalf("change source reference not relative for spaced filename: %#v", change)
			}
		}
	}
}

func TestRunScanPreviewPatchesWithAbsoluteInputDirectoryUsesRelativeSources(t *testing.T) {
	parent := t.TempDir()
	writePreviewFixture(t, parent, "scan-preview", false)
	inputDir := filepath.Join(parent, "scan-preview")

	stdout, stderr, code := runCommand("scan", "--preview-patches", inputDir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	if strings.Contains(stdout, inputDir) || strings.Contains(stdout, parent) || strings.Contains(stderr, parent) {
		t.Fatalf("preview output contains absolute temp path\nstdout:%s\nstderr:%s", stdout, stderr)
	}
	assertContains(t, stdout, "File: resources.yaml")
	assertContains(t, stdout, "--- resources.yaml\n")
	if _, err := os.Stat(filepath.Join(parent, "patched")); !os.IsNotExist(err) {
		t.Fatalf("unexpected patched directory stat err = %v", err)
	}

	jsonStdout, jsonStderr, jsonCode := runCommand("scan", "--format=json", "--preview-patches", inputDir)
	assertCode(t, jsonCode, 1)
	assertString(t, "json stderr", jsonStderr, "")
	if strings.Contains(jsonStdout, inputDir) || strings.Contains(jsonStdout, parent) || strings.Contains(jsonStderr, parent) {
		t.Fatalf("preview JSON contains absolute temp path\nstdout:%s\nstderr:%s", jsonStdout, jsonStderr)
	}
	report := assertValidJSONReport(t, jsonStdout)
	previewCount := 0
	for _, option := range report.Findings[0].Remediation.Options {
		for _, preview := range option.PatchPreviews {
			previewCount++
			if preview.File != "" && preview.File != "resources.yaml" {
				t.Fatalf("preview file not relative: %#v", preview)
			}
		}
	}
	if previewCount == 0 {
		t.Fatalf("no previews in absolute-input report: %#v", report.Findings[0].Remediation)
	}
}

func TestRunScanPreviewPatchesWithAbsoluteInputDirectoryAndSpacedFilenameUsesRelativeSources(t *testing.T) {
	parent := t.TempDir()
	writePreviewFixture(t, parent, "scan-preview", false)
	renameFixtureFile(t, filepath.Join(parent, "scan-preview"), "resources.yaml", "resources file.yaml")
	inputDir := filepath.Join(parent, "scan-preview")

	stdout, stderr, code := runCommand("scan", "--preview-patches", inputDir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	if strings.Contains(stdout, inputDir) || strings.Contains(stdout, parent) || strings.Contains(stderr, parent) {
		t.Fatalf("preview output contains absolute temp path\nstdout:%s\nstderr:%s", stdout, stderr)
	}
	assertContains(t, stdout, "File: resources file.yaml")
	assertContains(t, stdout, "--- resources file.yaml\n")
	if _, err := os.Stat(filepath.Join(parent, "patched")); !os.IsNotExist(err) {
		t.Fatalf("unexpected patched directory stat err = %v", err)
	}

	jsonStdout, jsonStderr, jsonCode := runCommand("scan", "--format=json", "--preview-patches", inputDir)
	assertCode(t, jsonCode, 1)
	assertString(t, "json stderr", jsonStderr, "")
	if strings.Contains(jsonStdout, inputDir) || strings.Contains(jsonStdout, parent) || strings.Contains(jsonStderr, parent) {
		t.Fatalf("preview JSON contains absolute temp path\nstdout:%s\nstderr:%s", jsonStdout, jsonStderr)
	}
	report := assertValidJSONReport(t, jsonStdout)
	previewCount := 0
	for _, option := range report.Findings[0].Remediation.Options {
		for _, preview := range option.PatchPreviews {
			previewCount++
			if preview.File != "" && preview.File != "resources file.yaml" {
				t.Fatalf("preview file not relative for spaced filename: %#v", preview)
			}
		}
	}
	if previewCount == 0 {
		t.Fatalf("no previews in spaced absolute-input report: %#v", report.Findings[0].Remediation)
	}
}

func TestRunScanDefaultWithAbsoluteInputDirectoryUsesRelativeSources(t *testing.T) {
	parent := t.TempDir()
	writePreviewFixture(t, parent, "scan-preview", false)
	inputDir := filepath.Join(parent, "scan-preview")

	stdout, stderr, code := runCommand("scan", inputDir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	if strings.Contains(stdout, inputDir) || strings.Contains(stdout, parent) || strings.Contains(stderr, parent) {
		t.Fatalf("default output contains absolute temp path\nstdout:%s\nstderr:%s", stdout, stderr)
	}
	assertContains(t, stdout, "resources.yaml#document=6")
	if strings.Contains(stdout, "Patch Preview:") || strings.Contains(stdout, "Patch Output:") {
		t.Fatalf("default absolute-input output contains patch sections: %s", stdout)
	}

	jsonStdout, jsonStderr, jsonCode := runCommand("scan", "--format=json", inputDir)
	assertCode(t, jsonCode, 1)
	assertString(t, "json stderr", jsonStderr, "")
	if strings.Contains(jsonStdout, inputDir) || strings.Contains(jsonStdout, parent) || strings.Contains(jsonStderr, parent) {
		t.Fatalf("default JSON contains absolute temp path\nstdout:%s\nstderr:%s", jsonStdout, jsonStderr)
	}
	if strings.Contains(jsonStdout, "patch_outputs") || strings.Contains(jsonStdout, "patch_previews") {
		t.Fatalf("default JSON contains patch fields: %s", jsonStdout)
	}
}

func TestNormalizeDisplaySourceReferencesLeavesMalformedAndOutsideReferencesUnchanged(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	writePreviewFixture(t, parent, "scan", false)
	outside := filepath.Join(parent, "outside.yaml")
	if err := os.WriteFile(outside, []byte("kind: ConfigMap\n"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	values := []string{
		outside + "#document=1",
		filepath.Join(root, "resources.yaml") + "#document=1x",
		filepath.Join(root, "resources.yaml") + "#document=1#extra",
		filepath.Join(root, "resources.yaml") + "#document=",
		filepath.Join(root, "resources.yaml") + "#document=-1",
		filepath.Join(root, "resources.yaml") + "#document=0",
		filepath.Join(root, "resources.yaml") + "#document=999999999999999999999999999999",
	}
	input := strings.Join(values, " ")

	got := normalizeDisplaySourceReferences(root, input)

	assertString(t, "normalized", got, input)
}

func TestNormalizeDisplaySourceReferencesNormalizesAbsoluteAndRootPrefixedRelativeSources(t *testing.T) {
	parent := t.TempDir()
	writePreviewFixture(t, parent, "scan", false)
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

	input := "absolute=" + filepath.Join(parent, "scan", "resources.yaml") + "#document=1 relative=scan/resources.yaml#document=2 spaced=" + filepath.Join(parent, "scan", "resources file.yaml") + "#document=12"
	if err := os.WriteFile(filepath.Join(parent, "scan", "resources file.yaml"), []byte("kind: ConfigMap\n"), 0o600); err != nil {
		t.Fatalf("write spaced file: %v", err)
	}
	got := normalizeDisplaySourceReferences("scan", input)

	assertString(t, "normalized", got, "absolute=resources.yaml#document=1 relative=resources.yaml#document=2 spaced=resources file.yaml#document=12")
}

func TestRunScanReversedInputFileCreationOrderIsDeterministic(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fixture")
	writeSplitVulnerableFixture(t, dir, []string{"service.yaml", "deployment.yaml", "rbac.yaml", "secret.yaml"})
	firstOut, firstErr, firstCode := runCommand("scan", "--format=json", dir)

	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove fixture dir: %v", err)
	}
	writeSplitVulnerableFixture(t, dir, []string{"secret.yaml", "rbac.yaml", "deployment.yaml", "service.yaml"})
	secondOut, secondErr, secondCode := runCommand("scan", "--format=json", dir)

	assertCode(t, firstCode, 1)
	assertCode(t, secondCode, 1)
	assertString(t, "first stderr", firstErr, "")
	assertString(t, "second stderr", secondErr, "")
	assertString(t, "stdout", secondOut, firstOut)
}

func TestRunScanSecretFixtureValuesNeverAppearInOutput(t *testing.T) {
	for _, args := range [][]string{
		{"scan", vulnerableFixture},
		{"scan", "--format=json", vulnerableFixture},
		{"scan", "--format=sarif", vulnerableFixture},
		{"scan", safeFixture},
		{"scan", invalidFixture},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, stderr, _ := runCommand(args...)
			for _, value := range []string{
				"FAKE_CLI_SECRET_DATA_VALUE_DO_NOT_RETAIN",
				"FAKE_CLI_SECRET_STRINGDATA_VALUE_DO_NOT_RETAIN",
				"FAKE_CLI_SECRET_MALFORMED_VALUE_DO_NOT_RETAIN",
			} {
				if strings.Contains(stdout, value) {
					t.Fatalf("stdout contains secret value %q: %s", value, stdout)
				}
				if strings.Contains(stderr, value) {
					t.Fatalf("stderr contains secret value %q: %s", value, stderr)
				}
			}
		})
	}
}

func TestRunScanMultipleFindingsFollowAnalysisOrder(t *testing.T) {
	dir := writeMultiFindingFixture(t)
	stdout, stderr, code := runCommand("scan", "--format=json", dir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.FindingCount != 2 {
		t.Fatalf("finding_count = %d, want 2", report.FindingCount)
	}
	for i := 1; i < len(report.Findings); i++ {
		if report.Findings[i-1].ID > report.Findings[i].ID {
			t.Fatalf("findings are not in deterministic analysis order: %#v", report.Findings)
		}
	}
	for _, finding := range report.Findings {
		if finding.Remediation == nil {
			t.Fatalf("finding %s remediation = nil, want matching plan", finding.ID)
		}
		if finding.Remediation.FindingID != finding.ID {
			t.Fatalf("remediation finding_id = %q, want %q", finding.Remediation.FindingID, finding.ID)
		}
	}
}

func TestProjectFindingRejectsMissingNode(t *testing.T) {
	g := graph.New()
	endpoint := mustAddNode(t, g, graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/public-api"))
	workload := mustAddNode(t, g, graph.NewNode(graph.Workload, "kubernetes://prod/deployment/api"))
	serviceAccount := mustAddNode(t, g, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/api"))
	route := mustAddEdge(t, g, graph.NewEdge(graph.RoutesTo, endpoint.ID, workload.ID, graph.SourceEvidence{Source: "route", Detail: "route"}))
	runsAs := mustAddEdge(t, g, graph.NewEdge(graph.RunsAs, workload.ID, serviceAccount.ID, graph.SourceEvidence{Source: "runs-as", Detail: "runs-as"}))
	canRead := graph.NewEdge(graph.CanRead, serviceAccount.ID, graph.NodeID("node:missing-secret"), graph.SourceEvidence{Source: "can-read", Detail: "can-read"})
	finding := analysis.Finding{
		ID:       "finding:test",
		NodeIDs:  []graph.NodeID{endpoint.ID, workload.ID, serviceAccount.ID, graph.NodeID("node:missing-secret")},
		EdgeIDs:  []graph.EdgeID{route.ID, runsAs.ID, canRead.ID},
		Evidence: []analysis.FindingEvidence{{EdgeID: route.ID, Kind: route.Kind, Source: route.Evidence}, {EdgeID: runsAs.ID, Kind: runsAs.Kind, Source: runsAs.Evidence}, {EdgeID: canRead.ID, Kind: canRead.Kind, Source: canRead.Evidence}},
	}

	_, err := newScanReport(".", []analysis.Finding{finding}, g, nil, nil, nil, false, nil, nil, nil)
	if err == nil {
		t.Fatal("newScanReport error = nil, want missing node error")
	}
	if !strings.Contains(err.Error(), "missing node") {
		t.Fatalf("error = %q, want missing node", err)
	}
}

func TestProjectFindingRejectsMissingEdge(t *testing.T) {
	g := graph.New()
	endpoint := mustAddNode(t, g, graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/public-api"))
	workload := mustAddNode(t, g, graph.NewNode(graph.Workload, "kubernetes://prod/deployment/api"))
	serviceAccount := mustAddNode(t, g, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/api"))
	secret := mustAddNode(t, g, graph.NewNode(graph.Secret, "kubernetes://prod/secret/database-password"))
	route := mustAddEdge(t, g, graph.NewEdge(graph.RoutesTo, endpoint.ID, workload.ID, graph.SourceEvidence{Source: "route", Detail: "route"}))
	runsAs := mustAddEdge(t, g, graph.NewEdge(graph.RunsAs, workload.ID, serviceAccount.ID, graph.SourceEvidence{Source: "runs-as", Detail: "runs-as"}))
	canRead := graph.NewEdge(graph.CanRead, serviceAccount.ID, secret.ID, graph.SourceEvidence{Source: "can-read", Detail: "can-read"})
	finding := analysis.Finding{
		ID:       "finding:test",
		NodeIDs:  []graph.NodeID{endpoint.ID, workload.ID, serviceAccount.ID, secret.ID},
		EdgeIDs:  []graph.EdgeID{route.ID, runsAs.ID, canRead.ID},
		Evidence: []analysis.FindingEvidence{{EdgeID: route.ID, Kind: route.Kind, Source: route.Evidence}, {EdgeID: runsAs.ID, Kind: runsAs.Kind, Source: runsAs.Evidence}, {EdgeID: canRead.ID, Kind: canRead.Kind, Source: canRead.Evidence}},
	}

	_, err := newScanReport(".", []analysis.Finding{finding}, g, nil, nil, nil, false, nil, nil, nil)
	if err == nil {
		t.Fatal("newScanReport error = nil, want missing edge error")
	}
	if !strings.Contains(err.Error(), "missing edge") {
		t.Fatalf("error = %q, want missing edge", err)
	}
}

func TestWriteScanResultRejectsUnrelatedFirstEdgeWithEmptyStdout(t *testing.T) {
	fixture := projectionFixtureWithValidFinding(t)
	otherEndpoint := mustAddNode(t, fixture.graph, graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/other-api"))
	edge := mustAddEdge(t, fixture.graph, graph.NewEdge(graph.RoutesTo, otherEndpoint.ID, fixture.workload.ID, graph.SourceEvidence{Source: "other-route", Detail: "other route"}))
	fixture.finding.EdgeIDs[0] = edge.ID
	fixture.finding.Evidence[0] = analysis.FindingEvidence{EdgeID: edge.ID, Kind: edge.Kind, Source: edge.Evidence}

	stdout, stderr, code := writeScanResultForTest([]analysis.Finding{fixture.finding}, fixture.graph, scanFormatHuman)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "internal scan error")
	assertContains(t, stderr, "build remediation plans")
	assertContains(t, stderr, "connects")
}

func TestWriteScanResultRejectsReversedEdgeWithEmptyStdout(t *testing.T) {
	fixture := projectionFixtureWithValidFinding(t)
	edge := mustAddEdge(t, fixture.graph, graph.NewEdge(graph.RoutesTo, fixture.workload.ID, fixture.endpoint.ID, graph.SourceEvidence{Source: "reversed-route", Detail: "reversed route"}))
	fixture.finding.EdgeIDs[0] = edge.ID
	fixture.finding.Evidence[0] = analysis.FindingEvidence{EdgeID: edge.ID, Kind: edge.Kind, Source: edge.Evidence}

	stdout, _, code := writeScanResultForTest([]analysis.Finding{fixture.finding}, fixture.graph, scanFormatHuman)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
}

func TestWriteScanResultRejectsWrongMiddleEdgeWithEmptyStdout(t *testing.T) {
	fixture := projectionFixtureWithValidFinding(t)
	otherServiceAccount := mustAddNode(t, fixture.graph, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/other-api"))
	edge := mustAddEdge(t, fixture.graph, graph.NewEdge(graph.RunsAs, fixture.workload.ID, otherServiceAccount.ID, graph.SourceEvidence{Source: "wrong-runs-as", Detail: "wrong runs as"}))
	fixture.finding.EdgeIDs[1] = edge.ID
	fixture.finding.Evidence[1] = analysis.FindingEvidence{EdgeID: edge.ID, Kind: edge.Kind, Source: edge.Evidence}

	stdout, _, code := writeScanResultForTest([]analysis.Finding{fixture.finding}, fixture.graph, scanFormatHuman)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
}

func TestWriteScanResultRejectsWrongLastEdgeWithEmptyStdout(t *testing.T) {
	fixture := projectionFixtureWithValidFinding(t)
	otherSecret := mustAddNode(t, fixture.graph, graph.NewNode(graph.Secret, "kubernetes://prod/secret/other-password"))
	edge := mustAddEdge(t, fixture.graph, graph.NewEdge(graph.CanRead, fixture.serviceAccount.ID, otherSecret.ID, graph.SourceEvidence{Source: "wrong-can-read", Detail: "wrong can read"}))
	fixture.finding.EdgeIDs[2] = edge.ID
	fixture.finding.Evidence[2] = analysis.FindingEvidence{EdgeID: edge.ID, Kind: edge.Kind, Source: edge.Evidence}

	stdout, _, code := writeScanResultForTest([]analysis.Finding{fixture.finding}, fixture.graph, scanFormatHuman)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
}

func TestWriteScanResultRejectsEdgeCountMismatchWithEmptyStdout(t *testing.T) {
	fixture := projectionFixtureWithValidFinding(t)
	fixture.finding.EdgeIDs = fixture.finding.EdgeIDs[:2]
	fixture.finding.Evidence = fixture.finding.Evidence[:2]

	stdout, stderr, code := writeScanResultForTest([]analysis.Finding{fixture.finding}, fixture.graph, scanFormatHuman)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "path edges")
}

func TestWriteScanResultValidOneNodeFindingProjectsInHumanJSONAndSARIF(t *testing.T) {
	g := graph.New()
	workflow := graph.NewNode(graph.Workflow, "githubactions://.github/workflows/permissions.yml")
	workflow.Evidence = []graph.SourceEvidence{{Source: "/repo/.github/workflows/permissions.yml#document=1", Detail: "github actions workflow"}}
	workflow = mustAddNode(t, g, workflow)
	finding := analysis.Finding{
		ID:               "finding:PP-GHA-003:test",
		RuleID:           analysis.RuleGitHubActionsDangerousPermissions,
		Title:            "pull_request_target workflow grants dangerous token permissions",
		Severity:         analysis.SeverityHigh,
		Summary:          "GitHub Actions workflow .github/workflows/permissions.yml grants permissions: write-all at workflow scope under pull_request_target.",
		NodeIDs:          []graph.NodeID{workflow.ID},
		EdgeIDs:          nil,
		Evidence:         nil,
		SourceReferences: []string{"/repo/.github/workflows/permissions.yml#document=1"},
	}

	humanStdout, humanStderr, humanCode := writeScanResultForTest([]analysis.Finding{finding}, g, scanFormatHuman)
	jsonStdout, jsonStderr, jsonCode := writeScanResultForTest([]analysis.Finding{finding}, g, scanFormatJSON)
	sarifStdout, sarifStderr, sarifCode := writeScanResultForTest([]analysis.Finding{finding}, g, scanFormatSARIF)

	assertCode(t, humanCode, 1)
	assertString(t, "human stderr", humanStderr, "")
	assertContains(t, humanStdout, "Rule: PP-GHA-003\n")
	assertContains(t, humanStdout, "permissions: write-all")
	assertContains(t, humanStdout, "Workflow githubactions://.github/workflows/permissions.yml")
	assertCode(t, jsonCode, 1)
	assertString(t, "json stderr", jsonStderr, "")
	report := assertValidJSONReport(t, jsonStdout)
	if len(report.Findings) != 1 || len(report.Findings[0].Path) != 1 || len(report.Findings[0].Evidence) != 0 {
		t.Fatalf("JSON one-node finding = %#v, want one path node and no evidence", report.Findings)
	}
	assertCode(t, sarifCode, 1)
	assertString(t, "sarif stderr", sarifStderr, "")
	sarif := assertValidSARIFReport(t, sarifStdout)
	if len(sarif.Runs[0].Results) != 1 {
		t.Fatalf("SARIF results = %#v, want one", sarif.Runs[0].Results)
	}
	if got := sarif.Runs[0].Results[0].RuleID; got != "PP-GHA-003" {
		t.Fatalf("SARIF ruleId = %q, want PP-GHA-003", got)
	}
}

func TestWriteScanResultRejectsMissingNodeForOneNodeFindingWithEmptyStdout(t *testing.T) {
	g := graph.New()
	finding := analysis.Finding{
		ID:      "finding:PP-GHA-003:test",
		RuleID:  analysis.RuleGitHubActionsDangerousPermissions,
		NodeIDs: []graph.NodeID{graph.NodeID("node:missing-workflow")},
	}

	stdout, stderr, code := writeScanResultForTest([]analysis.Finding{finding}, g, scanFormatHuman)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "internal scan error")
	assertContains(t, stderr, "missing node")
}

func TestWriteScanResultRejectsOneNodeFindingWithUnexpectedEdgeWithEmptyStdout(t *testing.T) {
	g := graph.New()
	workflow := mustAddNode(t, g, graph.NewNode(graph.Workflow, "githubactions://.github/workflows/permissions.yml"))
	job := mustAddNode(t, g, graph.NewNode(graph.WorkflowJob, "githubactions://.github/workflows/permissions.yml/job/test"))
	defines := mustAddEdge(t, g, graph.NewEdge(graph.DefinesJob, workflow.ID, job.ID, graph.SourceEvidence{Source: "permissions.yml", Detail: "defines"}))
	finding := analysis.Finding{
		ID:       "finding:PP-GHA-003:test",
		RuleID:   analysis.RuleGitHubActionsDangerousPermissions,
		NodeIDs:  []graph.NodeID{workflow.ID},
		EdgeIDs:  []graph.EdgeID{defines.ID},
		Evidence: []analysis.FindingEvidence{{EdgeID: defines.ID, Kind: defines.Kind, Source: defines.Evidence}},
	}

	stdout, stderr, code := writeScanResultForTest([]analysis.Finding{finding}, g, scanFormatHuman)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "internal scan error")
	assertContains(t, stderr, "one path node")
}

func TestWriteScanResultValidFindingProjectsInHumanAndJSON(t *testing.T) {
	fixture := projectionFixtureWithValidFinding(t)

	humanStdout, humanStderr, humanCode := writeScanResultForTest([]analysis.Finding{fixture.finding}, fixture.graph, scanFormatHuman)
	jsonStdout, jsonStderr, jsonCode := writeScanResultForTest([]analysis.Finding{fixture.finding}, fixture.graph, scanFormatJSON)

	assertCode(t, humanCode, 1)
	assertString(t, "human stderr", humanStderr, "")
	assertContains(t, humanStdout, "Finding count: 1\n")
	assertContains(t, humanStdout, "RoutesTo "+string(fixture.route.ID))
	assertCode(t, jsonCode, 1)
	assertString(t, "json stderr", jsonStderr, "")
	report := assertValidJSONReport(t, jsonStdout)
	if report.FindingCount != 1 {
		t.Fatalf("json finding_count = %d, want 1", report.FindingCount)
	}
	if got := report.Findings[0].Path[0].ID; got != string(fixture.endpoint.ID) {
		t.Fatalf("json path[0].id = %q, want %q", got, fixture.endpoint.ID)
	}
	if got := report.Findings[0].Evidence[0].EdgeID; got != string(fixture.route.ID) {
		t.Fatalf("json evidence[0].edge_id = %q, want %q", got, fixture.route.ID)
	}
}

func TestWriteScanResultRejectsLateInconsistencyWithoutPartialOutput(t *testing.T) {
	fixture := projectionFixtureWithValidFinding(t)
	otherSecret := mustAddNode(t, fixture.graph, graph.NewNode(graph.Secret, "kubernetes://prod/secret/late-other-password"))
	edge := mustAddEdge(t, fixture.graph, graph.NewEdge(graph.CanRead, fixture.serviceAccount.ID, otherSecret.ID, graph.SourceEvidence{Source: "late-wrong-can-read", Detail: "late wrong can read"}))
	fixture.finding.EdgeIDs[2] = edge.ID
	fixture.finding.Evidence[2] = analysis.FindingEvidence{EdgeID: edge.ID, Kind: edge.Kind, Source: edge.Evidence}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := writeScanResult([]analysis.Finding{fixture.finding}, fixture.graph, ".", scanFormatHuman, false, "", false, nil, &stdout, &stderr)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout.String(), "")
	assertOneLineStderr(t, stderr.String())
}

func TestWriteScanResultMissingNodeReturnsTwoWithEmptyStdout(t *testing.T) {
	g := graph.New()
	endpoint := mustAddNode(t, g, graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/public-api"))
	workload := mustAddNode(t, g, graph.NewNode(graph.Workload, "kubernetes://prod/deployment/api"))
	serviceAccount := mustAddNode(t, g, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/api"))
	route := mustAddEdge(t, g, graph.NewEdge(graph.RoutesTo, endpoint.ID, workload.ID, graph.SourceEvidence{Source: "route", Detail: "route"}))
	runsAs := mustAddEdge(t, g, graph.NewEdge(graph.RunsAs, workload.ID, serviceAccount.ID, graph.SourceEvidence{Source: "runs-as", Detail: "runs-as"}))
	canRead := graph.NewEdge(graph.CanRead, serviceAccount.ID, graph.NodeID("node:missing-secret"), graph.SourceEvidence{Source: "can-read", Detail: "can-read"})
	finding := analysis.Finding{
		ID:       "finding:test",
		NodeIDs:  []graph.NodeID{endpoint.ID, workload.ID, serviceAccount.ID, graph.NodeID("node:missing-secret")},
		EdgeIDs:  []graph.EdgeID{route.ID, runsAs.ID, canRead.ID},
		Evidence: []analysis.FindingEvidence{{EdgeID: route.ID, Kind: route.Kind, Source: route.Evidence}, {EdgeID: runsAs.ID, Kind: runsAs.Kind, Source: runsAs.Evidence}, {EdgeID: canRead.ID, Kind: canRead.Kind, Source: canRead.Evidence}},
	}
	var stdout, stderr bytes.Buffer

	code := writeScanResult([]analysis.Finding{finding}, g, ".", scanFormatHuman, false, "", false, nil, &stdout, &stderr)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout.String(), "")
	assertOneLineStderr(t, stderr.String())
	assertContains(t, stderr.String(), "internal scan error")
	assertContains(t, stderr.String(), "missing node")
}

func TestRunScanFailingStdoutWriterReturnsTwo(t *testing.T) {
	var stderr bytes.Buffer

	code := run([]string{"scan", safeFixture}, failingWriter{}, &stderr)

	assertCode(t, code, 2)
	assertOneLineStderr(t, stderr.String())
	assertContains(t, stderr.String(), "write scan report")
}

func runCommand(args ...string) (string, string, int) {
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

func runCommandInDir(t *testing.T, dir string, args ...string) (string, string, int) {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	defer func() {
		if err := os.Chdir(cwd); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	}()
	return runCommand(args...)
}

func writeScanResultForTest(findings []analysis.Finding, g *graph.Graph, format scanFormat) (string, string, int) {
	var stdout, stderr bytes.Buffer
	code := writeScanResult(findings, g, ".", format, false, "", false, nil, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

type projectionFixture struct {
	graph          *graph.Graph
	endpoint       graph.Node
	workload       graph.Node
	serviceAccount graph.Node
	secret         graph.Node
	route          graph.Edge
	runsAs         graph.Edge
	canRead        graph.Edge
	finding        analysis.Finding
}

func projectionFixtureWithValidFinding(t *testing.T) projectionFixture {
	t.Helper()
	g := graph.New()
	endpoint := mustAddNode(t, g, graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/public-api"))
	workload := mustAddNode(t, g, graph.NewNode(graph.Workload, "kubernetes://prod/deployment/api"))
	serviceAccount := mustAddNode(t, g, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/api"))
	secret := mustAddNode(t, g, graph.NewNode(graph.Secret, "kubernetes://prod/secret/database-password"))
	route := mustAddEdge(t, g, graph.NewEdge(graph.RoutesTo, endpoint.ID, workload.ID, graph.SourceEvidence{Source: "route", Detail: "route"}))
	runsAs := mustAddEdge(t, g, graph.NewEdge(graph.RunsAs, workload.ID, serviceAccount.ID, graph.SourceEvidence{Source: "runs-as", Detail: "runs-as"}))
	canRead := mustAddEdge(t, g, graph.NewEdge(graph.CanRead, serviceAccount.ID, secret.ID, graph.SourceEvidence{Source: "can-read", Detail: "can-read"}))
	finding := analysis.Finding{
		ID:               "finding:test",
		RuleID:           analysis.RulePublicWorkloadCanReadSecret,
		Title:            "Public workload can read Kubernetes Secret",
		Severity:         analysis.SeverityHigh,
		Summary:          "test finding",
		NodeIDs:          []graph.NodeID{endpoint.ID, workload.ID, serviceAccount.ID, secret.ID},
		EdgeIDs:          []graph.EdgeID{route.ID, runsAs.ID, canRead.ID},
		Evidence:         []analysis.FindingEvidence{{EdgeID: route.ID, Kind: route.Kind, Source: route.Evidence}, {EdgeID: runsAs.ID, Kind: runsAs.Kind, Source: runsAs.Evidence}, {EdgeID: canRead.ID, Kind: canRead.Kind, Source: canRead.Evidence}},
		SourceReferences: []string{route.Evidence.Source, runsAs.Evidence.Source, canRead.Evidence.Source},
	}
	return projectionFixture{
		graph:          g,
		endpoint:       endpoint,
		workload:       workload,
		serviceAccount: serviceAccount,
		secret:         secret,
		route:          route,
		runsAs:         runsAs,
		canRead:        canRead,
		finding:        finding,
	}
}

type cliJSONReport struct {
	Findings                []cliJSONFinding      `json:"findings"`
	FindingCount            int                   `json:"finding_count"`
	ConfigApplied           bool                  `json:"config_applied,omitempty"`
	DisabledRules           []string              `json:"disabled_rules,omitempty"`
	SuppressedFindingsCount *int                  `json:"suppressed_findings_count,omitempty"`
	BaselineWritten         *cliJSONBaseline      `json:"baseline_written,omitempty"`
	BaselineComparison      *cliJSONComparison    `json:"baseline_comparison,omitempty"`
	PatchOutputs            *[]cliJSONPatchOutput `json:"patch_outputs,omitempty"`
	Validation              []cliJSONValidation   `json:"validation,omitempty"`
}

type cliJSONBaseline struct {
	SuppressionsGenerated int `json:"suppressions_generated"`
}

type cliJSONComparison struct {
	NewFindingsCount      int      `json:"new_findings_count"`
	ExistingFindingsCount int      `json:"existing_findings_count"`
	ResolvedFindingsCount int      `json:"resolved_findings_count"`
	ResolvedFindingIDs    []string `json:"resolved_finding_ids"`
}

type cliJSONFinding struct {
	ID                string                    `json:"id"`
	RuleID            string                    `json:"rule_id"`
	Title             string                    `json:"title"`
	Severity          string                    `json:"severity"`
	Summary           string                    `json:"summary"`
	Path              []cliJSONPathNode         `json:"path"`
	Evidence          []cliJSONEvidence         `json:"evidence"`
	SourceReferences  []string                  `json:"source_references"`
	RiskSignal        *cliJSONRiskSignal        `json:"risk_signal,omitempty"`
	BucketSensitivity *cliJSONBucketSensitivity `json:"bucket_sensitivity,omitempty"`
	BaselineStatus    string                    `json:"baseline_status,omitempty"`
	Ranking           *cliJSONRanking           `json:"ranking,omitempty"`
	Remediation       *cliJSONRemediation       `json:"remediation,omitempty"`
}

type cliJSONRanking struct {
	Method  string   `json:"method"`
	Score   int      `json:"score"`
	Band    string   `json:"band"`
	Reasons []string `json:"reasons"`
}

type cliJSONRiskSignal struct {
	RuleID          string                `json:"rule_id"`
	SourceReference string                `json:"source_reference"`
	WorkflowFile    string                `json:"workflow_file"`
	JobID           string                `json:"job_id,omitempty"`
	StepIndex       *int                  `json:"step_index,omitempty"`
	Selectors       []cliJSONRiskSelector `json:"selectors,omitempty"`
	Permission      string                `json:"permission,omitempty"`
	Access          string                `json:"access,omitempty"`
	Summary         string                `json:"summary"`
}

type cliJSONRiskSelector struct {
	Field             string `json:"field"`
	MatchedExpression string `json:"matched_expression"`
}

type cliJSONBucketSensitivity struct {
	SensitivityLevel string                           `json:"sensitivity_level"`
	Reasons          []cliJSONBucketSensitivityReason `json:"reasons"`
}

type cliJSONBucketSensitivityReason struct {
	Source       string `json:"source"`
	MatchedToken string `json:"matched_token,omitempty"`
	Key          string `json:"key,omitempty"`
	Value        string `json:"value,omitempty"`
	SourceRef    string `json:"source_ref"`
}

type cliJSONPathNode struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type cliJSONEvidence struct {
	EdgeID string `json:"edge_id"`
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Detail string `json:"detail"`
}

type cliJSONRemediation struct {
	ID        string                     `json:"id"`
	FindingID string                     `json:"finding_id"`
	RuleID    string                     `json:"rule_id"`
	Summary   string                     `json:"summary"`
	Options   []cliJSONRemediationOption `json:"options"`
}

type cliJSONRemediationOption struct {
	Priority           int                        `json:"priority"`
	Action             string                     `json:"action"`
	Summary            string                     `json:"summary"`
	Rationale          string                     `json:"rationale"`
	RequiresAllChanges bool                       `json:"requires_all_changes"`
	Changes            []cliJSONRemediationChange `json:"changes"`
	Constraints        []string                   `json:"constraints,omitempty"`
	PatchPreviews      []cliJSONPatchPreview      `json:"patch_previews,omitempty"`
}

type cliJSONRemediationChange struct {
	Action           string                   `json:"action"`
	Target           cliJSONRemediationTarget `json:"target"`
	Summary          string                   `json:"summary"`
	SourceReference  string                   `json:"source_reference"`
	PermissionSHA256 string                   `json:"permission_sha256,omitempty"`
	MatchedVerb      string                   `json:"matched_verb,omitempty"`
	Subject          string                   `json:"subject,omitempty"`
	ActionRef        string                   `json:"action_ref,omitempty"`
	ReplacementSHA   string                   `json:"replacement_sha,omitempty"`
	ReplacementRef   string                   `json:"replacement_ref,omitempty"`
	PatchSupported   bool                     `json:"patch_supported,omitempty"`
	Advisory         bool                     `json:"advisory,omitempty"`
	Reason           string                   `json:"reason,omitempty"`
	SourceLine       int                      `json:"source_line,omitempty"`
	SourceColumn     int                      `json:"source_column,omitempty"`
}

type cliJSONRemediationTarget struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

type cliJSONPatchPreview struct {
	PlanID       string `json:"plan_id"`
	OptionIndex  int    `json:"option_index"`
	OptionAction string `json:"option_action"`
	ChangeIndex  int    `json:"change_index"`
	Status       string `json:"status"`
	Summary      string `json:"summary"`
	File         string `json:"file,omitempty"`
	Diff         string `json:"diff,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

type cliJSONPatchOutput struct {
	Source string `json:"source"`
	Output string `json:"output,omitempty"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

type cliJSONValidation struct {
	FindingID string `json:"finding_id"`
	RuleID    string `json:"rule_id"`
	Status    string `json:"status"`
	Summary   string `json:"summary"`
}

func assertValidJSONReport(t *testing.T, output string) cliJSONReport {
	t.Helper()
	var report cliJSONReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("json output is invalid: %v\n%s", err, output)
	}
	return report
}

func assertCode(t *testing.T, got, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("exit code = %d, want %d", got, want)
	}
}

func assertString(t *testing.T, name, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s = %q, want %q", name, got, want)
	}
}

func assertContains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("output = %q, want substring %q", got, want)
	}
}

func assertDoesNotContainSecretPayloadFields(t *testing.T, outputs ...string) {
	t.Helper()
	for _, output := range outputs {
		for _, forbidden := range []string{"data:", "stringData:"} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("output contains Secret payload field %q: %s", forbidden, output)
			}
		}
	}
}

func assertOneLineStderr(t *testing.T, stderr string) {
	t.Helper()
	assertExactlyOneTrailingNewline(t, stderr)
	if strings.Count(stderr, "\n") != 1 {
		t.Fatalf("stderr = %q, want exactly one line", stderr)
	}
}

func assertExactlyOneTrailingNewline(t *testing.T, output string) {
	t.Helper()
	if !strings.HasSuffix(output, "\n") {
		t.Fatalf("output = %q, want trailing newline", output)
	}
	if strings.HasSuffix(strings.TrimSuffix(output, "\n"), "\n") {
		t.Fatalf("output = %q, want exactly one trailing newline", output)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("stdout failed")
}

func mustAddNode(t *testing.T, g *graph.Graph, node graph.Node) graph.Node {
	t.Helper()
	added, err := g.AddNode(node)
	if err != nil {
		t.Fatalf("add node: %v", err)
	}
	return added
}

func mustAddEdge(t *testing.T, g *graph.Graph, edge graph.Edge) graph.Edge {
	t.Helper()
	added, err := g.AddEdge(edge)
	if err != nil {
		t.Fatalf("add edge: %v", err)
	}
	return added
}

func writeSplitVulnerableFixture(t *testing.T, dir string, order []string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create fixture dir: %v", err)
	}
	files := map[string]string{
		"service.yaml": `apiVersion: v1
kind: Service
metadata:
  name: public-api
  namespace: prod
spec:
  type: LoadBalancer
  selector:
    app: api
`,
		"deployment.yaml": `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
spec:
  template:
    metadata:
      labels:
        app: api
    spec:
      serviceAccountName: api
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api
  namespace: prod
`,
		"secret.yaml": `apiVersion: v1
kind: Secret
metadata:
  name: database-password
  namespace: prod
data:
  password: FAKE_CLI_SECRET_DATA_VALUE_DO_NOT_RETAIN
`,
		"rbac.yaml": `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: prod
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
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
  namespace: prod
`,
	}
	for _, name := range order {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(files[name]), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

func renameFixtureFile(t *testing.T, dir, oldName, newName string) {
	t.Helper()
	if err := os.Rename(filepath.Join(dir, oldName), filepath.Join(dir, newName)); err != nil {
		t.Fatalf("rename fixture file: %v", err)
	}
}

func writeMultiFindingFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	content := `apiVersion: v1
kind: Service
metadata:
  name: public-api
  namespace: prod
spec:
  type: LoadBalancer
  selector:
    app: api
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
spec:
  template:
    metadata:
      labels:
        app: api
    spec:
      serviceAccountName: api
---
apiVersion: v1
kind: Secret
metadata:
  name: api-token
  namespace: prod
---
apiVersion: v1
kind: Secret
metadata:
  name: database-password
  namespace: prod
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: prod
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["list"]
---
apiVersion: rbac.authorization.k8s.io/v1
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
  namespace: prod
`
	if err := os.WriteFile(filepath.Join(dir, "resources.yaml"), []byte(content), 0o600); err != nil {
		t.Fatalf("write multi finding fixture: %v", err)
	}
	return dir
}

func writeSplitPreviewFixture(t *testing.T, parent, name string) {
	t.Helper()
	dir := filepath.Join(parent, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create split fixture dir: %v", err)
	}
	writeFileForTest(t, dir, "service.yaml", `apiVersion: v1
kind: Service
metadata:
  name: public-api
  namespace: prod
spec:
  type: LoadBalancer
  selector:
    app: api
`)
	writeFileForTest(t, dir, "deployment.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
spec:
  template:
    metadata:
      labels:
        app: api
    spec:
      serviceAccountName: api
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api
  namespace: prod
`)
	writeFileForTest(t, dir, "secret.yaml", `apiVersion: v1
kind: Secret
metadata:
  name: database-password
  namespace: prod
data:
  password: FAKE_CLI_SECRET_DATA_VALUE_DO_NOT_RETAIN
stringData:
  token: FAKE_CLI_SECRET_STRINGDATA_VALUE_DO_NOT_RETAIN
`)
	writeFileForTest(t, dir, "role.yaml", `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: prod
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
`)
	writeFileForTest(t, dir, "rbac.yaml", `apiVersion: rbac.authorization.k8s.io/v1
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
  namespace: prod
- kind: ServiceAccount
  name: worker
  namespace: prod
`)
}

func writePartialValidationFixture(t *testing.T, parent, name string) {
	t.Helper()
	writeSplitPreviewFixture(t, parent, name)
	dir := filepath.Join(parent, name)
	if err := os.Rename(filepath.Join(dir, "rbac.yaml"), filepath.Join(dir, "binding-a.yaml")); err != nil {
		t.Fatalf("rename binding-a: %v", err)
	}
	writeFileForTest(t, dir, "binding-b.yaml", `apiVersion: v1
kind: Secret
metadata:
  name: validation-helper
  namespace: prod
data:
  token: FAKE_VALIDATION_OVERLAY_SECRET_VALUE_DO_NOT_RETAIN
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-secrets-b
  namespace: prod
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: secret-reader
subjects:
- kind: ServiceAccount
  name: api
  namespace: prod
- kind: ServiceAccount
  name: worker
  namespace: prod
`)
}

func writePreviewFixture(t *testing.T, parent, name string, secretPayload bool) {
	t.Helper()
	dir := filepath.Join(parent, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create preview fixture dir: %v", err)
	}
	secretExtra := ""
	if secretPayload {
		secretExtra = `data:
  password: FAKE_PREVIEW_CLI_SECRET_DATA_VALUE_DO_NOT_RETAIN
stringData:
  token: FAKE_PREVIEW_CLI_SECRET_STRINGDATA_VALUE_DO_NOT_RETAIN
`
	}
	content := `apiVersion: v1
kind: Service
metadata:
  name: public-api
  namespace: prod
spec:
  type: LoadBalancer
  selector:
    app: api
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
spec:
  template:
    metadata:
      labels:
        app: api
    spec:
      serviceAccountName: api
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api
  namespace: prod
---
apiVersion: v1
kind: Secret
metadata:
  name: database-password
  namespace: prod
` + secretExtra + `---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: prod
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
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
  namespace: prod
- kind: ServiceAccount
  name: worker
  namespace: prod
`
	if err := os.WriteFile(filepath.Join(dir, "resources.yaml"), []byte(content), 0o600); err != nil {
		t.Fatalf("write preview fixture: %v", err)
	}
}

func writeFileForTest(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func readFileForTest(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

type generatedBaselineForTest struct {
	Suppressions []generatedSuppressionForTest `json:"suppressions"`
}

type generatedSuppressionForTest struct {
	FindingID string `json:"finding_id"`
	Reason    string `json:"reason"`
}

func readGeneratedBaselineForTest(t *testing.T, path string) generatedBaselineForTest {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated baseline: %v", err)
	}
	var baseline generatedBaselineForTest
	if err := json.Unmarshal(data, &baseline); err != nil {
		t.Fatalf("unmarshal generated baseline: %v\n%s", err, data)
	}
	for _, forbidden := range []string{"rules", "path_exclusions", "disabled_rules"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("generated baseline contains non-suppression config field %q: %s", forbidden, data)
		}
	}
	return baseline
}

func testCLIBaselineFindingID(ruleID, hexDigit string) string {
	return "finding:" + ruleID + ":" + strings.Repeat(hexDigit, 64)
}

func writeGitHubActionsWorkflowForTest(t *testing.T, root, name, content string) {
	t.Helper()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir workflows: %v", err)
	}
	writeFileForTest(t, dir, name, content)
}

func writeTerraformForTest(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir terraform dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write terraform: %v", err)
	}
}

func terraformOIDCRole(name, subject string) string {
	return terraformOIDCRoleWithSuffix(name, subject, "")
}

func terraformOIDCRoleWithSuffix(name, subject, suffix string) string {
	return `resource "aws_iam_role" "` + name + `" {
  assume_role_policy = <<EOF
{
  "Statement": {
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "` + subject + `"
      }
    }
  }
}` + suffix + `
EOF
}
`
}

func terraformOIDCAdminRole(name, subject, policyName, action, resource string) string {
	return terraformOIDCPolicyRole(name, subject, policyName, action, resource)
}

func terraformOIDCPolicyRole(name, subject, policyName, action, resource string) string {
	return terraformOIDCRole(name, subject) + `
resource "aws_iam_role_policy" "` + policyName + `" {
  role = aws_iam_role.` + name + `.id
  policy = "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"` + action + `\",\"Resource\":\"` + resource + `\"}}"
}
`
}

func terraformOIDCS3Role(roleName, subject, bucketResourceName, bucketName, policyName, action, resource string) string {
	return terraformOIDCRole(roleName, subject) + `
resource "aws_s3_bucket" "` + bucketResourceName + `" {
  bucket = "` + bucketName + `"
}

resource "aws_iam_role_policy" "` + policyName + `" {
  role = aws_iam_role.` + roleName + `.id
  policy = "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"` + action + `\",\"Resource\":\"` + resource + `\"}}"
}
`
}

func terraformOIDCSensitiveS3Role(roleName, subject, bucketResourceName, bucketName, policyName, action, resource string) string {
	return terraformOIDCRole(roleName, subject) + `
resource "aws_s3_bucket" "` + bucketResourceName + `" {
  bucket = "` + bucketName + `"
  tags = {
    DataClassification = "Sensitive"
    Owner = "FAKE_CLI_XDOMAIN4_TAG_SECRET_DO_NOT_RETAIN"
  }
}

resource "aws_iam_role_policy" "` + policyName + `" {
  role = aws_iam_role.` + roleName + `.id
  policy = "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"` + action + `\",\"Resource\":\"` + resource + `\"}}"
}
`
}

func terraformOIDCSubjectsAdminRole(name string, subjects []string, policyName, action, resource string) string {
	var patterns strings.Builder
	for i, subject := range subjects {
		if i > 0 {
			patterns.WriteString(", ")
		}
		patterns.WriteString(`"`)
		patterns.WriteString(subject)
		patterns.WriteString(`"`)
	}
	return `resource "aws_iam_role" "` + name + `" {
  assume_role_policy = <<EOF
{
  "Statement": {
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": [` + patterns.String() + `]
      }
    }
  }
}
EOF
}

resource "aws_iam_role_policy" "` + policyName + `" {
  role = aws_iam_role.` + name + `.id
  policy = "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"` + action + `\",\"Resource\":\"` + resource + `\"}}"
}
`
}

func countGraphEdges(g *graph.Graph, kind graph.EdgeKind) int {
	count := 0
	for _, edge := range g.Edges() {
		if edge.Kind == kind {
			count++
		}
	}
	return count
}

func countGraphNodes(g *graph.Graph, kind graph.NodeKind) int {
	count := 0
	for _, node := range g.Nodes() {
		if node.Kind == kind {
			count++
		}
	}
	return count
}

func onlyGraphNodeIDOfKind(t *testing.T, g *graph.Graph, kind graph.NodeKind) graph.NodeID {
	t.Helper()
	var ids []graph.NodeID
	for _, node := range g.Nodes() {
		if node.Kind == kind {
			ids = append(ids, node.ID)
		}
	}
	if len(ids) != 1 {
		t.Fatalf("%s node count = %d, want 1: %#v", kind, len(ids), g.Nodes())
	}
	return ids[0]
}

func onlyCLIFindingByRule(t *testing.T, findings []analysis.Finding, ruleID analysis.RuleID) analysis.Finding {
	t.Helper()
	var matches []analysis.Finding
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			matches = append(matches, finding)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("%s finding count = %d, want 1: %#v", ruleID, len(matches), findings)
	}
	return matches[0]
}

func assertDoesNotContainGitHubActionsSecretValues(t *testing.T, outputs ...string) {
	t.Helper()
	for _, output := range outputs {
		for _, forbidden := range []string{
			"FAKE_CLI_GHA_ENV_SECRET_DO_NOT_RETAIN",
			"FAKE_CLI_GHA_WITH_SECRET_DO_NOT_RETAIN",
			"FAKE_CLI_GHA_RUN_SECRET_DO_NOT_RETAIN",
			"FAKE_CLI_GHA_MALFORMED_SECRET_DO_NOT_RETAIN",
		} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("output contains GitHub Actions secret-like value %q: %s", forbidden, output)
			}
		}
	}
}

func assertDoesNotContainTerraformAWSSecretValues(t *testing.T, outputs ...string) {
	t.Helper()
	for _, output := range outputs {
		for _, forbidden := range []string{
			"FAKE_CLI_AWS_TF_VARIABLE_SECRET_DO_NOT_RETAIN",
			"FAKE_CLI_AWS_TF_TRAILING_SECRET_DO_NOT_RETAIN",
			"FAKE_CLI_AWS_TF_ACCESS_KEY_DO_NOT_RETAIN",
			"FAKE_CLI_AWS_TF_CONDITION_SECRET_DO_NOT_RETAIN",
		} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("Terraform AWS output contains secret-like value %q: %s", forbidden, output)
			}
		}
	}
}

func assertDoesNotContainCrossDomainSecretValues(t *testing.T, outputs ...string) {
	t.Helper()
	for _, output := range outputs {
		for _, forbidden := range []string{
			"FAKE_CLI_XDOMAIN_GHA_ENV_SECRET_DO_NOT_RETAIN",
			"FAKE_CLI_XDOMAIN_GHA_WITH_SECRET_DO_NOT_RETAIN",
			"FAKE_CLI_XDOMAIN_GHA_RUN_SECRET_DO_NOT_RETAIN",
			"FAKE_CLI_XDOMAIN_TF_SECRET_DO_NOT_RETAIN",
		} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("output contains cross-domain secret-like value %q: %s", forbidden, output)
			}
		}
	}
}

func assertDoesNotContainCrossDomainAdminSecretValues(t *testing.T, outputs ...string) {
	t.Helper()
	for _, output := range outputs {
		for _, forbidden := range []string{
			"FAKE_CLI_XDOMAIN2_GHA_ENV_SECRET_DO_NOT_RETAIN",
			"FAKE_CLI_XDOMAIN2_GHA_WITH_SECRET_DO_NOT_RETAIN",
			"FAKE_CLI_XDOMAIN2_GHA_RUN_SECRET_DO_NOT_RETAIN",
			"FAKE_CLI_XDOMAIN2_TF_SECRET_DO_NOT_RETAIN",
		} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("output contains cross-domain admin secret-like value %q: %s", forbidden, output)
			}
		}
	}
}

func assertDoesNotContainCrossDomainS3SecretValues(t *testing.T, outputs ...string) {
	t.Helper()
	for _, output := range outputs {
		for _, forbidden := range []string{
			"FAKE_CLI_XDOMAIN3_GHA_ENV_SECRET_DO_NOT_RETAIN",
			"FAKE_CLI_XDOMAIN3_GHA_WITH_SECRET_DO_NOT_RETAIN",
			"FAKE_CLI_XDOMAIN3_GHA_RUN_SECRET_DO_NOT_RETAIN",
			"FAKE_CLI_XDOMAIN3_TF_SECRET_DO_NOT_RETAIN",
			"FAKE_CLI_XDOMAIN4_TAG_SECRET_DO_NOT_RETAIN",
		} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("output contains cross-domain S3 secret-like value %q: %s", forbidden, output)
			}
		}
	}
}

func assertNoRuleInJSONReport(t *testing.T, output, ruleID string) {
	t.Helper()
	report := assertValidJSONReport(t, output)
	for _, finding := range report.Findings {
		if finding.RuleID == ruleID {
			t.Fatalf("JSON report contains %s: %#v", ruleID, report.Findings)
		}
	}
}

func countCLIFindingsByRule(findings []cliJSONFinding, ruleID string) int {
	count := 0
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			count++
		}
	}
	return count
}

func firstCLIFindingByRule(t *testing.T, findings []cliJSONFinding, ruleID string) cliJSONFinding {
	t.Helper()
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return finding
		}
	}
	t.Fatalf("missing %s finding in %#v", ruleID, findings)
	return cliJSONFinding{}
}

func jsonReportHasRule(report cliJSONReport, ruleID string) bool {
	for _, finding := range report.Findings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}

func legacyGitHubActionsRuleWording() string {
	return "third" + "-party"
}

func assertPathDoesNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("path exists, want absent: %s", path)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat %s: %v", path, err)
	}
}

func listDirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

var _ io.Writer = failingWriter{}
