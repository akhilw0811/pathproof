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
	if strings.Contains(stdout, legacyGitHubActionsRuleWording()) || strings.Contains(stdout, "Remediation:") || strings.Contains(stdout, "Patch Preview:") || strings.Contains(stdout, "Validation:") {
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
	if finding.Remediation != nil {
		t.Fatalf("remediation = %#v, want nil", finding.Remediation)
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
		if finding.Remediation != nil {
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
	assertContains(t, stdout, "Patch Output:")
	assertContains(t, stdout, "Written files: 0")
	if strings.Contains(stdout, "Remediation:") || strings.Contains(stdout, "Patch Preview:") || strings.Contains(stdout, "Validation:") {
		t.Fatalf("PP-GHA-001 received unsupported remediation/patch/validation output: %s", stdout)
	}
	if _, err := os.Stat(filepath.Join(parent, "patched")); !os.IsNotExist(err) {
		t.Fatalf("patched output directory exists or stat failed unexpectedly: %v", err)
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
	if strings.Contains(stdout, legacyGitHubActionsRuleWording()) || strings.Contains(stdout, "Remediation:") {
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

	code := writeScanResult([]analysis.Finding{fixture.finding}, fixture.graph, "", scanFormatHuman, false, "", false, &stdout, &stderr)

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

	code := writeScanResult([]analysis.Finding{fixture.finding}, fixture.graph, "", scanFormatHuman, true, "", false, &stdout, &stderr)

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

	_, err := newScanReport(".", []analysis.Finding{finding}, g, nil, nil, nil, false, nil)
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

	_, err := newScanReport(".", []analysis.Finding{finding}, g, nil, nil, nil, false, nil)
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

	code := writeScanResult([]analysis.Finding{fixture.finding}, fixture.graph, ".", scanFormatHuman, false, "", false, &stdout, &stderr)

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

	code := writeScanResult([]analysis.Finding{finding}, g, ".", scanFormatHuman, false, "", false, &stdout, &stderr)

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
	code := writeScanResult(findings, g, ".", format, false, "", false, &stdout, &stderr)
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
	Findings     []cliJSONFinding      `json:"findings"`
	FindingCount int                   `json:"finding_count"`
	PatchOutputs *[]cliJSONPatchOutput `json:"patch_outputs,omitempty"`
	Validation   []cliJSONValidation   `json:"validation,omitempty"`
}

type cliJSONFinding struct {
	ID               string              `json:"id"`
	RuleID           string              `json:"rule_id"`
	Title            string              `json:"title"`
	Severity         string              `json:"severity"`
	Summary          string              `json:"summary"`
	Path             []cliJSONPathNode   `json:"path"`
	Evidence         []cliJSONEvidence   `json:"evidence"`
	SourceReferences []string            `json:"source_references"`
	Remediation      *cliJSONRemediation `json:"remediation,omitempty"`
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

func writeGitHubActionsWorkflowForTest(t *testing.T, root, name, content string) {
	t.Helper()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir workflows: %v", err)
	}
	writeFileForTest(t, dir, name, content)
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

func legacyGitHubActionsRuleWording() string {
	return "third" + "-party"
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
