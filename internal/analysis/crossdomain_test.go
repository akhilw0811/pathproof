package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"pathproof/internal/graph"
	parsergithubactions "pathproof/internal/parser/githubactions"
	parserterraform "pathproof/internal/parser/terraform"
	routinggithubactions "pathproof/internal/routing/githubactions"
	routingterraform "pathproof/internal/routing/terraform"
)

func TestAnalyzeCrossDomainWorkflowLevelOIDCAndRiskEmitsWorkflowPath(t *testing.T) {
	findings := Analyze(crossDomainGraphFromWorkflow(t, `on: pull_request_target
permissions: write-all
`, []string{"deploy"}, "owner/repo"))

	finding := onlyFindingByRule(t, findings, RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole)
	if finding.Title != crossDomainRiskyGitHubActionsCanAssumeAWSRoleTitle {
		t.Fatalf("title = %q, want %q", finding.Title, crossDomainRiskyGitHubActionsCanAssumeAWSRoleTitle)
	}
	if finding.Severity != SeverityHigh {
		t.Fatalf("severity = %q, want High", finding.Severity)
	}
	wantKinds := []graph.NodeKind{graph.Workflow, graph.OIDCTokenCapability, graph.AWSIAMRole}
	assertFindingNodeKinds(t, finding, wantKinds)
	wantEdgeKinds := []graph.EdgeKind{graph.CanRequestOIDCToken, graph.CanAssumeRole}
	assertFindingEdgeKinds(t, finding, wantEdgeKinds)
	if finding.RiskSignal == nil || finding.RiskSignal.RuleID != RuleGitHubActionsDangerousPermissions {
		t.Fatalf("risk signal = %#v, want PP-GHA-003", finding.RiskSignal)
	}
	if finding.RiskSignal.Permission != "all" || finding.RiskSignal.Access != "write-all" {
		t.Fatalf("risk permission = %#v, want permissions: write-all", finding.RiskSignal)
	}
	if !strings.Contains(finding.Summary, "workflow-level OIDC token capability") {
		t.Fatalf("summary = %q, want workflow-level scope", finding.Summary)
	}
}

func TestAnalyzeCrossDomainJobLevelOIDCAndRiskEmitsJobPath(t *testing.T) {
	findings := Analyze(crossDomainGraphFromWorkflow(t, `on: pull_request_target
jobs:
  deploy:
    permissions:
      id-token: write
`, []string{"deploy"}, "owner/repo"))

	finding := onlyFindingByRule(t, findings, RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole)
	wantKinds := []graph.NodeKind{graph.Workflow, graph.WorkflowJob, graph.OIDCTokenCapability, graph.AWSIAMRole}
	assertFindingNodeKinds(t, finding, wantKinds)
	wantEdgeKinds := []graph.EdgeKind{graph.DefinesJob, graph.CanRequestOIDCToken, graph.CanAssumeRole}
	assertFindingEdgeKinds(t, finding, wantEdgeKinds)
	if finding.RiskSignal == nil || finding.RiskSignal.JobID != "deploy" {
		t.Fatalf("risk signal = %#v, want job deploy", finding.RiskSignal)
	}
	if !strings.Contains(finding.Summary, "job-level OIDC token capability") {
		t.Fatalf("summary = %q, want job-level scope", finding.Summary)
	}
}

func TestAnalyzeCrossDomainWorkflowAndJobPathsBothEmit(t *testing.T) {
	findings := Analyze(crossDomainGraphFromWorkflow(t, `on: pull_request_target
permissions: write-all
jobs:
  deploy:
    permissions:
      id-token: write
`, []string{"deploy"}, "owner/repo"))

	var crossDomain []Finding
	for _, finding := range findings {
		if finding.RuleID == RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole {
			crossDomain = append(crossDomain, finding)
		}
	}
	if len(crossDomain) != 2 {
		t.Fatalf("PP-XDOMAIN-001 count = %d, want 2: %#v", len(crossDomain), findings)
	}
	shapes := map[int]bool{}
	for _, finding := range crossDomain {
		shapes[len(finding.NodeIDs)] = true
	}
	if !shapes[3] || !shapes[4] {
		t.Fatalf("finding path lengths = %#v, want workflow and job paths", crossDomain)
	}
	if crossDomain[0].ID == crossDomain[1].ID {
		t.Fatalf("distinct paths produced duplicate IDs: %#v", crossDomain)
	}
}

func TestAnalyzeCrossDomainExactDuplicatePathsDeduplicate(t *testing.T) {
	g := crossDomainGraphFromWorkflow(t, `on: pull_request_target
permissions: write-all
`, []string{"deploy"}, "owner/repo")
	duplicate := onlyEdgeByKind(t, g, graph.CanAssumeRole)
	mustAddEdge(t, g, duplicate)

	if got := countFindingsByRule(Analyze(g), RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole); got != 1 {
		t.Fatalf("PP-XDOMAIN-001 count = %d, want 1", got)
	}
}

func TestAnalyzeCrossDomainRequiresRiskAndTrust(t *testing.T) {
	tests := []struct {
		name     string
		workflow string
		repo     string
		want     int
	}{
		{
			name: "PP-GHA-001 alone does not trigger",
			workflow: `on: pull_request
permissions:
  id-token: write
jobs:
  deploy:
    steps:
      - uses: owner/repo@main
`,
			repo: "owner/repo",
			want: 0,
		},
		{
			name: "safe OIDC trust alone does not trigger",
			workflow: `on: pull_request
permissions:
  id-token: write
`,
			repo: "owner/repo",
			want: 0,
		},
		{
			name: "risk without CanAssumeRole does not trigger",
			workflow: `on: pull_request_target
permissions: write-all
`,
			repo: "",
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Analyze(crossDomainGraphFromWorkflow(t, tt.workflow, []string{"deploy"}, tt.repo))
			if got := countFindingsByRule(findings, RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole); got != tt.want {
				t.Fatalf("PP-XDOMAIN-001 count = %d, want %d: %#v", got, tt.want, findings)
			}
		})
	}
}

func TestAnalyzeCrossDomainRiskMustMatchRoleTrustSubjectContext(t *testing.T) {
	findings := Analyze(crossDomainGraphFromWorkflowAndTerraform(t, `on:
  push:
    branches: [main]
  pull_request_target:
permissions: write-all
`, terraformRole("deploy", "repo:owner/repo:ref:refs/heads/main"), "owner/repo"))

	if got := countFindingsByRule(findings, RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole); got != 0 {
		t.Fatalf("PP-XDOMAIN-001 count = %d, want 0 for PR-target risk with branch-only role trust: %#v", got, findings)
	}
	if got := countFindingsByRule(findings, RuleGitHubActionsDangerousPermissions); got != 1 {
		t.Fatalf("PP-GHA-003 count = %d, want existing risky workflow finding", got)
	}
}

func TestAnalyzeCrossDomainUnsafeCheckoutPairsWithJobAndWorkflowOIDC(t *testing.T) {
	findings := Analyze(crossDomainGraphFromWorkflow(t, `on: pull_request_target
permissions:
  id-token: write
jobs:
  deploy:
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`, []string{"deploy"}, "owner/repo"))

	var crossDomain []Finding
	for _, finding := range findings {
		if finding.RuleID == RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole && finding.RiskSignal != nil && finding.RiskSignal.RuleID == RuleGitHubActionsUnsafePullRequestTargetCheckout {
			crossDomain = append(crossDomain, finding)
		}
	}
	if len(crossDomain) != 2 {
		t.Fatalf("PP-XDOMAIN-001 count = %d, want workflow and job OIDC paths: %#v", len(crossDomain), findings)
	}
	for _, finding := range crossDomain {
		if finding.RiskSignal == nil || finding.RiskSignal.RuleID != RuleGitHubActionsUnsafePullRequestTargetCheckout || finding.RiskSignal.StepIndex == nil {
			t.Fatalf("risk signal = %#v, want PP-GHA-002 with step index", finding.RiskSignal)
		}
		if len(finding.RiskSignal.Selectors) != 1 || finding.RiskSignal.Selectors[0].MatchedExpression != "github.event.pull_request.head.sha" {
			t.Fatalf("selectors = %#v, want sanitized head sha", finding.RiskSignal.Selectors)
		}
	}
}

func TestAnalyzeCrossDomainFindingIDsAreStableSensitiveAndDeterministic(t *testing.T) {
	deterministicGraph := crossDomainGraphFromWorkflow(t, crossDomainWorkflowForIdentity("id-token", "write", "deploy"), []string{"deploy", "audit"}, "owner/repo")
	first := Analyze(deterministicGraph)
	baseFindings := Analyze(crossDomainGraphFromWorkflow(t, crossDomainWorkflowForIdentity("id-token", "write", "deploy"), []string{"deploy"}, "owner/repo"))
	changedRole := Analyze(crossDomainGraphFromWorkflow(t, crossDomainWorkflowForIdentity("id-token", "write", "deploy"), []string{"other"}, "owner/repo"))
	changedPermission := Analyze(crossDomainGraphFromWorkflow(t, crossDomainWorkflowForIdentity("all", "write-all", "deploy"), []string{"deploy"}, "owner/repo"))
	changedPath := Analyze(crossDomainGraphFromWorkflow(t, crossDomainWorkflowForIdentity("id-token", "write", "other"), []string{"deploy"}, "owner/repo"))

	firstJSON := mustMarshalFindings(t, first)
	repeatedJSON := mustMarshalFindings(t, Analyze(deterministicGraph))
	if string(firstJSON) != string(repeatedJSON) {
		t.Fatalf("findings differ across repeated equivalent input:\nfirst: %s\nsecond:%s", firstJSON, repeatedJSON)
	}
	base := onlyFindingByRule(t, baseFindings, RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole)
	for name, findings := range map[string][]Finding{
		"role":       changedRole,
		"permission": changedPermission,
		"path":       changedPath,
	} {
		changed := onlyFindingByRule(t, findings, RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole)
		if base.ID == changed.ID {
			t.Fatalf("finding ID did not change when %s changed: %q", name, base.ID)
		}
	}
}

func TestAnalyzeCrossDomainRiskSignalAndEvidenceAreSanitized(t *testing.T) {
	const envSecret = "FAKE_XDOMAIN_GHA_ENV_SECRET_DO_NOT_RETAIN"
	const withSecret = "FAKE_XDOMAIN_GHA_WITH_SECRET_DO_NOT_RETAIN"
	const runSecret = "FAKE_XDOMAIN_GHA_RUN_SECRET_DO_NOT_RETAIN"
	const terraformSecret = "FAKE_XDOMAIN_TF_SECRET_DO_NOT_RETAIN"
	findings := Analyze(crossDomainGraphFromWorkflowAndTerraform(t, `on: pull_request_target
permissions:
  id-token: write
env:
  TOKEN: FAKE_XDOMAIN_GHA_ENV_SECRET_DO_NOT_RETAIN
jobs:
  deploy:
    steps:
      - run: echo FAKE_XDOMAIN_GHA_RUN_SECRET_DO_NOT_RETAIN
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
        with:
          token: FAKE_XDOMAIN_GHA_WITH_SECRET_DO_NOT_RETAIN
          ref: ${{ github.event.pull_request.head.sha }}
`, terraformRole("deploy", "repo:owner/repo:pull_request")+"\n# "+terraformSecret+"\n", "owner/repo"))

	var finding Finding
	for _, candidate := range findings {
		if candidate.RuleID == RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole && candidate.RiskSignal != nil && candidate.RiskSignal.RuleID == RuleGitHubActionsUnsafePullRequestTargetCheckout {
			finding = candidate
			break
		}
	}
	if finding.ID == "" {
		t.Fatalf("PP-XDOMAIN-001 with PP-GHA-002 risk not found: %#v", findings)
	}
	if finding.RiskSignal == nil {
		t.Fatal("risk_signal = nil")
	}
	if len(finding.Evidence) != len(finding.EdgeIDs) {
		t.Fatalf("evidence/edge length = %d/%d, want path-only evidence", len(finding.Evidence), len(finding.EdgeIDs))
	}
	data := mustMarshalFindings(t, findings)
	for _, forbidden := range []string{envSecret, withSecret, runSecret, terraformSecret, "run:", "${{", "assume_role_policy", "Principal", "Condition", "arn:aws:iam"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("finding JSON contains %q: %s", forbidden, data)
		}
	}
}

func TestAnalyzeCrossDomainAdminRoleWorkflowRiskEmitsPPXDomain002(t *testing.T) {
	findings := Analyze(crossDomainAdminGraphFromWorkflowAndTerraform(t, `on: pull_request_target
permissions: write-all
`, terraformRoleWithInlineAdminPolicy("deploy", "repo:owner/repo:pull_request", "admin", "*", "*"), "owner/repo"))

	finding := onlyFindingByRule(t, findings, RuleCrossDomainRiskyGitHubActionsCanAssumeAWSAdminRole)
	if finding.Title != crossDomainRiskyGitHubActionsCanAssumeAWSAdminRoleTitle {
		t.Fatalf("title = %q, want %q", finding.Title, crossDomainRiskyGitHubActionsCanAssumeAWSAdminRoleTitle)
	}
	if finding.Severity != SeverityHigh {
		t.Fatalf("severity = %q, want High", finding.Severity)
	}
	assertFindingNodeKinds(t, finding, []graph.NodeKind{graph.Workflow, graph.OIDCTokenCapability, graph.AWSIAMRole, graph.AWSPermission})
	assertFindingEdgeKinds(t, finding, []graph.EdgeKind{graph.CanRequestOIDCToken, graph.CanAssumeRole, graph.GrantsPermission})
	if finding.RiskSignal == nil || finding.RiskSignal.RuleID != RuleGitHubActionsDangerousPermissions {
		t.Fatalf("risk signal = %#v, want PP-GHA-003", finding.RiskSignal)
	}
	if !strings.Contains(finding.Summary, "workflow-level OIDC token capability") || !strings.Contains(finding.Summary, "action_star_resource_star") {
		t.Fatalf("summary = %q, want OIDC scope and admin reason", finding.Summary)
	}
	if got := countFindingsByRule(findings, RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole); got != 1 {
		t.Fatalf("PP-XDOMAIN-001 count = %d, want existing role-assumption finding", got)
	}
}

func TestAnalyzeCrossDomainAdminRoleJobRiskEmitsPPXDomain002(t *testing.T) {
	findings := Analyze(crossDomainAdminGraphFromWorkflowAndTerraform(t, `on: pull_request_target
jobs:
  deploy:
    permissions:
      id-token: write
`, terraformRoleWithInlineAdminPolicy("deploy", "repo:owner/repo:pull_request", "admin", "*", "*"), "owner/repo"))

	finding := onlyFindingByRule(t, findings, RuleCrossDomainRiskyGitHubActionsCanAssumeAWSAdminRole)
	assertFindingNodeKinds(t, finding, []graph.NodeKind{graph.Workflow, graph.WorkflowJob, graph.OIDCTokenCapability, graph.AWSIAMRole, graph.AWSPermission})
	assertFindingEdgeKinds(t, finding, []graph.EdgeKind{graph.DefinesJob, graph.CanRequestOIDCToken, graph.CanAssumeRole, graph.GrantsPermission})
	if finding.RiskSignal == nil || finding.RiskSignal.JobID != "deploy" || finding.RiskSignal.Permission != "id-token" {
		t.Fatalf("risk signal = %#v, want job-level id-token risk", finding.RiskSignal)
	}
}

func TestAnalyzeCrossDomainAdminRoleUnsafeCheckoutRiskEmitsPPXDomain002(t *testing.T) {
	findings := Analyze(crossDomainAdminGraphFromWorkflowAndTerraform(t, `on: pull_request_target
permissions:
  id-token: write
jobs:
  deploy:
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`, terraformRoleWithInlineAdminPolicy("deploy", "repo:owner/repo:pull_request", "admin", "*", "*"), "owner/repo"))

	var matches []Finding
	for _, finding := range findings {
		if finding.RuleID == RuleCrossDomainRiskyGitHubActionsCanAssumeAWSAdminRole && finding.RiskSignal != nil && finding.RiskSignal.RuleID == RuleGitHubActionsUnsafePullRequestTargetCheckout {
			matches = append(matches, finding)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("PP-XDOMAIN-002 unsafe checkout count = %d, want workflow-level OIDC path: %#v", len(matches), findings)
	}
	finding := matches[0]
	assertFindingNodeKinds(t, finding, []graph.NodeKind{graph.Workflow, graph.OIDCTokenCapability, graph.AWSIAMRole, graph.AWSPermission})
	assertFindingEdgeKinds(t, finding, []graph.EdgeKind{graph.CanRequestOIDCToken, graph.CanAssumeRole, graph.GrantsPermission})
	if finding.RiskSignal.StepIndex == nil || len(finding.RiskSignal.Selectors) != 1 {
		t.Fatalf("risk signal = %#v, want sanitized checkout selector", finding.RiskSignal)
	}
}

func TestAnalyzeCrossDomainAdminRoleRequiresRiskTrustAndAdminPermission(t *testing.T) {
	tests := []struct {
		name      string
		workflow  string
		terraform string
		repo      string
	}{
		{
			name: "OIDC trust admin with no risky signal",
			workflow: `on: pull_request
permissions:
  id-token: write
`,
			terraform: terraformRoleWithInlineAdminPolicy("deploy", "repo:owner/repo:pull_request", "admin", "*", "*"),
			repo:      "owner/repo",
		},
		{
			name: "risk and admin without CanAssumeRole",
			workflow: `on: pull_request_target
permissions: write-all
`,
			terraform: terraformRoleWithInlineAdminPolicy("deploy", "repo:owner/repo:pull_request", "admin", "*", "*"),
			repo:      "",
		},
		{
			name: "risk and trust without admin permission",
			workflow: `on: pull_request_target
permissions: write-all
`,
			terraform: terraformRoleWithInlinePolicy("deploy", "repo:owner/repo:pull_request", "read", "s3:GetObject", "*"),
			repo:      "owner/repo",
		},
		{
			name: "PP-GHA-001 alone does not trigger",
			workflow: `on: pull_request
permissions:
  id-token: write
jobs:
  deploy:
    steps:
      - uses: owner/repo@main
`,
			terraform: terraformRoleWithInlineAdminPolicy("deploy", "repo:owner/repo:pull_request", "admin", "*", "*"),
			repo:      "owner/repo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Analyze(crossDomainAdminGraphFromWorkflowAndTerraform(t, tt.workflow, tt.terraform, tt.repo))
			if got := countFindingsByRule(findings, RuleCrossDomainRiskyGitHubActionsCanAssumeAWSAdminRole); got != 0 {
				t.Fatalf("PP-XDOMAIN-002 count = %d, want 0: %#v", got, findings)
			}
		})
	}
}

func TestAnalyzeCrossDomainAdminRoleRequiresPullRequestSubjectContext(t *testing.T) {
	tests := []struct {
		name      string
		workflow  string
		terraform string
	}{
		{
			name: "branch trust",
			workflow: `on:
  push:
    branches: [main]
  pull_request_target:
permissions: write-all
`,
			terraform: terraformRoleWithInlineAdminPolicy("deploy", "repo:owner/repo:ref:refs/heads/main", "admin", "*", "*"),
		},
		{
			name: "environment trust",
			workflow: `on: pull_request_target
permissions: write-all
jobs:
  deploy:
    environment: prod
`,
			terraform: terraformRoleWithInlineAdminPolicy("deploy", "repo:owner/repo:environment:prod", "admin", "*", "*"),
		},
		{
			name: "environment trust named pull_request",
			workflow: `on: pull_request_target
permissions: write-all
jobs:
  deploy:
    environment: pull_request
`,
			terraform: terraformRoleWithInlineAdminPolicy("deploy", "repo:owner/repo:environment:pull_request", "admin", "*", "*"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Analyze(crossDomainAdminGraphFromWorkflowAndTerraform(t, tt.workflow, tt.terraform, "owner/repo"))
			if got := countFindingsByRule(findings, RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole); got != 0 {
				t.Fatalf("PP-XDOMAIN-001 count = %d, want 0 for %s-only trust: %#v", got, tt.name, findings)
			}
			if got := countFindingsByRule(findings, RuleCrossDomainRiskyGitHubActionsCanAssumeAWSAdminRole); got != 0 {
				t.Fatalf("PP-XDOMAIN-002 count = %d, want 0 for %s-only trust: %#v", got, tt.name, findings)
			}
			if got := countFindingsByRule(findings, RuleAWSIAMRoleAdministrativePermissions); got != 1 {
				t.Fatalf("PP-AWS-001 count = %d, want admin permission still modeled", got)
			}
		})
	}
}

func TestAnalyzeCrossDomainAdminRoleMixedEnvironmentAndPullRequestTrustEmits(t *testing.T) {
	firstTerraform := terraformRoleWithSubjectsAndInlineAdminPolicy("deploy", []string{
		"repo:owner/repo:environment:prod",
		"repo:owner/repo:pull_request",
	}, "admin", "*", "*")
	secondTerraform := terraformRoleWithSubjectsAndInlineAdminPolicy("deploy", []string{
		"repo:owner/repo:pull_request",
		"repo:owner/repo:environment:prod",
	}, "admin", "*", "*")
	workflow := `on: pull_request_target
permissions: write-all
jobs:
  deploy:
    environment: prod
`

	firstFindings := Analyze(crossDomainAdminGraphFromWorkflowAndTerraform(t, workflow, firstTerraform, "owner/repo"))
	secondFindings := Analyze(crossDomainAdminGraphFromWorkflowAndTerraform(t, workflow, secondTerraform, "owner/repo"))
	first := onlyFindingByRule(t, firstFindings, RuleCrossDomainRiskyGitHubActionsCanAssumeAWSAdminRole)
	second := onlyFindingByRule(t, secondFindings, RuleCrossDomainRiskyGitHubActionsCanAssumeAWSAdminRole)
	if first.ID != second.ID {
		t.Fatalf("PP-XDOMAIN-002 ID changed with trust subject order:\nfirst: %s\nsecond:%s", first.ID, second.ID)
	}
	assertFindingEdgeKinds(t, first, []graph.EdgeKind{graph.CanRequestOIDCToken, graph.CanAssumeRole, graph.GrantsPermission})
	if got := countFindingsByRule(firstFindings, RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole); got != 1 {
		t.Fatalf("PP-XDOMAIN-001 count = %d, want existing role-assumption finding", got)
	}
}

func TestAnalyzeCrossDomainAdminRoleFindingIDIncludesAdminPermission(t *testing.T) {
	terraform := terraformRole("deploy", "repo:owner/repo:pull_request") + `
resource "aws_iam_role_policy" "admin_star" {
  role = aws_iam_role.deploy.id
  policy = "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}}"
}

resource "aws_iam_role_policy" "admin_service_star" {
  role = aws_iam_role.deploy.id
  policy = "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"*:*\",\"Resource\":\"*\"}}"
}
`
	findings := Analyze(crossDomainAdminGraphFromWorkflowAndTerraform(t, `on: pull_request_target
permissions: write-all
`, terraform, "owner/repo"))

	var adminFindings []Finding
	for _, finding := range findings {
		if finding.RuleID == RuleCrossDomainRiskyGitHubActionsCanAssumeAWSAdminRole {
			adminFindings = append(adminFindings, finding)
		}
	}
	if len(adminFindings) != 2 {
		t.Fatalf("PP-XDOMAIN-002 count = %d, want one per admin permission: %#v", len(adminFindings), findings)
	}
	if adminFindings[0].ID == adminFindings[1].ID {
		t.Fatalf("admin permissions produced duplicate PP-XDOMAIN-002 IDs: %#v", adminFindings)
	}
	if !strings.Contains(adminFindings[0].Summary+adminFindings[1].Summary, "action_star_resource_star") || !strings.Contains(adminFindings[0].Summary+adminFindings[1].Summary, "action_service_star_resource_star") {
		t.Fatalf("summaries missing distinct admin reasons: %#v", adminFindings)
	}

	base := onlyFindingByRule(t, Analyze(crossDomainAdminGraphFromWorkflowAndTerraform(t, `on: pull_request_target
permissions: write-all
`, terraformRoleWithInlineAdminPolicy("deploy", "repo:owner/repo:pull_request", "admin", "*", "*"), "owner/repo")), RuleCrossDomainRiskyGitHubActionsCanAssumeAWSAdminRole)
	changedReason := onlyFindingByRule(t, Analyze(crossDomainAdminGraphFromWorkflowAndTerraform(t, `on: pull_request_target
permissions: write-all
`, terraformRoleWithInlineAdminPolicy("deploy", "repo:owner/repo:pull_request", "admin", "*:*", "*"), "owner/repo")), RuleCrossDomainRiskyGitHubActionsCanAssumeAWSAdminRole)
	if base.ID == changedReason.ID {
		t.Fatalf("PP-XDOMAIN-002 ID did not change when admin reason changed: %q", base.ID)
	}
	roleOnly := onlyFindingByRule(t, Analyze(crossDomainAdminGraphFromWorkflowAndTerraform(t, `on: pull_request_target
permissions: write-all
`, terraformRoleWithInlineAdminPolicy("deploy", "repo:owner/repo:pull_request", "admin", "*", "*"), "owner/repo")), RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole)
	if base.ID == roleOnly.ID {
		t.Fatalf("PP-XDOMAIN-001 and PP-XDOMAIN-002 IDs match unexpectedly: %q", base.ID)
	}
}

func TestAnalyzeCrossDomainAdminRoleReversedPermissionOrderIsDeterministic(t *testing.T) {
	first := mustMarshalFindings(t, Analyze(manualCrossDomainAdminGraph(t, false)))
	second := mustMarshalFindings(t, Analyze(manualCrossDomainAdminGraph(t, true)))
	if string(first) != string(second) {
		t.Fatalf("findings differ when admin permission insertion order reverses:\nfirst: %s\nsecond:%s", first, second)
	}
}

func TestAnalyzeCrossDomainAdminRoleDeterministicAndSanitized(t *testing.T) {
	const envSecret = "FAKE_XDOMAIN2_GHA_ENV_SECRET_DO_NOT_RETAIN"
	const withSecret = "FAKE_XDOMAIN2_GHA_WITH_SECRET_DO_NOT_RETAIN"
	const runSecret = "FAKE_XDOMAIN2_GHA_RUN_SECRET_DO_NOT_RETAIN"
	const terraformSecret = "FAKE_XDOMAIN2_TF_SECRET_DO_NOT_RETAIN"
	g := crossDomainAdminGraphFromWorkflowAndTerraform(t, `on: pull_request_target
permissions:
  id-token: write
env:
  TOKEN: FAKE_XDOMAIN2_GHA_ENV_SECRET_DO_NOT_RETAIN
jobs:
  deploy:
    steps:
      - run: echo FAKE_XDOMAIN2_GHA_RUN_SECRET_DO_NOT_RETAIN
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
        with:
          token: FAKE_XDOMAIN2_GHA_WITH_SECRET_DO_NOT_RETAIN
          ref: ${{ github.event.pull_request.head.sha }}
`, terraformRoleWithInlineAdminPolicy("deploy", "repo:owner/repo:pull_request", "admin", "*", "*")+"\n# "+terraformSecret+"\n", "owner/repo")

	first := mustMarshalFindings(t, Analyze(g))
	second := mustMarshalFindings(t, Analyze(g))
	if string(first) != string(second) {
		t.Fatalf("PP-XDOMAIN-002 findings differ across repeated analysis:\nfirst: %s\nsecond:%s", first, second)
	}
	var finding Finding
	for _, candidate := range Analyze(g) {
		if candidate.RuleID == RuleCrossDomainRiskyGitHubActionsCanAssumeAWSAdminRole && candidate.RiskSignal != nil && candidate.RiskSignal.RuleID == RuleGitHubActionsUnsafePullRequestTargetCheckout {
			finding = candidate
			break
		}
	}
	if finding.ID == "" {
		t.Fatalf("PP-XDOMAIN-002 with PP-GHA-002 risk not found: %#v", Analyze(g))
	}
	assertFindingEdgeKinds(t, finding, []graph.EdgeKind{graph.CanRequestOIDCToken, graph.CanAssumeRole, graph.GrantsPermission})
	data := mustMarshalFindings(t, Analyze(g))
	for _, forbidden := range []string{envSecret, withSecret, runSecret, terraformSecret, "run:", "${{", "assume_role_policy", "Principal", "Condition", "Statement", "policy =", "arn:aws:iam"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("finding JSON contains %q: %s", forbidden, data)
		}
	}
}

func TestAnalyzeCrossDomainS3WorkflowRiskEmitsPPXDomain003Read(t *testing.T) {
	findings := Analyze(crossDomainGraphFromWorkflowAndTerraform(t, `on: pull_request_target
permissions: write-all
`, terraformRoleWithS3BucketAndPolicy("deploy", "repo:owner/repo:pull_request", "artifacts", "prod-artifacts", "read", "s3:GetObject", "arn:aws:s3:::prod-artifacts/*"), "owner/repo"))

	finding := onlyFindingByRule(t, findings, RuleCrossDomainRiskyGitHubActionsCanAccessAWSS3Bucket)
	if finding.Title != crossDomainRiskyGitHubActionsCanAccessAWSS3BucketTitle {
		t.Fatalf("title = %q, want %q", finding.Title, crossDomainRiskyGitHubActionsCanAccessAWSS3BucketTitle)
	}
	if finding.Severity != SeverityHigh {
		t.Fatalf("severity = %q, want High", finding.Severity)
	}
	assertFindingNodeKinds(t, finding, []graph.NodeKind{graph.Workflow, graph.OIDCTokenCapability, graph.AWSIAMRole, graph.AWSS3Bucket})
	assertFindingEdgeKinds(t, finding, []graph.EdgeKind{graph.CanRequestOIDCToken, graph.CanAssumeRole, graph.CanReadObject})
	if finding.RiskSignal == nil || finding.RiskSignal.RuleID != RuleGitHubActionsDangerousPermissions {
		t.Fatalf("risk signal = %#v, want PP-GHA-003", finding.RiskSignal)
	}
	if !strings.Contains(finding.Summary, "read access") || !strings.Contains(finding.Summary, "prod-artifacts") {
		t.Fatalf("summary = %q, want bucket read access", finding.Summary)
	}
}

func TestAnalyzeCrossDomainS3JobRiskEmitsPPXDomain003Write(t *testing.T) {
	findings := Analyze(crossDomainGraphFromWorkflowAndTerraform(t, `on: pull_request_target
jobs:
  deploy:
    permissions:
      id-token: write
`, terraformRoleWithS3BucketAndPolicy("deploy", "repo:owner/repo:pull_request", "artifacts", "prod-artifacts", "write", "s3:PutObject", "arn:aws:s3:::prod-artifacts/*"), "owner/repo"))

	finding := onlyFindingByRule(t, findings, RuleCrossDomainRiskyGitHubActionsCanAccessAWSS3Bucket)
	assertFindingNodeKinds(t, finding, []graph.NodeKind{graph.Workflow, graph.WorkflowJob, graph.OIDCTokenCapability, graph.AWSIAMRole, graph.AWSS3Bucket})
	assertFindingEdgeKinds(t, finding, []graph.EdgeKind{graph.DefinesJob, graph.CanRequestOIDCToken, graph.CanAssumeRole, graph.CanWriteObject})
	if finding.RiskSignal == nil || finding.RiskSignal.JobID != "deploy" || finding.RiskSignal.Permission != "id-token" {
		t.Fatalf("risk signal = %#v, want job-level id-token risk", finding.RiskSignal)
	}
	if !strings.Contains(finding.Summary, "write access") {
		t.Fatalf("summary = %q, want write access", finding.Summary)
	}
}

func TestAnalyzeCrossDomainS3RequiresRiskTrustAndS3Access(t *testing.T) {
	tests := []struct {
		name      string
		workflow  string
		terraform string
		repo      string
	}{
		{
			name: "safe OIDC trust and S3 access without risk",
			workflow: `on: pull_request
permissions:
  id-token: write
`,
			terraform: terraformRoleWithS3BucketAndPolicy("deploy", "repo:owner/repo:pull_request", "artifacts", "prod-artifacts", "read", "s3:GetObject", "arn:aws:s3:::prod-artifacts/*"),
			repo:      "owner/repo",
		},
		{
			name: "risk and trust without S3 access",
			workflow: `on: pull_request_target
permissions: write-all
`,
			terraform: terraformRole("deploy", "repo:owner/repo:pull_request") + terraformS3Bucket("artifacts", "prod-artifacts"),
			repo:      "owner/repo",
		},
		{
			name: "branch trust does not match pull request risk",
			workflow: `on:
  push:
    branches: [main]
  pull_request_target:
permissions: write-all
`,
			terraform: terraformRoleWithS3BucketAndPolicy("deploy", "repo:owner/repo:ref:refs/heads/main", "artifacts", "prod-artifacts", "read", "s3:GetObject", "arn:aws:s3:::prod-artifacts/*"),
			repo:      "owner/repo",
		},
		{
			name: "environment trust does not match pull request risk",
			workflow: `on: pull_request_target
permissions: write-all
jobs:
  deploy:
    environment: prod
`,
			terraform: terraformRoleWithS3BucketAndPolicy("deploy", "repo:owner/repo:environment:prod", "artifacts", "prod-artifacts", "read", "s3:GetObject", "arn:aws:s3:::prod-artifacts/*"),
			repo:      "owner/repo",
		},
		{
			name: "PP-GHA-001 alone does not trigger",
			workflow: `on: pull_request
permissions:
  id-token: write
jobs:
  deploy:
    steps:
      - uses: owner/repo@main
`,
			terraform: terraformRoleWithS3BucketAndPolicy("deploy", "repo:owner/repo:pull_request", "artifacts", "prod-artifacts", "read", "s3:GetObject", "arn:aws:s3:::prod-artifacts/*"),
			repo:      "owner/repo",
		},
		{
			name: "admin permission alone does not imply S3 access",
			workflow: `on: pull_request_target
permissions: write-all
`,
			terraform: terraformRoleWithInlineAdminPolicy("deploy", "repo:owner/repo:pull_request", "admin", "*", "*") + terraformS3Bucket("artifacts", "prod-artifacts"),
			repo:      "owner/repo",
		},
		{
			name: "nonmatching bucket policy",
			workflow: `on: pull_request_target
permissions: write-all
`,
			terraform: terraformRoleWithS3BucketAndPolicy("deploy", "repo:owner/repo:pull_request", "artifacts", "prod-artifacts", "read", "s3:GetObject", "arn:aws:s3:::other-artifacts/*"),
			repo:      "owner/repo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Analyze(crossDomainGraphFromWorkflowAndTerraform(t, tt.workflow, tt.terraform, tt.repo))
			if got := countFindingsByRule(findings, RuleCrossDomainRiskyGitHubActionsCanAccessAWSS3Bucket); got != 0 {
				t.Fatalf("PP-XDOMAIN-003 count = %d, want 0: %#v", got, findings)
			}
		})
	}
}

func TestAnalyzeCrossDomainS3ReadAndWriteSameBucketProduceDistinctFindings(t *testing.T) {
	findings := Analyze(crossDomainGraphFromWorkflowAndTerraform(t, `on: pull_request_target
permissions: write-all
`, terraformRoleWithS3BucketAndPolicy("deploy", "repo:owner/repo:pull_request", "artifacts", "prod-artifacts", "all_s3", "s3:*", "arn:aws:s3:::prod-artifacts/*"), "owner/repo"))

	var s3Findings []Finding
	for _, finding := range findings {
		if finding.RuleID == RuleCrossDomainRiskyGitHubActionsCanAccessAWSS3Bucket {
			s3Findings = append(s3Findings, finding)
		}
	}
	if len(s3Findings) != 2 {
		t.Fatalf("PP-XDOMAIN-003 count = %d, want read and write findings: %#v", len(s3Findings), findings)
	}
	if s3Findings[0].ID == s3Findings[1].ID {
		t.Fatalf("read/write findings have duplicate ID: %#v", s3Findings)
	}
	kinds := map[graph.EdgeKind]bool{}
	for _, finding := range s3Findings {
		kinds[finding.Evidence[len(finding.Evidence)-1].Kind] = true
	}
	if !kinds[graph.CanReadObject] || !kinds[graph.CanWriteObject] {
		t.Fatalf("finding edge kinds = %#v, want read and write", kinds)
	}
}

func TestAnalyzeCrossDomainS3FindingIDsAreStableSensitiveAndSanitized(t *testing.T) {
	const envSecret = "FAKE_XDOMAIN3_GHA_ENV_SECRET_DO_NOT_RETAIN"
	const withSecret = "FAKE_XDOMAIN3_GHA_WITH_SECRET_DO_NOT_RETAIN"
	const runSecret = "FAKE_XDOMAIN3_GHA_RUN_SECRET_DO_NOT_RETAIN"
	const terraformSecret = "FAKE_XDOMAIN3_TF_SECRET_DO_NOT_RETAIN"
	workflow := `on: pull_request_target
permissions:
  id-token: write
env:
  TOKEN: FAKE_XDOMAIN3_GHA_ENV_SECRET_DO_NOT_RETAIN
jobs:
  deploy:
    steps:
      - run: echo FAKE_XDOMAIN3_GHA_RUN_SECRET_DO_NOT_RETAIN
      - uses: owner/action@0123456789abcdef0123456789abcdef01234567
        with:
          token: FAKE_XDOMAIN3_GHA_WITH_SECRET_DO_NOT_RETAIN
`
	terraform := terraformRoleWithS3BucketAndPolicy("deploy", "repo:owner/repo:pull_request", "artifacts", "prod-artifacts", "read", "s3:GetObject", "arn:aws:s3:::prod-artifacts/*") + "\n# " + terraformSecret + "\n"
	g := crossDomainGraphFromWorkflowAndTerraform(t, workflow, terraform, "owner/repo")

	first := mustMarshalFindings(t, Analyze(g))
	second := mustMarshalFindings(t, Analyze(g))
	if string(first) != string(second) {
		t.Fatalf("PP-XDOMAIN-003 findings differ across repeated analysis:\nfirst: %s\nsecond:%s", first, second)
	}
	base := onlyFindingByRule(t, Analyze(g), RuleCrossDomainRiskyGitHubActionsCanAccessAWSS3Bucket)
	changedBucket := onlyFindingByRule(t, Analyze(crossDomainGraphFromWorkflowAndTerraform(t, workflow, terraformRoleWithS3BucketAndPolicy("deploy", "repo:owner/repo:pull_request", "other", "other-artifacts", "read", "s3:GetObject", "arn:aws:s3:::other-artifacts/*"), "owner/repo")), RuleCrossDomainRiskyGitHubActionsCanAccessAWSS3Bucket)
	changedRole := onlyFindingByRule(t, Analyze(crossDomainGraphFromWorkflowAndTerraform(t, workflow, terraformRoleWithS3BucketAndPolicy("audit", "repo:owner/repo:pull_request", "artifacts", "prod-artifacts", "read", "s3:GetObject", "arn:aws:s3:::prod-artifacts/*"), "owner/repo")), RuleCrossDomainRiskyGitHubActionsCanAccessAWSS3Bucket)
	changedMode := onlyFindingByRule(t, Analyze(crossDomainGraphFromWorkflowAndTerraform(t, workflow, terraformRoleWithS3BucketAndPolicy("deploy", "repo:owner/repo:pull_request", "artifacts", "prod-artifacts", "write", "s3:PutObject", "arn:aws:s3:::prod-artifacts/*"), "owner/repo")), RuleCrossDomainRiskyGitHubActionsCanAccessAWSS3Bucket)
	for name, changed := range map[string]Finding{"bucket": changedBucket, "role": changedRole, "access mode": changedMode} {
		if base.ID == changed.ID {
			t.Fatalf("finding ID did not change when %s changed: %q", name, base.ID)
		}
	}
	data := mustMarshalFindings(t, Analyze(g))
	for _, forbidden := range []string{envSecret, withSecret, runSecret, terraformSecret, "run:", "${{", "assume_role_policy", "Principal", "Condition", "Statement", "policy =", "FAKE_XDOMAIN3"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("finding JSON contains %q: %s", forbidden, data)
		}
	}
}

func TestAnalyzeRiskSignalOmittedForExistingRules(t *testing.T) {
	findings := Analyze(githubActionsGraphFromWorkflow(t, `on: pull_request_target
permissions:
  contents: write
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`))

	data, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("marshal findings: %v", err)
	}
	if strings.Contains(string(data), "risk_signal") {
		t.Fatalf("existing rule JSON contains risk_signal: %s", data)
	}
}

func crossDomainWorkflowForIdentity(permission, access, jobID string) string {
	if permission == "all" {
		return `on: pull_request_target
jobs:
  ` + jobID + `:
    permissions: ` + access + `
`
	}
	return `on: pull_request_target
jobs:
  ` + jobID + `:
    permissions:
      ` + permission + `: ` + access + `
      id-token: write
`
}

func crossDomainGraphFromWorkflow(t *testing.T, workflow string, roleNames []string, repo string) *graph.Graph {
	t.Helper()
	var terraform strings.Builder
	for _, name := range roleNames {
		terraform.WriteString(terraformRole(name, "repo:owner/repo:pull_request"))
		terraform.WriteString("\n")
	}
	return crossDomainGraphFromWorkflowAndTerraform(t, workflow, terraform.String(), repo)
}

func crossDomainGraphFromWorkflowAndTerraform(t *testing.T, workflow, terraform, repo string) *graph.Graph {
	t.Helper()
	root := t.TempDir()
	writeWorkflowForAnalysisTest(t, root, "deploy.yml", workflow)
	writeTerraformForAnalysisTest(t, root, "infra/iam.tf", terraform)
	workflows, err := parsergithubactions.ParseDir(root)
	if err != nil {
		t.Fatalf("parse github actions: %v", err)
	}
	resources, err := parserterraform.ParseDir(root)
	if err != nil {
		t.Fatalf("parse terraform: %v", err)
	}
	g := graph.New()
	if err := routinggithubactions.AddRoutes(g, workflows); err != nil {
		t.Fatalf("route github actions: %v", err)
	}
	if err := routingterraform.AddRoutes(g, resources, workflows, repo); err != nil {
		t.Fatalf("route terraform: %v", err)
	}
	return g
}

func crossDomainAdminGraphFromWorkflowAndTerraform(t *testing.T, workflow, terraform, repo string) *graph.Graph {
	t.Helper()
	return crossDomainGraphFromWorkflowAndTerraform(t, workflow, terraform, repo)
}

func writeTerraformForAnalysisTest(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir terraform dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write terraform: %v", err)
	}
}

func terraformRole(name, subject string) string {
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
}
EOF
}
`
}

func terraformRoleWithInlineAdminPolicy(name, subject, policyName, action, resource string) string {
	return terraformRoleWithInlinePolicy(name, subject, policyName, action, resource)
}

func terraformRoleWithInlinePolicy(name, subject, policyName, action, resource string) string {
	return terraformRole(name, subject) + `
resource "aws_iam_role_policy" "` + policyName + `" {
  role = aws_iam_role.` + name + `.id
  policy = "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"` + action + `\",\"Resource\":\"` + resource + `\"}}"
}
`
}

func terraformRoleWithS3BucketAndPolicy(roleName, subject, bucketResourceName, bucketName, policyName, action, resource string) string {
	return terraformRole(roleName, subject) + terraformS3Bucket(bucketResourceName, bucketName) + `
resource "aws_iam_role_policy" "` + policyName + `" {
  role = aws_iam_role.` + roleName + `.id
  policy = "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"` + action + `\",\"Resource\":\"` + resource + `\"}}"
}
`
}

func terraformS3Bucket(resourceName, bucketName string) string {
	return `
resource "aws_s3_bucket" "` + resourceName + `" {
  bucket = "` + bucketName + `"
}
`
}

func terraformRoleWithSubjectsAndInlineAdminPolicy(name string, subjects []string, policyName, action, resource string) string {
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

func manualCrossDomainAdminGraph(t *testing.T, reversed bool) *graph.Graph {
	t.Helper()
	g := graph.New()
	workflow := graph.NewNode(graph.Workflow, "githubactions://.github/workflows/deploy.yml")
	workflow.Evidence = []graph.SourceEvidence{{Source: ".github/workflows/deploy.yml#document=1", Detail: "github actions workflow with permissions: write-all"}}
	workflow.Metadata = &graph.NodeMetadata{GitHubActionsWorkflow: &graph.GitHubActionsWorkflow{
		WorkflowSourceReference:   ".github/workflows/deploy.yml#document=1",
		WorkflowFile:              ".github/workflows/deploy.yml",
		WorkflowName:              "Deploy",
		TriggersPullRequestTarget: true,
		PermissionGrants: []graph.GitHubActionsPermissionGrant{{
			Scope:      "workflow",
			Permission: "all",
			Access:     "write-all",
		}},
	}}
	capability := graph.NewNode(graph.OIDCTokenCapability, "githubactions://.github/workflows/deploy.yml/oidc-token/workflow")
	capability.Metadata = &graph.NodeMetadata{GitHubActionsOIDCTokenCapability: &graph.GitHubActionsOIDCTokenCapability{
		Provider:                "github-actions",
		WorkflowSourceReference: ".github/workflows/deploy.yml#document=1",
		WorkflowFile:            ".github/workflows/deploy.yml",
		WorkflowName:            "Deploy",
		Scope:                   "workflow",
	}}
	role := graph.NewNode(graph.AWSIAMRole, "aws://terraform/aws_iam_role/infra/iam.tf/deploy")
	role.Metadata = &graph.NodeMetadata{AWSIAMRole: &graph.AWSIAMRoleMetadata{
		Provider:        "aws",
		ResourceName:    "deploy",
		SourceReference: "infra/iam.tf#resource=aws_iam_role.deploy",
	}}
	permissionStar := graph.NewNode(graph.AWSPermission, "aws://terraform/aws_permission/admin-star")
	permissionStar.Metadata = &graph.NodeMetadata{AWSPermission: &graph.AWSPermissionMetadata{
		Provider:                 "aws",
		SourceReference:          "infra/iam.tf#resource=aws_iam_role_policy.admin_star",
		PolicyResourceName:       "admin_star",
		AttachedRoleResourceName: "deploy",
		Actions:                  []string{"*"},
		Resources:                []string{"*"},
		Administrative:           true,
		AdminReason:              "action_star_resource_star",
	}}
	permissionServiceStar := graph.NewNode(graph.AWSPermission, "aws://terraform/aws_permission/admin-service-star")
	permissionServiceStar.Metadata = &graph.NodeMetadata{AWSPermission: &graph.AWSPermissionMetadata{
		Provider:                 "aws",
		SourceReference:          "infra/iam.tf#resource=aws_iam_role_policy.admin_service_star",
		PolicyResourceName:       "admin_service_star",
		AttachedRoleResourceName: "deploy",
		Actions:                  []string{"*:*"},
		Resources:                []string{"*"},
		Administrative:           true,
		AdminReason:              "action_service_star_resource_star",
	}}

	nodes := []graph.Node{workflow, capability, role, permissionStar, permissionServiceStar}
	if reversed {
		nodes = []graph.Node{permissionServiceStar, permissionStar, role, capability, workflow}
	}
	var added []graph.Node
	for _, node := range nodes {
		added = append(added, mustAddNode(t, g, node))
	}
	byName := make(map[string]graph.Node, len(added))
	for _, node := range added {
		byName[node.Name] = node
	}
	workflow = byName["githubactions://.github/workflows/deploy.yml"]
	capability = byName["githubactions://.github/workflows/deploy.yml/oidc-token/workflow"]
	role = byName["aws://terraform/aws_iam_role/infra/iam.tf/deploy"]
	permissionStar = byName["aws://terraform/aws_permission/admin-star"]
	permissionServiceStar = byName["aws://terraform/aws_permission/admin-service-star"]

	oidc := graph.NewEdge(graph.CanRequestOIDCToken, workflow.ID, capability.ID, graph.SourceEvidence{
		Source: ".github/workflows/deploy.yml#document=1",
		Detail: "github actions workflow can request OIDC token because permissions: write-all includes id-token: write",
	})
	assumeRole := graph.NewEdge(graph.CanAssumeRole, capability.ID, role.ID, graph.SourceEvidence{
		Source: "infra/iam.tf#resource=aws_iam_role.deploy",
		Detail: "github actions oidc subject repo:owner/repo:pull_request matches aws iam role deploy trust statement 0",
	})
	assumeRole.Metadata = &graph.EdgeMetadata{AWSCanAssumeRole: &graph.AWSCanAssumeRoleMetadata{
		Provider:         "aws",
		RoleResourceName: "deploy",
		SubjectCandidate: "repo:owner/repo:pull_request",
	}}
	star := graph.NewEdge(graph.GrantsPermission, role.ID, permissionStar.ID, graph.SourceEvidence{
		Source: "infra/iam.tf#resource=aws_iam_role_policy.admin_star",
		Detail: "aws iam role deploy grants administrative permission via inline_policy admin_star (action_star_resource_star action=* resource=*)",
	})
	serviceStar := graph.NewEdge(graph.GrantsPermission, role.ID, permissionServiceStar.ID, graph.SourceEvidence{
		Source: "infra/iam.tf#resource=aws_iam_role_policy.admin_service_star",
		Detail: "aws iam role deploy grants administrative permission via inline_policy admin_service_star (action_service_star_resource_star action=*:* resource=*)",
	})
	edges := []graph.Edge{oidc, assumeRole, star, serviceStar}
	if reversed {
		edges = []graph.Edge{serviceStar, star, assumeRole, oidc}
	}
	for _, edge := range edges {
		mustAddEdge(t, g, edge)
	}
	return g
}

func assertFindingNodeKinds(t *testing.T, finding Finding, want []graph.NodeKind) {
	t.Helper()
	if len(finding.NodeIDs) != len(want) {
		t.Fatalf("node ID count = %d, want %d: %#v", len(finding.NodeIDs), len(want), finding)
	}
	for i, nodeID := range finding.NodeIDs {
		if !strings.Contains(string(nodeID), "node:"+string(want[i])+":") {
			t.Fatalf("node[%d] = %q, want kind %s", i, nodeID, want[i])
		}
	}
}

func assertFindingEdgeKinds(t *testing.T, finding Finding, want []graph.EdgeKind) {
	t.Helper()
	if len(finding.EdgeIDs) != len(want) {
		t.Fatalf("edge ID count = %d, want %d: %#v", len(finding.EdgeIDs), len(want), finding)
	}
	if len(finding.Evidence) != len(want) {
		t.Fatalf("evidence count = %d, want %d: %#v", len(finding.Evidence), len(want), finding)
	}
	for i, kind := range want {
		if finding.Evidence[i].Kind != kind {
			t.Fatalf("evidence[%d].kind = %q, want %q", i, finding.Evidence[i].Kind, kind)
		}
	}
}

func onlyEdgeByKind(t *testing.T, g *graph.Graph, kind graph.EdgeKind) graph.Edge {
	t.Helper()
	var edges []graph.Edge
	for _, edge := range g.Edges() {
		if edge.Kind == kind {
			edges = append(edges, edge)
		}
	}
	if len(edges) != 1 {
		t.Fatalf("%s edge count = %d, want 1: %#v", kind, len(edges), edges)
	}
	return edges[0]
}

func TestAnalyzeCrossDomainNoGraphMutation(t *testing.T) {
	g := crossDomainGraphFromWorkflow(t, `on: pull_request_target
permissions: write-all
`, []string{"deploy"}, "owner/repo")
	before := mustMarshalGraph(t, g)
	first := mustMarshalFindings(t, Analyze(g))
	second := mustMarshalFindings(t, Analyze(g))
	after := mustMarshalGraph(t, g)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("graph changed after analysis:\nbefore: %s\nafter: %s", before, after)
	}
	if string(first) != string(second) {
		t.Fatalf("findings changed across repeated analysis:\nfirst: %s\nsecond:%s", first, second)
	}
}
