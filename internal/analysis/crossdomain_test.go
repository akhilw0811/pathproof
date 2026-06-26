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
