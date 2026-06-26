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
	routinggithubactions "pathproof/internal/routing/githubactions"
)

const pinnedSHA = "0123456789abcdef0123456789ABCDEF01234567"

func TestAnalyzeGitHubActionsUnpinnedActionFindings(t *testing.T) {
	tests := []struct {
		name string
		uses string
		want bool
	}{
		{name: "actions checkout tag", uses: "actions/checkout@v4", want: true},
		{name: "docker login branch", uses: "docker/login-action@main", want: true},
		{name: "owner repo path tag", uses: "owner/repo/path@v1.2.3", want: true},
		{name: "missing ref", uses: "owner/repo/path", want: true},
		{name: "expression ref with static owner repo", uses: "owner/repo@${{ matrix.ref }}", want: true},
		{name: "owner repo SHA", uses: "owner/repo@" + pinnedSHA, want: false},
		{name: "owner repo path SHA", uses: "owner/repo/path@" + pinnedSHA, want: false},
		{name: "local", uses: "./local-action", want: false},
		{name: "docker action", uses: "docker://alpine:3.19", want: false},
		{name: "entire expression", uses: "${{ matrix.action }}", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := githubActionsGraphFromUses(t, tt.uses)
			findings := Analyze(g)
			if tt.want {
				if len(findings) != 1 {
					t.Fatalf("finding count = %d, want 1: %#v", len(findings), findings)
				}
				finding := findings[0]
				if finding.RuleID != RuleGitHubActionsUnpinnedAction {
					t.Fatalf("rule_id = %q, want %q", finding.RuleID, RuleGitHubActionsUnpinnedAction)
				}
				if finding.Title != githubActionsUnpinnedActionTitle {
					t.Fatalf("title = %q, want %q", finding.Title, githubActionsUnpinnedActionTitle)
				}
				if finding.Severity != SeverityMedium {
					t.Fatalf("severity = %q, want Medium", finding.Severity)
				}
				if strings.Contains(strings.ToLower(finding.Title), legacyGitHubActionsRuleWording()) || strings.Contains(strings.ToLower(finding.Summary), legacyGitHubActionsRuleWording()) {
					t.Fatalf("finding uses old inaccurate wording: %#v", finding)
				}
				if len(finding.NodeIDs) != 3 || len(finding.EdgeIDs) != 2 || len(finding.Evidence) != 2 {
					t.Fatalf("finding path/evidence shape = %#v/%#v/%#v, want 3 nodes, 2 edges, 2 evidence", finding.NodeIDs, finding.EdgeIDs, finding.Evidence)
				}
				if !strings.Contains(finding.Summary, tt.uses) {
					t.Fatalf("summary = %q, want raw uses %q", finding.Summary, tt.uses)
				}
				return
			}
			if len(findings) != 0 {
				t.Fatalf("finding count = %d, want 0: %#v", len(findings), findings)
			}
		})
	}
}

func legacyGitHubActionsRuleWording() string {
	return "third" + "-party"
}

func TestAnalyzeGitHubActionsFindingIDsAreStableAndRefSensitive(t *testing.T) {
	first := Analyze(githubActionsGraphFromUses(t, "owner/repo@main"))
	second := Analyze(githubActionsGraphFromUses(t, "owner/repo@main"))
	changed := Analyze(githubActionsGraphFromUses(t, "owner/repo@v1"))

	if len(first) != 1 || len(second) != 1 || len(changed) != 1 {
		t.Fatalf("finding counts = %d/%d/%d, want all one", len(first), len(second), len(changed))
	}
	if first[0].ID != second[0].ID {
		t.Fatalf("finding ID changed across repeated analysis: %q vs %q", first[0].ID, second[0].ID)
	}
	if first[0].ID == changed[0].ID {
		t.Fatalf("finding ID did not change when ref changed: %q", first[0].ID)
	}
}

func TestAnalyzeGitHubActionsRepeatedAnalysisIsDeterministic(t *testing.T) {
	g := githubActionsGraphFromUses(t, "owner/repo@main")
	first := Analyze(g)
	second := Analyze(g)

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("findings differ across repeated analysis:\nfirst=%#v\nsecond=%#v", first, second)
	}
}

func TestAnalyzeGitHubActionsSecretLikeWorkflowValuesAbsentFromFindings(t *testing.T) {
	const envSecret = "FAKE_ANALYSIS_GHA_ENV_SECRET_DO_NOT_RETAIN"
	const withSecret = "FAKE_ANALYSIS_GHA_WITH_SECRET_DO_NOT_RETAIN"
	const runSecret = "FAKE_ANALYSIS_GHA_RUN_SECRET_DO_NOT_RETAIN"
	root := t.TempDir()
	writeWorkflowForAnalysisTest(t, root, "secret.yml", `name: Secret safety
env:
  TOKEN: FAKE_ANALYSIS_GHA_ENV_SECRET_DO_NOT_RETAIN
jobs:
  test:
    steps:
      - run: echo FAKE_ANALYSIS_GHA_RUN_SECRET_DO_NOT_RETAIN
      - uses: owner/repo@main
        with:
          password: FAKE_ANALYSIS_GHA_WITH_SECRET_DO_NOT_RETAIN
`)
	resources, err := parsergithubactions.ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	g := graph.New()
	if err := routinggithubactions.AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	findings := Analyze(g)
	data, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("marshal findings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("finding count = %d, want 1", len(findings))
	}
	for _, forbidden := range []string{envSecret, withSecret, runSecret, "password:", "run:"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("finding JSON contains %q: %s", forbidden, data)
		}
	}
}

func githubActionsGraphFromUses(t *testing.T, uses string) *graph.Graph {
	t.Helper()
	resources := parsergithubactions.Resources{Workflows: []parsergithubactions.Workflow{{
		Name: "Build",
		Source: parsergithubactions.Source{
			Filename:     ".github/workflows/build.yml",
			RelativePath: ".github/workflows/build.yml",
			Document:     1,
		},
		Jobs: []parsergithubactions.Job{{
			ID: "test",
			Steps: []parsergithubactions.Step{{
				Index: 0,
				Name:  "Use action",
				Uses:  uses,
			}},
		}},
	}}}
	g := graph.New()
	if err := routinggithubactions.AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}
	return g
}

func writeWorkflowForAnalysisTest(t *testing.T, root, name, content string) {
	t.Helper()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir workflow dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}
}
