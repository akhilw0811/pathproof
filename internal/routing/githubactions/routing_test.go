package githubactions

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"pathproof/internal/graph"
	parsergithubactions "pathproof/internal/parser/githubactions"
)

func TestAddRoutesBuildsWorkflowJobAndActionGraph(t *testing.T) {
	resources := parsergithubactions.Resources{Workflows: []parsergithubactions.Workflow{{
		Name: "Build",
		Source: parsergithubactions.Source{
			Filename:     "/repo/.github/workflows/build.yml",
			RelativePath: ".github/workflows/build.yml",
			Document:     1,
		},
		Jobs: []parsergithubactions.Job{{
			ID: "test",
			Steps: []parsergithubactions.Step{{
				Index: 0,
				Name:  "Checkout",
				Uses:  "actions/checkout@v4",
				Owner: "actions",
				Repo:  "checkout",
				Ref:   "v4",
			}},
		}},
	}}}
	g := graph.New()

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	workflow := graph.NewNode(graph.Workflow, "githubactions://.github/workflows/build.yml")
	job := graph.NewNode(graph.WorkflowJob, "githubactions://.github/workflows/build.yml/job/test")
	action := graph.NewNode(graph.GitHubAction, "githubactions://.github/workflows/build.yml/job/test/step/0/action/actions/checkout@v4")
	for _, node := range []graph.Node{workflow, job, action} {
		if _, ok := g.Node(node.ID); !ok {
			t.Fatalf("missing node %s %s", node.Kind, node.Name)
		}
	}

	defines := graph.NewEdge(graph.DefinesJob, workflow.ID, job.ID, graph.SourceEvidence{})
	uses := graph.NewEdge(graph.UsesAction, job.ID, action.ID, graph.SourceEvidence{})
	gotDefines, ok := g.Edge(defines.ID)
	if !ok {
		t.Fatalf("missing DefinesJob edge %q", defines.ID)
	}
	if gotDefines.Evidence.Source != "/repo/.github/workflows/build.yml#document=1" {
		t.Fatalf("DefinesJob source = %q", gotDefines.Evidence.Source)
	}
	gotUses, ok := g.Edge(uses.ID)
	if !ok {
		t.Fatalf("missing UsesAction edge %q", uses.ID)
	}
	if gotUses.Metadata == nil || gotUses.Metadata.GitHubActionUse == nil {
		t.Fatalf("UsesAction metadata missing: %#v", gotUses)
	}
	wantUse := graph.GitHubActionUse{
		WorkflowSourceReference: "/repo/.github/workflows/build.yml#document=1",
		WorkflowFile:            ".github/workflows/build.yml",
		WorkflowName:            "Build",
		JobID:                   "test",
		StepIndex:               0,
		StepName:                "Checkout",
		Uses:                    "actions/checkout@v4",
		Owner:                   "actions",
		Repo:                    "checkout",
		Ref:                     "v4",
	}
	if !reflect.DeepEqual(*gotUses.Metadata.GitHubActionUse, wantUse) {
		t.Fatalf("metadata = %#v, want %#v", *gotUses.Metadata.GitHubActionUse, wantUse)
	}
}

func TestAddRoutesKeepsRepeatedActionUsesDistinctByStep(t *testing.T) {
	resources := parsergithubactions.Resources{Workflows: []parsergithubactions.Workflow{{
		Source: parsergithubactions.Source{Filename: "workflow.yml", RelativePath: ".github/workflows/workflow.yml", Document: 1},
		Jobs: []parsergithubactions.Job{{
			ID: "test",
			Steps: []parsergithubactions.Step{
				{Index: 0, Uses: "owner/repo@main", Owner: "owner", Repo: "repo", Ref: "main"},
				{Index: 1, Uses: "owner/repo@main", Owner: "owner", Repo: "repo", Ref: "main"},
			},
		}},
	}}}
	g := graph.New()

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	actionCount := 0
	for _, node := range g.Nodes() {
		if node.Kind == graph.GitHubAction {
			actionCount++
		}
	}
	if actionCount != 2 {
		t.Fatalf("GitHubAction node count = %d, want 2", actionCount)
	}
}

func TestAddRoutesGraphJSONExcludesIgnoredWorkflowValues(t *testing.T) {
	root := t.TempDir()
	writeWorkflowForRoutingTest(t, root, "workflow.yml", `name: Secret safety
env:
  TOKEN: FAKE_GHA_ENV_SECRET_DO_NOT_RETAIN
jobs:
  test:
    steps:
      - run: echo FAKE_GHA_RUN_SECRET_DO_NOT_RETAIN
      - uses: docker/login-action@v3
        with:
          password: FAKE_GHA_WITH_SECRET_DO_NOT_RETAIN
`)
	resources, err := parsergithubactions.ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	g := graph.New()

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}
	data, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal graph: %v", err)
	}
	for _, forbidden := range []string{
		"FAKE_GHA_ENV_SECRET_DO_NOT_RETAIN",
		"FAKE_GHA_WITH_SECRET_DO_NOT_RETAIN",
		"FAKE_GHA_RUN_SECRET_DO_NOT_RETAIN",
		"stringData:",
		"password:",
	} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("graph JSON contains %q: %s", forbidden, data)
		}
	}
}

func TestAddRoutesGraphJSONExcludesInvalidPermissionMapValues(t *testing.T) {
	root := t.TempDir()
	writeWorkflowForRoutingTest(t, root, "permissions.yml", `on: pull_request_target
permissions:
  contents: write-all
  actions: ${{ inputs.permission }}
jobs:
  test:
    permissions:
      contents: read-all
      checks: unknown
`)
	resources, err := parsergithubactions.ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	g := graph.New()

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}
	data, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal graph: %v", err)
	}
	for _, forbidden := range []string{"write-all", "read-all", "inputs.permission", "${{", "unknown"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("graph JSON contains %q: %s", forbidden, data)
		}
	}
}

func writeWorkflowForRoutingTest(t *testing.T, root, name, content string) {
	t.Helper()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir workflow dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}
}

func TestAddRoutesPreservesPullRequestTargetCheckoutSelectorMetadata(t *testing.T) {
	resources := parsergithubactions.Resources{Workflows: []parsergithubactions.Workflow{{
		Name: "Unsafe",
		Source: parsergithubactions.Source{
			Filename:     "/repo/.github/workflows/unsafe.yml",
			RelativePath: ".github/workflows/unsafe.yml",
			Document:     1,
		},
		TriggersPullRequestTarget: true,
		Jobs: []parsergithubactions.Job{{
			ID: "test",
			Steps: []parsergithubactions.Step{{
				Index: 0,
				Name:  "Checkout",
				Uses:  "actions/checkout@v4",
				Owner: "actions",
				Repo:  "checkout",
				Ref:   "v4",
				CheckoutHeadSelectors: []parsergithubactions.CheckoutHeadSelector{{
					Field:             "ref",
					MatchedExpression: "github.event.pull_request.head.sha",
				}},
			}},
		}},
	}}}
	g := graph.New()

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	workflow := graph.NewNode(graph.Workflow, "githubactions://.github/workflows/unsafe.yml")
	job := graph.NewNode(graph.WorkflowJob, "githubactions://.github/workflows/unsafe.yml/job/test")
	action := graph.NewNode(graph.GitHubAction, "githubactions://.github/workflows/unsafe.yml/job/test/step/0/action/actions/checkout@v4")
	uses := graph.NewEdge(graph.UsesAction, job.ID, action.ID, graph.SourceEvidence{})
	gotUses, ok := g.Edge(uses.ID)
	if !ok {
		t.Fatalf("missing UsesAction edge %q", uses.ID)
	}
	if _, ok := g.Node(workflow.ID); !ok {
		t.Fatalf("missing workflow node %s", workflow.ID)
	}
	actionUse := gotUses.Metadata.GitHubActionUse
	if actionUse == nil || !actionUse.TriggersPullRequestTarget {
		t.Fatalf("action metadata = %#v, want pull_request_target", gotUses.Metadata)
	}
	wantSelectors := []graph.GitHubActionsCheckoutHeadSelector{{
		Field:             "ref",
		MatchedExpression: "github.event.pull_request.head.sha",
	}}
	if !reflect.DeepEqual(actionUse.CheckoutHeadSelectors, wantSelectors) {
		t.Fatalf("selectors = %#v, want %#v", actionUse.CheckoutHeadSelectors, wantSelectors)
	}
	if !strings.Contains(gotUses.Evidence.Detail, "ref=github.event.pull_request.head.sha") {
		t.Fatalf("evidence detail = %q, want sanitized selector", gotUses.Evidence.Detail)
	}
}

func TestAddRoutesPreservesGitHubActionsPermissionGrantMetadata(t *testing.T) {
	resources := parsergithubactions.Resources{Workflows: []parsergithubactions.Workflow{{
		Name: "Permissions",
		Source: parsergithubactions.Source{
			Filename:     "/repo/.github/workflows/permissions.yml",
			RelativePath: ".github/workflows/permissions.yml",
			Document:     1,
		},
		TriggersPullRequestTarget: true,
		PermissionGrants: []parsergithubactions.PermissionGrant{{
			Scope:      "workflow",
			Permission: "all",
			Access:     "write-all",
		}},
		Jobs: []parsergithubactions.Job{{
			ID: "test",
			PermissionGrants: []parsergithubactions.PermissionGrant{{
				Scope:      "job",
				JobID:      "test",
				Permission: "contents",
				Access:     "write",
			}},
		}},
	}}}
	g := graph.New()

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	workflow := graph.NewNode(graph.Workflow, "githubactions://.github/workflows/permissions.yml")
	gotWorkflow, ok := g.Node(workflow.ID)
	if !ok {
		t.Fatalf("missing workflow node %q", workflow.ID)
	}
	if gotWorkflow.Metadata == nil || gotWorkflow.Metadata.GitHubActionsWorkflow == nil {
		t.Fatalf("workflow metadata = %#v, want github actions workflow metadata", gotWorkflow.Metadata)
	}
	wantWorkflow := graph.GitHubActionsWorkflow{
		WorkflowSourceReference:   "/repo/.github/workflows/permissions.yml#document=1",
		WorkflowFile:              ".github/workflows/permissions.yml",
		WorkflowName:              "Permissions",
		TriggersPullRequestTarget: true,
		PermissionGrants: []graph.GitHubActionsPermissionGrant{{
			Scope:      "workflow",
			Permission: "all",
			Access:     "write-all",
		}},
	}
	if !reflect.DeepEqual(*gotWorkflow.Metadata.GitHubActionsWorkflow, wantWorkflow) {
		t.Fatalf("workflow metadata = %#v, want %#v", *gotWorkflow.Metadata.GitHubActionsWorkflow, wantWorkflow)
	}
	if len(gotWorkflow.Evidence) != 1 || !strings.Contains(gotWorkflow.Evidence[0].Detail, "permissions: write-all") {
		t.Fatalf("workflow evidence = %#v, want permissions: write-all", gotWorkflow.Evidence)
	}
	if strings.Contains(gotWorkflow.Evidence[0].Detail, "all: write") {
		t.Fatalf("workflow evidence renders write-all confusingly: %q", gotWorkflow.Evidence[0].Detail)
	}

	job := graph.NewNode(graph.WorkflowJob, "githubactions://.github/workflows/permissions.yml/job/test")
	defines := graph.NewEdge(graph.DefinesJob, workflow.ID, job.ID, graph.SourceEvidence{})
	gotDefines, ok := g.Edge(defines.ID)
	if !ok {
		t.Fatalf("missing DefinesJob edge %q", defines.ID)
	}
	if gotDefines.Metadata == nil || gotDefines.Metadata.GitHubActionsWorkflowJob == nil {
		t.Fatalf("DefinesJob metadata = %#v, want github actions workflow job metadata", gotDefines.Metadata)
	}
	wantJob := graph.GitHubActionsWorkflowJob{
		WorkflowSourceReference:   "/repo/.github/workflows/permissions.yml#document=1",
		WorkflowFile:              ".github/workflows/permissions.yml",
		WorkflowName:              "Permissions",
		TriggersPullRequestTarget: true,
		JobID:                     "test",
		PermissionGrants: []graph.GitHubActionsPermissionGrant{{
			Scope:      "job",
			JobID:      "test",
			Permission: "contents",
			Access:     "write",
		}},
	}
	if !reflect.DeepEqual(*gotDefines.Metadata.GitHubActionsWorkflowJob, wantJob) {
		t.Fatalf("job metadata = %#v, want %#v", *gotDefines.Metadata.GitHubActionsWorkflowJob, wantJob)
	}
	if strings.Contains(gotDefines.Evidence.Detail, "all: write") {
		t.Fatalf("evidence detail renders write-all confusingly: %q", gotDefines.Evidence.Detail)
	}
	if strings.Contains(gotDefines.Evidence.Detail, "contents: write") {
		t.Fatalf("DefinesJob evidence contains shared permission text: %q", gotDefines.Evidence.Detail)
	}
	if gotDefines.Evidence.Detail != "github actions workflow defines job test" {
		t.Fatalf("DefinesJob evidence detail = %q, want generic job evidence", gotDefines.Evidence.Detail)
	}
}
