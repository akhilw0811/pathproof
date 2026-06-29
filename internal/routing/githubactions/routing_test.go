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

func TestAddRoutesPreservesGitHubActionUsesCoordinatesAndPatchSafety(t *testing.T) {
	root := t.TempDir()
	writeWorkflowForRoutingTest(t, root, "workflow.yml", `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
        env:
          TOKEN: FAKE_ROUTING_GHA_COORD_SECRET_DO_NOT_RETAIN
`)
	resources, err := parsergithubactions.ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	g := graph.New()

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	var actionUse *graph.GitHubActionUse
	for _, edge := range g.Edges() {
		if edge.Kind == graph.UsesAction && edge.Metadata != nil {
			actionUse = edge.Metadata.GitHubActionUse
		}
	}
	if actionUse == nil {
		t.Fatal("GitHubActionUse metadata missing")
	}
	if actionUse.UsesLine != 4 || actionUse.UsesColumn != 15 {
		t.Fatalf("uses coordinates = %d/%d, want 4/15", actionUse.UsesLine, actionUse.UsesColumn)
	}
	if actionUse.PatchUnsupportedReason == "" {
		t.Fatalf("patch unsupported reason is empty")
	}
	data, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal graph: %v", err)
	}
	if strings.Contains(string(data), "FAKE_ROUTING_GHA_COORD_SECRET_DO_NOT_RETAIN") || strings.Contains(string(data), "TOKEN") {
		t.Fatalf("graph output contains secret-like workflow value: %s", data)
	}
}

func TestAddRoutesPreservesQuotedUsesPatchColumnAndHarmlessContext(t *testing.T) {
	root := t.TempDir()
	writeWorkflowForRoutingTest(t, root, "workflow.yml", `jobs:
  test:
    env:
      SAFE_ENV: local
    steps:
      - run: go test ./...
      - uses: "actions/setup-go@v5"
        with:
          go-version: '1.22'
`)
	resources, err := parsergithubactions.ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	g := graph.New()

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	var actionUse *graph.GitHubActionUse
	for _, edge := range g.Edges() {
		if edge.Kind == graph.UsesAction && edge.Metadata != nil {
			actionUse = edge.Metadata.GitHubActionUse
		}
	}
	if actionUse == nil {
		t.Fatal("GitHubActionUse metadata missing")
	}
	if actionUse.Uses != "actions/setup-go@v5" || actionUse.UsesLine != 7 || actionUse.UsesColumn != 16 {
		t.Fatalf("action metadata = %#v, want quoted setup-go coordinates 7/16", actionUse)
	}
	if actionUse.PatchUnsupportedReason != "" {
		t.Fatalf("patch unsupported reason = %q, want empty", actionUse.PatchUnsupportedReason)
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

func TestAddRoutesWorkflowLevelIDTokenWriteCreatesOIDCTokenCapability(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".github", "workflows", "oidc.yml")
	writeWorkflowForRoutingTest(t, root, "oidc.yml", `name: OIDC
on: push
permissions:
  id-token: write
jobs:
  test:
    steps:
      - run: echo test
`)
	resources, err := parsergithubactions.ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	g := graph.New()

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	workflow := graph.NewNode(graph.Workflow, "githubactions://.github/workflows/oidc.yml")
	capability := graph.NewNode(graph.OIDCTokenCapability, "githubactions://.github/workflows/oidc.yml/oidc-token/workflow")
	gotCapability, ok := g.Node(capability.ID)
	if !ok {
		t.Fatalf("missing OIDC capability node %q", capability.ID)
	}
	wantCapability := graph.GitHubActionsOIDCTokenCapability{
		Provider:                "github-actions",
		WorkflowSourceReference: path + "#document=1",
		WorkflowFile:            ".github/workflows/oidc.yml",
		WorkflowName:            "OIDC",
		Scope:                   "workflow",
	}
	if gotCapability.Metadata == nil || gotCapability.Metadata.GitHubActionsOIDCTokenCapability == nil {
		t.Fatalf("capability metadata = %#v, want OIDC metadata", gotCapability.Metadata)
	}
	if !reflect.DeepEqual(*gotCapability.Metadata.GitHubActionsOIDCTokenCapability, wantCapability) {
		t.Fatalf("capability metadata = %#v, want %#v", *gotCapability.Metadata.GitHubActionsOIDCTokenCapability, wantCapability)
	}

	edge := graph.NewEdge(graph.CanRequestOIDCToken, workflow.ID, capability.ID, graph.SourceEvidence{})
	gotEdge, ok := g.Edge(edge.ID)
	if !ok {
		t.Fatalf("missing CanRequestOIDCToken edge %q", edge.ID)
	}
	if gotEdge.Evidence.Detail != "github actions workflow can request OIDC token with id-token: write" {
		t.Fatalf("edge detail = %q, want explicit id-token evidence", gotEdge.Evidence.Detail)
	}
	wantRequest := graph.GitHubActionsOIDCTokenRequest{
		Provider:                "github-actions",
		WorkflowSourceReference: path + "#document=1",
		WorkflowFile:            ".github/workflows/oidc.yml",
		WorkflowName:            "OIDC",
		Scope:                   "workflow",
		Permission:              "id-token",
		Access:                  "write",
	}
	if gotEdge.Metadata == nil || gotEdge.Metadata.GitHubActionsOIDCTokenRequest == nil {
		t.Fatalf("edge metadata = %#v, want OIDC request metadata", gotEdge.Metadata)
	}
	if !reflect.DeepEqual(*gotEdge.Metadata.GitHubActionsOIDCTokenRequest, wantRequest) {
		t.Fatalf("edge metadata = %#v, want %#v", *gotEdge.Metadata.GitHubActionsOIDCTokenRequest, wantRequest)
	}
}

func TestAddRoutesJobLevelIDTokenWriteCreatesOIDCTokenCapability(t *testing.T) {
	resources := parsergithubactions.Resources{Workflows: []parsergithubactions.Workflow{{
		Name:   "OIDC",
		Source: parsergithubactions.Source{Filename: "/repo/.github/workflows/oidc.yml", RelativePath: ".github/workflows/oidc.yml", Document: 1},
		Jobs: []parsergithubactions.Job{{
			ID: "deploy",
			PermissionGrants: []parsergithubactions.PermissionGrant{{
				Scope:      "job",
				JobID:      "deploy",
				Permission: "id-token",
				Access:     "write",
			}},
		}},
	}}}
	g := graph.New()

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	job := graph.NewNode(graph.WorkflowJob, "githubactions://.github/workflows/oidc.yml/job/deploy")
	capability := graph.NewNode(graph.OIDCTokenCapability, "githubactions://.github/workflows/oidc.yml/job/deploy/oidc-token")
	gotCapability, ok := g.Node(capability.ID)
	if !ok {
		t.Fatalf("missing OIDC capability node %q", capability.ID)
	}
	if gotCapability.Metadata == nil || gotCapability.Metadata.GitHubActionsOIDCTokenCapability == nil {
		t.Fatalf("capability metadata = %#v, want OIDC metadata", gotCapability.Metadata)
	}
	if gotCapability.Metadata.GitHubActionsOIDCTokenCapability.Scope != "job" || gotCapability.Metadata.GitHubActionsOIDCTokenCapability.JobID != "deploy" {
		t.Fatalf("capability metadata = %#v, want job deploy", gotCapability.Metadata.GitHubActionsOIDCTokenCapability)
	}

	edge := graph.NewEdge(graph.CanRequestOIDCToken, job.ID, capability.ID, graph.SourceEvidence{})
	gotEdge, ok := g.Edge(edge.ID)
	if !ok {
		t.Fatalf("missing CanRequestOIDCToken edge %q", edge.ID)
	}
	if gotEdge.Evidence.Detail != "github actions job deploy can request OIDC token with id-token: write" {
		t.Fatalf("edge detail = %q, want explicit job id-token evidence", gotEdge.Evidence.Detail)
	}
	if gotEdge.Metadata == nil || gotEdge.Metadata.GitHubActionsOIDCTokenRequest == nil {
		t.Fatalf("edge metadata = %#v, want OIDC request metadata", gotEdge.Metadata)
	}
	if gotEdge.Metadata.GitHubActionsOIDCTokenRequest.Scope != "job" || gotEdge.Metadata.GitHubActionsOIDCTokenRequest.JobID != "deploy" {
		t.Fatalf("edge metadata = %#v, want job deploy", gotEdge.Metadata.GitHubActionsOIDCTokenRequest)
	}
}

func TestAddRoutesOIDCTokenCapabilityPermissionCases(t *testing.T) {
	tests := []struct {
		name       string
		workflow   string
		wantEdges  int
		wantDetail string
	}{
		{
			name: "id token read",
			workflow: `permissions:
  id-token: read
`,
		},
		{
			name: "id token none",
			workflow: `permissions:
  id-token: none
`,
		},
		{
			name: "omitted permissions",
			workflow: `jobs:
  test:
    steps:
      - run: echo test
`,
		},
		{
			name: "write all",
			workflow: `permissions: write-all
`,
			wantEdges:  1,
			wantDetail: "github actions workflow can request OIDC token because permissions: write-all includes id-token: write",
		},
		{
			name: "read all",
			workflow: `permissions: read-all
`,
		},
		{
			name: "job write all",
			workflow: `jobs:
  deploy:
    permissions: write-all
`,
			wantEdges:  1,
			wantDetail: "github actions job deploy can request OIDC token because permissions: write-all includes id-token: write",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeWorkflowForRoutingTest(t, root, "oidc.yml", tt.workflow)
			resources, err := parsergithubactions.ParseDir(root)
			if err != nil {
				t.Fatalf("parse dir: %v", err)
			}
			g := graph.New()

			if err := AddRoutes(g, resources); err != nil {
				t.Fatalf("add routes: %v", err)
			}

			edges := oidcTokenRequestEdges(g)
			if len(edges) != tt.wantEdges {
				t.Fatalf("OIDC edge count = %d, want %d: %#v", len(edges), tt.wantEdges, edges)
			}
			if tt.wantEdges == 0 {
				return
			}
			if edges[0].Evidence.Detail != tt.wantDetail {
				t.Fatalf("edge detail = %q, want %q", edges[0].Evidence.Detail, tt.wantDetail)
			}
		})
	}
}

func TestAddRoutesWorkflowAndJobOIDCTokenCapabilitiesAreDistinct(t *testing.T) {
	root := t.TempDir()
	writeWorkflowForRoutingTest(t, root, "oidc.yml", `permissions:
  id-token: write
jobs:
  deploy:
    permissions:
      id-token: write
`)
	resources, err := parsergithubactions.ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	g := graph.New()

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	var capabilities []graph.Node
	for _, node := range g.Nodes() {
		if node.Kind == graph.OIDCTokenCapability {
			capabilities = append(capabilities, node)
		}
	}
	if len(capabilities) != 2 {
		t.Fatalf("OIDC capability node count = %d, want 2: %#v", len(capabilities), capabilities)
	}
	scopes := map[string]bool{}
	for _, node := range capabilities {
		if node.Metadata == nil || node.Metadata.GitHubActionsOIDCTokenCapability == nil {
			t.Fatalf("capability metadata missing: %#v", node)
		}
		metadata := node.Metadata.GitHubActionsOIDCTokenCapability
		scopes[metadata.Scope+":"+metadata.JobID] = true
	}
	if !scopes["workflow:"] || !scopes["job:deploy"] {
		t.Fatalf("capability scopes = %#v, want workflow and job deploy", scopes)
	}
}

func TestAddRoutesOIDCTokenCapabilityGraphJSONIsDeterministic(t *testing.T) {
	resources := parsergithubactions.Resources{Workflows: []parsergithubactions.Workflow{
		{
			Name:   "Z",
			Source: parsergithubactions.Source{Filename: "/repo/.github/workflows/z.yml", RelativePath: ".github/workflows/z.yml", Document: 1},
			PermissionGrants: []parsergithubactions.PermissionGrant{{
				Scope:      "workflow",
				Permission: "id-token",
				Access:     "write",
			}},
			Jobs: []parsergithubactions.Job{{ID: "z"}},
		},
		{
			Name:   "A",
			Source: parsergithubactions.Source{Filename: "/repo/.github/workflows/a.yml", RelativePath: ".github/workflows/a.yml", Document: 1},
			Jobs: []parsergithubactions.Job{
				{
					ID: "z",
					PermissionGrants: []parsergithubactions.PermissionGrant{{
						Scope:      "job",
						JobID:      "z",
						Permission: "id-token",
						Access:     "write",
					}},
				},
				{
					ID: "a",
					PermissionGrants: []parsergithubactions.PermissionGrant{{
						Scope:      "job",
						JobID:      "a",
						Permission: "all",
						Access:     "write-all",
					}},
				},
			},
		},
	}}
	reversed := parsergithubactions.Resources{Workflows: []parsergithubactions.Workflow{
		{
			Name:   "A",
			Source: parsergithubactions.Source{Filename: "/repo/.github/workflows/a.yml", RelativePath: ".github/workflows/a.yml", Document: 1},
			Jobs: []parsergithubactions.Job{
				{
					ID: "a",
					PermissionGrants: []parsergithubactions.PermissionGrant{{
						Scope:      "job",
						JobID:      "a",
						Permission: "all",
						Access:     "write-all",
					}},
				},
				{
					ID: "z",
					PermissionGrants: []parsergithubactions.PermissionGrant{{
						Scope:      "job",
						JobID:      "z",
						Permission: "id-token",
						Access:     "write",
					}},
				},
			},
		},
		{
			Name:   "Z",
			Source: parsergithubactions.Source{Filename: "/repo/.github/workflows/z.yml", RelativePath: ".github/workflows/z.yml", Document: 1},
			PermissionGrants: []parsergithubactions.PermissionGrant{{
				Scope:      "workflow",
				Permission: "id-token",
				Access:     "write",
			}},
			Jobs: []parsergithubactions.Job{{ID: "z"}},
		},
	}}

	first := graph.New()
	if err := AddRoutes(first, resources); err != nil {
		t.Fatalf("add first routes: %v", err)
	}
	second := graph.New()
	if err := AddRoutes(second, reversed); err != nil {
		t.Fatalf("add reversed routes: %v", err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first graph: %v", err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal second graph: %v", err)
	}
	thirdJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first graph again: %v", err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("graph JSON differs by input order:\nfirst:  %s\nsecond: %s", firstJSON, secondJSON)
	}
	if string(firstJSON) != string(thirdJSON) {
		t.Fatalf("graph JSON differs across repeated marshal:\nfirst: %s\nthird: %s", firstJSON, thirdJSON)
	}
}

func TestAddRoutesOIDCTokenCapabilityGraphJSONExcludesIgnoredWorkflowValues(t *testing.T) {
	root := t.TempDir()
	writeWorkflowForRoutingTest(t, root, "oidc.yml", `name: OIDC
permissions:
  id-token: write
  actions: ${{ inputs.permission }}
  contents: admin
env:
  TOKEN: FAKE_GHA_ENV_SECRET_DO_NOT_RETAIN
jobs:
  deploy:
    permissions:
      id-token: write
      checks: unknown
    steps:
      - run: echo FAKE_GHA_RUN_SECRET_DO_NOT_RETAIN
      - uses: owner/repo@0123456789abcdef0123456789abcdef01234567
        with:
          token: FAKE_GHA_WITH_SECRET_DO_NOT_RETAIN
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
		"inputs.permission",
		"${{",
		"admin",
		"unknown",
		"run:",
		"raw YAML",
	} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("graph JSON contains %q: %s", forbidden, data)
		}
	}
	if strings.Count(string(data), `"kind":"OIDCTokenCapability"`) != 2 {
		t.Fatalf("graph JSON = %s, want two OIDC capability nodes", data)
	}
}

func oidcTokenRequestEdges(g *graph.Graph) []graph.Edge {
	var edges []graph.Edge
	for _, edge := range g.Edges() {
		if edge.Kind == graph.CanRequestOIDCToken {
			edges = append(edges, edge)
		}
	}
	return edges
}
