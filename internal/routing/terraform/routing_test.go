package terraform

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"pathproof/internal/analysis"
	"pathproof/internal/graph"
	parsergithubactions "pathproof/internal/parser/githubactions"
	parserterraform "pathproof/internal/parser/terraform"
	routinggithubactions "pathproof/internal/routing/githubactions"
)

func TestAddRoutesCreatesAWSIAMRoleNodeWithTrustMetadata(t *testing.T) {
	resources := parserterraform.Resources{IAMRoles: []parserterraform.IAMRole{testRole("deploy", "repo:owner/repo:pull_request")}}
	g := graph.New()

	if err := AddRoutes(g, resources, parsergithubactions.Resources{}, ""); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	role := graph.NewNode(graph.AWSIAMRole, "aws://terraform/aws_iam_role/main.tf/deploy")
	got, ok := g.Node(role.ID)
	if !ok {
		t.Fatalf("missing role node %q", role.ID)
	}
	if got.Metadata == nil || got.Metadata.AWSIAMRole == nil {
		t.Fatalf("role metadata = %#v, want aws role metadata", got.Metadata)
	}
	want := graph.AWSIAMRoleMetadata{
		Provider:        "aws",
		ResourceName:    "deploy",
		SourceReference: "/repo/main.tf#resource=aws_iam_role.deploy",
		TrustedIssuer:   "token.actions.githubusercontent.com",
		TrustStatements: []graph.AWSOIDCTrustStatement{{
			StatementIndex: 0,
			SubjectPatterns: []graph.AWSOIDCSubjectPattern{{
				Operator: "StringEquals",
				Pattern:  "repo:owner/repo:pull_request",
			}},
			Audiences: []string{"sts.amazonaws.com"},
		}},
	}
	if !reflect.DeepEqual(*got.Metadata.AWSIAMRole, want) {
		t.Fatalf("metadata = %#v, want %#v", *got.Metadata.AWSIAMRole, want)
	}
	if countEdges(g, graph.CanAssumeRole) != 0 {
		t.Fatalf("CanAssumeRole edges = %d, want none without repo", countEdges(g, graph.CanAssumeRole))
	}
}

func TestAddRoutesCreatesCanAssumeRoleForMatchingPullRequestSubject(t *testing.T) {
	workflows := parsergithubactions.Resources{Workflows: []parsergithubactions.Workflow{{
		Name:                "Deploy",
		Source:              parsergithubactions.Source{Filename: "/repo/.github/workflows/deploy.yml", RelativePath: ".github/workflows/deploy.yml", Document: 1},
		TriggersPullRequest: true,
		PermissionGrants: []parsergithubactions.PermissionGrant{{
			Scope:      "workflow",
			Permission: "id-token",
			Access:     "write",
		}},
	}}}
	resources := parserterraform.Resources{IAMRoles: []parserterraform.IAMRole{testRole("deploy", "repo:owner/repo:pull_request")}}
	g := graph.New()
	if err := routinggithubactions.AddRoutes(g, workflows); err != nil {
		t.Fatalf("add github actions routes: %v", err)
	}

	if err := AddRoutes(g, resources, workflows, "owner/repo"); err != nil {
		t.Fatalf("add terraform routes: %v", err)
	}

	edges := edgesOfKind(g, graph.CanAssumeRole)
	if len(edges) != 1 {
		t.Fatalf("CanAssumeRole edges = %d, want 1: %#v", len(edges), edges)
	}
	metadata := edges[0].Metadata.AWSCanAssumeRole
	if metadata == nil {
		t.Fatalf("edge metadata missing: %#v", edges[0])
	}
	if metadata.SubjectCandidate != "repo:owner/repo:pull_request" || metadata.SubjectPattern != "repo:owner/repo:pull_request" || metadata.SubjectOperator != "StringEquals" {
		t.Fatalf("metadata = %#v, want matching pull_request subject", metadata)
	}
}

func TestAddRoutesCreatesAWSPermissionNodeAndGrantsPermissionEdge(t *testing.T) {
	resources := parserterraform.Resources{IAMRoles: []parserterraform.IAMRole{testRoleWithPermissions("deploy", []parserterraform.IAMPermission{{
		Kind:                     "inline_policy",
		Source:                   parserterraform.Source{Filename: "/repo/iam.tf", RelativePath: "iam.tf", ResourceType: "aws_iam_role_policy", ResourceName: "admin"},
		PolicyResourceName:       "admin",
		AttachedRoleResourceName: "deploy",
		Actions:                  []string{"*"},
		Resources:                []string{"*"},
		Administrative:           true,
		AdminReason:              "action_star_resource_star",
	}})}}
	g := graph.New()

	if err := AddRoutes(g, resources, parsergithubactions.Resources{}, ""); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	permissions := nodesOfKind(g, graph.AWSPermission)
	if len(permissions) != 1 {
		t.Fatalf("AWSPermission nodes = %d, want 1: %#v", len(permissions), g.Nodes())
	}
	metadata := permissions[0].Metadata.AWSPermission
	if metadata == nil {
		t.Fatalf("permission metadata missing: %#v", permissions[0])
	}
	if metadata.Provider != "aws" || metadata.PolicyResourceName != "admin" || metadata.AttachedRoleResourceName != "deploy" {
		t.Fatalf("permission metadata = %#v, want role admin metadata", metadata)
	}
	if !metadata.Administrative || metadata.AdminReason != "action_star_resource_star" {
		t.Fatalf("permission metadata = %#v, want admin reason", metadata)
	}
	edges := edgesOfKind(g, graph.GrantsPermission)
	if len(edges) != 1 {
		t.Fatalf("GrantsPermission edges = %d, want 1: %#v", len(edges), g.Edges())
	}
	role := graph.NewNode(graph.AWSIAMRole, "aws://terraform/aws_iam_role/main.tf/deploy")
	if edges[0].From != role.ID || edges[0].To != permissions[0].ID {
		t.Fatalf("edge connects %s -> %s, want role -> permission", edges[0].From, edges[0].To)
	}
	if !strings.Contains(edges[0].Evidence.Detail, "action_star_resource_star") || strings.Contains(edges[0].Evidence.Detail, "Statement") {
		t.Fatalf("edge evidence detail = %q, want sanitized admin reason", edges[0].Evidence.Detail)
	}
}

func TestAddRoutesAdministratorAccessPermissionMetadataIsSanitized(t *testing.T) {
	resources := parserterraform.Resources{IAMRoles: []parserterraform.IAMRole{testRoleWithPermissions("deploy", []parserterraform.IAMPermission{{
		Kind:                     "managed_policy",
		Source:                   parserterraform.Source{Filename: "/repo/iam.tf", RelativePath: "iam.tf", ResourceType: "aws_iam_role_policy_attachment", ResourceName: "admin"},
		AttachmentResourceName:   "admin",
		AttachedRoleResourceName: "deploy",
		ManagedPolicyARN:         "arn:aws:iam::aws:policy/AdministratorAccess",
		Administrative:           true,
		AdminReason:              "administrator_access_managed_policy",
	}})}}
	g := graph.New()

	if err := AddRoutes(g, resources, parsergithubactions.Resources{}, ""); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	data, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal graph: %v", err)
	}
	output := string(data)
	for _, want := range []string{"AWSPermission", "administrator_access_managed_policy", "arn:aws:iam::aws:policy/AdministratorAccess"} {
		if !strings.Contains(output, want) {
			t.Fatalf("graph JSON missing %q: %s", want, output)
		}
	}
	for _, forbidden := range []string{"Statement", "Action", "Resource", "FAKE_TF_SECRET_DO_NOT_RETAIN", "assume_role_policy"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("graph JSON contains %q: %s", forbidden, output)
		}
	}
}

func TestAddRoutesAWSIAMPermissionGraphJSONIsDeterministic(t *testing.T) {
	firstResources := parserterraform.Resources{IAMRoles: []parserterraform.IAMRole{
		testRoleWithPermissions("deploy", []parserterraform.IAMPermission{
			{
				Kind:                     "inline_policy",
				Source:                   parserterraform.Source{Filename: "/repo/b.tf", RelativePath: "b.tf", ResourceType: "aws_iam_role_policy", ResourceName: "admin_b"},
				PolicyResourceName:       "admin_b",
				AttachedRoleResourceName: "deploy",
				Actions:                  []string{"*:*"},
				Resources:                []string{"*"},
				Administrative:           true,
				AdminReason:              "action_service_star_resource_star",
			},
			{
				Kind:                     "inline_policy",
				Source:                   parserterraform.Source{Filename: "/repo/a.tf", RelativePath: "a.tf", ResourceType: "aws_iam_role_policy", ResourceName: "admin_a"},
				PolicyResourceName:       "admin_a",
				AttachedRoleResourceName: "deploy",
				Actions:                  []string{"*"},
				Resources:                []string{"*"},
				Administrative:           true,
				AdminReason:              "action_star_resource_star",
			},
		}),
	}}
	secondResources := parserterraform.Resources{IAMRoles: []parserterraform.IAMRole{
		testRoleWithPermissions("deploy", []parserterraform.IAMPermission{
			firstResources.IAMRoles[0].Permissions[1],
			firstResources.IAMRoles[0].Permissions[0],
		}),
	}}
	first := graph.New()
	second := graph.New()

	if err := AddRoutes(first, firstResources, parsergithubactions.Resources{}, ""); err != nil {
		t.Fatalf("add first routes: %v", err)
	}
	if err := AddRoutes(second, secondResources, parsergithubactions.Resources{}, ""); err != nil {
		t.Fatalf("add second routes: %v", err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first: %v", err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal second: %v", err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("graph JSON differs:\nfirst: %s\nsecond:%s", firstJSON, secondJSON)
	}
}

func TestAddRoutesAWSIAMPermissionIDsDoNotDependOnAbsoluteSourceFilename(t *testing.T) {
	firstResources := parserterraform.Resources{IAMRoles: []parserterraform.IAMRole{testRoleWithPermissions("deploy", []parserterraform.IAMPermission{{
		Kind:                     "inline_policy",
		Source:                   parserterraform.Source{Filename: "/tmp/checkout-a/infra/iam.tf", RelativePath: "infra/iam.tf", ResourceType: "aws_iam_role_policy", ResourceName: "admin"},
		PolicyResourceName:       "admin",
		AttachedRoleResourceName: "deploy",
		Actions:                  []string{"*"},
		Resources:                []string{"*"},
		Administrative:           true,
		AdminReason:              "action_star_resource_star",
	}})}}
	secondResources := parserterraform.Resources{IAMRoles: []parserterraform.IAMRole{testRoleWithPermissions("deploy", []parserterraform.IAMPermission{{
		Kind:                     "inline_policy",
		Source:                   parserterraform.Source{Filename: "/private/var/checkout-b/infra/iam.tf", RelativePath: "infra/iam.tf", ResourceType: "aws_iam_role_policy", ResourceName: "admin"},
		PolicyResourceName:       "admin",
		AttachedRoleResourceName: "deploy",
		Actions:                  []string{"*"},
		Resources:                []string{"*"},
		Administrative:           true,
		AdminReason:              "action_star_resource_star",
	}})}}
	first := graph.New()
	second := graph.New()

	if err := AddRoutes(first, firstResources, parsergithubactions.Resources{}, ""); err != nil {
		t.Fatalf("add first routes: %v", err)
	}
	if err := AddRoutes(second, secondResources, parsergithubactions.Resources{}, ""); err != nil {
		t.Fatalf("add second routes: %v", err)
	}

	firstPermission := onlyNodeOfKind(t, first, graph.AWSPermission)
	secondPermission := onlyNodeOfKind(t, second, graph.AWSPermission)
	if firstPermission.ID != secondPermission.ID {
		t.Fatalf("AWSPermission IDs differ by absolute source path:\nfirst: %s\nsecond:%s", firstPermission.ID, secondPermission.ID)
	}
	firstEdge := onlyEdgeOfKind(t, first, graph.GrantsPermission)
	secondEdge := onlyEdgeOfKind(t, second, graph.GrantsPermission)
	if firstEdge.ID != secondEdge.ID {
		t.Fatalf("GrantsPermission edge IDs differ by absolute source path:\nfirst: %s\nsecond:%s", firstEdge.ID, secondEdge.ID)
	}
	firstFinding := onlyFindingByRule(t, analysis.Analyze(first), analysis.RuleAWSIAMRoleAdministrativePermissions)
	secondFinding := onlyFindingByRule(t, analysis.Analyze(second), analysis.RuleAWSIAMRoleAdministrativePermissions)
	if firstFinding.ID != secondFinding.ID {
		t.Fatalf("PP-AWS-001 finding IDs differ by absolute source path:\nfirst: %s\nsecond:%s", firstFinding.ID, secondFinding.ID)
	}
}

func TestAddRoutesMatchesStaticPushBranchAndEnvironmentSubjects(t *testing.T) {
	workflows := parsergithubactions.Resources{Workflows: []parsergithubactions.Workflow{{
		Name:         "Deploy",
		Source:       parsergithubactions.Source{Filename: "/repo/.github/workflows/deploy.yml", RelativePath: ".github/workflows/deploy.yml", Document: 1},
		PushBranches: []string{"main"},
		Jobs: []parsergithubactions.Job{{
			ID:          "deploy",
			Environment: "prod",
			PermissionGrants: []parsergithubactions.PermissionGrant{{
				Scope:      "job",
				JobID:      "deploy",
				Permission: "id-token",
				Access:     "write",
			}},
		}},
	}}}
	resources := parserterraform.Resources{IAMRoles: []parserterraform.IAMRole{
		testRole("branch", "repo:owner/repo:ref:refs/heads/main"),
		testRole("environment", "repo:owner/repo:environment:prod"),
	}}
	g := graph.New()
	if err := routinggithubactions.AddRoutes(g, workflows); err != nil {
		t.Fatalf("add github actions routes: %v", err)
	}

	if err := AddRoutes(g, resources, workflows, "owner/repo"); err != nil {
		t.Fatalf("add terraform routes: %v", err)
	}

	edges := edgesOfKind(g, graph.CanAssumeRole)
	if len(edges) != 2 {
		t.Fatalf("CanAssumeRole edges = %d, want 2: %#v", len(edges), edges)
	}
	subjects := map[string]bool{}
	for _, edge := range edges {
		subjects[edge.Metadata.AWSCanAssumeRole.SubjectCandidate] = true
	}
	if !subjects["repo:owner/repo:ref:refs/heads/main"] || !subjects["repo:owner/repo:environment:prod"] {
		t.Fatalf("matched subjects = %#v", subjects)
	}
}

func TestAddRoutesMatchesStringLikeSimpleWildcardSubject(t *testing.T) {
	workflows := parsergithubactions.Resources{Workflows: []parsergithubactions.Workflow{{
		Source:       parsergithubactions.Source{Filename: "/repo/.github/workflows/deploy.yml", RelativePath: ".github/workflows/deploy.yml", Document: 1},
		PushBranches: []string{"release/prod"},
		PermissionGrants: []parsergithubactions.PermissionGrant{{
			Scope:      "workflow",
			Permission: "id-token",
			Access:     "write",
		}},
	}}}
	role := testRole("deploy", "repo:owner/repo:ref:refs/heads/release/*")
	role.Trusts[0].SubjectPatterns[0].Operator = "StringLike"
	g := graph.New()
	if err := routinggithubactions.AddRoutes(g, workflows); err != nil {
		t.Fatalf("add github actions routes: %v", err)
	}

	if err := AddRoutes(g, parserterraform.Resources{IAMRoles: []parserterraform.IAMRole{role}}, workflows, "owner/repo"); err != nil {
		t.Fatalf("add terraform routes: %v", err)
	}

	edges := edgesOfKind(g, graph.CanAssumeRole)
	if len(edges) != 1 || edges[0].Metadata.AWSCanAssumeRole.SubjectOperator != "StringLike" {
		t.Fatalf("edges = %#v, want one StringLike edge", edges)
	}
}

func TestAddRoutesDoesNotCreateCanAssumeRoleWithoutStaticInputsOrMatch(t *testing.T) {
	workflows := parsergithubactions.Resources{Workflows: []parsergithubactions.Workflow{{
		Source: parsergithubactions.Source{Filename: "/repo/.github/workflows/deploy.yml", RelativePath: ".github/workflows/deploy.yml", Document: 1},
		PermissionGrants: []parsergithubactions.PermissionGrant{{
			Scope:      "workflow",
			Permission: "id-token",
			Access:     "write",
		}},
	}}}
	resources := parserterraform.Resources{IAMRoles: []parserterraform.IAMRole{testRole("deploy", "repo:owner/repo:pull_request")}}

	for _, tt := range []struct {
		name string
		repo string
		wf   parsergithubactions.Resources
	}{
		{name: "no repo", repo: "", wf: workflows},
		{name: "no static candidate", repo: "owner/repo", wf: workflows},
		{name: "repo mismatch", repo: "other/repo", wf: parsergithubactions.Resources{Workflows: []parsergithubactions.Workflow{{
			Source:              workflows.Workflows[0].Source,
			TriggersPullRequest: true,
			PermissionGrants:    workflows.Workflows[0].PermissionGrants,
		}}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := graph.New()
			if err := routinggithubactions.AddRoutes(g, tt.wf); err != nil {
				t.Fatalf("add github actions routes: %v", err)
			}
			if err := AddRoutes(g, resources, tt.wf, tt.repo); err != nil {
				t.Fatalf("add terraform routes: %v", err)
			}
			if countEdges(g, graph.CanAssumeRole) != 0 {
				t.Fatalf("CanAssumeRole edges = %d, want none", countEdges(g, graph.CanAssumeRole))
			}
		})
	}
}

func TestAddRoutesRejectedOIDCIssuerHasNoTrustMetadataOrEdge(t *testing.T) {
	root := t.TempDir()
	writeTerraformForRoutingTest(t, root, "role.tf", `resource "aws_iam_role" "deploy" {
  assume_role_policy = <<EOF
{"Statement":{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/evil-token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com","token.actions.githubusercontent.com:sub":"repo:owner/repo:pull_request"}}}}
EOF
}
`)
	resources, err := parserterraform.ParseDir(root)
	if err != nil {
		t.Fatalf("parse terraform dir: %v", err)
	}
	workflows := parsergithubactions.Resources{Workflows: []parsergithubactions.Workflow{{
		Source:              parsergithubactions.Source{Filename: "/repo/.github/workflows/deploy.yml", RelativePath: ".github/workflows/deploy.yml", Document: 1},
		TriggersPullRequest: true,
		PermissionGrants: []parsergithubactions.PermissionGrant{{
			Scope:      "workflow",
			Permission: "id-token",
			Access:     "write",
		}},
	}}}
	g := graph.New()
	if err := routinggithubactions.AddRoutes(g, workflows); err != nil {
		t.Fatalf("add github actions routes: %v", err)
	}

	if err := AddRoutes(g, resources, workflows, "owner/repo"); err != nil {
		t.Fatalf("add terraform routes: %v", err)
	}

	if countEdges(g, graph.CanAssumeRole) != 0 {
		t.Fatalf("CanAssumeRole edges = %d, want none", countEdges(g, graph.CanAssumeRole))
	}
	role := graph.NewNode(graph.AWSIAMRole, "aws://terraform/aws_iam_role/role.tf/deploy")
	got, ok := g.Node(role.ID)
	if !ok {
		t.Fatalf("missing AWSIAMRole node %q", role.ID)
	}
	if got.Metadata == nil || got.Metadata.AWSIAMRole == nil {
		t.Fatalf("AWSIAMRole metadata missing: %#v", got.Metadata)
	}
	if got.Metadata.AWSIAMRole.TrustedIssuer != "" || len(got.Metadata.AWSIAMRole.TrustStatements) != 0 {
		t.Fatalf("trust metadata = %#v, want no trusted issuer or statements", got.Metadata.AWSIAMRole)
	}
}

func TestAddRoutesTrailingContentPolicyCannotCreateTrustMetadataOrEdge(t *testing.T) {
	root := t.TempDir()
	writeTerraformForRoutingTest(t, root, "role.tf", `resource "aws_iam_role" "deploy" {
  assume_role_policy = <<EOF
{"Statement":{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com","token.actions.githubusercontent.com:sub":"repo:owner/repo:pull_request"}}}} FAKE_TF_TRAILING_SECRET_DO_NOT_RETAIN
EOF
}
`)

	resources, err := parserterraform.ParseDir(root)
	if err == nil {
		t.Fatalf("parse terraform error = nil, resources = %#v", resources)
	}
	message := err.Error()
	if strings.Contains(message, "FAKE_TF_TRAILING_SECRET_DO_NOT_RETAIN") || strings.Contains(message, "Statement") {
		t.Fatalf("parse error leaked policy content: %s", message)
	}
}

func TestAddRoutesGraphJSONIsDeterministicAndExcludesUnsupportedValues(t *testing.T) {
	workflows := parsergithubactions.Resources{Workflows: []parsergithubactions.Workflow{{
		Source:              parsergithubactions.Source{Filename: "/repo/.github/workflows/deploy.yml", RelativePath: ".github/workflows/deploy.yml", Document: 1},
		TriggersPullRequest: true,
		PermissionGrants: []parsergithubactions.PermissionGrant{{
			Scope:      "workflow",
			Permission: "id-token",
			Access:     "write",
		}},
	}}}
	resources := parserterraform.Resources{IAMRoles: []parserterraform.IAMRole{testRole("deploy", "repo:owner/repo:pull_request")}}

	first := graph.New()
	if err := routinggithubactions.AddRoutes(first, workflows); err != nil {
		t.Fatalf("add first github actions routes: %v", err)
	}
	if err := AddRoutes(first, resources, workflows, "owner/repo"); err != nil {
		t.Fatalf("add first terraform routes: %v", err)
	}
	second := graph.New()
	if err := routinggithubactions.AddRoutes(second, workflows); err != nil {
		t.Fatalf("add second github actions routes: %v", err)
	}
	if err := AddRoutes(second, resources, workflows, "owner/repo"); err != nil {
		t.Fatalf("add second terraform routes: %v", err)
	}

	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first graph: %v", err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal second graph: %v", err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("graph JSON differs:\nfirst: %s\nsecond:%s", firstJSON, secondJSON)
	}
	for _, forbidden := range []string{
		"FAKE_TF_SECRET_DO_NOT_RETAIN",
		"assume_role_policy",
		"arn:aws:iam",
		"Principal",
		"Condition",
	} {
		if strings.Contains(string(firstJSON), forbidden) {
			t.Fatalf("graph JSON contains %q: %s", forbidden, firstJSON)
		}
	}
}

func testRole(name, subject string) parserterraform.IAMRole {
	return parserterraform.IAMRole{
		ResourceType: "aws_iam_role",
		ResourceName: name,
		Source: parserterraform.Source{
			Filename:     "/repo/main.tf",
			RelativePath: "main.tf",
			ResourceType: "aws_iam_role",
			ResourceName: name,
		},
		Trusts: []parserterraform.OIDCTrust{{
			StatementIndex: 0,
			Issuer:         "token.actions.githubusercontent.com",
			SubjectPatterns: []parserterraform.SubjectPattern{{
				Operator: "StringEquals",
				Pattern:  subject,
			}},
			Audiences: []string{"sts.amazonaws.com"},
		}},
	}
}

func testRoleWithPermissions(name string, permissions []parserterraform.IAMPermission) parserterraform.IAMRole {
	role := testRole(name, "repo:owner/repo:pull_request")
	role.Permissions = permissions
	return role
}

func nodesOfKind(g *graph.Graph, kind graph.NodeKind) []graph.Node {
	var nodes []graph.Node
	for _, node := range g.Nodes() {
		if node.Kind == kind {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func onlyNodeOfKind(t *testing.T, g *graph.Graph, kind graph.NodeKind) graph.Node {
	t.Helper()
	nodes := nodesOfKind(g, kind)
	if len(nodes) != 1 {
		t.Fatalf("%s node count = %d, want 1: %#v", kind, len(nodes), nodes)
	}
	return nodes[0]
}

func edgesOfKind(g *graph.Graph, kind graph.EdgeKind) []graph.Edge {
	var edges []graph.Edge
	for _, edge := range g.Edges() {
		if edge.Kind == kind {
			edges = append(edges, edge)
		}
	}
	return edges
}

func onlyEdgeOfKind(t *testing.T, g *graph.Graph, kind graph.EdgeKind) graph.Edge {
	t.Helper()
	edges := edgesOfKind(g, kind)
	if len(edges) != 1 {
		t.Fatalf("%s edge count = %d, want 1: %#v", kind, len(edges), edges)
	}
	return edges[0]
}

func countEdges(g *graph.Graph, kind graph.EdgeKind) int {
	return len(edgesOfKind(g, kind))
}

func onlyFindingByRule(t *testing.T, findings []analysis.Finding, ruleID analysis.RuleID) analysis.Finding {
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

func writeTerraformForRoutingTest(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir terraform dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write terraform: %v", err)
	}
}
