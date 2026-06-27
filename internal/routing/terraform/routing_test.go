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

func TestAddRoutesCreatesAWSS3BucketNodeWithSanitizedMetadata(t *testing.T) {
	resources := parserterraform.Resources{S3Buckets: []parserterraform.S3Bucket{testS3Bucket("artifacts", "prod-artifacts")}}
	g := graph.New()

	if err := AddRoutes(g, resources, parsergithubactions.Resources{}, ""); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	bucket := graph.NewNode(graph.AWSS3Bucket, "aws://terraform/aws_s3_bucket/s3.tf/artifacts")
	got, ok := g.Node(bucket.ID)
	if !ok {
		t.Fatalf("missing bucket node %q", bucket.ID)
	}
	if got.Metadata == nil || got.Metadata.AWSS3Bucket == nil {
		t.Fatalf("bucket metadata = %#v, want aws s3 bucket metadata", got.Metadata)
	}
	want := graph.AWSS3BucketMetadata{
		Provider:        "aws",
		BucketName:      "prod-artifacts",
		ResourceName:    "artifacts",
		SourceReference: "/repo/s3.tf#resource=aws_s3_bucket.artifacts",
	}
	if !reflect.DeepEqual(*got.Metadata.AWSS3Bucket, want) {
		t.Fatalf("metadata = %#v, want %#v", *got.Metadata.AWSS3Bucket, want)
	}
}

func TestAddRoutesCreatesS3ReadEdgesForExactReadActions(t *testing.T) {
	resources := parserterraform.Resources{
		S3Buckets: []parserterraform.S3Bucket{testS3Bucket("artifacts", "prod-artifacts")},
		IAMRoles: []parserterraform.IAMRole{testRoleWithPermissions("deploy", []parserterraform.IAMPermission{
			testS3Permission("deploy", "read_list", 0, "s3:ListBucket", "arn:aws:s3:::prod-artifacts"),
			testS3Permission("deploy", "read_get", 1, "s3:GetObject", "arn:aws:s3:::prod-artifacts/*"),
		})},
	}
	g := graph.New()

	if err := AddRoutes(g, resources, parsergithubactions.Resources{}, ""); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	edges := edgesOfKind(g, graph.CanReadObject)
	if len(edges) != 1 {
		t.Fatalf("CanReadObject edges = %d, want 1: %#v", len(edges), edges)
	}
	metadata := edges[0].Metadata.AWSS3Access
	if metadata == nil || metadata.AccessMode != "read" || metadata.BucketName != "prod-artifacts" {
		t.Fatalf("metadata = %#v, want read access to prod-artifacts", metadata)
	}
	gotKinds := s3GrantKinds(metadata.Grants)
	wantKinds := []string{"get_object", "list_bucket"}
	if !reflect.DeepEqual(gotKinds, wantKinds) {
		t.Fatalf("grant kinds = %#v, want %#v", gotKinds, wantKinds)
	}
	if countEdges(g, graph.CanWriteObject) != 0 {
		t.Fatalf("CanWriteObject edges = %d, want none", countEdges(g, graph.CanWriteObject))
	}
}

func TestAddRoutesCreatesS3WriteEdgesForExactWriteActions(t *testing.T) {
	resources := parserterraform.Resources{
		S3Buckets: []parserterraform.S3Bucket{testS3Bucket("artifacts", "prod-artifacts")},
		IAMRoles: []parserterraform.IAMRole{testRoleWithPermissions("deploy", []parserterraform.IAMPermission{
			testS3Permission("deploy", "write_put", 0, "s3:PutObject", "arn:aws:s3:::prod-artifacts/*"),
			testS3Permission("deploy", "write_delete", 1, "s3:DeleteObject", "arn:aws:s3:::prod-artifacts/*"),
		})},
	}
	g := graph.New()

	if err := AddRoutes(g, resources, parsergithubactions.Resources{}, ""); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	edges := edgesOfKind(g, graph.CanWriteObject)
	if len(edges) != 1 {
		t.Fatalf("CanWriteObject edges = %d, want 1: %#v", len(edges), edges)
	}
	metadata := edges[0].Metadata.AWSS3Access
	gotKinds := s3GrantKinds(metadata.Grants)
	wantKinds := []string{"delete_object", "put_object"}
	if !reflect.DeepEqual(gotKinds, wantKinds) {
		t.Fatalf("grant kinds = %#v, want %#v", gotKinds, wantKinds)
	}
}

func TestAddRoutesS3StarExactARNAccessSemantics(t *testing.T) {
	tests := []struct {
		name      string
		resource  string
		wantRead  int
		wantWrite int
		wantKinds []string
	}{
		{name: "bucket arn creates read only", resource: "arn:aws:s3:::prod-artifacts", wantRead: 1, wantKinds: []string{"s3_star_bucket"}},
		{name: "object arn creates read and write", resource: "arn:aws:s3:::prod-artifacts/*", wantRead: 1, wantWrite: 1, wantKinds: []string{"s3_star_object"}},
		{name: "resource star creates no s3 access", resource: "*"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resources := parserterraform.Resources{
				S3Buckets: []parserterraform.S3Bucket{testS3Bucket("artifacts", "prod-artifacts")},
				IAMRoles: []parserterraform.IAMRole{testRoleWithPermissions("deploy", []parserterraform.IAMPermission{
					testS3Permission("deploy", "s3_star", 0, "s3:*", tt.resource),
				})},
			}
			g := graph.New()

			if err := AddRoutes(g, resources, parsergithubactions.Resources{}, ""); err != nil {
				t.Fatalf("add routes: %v", err)
			}
			if got := countEdges(g, graph.CanReadObject); got != tt.wantRead {
				t.Fatalf("CanReadObject edges = %d, want %d", got, tt.wantRead)
			}
			if got := countEdges(g, graph.CanWriteObject); got != tt.wantWrite {
				t.Fatalf("CanWriteObject edges = %d, want %d", got, tt.wantWrite)
			}
			if tt.wantRead > 0 {
				read := onlyEdgeOfKind(t, g, graph.CanReadObject)
				if got := s3GrantKinds(read.Metadata.AWSS3Access.Grants); !reflect.DeepEqual(got, tt.wantKinds) {
					t.Fatalf("read grant kinds = %#v, want %#v", got, tt.wantKinds)
				}
			}
			if tt.wantWrite > 0 {
				write := onlyEdgeOfKind(t, g, graph.CanWriteObject)
				if got := s3GrantKinds(write.Metadata.AWSS3Access.Grants); !reflect.DeepEqual(got, tt.wantKinds) {
					t.Fatalf("write grant kinds = %#v, want %#v", got, tt.wantKinds)
				}
			}
		})
	}
}

func TestAddRoutesDoesNotCreateS3AccessEdgesForUnsupportedOrAdminInputs(t *testing.T) {
	tests := []struct {
		name       string
		permission parserterraform.IAMPermission
	}{
		{
			name:       "action star resource star",
			permission: testAdminPermission("deploy", "admin", "*", "*"),
		},
		{
			name:       "s3 star resource star",
			permission: testS3Permission("deploy", "s3_star", 0, "s3:*", "*"),
		},
		{
			name:       "wildcard bucket",
			permission: testS3Permission("deploy", "wildcard", 0, "s3:GetObject", "arn:aws:s3:::*"),
		},
		{
			name:       "wildcard prefix",
			permission: testS3Permission("deploy", "prefix", 0, "s3:GetObject", "arn:aws:s3:::prod-artifacts/prefix/*"),
		},
		{
			name:       "nonmatching bucket",
			permission: testS3Permission("deploy", "other", 0, "s3:GetObject", "arn:aws:s3:::other-artifacts/*"),
		},
		{
			name:       "s3 star object unsupported action was not retained",
			permission: testS3Permission("deploy", "object_star", 0, "s3:*Object", "arn:aws:s3:::prod-artifacts/*"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resources := parserterraform.Resources{
				S3Buckets: []parserterraform.S3Bucket{testS3Bucket("artifacts", "prod-artifacts")},
				IAMRoles:  []parserterraform.IAMRole{testRoleWithPermissions("deploy", []parserterraform.IAMPermission{tt.permission})},
			}
			g := graph.New()

			if err := AddRoutes(g, resources, parsergithubactions.Resources{}, ""); err != nil {
				t.Fatalf("add routes: %v", err)
			}
			if got := countEdges(g, graph.CanReadObject) + countEdges(g, graph.CanWriteObject); got != 0 {
				t.Fatalf("s3 access edges = %d, want none: %#v", got, g.Edges())
			}
		})
	}
}

func TestAddRoutesS3AccessGrantsDedupedAggregatedAndDeterministic(t *testing.T) {
	firstResources := parserterraform.Resources{
		S3Buckets: []parserterraform.S3Bucket{testS3Bucket("artifacts", "prod-artifacts")},
		IAMRoles: []parserterraform.IAMRole{testRoleWithPermissions("deploy", []parserterraform.IAMPermission{
			testS3Permission("deploy", "read_b", 1, "s3:GetObject", "arn:aws:s3:::prod-artifacts/*"),
			testS3Permission("deploy", "read_a", 0, "s3:ListBucket", "arn:aws:s3:::prod-artifacts"),
			testS3Permission("deploy", "read_a", 0, "s3:ListBucket", "arn:aws:s3:::prod-artifacts"),
		})},
	}
	secondResources := parserterraform.Resources{
		S3Buckets: []parserterraform.S3Bucket{firstResources.S3Buckets[0]},
		IAMRoles: []parserterraform.IAMRole{testRoleWithPermissions("deploy", []parserterraform.IAMPermission{
			firstResources.IAMRoles[0].Permissions[2],
			firstResources.IAMRoles[0].Permissions[1],
			firstResources.IAMRoles[0].Permissions[0],
		})},
	}
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
	read := onlyEdgeOfKind(t, first, graph.CanReadObject)
	if got := len(read.Metadata.AWSS3Access.Grants); got != 2 {
		t.Fatalf("deduped grants = %d, want 2: %#v", got, read.Metadata.AWSS3Access.Grants)
	}
}

func TestAddRoutesS3AccessMetadataIsCloned(t *testing.T) {
	resources := parserterraform.Resources{
		S3Buckets: []parserterraform.S3Bucket{testS3Bucket("artifacts", "prod-artifacts")},
		IAMRoles: []parserterraform.IAMRole{testRoleWithPermissions("deploy", []parserterraform.IAMPermission{
			testS3Permission("deploy", "read", 0, "s3:GetObject", "arn:aws:s3:::prod-artifacts/*"),
		})},
	}
	g := graph.New()
	if err := AddRoutes(g, resources, parsergithubactions.Resources{}, ""); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	edge := onlyEdgeOfKind(t, g, graph.CanReadObject)
	edge.Metadata.AWSS3Access.Grants[0].Action = "changed"
	stored := onlyEdgeOfKind(t, g, graph.CanReadObject)
	if stored.Metadata.AWSS3Access.Grants[0].Action != "s3:GetObject" {
		t.Fatalf("stored grant action = %q, want original", stored.Metadata.AWSS3Access.Grants[0].Action)
	}
	bucket := onlyNodeOfKind(t, g, graph.AWSS3Bucket)
	bucket.Metadata.AWSS3Bucket.BucketName = "changed"
	storedBucket := onlyNodeOfKind(t, g, graph.AWSS3Bucket)
	if storedBucket.Metadata.AWSS3Bucket.BucketName != "prod-artifacts" {
		t.Fatalf("stored bucket name = %q, want original", storedBucket.Metadata.AWSS3Bucket.BucketName)
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

func TestAddRoutesAggregatesCanAssumeRoleMatchesForSameCapabilityAndRole(t *testing.T) {
	workflows := parsergithubactions.Resources{Workflows: []parsergithubactions.Workflow{{
		Name:                      "Deploy",
		Source:                    parsergithubactions.Source{Filename: "/repo/.github/workflows/deploy.yml", RelativePath: ".github/workflows/deploy.yml", Document: 1},
		TriggersPullRequestTarget: true,
		PermissionGrants: []parsergithubactions.PermissionGrant{{
			Scope:      "workflow",
			Permission: "id-token",
			Access:     "write",
		}},
		Jobs: []parsergithubactions.Job{{
			ID:          "deploy",
			Environment: "prod",
		}},
	}}}
	role := testRoleWithSubjects("deploy", []string{
		"repo:owner/repo:environment:prod",
		"repo:owner/repo:pull_request",
	})
	g := graph.New()
	if err := routinggithubactions.AddRoutes(g, workflows); err != nil {
		t.Fatalf("add github actions routes: %v", err)
	}

	if err := AddRoutes(g, parserterraform.Resources{IAMRoles: []parserterraform.IAMRole{role}}, workflows, "owner/repo"); err != nil {
		t.Fatalf("add terraform routes: %v", err)
	}

	edge := onlyEdgeOfKind(t, g, graph.CanAssumeRole)
	matches := edge.Metadata.AWSCanAssumeRole.Matches
	if got := len(matches); got != 2 {
		t.Fatalf("CanAssumeRole matches = %d, want 2: %#v", got, matches)
	}
	gotSubjects := canAssumeMatchSubjects(matches)
	wantSubjects := []string{"repo:owner/repo:environment:prod", "repo:owner/repo:pull_request"}
	if !reflect.DeepEqual(gotSubjects, wantSubjects) {
		t.Fatalf("matched subjects = %#v, want %#v", gotSubjects, wantSubjects)
	}
}

func TestAddRoutesCanAssumeRoleMatchAggregationIsDeterministicAndDeduped(t *testing.T) {
	workflows := parsergithubactions.Resources{Workflows: []parsergithubactions.Workflow{{
		Source:                    parsergithubactions.Source{Filename: "/repo/.github/workflows/deploy.yml", RelativePath: ".github/workflows/deploy.yml", Document: 1},
		TriggersPullRequestTarget: true,
		PermissionGrants: []parsergithubactions.PermissionGrant{{
			Scope:      "workflow",
			Permission: "id-token",
			Access:     "write",
		}},
		Jobs: []parsergithubactions.Job{{
			ID:          "deploy",
			Environment: "prod",
		}},
	}}}
	firstRole := testRoleWithSubjects("deploy", []string{
		"repo:owner/repo:environment:prod",
		"repo:owner/repo:pull_request",
		"repo:owner/repo:pull_request",
	})
	secondRole := testRoleWithSubjects("deploy", []string{
		"repo:owner/repo:pull_request",
		"repo:owner/repo:environment:prod",
		"repo:owner/repo:pull_request",
	})
	first := graph.New()
	second := graph.New()
	if err := routinggithubactions.AddRoutes(first, workflows); err != nil {
		t.Fatalf("add first github actions routes: %v", err)
	}
	if err := AddRoutes(first, parserterraform.Resources{IAMRoles: []parserterraform.IAMRole{firstRole}}, workflows, "owner/repo"); err != nil {
		t.Fatalf("add first terraform routes: %v", err)
	}
	if err := routinggithubactions.AddRoutes(second, workflows); err != nil {
		t.Fatalf("add second github actions routes: %v", err)
	}
	if err := AddRoutes(second, parserterraform.Resources{IAMRoles: []parserterraform.IAMRole{secondRole}}, workflows, "owner/repo"); err != nil {
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
	matches := onlyEdgeOfKind(t, first, graph.CanAssumeRole).Metadata.AWSCanAssumeRole.Matches
	if got := len(matches); got != 2 {
		t.Fatalf("deduped matches = %d, want 2: %#v", got, matches)
	}
}

func TestAddRoutesCanAssumeRolePreservesNonPullRequestMatches(t *testing.T) {
	workflows := parsergithubactions.Resources{Workflows: []parsergithubactions.Workflow{{
		Source:       parsergithubactions.Source{Filename: "/repo/.github/workflows/deploy.yml", RelativePath: ".github/workflows/deploy.yml", Document: 1},
		PushBranches: []string{"main"},
		PermissionGrants: []parsergithubactions.PermissionGrant{{
			Scope:      "workflow",
			Permission: "id-token",
			Access:     "write",
		}},
		Jobs: []parsergithubactions.Job{{
			ID:          "deploy",
			Environment: "prod",
		}},
	}}}
	role := testRoleWithSubjects("deploy", []string{
		"repo:owner/repo:environment:prod",
		"repo:owner/repo:ref:refs/heads/main",
	})
	g := graph.New()
	if err := routinggithubactions.AddRoutes(g, workflows); err != nil {
		t.Fatalf("add github actions routes: %v", err)
	}

	if err := AddRoutes(g, parserterraform.Resources{IAMRoles: []parserterraform.IAMRole{role}}, workflows, "owner/repo"); err != nil {
		t.Fatalf("add terraform routes: %v", err)
	}

	edge := onlyEdgeOfKind(t, g, graph.CanAssumeRole)
	gotSubjects := canAssumeMatchSubjects(edge.Metadata.AWSCanAssumeRole.Matches)
	wantSubjects := []string{"repo:owner/repo:environment:prod", "repo:owner/repo:ref:refs/heads/main"}
	if !reflect.DeepEqual(gotSubjects, wantSubjects) {
		t.Fatalf("matched subjects = %#v, want %#v", gotSubjects, wantSubjects)
	}
}

func TestAddRoutesPreservesEnvironmentSubjectNamedPullRequest(t *testing.T) {
	workflows := parsergithubactions.Resources{Workflows: []parsergithubactions.Workflow{{
		Source:                    parsergithubactions.Source{Filename: "/repo/.github/workflows/deploy.yml", RelativePath: ".github/workflows/deploy.yml", Document: 1},
		TriggersPullRequestTarget: true,
		PermissionGrants: []parsergithubactions.PermissionGrant{{
			Scope:      "workflow",
			Permission: "id-token",
			Access:     "write",
		}},
		Jobs: []parsergithubactions.Job{{
			ID:          "deploy",
			Environment: "pull_request",
		}},
	}}}
	role := testRoleWithSubjects("deploy", []string{"repo:owner/repo:environment:pull_request"})
	g := graph.New()
	if err := routinggithubactions.AddRoutes(g, workflows); err != nil {
		t.Fatalf("add github actions routes: %v", err)
	}

	if err := AddRoutes(g, parserterraform.Resources{IAMRoles: []parserterraform.IAMRole{role}}, workflows, "owner/repo"); err != nil {
		t.Fatalf("add terraform routes: %v", err)
	}

	edge := onlyEdgeOfKind(t, g, graph.CanAssumeRole)
	matches := edge.Metadata.AWSCanAssumeRole.Matches
	if got := len(matches); got != 1 {
		t.Fatalf("CanAssumeRole matches = %d, want 1: %#v", got, matches)
	}
	if matches[0].SubjectCandidate != "repo:owner/repo:environment:pull_request" {
		t.Fatalf("subject candidate = %q, want environment pull_request subject", matches[0].SubjectCandidate)
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

func testRoleWithSubjects(name string, subjects []string) parserterraform.IAMRole {
	role := testRole(name, "")
	role.Trusts[0].SubjectPatterns = make([]parserterraform.SubjectPattern, 0, len(subjects))
	for _, subject := range subjects {
		role.Trusts[0].SubjectPatterns = append(role.Trusts[0].SubjectPatterns, parserterraform.SubjectPattern{
			Operator: "StringEquals",
			Pattern:  subject,
		})
	}
	return role
}

func testRoleWithPermissions(name string, permissions []parserterraform.IAMPermission) parserterraform.IAMRole {
	role := testRole(name, "repo:owner/repo:pull_request")
	role.Permissions = permissions
	return role
}

func testS3Bucket(resourceName, bucketName string) parserterraform.S3Bucket {
	return parserterraform.S3Bucket{
		ResourceType: "aws_s3_bucket",
		ResourceName: resourceName,
		BucketName:   bucketName,
		Source: parserterraform.Source{
			Filename:     "/repo/s3.tf",
			RelativePath: "s3.tf",
			ResourceType: "aws_s3_bucket",
			ResourceName: resourceName,
		},
	}
}

func testS3Permission(roleName, policyName string, statementIndex int, action, resource string) parserterraform.IAMPermission {
	return parserterraform.IAMPermission{
		Kind:                     "inline_policy",
		Source:                   parserterraform.Source{Filename: "/repo/iam.tf", RelativePath: "iam.tf", ResourceType: "aws_iam_role_policy", ResourceName: policyName},
		PolicyResourceName:       policyName,
		AttachedRoleResourceName: roleName,
		StatementIndex:           statementIndex,
		Actions:                  []string{action},
		Resources:                []string{resource},
	}
}

func testAdminPermission(roleName, policyName, action, resource string) parserterraform.IAMPermission {
	permission := testS3Permission(roleName, policyName, 0, action, resource)
	permission.Administrative = true
	permission.AdminReason = "action_star_resource_star"
	return permission
}

func s3GrantKinds(grants []graph.AWSS3AccessGrant) []string {
	kinds := make([]string, 0, len(grants))
	for _, grant := range grants {
		kinds = append(kinds, grant.AccessKind)
	}
	return kinds
}

func canAssumeMatchSubjects(matches []graph.AWSCanAssumeRoleMatch) []string {
	subjects := make([]string, 0, len(matches))
	for _, match := range matches {
		subjects = append(subjects, match.SubjectCandidate)
	}
	return subjects
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
