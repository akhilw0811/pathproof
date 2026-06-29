package analysis

import (
	"encoding/json"
	"strings"
	"testing"

	"pathproof/internal/graph"
)

func TestAnalyzeAWSIAMRoleInlineAdminPermissionEmitsPPAWS001(t *testing.T) {
	tests := []struct {
		name      string
		action    string
		reason    string
		wantInSum string
	}{
		{name: "action star", action: "*", reason: "action_star_resource_star", wantInSum: "action_star_resource_star"},
		{name: "action service star", action: "*:*", reason: "action_service_star_resource_star", wantInSum: "action_service_star_resource_star"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := awsAdminPermissionGraph(t, "deploy", graph.AWSPermissionMetadata{
				Provider:                 "aws",
				SourceReference:          "iam.tf#resource=aws_iam_role_policy.admin",
				PolicyResourceName:       "admin",
				AttachedRoleResourceName: "deploy",
				Actions:                  []string{tt.action},
				Resources:                []string{"*"},
				Administrative:           true,
				AdminReason:              tt.reason,
			})

			findings := Analyze(g)

			finding := onlyAWSFinding(t, findings)
			if finding.Title != ruleTitle(RuleAWSIAMRoleAdministrativePermissions) {
				t.Fatalf("title = %q, want %q", finding.Title, ruleTitle(RuleAWSIAMRoleAdministrativePermissions))
			}
			if finding.Severity != SeverityHigh {
				t.Fatalf("severity = %q, want High", finding.Severity)
			}
			assertFindingNodeKinds(t, finding, []graph.NodeKind{graph.AWSIAMRole, graph.AWSPermission})
			assertFindingEdgeKinds(t, finding, []graph.EdgeKind{graph.GrantsPermission})
			if !strings.Contains(finding.Summary, tt.wantInSum) {
				t.Fatalf("summary = %q, want admin reason %q", finding.Summary, tt.wantInSum)
			}
			if len(finding.Evidence) != 1 || !strings.Contains(finding.Evidence[0].Source.Detail, tt.reason) {
				t.Fatalf("evidence = %#v, want admin reason", finding.Evidence)
			}
		})
	}
}

func TestAnalyzeAWSIAMRoleAdministratorAccessAttachmentEmitsPPAWS001(t *testing.T) {
	g := awsAdminPermissionGraph(t, "deploy", graph.AWSPermissionMetadata{
		Provider:                 "aws",
		SourceReference:          "iam.tf#resource=aws_iam_role_policy_attachment.admin",
		AttachmentResourceName:   "admin",
		AttachedRoleResourceName: "deploy",
		ManagedPolicyARN:         "arn:aws:iam::aws:policy/AdministratorAccess",
		Administrative:           true,
		AdminReason:              "administrator_access_managed_policy",
	})

	finding := onlyAWSFinding(t, Analyze(g))

	if finding.RuleID != RuleAWSIAMRoleAdministrativePermissions {
		t.Fatalf("rule = %q, want PP-AWS-001", finding.RuleID)
	}
	if !strings.Contains(finding.Summary, "administrator_access_managed_policy") {
		t.Fatalf("summary = %q, want managed policy reason", finding.Summary)
	}
}

func TestAnalyzeAWSIAMRoleNonAdminPermissionEmitsNoFinding(t *testing.T) {
	tests := []struct {
		name     string
		metadata graph.AWSPermissionMetadata
	}{
		{
			name: "specific action on wildcard resource",
			metadata: graph.AWSPermissionMetadata{
				Provider:                 "aws",
				SourceReference:          "iam.tf#resource=aws_iam_role_policy.read",
				PolicyResourceName:       "read",
				AttachedRoleResourceName: "deploy",
				Actions:                  []string{"s3:GetObject"},
				Resources:                []string{"*"},
			},
		},
		{
			name: "unsupported admin reason",
			metadata: graph.AWSPermissionMetadata{
				Provider:                 "aws",
				SourceReference:          "iam.tf#resource=aws_iam_role_policy.admin",
				PolicyResourceName:       "admin",
				AttachedRoleResourceName: "deploy",
				Actions:                  []string{"*"},
				Resources:                []string{"*"},
				Administrative:           true,
				AdminReason:              "vague_admin_reason",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := awsAdminPermissionGraph(t, "deploy", tt.metadata)

			if got := countFindingsByRule(Analyze(g), RuleAWSIAMRoleAdministrativePermissions); got != 0 {
				t.Fatalf("PP-AWS-001 count = %d, want 0", got)
			}
		})
	}
}

func TestAnalyzeAWSIAMRoleAdminFindingIDIsStableAndSensitive(t *testing.T) {
	baseGraph := awsAdminPermissionGraph(t, "deploy", graph.AWSPermissionMetadata{
		Provider:                 "aws",
		SourceReference:          "iam.tf#resource=aws_iam_role_policy.admin",
		PolicyResourceName:       "admin",
		AttachedRoleResourceName: "deploy",
		Actions:                  []string{"*"},
		Resources:                []string{"*"},
		Administrative:           true,
		AdminReason:              "action_star_resource_star",
	})
	base := onlyAWSFinding(t, Analyze(baseGraph))
	repeated := onlyAWSFinding(t, Analyze(baseGraph))
	if base.ID != repeated.ID {
		t.Fatalf("finding ID changed across repeated analysis: %q vs %q", base.ID, repeated.ID)
	}

	changedRole := onlyAWSFinding(t, Analyze(awsAdminPermissionGraph(t, "audit", graph.AWSPermissionMetadata{
		Provider:                 "aws",
		SourceReference:          "iam.tf#resource=aws_iam_role_policy.admin",
		PolicyResourceName:       "admin",
		AttachedRoleResourceName: "audit",
		Actions:                  []string{"*"},
		Resources:                []string{"*"},
		Administrative:           true,
		AdminReason:              "action_star_resource_star",
	})))
	changedReason := onlyAWSFinding(t, Analyze(awsAdminPermissionGraph(t, "deploy", graph.AWSPermissionMetadata{
		Provider:                 "aws",
		SourceReference:          "iam.tf#resource=aws_iam_role_policy.admin",
		PolicyResourceName:       "admin",
		AttachedRoleResourceName: "deploy",
		Actions:                  []string{"*:*"},
		Resources:                []string{"*"},
		Administrative:           true,
		AdminReason:              "action_service_star_resource_star",
	})))
	if base.ID == changedRole.ID {
		t.Fatalf("finding ID did not change when role changed: %q", base.ID)
	}
	if base.ID == changedReason.ID {
		t.Fatalf("finding ID did not change when admin reason changed: %q", base.ID)
	}
}

func TestAnalyzeAWSIAMRoleAdminEvidenceIsSanitized(t *testing.T) {
	g := awsAdminPermissionGraph(t, "deploy", graph.AWSPermissionMetadata{
		Provider:                 "aws",
		SourceReference:          "iam.tf#resource=aws_iam_role_policy.admin",
		PolicyResourceName:       "admin",
		AttachedRoleResourceName: "deploy",
		Actions:                  []string{"*"},
		Resources:                []string{"*"},
		Administrative:           true,
		AdminReason:              "action_star_resource_star",
	})

	data, err := json.Marshal(Analyze(g))
	if err != nil {
		t.Fatalf("marshal findings: %v", err)
	}
	for _, forbidden := range []string{"Statement", "Action", "Resource", "FAKE_TF_AWS_SECRET_DO_NOT_RETAIN", "policy ="} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("finding JSON contains %q: %s", forbidden, data)
		}
	}
}

func awsAdminPermissionGraph(t *testing.T, roleName string, metadata graph.AWSPermissionMetadata) *graph.Graph {
	t.Helper()
	g := graph.New()
	role := graph.NewNode(graph.AWSIAMRole, "aws://terraform/aws_iam_role/iam.tf/"+roleName)
	role.Metadata = &graph.NodeMetadata{AWSIAMRole: &graph.AWSIAMRoleMetadata{
		Provider:        "aws",
		ResourceName:    roleName,
		SourceReference: "iam.tf#resource=aws_iam_role." + roleName,
	}}
	role = mustAddNode(t, g, role)
	permissionName := "aws://terraform/aws_permission/" + roleName + "/" + metadata.AdminReason
	if metadata.AdminReason == "" {
		permissionName = "aws://terraform/aws_permission/" + roleName + "/non-admin"
	}
	permission := graph.NewNode(graph.AWSPermission, permissionName)
	permission.Metadata = &graph.NodeMetadata{AWSPermission: &metadata}
	permission = mustAddNode(t, g, permission)
	detail := "aws iam role " + roleName + " grants static permission"
	if metadata.AdminReason != "" {
		detail = "aws iam role " + roleName + " grants administrative permission (" + metadata.AdminReason + ")"
	}
	mustAddEdge(t, g, graph.NewEdge(graph.GrantsPermission, role.ID, permission.ID, graph.SourceEvidence{
		Source: metadata.SourceReference,
		Detail: detail,
	}))
	return g
}

func onlyAWSFinding(t *testing.T, findings []Finding) Finding {
	t.Helper()
	var matches []Finding
	for _, finding := range findings {
		if finding.RuleID == RuleAWSIAMRoleAdministrativePermissions {
			matches = append(matches, finding)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("PP-AWS-001 finding count = %d, want 1: %#v", len(matches), findings)
	}
	return matches[0]
}
