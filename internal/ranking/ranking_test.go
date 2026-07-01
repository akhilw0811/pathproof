package ranking

import (
	"reflect"
	"testing"

	"pathproof/internal/analysis"
	"pathproof/internal/graph"
	"pathproof/internal/remediation"
	"pathproof/internal/rules"
	"pathproof/internal/validation"
)

func TestExtractFeaturesRuleMetadataForEveryRule(t *testing.T) {
	findings := make([]analysis.Finding, 0, len(rules.All()))
	for _, rule := range rules.All() {
		findings = append(findings, testFinding("finding:"+rule.ID, analysis.RuleID(rule.ID)))
	}

	vectors := ExtractFeatures(findings, nil, Context{})

	if len(vectors) != len(findings) {
		t.Fatalf("feature count = %d, want %d", len(vectors), len(findings))
	}
	for i, rule := range rules.All() {
		vector := vectors[i]
		if vector.RuleID != rule.ID || vector.Severity != string(rule.Severity) || vector.Category != string(rule.Category) {
			t.Fatalf("vector metadata for %s = %#v, want rule metadata %#v", rule.ID, vector, rule)
		}
	}
}

func TestExtractFeaturesUnknownRuleHasNoRuleMetadataScore(t *testing.T) {
	vector := ExtractFeatures([]analysis.Finding{testFinding("finding:unknown", analysis.RuleID("PP-UNKNOWN-001"))}, nil, Context{})[0]

	if vector.Severity != "" || vector.Category != "" {
		t.Fatalf("unknown rule metadata = %#v, want empty severity/category", vector)
	}
	score := ScoreHeuristic(vector)
	if score.Score != 0 || len(score.Reasons) != 0 || score.Band != "low_priority" {
		t.Fatalf("unknown rule score = %#v, want no scoring points", score)
	}
}

func TestExtractFeaturesRuleRiskBooleans(t *testing.T) {
	tests := []struct {
		name string
		rule analysis.RuleID
		want FeatureVector
	}{
		{
			name: "kubernetes public secret",
			rule: analysis.RulePublicWorkloadCanReadSecret,
			want: FeatureVector{PublicExposure: true, KubernetesSecretAccess: true, SensitiveResource: true},
		},
		{
			name: "unsafe checkout",
			rule: analysis.RuleGitHubActionsUnsafePullRequestTargetCheckout,
			want: FeatureVector{PullRequestTargetRisk: true, UntrustedCheckoutRisk: true},
		},
		{
			name: "dangerous permissions",
			rule: analysis.RuleGitHubActionsDangerousPermissions,
			want: FeatureVector{PullRequestTargetRisk: true, DangerousTokenPermissionsRisk: true},
		},
		{
			name: "aws admin",
			rule: analysis.RuleAWSIAMRoleAdministrativePermissions,
			want: FeatureVector{AWSAdminRole: true},
		},
		{
			name: "cross domain role",
			rule: analysis.RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole,
			want: FeatureVector{OIDCRoleAssumption: true},
		},
		{
			name: "cross domain admin",
			rule: analysis.RuleCrossDomainRiskyGitHubActionsCanAssumeAWSAdminRole,
			want: FeatureVector{OIDCRoleAssumption: true, AWSAdminRole: true},
		},
		{
			name: "cross domain s3",
			rule: analysis.RuleCrossDomainRiskyGitHubActionsCanAccessAWSS3Bucket,
			want: FeatureVector{OIDCRoleAssumption: true, S3Access: true},
		},
		{
			name: "cross domain sensitive s3",
			rule: analysis.RuleCrossDomainRiskyGitHubActionsCanAccessSensitiveAWSS3Bucket,
			want: FeatureVector{OIDCRoleAssumption: true, S3Access: true, SensitiveResource: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vector := ExtractFeatures([]analysis.Finding{testFinding("finding:"+string(tt.rule), tt.rule)}, nil, Context{})[0]

			if vector.PublicExposure != tt.want.PublicExposure ||
				vector.PullRequestTargetRisk != tt.want.PullRequestTargetRisk ||
				vector.UntrustedCheckoutRisk != tt.want.UntrustedCheckoutRisk ||
				vector.DangerousTokenPermissionsRisk != tt.want.DangerousTokenPermissionsRisk ||
				vector.OIDCRoleAssumption != tt.want.OIDCRoleAssumption ||
				vector.AWSAdminRole != tt.want.AWSAdminRole ||
				vector.S3Access != tt.want.S3Access ||
				vector.SensitiveResource != tt.want.SensitiveResource ||
				vector.KubernetesSecretAccess != tt.want.KubernetesSecretAccess {
				t.Fatalf("vector booleans = %#v, want %#v", vector, tt.want)
			}
			if rules.MustLookup(string(tt.rule)).Category == rules.CategoryCrossDomain && vector.CrossDomainBoundaryCount < 1 {
				t.Fatalf("cross-domain boundary count = %d, want at least 1", vector.CrossDomainBoundaryCount)
			}
		})
	}
}

func TestExtractFeaturesCrossDomainRiskSignalsAreStructured(t *testing.T) {
	for _, tt := range []struct {
		name       string
		riskRuleID analysis.RuleID
		wantField  string
	}{
		{name: "unsafe checkout", riskRuleID: analysis.RuleGitHubActionsUnsafePullRequestTargetCheckout, wantField: "checkout"},
		{name: "dangerous permissions", riskRuleID: analysis.RuleGitHubActionsDangerousPermissions, wantField: "permissions"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			finding := testFinding("finding:xdomain", analysis.RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole)
			finding.RiskSignal = &analysis.RiskSignal{RuleID: tt.riskRuleID}

			vector := ExtractFeatures([]analysis.Finding{finding}, nil, Context{})[0]

			if !vector.PullRequestTargetRisk {
				t.Fatalf("pull request target risk = false, want true: %#v", vector)
			}
			switch tt.wantField {
			case "checkout":
				if !vector.UntrustedCheckoutRisk || vector.DangerousTokenPermissionsRisk {
					t.Fatalf("risk booleans = %#v, want checkout only", vector)
				}
			case "permissions":
				if !vector.DangerousTokenPermissionsRisk || vector.UntrustedCheckoutRisk {
					t.Fatalf("risk booleans = %#v, want permissions only", vector)
				}
			}
		})
	}
}

func TestExtractFeaturesBaselineRemediationPatchAndValidationContext(t *testing.T) {
	finding := testFinding("finding:ctx", analysis.RuleGitHubActionsUnpinnedAction)
	plan := remediation.Plan{
		FindingID: finding.ID,
		Options: []remediation.Option{{
			Changes: []remediation.Change{{PatchSupported: true}},
		}},
	}

	vector := ExtractFeatures([]analysis.Finding{finding}, nil, Context{
		BaselineStatusByFindingID: map[analysis.FindingID]string{finding.ID: "new"},
		Plans:                     []remediation.Plan{plan},
		ValidationResults:         []validation.Result{{FindingID: finding.ID, Status: validation.StatusFailed}},
	})[0]

	if vector.BaselineStatus != "new" || !vector.RemediationAvailable || !vector.PatchAvailable || vector.ValidationStatus != "failed" {
		t.Fatalf("context features = %#v, want baseline/remediation/patch/validation", vector)
	}

	withoutContext := ExtractFeatures([]analysis.Finding{finding}, nil, Context{})[0]
	if withoutContext.BaselineStatus != "" || withoutContext.RemediationAvailable || withoutContext.PatchAvailable || withoutContext.ValidationStatus != "" {
		t.Fatalf("empty context features = %#v, want empty/false values", withoutContext)
	}
}

func TestExtractFeaturesUsesTypedGraphMetadataOnly(t *testing.T) {
	g, finding := s3FindingWithTypedMetadata(t, "write")

	vector := ExtractFeatures([]analysis.Finding{finding}, g, Context{})[0]

	if vector.AccessMode != "write" {
		t.Fatalf("access mode = %q, want write from typed S3 metadata", vector.AccessMode)
	}
	if vector.ResourceKind != string(graph.AWSS3Bucket) {
		t.Fatalf("resource kind = %q, want AWSS3Bucket", vector.ResourceKind)
	}
	if vector.CrossDomainBoundaryCount != 1 {
		t.Fatalf("cross-domain boundary count = %d, want 1", vector.CrossDomainBoundaryCount)
	}
	if vector.AuthTrustChainCount != 2 {
		t.Fatalf("auth/trust chain count = %d, want typed trust match plus S3 grant", vector.AuthTrustChainCount)
	}

	misleading := testFinding("finding:misleading", analysis.RuleGitHubActionsUnpinnedAction)
	misleading.Summary = "PP-XDOMAIN-004 can write sensitive S3 bucket"
	misleading.Evidence = []analysis.FindingEvidence{{
		Kind:   graph.CanWriteObject,
		Source: graph.SourceEvidence{Source: "source", Detail: "sensitive S3 access_mode=write"},
	}}
	misleadingVector := ExtractFeatures([]analysis.Finding{misleading}, nil, Context{})[0]
	if misleadingVector.S3Access || misleadingVector.SensitiveResource || misleadingVector.AccessMode != "" {
		t.Fatalf("misleading prose affected features: %#v", misleadingVector)
	}
}

func TestExtractFeaturesKubernetesSecretReadModeFromCanReadEdge(t *testing.T) {
	g := graph.New()
	endpoint := mustAddNode(t, g, graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/public-api"))
	workload := mustAddNode(t, g, graph.NewNode(graph.Workload, "kubernetes://prod/deployment/api"))
	serviceAccount := mustAddNode(t, g, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/api"))
	secret := mustAddNode(t, g, graph.NewNode(graph.Secret, "kubernetes://prod/secret/database-password"))
	route := mustAddEdge(t, g, graph.NewEdge(graph.RoutesTo, endpoint.ID, workload.ID, graph.SourceEvidence{Source: "service.yaml#document=1"}))
	runsAs := mustAddEdge(t, g, graph.NewEdge(graph.RunsAs, workload.ID, serviceAccount.ID, graph.SourceEvidence{Source: "deploy.yaml#document=1"}))
	canRead := graph.NewEdge(graph.CanRead, serviceAccount.ID, secret.ID, graph.SourceEvidence{Source: "rbac.yaml#document=1"})
	canRead.Metadata = &graph.EdgeMetadata{KubernetesCanReadAuthorizations: []graph.KubernetesCanReadAuthorization{{BindingName: "read-secrets"}}}
	canRead = mustAddEdge(t, g, canRead)
	finding := analysis.Finding{
		ID:       "finding:k8s",
		RuleID:   analysis.RulePublicWorkloadCanReadSecret,
		NodeIDs:  []graph.NodeID{endpoint.ID, workload.ID, serviceAccount.ID, secret.ID},
		EdgeIDs:  []graph.EdgeID{route.ID, runsAs.ID, canRead.ID},
		Evidence: []analysis.FindingEvidence{{EdgeID: route.ID, Kind: route.Kind}, {EdgeID: runsAs.ID, Kind: runsAs.Kind}, {EdgeID: canRead.ID, Kind: canRead.Kind}},
	}

	vector := ExtractFeatures([]analysis.Finding{finding}, g, Context{})[0]

	if vector.AccessMode != "read" || vector.ResourceKind != string(graph.Secret) || vector.AuthTrustChainCount != 1 {
		t.Fatalf("kubernetes access features = %#v, want read Secret with one auth chain", vector)
	}
}

func TestExtractFeaturesAndScoringAreDeterministicAndDoNotMutateInputs(t *testing.T) {
	g, s3Finding := s3FindingWithTypedMetadata(t, "read")
	ghaFinding := testFinding("finding:gha", analysis.RuleGitHubActionsUnpinnedAction)
	findings := []analysis.Finding{s3Finding, ghaFinding}
	original := append([]analysis.Finding(nil), findings...)

	firstVectors := ExtractFeatures(findings, g, Context{})
	secondVectors := ExtractFeatures(findings, g, Context{})
	if !reflect.DeepEqual(firstVectors, secondVectors) {
		t.Fatalf("feature vectors differ:\nfirst: %#v\nsecond:%#v", firstVectors, secondVectors)
	}
	if !reflect.DeepEqual(findings, original) {
		t.Fatalf("findings mutated:\ngot: %#v\nwant:%#v", findings, original)
	}
	if firstVectors[0].FindingID != string(s3Finding.ID) || firstVectors[1].FindingID != string(ghaFinding.ID) {
		t.Fatalf("feature order = %#v, want input finding order", firstVectors)
	}

	firstScores := ScoreHeuristicAll(firstVectors)
	secondScores := ScoreHeuristicAll(secondVectors)
	if !reflect.DeepEqual(firstScores, secondScores) {
		t.Fatalf("scores differ:\nfirst: %#v\nsecond:%#v", firstScores, secondScores)
	}
	if firstScores[0].FindingID != string(s3Finding.ID) || firstScores[1].FindingID != string(ghaFinding.ID) {
		t.Fatalf("score finding IDs = %#v, want unchanged IDs/order", firstScores)
	}
	if firstVectors[0].Severity != "High" || firstVectors[1].Severity != "Medium" {
		t.Fatalf("feature severities = %#v, want registry severities", firstVectors)
	}
	if firstScores[0].Score <= firstScores[1].Score {
		t.Fatalf("composed finding score = %d, lint finding score = %d, want composed higher", firstScores[0].Score, firstScores[1].Score)
	}
}

func TestScoreHeuristicReasonOrderAndBands(t *testing.T) {
	vector := FeatureVector{
		FindingID:                     "finding:score",
		Severity:                      "High",
		Category:                      "cross-domain",
		PublicExposure:                true,
		PullRequestTargetRisk:         true,
		UntrustedCheckoutRisk:         true,
		DangerousTokenPermissionsRisk: true,
		OIDCRoleAssumption:            true,
		AWSAdminRole:                  true,
		S3Access:                      true,
		SensitiveResource:             true,
		KubernetesSecretAccess:        true,
		BaselineStatus:                "new",
		RemediationAvailable:          true,
		ValidationStatus:              "failed",
	}

	score := ScoreHeuristic(vector)

	wantReasons := []string{
		"high severity +50",
		"cross-domain category +20",
		"public exposure +15",
		"pull request target risk +15",
		"untrusted checkout +15",
		"dangerous token permissions +15",
		"OIDC role assumption +15",
		"AWS admin role +20",
		"S3 access +10",
		"sensitive resource +20",
		"Kubernetes Secret access +15",
		"new baseline status +10",
		"remediation available +5",
		"validation failed +10",
	}
	if !reflect.DeepEqual(score.Reasons, wantReasons) {
		t.Fatalf("reasons = %#v, want %#v", score.Reasons, wantReasons)
	}
	if score.Score != 235 || score.Band != "critical_priority" {
		t.Fatalf("score = %#v, want 235 critical_priority", score)
	}

	for _, tt := range []struct {
		score int
		band  string
	}{
		{100, "critical_priority"},
		{70, "high_priority"},
		{35, "medium_priority"},
		{34, "low_priority"},
	} {
		if got := priorityBand(tt.score); got != tt.band {
			t.Fatalf("priorityBand(%d) = %q, want %q", tt.score, got, tt.band)
		}
	}
}

func TestScoreHeuristicValidationRemediatedDeductsPoints(t *testing.T) {
	score := ScoreHeuristic(FeatureVector{FindingID: "finding:fixed", Severity: "Medium", ValidationStatus: "remediated"})

	if score.Score != 5 || score.Band != "low_priority" {
		t.Fatalf("score = %#v, want medium severity minus remediated deduction", score)
	}
	wantReasons := []string{"medium severity +25", "validation remediated -20"}
	if !reflect.DeepEqual(score.Reasons, wantReasons) {
		t.Fatalf("reasons = %#v, want %#v", score.Reasons, wantReasons)
	}
}

func testFinding(id string, ruleID analysis.RuleID) analysis.Finding {
	return analysis.Finding{
		ID:       analysis.FindingID(id),
		RuleID:   ruleID,
		Severity: analysis.Severity("input severity should not be used"),
	}
}

func s3FindingWithTypedMetadata(t *testing.T, accessMode string) (*graph.Graph, analysis.Finding) {
	t.Helper()
	g := graph.New()
	workflow := mustAddNode(t, g, graph.NewNode(graph.Workflow, "githubactions://.github/workflows/deploy.yml"))
	oidc := mustAddNode(t, g, graph.NewNode(graph.OIDCTokenCapability, "githubactions://.github/workflows/deploy.yml/oidc-token/workflow"))
	role := mustAddNode(t, g, graph.NewNode(graph.AWSIAMRole, "aws://terraform/aws_iam_role/main.tf/deploy"))
	bucket := mustAddNode(t, g, graph.NewNode(graph.AWSS3Bucket, "aws://terraform/aws_s3_bucket/s3.tf/artifacts"))
	canRequest := mustAddEdge(t, g, graph.NewEdge(graph.CanRequestOIDCToken, workflow.ID, oidc.ID, graph.SourceEvidence{Source: ".github/workflows/deploy.yml#document=1"}))
	canAssume := graph.NewEdge(graph.CanAssumeRole, oidc.ID, role.ID, graph.SourceEvidence{Source: "iam.tf#resource=aws_iam_role.deploy"})
	canAssume.Metadata = &graph.EdgeMetadata{AWSCanAssumeRole: &graph.AWSCanAssumeRoleMetadata{Matches: []graph.AWSCanAssumeRoleMatch{{StatementIndex: 0}}}}
	canAssume = mustAddEdge(t, g, canAssume)
	accessKind := graph.CanReadObject
	if accessMode == "write" {
		accessKind = graph.CanWriteObject
	}
	access := graph.NewEdge(accessKind, role.ID, bucket.ID, graph.SourceEvidence{Source: "iam.tf#resource=aws_iam_role_policy.s3"})
	access.Metadata = &graph.EdgeMetadata{AWSS3Access: &graph.AWSS3AccessMetadata{
		AccessMode: accessMode,
		Grants:     []graph.AWSS3AccessGrant{{AccessMode: accessMode, Action: "s3:GetObject"}},
	}}
	access = mustAddEdge(t, g, access)
	finding := analysis.Finding{
		ID:         analysis.FindingID("finding:s3:" + accessMode),
		RuleID:     analysis.RuleCrossDomainRiskyGitHubActionsCanAccessSensitiveAWSS3Bucket,
		NodeIDs:    []graph.NodeID{workflow.ID, oidc.ID, role.ID, bucket.ID},
		EdgeIDs:    []graph.EdgeID{canRequest.ID, canAssume.ID, access.ID},
		Evidence:   []analysis.FindingEvidence{{EdgeID: canRequest.ID, Kind: canRequest.Kind}, {EdgeID: canAssume.ID, Kind: canAssume.Kind}, {EdgeID: access.ID, Kind: access.Kind}},
		RiskSignal: &analysis.RiskSignal{RuleID: analysis.RuleGitHubActionsDangerousPermissions},
	}
	return g, finding
}

func mustAddNode(t *testing.T, g *graph.Graph, node graph.Node) graph.Node {
	t.Helper()
	added, err := g.AddNode(node)
	if err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	return added
}

func mustAddEdge(t *testing.T, g *graph.Graph, edge graph.Edge) graph.Edge {
	t.Helper()
	added, err := g.AddEdge(edge)
	if err != nil {
		t.Fatalf("AddEdge: %v", err)
	}
	return added
}
