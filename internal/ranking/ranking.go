package ranking

import (
	"pathproof/internal/analysis"
	"pathproof/internal/graph"
	"pathproof/internal/remediation"
	"pathproof/internal/rules"
	"pathproof/internal/validation"
)

type Method string

const MethodHeuristic Method = "heuristic"

type FeatureVector struct {
	FindingID string
	RuleID    string
	Severity  string
	Category  string

	PathLength               int
	CrossDomainBoundaryCount int

	PublicExposure                bool
	PullRequestTargetRisk         bool
	UntrustedCheckoutRisk         bool
	DangerousTokenPermissionsRisk bool
	OIDCRoleAssumption            bool
	AWSAdminRole                  bool
	S3Access                      bool
	SensitiveResource             bool
	KubernetesSecretAccess        bool
	AccessMode                    string
	ResourceKind                  string
	RemediationAvailable          bool
	PatchAvailable                bool
	ValidationStatus              string
	BaselineStatus                string
	EvidenceCount                 int
	AuthTrustChainCount           int
}

type Score struct {
	FindingID string
	Score     int
	Band      string
	Reasons   []string
}

type Context struct {
	BaselineStatusByFindingID map[analysis.FindingID]string
	Plans                     []remediation.Plan
	ValidationResults         []validation.Result
}

func ExtractFeatures(findings []analysis.Finding, g *graph.Graph, ctx Context) []FeatureVector {
	planByFinding := plansByFindingID(ctx.Plans)
	validationByFinding := validationByFindingID(ctx.ValidationResults)

	out := make([]FeatureVector, 0, len(findings))
	for _, finding := range findings {
		vector := FeatureVector{
			FindingID:      string(finding.ID),
			RuleID:         string(finding.RuleID),
			PathLength:     len(finding.NodeIDs),
			EvidenceCount:  len(finding.Evidence),
			BaselineStatus: ctx.BaselineStatusByFindingID[finding.ID],
		}
		if rule, ok := rules.Lookup(string(finding.RuleID)); ok {
			vector.Severity = string(rule.Severity)
			vector.Category = string(rule.Category)
		}
		if status, ok := validationByFinding[finding.ID]; ok {
			vector.ValidationStatus = string(status)
		}
		if plan, ok := planByFinding[finding.ID]; ok {
			vector.RemediationAvailable = true
			vector.PatchAvailable = planHasPatchAvailable(plan)
		}

		applyRuleFeatures(&vector, finding)
		applyGraphFeatures(&vector, finding, g)
		out = append(out, vector)
	}
	return out
}

func ScoreHeuristicAll(vectors []FeatureVector) []Score {
	out := make([]Score, 0, len(vectors))
	for _, vector := range vectors {
		out = append(out, ScoreHeuristic(vector))
	}
	return out
}

func ScoreHeuristic(vector FeatureVector) Score {
	score := 0
	reasons := make([]string, 0)
	add := func(points int, reason string) {
		score += points
		reasons = append(reasons, reason)
	}

	switch vector.Severity {
	case string(rules.SeverityHigh):
		add(50, "high severity +50")
	case string(rules.SeverityMedium):
		add(25, "medium severity +25")
	}
	if vector.Category == string(rules.CategoryCrossDomain) {
		add(20, "cross-domain category +20")
	}
	if vector.PublicExposure {
		add(15, "public exposure +15")
	}
	if vector.PullRequestTargetRisk {
		add(15, "pull request target risk +15")
	}
	if vector.UntrustedCheckoutRisk {
		add(15, "untrusted checkout +15")
	}
	if vector.DangerousTokenPermissionsRisk {
		add(15, "dangerous token permissions +15")
	}
	if vector.OIDCRoleAssumption {
		add(15, "OIDC role assumption +15")
	}
	if vector.AWSAdminRole {
		add(20, "AWS admin role +20")
	}
	if vector.S3Access {
		add(10, "S3 access +10")
	}
	if vector.SensitiveResource {
		add(20, "sensitive resource +20")
	}
	if vector.KubernetesSecretAccess {
		add(15, "Kubernetes Secret access +15")
	}
	if vector.BaselineStatus == "new" {
		add(10, "new baseline status +10")
	}
	if vector.RemediationAvailable {
		add(5, "remediation available +5")
	}
	if vector.ValidationStatus == string(validation.StatusFailed) {
		add(10, "validation failed +10")
	}
	if vector.ValidationStatus == string(validation.StatusRemediated) {
		add(-20, "validation remediated -20")
	}

	return Score{
		FindingID: vector.FindingID,
		Score:     score,
		Band:      priorityBand(score),
		Reasons:   reasons,
	}
}

func applyRuleFeatures(vector *FeatureVector, finding analysis.Finding) {
	switch finding.RuleID {
	case analysis.RulePublicWorkloadCanReadSecret:
		vector.PublicExposure = true
		vector.KubernetesSecretAccess = true
		vector.SensitiveResource = true
	case analysis.RuleGitHubActionsUnsafePullRequestTargetCheckout:
		vector.PullRequestTargetRisk = true
		vector.UntrustedCheckoutRisk = true
	case analysis.RuleGitHubActionsDangerousPermissions:
		vector.PullRequestTargetRisk = true
		vector.DangerousTokenPermissionsRisk = true
	case analysis.RuleAWSIAMRoleAdministrativePermissions:
		vector.AWSAdminRole = true
	case analysis.RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole:
		vector.OIDCRoleAssumption = true
	case analysis.RuleCrossDomainRiskyGitHubActionsCanAssumeAWSAdminRole:
		vector.OIDCRoleAssumption = true
		vector.AWSAdminRole = true
	case analysis.RuleCrossDomainRiskyGitHubActionsCanAccessAWSS3Bucket:
		vector.OIDCRoleAssumption = true
		vector.S3Access = true
	case analysis.RuleCrossDomainRiskyGitHubActionsCanAccessSensitiveAWSS3Bucket:
		vector.OIDCRoleAssumption = true
		vector.S3Access = true
		vector.SensitiveResource = true
	}

	if finding.RiskSignal == nil {
		return
	}
	switch finding.RiskSignal.RuleID {
	case analysis.RuleGitHubActionsUnsafePullRequestTargetCheckout:
		vector.PullRequestTargetRisk = true
		vector.UntrustedCheckoutRisk = true
	case analysis.RuleGitHubActionsDangerousPermissions:
		vector.PullRequestTargetRisk = true
		vector.DangerousTokenPermissionsRisk = true
	}
}

func applyGraphFeatures(vector *FeatureVector, finding analysis.Finding, g *graph.Graph) {
	if g == nil {
		if vector.Category == string(rules.CategoryCrossDomain) && vector.CrossDomainBoundaryCount == 0 {
			vector.CrossDomainBoundaryCount = 1
		}
		return
	}

	nodeDomains := make([]string, 0, len(finding.NodeIDs))
	for i, nodeID := range finding.NodeIDs {
		node, ok := g.Node(nodeID)
		if !ok {
			nodeDomains = append(nodeDomains, "")
			continue
		}
		if i == len(finding.NodeIDs)-1 {
			vector.ResourceKind = string(node.Kind)
		}
		nodeDomains = append(nodeDomains, domainForNodeKind(node.Kind))
	}
	vector.CrossDomainBoundaryCount = countDomainTransitions(nodeDomains)
	if vector.Category == string(rules.CategoryCrossDomain) && vector.CrossDomainBoundaryCount == 0 {
		vector.CrossDomainBoundaryCount = 1
	}

	for _, edgeID := range finding.EdgeIDs {
		edge, ok := g.Edge(edgeID)
		if !ok {
			continue
		}
		if edge.Kind == graph.CanRead && vector.AccessMode == "" {
			vector.AccessMode = "read"
		}
		if edge.Metadata == nil {
			continue
		}
		if len(edge.Metadata.KubernetesCanReadAuthorizations) > 0 {
			vector.AuthTrustChainCount += len(edge.Metadata.KubernetesCanReadAuthorizations)
		}
		if edge.Metadata.AWSS3Access != nil && vector.AccessMode == "" {
			vector.AccessMode = edge.Metadata.AWSS3Access.AccessMode
		}
		if edge.Metadata.AWSS3Access != nil {
			vector.AuthTrustChainCount += len(edge.Metadata.AWSS3Access.Grants)
		}
		if edge.Metadata.AWSCanAssumeRole != nil {
			if len(edge.Metadata.AWSCanAssumeRole.Matches) > 0 {
				vector.AuthTrustChainCount += len(edge.Metadata.AWSCanAssumeRole.Matches)
			} else {
				vector.AuthTrustChainCount++
			}
		}
	}
}

func plansByFindingID(plans []remediation.Plan) map[analysis.FindingID]remediation.Plan {
	out := make(map[analysis.FindingID]remediation.Plan, len(plans))
	for _, plan := range plans {
		out[plan.FindingID] = plan
	}
	return out
}

func validationByFindingID(results []validation.Result) map[analysis.FindingID]validation.Status {
	out := make(map[analysis.FindingID]validation.Status, len(results))
	for _, result := range results {
		out[result.FindingID] = result.Status
	}
	return out
}

func planHasPatchAvailable(plan remediation.Plan) bool {
	for _, option := range plan.Options {
		for _, change := range option.Changes {
			if change.PatchSupported {
				return true
			}
		}
	}
	return false
}

func countDomainTransitions(domains []string) int {
	count := 0
	for i := 1; i < len(domains); i++ {
		if domains[i-1] == "" || domains[i] == "" {
			continue
		}
		if domains[i-1] != domains[i] {
			count++
		}
	}
	return count
}

func domainForNodeKind(kind graph.NodeKind) string {
	switch kind {
	case graph.PublicEndpoint, graph.Workload, graph.ServiceAccount, graph.Role, graph.Permission, graph.Secret:
		return string(rules.CategoryKubernetes)
	case graph.Workflow, graph.WorkflowJob, graph.GitHubAction, graph.OIDCTokenCapability:
		return string(rules.CategoryGitHubActions)
	case graph.AWSIAMRole, graph.AWSPermission, graph.AWSS3Bucket:
		return string(rules.CategoryAWS)
	default:
		return ""
	}
}

func priorityBand(score int) string {
	switch {
	case score >= 100:
		return "critical_priority"
	case score >= 70:
		return "high_priority"
	case score >= 35:
		return "medium_priority"
	default:
		return "low_priority"
	}
}
