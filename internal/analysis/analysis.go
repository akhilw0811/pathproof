package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"pathproof/internal/graph"
)

type FindingID string
type RuleID string
type Severity string

const (
	RulePublicWorkloadCanReadSecret                   RuleID   = "PP-K8S-001"
	RuleGitHubActionsUnpinnedAction                   RuleID   = "PP-GHA-001"
	RuleGitHubActionsUnsafePullRequestTargetCheckout  RuleID   = "PP-GHA-002"
	RuleGitHubActionsDangerousPermissions             RuleID   = "PP-GHA-003"
	RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole RuleID   = "PP-XDOMAIN-001"
	SeverityHigh                                      Severity = "High"
	SeverityMedium                                    Severity = "Medium"
)

const publicWorkloadCanReadSecretTitle = "Public workload can read Kubernetes Secret"
const githubActionsUnpinnedActionTitle = "GitHub Actions workflow uses an action that is not pinned to a full commit SHA"
const githubActionsUnsafePullRequestTargetCheckoutTitle = "pull_request_target workflow checks out untrusted pull request head code"
const githubActionsDangerousPermissionsTitle = "pull_request_target workflow grants dangerous token permissions"
const crossDomainRiskyGitHubActionsCanAssumeAWSRoleTitle = "Risky GitHub Actions workflow can assume AWS IAM role"

type Finding struct {
	ID               FindingID         `json:"id"`
	RuleID           RuleID            `json:"rule_id"`
	Title            string            `json:"title"`
	Severity         Severity          `json:"severity"`
	NodeIDs          []graph.NodeID    `json:"node_ids"`
	EdgeIDs          []graph.EdgeID    `json:"edge_ids"`
	Summary          string            `json:"summary"`
	Evidence         []FindingEvidence `json:"evidence"`
	SourceReferences []string          `json:"source_references"`
	RiskSignal       *RiskSignal       `json:"risk_signal,omitempty"`
}

type FindingEvidence struct {
	EdgeID graph.EdgeID         `json:"edge_id"`
	Kind   graph.EdgeKind       `json:"kind"`
	Source graph.SourceEvidence `json:"source"`
}

type RiskSignal struct {
	RuleID          RuleID                          `json:"rule_id"`
	SourceReference string                          `json:"source_reference"`
	WorkflowFile    string                          `json:"workflow_file"`
	JobID           string                          `json:"job_id,omitempty"`
	StepIndex       *int                            `json:"step_index,omitempty"`
	Selectors       []githubActionsSelectorIdentity `json:"selectors,omitempty"`
	Permission      string                          `json:"permission,omitempty"`
	Access          string                          `json:"access,omitempty"`
	Summary         string                          `json:"summary"`
}

type findingIdentity struct {
	RuleID  RuleID         `json:"rule_id"`
	NodeIDs []graph.NodeID `json:"node_ids"`
	EdgeIDs []graph.EdgeID `json:"edge_ids"`
}

type githubActionsFindingIdentity struct {
	RuleID       RuleID `json:"rule_id"`
	WorkflowFile string `json:"workflow_file"`
	JobID        string `json:"job_id"`
	StepIndex    int    `json:"step_index"`
	Owner        string `json:"owner"`
	Repo         string `json:"repo"`
	Path         string `json:"path,omitempty"`
	Ref          string `json:"ref,omitempty"`
}

type githubActionsUnsafeCheckoutFindingIdentity struct {
	RuleID       RuleID                          `json:"rule_id"`
	WorkflowFile string                          `json:"workflow_file"`
	JobID        string                          `json:"job_id"`
	StepIndex    int                             `json:"step_index"`
	Owner        string                          `json:"owner"`
	Repo         string                          `json:"repo"`
	Path         string                          `json:"path,omitempty"`
	Ref          string                          `json:"ref,omitempty"`
	Selectors    []githubActionsSelectorIdentity `json:"selectors"`
}

type githubActionsDangerousPermissionsFindingIdentity struct {
	RuleID       RuleID `json:"rule_id"`
	WorkflowFile string `json:"workflow_file"`
	Scope        string `json:"scope"`
	JobID        string `json:"job_id,omitempty"`
	Permission   string `json:"permission"`
	Access       string `json:"access"`
}

type githubActionsSelectorIdentity struct {
	Field             string `json:"field"`
	MatchedExpression string `json:"matched_expression"`
}

type crossDomainFindingIdentity struct {
	RuleID     RuleID                        `json:"rule_id"`
	NodeIDs    []graph.NodeID                `json:"node_ids"`
	EdgeIDs    []graph.EdgeID                `json:"edge_ids"`
	RiskRuleID RuleID                        `json:"risk_rule_id"`
	RiskSignal crossDomainRiskSignalIdentity `json:"risk_signal"`
	AWSRoleID  graph.NodeID                  `json:"aws_role_node_id"`
}

type crossDomainRiskSignalIdentity struct {
	WorkflowFile string                          `json:"workflow_file"`
	JobID        string                          `json:"job_id,omitempty"`
	StepIndex    *int                            `json:"step_index,omitempty"`
	Selectors    []githubActionsSelectorIdentity `json:"selectors,omitempty"`
	Scope        string                          `json:"scope,omitempty"`
	Permission   string                          `json:"permission,omitempty"`
	Access       string                          `json:"access,omitempty"`
}

type githubActionsRiskSignal struct {
	ruleID       RuleID
	workflowFile string
	sourceRef    string
	jobID        string
	stepIndex    *int
	selectors    []githubActionsSelectorIdentity
	scope        string
	permission   string
	access       string
	summary      string
}

func Analyze(g *graph.Graph) []Finding {
	findings := make([]Finding, 0)
	if g == nil {
		return findings
	}

	var routesTo []graph.Edge
	var definesJob []graph.Edge
	runsAsByWorkload := make(map[graph.NodeID][]graph.Edge)
	canReadByServiceAccount := make(map[graph.NodeID][]graph.Edge)
	usesActionByJob := make(map[graph.NodeID][]graph.Edge)
	canRequestOIDCBySource := make(map[graph.NodeID][]graph.Edge)
	canAssumeRoleByCapability := make(map[graph.NodeID][]graph.Edge)
	for _, edge := range g.Edges() {
		switch edge.Kind {
		case graph.RoutesTo:
			routesTo = append(routesTo, edge)
		case graph.RunsAs:
			runsAsByWorkload[edge.From] = append(runsAsByWorkload[edge.From], edge)
		case graph.CanRead:
			canReadByServiceAccount[edge.From] = append(canReadByServiceAccount[edge.From], edge)
		case graph.DefinesJob:
			definesJob = append(definesJob, edge)
		case graph.UsesAction:
			usesActionByJob[edge.From] = append(usesActionByJob[edge.From], edge)
		case graph.CanRequestOIDCToken:
			canRequestOIDCBySource[edge.From] = append(canRequestOIDCBySource[edge.From], edge)
		case graph.CanAssumeRole:
			canAssumeRoleByCapability[edge.From] = append(canAssumeRoleByCapability[edge.From], edge)
		}
	}

	workflowRisks := make(map[graph.NodeID][]githubActionsRiskSignal)
	jobRisks := make(map[graph.NodeID][]githubActionsRiskSignal)
	for _, node := range g.Nodes() {
		if node.Kind != graph.Workflow {
			continue
		}
		findings = append(findings, newGitHubActionsDangerousWorkflowPermissionFindings(node)...)
		workflowRisks[node.ID] = append(workflowRisks[node.ID], dangerousWorkflowPermissionRiskSignals(node)...)
	}

	for _, route := range routesTo {
		endpoint, ok := nodeOfKind(g, route.From, graph.PublicEndpoint)
		if !ok {
			continue
		}
		workload, ok := nodeOfKind(g, route.To, graph.Workload)
		if !ok {
			continue
		}

		for _, runsAs := range runsAsByWorkload[workload.ID] {
			serviceAccount, ok := nodeOfKind(g, runsAs.To, graph.ServiceAccount)
			if !ok {
				continue
			}

			for _, canRead := range canReadByServiceAccount[serviceAccount.ID] {
				secret, ok := nodeOfKind(g, canRead.To, graph.Secret)
				if !ok {
					continue
				}

				finding, err := newPublicWorkloadCanReadSecretFinding(endpoint, workload, serviceAccount, secret, route, runsAs, canRead)
				if err != nil {
					continue
				}
				findings = append(findings, finding)
			}
		}
	}

	for _, defines := range definesJob {
		workflow, ok := nodeOfKind(g, defines.From, graph.Workflow)
		if !ok {
			continue
		}
		job, ok := nodeOfKind(g, defines.To, graph.WorkflowJob)
		if !ok {
			continue
		}
		findings = append(findings, newGitHubActionsDangerousJobPermissionFindings(workflow, job, defines)...)
		jobRisks[job.ID] = append(jobRisks[job.ID], dangerousJobPermissionRiskSignals(defines)...)
		for _, uses := range usesActionByJob[job.ID] {
			action, ok := nodeOfKind(g, uses.To, graph.GitHubAction)
			if !ok {
				continue
			}
			finding, ok := newGitHubActionsUnpinnedActionFinding(workflow, job, action, defines, uses)
			if ok {
				findings = append(findings, finding)
			}
			finding, ok = newGitHubActionsUnsafePullRequestTargetCheckoutFinding(workflow, job, action, defines, uses)
			if ok {
				findings = append(findings, finding)
			}
			if risk, ok := unsafeCheckoutRiskSignal(uses); ok {
				jobRisks[job.ID] = append(jobRisks[job.ID], risk)
			}
		}
	}
	findings = append(findings, newCrossDomainGitHubActionsAWSRoleFindings(g, definesJob, canRequestOIDCBySource, canAssumeRoleByCapability, workflowRisks, jobRisks)...)

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].ID < findings[j].ID
	})
	return findings
}

func newGitHubActionsDangerousWorkflowPermissionFindings(workflow graph.Node) []Finding {
	if workflow.Metadata == nil || workflow.Metadata.GitHubActionsWorkflow == nil {
		return nil
	}
	workflowMetadata := *workflow.Metadata.GitHubActionsWorkflow
	if !workflowMetadata.TriggersPullRequestTarget {
		return nil
	}

	findings := make([]Finding, 0)
	for _, grant := range workflowMetadata.PermissionGrants {
		if !isDangerousGitHubActionsPermissionGrant(grant) {
			continue
		}
		id, err := stableGitHubActionsDangerousPermissionsFindingID(workflowMetadata.WorkflowFile, grant)
		if err != nil {
			continue
		}
		findings = append(findings, Finding{
			ID:               id,
			RuleID:           RuleGitHubActionsDangerousPermissions,
			Title:            githubActionsDangerousPermissionsTitle,
			Severity:         SeverityHigh,
			NodeIDs:          []graph.NodeID{workflow.ID},
			EdgeIDs:          nil,
			Summary:          "GitHub Actions workflow " + workflowDisplay(workflowMetadata.WorkflowName, workflowMetadata.WorkflowFile) + " grants " + githubActionsPermissionGrantSummary(grant) + " at workflow scope under pull_request_target.",
			Evidence:         nil,
			SourceReferences: sourceReferencesFromValues(workflowMetadata.WorkflowSourceReference),
		})
	}
	return findings
}

func newGitHubActionsDangerousJobPermissionFindings(workflow, job graph.Node, definesJob graph.Edge) []Finding {
	if definesJob.Metadata == nil || definesJob.Metadata.GitHubActionsWorkflowJob == nil {
		return nil
	}
	jobMetadata := *definesJob.Metadata.GitHubActionsWorkflowJob
	if !jobMetadata.TriggersPullRequestTarget {
		return nil
	}

	evidence := []FindingEvidence{findingEvidence(definesJob)}
	findings := make([]Finding, 0)
	for _, grant := range jobMetadata.PermissionGrants {
		if !isDangerousGitHubActionsPermissionGrant(grant) {
			continue
		}
		id, err := stableGitHubActionsDangerousPermissionsFindingID(jobMetadata.WorkflowFile, grant)
		if err != nil {
			continue
		}
		findings = append(findings, Finding{
			ID:               id,
			RuleID:           RuleGitHubActionsDangerousPermissions,
			Title:            githubActionsDangerousPermissionsTitle,
			Severity:         SeverityHigh,
			NodeIDs:          []graph.NodeID{workflow.ID, job.ID},
			EdgeIDs:          []graph.EdgeID{definesJob.ID},
			Summary:          "GitHub Actions workflow " + workflowDisplay(jobMetadata.WorkflowName, jobMetadata.WorkflowFile) + " job " + jobMetadata.JobID + " grants " + githubActionsPermissionGrantSummary(grant) + " under pull_request_target.",
			Evidence:         cloneFindingEvidence(evidence),
			SourceReferences: sourceReferences(evidence),
		})
	}
	return findings
}

func dangerousWorkflowPermissionRiskSignals(workflow graph.Node) []githubActionsRiskSignal {
	if workflow.Metadata == nil || workflow.Metadata.GitHubActionsWorkflow == nil {
		return nil
	}
	metadata := *workflow.Metadata.GitHubActionsWorkflow
	if !metadata.TriggersPullRequestTarget {
		return nil
	}
	var risks []githubActionsRiskSignal
	for _, grant := range metadata.PermissionGrants {
		if !isDangerousGitHubActionsPermissionGrant(grant) {
			continue
		}
		risks = append(risks, dangerousPermissionRiskSignal(metadata.WorkflowSourceReference, metadata.WorkflowFile, grant))
	}
	return risks
}

func dangerousJobPermissionRiskSignals(definesJob graph.Edge) []githubActionsRiskSignal {
	if definesJob.Metadata == nil || definesJob.Metadata.GitHubActionsWorkflowJob == nil {
		return nil
	}
	metadata := *definesJob.Metadata.GitHubActionsWorkflowJob
	if !metadata.TriggersPullRequestTarget {
		return nil
	}
	var risks []githubActionsRiskSignal
	for _, grant := range metadata.PermissionGrants {
		if !isDangerousGitHubActionsPermissionGrant(grant) {
			continue
		}
		risks = append(risks, dangerousPermissionRiskSignal(metadata.WorkflowSourceReference, metadata.WorkflowFile, grant))
	}
	return risks
}

func dangerousPermissionRiskSignal(sourceRef, workflowFile string, grant graph.GitHubActionsPermissionGrant) githubActionsRiskSignal {
	return githubActionsRiskSignal{
		ruleID:       RuleGitHubActionsDangerousPermissions,
		workflowFile: workflowFile,
		sourceRef:    sourceRef,
		jobID:        grant.JobID,
		scope:        grant.Scope,
		permission:   grant.Permission,
		access:       grant.Access,
		summary:      "dangerous permission grant " + githubActionsPermissionGrantSummary(grant) + " under pull_request_target",
	}
}

func isDangerousGitHubActionsPermissionGrant(grant graph.GitHubActionsPermissionGrant) bool {
	if grant.Permission == "all" && grant.Access == "write-all" {
		return true
	}
	if grant.Access != "write" {
		return false
	}
	switch grant.Permission {
	case "contents", "pull-requests", "actions", "checks", "deployments", "id-token", "security-events":
		return true
	default:
		return false
	}
}

func stableGitHubActionsDangerousPermissionsFindingID(workflowFile string, grant graph.GitHubActionsPermissionGrant) (FindingID, error) {
	data, err := json.Marshal(githubActionsDangerousPermissionsFindingIdentity{
		RuleID:       RuleGitHubActionsDangerousPermissions,
		WorkflowFile: workflowFile,
		Scope:        grant.Scope,
		JobID:        grant.JobID,
		Permission:   grant.Permission,
		Access:       grant.Access,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return FindingID("finding:" + string(RuleGitHubActionsDangerousPermissions) + ":" + hex.EncodeToString(sum[:])), nil
}

func githubActionsPermissionGrantSummary(grant graph.GitHubActionsPermissionGrant) string {
	if grant.Permission == "all" && (grant.Access == "write-all" || grant.Access == "read-all") {
		return "permissions: " + grant.Access
	}
	return grant.Permission + ": " + grant.Access
}

func workflowDisplay(name, file string) string {
	if name == "" || name == file {
		return file
	}
	return name + " (" + file + ")"
}

func newGitHubActionsUnpinnedActionFinding(workflow, job, action graph.Node, definesJob, usesAction graph.Edge) (Finding, bool) {
	if usesAction.Metadata == nil || usesAction.Metadata.GitHubActionUse == nil {
		return Finding{}, false
	}
	actionUse := *usesAction.Metadata.GitHubActionUse
	if actionUse.Owner == "" || actionUse.Repo == "" || isFullCommitSHA(actionUse.Ref) {
		return Finding{}, false
	}

	nodeIDs := []graph.NodeID{workflow.ID, job.ID, action.ID}
	edgeIDs := []graph.EdgeID{definesJob.ID, usesAction.ID}
	id, err := stableGitHubActionsFindingID(actionUse)
	if err != nil {
		return Finding{}, false
	}
	evidence := []FindingEvidence{
		findingEvidence(definesJob),
		findingEvidence(usesAction),
	}
	return Finding{
		ID:               id,
		RuleID:           RuleGitHubActionsUnpinnedAction,
		Title:            githubActionsUnpinnedActionTitle,
		Severity:         SeverityMedium,
		NodeIDs:          append([]graph.NodeID(nil), nodeIDs...),
		EdgeIDs:          append([]graph.EdgeID(nil), edgeIDs...),
		Summary:          "GitHub Actions workflow " + actionUse.WorkflowFile + " job " + actionUse.JobID + " step " + stepIndexString(actionUse.StepIndex) + " uses " + actionUse.Uses + ", which is not pinned to a full commit SHA.",
		Evidence:         cloneFindingEvidence(evidence),
		SourceReferences: sourceReferences(evidence),
	}, true
}

func stableGitHubActionsFindingID(actionUse graph.GitHubActionUse) (FindingID, error) {
	data, err := json.Marshal(githubActionsFindingIdentity{
		RuleID:       RuleGitHubActionsUnpinnedAction,
		WorkflowFile: actionUse.WorkflowFile,
		JobID:        actionUse.JobID,
		StepIndex:    actionUse.StepIndex,
		Owner:        actionUse.Owner,
		Repo:         actionUse.Repo,
		Path:         actionUse.Path,
		Ref:          actionUse.Ref,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return FindingID("finding:" + string(RuleGitHubActionsUnpinnedAction) + ":" + hex.EncodeToString(sum[:])), nil
}

func newGitHubActionsUnsafePullRequestTargetCheckoutFinding(workflow, job, action graph.Node, definesJob, usesAction graph.Edge) (Finding, bool) {
	if usesAction.Metadata == nil || usesAction.Metadata.GitHubActionUse == nil {
		return Finding{}, false
	}
	actionUse := *usesAction.Metadata.GitHubActionUse
	if !actionUse.TriggersPullRequestTarget || actionUse.Owner != "actions" || actionUse.Repo != "checkout" || actionUse.Path != "" || len(actionUse.CheckoutHeadSelectors) == 0 {
		return Finding{}, false
	}

	nodeIDs := []graph.NodeID{workflow.ID, job.ID, action.ID}
	edgeIDs := []graph.EdgeID{definesJob.ID, usesAction.ID}
	id, err := stableGitHubActionsUnsafeCheckoutFindingID(actionUse)
	if err != nil {
		return Finding{}, false
	}
	evidence := []FindingEvidence{
		findingEvidence(definesJob),
		findingEvidence(usesAction),
	}
	return Finding{
		ID:               id,
		RuleID:           RuleGitHubActionsUnsafePullRequestTargetCheckout,
		Title:            githubActionsUnsafePullRequestTargetCheckoutTitle,
		Severity:         SeverityHigh,
		NodeIDs:          append([]graph.NodeID(nil), nodeIDs...),
		EdgeIDs:          append([]graph.EdgeID(nil), edgeIDs...),
		Summary:          "GitHub Actions workflow " + actionUse.WorkflowFile + " job " + actionUse.JobID + " step " + stepIndexString(actionUse.StepIndex) + " uses " + actionUse.Uses + " in pull_request_target with " + githubActionsSelectorSummary(actionUse.CheckoutHeadSelectors) + ".",
		Evidence:         cloneFindingEvidence(evidence),
		SourceReferences: sourceReferences(evidence),
	}, true
}

func unsafeCheckoutRiskSignal(usesAction graph.Edge) (githubActionsRiskSignal, bool) {
	if usesAction.Metadata == nil || usesAction.Metadata.GitHubActionUse == nil {
		return githubActionsRiskSignal{}, false
	}
	actionUse := *usesAction.Metadata.GitHubActionUse
	if !actionUse.TriggersPullRequestTarget || actionUse.Owner != "actions" || actionUse.Repo != "checkout" || actionUse.Path != "" || len(actionUse.CheckoutHeadSelectors) == 0 {
		return githubActionsRiskSignal{}, false
	}
	stepIndex := actionUse.StepIndex
	selectors := githubActionsSelectorIdentities(actionUse.CheckoutHeadSelectors)
	return githubActionsRiskSignal{
		ruleID:       RuleGitHubActionsUnsafePullRequestTargetCheckout,
		workflowFile: actionUse.WorkflowFile,
		sourceRef:    actionUse.WorkflowSourceReference,
		jobID:        actionUse.JobID,
		stepIndex:    &stepIndex,
		selectors:    selectors,
		summary:      "unsafe checkout selector " + githubActionsSelectorSummary(actionUse.CheckoutHeadSelectors) + " under pull_request_target",
	}, true
}

func newCrossDomainGitHubActionsAWSRoleFindings(g *graph.Graph, definesJob []graph.Edge, canRequestOIDCBySource map[graph.NodeID][]graph.Edge, canAssumeRoleByCapability map[graph.NodeID][]graph.Edge, workflowRisks, jobRisks map[graph.NodeID][]githubActionsRiskSignal) []Finding {
	findings := make([]Finding, 0)
	seen := make(map[FindingID]struct{})
	add := func(nodes []graph.Node, edges []graph.Edge, risk githubActionsRiskSignal) {
		if len(nodes) == 0 || len(edges) == 0 {
			return
		}
		role := nodes[len(nodes)-1]
		id, err := stableCrossDomainFindingID(nodeIDs(nodes), edgeIDs(edges), risk, role.ID)
		if err != nil {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		evidence := findingEvidenceForEdges(edges)
		findings = append(findings, Finding{
			ID:               id,
			RuleID:           RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole,
			Title:            crossDomainRiskyGitHubActionsCanAssumeAWSRoleTitle,
			Severity:         SeverityHigh,
			NodeIDs:          nodeIDs(nodes),
			EdgeIDs:          edgeIDs(edges),
			Summary:          crossDomainSummary(nodes, risk),
			Evidence:         evidence,
			SourceReferences: crossDomainSourceReferences(evidence, risk),
			RiskSignal:       riskSignal(risk),
		})
	}

	for _, workflow := range g.Nodes() {
		if workflow.Kind != graph.Workflow {
			continue
		}
		for _, risk := range workflowRisks[workflow.ID] {
			addWorkflowLevelCrossDomainFindings(g, workflow, risk, canRequestOIDCBySource, canAssumeRoleByCapability, add)
		}
	}

	for _, defines := range definesJob {
		workflow, ok := nodeOfKind(g, defines.From, graph.Workflow)
		if !ok {
			continue
		}
		job, ok := nodeOfKind(g, defines.To, graph.WorkflowJob)
		if !ok {
			continue
		}
		for _, risk := range jobRisks[job.ID] {
			if risk.ruleID == RuleGitHubActionsUnsafePullRequestTargetCheckout {
				addWorkflowLevelCrossDomainFindings(g, workflow, risk, canRequestOIDCBySource, canAssumeRoleByCapability, add)
			}
			addJobLevelCrossDomainFindings(g, workflow, job, defines, risk, canRequestOIDCBySource, canAssumeRoleByCapability, add)
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].ID < findings[j].ID
	})
	return findings
}

func addWorkflowLevelCrossDomainFindings(g *graph.Graph, workflow graph.Node, risk githubActionsRiskSignal, canRequestOIDCBySource map[graph.NodeID][]graph.Edge, canAssumeRoleByCapability map[graph.NodeID][]graph.Edge, add func([]graph.Node, []graph.Edge, githubActionsRiskSignal)) {
	for _, oidcRequest := range canRequestOIDCBySource[workflow.ID] {
		capability, ok := nodeOfKind(g, oidcRequest.To, graph.OIDCTokenCapability)
		if !ok {
			continue
		}
		for _, canAssumeRole := range canAssumeRoleByCapability[capability.ID] {
			if !riskMatchesCanAssumeRoleContext(risk, canAssumeRole) {
				continue
			}
			role, ok := nodeOfKind(g, canAssumeRole.To, graph.AWSIAMRole)
			if !ok {
				continue
			}
			add([]graph.Node{workflow, capability, role}, []graph.Edge{oidcRequest, canAssumeRole}, risk)
		}
	}
}

func addJobLevelCrossDomainFindings(g *graph.Graph, workflow, job graph.Node, defines graph.Edge, risk githubActionsRiskSignal, canRequestOIDCBySource map[graph.NodeID][]graph.Edge, canAssumeRoleByCapability map[graph.NodeID][]graph.Edge, add func([]graph.Node, []graph.Edge, githubActionsRiskSignal)) {
	for _, oidcRequest := range canRequestOIDCBySource[job.ID] {
		capability, ok := nodeOfKind(g, oidcRequest.To, graph.OIDCTokenCapability)
		if !ok {
			continue
		}
		for _, canAssumeRole := range canAssumeRoleByCapability[capability.ID] {
			if !riskMatchesCanAssumeRoleContext(risk, canAssumeRole) {
				continue
			}
			role, ok := nodeOfKind(g, canAssumeRole.To, graph.AWSIAMRole)
			if !ok {
				continue
			}
			add([]graph.Node{workflow, job, capability, role}, []graph.Edge{defines, oidcRequest, canAssumeRole}, risk)
		}
	}
}

func riskMatchesCanAssumeRoleContext(risk githubActionsRiskSignal, canAssumeRole graph.Edge) bool {
	if risk.ruleID != RuleGitHubActionsUnsafePullRequestTargetCheckout && risk.ruleID != RuleGitHubActionsDangerousPermissions {
		return false
	}
	if canAssumeRole.Metadata == nil || canAssumeRole.Metadata.AWSCanAssumeRole == nil {
		return false
	}
	return strings.HasSuffix(canAssumeRole.Metadata.AWSCanAssumeRole.SubjectCandidate, ":pull_request")
}

func stableCrossDomainFindingID(nodeIDs []graph.NodeID, edgeIDs []graph.EdgeID, risk githubActionsRiskSignal, roleID graph.NodeID) (FindingID, error) {
	data, err := json.Marshal(crossDomainFindingIdentity{
		RuleID:     RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole,
		NodeIDs:    append([]graph.NodeID(nil), nodeIDs...),
		EdgeIDs:    append([]graph.EdgeID(nil), edgeIDs...),
		RiskRuleID: risk.ruleID,
		RiskSignal: crossDomainRiskSignalIdentity{
			WorkflowFile: risk.workflowFile,
			JobID:        risk.jobID,
			StepIndex:    cloneIntPointer(risk.stepIndex),
			Selectors:    cloneSelectorIdentities(risk.selectors),
			Scope:        risk.scope,
			Permission:   risk.permission,
			Access:       risk.access,
		},
		AWSRoleID: roleID,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return FindingID("finding:" + string(RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole) + ":" + hex.EncodeToString(sum[:])), nil
}

func crossDomainSummary(nodes []graph.Node, risk githubActionsRiskSignal) string {
	workflow := nodes[0]
	role := nodes[len(nodes)-1]
	scope := "workflow-level"
	if len(nodes) == 4 {
		scope = "job-level"
	}
	target := workflow.Name
	if risk.jobID != "" {
		target += " job " + risk.jobID
	}
	return "GitHub Actions " + target + " has " + risk.ruleIDSummary() + "; its " + scope + " OIDC token capability can assume AWS IAM role " + role.Name + "."
}

func (risk githubActionsRiskSignal) ruleIDSummary() string {
	switch risk.ruleID {
	case RuleGitHubActionsUnsafePullRequestTargetCheckout:
		return "unsafe pull_request_target checkout (" + selectorSummaryFromIdentities(risk.selectors) + ")"
	case RuleGitHubActionsDangerousPermissions:
		return "dangerous pull_request_target permission grant (" + githubActionsPermissionGrantSummary(graph.GitHubActionsPermissionGrant{Permission: risk.permission, Access: risk.access}) + ")"
	default:
		return "risky GitHub Actions condition"
	}
}

func selectorSummaryFromIdentities(selectors []githubActionsSelectorIdentity) string {
	out := ""
	for i, selector := range selectors {
		if i > 0 {
			out += ", "
		}
		out += selector.Field + "=" + selector.MatchedExpression
	}
	return out
}

func riskSignal(risk githubActionsRiskSignal) *RiskSignal {
	return &RiskSignal{
		RuleID:          risk.ruleID,
		SourceReference: risk.sourceRef,
		WorkflowFile:    risk.workflowFile,
		JobID:           risk.jobID,
		StepIndex:       cloneIntPointer(risk.stepIndex),
		Selectors:       cloneSelectorIdentities(risk.selectors),
		Permission:      risk.permission,
		Access:          risk.access,
		Summary:         risk.summary,
	}
}

func crossDomainSourceReferences(evidence []FindingEvidence, risk githubActionsRiskSignal) []string {
	refs := sourceReferences(evidence)
	if risk.sourceRef == "" {
		return refs
	}
	for _, ref := range refs {
		if ref == risk.sourceRef {
			return refs
		}
	}
	return append(refs, risk.sourceRef)
}

func findingEvidenceForEdges(edges []graph.Edge) []FindingEvidence {
	evidence := make([]FindingEvidence, 0, len(edges))
	for _, edge := range edges {
		evidence = append(evidence, findingEvidence(edge))
	}
	return evidence
}

func nodeIDs(nodes []graph.Node) []graph.NodeID {
	ids := make([]graph.NodeID, 0, len(nodes))
	for _, node := range nodes {
		ids = append(ids, node.ID)
	}
	return ids
}

func edgeIDs(edges []graph.Edge) []graph.EdgeID {
	ids := make([]graph.EdgeID, 0, len(edges))
	for _, edge := range edges {
		ids = append(ids, edge.ID)
	}
	return ids
}

func cloneIntPointer(value *int) *int {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneSelectorIdentities(selectors []githubActionsSelectorIdentity) []githubActionsSelectorIdentity {
	if selectors == nil {
		return nil
	}
	return append([]githubActionsSelectorIdentity(nil), selectors...)
}

func stableGitHubActionsUnsafeCheckoutFindingID(actionUse graph.GitHubActionUse) (FindingID, error) {
	data, err := json.Marshal(githubActionsUnsafeCheckoutFindingIdentity{
		RuleID:       RuleGitHubActionsUnsafePullRequestTargetCheckout,
		WorkflowFile: actionUse.WorkflowFile,
		JobID:        actionUse.JobID,
		StepIndex:    actionUse.StepIndex,
		Owner:        actionUse.Owner,
		Repo:         actionUse.Repo,
		Path:         actionUse.Path,
		Ref:          actionUse.Ref,
		Selectors:    githubActionsSelectorIdentities(actionUse.CheckoutHeadSelectors),
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return FindingID("finding:" + string(RuleGitHubActionsUnsafePullRequestTargetCheckout) + ":" + hex.EncodeToString(sum[:])), nil
}

func githubActionsSelectorIdentities(selectors []graph.GitHubActionsCheckoutHeadSelector) []githubActionsSelectorIdentity {
	out := make([]githubActionsSelectorIdentity, 0, len(selectors))
	for _, selector := range selectors {
		out = append(out, githubActionsSelectorIdentity{
			Field:             selector.Field,
			MatchedExpression: selector.MatchedExpression,
		})
	}
	return out
}

func githubActionsSelectorSummary(selectors []graph.GitHubActionsCheckoutHeadSelector) string {
	out := ""
	for i, selector := range selectors {
		if i > 0 {
			out += ", "
		}
		out += selector.Field + "=" + selector.MatchedExpression
	}
	return out
}

func isFullCommitSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, r := range value {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			continue
		}
		return false
	}
	return true
}

func stepIndexString(index int) string {
	return strconv.Itoa(index)
}

func nodeOfKind(g *graph.Graph, id graph.NodeID, kind graph.NodeKind) (graph.Node, bool) {
	node, ok := g.Node(id)
	if !ok || node.Kind != kind {
		return graph.Node{}, false
	}
	return node, true
}

func newPublicWorkloadCanReadSecretFinding(endpoint, workload, serviceAccount, secret graph.Node, route, runsAs, canRead graph.Edge) (Finding, error) {
	nodeIDs := []graph.NodeID{endpoint.ID, workload.ID, serviceAccount.ID, secret.ID}
	edgeIDs := []graph.EdgeID{route.ID, runsAs.ID, canRead.ID}
	id, err := stableFindingID(RulePublicWorkloadCanReadSecret, nodeIDs, edgeIDs)
	if err != nil {
		return Finding{}, err
	}

	evidence := []FindingEvidence{
		findingEvidence(route),
		findingEvidence(runsAs),
		findingEvidence(canRead),
	}
	return Finding{
		ID:               id,
		RuleID:           RulePublicWorkloadCanReadSecret,
		Title:            publicWorkloadCanReadSecretTitle,
		Severity:         SeverityHigh,
		NodeIDs:          append([]graph.NodeID(nil), nodeIDs...),
		EdgeIDs:          append([]graph.EdgeID(nil), edgeIDs...),
		Summary:          "Public endpoint " + endpoint.Name + " routes to workload " + workload.Name + ", which runs as service account " + serviceAccount.Name + " that can read Secret " + secret.Name + ".",
		Evidence:         cloneFindingEvidence(evidence),
		SourceReferences: sourceReferences(evidence),
	}, nil
}

func stableFindingID(ruleID RuleID, nodeIDs []graph.NodeID, edgeIDs []graph.EdgeID) (FindingID, error) {
	data, err := json.Marshal(findingIdentity{
		RuleID:  ruleID,
		NodeIDs: append([]graph.NodeID(nil), nodeIDs...),
		EdgeIDs: append([]graph.EdgeID(nil), edgeIDs...),
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return FindingID("finding:" + string(ruleID) + ":" + hex.EncodeToString(sum[:])), nil
}

func findingEvidence(edge graph.Edge) FindingEvidence {
	return FindingEvidence{
		EdgeID: edge.ID,
		Kind:   edge.Kind,
		Source: edge.Evidence,
	}
}

func cloneFindingEvidence(evidence []FindingEvidence) []FindingEvidence {
	if evidence == nil {
		return nil
	}
	return append([]FindingEvidence(nil), evidence...)
}

func sourceReferences(evidence []FindingEvidence) []string {
	refs := make([]string, 0, len(evidence))
	seen := make(map[string]struct{})
	for _, item := range evidence {
		ref := item.Source.Source
		if ref == "" {
			continue
		}
		if _, exists := seen[ref]; exists {
			continue
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}
	return refs
}

func sourceReferencesFromValues(values ...string) []string {
	refs := make([]string, 0, len(values))
	seen := make(map[string]struct{})
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		refs = append(refs, value)
	}
	return refs
}
