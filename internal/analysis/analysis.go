package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"

	"pathproof/internal/graph"
)

type FindingID string
type RuleID string
type Severity string

const (
	RulePublicWorkloadCanReadSecret                  RuleID   = "PP-K8S-001"
	RuleGitHubActionsUnpinnedAction                  RuleID   = "PP-GHA-001"
	RuleGitHubActionsUnsafePullRequestTargetCheckout RuleID   = "PP-GHA-002"
	SeverityHigh                                     Severity = "High"
	SeverityMedium                                   Severity = "Medium"
)

const publicWorkloadCanReadSecretTitle = "Public workload can read Kubernetes Secret"
const githubActionsUnpinnedActionTitle = "GitHub Actions workflow uses an action that is not pinned to a full commit SHA"
const githubActionsUnsafePullRequestTargetCheckoutTitle = "pull_request_target workflow checks out untrusted pull request head code"

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
}

type FindingEvidence struct {
	EdgeID graph.EdgeID         `json:"edge_id"`
	Kind   graph.EdgeKind       `json:"kind"`
	Source graph.SourceEvidence `json:"source"`
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

type githubActionsSelectorIdentity struct {
	Field             string `json:"field"`
	MatchedExpression string `json:"matched_expression"`
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
		}
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
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].ID < findings[j].ID
	})
	return findings
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
