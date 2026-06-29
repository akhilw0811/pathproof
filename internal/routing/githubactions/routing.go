package githubactions

import (
	"fmt"

	"pathproof/internal/graph"
	parsergithubactions "pathproof/internal/parser/githubactions"
)

func AddRoutes(g *graph.Graph, resources parsergithubactions.Resources) error {
	for _, workflow := range resources.Workflows {
		workflowNode := graph.NewNode(graph.Workflow, workflowName(workflow))
		workflowNode.Evidence = []graph.SourceEvidence{sourceEvidence(workflow.Source, workflowEvidenceDetail(workflow))}
		workflowMetadata := buildWorkflowMetadata(workflow)
		workflowNode.Metadata = &graph.NodeMetadata{GitHubActionsWorkflow: &workflowMetadata}
		addedWorkflow, err := g.AddNode(workflowNode)
		if err != nil {
			return fmt.Errorf("add workflow %s: %w", workflow.Source.RelativePath, err)
		}
		if err := addWorkflowOIDCTokenCapability(g, workflow, addedWorkflow); err != nil {
			return err
		}

		for _, job := range workflow.Jobs {
			jobNode := graph.NewNode(graph.WorkflowJob, workflowJobName(workflow, job))
			jobNode.Evidence = []graph.SourceEvidence{sourceEvidence(workflow.Source, "github actions workflow job "+job.ID)}
			addedJob, err := g.AddNode(jobNode)
			if err != nil {
				return fmt.Errorf("add workflow job %s %s: %w", workflow.Source.RelativePath, job.ID, err)
			}
			definesJob := graph.NewEdge(graph.DefinesJob, addedWorkflow.ID, addedJob.ID, graph.SourceEvidence{
				Source: sourceRef(workflow.Source),
				Detail: definesJobEvidenceDetail(job),
			})
			jobMetadata := buildWorkflowJobMetadata(workflow, job)
			definesJob.Metadata = &graph.EdgeMetadata{GitHubActionsWorkflowJob: &jobMetadata}
			if _, err := g.AddEdge(definesJob); err != nil {
				return fmt.Errorf("add workflow job edge %s %s: %w", workflow.Source.RelativePath, job.ID, err)
			}
			if err := addJobOIDCTokenCapability(g, workflow, job, addedJob); err != nil {
				return err
			}

			for _, step := range job.Steps {
				actionUse, ok := actionUseMetadata(workflow, job, step)
				if !ok {
					continue
				}
				actionNode := graph.NewNode(graph.GitHubAction, githubActionNodeName(workflow, job, step))
				actionNode.Evidence = []graph.SourceEvidence{sourceEvidence(workflow.Source, "github actions workflow step uses "+step.Uses)}
				addedAction, err := g.AddNode(actionNode)
				if err != nil {
					return fmt.Errorf("add github action use %s job %s step %d: %w", workflow.Source.RelativePath, job.ID, step.Index, err)
				}
				usesAction := graph.NewEdge(graph.UsesAction, addedJob.ID, addedAction.ID, graph.SourceEvidence{
					Source: sourceRef(workflow.Source),
					Detail: actionUseEvidenceDetail(actionUse),
				})
				usesAction.Metadata = &graph.EdgeMetadata{GitHubActionUse: &actionUse}
				if _, err := g.AddEdge(usesAction); err != nil {
					return fmt.Errorf("add github action use edge %s job %s step %d: %w", workflow.Source.RelativePath, job.ID, step.Index, err)
				}
			}
		}
	}
	return nil
}

func addWorkflowOIDCTokenCapability(g *graph.Graph, workflow parsergithubactions.Workflow, workflowNode graph.Node) error {
	grant, ok := oidcCapabilityGrant(workflow.PermissionGrants)
	if !ok {
		return nil
	}
	detail := workflowOIDCTokenCapabilityEvidenceDetail(grant)
	capability := oidcTokenCapabilityMetadata(workflow, "workflow", "")
	capabilityNode := graph.NewNode(graph.OIDCTokenCapability, workflowOIDCTokenCapabilityName(workflow))
	capabilityNode.Evidence = []graph.SourceEvidence{sourceEvidence(workflow.Source, detail)}
	capabilityNode.Metadata = &graph.NodeMetadata{GitHubActionsOIDCTokenCapability: &capability}
	addedCapability, err := g.AddNode(capabilityNode)
	if err != nil {
		return fmt.Errorf("add workflow oidc token capability %s: %w", workflow.Source.RelativePath, err)
	}

	request := oidcTokenRequestMetadata(workflow, "workflow", "")
	edge := graph.NewEdge(graph.CanRequestOIDCToken, workflowNode.ID, addedCapability.ID, graph.SourceEvidence{
		Source: sourceRef(workflow.Source),
		Detail: detail,
	})
	edge.Metadata = &graph.EdgeMetadata{GitHubActionsOIDCTokenRequest: &request}
	if _, err := g.AddEdge(edge); err != nil {
		return fmt.Errorf("add workflow oidc token capability edge %s: %w", workflow.Source.RelativePath, err)
	}
	return nil
}

func addJobOIDCTokenCapability(g *graph.Graph, workflow parsergithubactions.Workflow, job parsergithubactions.Job, jobNode graph.Node) error {
	grant, ok := oidcCapabilityGrant(job.PermissionGrants)
	if !ok {
		return nil
	}
	detail := jobOIDCTokenCapabilityEvidenceDetail(job, grant)
	capability := oidcTokenCapabilityMetadata(workflow, "job", job.ID)
	capabilityNode := graph.NewNode(graph.OIDCTokenCapability, jobOIDCTokenCapabilityName(workflow, job))
	capabilityNode.Evidence = []graph.SourceEvidence{sourceEvidence(workflow.Source, detail)}
	capabilityNode.Metadata = &graph.NodeMetadata{GitHubActionsOIDCTokenCapability: &capability}
	addedCapability, err := g.AddNode(capabilityNode)
	if err != nil {
		return fmt.Errorf("add job oidc token capability %s %s: %w", workflow.Source.RelativePath, job.ID, err)
	}

	request := oidcTokenRequestMetadata(workflow, "job", job.ID)
	edge := graph.NewEdge(graph.CanRequestOIDCToken, jobNode.ID, addedCapability.ID, graph.SourceEvidence{
		Source: sourceRef(workflow.Source),
		Detail: detail,
	})
	edge.Metadata = &graph.EdgeMetadata{GitHubActionsOIDCTokenRequest: &request}
	if _, err := g.AddEdge(edge); err != nil {
		return fmt.Errorf("add job oidc token capability edge %s %s: %w", workflow.Source.RelativePath, job.ID, err)
	}
	return nil
}

func buildWorkflowMetadata(workflow parsergithubactions.Workflow) graph.GitHubActionsWorkflow {
	return graph.GitHubActionsWorkflow{
		WorkflowSourceReference:   sourceRef(workflow.Source),
		WorkflowFile:              workflow.Source.RelativePath,
		WorkflowName:              workflowDisplayName(workflow),
		TriggersPullRequestTarget: workflow.TriggersPullRequestTarget,
		PermissionGrants:          permissionGrants(workflow.PermissionGrants),
	}
}

func buildWorkflowJobMetadata(workflow parsergithubactions.Workflow, job parsergithubactions.Job) graph.GitHubActionsWorkflowJob {
	return graph.GitHubActionsWorkflowJob{
		WorkflowSourceReference:   sourceRef(workflow.Source),
		WorkflowFile:              workflow.Source.RelativePath,
		WorkflowName:              workflowDisplayName(workflow),
		TriggersPullRequestTarget: workflow.TriggersPullRequestTarget,
		JobID:                     job.ID,
		PermissionGrants:          permissionGrants(job.PermissionGrants),
	}
}

func oidcTokenCapabilityMetadata(workflow parsergithubactions.Workflow, scope, jobID string) graph.GitHubActionsOIDCTokenCapability {
	return graph.GitHubActionsOIDCTokenCapability{
		Provider:                "github-actions",
		WorkflowSourceReference: sourceRef(workflow.Source),
		WorkflowFile:            workflow.Source.RelativePath,
		WorkflowName:            workflowDisplayName(workflow),
		Scope:                   scope,
		JobID:                   jobID,
	}
}

func oidcTokenRequestMetadata(workflow parsergithubactions.Workflow, scope, jobID string) graph.GitHubActionsOIDCTokenRequest {
	return graph.GitHubActionsOIDCTokenRequest{
		Provider:                "github-actions",
		WorkflowSourceReference: sourceRef(workflow.Source),
		WorkflowFile:            workflow.Source.RelativePath,
		WorkflowName:            workflowDisplayName(workflow),
		Scope:                   scope,
		JobID:                   jobID,
		Permission:              "id-token",
		Access:                  "write",
	}
}

func actionUseMetadata(workflow parsergithubactions.Workflow, job parsergithubactions.Job, step parsergithubactions.Step) (graph.GitHubActionUse, bool) {
	if step.Owner == "" || step.Repo == "" || step.Uses == "" {
		return graph.GitHubActionUse{}, false
	}
	return graph.GitHubActionUse{
		WorkflowSourceReference:   sourceRef(workflow.Source),
		WorkflowFile:              workflow.Source.RelativePath,
		WorkflowName:              workflowDisplayName(workflow),
		TriggersPullRequestTarget: workflow.TriggersPullRequestTarget,
		JobID:                     job.ID,
		StepIndex:                 step.Index,
		StepName:                  step.Name,
		Uses:                      step.Uses,
		UsesLine:                  step.UsesLine,
		UsesColumn:                step.UsesColumn,
		Owner:                     step.Owner,
		Repo:                      step.Repo,
		Path:                      step.Path,
		Ref:                       step.Ref,
		CheckoutHeadSelectors:     checkoutHeadSelectors(step.CheckoutHeadSelectors),
		PatchUnsupportedReason:    firstNonEmpty(step.PatchUnsupportedReason, workflow.PatchUnsupportedReason),
	}, true
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func permissionGrants(grants []parsergithubactions.PermissionGrant) []graph.GitHubActionsPermissionGrant {
	if len(grants) == 0 {
		return nil
	}
	out := make([]graph.GitHubActionsPermissionGrant, 0, len(grants))
	for _, grant := range grants {
		out = append(out, graph.GitHubActionsPermissionGrant{
			Scope:      grant.Scope,
			JobID:      grant.JobID,
			Permission: grant.Permission,
			Access:     grant.Access,
		})
	}
	return out
}

func oidcCapabilityGrant(grants []parsergithubactions.PermissionGrant) (parsergithubactions.PermissionGrant, bool) {
	for _, grant := range grants {
		if grant.Permission == "id-token" && grant.Access == "write" {
			return grant, true
		}
	}
	for _, grant := range grants {
		if grant.Permission == "all" && grant.Access == "write-all" {
			return grant, true
		}
	}
	return parsergithubactions.PermissionGrant{}, false
}

func checkoutHeadSelectors(selectors []parsergithubactions.CheckoutHeadSelector) []graph.GitHubActionsCheckoutHeadSelector {
	if len(selectors) == 0 {
		return nil
	}
	out := make([]graph.GitHubActionsCheckoutHeadSelector, 0, len(selectors))
	for _, selector := range selectors {
		out = append(out, graph.GitHubActionsCheckoutHeadSelector{
			Field:             selector.Field,
			MatchedExpression: selector.MatchedExpression,
		})
	}
	return out
}

func definesJobEvidenceDetail(job parsergithubactions.Job) string {
	return "github actions workflow defines job " + job.ID
}

func workflowEvidenceDetail(workflow parsergithubactions.Workflow) string {
	detail := "github actions workflow"
	if len(workflow.PermissionGrants) == 0 {
		return detail
	}
	return detail + " with " + permissionGrantListEvidence(permissionGrants(workflow.PermissionGrants))
}

func actionUseEvidenceDetail(actionUse graph.GitHubActionUse) string {
	detail := fmt.Sprintf("github actions job %s step %d uses %s", actionUse.JobID, actionUse.StepIndex, actionUse.Uses)
	if !actionUse.TriggersPullRequestTarget || len(actionUse.CheckoutHeadSelectors) == 0 {
		return detail
	}
	return detail + " in pull_request_target with " + selectorEvidence(actionUse.CheckoutHeadSelectors)
}

func workflowOIDCTokenCapabilityEvidenceDetail(grant parsergithubactions.PermissionGrant) string {
	if grant.Permission == "all" && grant.Access == "write-all" {
		return "github actions workflow can request OIDC token because permissions: write-all includes id-token: write"
	}
	return "github actions workflow can request OIDC token with id-token: write"
}

func jobOIDCTokenCapabilityEvidenceDetail(job parsergithubactions.Job, grant parsergithubactions.PermissionGrant) string {
	if grant.Permission == "all" && grant.Access == "write-all" {
		return "github actions job " + job.ID + " can request OIDC token because permissions: write-all includes id-token: write"
	}
	return "github actions job " + job.ID + " can request OIDC token with id-token: write"
}

func permissionGrantListEvidence(grants []graph.GitHubActionsPermissionGrant) string {
	out := ""
	for i, grant := range grants {
		if i > 0 {
			out += ", "
		}
		out += permissionGrantEvidence(grant)
	}
	return out
}

func permissionGrantEvidence(grant graph.GitHubActionsPermissionGrant) string {
	if grant.Permission == "all" && (grant.Access == "write-all" || grant.Access == "read-all") {
		return "permissions: " + grant.Access
	}
	return grant.Permission + ": " + grant.Access
}

func selectorEvidence(selectors []graph.GitHubActionsCheckoutHeadSelector) string {
	out := ""
	for i, selector := range selectors {
		if i > 0 {
			out += ", "
		}
		out += selector.Field + "=" + selector.MatchedExpression
	}
	return out
}

func workflowName(workflow parsergithubactions.Workflow) string {
	return "githubactions://" + workflow.Source.RelativePath
}

func workflowJobName(workflow parsergithubactions.Workflow, job parsergithubactions.Job) string {
	return workflowName(workflow) + "/job/" + job.ID
}

func workflowOIDCTokenCapabilityName(workflow parsergithubactions.Workflow) string {
	return workflowName(workflow) + "/oidc-token/workflow"
}

func jobOIDCTokenCapabilityName(workflow parsergithubactions.Workflow, job parsergithubactions.Job) string {
	return workflowJobName(workflow, job) + "/oidc-token"
}

func githubActionNodeName(workflow parsergithubactions.Workflow, job parsergithubactions.Job, step parsergithubactions.Step) string {
	return workflowJobName(workflow, job) + fmt.Sprintf("/step/%d/action/%s", step.Index, step.Uses)
}

func workflowDisplayName(workflow parsergithubactions.Workflow) string {
	if workflow.Name != "" {
		return workflow.Name
	}
	return workflow.Source.RelativePath
}

func sourceEvidence(source parsergithubactions.Source, detail string) graph.SourceEvidence {
	return graph.SourceEvidence{
		Source: sourceRef(source),
		Detail: detail,
	}
}

func sourceRef(source parsergithubactions.Source) string {
	return fmt.Sprintf("%s#document=%d", source.Filename, source.Document)
}
