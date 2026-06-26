package githubactions

import (
	"fmt"

	"pathproof/internal/graph"
	parsergithubactions "pathproof/internal/parser/githubactions"
)

func AddRoutes(g *graph.Graph, resources parsergithubactions.Resources) error {
	for _, workflow := range resources.Workflows {
		workflowNode := graph.NewNode(graph.Workflow, workflowName(workflow))
		workflowNode.Evidence = []graph.SourceEvidence{sourceEvidence(workflow.Source, "github actions workflow")}
		addedWorkflow, err := g.AddNode(workflowNode)
		if err != nil {
			return fmt.Errorf("add workflow %s: %w", workflow.Source.RelativePath, err)
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
				Detail: "github actions workflow defines job " + job.ID,
			})
			if _, err := g.AddEdge(definesJob); err != nil {
				return fmt.Errorf("add workflow job edge %s %s: %w", workflow.Source.RelativePath, job.ID, err)
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
		Owner:                     step.Owner,
		Repo:                      step.Repo,
		Path:                      step.Path,
		Ref:                       step.Ref,
		CheckoutHeadSelectors:     checkoutHeadSelectors(step.CheckoutHeadSelectors),
	}, true
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

func actionUseEvidenceDetail(actionUse graph.GitHubActionUse) string {
	detail := fmt.Sprintf("github actions job %s step %d uses %s", actionUse.JobID, actionUse.StepIndex, actionUse.Uses)
	if !actionUse.TriggersPullRequestTarget || len(actionUse.CheckoutHeadSelectors) == 0 {
		return detail
	}
	return detail + " in pull_request_target with " + selectorEvidence(actionUse.CheckoutHeadSelectors)
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
