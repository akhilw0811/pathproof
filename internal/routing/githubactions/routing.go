package githubactions

import (
	"fmt"
	"strings"

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
				actionUse := actionUseMetadata(workflow, job, step)
				actionNode := graph.NewNode(graph.GitHubAction, githubActionNodeName(workflow, job, step))
				actionNode.Evidence = []graph.SourceEvidence{sourceEvidence(workflow.Source, "github actions workflow step uses "+step.Uses)}
				addedAction, err := g.AddNode(actionNode)
				if err != nil {
					return fmt.Errorf("add github action use %s job %s step %d: %w", workflow.Source.RelativePath, job.ID, step.Index, err)
				}
				usesAction := graph.NewEdge(graph.UsesAction, addedJob.ID, addedAction.ID, graph.SourceEvidence{
					Source: sourceRef(workflow.Source),
					Detail: fmt.Sprintf("github actions job %s step %d uses %s", job.ID, step.Index, step.Uses),
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

func actionUseMetadata(workflow parsergithubactions.Workflow, job parsergithubactions.Job, step parsergithubactions.Step) graph.GitHubActionUse {
	ref := parseActionReference(step.Uses)
	return graph.GitHubActionUse{
		WorkflowSourceReference: sourceRef(workflow.Source),
		WorkflowFile:            workflow.Source.RelativePath,
		WorkflowName:            workflowDisplayName(workflow),
		JobID:                   job.ID,
		StepIndex:               step.Index,
		StepName:                step.Name,
		Uses:                    step.Uses,
		Owner:                   ref.owner,
		Repo:                    ref.repo,
		Path:                    ref.path,
		Ref:                     ref.ref,
	}
}

type actionReference struct {
	owner string
	repo  string
	path  string
	ref   string
}

func parseActionReference(uses string) actionReference {
	value := strings.TrimSpace(uses)
	if value == "" || strings.HasPrefix(value, "./") || strings.HasPrefix(value, "docker://") {
		return actionReference{}
	}
	if isEntireExpression(value) {
		return actionReference{}
	}

	target, ref, _ := strings.Cut(value, "@")
	if strings.Contains(target, "${{") || strings.Contains(target, "}}") {
		return actionReference{}
	}
	parts := strings.Split(target, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return actionReference{}
	}
	if strings.ContainsAny(parts[0], " \t\r\n:") || strings.ContainsAny(parts[1], " \t\r\n:") {
		return actionReference{}
	}
	path := ""
	if len(parts) > 2 {
		path = strings.Join(parts[2:], "/")
	}
	return actionReference{
		owner: parts[0],
		repo:  parts[1],
		path:  path,
		ref:   ref,
	}
}

func isEntireExpression(value string) bool {
	return strings.HasPrefix(value, "${{") && strings.HasSuffix(value, "}}")
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
