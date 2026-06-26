package terraform

import (
	"fmt"
	"sort"
	"strings"

	"pathproof/internal/graph"
	parsergithubactions "pathproof/internal/parser/githubactions"
	parserterraform "pathproof/internal/parser/terraform"
)

const (
	providerAWS         = "aws"
	githubActionsIssuer = "token.actions.githubusercontent.com"
	awsAudience         = "sts.amazonaws.com"
)

func AddRoutes(g *graph.Graph, resources parserterraform.Resources, workflows parsergithubactions.Resources, repo string) error {
	for _, role := range resources.IAMRoles {
		roleNode := graph.NewNode(graph.AWSIAMRole, roleNodeName(role))
		roleNode.Evidence = []graph.SourceEvidence{{
			Source: sourceRef(role.Source),
			Detail: "terraform aws_iam_role " + role.ResourceName + " with static trust policy metadata",
		}}
		metadata := roleMetadata(role)
		roleNode.Metadata = &graph.NodeMetadata{AWSIAMRole: &metadata}
		if _, err := g.AddNode(roleNode); err != nil {
			return fmt.Errorf("add aws iam role %s: %w", role.ResourceName, err)
		}
	}
	if repo == "" {
		return nil
	}

	candidates := oidcSubjectCandidates(g, workflows, repo)
	if len(candidates) == 0 {
		return nil
	}
	for _, role := range resources.IAMRoles {
		if len(role.Trusts) == 0 {
			continue
		}
		roleNode := graph.NewNode(graph.AWSIAMRole, roleNodeName(role))
		for _, candidate := range candidates {
			match, ok := matchingTrust(role.Trusts, candidate.subject)
			if !ok {
				continue
			}
			edge := graph.NewEdge(graph.CanAssumeRole, candidate.capability.ID, roleNode.ID, graph.SourceEvidence{
				Source: sourceRef(role.Source),
				Detail: fmt.Sprintf("github actions oidc subject %s matches aws iam role %s trust statement %d", candidate.subject, role.ResourceName, match.statementIndex),
			})
			edge.Metadata = &graph.EdgeMetadata{AWSCanAssumeRole: &graph.AWSCanAssumeRoleMetadata{
				Provider:                      providerAWS,
				RoleResourceName:              role.ResourceName,
				RoleSourceReference:           sourceRef(role.Source),
				TrustedIssuer:                 githubActionsIssuer,
				StatementIndex:                match.statementIndex,
				Audience:                      awsAudience,
				SubjectCandidate:              candidate.subject,
				SubjectPattern:                match.pattern.Pattern,
				SubjectOperator:               match.pattern.Operator,
				OIDCCapabilitySourceReference: candidate.metadata.WorkflowSourceReference,
				WorkflowFile:                  candidate.metadata.WorkflowFile,
				Scope:                         candidate.metadata.Scope,
				JobID:                         candidate.metadata.JobID,
			}}
			if _, err := g.AddEdge(edge); err != nil {
				return fmt.Errorf("add can assume role edge %s: %w", role.ResourceName, err)
			}
		}
	}
	return nil
}

type subjectCandidate struct {
	capability graph.Node
	metadata   graph.GitHubActionsOIDCTokenCapability
	subject    string
}

type trustMatch struct {
	statementIndex int
	pattern        graph.AWSOIDCSubjectPattern
}

func oidcSubjectCandidates(g *graph.Graph, workflows parsergithubactions.Resources, repo string) []subjectCandidate {
	workflowsByFile := make(map[string]parsergithubactions.Workflow, len(workflows.Workflows))
	for _, workflow := range workflows.Workflows {
		workflowsByFile[workflow.Source.RelativePath] = workflow
	}
	var candidates []subjectCandidate
	seen := make(map[string]struct{})
	for _, node := range g.Nodes() {
		if node.Kind != graph.OIDCTokenCapability || node.Metadata == nil || node.Metadata.GitHubActionsOIDCTokenCapability == nil {
			continue
		}
		metadata := *node.Metadata.GitHubActionsOIDCTokenCapability
		workflow, ok := workflowsByFile[metadata.WorkflowFile]
		if !ok {
			continue
		}
		for _, subject := range workflowSubjectCandidates(workflow, metadata, repo) {
			key := string(node.ID) + "\x00" + subject
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			candidates = append(candidates, subjectCandidate{
				capability: node,
				metadata:   metadata,
				subject:    subject,
			})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].capability.ID != candidates[j].capability.ID {
			return candidates[i].capability.ID < candidates[j].capability.ID
		}
		return candidates[i].subject < candidates[j].subject
	})
	return candidates
}

func workflowSubjectCandidates(workflow parsergithubactions.Workflow, capability graph.GitHubActionsOIDCTokenCapability, repo string) []string {
	var subjects []string
	for _, branch := range workflow.PushBranches {
		subjects = append(subjects, "repo:"+repo+":ref:refs/heads/"+branch)
	}
	if workflow.TriggersPullRequest || workflow.TriggersPullRequestTarget {
		subjects = append(subjects, "repo:"+repo+":pull_request")
	}
	switch capability.Scope {
	case "job":
		if env := jobEnvironment(workflow, capability.JobID); env != "" {
			subjects = append(subjects, "repo:"+repo+":environment:"+env)
		}
	case "workflow":
		for _, job := range workflow.Jobs {
			if job.Environment != "" {
				subjects = append(subjects, "repo:"+repo+":environment:"+job.Environment)
			}
		}
	}
	return uniqueStrings(subjects)
}

func jobEnvironment(workflow parsergithubactions.Workflow, jobID string) string {
	for _, job := range workflow.Jobs {
		if job.ID == jobID {
			return job.Environment
		}
	}
	return ""
}

func matchingTrust(trusts []parserterraform.OIDCTrust, subject string) (trustMatch, bool) {
	for _, trust := range trusts {
		if trust.Issuer != githubActionsIssuer || !stringListContains(trust.Audiences, awsAudience) {
			continue
		}
		patterns := trustPatterns(trust.SubjectPatterns)
		for _, pattern := range patterns {
			if subjectPatternMatches(pattern, subject) {
				return trustMatch{statementIndex: trust.StatementIndex, pattern: pattern}, true
			}
		}
	}
	return trustMatch{}, false
}

func trustPatterns(patterns []parserterraform.SubjectPattern) []graph.AWSOIDCSubjectPattern {
	out := make([]graph.AWSOIDCSubjectPattern, 0, len(patterns))
	for _, pattern := range patterns {
		out = append(out, graph.AWSOIDCSubjectPattern{
			Operator: pattern.Operator,
			Pattern:  pattern.Pattern,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Operator != out[j].Operator {
			return out[i].Operator < out[j].Operator
		}
		return out[i].Pattern < out[j].Pattern
	})
	return out
}

func subjectPatternMatches(pattern graph.AWSOIDCSubjectPattern, subject string) bool {
	switch pattern.Operator {
	case "StringEquals":
		return pattern.Pattern == subject
	case "StringLike":
		return simpleGlobMatch(pattern.Pattern, subject)
	default:
		return false
	}
}

func simpleGlobMatch(pattern, value string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == value
	}
	if !strings.HasPrefix(value, parts[0]) {
		return false
	}
	offset := len(parts[0])
	for _, part := range parts[1 : len(parts)-1] {
		if part == "" {
			continue
		}
		index := strings.Index(value[offset:], part)
		if index < 0 {
			return false
		}
		offset += index + len(part)
	}
	last := parts[len(parts)-1]
	if last == "" {
		return true
	}
	return strings.HasSuffix(value[offset:], last)
}

func roleMetadata(role parserterraform.IAMRole) graph.AWSIAMRoleMetadata {
	return graph.AWSIAMRoleMetadata{
		Provider:        providerAWS,
		ResourceName:    role.ResourceName,
		SourceReference: sourceRef(role.Source),
		TrustedIssuer:   trustedIssuer(role.Trusts),
		TrustStatements: trustStatements(role.Trusts),
	}
}

func trustStatements(trusts []parserterraform.OIDCTrust) []graph.AWSOIDCTrustStatement {
	if len(trusts) == 0 {
		return nil
	}
	out := make([]graph.AWSOIDCTrustStatement, 0, len(trusts))
	for _, trust := range trusts {
		out = append(out, graph.AWSOIDCTrustStatement{
			StatementIndex:  trust.StatementIndex,
			SubjectPatterns: trustPatterns(trust.SubjectPatterns),
			Audiences:       append([]string(nil), trust.Audiences...),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].StatementIndex < out[j].StatementIndex
	})
	return out
}

func trustedIssuer(trusts []parserterraform.OIDCTrust) string {
	for _, trust := range trusts {
		if trust.Issuer == githubActionsIssuer {
			return githubActionsIssuer
		}
	}
	return ""
}

func stringListContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func roleNodeName(role parserterraform.IAMRole) string {
	return "aws://terraform/aws_iam_role/" + role.Source.RelativePath + "/" + role.ResourceName
}

func sourceRef(source parserterraform.Source) string {
	return fmt.Sprintf("%s#resource=%s.%s", source.Filename, source.ResourceType, source.ResourceName)
}
