package terraform

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"pathproof/internal/graph"
	parsergithubactions "pathproof/internal/parser/githubactions"
	parserterraform "pathproof/internal/parser/terraform"
)

const (
	providerAWS          = "aws"
	githubActionsIssuer  = "token.actions.githubusercontent.com"
	awsAudience          = "sts.amazonaws.com"
	accessModeRead       = "read"
	accessModeWrite      = "write"
	sensitivityUnknown   = "unknown"
	sensitivitySensitive = "sensitive"
)

func AddRoutes(g *graph.Graph, resources parserterraform.Resources, workflows parsergithubactions.Resources, repo string) error {
	bucketsByName := make(map[string][]graph.Node)
	for _, bucket := range resources.S3Buckets {
		bucketNode := graph.NewNode(graph.AWSS3Bucket, bucketNodeName(bucket))
		bucketNode.Evidence = []graph.SourceEvidence{{
			Source: sourceRef(bucket.Source),
			Detail: "terraform aws_s3_bucket " + bucket.ResourceName + " with static bucket name",
		}}
		metadata := bucketMetadata(bucket)
		bucketNode.Metadata = &graph.NodeMetadata{AWSS3Bucket: &metadata}
		addedBucket, err := g.AddNode(bucketNode)
		if err != nil {
			return fmt.Errorf("add aws s3 bucket %s: %w", bucket.ResourceName, err)
		}
		bucketsByName[bucket.BucketName] = append(bucketsByName[bucket.BucketName], addedBucket)
	}
	for bucketName := range bucketsByName {
		sort.SliceStable(bucketsByName[bucketName], func(i, j int) bool {
			return bucketsByName[bucketName][i].ID < bucketsByName[bucketName][j].ID
		})
	}

	for _, role := range resources.IAMRoles {
		roleNode := graph.NewNode(graph.AWSIAMRole, roleNodeName(role))
		roleNode.Evidence = []graph.SourceEvidence{{
			Source: sourceRef(role.Source),
			Detail: "terraform aws_iam_role " + role.ResourceName + " with static Terraform metadata",
		}}
		metadata := roleMetadata(role)
		roleNode.Metadata = &graph.NodeMetadata{AWSIAMRole: &metadata}
		addedRole, err := g.AddNode(roleNode)
		if err != nil {
			return fmt.Errorf("add aws iam role %s: %w", role.ResourceName, err)
		}
		if err := addRolePermissions(g, addedRole, role); err != nil {
			return err
		}
		if err := addRoleS3Access(g, addedRole, role, bucketsByName); err != nil {
			return err
		}
	}
	if repo == "" {
		return nil
	}

	candidates := oidcSubjectCandidates(g, workflows, repo)
	if len(candidates) == 0 {
		return nil
	}
	assumptions := make(map[string]*canAssumeRoleAggregate)
	for _, role := range resources.IAMRoles {
		if len(role.Trusts) == 0 {
			continue
		}
		roleNode := graph.NewNode(graph.AWSIAMRole, roleNodeName(role))
		for _, candidate := range candidates {
			matches := matchingTrusts(role.Trusts, candidate.subject)
			if len(matches) == 0 {
				continue
			}
			key := string(candidate.capability.ID) + "\x00" + string(roleNode.ID)
			aggregate := assumptions[key]
			if aggregate == nil {
				aggregate = &canAssumeRoleAggregate{
					edge: graph.NewEdge(graph.CanAssumeRole, candidate.capability.ID, roleNode.ID, graph.SourceEvidence{
						Source: sourceRef(role.Source),
					}),
					metadata: graph.AWSCanAssumeRoleMetadata{
						Provider:                      providerAWS,
						RoleResourceName:              role.ResourceName,
						RoleSourceReference:           sourceRef(role.Source),
						TrustedIssuer:                 githubActionsIssuer,
						Audience:                      awsAudience,
						OIDCCapabilitySourceReference: candidate.metadata.WorkflowSourceReference,
						WorkflowFile:                  candidate.metadata.WorkflowFile,
						Scope:                         candidate.metadata.Scope,
						JobID:                         candidate.metadata.JobID,
					},
					seen: make(map[string]struct{}),
				}
				assumptions[key] = aggregate
			}
			for _, match := range matches {
				aggregate.add(matchMetadata(role, candidate, match))
			}
		}
	}
	ordered := make([]*canAssumeRoleAggregate, 0, len(assumptions))
	for _, aggregate := range assumptions {
		ordered = append(ordered, aggregate)
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].edge.ID < ordered[j].edge.ID
	})
	for _, aggregate := range ordered {
		edge := aggregate.finalize()
		if _, err := g.AddEdge(edge); err != nil {
			return fmt.Errorf("add can assume role edge %s: %w", aggregate.metadata.RoleResourceName, err)
		}
	}
	return nil
}

type s3AccessAggregate struct {
	edge     graph.Edge
	metadata graph.AWSS3AccessMetadata
	seen     map[string]struct{}
}

func (aggregate *s3AccessAggregate) add(grant graph.AWSS3AccessGrant) {
	key := s3AccessGrantIdentity(grant)
	if _, ok := aggregate.seen[key]; ok {
		return
	}
	aggregate.seen[key] = struct{}{}
	aggregate.metadata.Grants = append(aggregate.metadata.Grants, grant)
}

func (aggregate *s3AccessAggregate) finalize() graph.Edge {
	sort.SliceStable(aggregate.metadata.Grants, func(i, j int) bool {
		return s3AccessGrantIdentity(aggregate.metadata.Grants[i]) < s3AccessGrantIdentity(aggregate.metadata.Grants[j])
	})
	if len(aggregate.metadata.Grants) > 0 {
		aggregate.edge.Evidence.Source = aggregate.metadata.Grants[0].PolicySourceReference
	}
	aggregate.edge.Evidence.Detail = s3AccessEvidenceDetail(aggregate.metadata)
	aggregate.edge.Metadata = &graph.EdgeMetadata{AWSS3Access: &aggregate.metadata}
	return aggregate.edge
}

func addRoleS3Access(g *graph.Graph, roleNode graph.Node, role parserterraform.IAMRole, bucketsByName map[string][]graph.Node) error {
	aggregates := make(map[string]*s3AccessAggregate)
	for _, permission := range role.Permissions {
		if permission.Administrative {
			continue
		}
		for _, action := range permission.Actions {
			for _, resource := range permission.Resources {
				matches := s3AccessMatches(action, resource)
				if len(matches) == 0 {
					continue
				}
				bucketName, ok := s3BucketNameFromResourceARN(resource)
				if !ok {
					continue
				}
				for _, bucketNode := range bucketsByName[bucketName] {
					if bucketNode.Metadata == nil || bucketNode.Metadata.AWSS3Bucket == nil {
						continue
					}
					bucketMetadata := *bucketNode.Metadata.AWSS3Bucket
					for _, match := range matches {
						kind := graph.CanReadObject
						if match.accessMode == accessModeWrite {
							kind = graph.CanWriteObject
						}
						key := string(roleNode.ID) + "\x00" + string(bucketNode.ID) + "\x00" + match.accessMode
						aggregate := aggregates[key]
						if aggregate == nil {
							aggregate = &s3AccessAggregate{
								edge: graph.NewEdge(kind, roleNode.ID, bucketNode.ID, graph.SourceEvidence{
									Source: sourceRef(permission.Source),
								}),
								metadata: graph.AWSS3AccessMetadata{
									Provider:              providerAWS,
									RoleResourceName:      role.ResourceName,
									BucketName:            bucketMetadata.BucketName,
									BucketResourceName:    bucketMetadata.ResourceName,
									BucketSourceReference: bucketMetadata.SourceReference,
									AccessMode:            match.accessMode,
								},
								seen: make(map[string]struct{}),
							}
							aggregates[key] = aggregate
						}
						aggregate.add(graph.AWSS3AccessGrant{
							AccessMode:               match.accessMode,
							AccessKind:               match.accessKind,
							Action:                   action,
							Resource:                 resource,
							PolicySourceReference:    sourceRef(permission.Source),
							PolicyResourceName:       permission.PolicyResourceName,
							AttachedRoleResourceName: permission.AttachedRoleResourceName,
							StatementIndex:           permission.StatementIndex,
						})
					}
				}
			}
		}
	}

	ordered := make([]*s3AccessAggregate, 0, len(aggregates))
	for _, aggregate := range aggregates {
		ordered = append(ordered, aggregate)
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].edge.ID < ordered[j].edge.ID
	})
	for _, aggregate := range ordered {
		if _, err := g.AddEdge(aggregate.finalize()); err != nil {
			return fmt.Errorf("add aws s3 access edge for role %s: %w", role.ResourceName, err)
		}
	}
	return nil
}

type s3AccessMatch struct {
	accessMode string
	accessKind string
}

func s3AccessMatches(action, resource string) []s3AccessMatch {
	bucketName, ok := s3BucketNameFromResourceARN(resource)
	if !ok || bucketName == "" {
		return nil
	}
	objectARN := strings.HasSuffix(resource, "/*")
	bucketARN := !objectARN
	switch action {
	case "s3:ListBucket":
		if bucketARN {
			return []s3AccessMatch{{accessMode: accessModeRead, accessKind: "list_bucket"}}
		}
	case "s3:GetObject":
		if objectARN {
			return []s3AccessMatch{{accessMode: accessModeRead, accessKind: "get_object"}}
		}
	case "s3:PutObject":
		if objectARN {
			return []s3AccessMatch{{accessMode: accessModeWrite, accessKind: "put_object"}}
		}
	case "s3:DeleteObject":
		if objectARN {
			return []s3AccessMatch{{accessMode: accessModeWrite, accessKind: "delete_object"}}
		}
	case "s3:*":
		if bucketARN {
			return []s3AccessMatch{{accessMode: accessModeRead, accessKind: "s3_star_bucket"}}
		}
		if objectARN {
			return []s3AccessMatch{
				{accessMode: accessModeRead, accessKind: "s3_star_object"},
				{accessMode: accessModeWrite, accessKind: "s3_star_object"},
			}
		}
	}
	return nil
}

func s3BucketNameFromResourceARN(resource string) (string, bool) {
	const prefix = "arn:aws:s3:::"
	if !strings.HasPrefix(resource, prefix) {
		return "", false
	}
	target := strings.TrimPrefix(resource, prefix)
	if target == "" || target == "*" || strings.Contains(target, "${") || strings.Contains(target, "%{") {
		return "", false
	}
	if strings.HasSuffix(target, "/*") {
		bucketName := strings.TrimSuffix(target, "/*")
		if bucketName == "" || strings.ContainsAny(bucketName, "*/") {
			return "", false
		}
		return bucketName, true
	}
	if strings.ContainsAny(target, "*/") {
		return "", false
	}
	return target, true
}

func s3AccessGrantIdentity(grant graph.AWSS3AccessGrant) string {
	data, err := json.Marshal(struct {
		AccessMode               string `json:"access_mode"`
		AccessKind               string `json:"access_kind"`
		Action                   string `json:"action"`
		Resource                 string `json:"resource"`
		PolicySourceReference    string `json:"policy_source_reference"`
		PolicyResourceName       string `json:"policy_resource_name"`
		AttachedRoleResourceName string `json:"attached_role_resource_name"`
		StatementIndex           int    `json:"statement_index"`
	}{
		AccessMode:               grant.AccessMode,
		AccessKind:               grant.AccessKind,
		Action:                   grant.Action,
		Resource:                 grant.Resource,
		PolicySourceReference:    stableSourceReferenceValue(grant.PolicySourceReference),
		PolicyResourceName:       grant.PolicyResourceName,
		AttachedRoleResourceName: grant.AttachedRoleResourceName,
		StatementIndex:           grant.StatementIndex,
	})
	if err != nil {
		return ""
	}
	return string(data)
}

func stableSourceReferenceValue(value string) string {
	filename, resource, ok := strings.Cut(value, "#resource=")
	if !ok {
		return value
	}
	return filepath.ToSlash(filepath.Clean(filename)) + "#resource=" + resource
}

func s3AccessEvidenceDetail(metadata graph.AWSS3AccessMetadata) string {
	parts := make([]string, 0, len(metadata.Grants))
	for _, grant := range metadata.Grants {
		parts = append(parts, fmt.Sprintf("%s action=%s resource=%s", grant.AccessKind, grant.Action, grant.Resource))
	}
	return fmt.Sprintf("aws iam role %s has %s access to s3 bucket %s via static policy grant(s): %s", metadata.RoleResourceName, metadata.AccessMode, metadata.BucketName, strings.Join(parts, "; "))
}

func addRolePermissions(g *graph.Graph, roleNode graph.Node, role parserterraform.IAMRole) error {
	for _, permission := range role.Permissions {
		permissionNode := graph.NewNode(graph.AWSPermission, permissionNodeName(permission))
		permissionNode.Evidence = []graph.SourceEvidence{{
			Source: sourceRef(permission.Source),
			Detail: permissionEvidenceDetail(permission),
		}}
		metadata := permissionMetadata(permission)
		permissionNode.Metadata = &graph.NodeMetadata{AWSPermission: &metadata}
		addedPermission, err := g.AddNode(permissionNode)
		if err != nil {
			return fmt.Errorf("add aws permission for role %s: %w", role.ResourceName, err)
		}
		edge := graph.NewEdge(graph.GrantsPermission, roleNode.ID, addedPermission.ID, graph.SourceEvidence{
			Source: sourceRef(permission.Source),
			Detail: permissionEvidenceDetail(permission),
		})
		if _, err := g.AddEdge(edge); err != nil {
			return fmt.Errorf("add aws grants permission edge for role %s: %w", role.ResourceName, err)
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

type canAssumeRoleAggregate struct {
	edge     graph.Edge
	metadata graph.AWSCanAssumeRoleMetadata
	matches  []graph.AWSCanAssumeRoleMatch
	seen     map[string]struct{}
}

func (aggregate *canAssumeRoleAggregate) add(match graph.AWSCanAssumeRoleMatch) {
	key := canAssumeRoleMatchIdentity(match)
	if _, ok := aggregate.seen[key]; ok {
		return
	}
	aggregate.seen[key] = struct{}{}
	aggregate.matches = append(aggregate.matches, match)
}

func (aggregate *canAssumeRoleAggregate) finalize() graph.Edge {
	sort.SliceStable(aggregate.matches, func(i, j int) bool {
		return canAssumeRoleMatchIdentity(aggregate.matches[i]) < canAssumeRoleMatchIdentity(aggregate.matches[j])
	})
	if len(aggregate.matches) > 0 {
		first := aggregate.matches[0]
		aggregate.metadata.StatementIndex = first.StatementIndex
		aggregate.metadata.SubjectCandidate = first.SubjectCandidate
		aggregate.metadata.SubjectPattern = first.SubjectPattern
		aggregate.metadata.SubjectOperator = first.SubjectOperator
		aggregate.metadata.Matches = append([]graph.AWSCanAssumeRoleMatch(nil), aggregate.matches...)
	}
	aggregate.edge.Evidence.Detail = canAssumeRoleEvidenceDetail(aggregate.metadata.RoleResourceName, aggregate.matches)
	aggregate.edge.Metadata = &graph.EdgeMetadata{AWSCanAssumeRole: &aggregate.metadata}
	return aggregate.edge
}

func matchMetadata(role parserterraform.IAMRole, candidate subjectCandidate, match trustMatch) graph.AWSCanAssumeRoleMatch {
	return graph.AWSCanAssumeRoleMatch{
		Provider:            providerAWS,
		RoleResourceName:    role.ResourceName,
		RoleSourceReference: sourceRef(role.Source),
		TrustedIssuer:       githubActionsIssuer,
		StatementIndex:      match.statementIndex,
		Audience:            awsAudience,
		SubjectCandidate:    candidate.subject,
		SubjectPattern:      match.pattern.Pattern,
		SubjectOperator:     match.pattern.Operator,
	}
}

func canAssumeRoleMatchIdentity(match graph.AWSCanAssumeRoleMatch) string {
	data, err := json.Marshal(struct {
		Provider            string `json:"provider"`
		RoleResourceName    string `json:"role_resource_name"`
		RoleSourceReference string `json:"role_source_reference"`
		TrustedIssuer       string `json:"trusted_issuer"`
		StatementIndex      int    `json:"statement_index"`
		Audience            string `json:"audience"`
		SubjectCandidate    string `json:"subject_candidate"`
		SubjectPattern      string `json:"subject_pattern"`
		SubjectOperator     string `json:"subject_operator"`
	}{
		Provider:            match.Provider,
		RoleResourceName:    match.RoleResourceName,
		RoleSourceReference: match.RoleSourceReference,
		TrustedIssuer:       match.TrustedIssuer,
		StatementIndex:      match.StatementIndex,
		Audience:            match.Audience,
		SubjectCandidate:    match.SubjectCandidate,
		SubjectPattern:      match.SubjectPattern,
		SubjectOperator:     match.SubjectOperator,
	})
	if err != nil {
		return ""
	}
	return string(data)
}

func canAssumeRoleEvidenceDetail(roleName string, matches []graph.AWSCanAssumeRoleMatch) string {
	subjects := make([]string, 0, len(matches))
	for _, match := range matches {
		subjects = append(subjects, match.SubjectCandidate)
	}
	return fmt.Sprintf("github actions oidc subjects %s match aws iam role %s trust", strings.Join(subjects, ","), roleName)
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

func matchingTrusts(trusts []parserterraform.OIDCTrust, subject string) []trustMatch {
	var matches []trustMatch
	for _, trust := range trusts {
		if trust.Issuer != githubActionsIssuer || !stringListContains(trust.Audiences, awsAudience) {
			continue
		}
		patterns := trustPatterns(trust.SubjectPatterns)
		for _, pattern := range patterns {
			if subjectPatternMatches(pattern, subject) {
				matches = append(matches, trustMatch{statementIndex: trust.StatementIndex, pattern: pattern})
			}
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].statementIndex != matches[j].statementIndex {
			return matches[i].statementIndex < matches[j].statementIndex
		}
		if matches[i].pattern.Operator != matches[j].pattern.Operator {
			return matches[i].pattern.Operator < matches[j].pattern.Operator
		}
		return matches[i].pattern.Pattern < matches[j].pattern.Pattern
	})
	return matches
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

func bucketMetadata(bucket parserterraform.S3Bucket) graph.AWSS3BucketMetadata {
	reasons := bucketSensitivityReasons(bucket.SensitivityReasons)
	level := sensitivityUnknown
	if len(reasons) > 0 {
		level = sensitivitySensitive
	}
	return graph.AWSS3BucketMetadata{
		Provider:           providerAWS,
		BucketName:         bucket.BucketName,
		ResourceName:       bucket.ResourceName,
		SourceReference:    sourceRef(bucket.Source),
		SensitivityLevel:   level,
		SensitivityReasons: reasons,
	}
}

func bucketSensitivityReasons(reasons []parserterraform.S3BucketSensitivityReason) []graph.AWSS3BucketSensitivityReason {
	out := make([]graph.AWSS3BucketSensitivityReason, 0, len(reasons))
	for _, reason := range reasons {
		out = append(out, graph.AWSS3BucketSensitivityReason{
			Source:       reason.Source,
			MatchedToken: reason.MatchedToken,
			Key:          reason.Key,
			Value:        reason.Value,
			SourceRef:    stableSourceRefFromReason(reason.SourceRef),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return bucketSensitivityReasonIdentity(out[i]) < bucketSensitivityReasonIdentity(out[j])
	})
	return dedupeBucketSensitivityReasons(out)
}

func dedupeBucketSensitivityReasons(reasons []graph.AWSS3BucketSensitivityReason) []graph.AWSS3BucketSensitivityReason {
	if len(reasons) == 0 {
		return []graph.AWSS3BucketSensitivityReason{}
	}
	seen := make(map[string]struct{}, len(reasons))
	out := make([]graph.AWSS3BucketSensitivityReason, 0, len(reasons))
	for _, reason := range reasons {
		key := bucketSensitivityReasonIdentity(reason)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, reason)
	}
	return out
}

func bucketSensitivityReasonIdentity(reason graph.AWSS3BucketSensitivityReason) string {
	data, err := json.Marshal(struct {
		Source       string `json:"source"`
		MatchedToken string `json:"matched_token,omitempty"`
		Key          string `json:"key,omitempty"`
		Value        string `json:"value,omitempty"`
		SourceRef    string `json:"source_ref"`
	}{
		Source:       reason.Source,
		MatchedToken: reason.MatchedToken,
		Key:          reason.Key,
		Value:        reason.Value,
		SourceRef:    stableSourceReferenceValue(reason.SourceRef),
	})
	if err != nil {
		return ""
	}
	return string(data)
}

func stableSourceRefFromReason(sourceRef string) string {
	if sourceRef == "" {
		return ""
	}
	return stableSourceReferenceValue(sourceRef)
}

func permissionMetadata(permission parserterraform.IAMPermission) graph.AWSPermissionMetadata {
	return graph.AWSPermissionMetadata{
		Provider:                 providerAWS,
		SourceReference:          sourceRef(permission.Source),
		PolicyResourceName:       permission.PolicyResourceName,
		AttachmentResourceName:   permission.AttachmentResourceName,
		AttachedRoleResourceName: permission.AttachedRoleResourceName,
		StatementIndex:           permission.StatementIndex,
		Actions:                  append([]string(nil), permission.Actions...),
		Resources:                append([]string(nil), permission.Resources...),
		ManagedPolicyARN:         permission.ManagedPolicyARN,
		Administrative:           permission.Administrative,
		AdminReason:              permission.AdminReason,
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

func bucketNodeName(bucket parserterraform.S3Bucket) string {
	return "aws://terraform/aws_s3_bucket/" + bucket.Source.RelativePath + "/" + bucket.ResourceName
}

func permissionNodeName(permission parserterraform.IAMPermission) string {
	return "aws://terraform/aws_permission/" + permissionIdentityHash(permission)
}

func permissionIdentityHash(permission parserterraform.IAMPermission) string {
	data, err := json.Marshal(struct {
		Provider                 string   `json:"provider"`
		Kind                     string   `json:"kind"`
		SourceReference          string   `json:"source_reference"`
		PolicyResourceName       string   `json:"policy_resource_name,omitempty"`
		AttachmentResourceName   string   `json:"attachment_resource_name,omitempty"`
		AttachedRoleResourceName string   `json:"attached_role_resource_name"`
		StatementIndex           int      `json:"statement_index,omitempty"`
		Actions                  []string `json:"actions,omitempty"`
		Resources                []string `json:"resources,omitempty"`
		ManagedPolicyARN         string   `json:"managed_policy_arn,omitempty"`
		Administrative           bool     `json:"administrative"`
		AdminReason              string   `json:"admin_reason,omitempty"`
	}{
		Provider:                 providerAWS,
		Kind:                     permission.Kind,
		SourceReference:          stableSourceRef(permission.Source),
		PolicyResourceName:       permission.PolicyResourceName,
		AttachmentResourceName:   permission.AttachmentResourceName,
		AttachedRoleResourceName: permission.AttachedRoleResourceName,
		StatementIndex:           permission.StatementIndex,
		Actions:                  append([]string(nil), permission.Actions...),
		Resources:                append([]string(nil), permission.Resources...),
		ManagedPolicyARN:         permission.ManagedPolicyARN,
		Administrative:           permission.Administrative,
		AdminReason:              permission.AdminReason,
	})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func permissionEvidenceDetail(permission parserterraform.IAMPermission) string {
	target := permission.PolicyResourceName
	if target == "" {
		target = permission.AttachmentResourceName
	}
	if permission.Administrative {
		if permission.ManagedPolicyARN != "" {
			return fmt.Sprintf("aws iam role %s grants administrative permission via %s %s (%s managed_policy_arn=%s)", permission.AttachedRoleResourceName, permission.Kind, target, permission.AdminReason, permission.ManagedPolicyARN)
		}
		return fmt.Sprintf("aws iam role %s grants administrative permission via %s %s (%s action=%s resource=%s)", permission.AttachedRoleResourceName, permission.Kind, target, permission.AdminReason, strings.Join(permission.Actions, ","), strings.Join(permission.Resources, ","))
	}
	return fmt.Sprintf("aws iam role %s grants static permission via %s %s", permission.AttachedRoleResourceName, permission.Kind, target)
}

func sourceRef(source parserterraform.Source) string {
	return fmt.Sprintf("%s#resource=%s.%s", source.Filename, source.ResourceType, source.ResourceName)
}

func stableSourceRef(source parserterraform.Source) string {
	return fmt.Sprintf("%s#resource=%s.%s", source.RelativePath, source.ResourceType, source.ResourceName)
}
