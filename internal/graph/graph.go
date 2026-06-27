package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

type NodeKind string

const (
	PublicEndpoint      NodeKind = "PublicEndpoint"
	Workload            NodeKind = "Workload"
	ServiceAccount      NodeKind = "ServiceAccount"
	Role                NodeKind = "Role"
	Permission          NodeKind = "Permission"
	Secret              NodeKind = "Secret"
	Workflow            NodeKind = "Workflow"
	WorkflowJob         NodeKind = "WorkflowJob"
	GitHubAction        NodeKind = "GitHubAction"
	OIDCTokenCapability NodeKind = "OIDCTokenCapability"
	AWSIAMRole          NodeKind = "AWSIAMRole"
	AWSPermission       NodeKind = "AWSPermission"
)

type NodeID string
type EdgeID string

type EdgeKind string

const (
	RoutesTo            EdgeKind = "RoutesTo"
	RunsAs              EdgeKind = "RunsAs"
	BoundTo             EdgeKind = "BoundTo"
	GrantsPermission    EdgeKind = "GrantsPermission"
	CanRead             EdgeKind = "CanRead"
	DefinesJob          EdgeKind = "DefinesJob"
	UsesAction          EdgeKind = "UsesAction"
	CanRequestOIDCToken EdgeKind = "CanRequestOIDCToken"
	CanAssumeRole       EdgeKind = "CanAssumeRole"
)

var (
	ErrInvalidNodeID   = errors.New("node ID does not match node identity")
	ErrInvalidEdgeID   = errors.New("edge ID does not match edge identity")
	ErrMissingEndpoint = errors.New("edge endpoint does not exist")
)

type Node struct {
	ID       NodeID           `json:"id"`
	Kind     NodeKind         `json:"kind"`
	Name     string           `json:"name"`
	Evidence []SourceEvidence `json:"evidence,omitempty"`
	Metadata *NodeMetadata    `json:"metadata,omitempty"`
}

type SourceEvidence struct {
	Source string `json:"source"`
	Detail string `json:"detail"`
}

type NodeMetadata struct {
	GitHubActionsWorkflow            *GitHubActionsWorkflow            `json:"github_actions_workflow,omitempty"`
	GitHubActionsOIDCTokenCapability *GitHubActionsOIDCTokenCapability `json:"github_actions_oidc_token_capability,omitempty"`
	AWSIAMRole                       *AWSIAMRoleMetadata               `json:"aws_iam_role,omitempty"`
	AWSPermission                    *AWSPermissionMetadata            `json:"aws_permission,omitempty"`
}

type EdgeMetadata struct {
	KubernetesCanReadAuthorizations []KubernetesCanReadAuthorization `json:"kubernetes_can_read_authorizations,omitempty"`
	GitHubActionUse                 *GitHubActionUse                 `json:"github_action_use,omitempty"`
	GitHubActionsWorkflowJob        *GitHubActionsWorkflowJob        `json:"github_actions_workflow_job,omitempty"`
	GitHubActionsOIDCTokenRequest   *GitHubActionsOIDCTokenRequest   `json:"github_actions_oidc_token_request,omitempty"`
	AWSCanAssumeRole                *AWSCanAssumeRoleMetadata        `json:"aws_can_assume_role,omitempty"`
}

type AWSIAMRoleMetadata struct {
	Provider        string                  `json:"provider"`
	ResourceName    string                  `json:"resource_name"`
	SourceReference string                  `json:"source_reference"`
	TrustedIssuer   string                  `json:"trusted_issuer,omitempty"`
	TrustStatements []AWSOIDCTrustStatement `json:"trust_statements,omitempty"`
}

type AWSOIDCTrustStatement struct {
	StatementIndex  int                     `json:"statement_index"`
	SubjectPatterns []AWSOIDCSubjectPattern `json:"subject_patterns,omitempty"`
	Audiences       []string                `json:"audiences,omitempty"`
}

type AWSOIDCSubjectPattern struct {
	Operator string `json:"operator"`
	Pattern  string `json:"pattern"`
}

type AWSCanAssumeRoleMetadata struct {
	Provider                      string                  `json:"provider"`
	RoleResourceName              string                  `json:"role_resource_name"`
	RoleSourceReference           string                  `json:"role_source_reference"`
	TrustedIssuer                 string                  `json:"trusted_issuer"`
	StatementIndex                int                     `json:"statement_index"`
	Audience                      string                  `json:"audience"`
	SubjectCandidate              string                  `json:"subject_candidate"`
	SubjectPattern                string                  `json:"subject_pattern"`
	SubjectOperator               string                  `json:"subject_operator"`
	OIDCCapabilitySourceReference string                  `json:"oidc_capability_source_reference"`
	WorkflowFile                  string                  `json:"workflow_file"`
	Scope                         string                  `json:"scope"`
	JobID                         string                  `json:"job_id,omitempty"`
	Matches                       []AWSCanAssumeRoleMatch `json:"matches,omitempty"`
}

type AWSCanAssumeRoleMatch struct {
	Provider            string `json:"provider"`
	RoleResourceName    string `json:"role_resource_name"`
	RoleSourceReference string `json:"role_source_reference"`
	TrustedIssuer       string `json:"trusted_issuer"`
	StatementIndex      int    `json:"statement_index"`
	Audience            string `json:"audience"`
	SubjectCandidate    string `json:"subject_candidate"`
	SubjectPattern      string `json:"subject_pattern"`
	SubjectOperator     string `json:"subject_operator"`
}

type AWSPermissionMetadata struct {
	Provider                 string   `json:"provider"`
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
}

type GitHubActionsWorkflow struct {
	WorkflowSourceReference   string                         `json:"workflow_source_reference"`
	WorkflowFile              string                         `json:"workflow_file"`
	WorkflowName              string                         `json:"workflow_name,omitempty"`
	TriggersPullRequestTarget bool                           `json:"triggers_pull_request_target,omitempty"`
	PermissionGrants          []GitHubActionsPermissionGrant `json:"permission_grants,omitempty"`
}

type GitHubActionsWorkflowJob struct {
	WorkflowSourceReference   string                         `json:"workflow_source_reference"`
	WorkflowFile              string                         `json:"workflow_file"`
	WorkflowName              string                         `json:"workflow_name,omitempty"`
	TriggersPullRequestTarget bool                           `json:"triggers_pull_request_target,omitempty"`
	JobID                     string                         `json:"job_id"`
	PermissionGrants          []GitHubActionsPermissionGrant `json:"permission_grants,omitempty"`
}

type GitHubActionsOIDCTokenCapability struct {
	Provider                string `json:"provider"`
	WorkflowSourceReference string `json:"workflow_source_reference"`
	WorkflowFile            string `json:"workflow_file"`
	WorkflowName            string `json:"workflow_name,omitempty"`
	Scope                   string `json:"scope"`
	JobID                   string `json:"job_id,omitempty"`
}

type GitHubActionsOIDCTokenRequest struct {
	Provider                string `json:"provider"`
	WorkflowSourceReference string `json:"workflow_source_reference"`
	WorkflowFile            string `json:"workflow_file"`
	WorkflowName            string `json:"workflow_name,omitempty"`
	Scope                   string `json:"scope"`
	JobID                   string `json:"job_id,omitempty"`
	Permission              string `json:"permission"`
	Access                  string `json:"access"`
}

type GitHubActionsPermissionGrant struct {
	Scope      string `json:"scope"`
	JobID      string `json:"job_id,omitempty"`
	Permission string `json:"permission"`
	Access     string `json:"access"`
}

type GitHubActionUse struct {
	WorkflowSourceReference   string                              `json:"workflow_source_reference"`
	WorkflowFile              string                              `json:"workflow_file"`
	WorkflowName              string                              `json:"workflow_name,omitempty"`
	TriggersPullRequestTarget bool                                `json:"triggers_pull_request_target,omitempty"`
	JobID                     string                              `json:"job_id"`
	StepIndex                 int                                 `json:"step_index"`
	StepName                  string                              `json:"step_name,omitempty"`
	Uses                      string                              `json:"uses"`
	Owner                     string                              `json:"owner,omitempty"`
	Repo                      string                              `json:"repo,omitempty"`
	Path                      string                              `json:"path,omitempty"`
	Ref                       string                              `json:"ref,omitempty"`
	CheckoutHeadSelectors     []GitHubActionsCheckoutHeadSelector `json:"checkout_head_selectors,omitempty"`
}

type GitHubActionsCheckoutHeadSelector struct {
	Field             string `json:"field"`
	MatchedExpression string `json:"matched_expression"`
}

type KubernetesCanReadAuthorization struct {
	BindingKind                         string               `json:"binding_kind"`
	BindingNamespace                    string               `json:"binding_namespace,omitempty"`
	BindingName                         string               `json:"binding_name"`
	BindingSourceReference              string               `json:"binding_source_reference"`
	BindingSupportedServiceAccountCount int                  `json:"binding_supported_service_account_count"`
	ServiceAccountNamespace             string               `json:"service_account_namespace"`
	ServiceAccountName                  string               `json:"service_account_name"`
	RoleKind                            string               `json:"role_kind"`
	RoleNamespace                       string               `json:"role_namespace,omitempty"`
	RoleName                            string               `json:"role_name"`
	RoleSourceReference                 string               `json:"role_source_reference"`
	PermissionSHA256                    string               `json:"permission_sha256"`
	Permission                          KubernetesPermission `json:"permission"`
	MatchedVerb                         string               `json:"matched_verb"`
	ScopeKind                           string               `json:"scope_kind"`
	ScopeName                           string               `json:"scope_name,omitempty"`
	SecretNamespace                     string               `json:"secret_namespace"`
	SecretName                          string               `json:"secret_name"`
	SecretSourceReferences              []string             `json:"secret_source_references,omitempty"`
}

type KubernetesPermission struct {
	APIGroups     []string `json:"apiGroups"`
	Resources     []string `json:"resources"`
	ResourceNames []string `json:"resourceNames"`
	Verbs         []string `json:"verbs"`
}

type Edge struct {
	ID       EdgeID         `json:"id"`
	Kind     EdgeKind       `json:"kind"`
	From     NodeID         `json:"from"`
	To       NodeID         `json:"to"`
	Evidence SourceEvidence `json:"evidence"`
	Metadata *EdgeMetadata  `json:"metadata,omitempty"`
}

type Graph struct {
	nodes    map[NodeID]Node
	edges    map[EdgeID]Edge
	outgoing map[NodeID]map[EdgeID]Edge
}

func New() *Graph {
	return &Graph{
		nodes:    make(map[NodeID]Node),
		edges:    make(map[EdgeID]Edge),
		outgoing: make(map[NodeID]map[EdgeID]Edge),
	}
}

func NewNode(kind NodeKind, name string) Node {
	return Node{
		ID:   nodeID(kind, name),
		Kind: kind,
		Name: name,
	}
}

func NewEdge(kind EdgeKind, from, to NodeID, evidence SourceEvidence) Edge {
	return Edge{
		ID:       edgeID(kind, from, to),
		Kind:     kind,
		From:     from,
		To:       to,
		Evidence: evidence,
	}
}

func (g *Graph) AddNode(node Node) (Node, error) {
	canonicalID := nodeID(node.Kind, node.Name)
	if node.ID == "" {
		node.ID = canonicalID
	} else if node.ID != canonicalID {
		return Node{}, fmt.Errorf("%w: got %q, want %q", ErrInvalidNodeID, node.ID, canonicalID)
	}

	if existing, ok := g.nodes[node.ID]; ok {
		return cloneNode(existing), nil
	}

	node = cloneNode(node)
	g.nodes[node.ID] = node
	return cloneNode(node), nil
}

func (g *Graph) Node(id NodeID) (Node, bool) {
	node, ok := g.nodes[id]
	if !ok {
		return Node{}, false
	}
	return cloneNode(node), true
}

func (g *Graph) Nodes() []Node {
	nodes := make([]Node, 0, len(g.nodes))
	for _, node := range g.nodes {
		nodes = append(nodes, cloneNode(node))
	}

	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].ID < nodes[j].ID
	})

	return nodes
}

func (g *Graph) AddEdge(edge Edge) (Edge, error) {
	if _, ok := g.nodes[edge.From]; !ok {
		return Edge{}, fmt.Errorf("%w: from %q", ErrMissingEndpoint, edge.From)
	}
	if _, ok := g.nodes[edge.To]; !ok {
		return Edge{}, fmt.Errorf("%w: to %q", ErrMissingEndpoint, edge.To)
	}

	canonicalID := edgeID(edge.Kind, edge.From, edge.To)
	if edge.ID == "" {
		edge.ID = canonicalID
	} else if edge.ID != canonicalID {
		return Edge{}, fmt.Errorf("%w: got %q, want %q", ErrInvalidEdgeID, edge.ID, canonicalID)
	}

	if existing, ok := g.edges[edge.ID]; ok {
		return cloneEdge(existing), nil
	}

	edge = cloneEdge(edge)
	g.edges[edge.ID] = edge
	if g.outgoing[edge.From] == nil {
		g.outgoing[edge.From] = make(map[EdgeID]Edge)
	}
	g.outgoing[edge.From][edge.ID] = edge

	return cloneEdge(edge), nil
}

func (g *Graph) Edge(id EdgeID) (Edge, bool) {
	edge, ok := g.edges[id]
	if !ok {
		return Edge{}, false
	}
	return cloneEdge(edge), true
}

func (g *Graph) Edges() []Edge {
	edges := make([]Edge, 0, len(g.edges))
	for _, edge := range g.edges {
		edges = append(edges, cloneEdge(edge))
	}

	sort.Slice(edges, func(i, j int) bool {
		return edges[i].ID < edges[j].ID
	})

	return edges
}

func (g *Graph) Outgoing(from NodeID) []Edge {
	edges := make([]Edge, 0, len(g.outgoing[from]))
	for _, edge := range g.outgoing[from] {
		edges = append(edges, cloneEdge(edge))
	}

	sort.Slice(edges, func(i, j int) bool {
		return edges[i].ID < edges[j].ID
	})

	return edges
}

func (g *Graph) FindPath(from, to NodeID, maxDepth int) ([]Edge, bool) {
	if maxDepth < 0 {
		return nil, false
	}
	if _, ok := g.nodes[from]; !ok {
		return nil, false
	}
	if _, ok := g.nodes[to]; !ok {
		return nil, false
	}
	if from == to {
		return []Edge{}, true
	}

	type queuedPath struct {
		node NodeID
		path []Edge
	}

	queue := []queuedPath{{node: from}}
	visitedDepth := map[NodeID]int{from: 0}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if len(current.path) >= maxDepth {
			continue
		}

		for _, edge := range g.Outgoing(current.node) {
			nextDepth := len(current.path) + 1
			if previousDepth, seen := visitedDepth[edge.To]; seen && previousDepth <= nextDepth {
				continue
			}

			nextPath := append(append([]Edge(nil), current.path...), edge)
			if edge.To == to {
				return nextPath, true
			}

			visitedDepth[edge.To] = nextDepth
			queue = append(queue, queuedPath{node: edge.To, path: nextPath})
		}
	}

	return nil, false
}

func (g *Graph) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Nodes []Node `json:"nodes"`
		Edges []Edge `json:"edges"`
	}{
		Nodes: g.Nodes(),
		Edges: g.Edges(),
	})
}

func cloneNode(node Node) Node {
	node.Evidence = cloneEvidence(node.Evidence)
	if node.Metadata != nil {
		metadata := *node.Metadata
		if metadata.GitHubActionsWorkflow != nil {
			workflow := *metadata.GitHubActionsWorkflow
			workflow.PermissionGrants = cloneGitHubActionsPermissionGrants(workflow.PermissionGrants)
			metadata.GitHubActionsWorkflow = &workflow
		}
		if metadata.GitHubActionsOIDCTokenCapability != nil {
			capability := *metadata.GitHubActionsOIDCTokenCapability
			metadata.GitHubActionsOIDCTokenCapability = &capability
		}
		if metadata.AWSIAMRole != nil {
			role := *metadata.AWSIAMRole
			role.TrustStatements = cloneAWSOIDCTrustStatements(role.TrustStatements)
			metadata.AWSIAMRole = &role
		}
		if metadata.AWSPermission != nil {
			permission := *metadata.AWSPermission
			permission.Actions = cloneStrings(permission.Actions)
			permission.Resources = cloneStrings(permission.Resources)
			metadata.AWSPermission = &permission
		}
		node.Metadata = &metadata
	}
	return node
}

func cloneEvidence(evidence []SourceEvidence) []SourceEvidence {
	if evidence == nil {
		return nil
	}
	return append([]SourceEvidence(nil), evidence...)
}

func cloneEdge(edge Edge) Edge {
	if edge.Metadata == nil {
		return edge
	}
	metadata := *edge.Metadata
	metadata.KubernetesCanReadAuthorizations = cloneKubernetesCanReadAuthorizations(metadata.KubernetesCanReadAuthorizations)
	if metadata.GitHubActionUse != nil {
		actionUse := *metadata.GitHubActionUse
		actionUse.CheckoutHeadSelectors = cloneGitHubActionsCheckoutHeadSelectors(actionUse.CheckoutHeadSelectors)
		metadata.GitHubActionUse = &actionUse
	}
	if metadata.GitHubActionsWorkflowJob != nil {
		job := *metadata.GitHubActionsWorkflowJob
		job.PermissionGrants = cloneGitHubActionsPermissionGrants(job.PermissionGrants)
		metadata.GitHubActionsWorkflowJob = &job
	}
	if metadata.GitHubActionsOIDCTokenRequest != nil {
		request := *metadata.GitHubActionsOIDCTokenRequest
		metadata.GitHubActionsOIDCTokenRequest = &request
	}
	if metadata.AWSCanAssumeRole != nil {
		canAssume := *metadata.AWSCanAssumeRole
		canAssume.Matches = cloneAWSCanAssumeRoleMatches(canAssume.Matches)
		metadata.AWSCanAssumeRole = &canAssume
	}
	edge.Metadata = &metadata
	return edge
}

func cloneAWSCanAssumeRoleMatches(matches []AWSCanAssumeRoleMatch) []AWSCanAssumeRoleMatch {
	if matches == nil {
		return nil
	}
	return append([]AWSCanAssumeRoleMatch(nil), matches...)
}

func cloneKubernetesCanReadAuthorizations(authorizations []KubernetesCanReadAuthorization) []KubernetesCanReadAuthorization {
	if authorizations == nil {
		return nil
	}
	cloned := make([]KubernetesCanReadAuthorization, len(authorizations))
	for i, authorization := range authorizations {
		cloned[i] = authorization
		cloned[i].Permission.APIGroups = cloneStrings(authorization.Permission.APIGroups)
		cloned[i].Permission.Resources = cloneStrings(authorization.Permission.Resources)
		cloned[i].Permission.ResourceNames = cloneStrings(authorization.Permission.ResourceNames)
		cloned[i].Permission.Verbs = cloneStrings(authorization.Permission.Verbs)
		cloned[i].SecretSourceReferences = cloneStrings(authorization.SecretSourceReferences)
	}
	return cloned
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string(nil), values...)
}

func cloneAWSOIDCTrustStatements(statements []AWSOIDCTrustStatement) []AWSOIDCTrustStatement {
	if statements == nil {
		return nil
	}
	cloned := make([]AWSOIDCTrustStatement, len(statements))
	for i, statement := range statements {
		cloned[i] = statement
		cloned[i].SubjectPatterns = cloneAWSOIDCSubjectPatterns(statement.SubjectPatterns)
		cloned[i].Audiences = cloneStrings(statement.Audiences)
	}
	return cloned
}

func cloneAWSOIDCSubjectPatterns(patterns []AWSOIDCSubjectPattern) []AWSOIDCSubjectPattern {
	if patterns == nil {
		return nil
	}
	return append([]AWSOIDCSubjectPattern(nil), patterns...)
}

func cloneGitHubActionsCheckoutHeadSelectors(selectors []GitHubActionsCheckoutHeadSelector) []GitHubActionsCheckoutHeadSelector {
	if selectors == nil {
		return nil
	}
	return append([]GitHubActionsCheckoutHeadSelector(nil), selectors...)
}

func cloneGitHubActionsPermissionGrants(grants []GitHubActionsPermissionGrant) []GitHubActionsPermissionGrant {
	if grants == nil {
		return nil
	}
	return append([]GitHubActionsPermissionGrant(nil), grants...)
}

func nodeID(kind NodeKind, name string) NodeID {
	return NodeID("node:" + string(kind) + ":" + stableHash("node", string(kind), name))
}

func edgeID(kind EdgeKind, from, to NodeID) EdgeID {
	return EdgeID("edge:" + string(kind) + ":" + stableHash("edge", string(kind), string(from), string(to)))
}

func stableHash(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write([]byte{0})
		hash.Write([]byte(part))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
