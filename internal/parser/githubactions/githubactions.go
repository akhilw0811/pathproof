package githubactions

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Resources struct {
	Workflows []Workflow `json:"workflows,omitempty"`
}

type Source struct {
	Filename     string `json:"filename"`
	RelativePath string `json:"relative_path"`
	Document     int    `json:"document"`
}

type Workflow struct {
	Name                      string            `json:"name,omitempty"`
	Source                    Source            `json:"source"`
	TriggersPullRequest       bool              `json:"triggers_pull_request,omitempty"`
	TriggersPullRequestTarget bool              `json:"triggers_pull_request_target,omitempty"`
	PushBranches              []string          `json:"push_branches,omitempty"`
	PermissionGrants          []PermissionGrant `json:"permission_grants,omitempty"`
	Jobs                      []Job             `json:"jobs,omitempty"`
	PatchUnsupportedReason    string            `json:"patch_unsupported_reason,omitempty"`
}

type Job struct {
	ID               string            `json:"id"`
	Environment      string            `json:"environment,omitempty"`
	PermissionGrants []PermissionGrant `json:"permission_grants,omitempty"`
	Steps            []Step            `json:"steps,omitempty"`
}

type Step struct {
	Index                  int                    `json:"index"`
	Name                   string                 `json:"name,omitempty"`
	Uses                   string                 `json:"uses"`
	UsesLine               int                    `json:"uses_line,omitempty"`
	UsesColumn             int                    `json:"uses_column,omitempty"`
	Owner                  string                 `json:"owner"`
	Repo                   string                 `json:"repo"`
	Path                   string                 `json:"path,omitempty"`
	Ref                    string                 `json:"ref,omitempty"`
	CheckoutHeadSelectors  []CheckoutHeadSelector `json:"checkout_head_selectors,omitempty"`
	PatchUnsupportedReason string                 `json:"patch_unsupported_reason,omitempty"`
}

type CheckoutHeadSelector struct {
	Field             string `json:"field"`
	MatchedExpression string `json:"matched_expression"`
}

type PermissionGrant struct {
	Scope      string `json:"scope"`
	JobID      string `json:"job_id,omitempty"`
	Permission string `json:"permission"`
	Access     string `json:"access"`
}

func ParseDir(root string) (Resources, error) {
	workflowDir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(workflowDir)
	if errors.Is(err, os.ErrNotExist) {
		return Resources{}, nil
	}
	if err != nil {
		return Resources{}, fmt.Errorf("read github actions workflow directory %q: %w", workflowDir, err)
	}

	var paths []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := filepath.Ext(name)
		if ext != ".yml" && ext != ".yaml" {
			continue
		}
		paths = append(paths, filepath.Join(workflowDir, name))
	}
	sort.Strings(paths)

	resources := Resources{Workflows: make([]Workflow, 0, len(paths))}
	for _, path := range paths {
		workflow, err := parseFile(root, path)
		if err != nil {
			return Resources{}, err
		}
		resources.Workflows = append(resources.Workflows, workflow)
	}
	sortWorkflows(resources.Workflows)
	return resources, nil
}

func parseFile(root, path string) (Workflow, error) {
	file, err := os.Open(path)
	if err != nil {
		return Workflow{}, fmt.Errorf("open github actions workflow %q: %w", path, err)
	}
	defer file.Close()

	return parseWorkflow(file, root, path)
}

func parseWorkflow(r io.Reader, root, filename string) (Workflow, error) {
	relPath := workflowRelativePath(root, filename)
	decoder := yaml.NewDecoder(r)
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		if errors.Is(err, io.EOF) {
			document = yaml.Node{Kind: yaml.MappingNode}
		} else {
			return Workflow{}, invalidYAMLError(relPath, 1)
		}
	}

	for documentIndex := 2; ; documentIndex++ {
		var extra yaml.Node
		err := decoder.Decode(&extra)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Workflow{}, invalidYAMLError(relPath, documentIndex)
		}
	}
	source := Source{
		Filename:     filename,
		RelativePath: relPath,
		Document:     1,
	}
	if document.Kind == yaml.DocumentNode && len(document.Content) > 0 {
		document = *document.Content[0]
	}
	if document.Kind != yaml.MappingNode {
		return Workflow{Source: source}, nil
	}

	workflow := Workflow{Source: source}
	if name := scalarMappingValue(&document, "name"); name != nil {
		workflow.Name = name.Value
	}
	if on := mappingValue(&document, "on"); on != nil {
		workflow.TriggersPullRequest = hasTrigger(on, "pull_request")
		workflow.TriggersPullRequestTarget = hasPullRequestTargetTrigger(on)
		workflow.PushBranches = parsePushBranches(on)
	}
	if permissions := mappingValue(&document, "permissions"); permissions != nil {
		workflow.PermissionGrants = parsePermissionGrants(permissions, "workflow", "")
	}
	if jobs := mappingValue(&document, "jobs"); jobs != nil && jobs.Kind == yaml.MappingNode {
		workflow.Jobs = parseJobs(jobs)
	}
	workflow.PatchUnsupportedReason = workflowPatchUnsupportedReason(&document)
	sortJobs(workflow.Jobs)
	return workflow, nil
}

func workflowRelativePath(root, filename string) string {
	relPath, err := filepath.Rel(root, filename)
	if err != nil {
		relPath = filename
	}
	return filepath.ToSlash(filepath.Clean(relPath))
}

func invalidYAMLError(relPath string, document int) error {
	return fmt.Errorf("github actions workflow %s document %d: invalid YAML", relPath, document)
}

func parseJobs(jobs *yaml.Node) []Job {
	out := make([]Job, 0, len(jobs.Content)/2)
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		key := jobs.Content[i]
		value := jobs.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Value == "" || value.Kind != yaml.MappingNode {
			continue
		}
		job := Job{ID: key.Value}
		if environment := mappingValue(value, "environment"); environment != nil {
			job.Environment = parseJobEnvironment(environment)
		}
		if permissions := mappingValue(value, "permissions"); permissions != nil {
			job.PermissionGrants = parsePermissionGrants(permissions, "job", job.ID)
		}
		if steps := mappingValue(value, "steps"); steps != nil && steps.Kind == yaml.SequenceNode {
			job.Steps = parseSteps(steps)
		}
		out = append(out, job)
	}
	sortJobs(out)
	return out
}

func parseSteps(steps *yaml.Node) []Step {
	out := make([]Step, 0, len(steps.Content))
	for i, stepNode := range steps.Content {
		if stepNode.Kind != yaml.MappingNode {
			continue
		}
		uses := scalarMappingValue(stepNode, "uses")
		if uses == nil || uses.Value == "" {
			continue
		}
		ref, ok := parseActionReference(uses.Value)
		if !ok {
			continue
		}
		step := Step{
			Index:      i,
			Uses:       ref.canonicalUses(),
			UsesLine:   uses.Line,
			UsesColumn: actionRefValueColumn(uses),
			Owner:      ref.owner,
			Repo:       ref.repo,
			Path:       ref.path,
			Ref:        ref.ref,
		}
		if uses.LineComment != "" {
			step.PatchUnsupportedReason = "uses value has a same-line comment"
		}
		if step.PatchUnsupportedReason == "" && !isPatchableUsesScalarStyle(uses) {
			step.PatchUnsupportedReason = "uses scalar style is not supported for patching"
		}
		if step.PatchUnsupportedReason == "" && stepHasUnsafeSameLineContext(stepNode, uses) {
			step.PatchUnsupportedReason = "uses value shares a source line with unsupported or secret-like context"
		}
		if name := scalarMappingValue(stepNode, "name"); name != nil {
			step.Name = name.Value
		}
		if ref.owner == "actions" && ref.repo == "checkout" && ref.path == "" {
			step.CheckoutHeadSelectors = parseCheckoutHeadSelectors(stepNode)
		}
		out = append(out, step)
	}
	return out
}

func workflowPatchUnsupportedReason(document *yaml.Node) string {
	if document == nil {
		return ""
	}
	if containsUnsupportedWorkflowPatchContext(document, "") {
		return "workflow contains unsupported or secret-like context"
	}
	return ""
}

func containsUnsupportedWorkflowPatchContext(node *yaml.Node, context string) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			value := node.Content[i+1]
			nextContext := context
			if key.Kind == yaml.ScalarNode {
				keyName := strings.ToLower(strings.TrimSpace(key.Value))
				switch keyName {
				case "secrets":
					return true
				case "permissions":
					nextContext = "permissions"
				}
				if context != "permissions" && isSecretLikeWorkflowScalar(key.Value) {
					return true
				}
			}
			if containsUnsupportedWorkflowPatchContext(value, nextContext) {
				return true
			}
		}
		return false
	}
	if node.Kind == yaml.SequenceNode || node.Kind == yaml.DocumentNode {
		for _, child := range node.Content {
			if containsUnsupportedWorkflowPatchContext(child, context) {
				return true
			}
		}
		return false
	}
	if node.Kind == yaml.ScalarNode && isSecretLikeWorkflowScalar(node.Value) {
		return true
	}
	return false
}

func actionRefValueColumn(uses *yaml.Node) int {
	if uses == nil {
		return 0
	}
	switch uses.Style {
	case yaml.DoubleQuotedStyle, yaml.SingleQuotedStyle:
		return uses.Column + 1 + leadingWhitespaceCount(uses.Value)
	default:
		return uses.Column
	}
}

func isPatchableUsesScalarStyle(uses *yaml.Node) bool {
	if uses == nil {
		return false
	}
	return uses.Style != yaml.FoldedStyle && uses.Style != yaml.LiteralStyle
}

func stepHasUnsafeSameLineContext(stepNode, uses *yaml.Node) bool {
	if stepNode == nil || uses == nil || uses.Line <= 0 {
		return false
	}
	return nodeHasUnsafeSameLineContext(stepNode, uses.Line, uses)
}

func nodeHasUnsafeSameLineContext(node *yaml.Node, line int, uses *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			value := node.Content[i+1]
			if key.Kind == yaml.ScalarNode && key.Line == line && isUnsafeSameLineWorkflowKey(key.Value) {
				return true
			}
			if value != uses && nodeHasUnsafeSameLineContext(value, line, uses) {
				return true
			}
		}
		return false
	}
	if node.Kind == yaml.SequenceNode || node.Kind == yaml.DocumentNode {
		for _, child := range node.Content {
			if nodeHasUnsafeSameLineContext(child, line, uses) {
				return true
			}
		}
		return false
	}
	return node.Kind == yaml.ScalarNode && node.Line == line && node != uses && isSecretLikeWorkflowScalar(node.Value)
}

func isUnsafeSameLineWorkflowKey(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "run", "env", "with", "secrets":
		return true
	default:
		return isSecretLikeWorkflowScalar(value)
	}
}

func leadingWhitespaceCount(value string) int {
	count := 0
	for _, r := range value {
		if r != ' ' && r != '\t' {
			break
		}
		count++
	}
	return count
}

func isSecretLikeWorkflowScalar(value string) bool {
	lower := strings.ToLower(value)
	normalized := strings.NewReplacer("-", "_", " ", "_").Replace(lower)
	for _, marker := range []string{"secret", "token", "password", "credential", "access_key", "private_key"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func parsePermissionGrants(node *yaml.Node, scope, jobID string) []PermissionGrant {
	switch node.Kind {
	case yaml.ScalarNode:
		access := sanitizeScalarPermissionAccess(node.Value)
		if access != "write-all" && access != "read-all" {
			return nil
		}
		return []PermissionGrant{{
			Scope:      scope,
			JobID:      jobID,
			Permission: "all",
			Access:     access,
		}}
	case yaml.MappingNode:
		grants := make([]PermissionGrant, 0, len(node.Content)/2)
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			value := node.Content[i+1]
			if key.Kind != yaml.ScalarNode || value.Kind != yaml.ScalarNode {
				continue
			}
			permission := sanitizePermissionName(key.Value)
			access := sanitizeMapPermissionAccess(value.Value)
			if permission == "" || access == "" {
				continue
			}
			grants = append(grants, PermissionGrant{
				Scope:      scope,
				JobID:      jobID,
				Permission: permission,
				Access:     access,
			})
		}
		sortPermissionGrants(grants)
		return grants
	default:
		return nil
	}
}

func sanitizePermissionName(value string) string {
	switch value {
	case "contents", "pull-requests", "actions", "checks", "deployments", "id-token", "security-events":
		return value
	default:
		return ""
	}
}

func sanitizeScalarPermissionAccess(value string) string {
	if strings.Contains(value, "${{") || strings.Contains(value, "}}") {
		return ""
	}
	switch value {
	case "write-all", "read-all":
		return value
	default:
		return ""
	}
}

func sanitizeMapPermissionAccess(value string) string {
	if strings.Contains(value, "${{") || strings.Contains(value, "}}") {
		return ""
	}
	switch value {
	case "write", "read", "none":
		return value
	default:
		return ""
	}
}

func hasPullRequestTargetTrigger(on *yaml.Node) bool {
	return hasTrigger(on, "pull_request_target")
}

func hasTrigger(on *yaml.Node, trigger string) bool {
	switch on.Kind {
	case yaml.ScalarNode:
		return on.Value == trigger
	case yaml.SequenceNode:
		for _, item := range on.Content {
			if item.Kind == yaml.ScalarNode && item.Value == trigger {
				return true
			}
		}
	case yaml.MappingNode:
		return mappingValue(on, trigger) != nil
	}
	return false
}

func parsePushBranches(on *yaml.Node) []string {
	if on.Kind != yaml.MappingNode {
		return nil
	}
	push := mappingValue(on, "push")
	if push == nil || push.Kind != yaml.MappingNode {
		return nil
	}
	branches := mappingValue(push, "branches")
	if branches == nil {
		return nil
	}
	var out []string
	seen := make(map[string]struct{})
	add := func(value string) {
		branch := sanitizeStaticGitHubValue(value)
		if branch == "" || strings.ContainsAny(branch, "*?[]") {
			return
		}
		if _, ok := seen[branch]; ok {
			return
		}
		seen[branch] = struct{}{}
		out = append(out, branch)
	}
	switch branches.Kind {
	case yaml.ScalarNode:
		add(branches.Value)
	case yaml.SequenceNode:
		for _, item := range branches.Content {
			if item.Kind == yaml.ScalarNode {
				add(item.Value)
			}
		}
	}
	sort.Strings(out)
	return out
}

func parseJobEnvironment(node *yaml.Node) string {
	switch node.Kind {
	case yaml.ScalarNode:
		return sanitizeStaticGitHubValue(node.Value)
	case yaml.MappingNode:
		name := scalarMappingValue(node, "name")
		if name == nil {
			return ""
		}
		return sanitizeStaticGitHubValue(name.Value)
	default:
		return ""
	}
}

func sanitizeStaticGitHubValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "${{") || strings.Contains(value, "}}") {
		return ""
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return ""
		}
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case strings.ContainsRune("/._-", r):
		default:
			return ""
		}
	}
	return value
}

func parseCheckoutHeadSelectors(stepNode *yaml.Node) []CheckoutHeadSelector {
	with := mappingValue(stepNode, "with")
	if with == nil || with.Kind != yaml.MappingNode {
		return nil
	}
	expressionsByField := map[string][]string{
		"ref": {
			"github.event.pull_request.head.sha",
			"github.event.pull_request.head.ref",
			"github.head_ref",
		},
		"repository": {
			"github.event.pull_request.head.repo.full_name",
		},
	}
	var selectors []CheckoutHeadSelector
	seen := make(map[CheckoutHeadSelector]struct{})
	for _, field := range []string{"ref", "repository"} {
		value := scalarMappingValue(with, field)
		if value == nil {
			continue
		}
		actualExpressions := githubExpressionBodies(value.Value)
		for _, expression := range expressionsByField[field] {
			if !containsString(actualExpressions, expression) {
				continue
			}
			selector := CheckoutHeadSelector{Field: field, MatchedExpression: expression}
			if _, ok := seen[selector]; ok {
				continue
			}
			seen[selector] = struct{}{}
			selectors = append(selectors, selector)
		}
	}
	return selectors
}

func githubExpressionBodies(value string) []string {
	var expressions []string
	offset := 0
	for {
		start := strings.Index(value[offset:], "${{")
		if start < 0 {
			return expressions
		}
		start += offset
		bodyStart := start + len("${{")
		end := strings.Index(value[bodyStart:], "}}")
		if end < 0 {
			return expressions
		}
		end += bodyStart
		expressions = append(expressions, strings.TrimSpace(value[bodyStart:end]))
		offset = end + len("}}")
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type actionReference struct {
	owner string
	repo  string
	path  string
	ref   string
}

func parseActionReference(uses string) (actionReference, bool) {
	value := strings.TrimSpace(uses)
	if value == "" || strings.HasPrefix(value, "./") || strings.HasPrefix(value, "docker://") || isEntireExpression(value) {
		return actionReference{}, false
	}

	target, ref, _ := strings.Cut(value, "@")
	if strings.Contains(target, "${{") || strings.Contains(target, "}}") {
		return actionReference{}, false
	}
	parts := strings.Split(target, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return actionReference{}, false
	}
	if strings.ContainsAny(parts[0], " \t\r\n:") || strings.ContainsAny(parts[1], " \t\r\n:") {
		return actionReference{}, false
	}
	path := ""
	if len(parts) > 2 {
		path = strings.Join(parts[2:], "/")
	}
	if strings.Contains(ref, "${{") || strings.Contains(ref, "}}") {
		ref = "<expression>"
	}
	return actionReference{
		owner: parts[0],
		repo:  parts[1],
		path:  path,
		ref:   ref,
	}, true
}

func (ref actionReference) canonicalUses() string {
	var out strings.Builder
	out.WriteString(ref.owner)
	out.WriteString("/")
	out.WriteString(ref.repo)
	if ref.path != "" {
		out.WriteString("/")
		out.WriteString(ref.path)
	}
	if ref.ref != "" {
		out.WriteString("@")
		out.WriteString(ref.ref)
	}
	return out.String()
}

func isEntireExpression(value string) bool {
	return strings.HasPrefix(value, "${{") && strings.HasSuffix(value, "}}")
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Kind == yaml.ScalarNode && node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func scalarMappingValue(node *yaml.Node, key string) *yaml.Node {
	value := mappingValue(node, key)
	if value == nil || value.Kind != yaml.ScalarNode {
		return nil
	}
	return value
}

func sortWorkflows(workflows []Workflow) {
	sort.SliceStable(workflows, func(i, j int) bool {
		return workflows[i].Source.RelativePath < workflows[j].Source.RelativePath
	})
}

func sortJobs(jobs []Job) {
	sort.SliceStable(jobs, func(i, j int) bool {
		return jobs[i].ID < jobs[j].ID
	})
}

func sortPermissionGrants(grants []PermissionGrant) {
	sort.SliceStable(grants, func(i, j int) bool {
		if grants[i].Scope != grants[j].Scope {
			return grants[i].Scope < grants[j].Scope
		}
		if grants[i].JobID != grants[j].JobID {
			return grants[i].JobID < grants[j].JobID
		}
		if grants[i].Permission != grants[j].Permission {
			return grants[i].Permission < grants[j].Permission
		}
		return grants[i].Access < grants[j].Access
	})
}
