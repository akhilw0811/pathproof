package remediation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"pathproof/internal/analysis"
	"pathproof/internal/graph"
)

type PlanID string
type Action string

const (
	RemoveSecretsResource Action = "RemoveSecretsResource"
	RemoveSecretReadVerb  Action = "RemoveSecretReadVerb"
	NarrowBindingSubject  Action = "NarrowBindingSubject"
	PinGitHubActionToSHA  Action = "PinGitHubActionToSHA"
)

type Plan struct {
	ID        PlanID             `json:"id"`
	FindingID analysis.FindingID `json:"finding_id"`
	RuleID    analysis.RuleID    `json:"rule_id"`
	Summary   string             `json:"summary"`
	Options   []Option           `json:"options"`
}

type Option struct {
	Priority           int      `json:"priority"`
	Action             Action   `json:"action"`
	Summary            string   `json:"summary"`
	Rationale          string   `json:"rationale"`
	RequiresAllChanges bool     `json:"requires_all_changes"`
	Changes            []Change `json:"changes"`
	Constraints        []string `json:"constraints,omitempty"`
}

type Change struct {
	Action           Action `json:"action"`
	Target           Target `json:"target"`
	Summary          string `json:"summary"`
	SourceReference  string `json:"source_reference"`
	PermissionSHA256 string `json:"permission_sha256,omitempty"`
	MatchedVerb      string `json:"matched_verb,omitempty"`
	Subject          string `json:"subject,omitempty"`
	ActionRef        string `json:"action_ref,omitempty"`
	ReplacementSHA   string `json:"replacement_sha,omitempty"`
	ReplacementRef   string `json:"replacement_ref,omitempty"`
	PatchSupported   bool   `json:"patch_supported,omitempty"`
	Advisory         bool   `json:"advisory,omitempty"`
	Reason           string `json:"reason,omitempty"`
	SourceLine       int    `json:"source_line,omitempty"`
	SourceColumn     int    `json:"source_column,omitempty"`
}

type Target struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

type optionCandidate struct {
	option   Option
	identity string
}

type changeCandidate struct {
	change   Change
	identity string
}

type planIdentity struct {
	FindingID        analysis.FindingID `json:"finding_id"`
	OptionIdentities []string           `json:"option_identities"`
}

type optionIdentity struct {
	Priority         int      `json:"priority"`
	Action           Action   `json:"action"`
	ChangeIdentities []string `json:"change_identities"`
}

type changeIdentity struct {
	Action           Action `json:"action"`
	Target           Target `json:"target"`
	PermissionSHA256 string `json:"permission_sha256,omitempty"`
	MatchedVerb      string `json:"matched_verb,omitempty"`
	Subject          string `json:"subject,omitempty"`
	SourceReference  string `json:"source_reference"`
	ActionRef        string `json:"action_ref,omitempty"`
	ReplacementSHA   string `json:"replacement_sha,omitempty"`
	ReplacementRef   string `json:"replacement_ref,omitempty"`
	PatchSupported   bool   `json:"patch_supported,omitempty"`
	Advisory         bool   `json:"advisory,omitempty"`
	Reason           string `json:"reason,omitempty"`
	SourceLine       int    `json:"source_line,omitempty"`
	SourceColumn     int    `json:"source_column,omitempty"`
}

func Build(g *graph.Graph, findings []analysis.Finding) ([]Plan, error) {
	return BuildWithGitHubActionPins(g, findings, nil)
}

func BuildWithGitHubActionPins(g *graph.Graph, findings []analysis.Finding, pins GitHubActionPins) ([]Plan, error) {
	plans := make([]Plan, 0)
	if len(findings) == 0 {
		return plans, nil
	}

	orderedFindings := append([]analysis.Finding(nil), findings...)
	sort.Slice(orderedFindings, func(i, j int) bool {
		return orderedFindings[i].ID < orderedFindings[j].ID
	})

	for _, finding := range orderedFindings {
		if finding.RuleID == analysis.RuleGitHubActionsUnpinnedAction {
			plan, ok, err := githubActionPinPlan(g, finding, pins)
			if err != nil {
				return nil, err
			}
			if ok {
				plans = append(plans, plan)
			}
			continue
		}
		if finding.RuleID != analysis.RulePublicWorkloadCanReadSecret {
			continue
		}
		context, err := validateFinding(g, finding)
		if err != nil {
			return nil, err
		}
		authorizations := supportedAuthorizations(context)
		if len(authorizations) == 0 {
			continue
		}

		options, identities, err := optionsForAuthorizations(authorizations)
		if err != nil {
			return nil, fmt.Errorf("build remediation options for finding %q: %w", finding.ID, err)
		}
		if len(options) == 0 {
			continue
		}
		id, err := stablePlanID(finding.ID, identities)
		if err != nil {
			return nil, fmt.Errorf("build remediation plan ID for finding %q: %w", finding.ID, err)
		}
		plans = append(plans, Plan{
			ID:        id,
			FindingID: finding.ID,
			RuleID:    finding.RuleID,
			Summary:   fmt.Sprintf("Remediate Kubernetes Secret read access for finding %s.", finding.ID),
			Options:   options,
		})
	}

	return plans, nil
}

func githubActionPinPlan(g *graph.Graph, finding analysis.Finding, pins GitHubActionPins) (Plan, bool, error) {
	if g == nil {
		return Plan{}, false, fmt.Errorf("finding %q cannot be remediated without a graph", finding.ID)
	}
	actionUse, ok := githubActionUseForFinding(g, finding)
	if !ok {
		return Plan{}, false, fmt.Errorf("finding %q lacks GitHub action use metadata", finding.ID)
	}
	change := githubActionPinChange(actionUse, pins)
	identity, err := stableChangeIdentity(change)
	if err != nil {
		return Plan{}, false, err
	}
	option, err := makeOption(1, PinGitHubActionToSHA, []changeCandidate{{change: change, identity: identity}},
		"Pin the GitHub Action reference to a full 40-character commit SHA.",
		"Full commit SHA pinning avoids trusting mutable tags or branches. PathProof does not resolve refs; patching is supported only when a local pin mapping supplies the exact SHA.",
	)
	if err != nil {
		return Plan{}, false, err
	}
	id, err := stablePlanID(finding.ID, []string{option.identity})
	if err != nil {
		return Plan{}, false, err
	}
	return Plan{
		ID:        id,
		FindingID: finding.ID,
		RuleID:    finding.RuleID,
		Summary:   "Pin the GitHub Action reference to a full 40-character commit SHA using a locally supplied trusted mapping when available.",
		Options:   []Option{option.option},
	}, true, nil
}

func githubActionUseForFinding(g *graph.Graph, finding analysis.Finding) (graph.GitHubActionUse, bool) {
	if finding.RuleID != analysis.RuleGitHubActionsUnpinnedAction || len(finding.EdgeIDs) == 0 {
		return graph.GitHubActionUse{}, false
	}
	edge, ok := g.Edge(finding.EdgeIDs[len(finding.EdgeIDs)-1])
	if !ok || edge.Metadata == nil || edge.Metadata.GitHubActionUse == nil {
		return graph.GitHubActionUse{}, false
	}
	return *edge.Metadata.GitHubActionUse, true
}

func githubActionPinChange(actionUse graph.GitHubActionUse, pins GitHubActionPins) Change {
	targetName := actionUse.Owner + "/" + actionUse.Repo
	if actionUse.Path != "" {
		targetName += "/" + actionUse.Path
	}
	change := Change{
		Action:          PinGitHubActionToSHA,
		Target:          Target{Kind: "GitHubAction", Name: targetName},
		Summary:         "Pin " + actionUse.Uses + " to a full 40-character commit SHA.",
		SourceReference: actionUse.WorkflowFile + "#document=1",
		ActionRef:       actionUse.Uses,
		Advisory:        true,
		SourceLine:      actionUse.UsesLine,
		SourceColumn:    actionUse.UsesColumn,
	}
	sha, ok := pins.SHAFor(actionUse.Uses)
	if !ok {
		change.Reason = "no local SHA mapping was provided for this exact action ref"
		return change
	}
	replacementRef := targetName + "@" + sha
	change.ReplacementSHA = sha
	change.ReplacementRef = replacementRef
	if actionUse.Ref == "" {
		change.Reason = "action ref has no explicit ref to replace"
		return change
	}
	if actionUse.Ref == "<expression>" || strings.Contains(actionUse.Ref, "${{") || strings.Contains(actionUse.Ref, "}}") {
		change.Reason = "action ref is expression-based"
		return change
	}
	if actionUse.UsesLine <= 0 || actionUse.UsesColumn <= 0 {
		change.Reason = "uses source location is not precise enough to patch"
		return change
	}
	if actionUse.PatchUnsupportedReason != "" {
		change.Reason = actionUse.PatchUnsupportedReason
		return change
	}
	change.PatchSupported = true
	change.Reason = ""
	return change
}

type findingContext struct {
	finding        analysis.Finding
	serviceAccount graph.Node
	secret         graph.Node
	canRead        graph.Edge
}

func validateFinding(g *graph.Graph, finding analysis.Finding) (findingContext, error) {
	if g == nil {
		return findingContext{}, fmt.Errorf("finding %q cannot be remediated without a graph", finding.ID)
	}
	if len(finding.NodeIDs) != 4 {
		return findingContext{}, fmt.Errorf("finding %q has %d path nodes, want 4", finding.ID, len(finding.NodeIDs))
	}
	if len(finding.EdgeIDs) != 3 {
		return findingContext{}, fmt.Errorf("finding %q has %d path edges, want 3", finding.ID, len(finding.EdgeIDs))
	}

	wantNodeKinds := []graph.NodeKind{graph.PublicEndpoint, graph.Workload, graph.ServiceAccount, graph.Secret}
	nodes := make([]graph.Node, len(finding.NodeIDs))
	for i, id := range finding.NodeIDs {
		node, ok := g.Node(id)
		if !ok {
			return findingContext{}, fmt.Errorf("finding %q references missing node %q", finding.ID, id)
		}
		if node.Kind != wantNodeKinds[i] {
			return findingContext{}, fmt.Errorf("finding %q node %d has kind %q, want %q", finding.ID, i, node.Kind, wantNodeKinds[i])
		}
		nodes[i] = node
	}

	wantEdgeKinds := []graph.EdgeKind{graph.RoutesTo, graph.RunsAs, graph.CanRead}
	edges := make([]graph.Edge, len(finding.EdgeIDs))
	for i, id := range finding.EdgeIDs {
		edge, ok := g.Edge(id)
		if !ok {
			return findingContext{}, fmt.Errorf("finding %q references missing edge %q", finding.ID, id)
		}
		if edge.Kind != wantEdgeKinds[i] {
			return findingContext{}, fmt.Errorf("finding %q edge %d has kind %q, want %q", finding.ID, i, edge.Kind, wantEdgeKinds[i])
		}
		if edge.From != finding.NodeIDs[i] || edge.To != finding.NodeIDs[i+1] {
			return findingContext{}, fmt.Errorf("finding %q edge %d connects %q -> %q, want %q -> %q", finding.ID, i, edge.From, edge.To, finding.NodeIDs[i], finding.NodeIDs[i+1])
		}
		edges[i] = edge
	}

	return findingContext{
		finding:        finding,
		serviceAccount: nodes[2],
		secret:         nodes[3],
		canRead:        edges[2],
	}, nil
}

func supportedAuthorizations(context findingContext) []graph.KubernetesCanReadAuthorization {
	if context.canRead.Metadata == nil {
		return nil
	}
	serviceAccountNamespace, serviceAccountName, ok := parseNamespacedNodeName(context.serviceAccount.Name, "serviceaccount")
	if !ok {
		return nil
	}
	secretNamespace, secretName, ok := parseNamespacedNodeName(context.secret.Name, "secret")
	if !ok {
		return nil
	}

	seen := make(map[string]graph.KubernetesCanReadAuthorization)
	for _, authorization := range context.canRead.Metadata.KubernetesCanReadAuthorizations {
		if authorization.ServiceAccountNamespace != serviceAccountNamespace || authorization.ServiceAccountName != serviceAccountName {
			continue
		}
		if authorization.SecretNamespace != secretNamespace || authorization.SecretName != secretName {
			continue
		}
		identity, err := authorizationIdentity(authorization)
		if err != nil {
			continue
		}
		seen[identity] = cloneAuthorization(authorization)
	}

	identities := make([]string, 0, len(seen))
	for identity := range seen {
		identities = append(identities, identity)
	}
	sort.Strings(identities)
	authorizations := make([]graph.KubernetesCanReadAuthorization, 0, len(identities))
	for _, identity := range identities {
		authorizations = append(authorizations, seen[identity])
	}
	return authorizations
}

func optionsForAuthorizations(authorizations []graph.KubernetesCanReadAuthorization) ([]Option, []string, error) {
	candidates := make([]optionCandidate, 0, 3)
	if candidate, ok, err := removeSecretsResourceOption(authorizations); err != nil {
		return nil, nil, err
	} else if ok {
		candidates = append(candidates, candidate)
	}
	if candidate, ok, err := removeSecretReadVerbOption(authorizations); err != nil {
		return nil, nil, err
	} else if ok {
		candidates = append(candidates, candidate)
	}
	if candidate, ok, err := narrowBindingSubjectOption(authorizations); err != nil {
		return nil, nil, err
	} else if ok {
		candidates = append(candidates, candidate)
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].option.Priority != candidates[j].option.Priority {
			return candidates[i].option.Priority < candidates[j].option.Priority
		}
		return candidates[i].identity < candidates[j].identity
	})
	options := make([]Option, 0, len(candidates))
	identities := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		options = append(options, candidate.option)
		identities = append(identities, candidate.identity)
	}
	return options, identities, nil
}

func removeSecretsResourceOption(authorizations []graph.KubernetesCanReadAuthorization) (optionCandidate, bool, error) {
	changes := make([]changeCandidate, 0, len(authorizations))
	for _, authorization := range authorizations {
		if !canSafelyRemoveSecretsResource(authorization.Permission) {
			return optionCandidate{}, false, nil
		}
		target := Target{Kind: authorization.RoleKind, Namespace: authorization.RoleNamespace, Name: authorization.RoleName}
		summary := fmt.Sprintf("Remove the secrets resource grant from %s %s.", target.Kind, targetName(target))
		if len(authorization.Permission.Resources) > 1 {
			summary = fmt.Sprintf("Remove secrets from the %s %s resource list or split the rule so unrelated resources remain granted.", target.Kind, targetName(target))
		}
		change := Change{
			Action:           RemoveSecretsResource,
			Target:           target,
			Summary:          summary,
			SourceReference:  authorization.RoleSourceReference,
			PermissionSHA256: authorization.PermissionSHA256,
		}
		identity, err := stableChangeIdentity(change)
		if err != nil {
			return optionCandidate{}, false, err
		}
		changes = append(changes, changeCandidate{change: change, identity: identity})
	}
	changes = dedupeChanges(changes)
	option, err := makeOption(2, RemoveSecretsResource, changes,
		fmt.Sprintf("Remove Secret resource access from %d RBAC rule change(s).", len(changes)),
		"Removing the secrets resource from each contributing permission rule breaks the modeled ServiceAccount-to-Secret read edge while preserving unrelated resource access when rules are split.",
	)
	if err != nil {
		return optionCandidate{}, false, err
	}
	return option, true, nil
}

func removeSecretReadVerbOption(authorizations []graph.KubernetesCanReadAuthorization) (optionCandidate, bool, error) {
	changes := make([]changeCandidate, 0, len(authorizations))
	for _, authorization := range authorizations {
		if !isSecretOnlyCoreResourceRule(authorization.Permission) {
			return optionCandidate{}, false, nil
		}
		switch authorization.MatchedVerb {
		case "get", "list", "watch", "*":
		default:
			return optionCandidate{}, false, nil
		}
		target := Target{Kind: authorization.RoleKind, Namespace: authorization.RoleNamespace, Name: authorization.RoleName}
		summary := fmt.Sprintf("Remove the %s verb from the Secret read rule in %s %s.", authorization.MatchedVerb, target.Kind, targetName(target))
		if authorization.MatchedVerb == "*" {
			summary = fmt.Sprintf("Replace wildcard verb * in %s %s with explicit least-privilege verbs that exclude modeled Secret read operations.", target.Kind, targetName(target))
		}
		change := Change{
			Action:           RemoveSecretReadVerb,
			Target:           target,
			Summary:          summary,
			SourceReference:  authorization.RoleSourceReference,
			PermissionSHA256: authorization.PermissionSHA256,
			MatchedVerb:      authorization.MatchedVerb,
		}
		identity, err := stableChangeIdentity(change)
		if err != nil {
			return optionCandidate{}, false, err
		}
		changes = append(changes, changeCandidate{change: change, identity: identity})
	}
	changes = dedupeChanges(changes)
	option, err := makeOption(3, RemoveSecretReadVerb, changes,
		fmt.Sprintf("Remove or narrow Secret read verbs in %d RBAC rule change(s).", len(changes)),
		"Removing each matched read-enabling verb breaks the modeled ServiceAccount-to-Secret read edge. Wildcard verbs must be replaced with explicit least-privilege verbs rather than treated as one removable literal read verb.",
	)
	if err != nil {
		return optionCandidate{}, false, err
	}
	return option, true, nil
}

func canSafelyRemoveSecretsResource(permission graph.KubernetesPermission) bool {
	return isCoreOnlyAPIGroup(permission.APIGroups) && containsString(permission.Resources, "secrets") && !containsString(permission.Resources, "*")
}

func isSecretOnlyCoreResourceRule(permission graph.KubernetesPermission) bool {
	return isCoreOnlyAPIGroup(permission.APIGroups) && len(permission.Resources) == 1 && permission.Resources[0] == "secrets"
}

func isCoreOnlyAPIGroup(apiGroups []string) bool {
	return len(apiGroups) == 1 && apiGroups[0] == ""
}

func narrowBindingSubjectOption(authorizations []graph.KubernetesCanReadAuthorization) (optionCandidate, bool, error) {
	changes := make([]changeCandidate, 0, len(authorizations))
	for _, authorization := range authorizations {
		if authorization.BindingSupportedServiceAccountCount <= 1 {
			return optionCandidate{}, false, nil
		}
		target := Target{Kind: authorization.BindingKind, Namespace: authorization.BindingNamespace, Name: authorization.BindingName}
		subject := authorization.ServiceAccountNamespace + "/" + authorization.ServiceAccountName
		change := Change{
			Action:          NarrowBindingSubject,
			Target:          target,
			Summary:         fmt.Sprintf("Remove only ServiceAccount %s from %s %s; keep other subjects intact.", subject, target.Kind, targetName(target)),
			SourceReference: authorization.BindingSourceReference,
			Subject:         subject,
		}
		identity, err := stableChangeIdentity(change)
		if err != nil {
			return optionCandidate{}, false, err
		}
		changes = append(changes, changeCandidate{change: change, identity: identity})
	}
	changes = dedupeChanges(changes)
	option, err := makeOption(1, NarrowBindingSubject, changes,
		fmt.Sprintf("Remove the affected ServiceAccount from %d multi-subject binding change(s).", len(changes)),
		"Removing only the affected ServiceAccount subject from every contributing multi-subject binding breaks the modeled read edge without deleting bindings used by other subjects.",
	)
	if err != nil {
		return optionCandidate{}, false, err
	}
	return option, true, nil
}

func makeOption(priority int, action Action, changes []changeCandidate, summary, rationale string) (optionCandidate, error) {
	option := Option{
		Priority:           priority,
		Action:             action,
		Summary:            summary,
		Rationale:          rationale,
		RequiresAllChanges: len(changes) > 1,
		Changes:            make([]Change, 0, len(changes)),
	}
	if len(changes) > 1 {
		option.Constraints = []string{"All listed changes in this option must be applied together."}
	}
	identities := make([]string, 0, len(changes))
	for _, change := range changes {
		option.Changes = append(option.Changes, change.change)
		identities = append(identities, change.identity)
	}
	identity, err := stableOptionIdentity(priority, action, identities)
	if err != nil {
		return optionCandidate{}, err
	}
	return optionCandidate{option: option, identity: identity}, nil
}

func dedupeChanges(changes []changeCandidate) []changeCandidate {
	byIdentity := make(map[string]Change, len(changes))
	for _, change := range changes {
		byIdentity[change.identity] = change.change
	}
	identities := make([]string, 0, len(byIdentity))
	for identity := range byIdentity {
		identities = append(identities, identity)
	}
	sort.Strings(identities)
	deduped := make([]changeCandidate, 0, len(identities))
	for _, identity := range identities {
		deduped = append(deduped, changeCandidate{change: byIdentity[identity], identity: identity})
	}
	return deduped
}

func stablePlanID(findingID analysis.FindingID, optionIdentities []string) (PlanID, error) {
	data, err := json.Marshal(planIdentity{
		FindingID:        findingID,
		OptionIdentities: append([]string(nil), optionIdentities...),
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return PlanID("plan:" + hex.EncodeToString(sum[:])), nil
}

func stableOptionIdentity(priority int, action Action, changeIdentities []string) (string, error) {
	data, err := json.Marshal(optionIdentity{
		Priority:         priority,
		Action:           action,
		ChangeIdentities: append([]string(nil), changeIdentities...),
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func stableChangeIdentity(change Change) (string, error) {
	data, err := json.Marshal(changeIdentity{
		Action:           change.Action,
		Target:           change.Target,
		PermissionSHA256: change.PermissionSHA256,
		MatchedVerb:      change.MatchedVerb,
		Subject:          change.Subject,
		SourceReference:  change.SourceReference,
		ActionRef:        change.ActionRef,
		ReplacementSHA:   change.ReplacementSHA,
		ReplacementRef:   change.ReplacementRef,
		PatchSupported:   change.PatchSupported,
		Advisory:         change.Advisory,
		Reason:           change.Reason,
		SourceLine:       change.SourceLine,
		SourceColumn:     change.SourceColumn,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func authorizationIdentity(authorization graph.KubernetesCanReadAuthorization) (string, error) {
	data, err := json.Marshal(authorization)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func cloneAuthorization(authorization graph.KubernetesCanReadAuthorization) graph.KubernetesCanReadAuthorization {
	authorization.Permission.APIGroups = append([]string(nil), authorization.Permission.APIGroups...)
	authorization.Permission.Resources = append([]string(nil), authorization.Permission.Resources...)
	authorization.Permission.ResourceNames = append([]string(nil), authorization.Permission.ResourceNames...)
	authorization.Permission.Verbs = append([]string(nil), authorization.Permission.Verbs...)
	authorization.SecretSourceReferences = append([]string(nil), authorization.SecretSourceReferences...)
	return authorization
}

func parseNamespacedNodeName(nodeName, kind string) (string, string, bool) {
	rest, ok := strings.CutPrefix(nodeName, "kubernetes://")
	if !ok {
		return "", "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[1] != kind || parts[0] == "" || parts[2] == "" {
		return "", "", false
	}
	return parts[0], parts[2], true
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func targetName(target Target) string {
	if target.Namespace == "" {
		return target.Name
	}
	return target.Namespace + "/" + target.Name
}
