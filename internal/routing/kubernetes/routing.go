package kubernetes

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"pathproof/internal/graph"
	parserkubernetes "pathproof/internal/parser/kubernetes"
)

func AddRoutes(g *graph.Graph, resources parserkubernetes.Resources) error {
	services := append([]parserkubernetes.Service(nil), resources.Services...)
	deployments := append([]parserkubernetes.Deployment(nil), resources.Deployments...)
	ingresses := append([]parserkubernetes.Ingress(nil), resources.Ingresses...)
	serviceAccounts := append([]parserkubernetes.ServiceAccount(nil), resources.ServiceAccounts...)
	roles := append([]parserkubernetes.Role(nil), resources.Roles...)
	clusterRoles := append([]parserkubernetes.ClusterRole(nil), resources.ClusterRoles...)
	roleBindings := append([]parserkubernetes.RoleBinding(nil), resources.RoleBindings...)
	clusterRoleBindings := append([]parserkubernetes.ClusterRoleBinding(nil), resources.ClusterRoleBindings...)
	sortServices(services)
	sortDeployments(deployments)
	sortIngresses(ingresses)
	sortServiceAccounts(serviceAccounts)
	sortRoles(roles)
	sortClusterRoles(clusterRoles)
	sortRoleBindings(roleBindings)
	sortClusterRoleBindings(clusterRoleBindings)
	if err := validateNoConflictingDuplicates(services, deployments, ingresses, serviceAccounts, roles, clusterRoles, roleBindings, clusterRoleBindings); err != nil {
		return err
	}

	rbac, err := desiredRBACGraph(uniqueRoles(roles), uniqueClusterRoles(clusterRoles), roleBindings, clusterRoleBindings)
	if err != nil {
		return err
	}

	if err := addDeploymentServiceAccounts(g, uniqueDeployments(deployments), uniqueServiceAccounts(serviceAccounts)); err != nil {
		return err
	}

	for _, service := range services {
		if !isPublicService(service.Type) {
			continue
		}

		endpoint := graph.NewNode(graph.PublicEndpoint, endpointName(service))
		endpoint.Evidence = []graph.SourceEvidence{sourceEvidence(service.Source, "kubernetes Service")}
		addedEndpoint, err := g.AddNode(endpoint)
		if err != nil {
			return fmt.Errorf("add public endpoint for service %s/%s: %w", service.Namespace, service.Name, err)
		}

		for _, deployment := range matchingDeployments(service, deployments) {
			workload := graph.NewNode(graph.Workload, workloadName(deployment))
			workload.Evidence = []graph.SourceEvidence{sourceEvidence(deployment.Source, "kubernetes Deployment")}
			addedWorkload, err := g.AddNode(workload)
			if err != nil {
				return fmt.Errorf("add workload for deployment %s/%s: %w", deployment.Namespace, deployment.Name, err)
			}

			edge := graph.NewEdge(graph.RoutesTo, addedEndpoint.ID, addedWorkload.ID, routeEvidence(service.Source, deployment.Source))
			if _, err := g.AddEdge(edge); err != nil {
				return fmt.Errorf("add route from service %s/%s to deployment %s/%s: %w", service.Namespace, service.Name, deployment.Namespace, deployment.Name, err)
			}
		}
	}

	if err := addIngressRoutes(g, uniqueIngresses(ingresses), services, deployments); err != nil {
		return err
	}

	if err := addDesiredRBACGraph(g, rbac); err != nil {
		return err
	}

	return nil
}

func endpointName(service parserkubernetes.Service) string {
	return "kubernetes://" + service.Namespace + "/service/" + service.Name
}

func ingressEndpointName(ingress parserkubernetes.Ingress) string {
	return "kubernetes://" + ingress.Namespace + "/ingress/" + ingress.Name
}

func workloadName(deployment parserkubernetes.Deployment) string {
	return "kubernetes://" + deployment.Namespace + "/deployment/" + deployment.Name
}

func serviceAccountName(namespace, name string) string {
	return "kubernetes://" + namespace + "/serviceaccount/" + name
}

func isPublicService(serviceType string) bool {
	serviceType = normalizedServiceType(serviceType)
	return serviceType == "LoadBalancer" || serviceType == "NodePort"
}

func selectorMatches(selector, labels map[string]string) bool {
	for key, want := range selector {
		if got, ok := labels[key]; !ok || got != want {
			return false
		}
	}
	return true
}

func matchingDeployments(service parserkubernetes.Service, deployments []parserkubernetes.Deployment) []parserkubernetes.Deployment {
	if len(service.Selector) == 0 {
		return nil
	}

	var matches []parserkubernetes.Deployment
	for _, deployment := range deployments {
		if deployment.Namespace != service.Namespace || !selectorMatches(service.Selector, deployment.PodLabels) {
			continue
		}
		matches = append(matches, deployment)
	}
	return matches
}

func sourceEvidence(source parserkubernetes.Source, detail string) graph.SourceEvidence {
	return graph.SourceEvidence{
		Source: fmt.Sprintf("%s#document=%d", source.Filename, source.Document),
		Detail: detail,
	}
}

func inferredServiceAccountEvidence(deployment parserkubernetes.Deployment) graph.SourceEvidence {
	return graph.SourceEvidence{
		Source: fmt.Sprintf("deployment %s; serviceAccountName %s", sourceRef(deployment.Source), deployment.ServiceAccountName),
		Detail: "inferred kubernetes ServiceAccount from Deployment serviceAccountName",
	}
}

func observedRunsAsEvidence(deploymentSource, serviceAccountSource parserkubernetes.Source) graph.SourceEvidence {
	return graph.SourceEvidence{
		Source: fmt.Sprintf("deployment %s; serviceaccount %s", sourceRef(deploymentSource), sourceRef(serviceAccountSource)),
		Detail: "kubernetes Deployment serviceAccountName runs as observed ServiceAccount",
	}
}

func inferredRunsAsEvidence(deployment parserkubernetes.Deployment) graph.SourceEvidence {
	return graph.SourceEvidence{
		Source: fmt.Sprintf("deployment %s; serviceAccountName %s", sourceRef(deployment.Source), deployment.ServiceAccountName),
		Detail: "kubernetes Deployment serviceAccountName runs as inferred ServiceAccount",
	}
}

func routeEvidence(serviceSource, deploymentSource parserkubernetes.Source) graph.SourceEvidence {
	return graph.SourceEvidence{
		Source: fmt.Sprintf("service %s#document=%d; deployment %s#document=%d", serviceSource.Filename, serviceSource.Document, deploymentSource.Filename, deploymentSource.Document),
		Detail: "kubernetes Service selector routes to Deployment pod template labels",
	}
}

func ingressRouteEvidence(chains []string) graph.SourceEvidence {
	return graph.SourceEvidence{
		Source: strings.Join(chains, "; "),
		Detail: "kubernetes Ingress backend routes through Service selector to Deployment pod template labels",
	}
}

type ingressRouteGroup struct {
	endpoint graph.Node
	workload graph.Node
	chains   []string
}

type namespacedName struct {
	namespace string
	name      string
}

type desiredGraph struct {
	nodes map[graph.NodeID]graph.Node
	edges map[graph.EdgeID]graph.Edge
}

type boundToKey struct {
	from graph.NodeID
	to   graph.NodeID
}

type observedRole struct {
	kind   string
	source parserkubernetes.Source
	rules  []parserkubernetes.PolicyRule
	node   graph.Node
}

type resolvedBinding struct {
	subject     parserkubernetes.Subject
	role        graph.Node
	roleKind    string
	roleSource  *parserkubernetes.Source
	rules       []parserkubernetes.PolicyRule
	binding     parserkubernetes.Source
	bindingKind string
	bindingName string
	scopeKind   string
	scopeName   string
	unresolved  bool
}

type canonicalPermission struct {
	APIGroups     []string `json:"apiGroups"`
	Resources     []string `json:"resources"`
	ResourceNames []string `json:"resourceNames"`
	Verbs         []string `json:"verbs"`
}

const rbacAPIGroup = "rbac.authorization.k8s.io"

func desiredRBACGraph(roles []parserkubernetes.Role, clusterRoles []parserkubernetes.ClusterRole, roleBindings []parserkubernetes.RoleBinding, clusterRoleBindings []parserkubernetes.ClusterRoleBinding) (desiredGraph, error) {
	desired := desiredGraph{
		nodes: make(map[graph.NodeID]graph.Node),
		edges: make(map[graph.EdgeID]graph.Edge),
	}
	roleByIdentity := indexRoles(roles)
	clusterRoleByName := indexClusterRoles(clusterRoles)
	bindings := resolveSupportedBindings(roleBindings, clusterRoleBindings, roleByIdentity, clusterRoleByName)
	reachableRoles := make(map[graph.NodeID]observedRole)
	boundToEvidenceRecords := make(map[boundToKey]map[string]struct{})

	for _, binding := range bindings {
		serviceAccount := graph.NewNode(graph.ServiceAccount, serviceAccountName(binding.subject.Namespace, binding.subject.Name))
		serviceAccount.Evidence = []graph.SourceEvidence{rbacInferredServiceAccountEvidence(binding.binding, binding.bindingKind, binding.subject)}
		desired.addNode(serviceAccount)
		desired.addNode(binding.role)
		key := boundToKey{from: serviceAccount.ID, to: binding.role.ID}
		if boundToEvidenceRecords[key] == nil {
			boundToEvidenceRecords[key] = make(map[string]struct{})
		}
		boundToEvidenceRecords[key][boundToEvidenceRecord(binding)] = struct{}{}

		if binding.unresolved {
			continue
		}
		if _, exists := reachableRoles[binding.role.ID]; exists {
			continue
		}
		if binding.roleSource == nil {
			continue
		}
		reachableRoles[binding.role.ID] = observedRole{
			kind:   binding.roleKind,
			source: *binding.roleSource,
			rules:  binding.rules,
			node:   binding.role,
		}
	}

	boundToKeys := make([]boundToKey, 0, len(boundToEvidenceRecords))
	for key := range boundToEvidenceRecords {
		boundToKeys = append(boundToKeys, key)
	}
	sort.Slice(boundToKeys, func(i, j int) bool {
		if boundToKeys[i].from != boundToKeys[j].from {
			return boundToKeys[i].from < boundToKeys[j].from
		}
		return boundToKeys[i].to < boundToKeys[j].to
	})
	for _, key := range boundToKeys {
		records := make([]string, 0, len(boundToEvidenceRecords[key]))
		for record := range boundToEvidenceRecords[key] {
			records = append(records, record)
		}
		sort.Strings(records)
		desired.addEdge(graph.NewEdge(graph.BoundTo, key.from, key.to, aggregatedBoundToEvidence(records)))
	}

	roleIDs := make([]graph.NodeID, 0, len(reachableRoles))
	for id := range reachableRoles {
		roleIDs = append(roleIDs, id)
	}
	sort.Slice(roleIDs, func(i, j int) bool {
		return roleIDs[i] < roleIDs[j]
	})
	for _, roleID := range roleIDs {
		role := reachableRoles[roleID]
		for _, rule := range role.rules {
			if len(rule.NonResourceURLs) > 0 || len(rule.Resources) == 0 {
				continue
			}
			permission, hash, err := permissionNode(rule)
			if err != nil {
				return desiredGraph{}, fmt.Errorf("canonicalize permission for %s %s: %w", role.kind, role.node.Name, err)
			}
			desired.addNode(permission)
			desired.addEdge(graph.NewEdge(graph.GrantsPermission, role.node.ID, permission.ID, grantsPermissionEvidence(role, hash)))
		}
	}

	return desired, nil
}

func (d desiredGraph) addNode(node graph.Node) {
	if _, exists := d.nodes[node.ID]; exists {
		return
	}
	d.nodes[node.ID] = node
}

func (d desiredGraph) addEdge(edge graph.Edge) {
	if _, exists := d.edges[edge.ID]; exists {
		return
	}
	d.edges[edge.ID] = edge
}

func addDesiredRBACGraph(g *graph.Graph, desired desiredGraph) error {
	nodes := make([]graph.Node, 0, len(desired.nodes))
	for _, node := range desired.nodes {
		nodes = append(nodes, node)
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].ID < nodes[j].ID
	})
	for _, node := range nodes {
		if _, err := g.AddNode(node); err != nil {
			return fmt.Errorf("add RBAC node %s %s: %w", node.Kind, node.Name, err)
		}
	}

	edges := make([]graph.Edge, 0, len(desired.edges))
	for _, edge := range desired.edges {
		edges = append(edges, edge)
	}
	sort.Slice(edges, func(i, j int) bool {
		return edges[i].ID < edges[j].ID
	})
	for _, edge := range edges {
		if _, err := g.AddEdge(edge); err != nil {
			return fmt.Errorf("add RBAC edge %s %s -> %s: %w", edge.Kind, edge.From, edge.To, err)
		}
	}
	return nil
}

func indexRoles(roles []parserkubernetes.Role) map[namespacedName]parserkubernetes.Role {
	index := make(map[namespacedName]parserkubernetes.Role, len(roles))
	for _, role := range roles {
		key := namespacedName{namespace: role.Namespace, name: role.Name}
		if _, exists := index[key]; exists {
			continue
		}
		index[key] = role
	}
	return index
}

func indexClusterRoles(clusterRoles []parserkubernetes.ClusterRole) map[string]parserkubernetes.ClusterRole {
	index := make(map[string]parserkubernetes.ClusterRole, len(clusterRoles))
	for _, role := range clusterRoles {
		if _, exists := index[role.Name]; exists {
			continue
		}
		index[role.Name] = role
	}
	return index
}

func resolveSupportedBindings(roleBindings []parserkubernetes.RoleBinding, clusterRoleBindings []parserkubernetes.ClusterRoleBinding, roles map[namespacedName]parserkubernetes.Role, clusterRoles map[string]parserkubernetes.ClusterRole) []resolvedBinding {
	var resolved []resolvedBinding
	for _, binding := range roleBindings {
		if binding.RoleRef.APIGroup != rbacAPIGroup || (binding.RoleRef.Kind != "Role" && binding.RoleRef.Kind != "ClusterRole") {
			continue
		}
		subjects := explicitServiceAccountSubjects(binding.Subjects)
		if len(subjects) == 0 {
			continue
		}

		var roleNode graph.Node
		var roleSource *parserkubernetes.Source
		var rules []parserkubernetes.PolicyRule
		unresolved := false
		roleKind := binding.RoleRef.Kind
		switch binding.RoleRef.Kind {
		case "Role":
			key := namespacedName{namespace: binding.Namespace, name: binding.RoleRef.Name}
			if role, ok := roles[key]; ok {
				roleNode = graph.NewNode(graph.Role, roleName(role.Namespace, role.Name))
				roleNode.Evidence = []graph.SourceEvidence{sourceEvidence(role.Source, "observed kubernetes Role")}
				source := role.Source
				roleSource = &source
				rules = role.Rules
			} else {
				roleNode = graph.NewNode(graph.Role, roleName(binding.Namespace, binding.RoleRef.Name))
				roleNode.Evidence = []graph.SourceEvidence{unresolvedRoleEvidence(binding.Source, "RoleBinding", binding.RoleRef)}
				unresolved = true
			}
		case "ClusterRole":
			if role, ok := clusterRoles[binding.RoleRef.Name]; ok {
				roleNode = graph.NewNode(graph.Role, clusterRoleName(role.Name))
				roleNode.Evidence = []graph.SourceEvidence{sourceEvidence(role.Source, "observed kubernetes ClusterRole")}
				source := role.Source
				roleSource = &source
				rules = role.Rules
			} else {
				roleNode = graph.NewNode(graph.Role, clusterRoleName(binding.RoleRef.Name))
				roleNode.Evidence = []graph.SourceEvidence{unresolvedRoleEvidence(binding.Source, "RoleBinding", binding.RoleRef)}
				unresolved = true
			}
		}

		for _, subject := range subjects {
			resolved = append(resolved, resolvedBinding{
				subject:     subject,
				role:        roleNode,
				roleKind:    roleKind,
				roleSource:  roleSource,
				rules:       rules,
				binding:     binding.Source,
				bindingKind: "RoleBinding",
				bindingName: binding.Name,
				scopeKind:   "namespace",
				scopeName:   binding.Namespace,
				unresolved:  unresolved,
			})
		}
	}

	for _, binding := range clusterRoleBindings {
		if binding.RoleRef.APIGroup != rbacAPIGroup || binding.RoleRef.Kind != "ClusterRole" {
			continue
		}
		subjects := explicitServiceAccountSubjects(binding.Subjects)
		if len(subjects) == 0 {
			continue
		}

		roleKind := "ClusterRole"
		var roleNode graph.Node
		var roleSource *parserkubernetes.Source
		var rules []parserkubernetes.PolicyRule
		unresolved := false
		if role, ok := clusterRoles[binding.RoleRef.Name]; ok {
			roleNode = graph.NewNode(graph.Role, clusterRoleName(role.Name))
			roleNode.Evidence = []graph.SourceEvidence{sourceEvidence(role.Source, "observed kubernetes ClusterRole")}
			source := role.Source
			roleSource = &source
			rules = role.Rules
		} else {
			roleNode = graph.NewNode(graph.Role, clusterRoleName(binding.RoleRef.Name))
			roleNode.Evidence = []graph.SourceEvidence{unresolvedRoleEvidence(binding.Source, "ClusterRoleBinding", binding.RoleRef)}
			unresolved = true
		}

		for _, subject := range subjects {
			resolved = append(resolved, resolvedBinding{
				subject:     subject,
				role:        roleNode,
				roleKind:    roleKind,
				roleSource:  roleSource,
				rules:       rules,
				binding:     binding.Source,
				bindingKind: "ClusterRoleBinding",
				bindingName: binding.Name,
				scopeKind:   "cluster",
				unresolved:  unresolved,
			})
		}
	}

	sort.Slice(resolved, func(i, j int) bool {
		return resolvedBindingLess(resolved[i], resolved[j])
	})
	return resolved
}

func explicitServiceAccountSubjects(subjects []parserkubernetes.Subject) []parserkubernetes.Subject {
	var explicit []parserkubernetes.Subject
	for _, subject := range subjects {
		if subject.Kind != "ServiceAccount" || subject.Namespace == "" || subject.Name == "" {
			continue
		}
		explicit = append(explicit, subject)
	}
	sort.Slice(explicit, func(i, j int) bool {
		if explicit[i].Namespace != explicit[j].Namespace {
			return explicit[i].Namespace < explicit[j].Namespace
		}
		return explicit[i].Name < explicit[j].Name
	})
	return explicit
}

func resolvedBindingLess(a, b resolvedBinding) bool {
	if a.bindingKind != b.bindingKind {
		return a.bindingKind < b.bindingKind
	}
	if a.scopeKind != b.scopeKind {
		return a.scopeKind < b.scopeKind
	}
	if a.scopeName != b.scopeName {
		return a.scopeName < b.scopeName
	}
	if a.subject.Namespace != b.subject.Namespace {
		return a.subject.Namespace < b.subject.Namespace
	}
	if a.subject.Name != b.subject.Name {
		return a.subject.Name < b.subject.Name
	}
	if a.role.ID != b.role.ID {
		return a.role.ID < b.role.ID
	}
	return sourceLess(a.binding, b.binding)
}

func roleName(namespace, name string) string {
	return "kubernetes://" + namespace + "/role/" + name
}

func clusterRoleName(name string) string {
	return "kubernetes://cluster/clusterrole/" + name
}

func permissionNode(rule parserkubernetes.PolicyRule) (graph.Node, string, error) {
	canonical := canonicalPermission{
		APIGroups:     canonicalStrings(rule.APIGroups),
		Resources:     canonicalStrings(rule.Resources),
		ResourceNames: canonicalStrings(rule.ResourceNames),
		Verbs:         canonicalStrings(rule.Verbs),
	}
	data, err := json.Marshal(canonical)
	if err != nil {
		return graph.Node{}, "", err
	}
	hashBytes := sha256.Sum256(data)
	hash := hex.EncodeToString(hashBytes[:])
	node := graph.NewNode(graph.Permission, "kubernetes://permission/"+hash)
	node.Evidence = []graph.SourceEvidence{{
		Source: "canonical permission sha256:" + hash,
		Detail: "kubernetes RBAC Permission " + string(data),
	}}
	return node, hash, nil
}

func canonicalStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	values = append([]string(nil), values...)
	sort.Strings(values)
	out := values[:0]
	for _, value := range values {
		if len(out) > 0 && out[len(out)-1] == value {
			continue
		}
		out = append(out, value)
	}
	return out
}

func rbacInferredServiceAccountEvidence(source parserkubernetes.Source, bindingKind string, subject parserkubernetes.Subject) graph.SourceEvidence {
	return graph.SourceEvidence{
		Source: fmt.Sprintf("%s %s; subject serviceaccount %s/%s", strings.ToLower(bindingKind), sourceRef(source), subject.Namespace, subject.Name),
		Detail: "inferred kubernetes ServiceAccount from RBAC binding subject",
	}
}

func unresolvedRoleEvidence(source parserkubernetes.Source, bindingKind string, roleRef parserkubernetes.RoleRef) graph.SourceEvidence {
	return graph.SourceEvidence{
		Source: fmt.Sprintf("%s %s; roleRef apiGroup=%s kind=%s name=%s", strings.ToLower(bindingKind), sourceRef(source), roleRef.APIGroup, roleRef.Kind, roleRef.Name),
		Detail: fmt.Sprintf("unresolved kubernetes %s inferred from %s roleRef", roleRef.Kind, bindingKind),
	}
}

func boundToEvidenceRecord(binding resolvedBinding) string {
	parts := []string{
		"binding_kind=" + binding.bindingKind,
		"binding_name=" + binding.bindingName,
		"scope_kind=" + binding.scopeKind,
		"binding_source=" + sourceRef(binding.binding),
	}
	if binding.bindingKind == "RoleBinding" {
		parts = append(parts,
			"binding_namespace="+binding.scopeName,
			"scope_name="+binding.scopeName,
		)
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func aggregatedBoundToEvidence(records []string) graph.SourceEvidence {
	return graph.SourceEvidence{
		Source: "kubernetes RBAC bindings: " + strings.Join(records, " | "),
		Detail: strings.Join(records, " | "),
	}
}

func grantsPermissionEvidence(role observedRole, permissionHash string) graph.SourceEvidence {
	return graph.SourceEvidence{
		Source: fmt.Sprintf("%s %s; permission sha256:%s", strings.ToLower(role.kind), sourceRef(role.source), permissionHash),
		Detail: "kubernetes RBAC role rule grants permission",
	}
}

func addDeploymentServiceAccounts(g *graph.Graph, deployments []parserkubernetes.Deployment, serviceAccounts []parserkubernetes.ServiceAccount) error {
	serviceAccountByName := indexServiceAccounts(serviceAccounts)
	inferredEvidence := inferredServiceAccountEvidenceByName(deployments, serviceAccountByName)

	for _, deployment := range deployments {
		workload := graph.NewNode(graph.Workload, workloadName(deployment))
		workload.Evidence = []graph.SourceEvidence{sourceEvidence(deployment.Source, "kubernetes Deployment")}
		addedWorkload, err := g.AddNode(workload)
		if err != nil {
			return fmt.Errorf("add workload for deployment %s/%s: %w", deployment.Namespace, deployment.Name, err)
		}

		key := namespacedName{namespace: deployment.Namespace, name: deployment.ServiceAccountName}
		serviceAccountNode := graph.NewNode(graph.ServiceAccount, serviceAccountName(key.namespace, key.name))
		if serviceAccount, ok := serviceAccountByName[key]; ok {
			serviceAccountNode.Evidence = []graph.SourceEvidence{sourceEvidence(serviceAccount.Source, "observed kubernetes ServiceAccount")}
		} else {
			serviceAccountNode.Evidence = inferredEvidence[key]
		}
		addedServiceAccount, err := g.AddNode(serviceAccountNode)
		if err != nil {
			return fmt.Errorf("add service account for deployment %s/%s: %w", deployment.Namespace, deployment.Name, err)
		}

		var evidence graph.SourceEvidence
		if serviceAccount, ok := serviceAccountByName[key]; ok {
			evidence = observedRunsAsEvidence(deployment.Source, serviceAccount.Source)
		} else {
			evidence = inferredRunsAsEvidence(deployment)
		}
		edge := graph.NewEdge(graph.RunsAs, addedWorkload.ID, addedServiceAccount.ID, evidence)
		if _, err := g.AddEdge(edge); err != nil {
			return fmt.Errorf("add runs-as from deployment %s/%s to service account %s/%s: %w", deployment.Namespace, deployment.Name, key.namespace, key.name, err)
		}
	}

	return nil
}

func inferredServiceAccountEvidenceByName(deployments []parserkubernetes.Deployment, observed map[namespacedName]parserkubernetes.ServiceAccount) map[namespacedName][]graph.SourceEvidence {
	evidence := make(map[namespacedName][]graph.SourceEvidence)
	seen := make(map[namespacedName]map[graph.SourceEvidence]struct{})
	for _, deployment := range deployments {
		key := namespacedName{namespace: deployment.Namespace, name: deployment.ServiceAccountName}
		if _, ok := observed[key]; ok {
			continue
		}
		item := inferredServiceAccountEvidence(deployment)
		if seen[key] == nil {
			seen[key] = make(map[graph.SourceEvidence]struct{})
		}
		if _, exists := seen[key][item]; exists {
			continue
		}
		seen[key][item] = struct{}{}
		evidence[key] = append(evidence[key], item)
	}
	return evidence
}

func addIngressRoutes(g *graph.Graph, ingresses []parserkubernetes.Ingress, services []parserkubernetes.Service, deployments []parserkubernetes.Deployment) error {
	serviceByName := indexServices(services)
	routeGroups := make(map[string]ingressRouteGroup)

	for _, ingress := range ingresses {
		endpoint := graph.NewNode(graph.PublicEndpoint, ingressEndpointName(ingress))
		endpoint.Evidence = []graph.SourceEvidence{sourceEvidence(ingress.Source, "kubernetes Ingress")}

		for _, backend := range canonicalIngressBackends(ingress.Backends) {
			service, ok := serviceByName[namespacedName{namespace: ingress.Namespace, name: backend.ServiceName}]
			if !ok {
				continue
			}

			for _, deployment := range matchingDeployments(service, deployments) {
				workload := graph.NewNode(graph.Workload, workloadName(deployment))
				workload.Evidence = []graph.SourceEvidence{sourceEvidence(deployment.Source, "kubernetes Deployment")}
				key := string(endpoint.ID) + "\x00" + string(workload.ID)
				group := routeGroups[key]
				if group.endpoint.ID == "" {
					group.endpoint = endpoint
					group.workload = workload
				}
				group.chains = append(group.chains, ingressRouteEvidenceChain(ingress.Source, backend, service.Source, deployment.Source))
				routeGroups[key] = group
			}
		}
	}

	for _, ingress := range ingresses {
		endpoint := graph.NewNode(graph.PublicEndpoint, ingressEndpointName(ingress))
		endpoint.Evidence = []graph.SourceEvidence{sourceEvidence(ingress.Source, "kubernetes Ingress")}
		if _, err := g.AddNode(endpoint); err != nil {
			return fmt.Errorf("add public endpoint for ingress %s/%s: %w", ingress.Namespace, ingress.Name, err)
		}
	}

	keys := make([]string, 0, len(routeGroups))
	for key := range routeGroups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		group := routeGroups[key]
		addedEndpoint, err := g.AddNode(group.endpoint)
		if err != nil {
			return fmt.Errorf("add public endpoint for ingress route %s: %w", group.endpoint.Name, err)
		}
		addedWorkload, err := g.AddNode(group.workload)
		if err != nil {
			return fmt.Errorf("add workload for ingress route %s: %w", group.workload.Name, err)
		}

		chains := dedupeSortedStrings(group.chains)
		edge := graph.NewEdge(graph.RoutesTo, addedEndpoint.ID, addedWorkload.ID, ingressRouteEvidence(chains))
		if _, err := g.AddEdge(edge); err != nil {
			return fmt.Errorf("add route from ingress %s to workload %s: %w", addedEndpoint.Name, addedWorkload.Name, err)
		}
	}

	return nil
}

func indexServices(services []parserkubernetes.Service) map[namespacedName]parserkubernetes.Service {
	index := make(map[namespacedName]parserkubernetes.Service, len(services))
	for _, service := range services {
		key := namespacedName{namespace: service.Namespace, name: service.Name}
		if _, exists := index[key]; exists {
			continue
		}
		index[key] = service
	}
	return index
}

func indexServiceAccounts(serviceAccounts []parserkubernetes.ServiceAccount) map[namespacedName]parserkubernetes.ServiceAccount {
	index := make(map[namespacedName]parserkubernetes.ServiceAccount, len(serviceAccounts))
	for _, serviceAccount := range serviceAccounts {
		key := namespacedName{namespace: serviceAccount.Namespace, name: serviceAccount.Name}
		if _, exists := index[key]; exists {
			continue
		}
		index[key] = serviceAccount
	}
	return index
}

func uniqueDeployments(deployments []parserkubernetes.Deployment) []parserkubernetes.Deployment {
	unique := make([]parserkubernetes.Deployment, 0, len(deployments))
	seen := make(map[namespacedName]struct{}, len(deployments))
	for _, deployment := range deployments {
		key := namespacedName{namespace: deployment.Namespace, name: deployment.Name}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, deployment)
	}
	return unique
}

func uniqueIngresses(ingresses []parserkubernetes.Ingress) []parserkubernetes.Ingress {
	unique := make([]parserkubernetes.Ingress, 0, len(ingresses))
	seen := make(map[namespacedName]struct{}, len(ingresses))
	for _, ingress := range ingresses {
		key := namespacedName{namespace: ingress.Namespace, name: ingress.Name}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, ingress)
	}
	return unique
}

func uniqueServiceAccounts(serviceAccounts []parserkubernetes.ServiceAccount) []parserkubernetes.ServiceAccount {
	unique := make([]parserkubernetes.ServiceAccount, 0, len(serviceAccounts))
	seen := make(map[namespacedName]struct{}, len(serviceAccounts))
	for _, serviceAccount := range serviceAccounts {
		key := namespacedName{namespace: serviceAccount.Namespace, name: serviceAccount.Name}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, serviceAccount)
	}
	return unique
}

func uniqueRoles(roles []parserkubernetes.Role) []parserkubernetes.Role {
	unique := make([]parserkubernetes.Role, 0, len(roles))
	seen := make(map[namespacedName]struct{}, len(roles))
	for _, role := range roles {
		key := namespacedName{namespace: role.Namespace, name: role.Name}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, role)
	}
	return unique
}

func uniqueClusterRoles(clusterRoles []parserkubernetes.ClusterRole) []parserkubernetes.ClusterRole {
	unique := make([]parserkubernetes.ClusterRole, 0, len(clusterRoles))
	seen := make(map[string]struct{}, len(clusterRoles))
	for _, role := range clusterRoles {
		if _, exists := seen[role.Name]; exists {
			continue
		}
		seen[role.Name] = struct{}{}
		unique = append(unique, role)
	}
	return unique
}

func uniqueRoleBindings(roleBindings []parserkubernetes.RoleBinding) []parserkubernetes.RoleBinding {
	unique := make([]parserkubernetes.RoleBinding, 0, len(roleBindings))
	seen := make(map[namespacedName]struct{}, len(roleBindings))
	for _, binding := range roleBindings {
		key := namespacedName{namespace: binding.Namespace, name: binding.Name}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, binding)
	}
	return unique
}

func uniqueClusterRoleBindings(clusterRoleBindings []parserkubernetes.ClusterRoleBinding) []parserkubernetes.ClusterRoleBinding {
	unique := make([]parserkubernetes.ClusterRoleBinding, 0, len(clusterRoleBindings))
	seen := make(map[string]struct{}, len(clusterRoleBindings))
	for _, binding := range clusterRoleBindings {
		if _, exists := seen[binding.Name]; exists {
			continue
		}
		seen[binding.Name] = struct{}{}
		unique = append(unique, binding)
	}
	return unique
}

func ingressRouteEvidenceChain(ingressSource parserkubernetes.Source, backend parserkubernetes.IngressBackend, serviceSource, deploymentSource parserkubernetes.Source) string {
	return fmt.Sprintf("ingress %s; backend %s %s; service %s; deployment %s", sourceRef(ingressSource), backend.Kind, backend.ServiceName, sourceRef(serviceSource), sourceRef(deploymentSource))
}

func dedupeSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	values = append([]string(nil), values...)
	sort.Strings(values)
	deduped := values[:0]
	for _, value := range values {
		if len(deduped) > 0 && deduped[len(deduped)-1] == value {
			continue
		}
		deduped = append(deduped, value)
	}
	return deduped
}

func validateNoConflictingDuplicates(services []parserkubernetes.Service, deployments []parserkubernetes.Deployment, ingresses []parserkubernetes.Ingress, serviceAccounts []parserkubernetes.ServiceAccount, roles []parserkubernetes.Role, clusterRoles []parserkubernetes.ClusterRole, roleBindings []parserkubernetes.RoleBinding, clusterRoleBindings []parserkubernetes.ClusterRoleBinding) error {
	if err := validateDuplicateServices(services); err != nil {
		return err
	}
	if err := validateDuplicateDeployments(deployments); err != nil {
		return err
	}
	if err := validateDuplicateIngresses(ingresses); err != nil {
		return err
	}
	if err := validateDuplicateServiceAccounts(serviceAccounts); err != nil {
		return err
	}
	if err := validateDuplicateRoles(roles); err != nil {
		return err
	}
	if err := validateDuplicateClusterRoles(clusterRoles); err != nil {
		return err
	}
	if err := validateDuplicateRoleBindings(roleBindings); err != nil {
		return err
	}
	if err := validateDuplicateClusterRoleBindings(clusterRoleBindings); err != nil {
		return err
	}
	return nil
}

func validateDuplicateServices(services []parserkubernetes.Service) error {
	var previous parserkubernetes.Service
	for i, service := range services {
		if i == 0 || service.Namespace != previous.Namespace || service.Name != previous.Name {
			previous = service
			continue
		}
		if normalizedServiceType(service.Type) != normalizedServiceType(previous.Type) || !stringMapsEqual(service.Selector, previous.Selector) {
			return duplicateConflictError("Service", service.Namespace, service.Name, previous.Source, service.Source)
		}
	}
	return nil
}

func validateDuplicateDeployments(deployments []parserkubernetes.Deployment) error {
	var previous parserkubernetes.Deployment
	for i, deployment := range deployments {
		if i == 0 || deployment.Namespace != previous.Namespace || deployment.Name != previous.Name {
			previous = deployment
			continue
		}
		if !stringMapsEqual(deployment.PodLabels, previous.PodLabels) || deployment.ServiceAccountName != previous.ServiceAccountName {
			return duplicateConflictError("Deployment", deployment.Namespace, deployment.Name, previous.Source, deployment.Source)
		}
	}
	return nil
}

func validateDuplicateIngresses(ingresses []parserkubernetes.Ingress) error {
	var previous parserkubernetes.Ingress
	var previousBackends []parserkubernetes.IngressBackend
	for i, ingress := range ingresses {
		currentBackends := canonicalIngressBackends(ingress.Backends)
		if i == 0 || ingress.Namespace != previous.Namespace || ingress.Name != previous.Name {
			previous = ingress
			previousBackends = currentBackends
			continue
		}
		if !ingressBackendsEqual(currentBackends, previousBackends) {
			return duplicateConflictError("Ingress", ingress.Namespace, ingress.Name, previous.Source, ingress.Source)
		}
	}
	return nil
}

func validateDuplicateServiceAccounts(serviceAccounts []parserkubernetes.ServiceAccount) error {
	var previous parserkubernetes.ServiceAccount
	for i, serviceAccount := range serviceAccounts {
		if i == 0 || serviceAccount.Namespace != previous.Namespace || serviceAccount.Name != previous.Name {
			previous = serviceAccount
			continue
		}
		if !boolPointersEqual(serviceAccount.AutomountServiceAccountToken, previous.AutomountServiceAccountToken) {
			return duplicateConflictError("ServiceAccount", serviceAccount.Namespace, serviceAccount.Name, previous.Source, serviceAccount.Source)
		}
	}
	return nil
}

func validateDuplicateRoles(roles []parserkubernetes.Role) error {
	var previous parserkubernetes.Role
	for i, role := range roles {
		if i == 0 || role.Namespace != previous.Namespace || role.Name != previous.Name {
			previous = role
			continue
		}
		if !policyRulesEqual(role.Rules, previous.Rules) {
			return duplicateConflictError("Role", role.Namespace, role.Name, previous.Source, role.Source)
		}
	}
	return nil
}

func validateDuplicateClusterRoles(clusterRoles []parserkubernetes.ClusterRole) error {
	var previous parserkubernetes.ClusterRole
	for i, role := range clusterRoles {
		if i == 0 || role.Name != previous.Name {
			previous = role
			continue
		}
		if !policyRulesEqual(role.Rules, previous.Rules) {
			return duplicateClusterConflictError("ClusterRole", role.Name, previous.Source, role.Source)
		}
	}
	return nil
}

func validateDuplicateRoleBindings(roleBindings []parserkubernetes.RoleBinding) error {
	var previous parserkubernetes.RoleBinding
	for i, binding := range roleBindings {
		if i == 0 || binding.Namespace != previous.Namespace || binding.Name != previous.Name {
			previous = binding
			continue
		}
		if binding.RoleRef != previous.RoleRef || !subjectsEqual(binding.Subjects, previous.Subjects) {
			return duplicateConflictError("RoleBinding", binding.Namespace, binding.Name, previous.Source, binding.Source)
		}
	}
	return nil
}

func validateDuplicateClusterRoleBindings(clusterRoleBindings []parserkubernetes.ClusterRoleBinding) error {
	var previous parserkubernetes.ClusterRoleBinding
	for i, binding := range clusterRoleBindings {
		if i == 0 || binding.Name != previous.Name {
			previous = binding
			continue
		}
		if binding.RoleRef != previous.RoleRef || !subjectsEqual(binding.Subjects, previous.Subjects) {
			return duplicateClusterConflictError("ClusterRoleBinding", binding.Name, previous.Source, binding.Source)
		}
	}
	return nil
}

func duplicateConflictError(kind, namespace, name string, first, second parserkubernetes.Source) error {
	return fmt.Errorf("conflicting Kubernetes %s %s/%s: %s differs from %s", kind, namespace, name, sourceRef(first), sourceRef(second))
}

func duplicateClusterConflictError(kind, name string, first, second parserkubernetes.Source) error {
	return fmt.Errorf("conflicting Kubernetes %s %s: %s differs from %s", kind, name, sourceRef(first), sourceRef(second))
}

func sourceRef(source parserkubernetes.Source) string {
	return fmt.Sprintf("%s#document=%d", source.Filename, source.Document)
}

func normalizedServiceType(serviceType string) string {
	if serviceType == "" {
		return "ClusterIP"
	}
	return serviceType
}

func stringMapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		otherValue, exists := b[key]
		if !exists || otherValue != value {
			return false
		}
	}
	return true
}

func boolPointersEqual(a, b *bool) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func policyRulesEqual(a, b []parserkubernetes.PolicyRule) bool {
	a = canonicalPolicyRules(a)
	b = canonicalPolicyRules(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !stringSlicesEqual(a[i].APIGroups, b[i].APIGroups) ||
			!stringSlicesEqual(a[i].Resources, b[i].Resources) ||
			!stringSlicesEqual(a[i].ResourceNames, b[i].ResourceNames) ||
			!stringSlicesEqual(a[i].Verbs, b[i].Verbs) ||
			!stringSlicesEqual(a[i].NonResourceURLs, b[i].NonResourceURLs) {
			return false
		}
	}
	return true
}

func subjectsEqual(a, b []parserkubernetes.Subject) bool {
	a = canonicalSubjects(a)
	b = canonicalSubjects(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func canonicalPolicyRules(rules []parserkubernetes.PolicyRule) []parserkubernetes.PolicyRule {
	if len(rules) == 0 {
		return nil
	}
	canonical := make([]parserkubernetes.PolicyRule, 0, len(rules))
	for _, rule := range rules {
		canonical = append(canonical, parserkubernetes.PolicyRule{
			APIGroups:       canonicalStrings(rule.APIGroups),
			Resources:       canonicalStrings(rule.Resources),
			ResourceNames:   canonicalStrings(rule.ResourceNames),
			Verbs:           canonicalStrings(rule.Verbs),
			NonResourceURLs: canonicalStrings(rule.NonResourceURLs),
		})
	}
	sort.Slice(canonical, func(i, j int) bool {
		return policyRuleLess(canonical[i], canonical[j])
	})
	deduped := canonical[:0]
	for _, rule := range canonical {
		if len(deduped) > 0 && policyRuleEqual(rule, deduped[len(deduped)-1]) {
			continue
		}
		deduped = append(deduped, rule)
	}
	return deduped
}

func canonicalSubjects(subjects []parserkubernetes.Subject) []parserkubernetes.Subject {
	if len(subjects) == 0 {
		return nil
	}
	canonical := append([]parserkubernetes.Subject(nil), subjects...)
	sort.Slice(canonical, func(i, j int) bool {
		if canonical[i].Kind != canonical[j].Kind {
			return canonical[i].Kind < canonical[j].Kind
		}
		if canonical[i].Namespace != canonical[j].Namespace {
			return canonical[i].Namespace < canonical[j].Namespace
		}
		return canonical[i].Name < canonical[j].Name
	})
	deduped := canonical[:0]
	for _, subject := range canonical {
		if len(deduped) > 0 && subject == deduped[len(deduped)-1] {
			continue
		}
		deduped = append(deduped, subject)
	}
	return deduped
}

func policyRuleLess(a, b parserkubernetes.PolicyRule) bool {
	if c := compareStrings(a.APIGroups, b.APIGroups); c != 0 {
		return c < 0
	}
	if c := compareStrings(a.Resources, b.Resources); c != 0 {
		return c < 0
	}
	if c := compareStrings(a.ResourceNames, b.ResourceNames); c != 0 {
		return c < 0
	}
	if c := compareStrings(a.Verbs, b.Verbs); c != 0 {
		return c < 0
	}
	return compareStrings(a.NonResourceURLs, b.NonResourceURLs) < 0
}

func policyRuleEqual(a, b parserkubernetes.PolicyRule) bool {
	return stringSlicesEqual(a.APIGroups, b.APIGroups) &&
		stringSlicesEqual(a.Resources, b.Resources) &&
		stringSlicesEqual(a.ResourceNames, b.ResourceNames) &&
		stringSlicesEqual(a.Verbs, b.Verbs) &&
		stringSlicesEqual(a.NonResourceURLs, b.NonResourceURLs)
}

func compareStrings(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func canonicalIngressBackends(backends []parserkubernetes.IngressBackend) []parserkubernetes.IngressBackend {
	seen := make(map[parserkubernetes.IngressBackend]struct{}, len(backends))
	for _, backend := range backends {
		seen[backend] = struct{}{}
	}

	canonical := make([]parserkubernetes.IngressBackend, 0, len(seen))
	for backend := range seen {
		canonical = append(canonical, backend)
	}
	sort.Slice(canonical, func(i, j int) bool {
		if canonical[i].Kind != canonical[j].Kind {
			return canonical[i].Kind < canonical[j].Kind
		}
		return canonical[i].ServiceName < canonical[j].ServiceName
	})
	return canonical
}

func ingressBackendsEqual(a, b []parserkubernetes.IngressBackend) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sortServices(services []parserkubernetes.Service) {
	sort.SliceStable(services, func(i, j int) bool {
		return serviceLess(services[i], services[j])
	})
}

func sortDeployments(deployments []parserkubernetes.Deployment) {
	sort.SliceStable(deployments, func(i, j int) bool {
		return deploymentLess(deployments[i], deployments[j])
	})
}

func sortIngresses(ingresses []parserkubernetes.Ingress) {
	sort.SliceStable(ingresses, func(i, j int) bool {
		return ingressLess(ingresses[i], ingresses[j])
	})
}

func sortServiceAccounts(serviceAccounts []parserkubernetes.ServiceAccount) {
	sort.SliceStable(serviceAccounts, func(i, j int) bool {
		return serviceAccountLess(serviceAccounts[i], serviceAccounts[j])
	})
}

func sortRoles(roles []parserkubernetes.Role) {
	sort.SliceStable(roles, func(i, j int) bool {
		return roleLess(roles[i], roles[j])
	})
}

func sortClusterRoles(clusterRoles []parserkubernetes.ClusterRole) {
	sort.SliceStable(clusterRoles, func(i, j int) bool {
		return clusterRoleLess(clusterRoles[i], clusterRoles[j])
	})
}

func sortRoleBindings(roleBindings []parserkubernetes.RoleBinding) {
	sort.SliceStable(roleBindings, func(i, j int) bool {
		return roleBindingLess(roleBindings[i], roleBindings[j])
	})
}

func sortClusterRoleBindings(clusterRoleBindings []parserkubernetes.ClusterRoleBinding) {
	sort.SliceStable(clusterRoleBindings, func(i, j int) bool {
		return clusterRoleBindingLess(clusterRoleBindings[i], clusterRoleBindings[j])
	})
}

func serviceLess(a, b parserkubernetes.Service) bool {
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return sourceLess(a.Source, b.Source)
}

func deploymentLess(a, b parserkubernetes.Deployment) bool {
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return sourceLess(a.Source, b.Source)
}

func ingressLess(a, b parserkubernetes.Ingress) bool {
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return sourceLess(a.Source, b.Source)
}

func serviceAccountLess(a, b parserkubernetes.ServiceAccount) bool {
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return sourceLess(a.Source, b.Source)
}

func roleLess(a, b parserkubernetes.Role) bool {
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return sourceLess(a.Source, b.Source)
}

func clusterRoleLess(a, b parserkubernetes.ClusterRole) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return sourceLess(a.Source, b.Source)
}

func roleBindingLess(a, b parserkubernetes.RoleBinding) bool {
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return sourceLess(a.Source, b.Source)
}

func clusterRoleBindingLess(a, b parserkubernetes.ClusterRoleBinding) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return sourceLess(a.Source, b.Source)
}

func sourceLess(a, b parserkubernetes.Source) bool {
	if a.Filename != b.Filename {
		return a.Filename < b.Filename
	}
	return a.Document < b.Document
}
