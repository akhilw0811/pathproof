package kubernetes

import (
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
	sortServices(services)
	sortDeployments(deployments)
	sortIngresses(ingresses)
	sortServiceAccounts(serviceAccounts)
	if err := validateNoConflictingDuplicates(services, deployments, ingresses, serviceAccounts); err != nil {
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

func validateNoConflictingDuplicates(services []parserkubernetes.Service, deployments []parserkubernetes.Deployment, ingresses []parserkubernetes.Ingress, serviceAccounts []parserkubernetes.ServiceAccount) error {
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

func duplicateConflictError(kind, namespace, name string, first, second parserkubernetes.Source) error {
	return fmt.Errorf("conflicting Kubernetes %s %s/%s: %s differs from %s", kind, namespace, name, sourceRef(first), sourceRef(second))
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

func sourceLess(a, b parserkubernetes.Source) bool {
	if a.Filename != b.Filename {
		return a.Filename < b.Filename
	}
	return a.Document < b.Document
}
