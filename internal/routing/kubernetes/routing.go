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
	sortServices(services)
	sortDeployments(deployments)
	sortIngresses(ingresses)
	if err := validateNoConflictingDuplicates(services, deployments, ingresses); err != nil {
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

func validateNoConflictingDuplicates(services []parserkubernetes.Service, deployments []parserkubernetes.Deployment, ingresses []parserkubernetes.Ingress) error {
	if err := validateDuplicateServices(services); err != nil {
		return err
	}
	if err := validateDuplicateDeployments(deployments); err != nil {
		return err
	}
	if err := validateDuplicateIngresses(ingresses); err != nil {
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
		if !stringMapsEqual(deployment.PodLabels, previous.PodLabels) {
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

func sourceLess(a, b parserkubernetes.Source) bool {
	if a.Filename != b.Filename {
		return a.Filename < b.Filename
	}
	return a.Document < b.Document
}
