package kubernetes

import (
	"fmt"
	"sort"

	"pathproof/internal/graph"
	parserkubernetes "pathproof/internal/parser/kubernetes"
)

func AddRoutes(g *graph.Graph, resources parserkubernetes.Resources) error {
	services := append([]parserkubernetes.Service(nil), resources.Services...)
	deployments := append([]parserkubernetes.Deployment(nil), resources.Deployments...)
	sortServices(services)
	sortDeployments(deployments)
	if err := validateNoConflictingDuplicates(services, deployments); err != nil {
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

		if len(service.Selector) == 0 {
			continue
		}

		for _, deployment := range deployments {
			if deployment.Namespace != service.Namespace || !selectorMatches(service.Selector, deployment.PodLabels) {
				continue
			}

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

	return nil
}

func endpointName(service parserkubernetes.Service) string {
	return "kubernetes://" + service.Namespace + "/service/" + service.Name
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

func validateNoConflictingDuplicates(services []parserkubernetes.Service, deployments []parserkubernetes.Deployment) error {
	if err := validateDuplicateServices(services); err != nil {
		return err
	}
	if err := validateDuplicateDeployments(deployments); err != nil {
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

func sourceLess(a, b parserkubernetes.Source) bool {
	if a.Filename != b.Filename {
		return a.Filename < b.Filename
	}
	return a.Document < b.Document
}
