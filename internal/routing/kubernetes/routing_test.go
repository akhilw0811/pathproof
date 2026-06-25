package kubernetes

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"pathproof/internal/graph"
	parserkubernetes "pathproof/internal/parser/kubernetes"
)

func TestAddRoutesLoadBalancerServiceCreatesRouteToWorkload(t *testing.T) {
	g := graph.New()
	resources := routeResources("LoadBalancer")

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	nodes := g.Nodes()
	edges := g.Edges()
	if len(nodes) != 2 {
		t.Fatalf("node count = %d, want 2: %#v", len(nodes), nodes)
	}
	if len(edges) != 1 {
		t.Fatalf("edge count = %d, want 1: %#v", len(edges), edges)
	}
	if edges[0].Kind != graph.RoutesTo {
		t.Fatalf("edge kind = %q, want %q", edges[0].Kind, graph.RoutesTo)
	}

	endpoint := graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/public-api")
	workload := graph.NewNode(graph.Workload, "kubernetes://prod/deployment/api")
	if _, ok := g.Node(endpoint.ID); !ok {
		t.Fatalf("endpoint node %q not found", endpoint.ID)
	}
	if _, ok := g.Node(workload.ID); !ok {
		t.Fatalf("workload node %q not found", workload.ID)
	}
	if edges[0].From != endpoint.ID || edges[0].To != workload.ID {
		t.Fatalf("edge endpoints = %q -> %q, want %q -> %q", edges[0].From, edges[0].To, endpoint.ID, workload.ID)
	}
}

func TestAddRoutesNodePortServiceCreatesRouteToWorkload(t *testing.T) {
	g := graph.New()

	if err := AddRoutes(g, routeResources("NodePort")); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 2, 1, 1)
}

func TestAddRoutesClusterIPServiceCreatesNoPublicEndpoint(t *testing.T) {
	g := graph.New()

	if err := AddRoutes(g, routeResources("ClusterIP")); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 0, 0, 0)
}

func TestAddRoutesPublicServiceWithNoMatchingDeploymentCreatesOnlyEndpoint(t *testing.T) {
	g := graph.New()
	resources := routeResources("LoadBalancer")
	resources.Deployments[0].PodLabels = map[string]string{"app": "worker"}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 1, 0, 0)
}

func TestAddRoutesUnmatchedDeploymentIsNotAddedAsWorkload(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Deployments: []parserkubernetes.Deployment{deployment("prod", "api", map[string]string{"app": "api"}, "deployment.yaml", 1)},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 0, 0, 0)
}

func TestAddRoutesSelectorMismatchCreatesNoEdge(t *testing.T) {
	g := graph.New()
	resources := routeResources("LoadBalancer")
	resources.Services[0].Selector = map[string]string{"app": "web"}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 1, 0, 0)
}

func TestAddRoutesNamespaceMismatchCreatesNoEdge(t *testing.T) {
	g := graph.New()
	resources := routeResources("LoadBalancer")
	resources.Deployments[0].Namespace = "staging"

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 1, 0, 0)
}

func TestAddRoutesEmptyServiceSelectorCreatesNoEdge(t *testing.T) {
	g := graph.New()
	resources := routeResources("LoadBalancer")
	resources.Services[0].Selector = nil

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 1, 0, 0)
}

func TestAddRoutesSelectorMatchingMultipleDeploymentsCreatesOneEdgePerDeployment(t *testing.T) {
	g := graph.New()
	resources := routeResources("LoadBalancer")
	resources.Deployments = append(resources.Deployments,
		deployment("prod", "api-canary", map[string]string{"app": "api"}, "deployment-canary.yaml", 1),
	)

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 3, 2, 2)
}

func TestAddRoutesDeploymentWithAdditionalLabelsMatches(t *testing.T) {
	g := graph.New()
	resources := routeResources("LoadBalancer")
	resources.Deployments[0].PodLabels = map[string]string{"app": "api", "tier": "backend"}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 2, 1, 1)
}

func TestAddRoutesDoesNotMatchDeploymentMetadataLabels(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "resources.yaml", `apiVersion: v1
kind: Service
metadata:
  name: public-api
  namespace: prod
spec:
  type: LoadBalancer
  selector:
    app: api
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
  labels:
    app: api
spec:
  template:
    metadata:
      labels:
        app: worker
`)
	resources, err := parserkubernetes.ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	g := graph.New()

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 1, 0, 0)
}

func TestAddRoutesMatchesTemplateLabelsWhenDeploymentSelectorPresent(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "resources.yaml", `apiVersion: v1
kind: Service
metadata:
  name: public-api
  namespace: prod
spec:
  type: LoadBalancer
  selector:
    app: api
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
  labels:
    app: metadata-only
spec:
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
        tier: backend
`)
	resources, err := parserkubernetes.ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	g := graph.New()

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 2, 1, 1)
}

func TestAddRoutesEvidenceIdentifiesSources(t *testing.T) {
	g := graph.New()

	if err := AddRoutes(g, routeResources("LoadBalancer")); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	endpoint, ok := g.Node(graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/public-api").ID)
	if !ok {
		t.Fatal("endpoint node not found")
	}
	workload, ok := g.Node(graph.NewNode(graph.Workload, "kubernetes://prod/deployment/api").ID)
	if !ok {
		t.Fatal("workload node not found")
	}
	if !reflect.DeepEqual(endpoint.Evidence, []graph.SourceEvidence{{Source: "service.yaml#document=1", Detail: "kubernetes Service"}}) {
		t.Fatalf("endpoint evidence = %#v", endpoint.Evidence)
	}
	if !reflect.DeepEqual(workload.Evidence, []graph.SourceEvidence{{Source: "deployment.yaml#document=1", Detail: "kubernetes Deployment"}}) {
		t.Fatalf("workload evidence = %#v", workload.Evidence)
	}

	edges := g.Edges()
	if len(edges) != 1 {
		t.Fatalf("edge count = %d, want 1", len(edges))
	}
	if !strings.Contains(edges[0].Evidence.Source, "service service.yaml#document=1") ||
		!strings.Contains(edges[0].Evidence.Source, "deployment deployment.yaml#document=1") {
		t.Fatalf("edge evidence source = %q, want service and deployment sources", edges[0].Evidence.Source)
	}
}

func TestAddRoutesRepeatedConstructionIsDeterministic(t *testing.T) {
	forward := parserkubernetes.Resources{
		Services: []parserkubernetes.Service{
			service("prod", "public-api", "LoadBalancer", map[string]string{"app": "api"}, "service.yaml", 1),
			service("prod", "public-worker", "NodePort", map[string]string{"app": "worker"}, "worker-service.yaml", 1),
		},
		Deployments: []parserkubernetes.Deployment{
			deployment("prod", "api", map[string]string{"app": "api"}, "deployment.yaml", 1),
			deployment("prod", "worker", map[string]string{"app": "worker"}, "worker-deployment.yaml", 1),
		},
	}
	reverse := parserkubernetes.Resources{
		Services:    []parserkubernetes.Service{forward.Services[1], forward.Services[0]},
		Deployments: []parserkubernetes.Deployment{forward.Deployments[1], forward.Deployments[0]},
	}

	firstJSON := mustGraphJSON(t, forward)
	secondJSON := mustGraphJSON(t, reverse)
	thirdJSON := mustGraphJSON(t, forward)

	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("json differs by input order:\nfirst:  %s\nsecond: %s", firstJSON, secondJSON)
	}
	if string(firstJSON) != string(thirdJSON) {
		t.Fatalf("json differs across repeated construction:\nfirst: %s\nthird: %s", firstJSON, thirdJSON)
	}
}

func TestAddRoutesDuplicateInputDocumentsDoNotDuplicateRelationships(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Services: []parserkubernetes.Service{
			service("prod", "public-api", "LoadBalancer", map[string]string{"app": "api"}, "z-service.yaml", 2),
			service("prod", "public-api", "LoadBalancer", map[string]string{"app": "api"}, "a-service.yaml", 1),
		},
		Deployments: []parserkubernetes.Deployment{
			deployment("prod", "api", map[string]string{"app": "api"}, "z-deployment.yaml", 2),
			deployment("prod", "api", map[string]string{"app": "api"}, "a-deployment.yaml", 1),
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 2, 1, 1)
	endpoint := mustNode(t, g, graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/public-api").ID)
	workload := mustNode(t, g, graph.NewNode(graph.Workload, "kubernetes://prod/deployment/api").ID)
	if got, want := endpoint.Evidence[0].Source, "a-service.yaml#document=1"; got != want {
		t.Fatalf("endpoint evidence source = %q, want %q", got, want)
	}
	if got, want := workload.Evidence[0].Source, "a-deployment.yaml#document=1"; got != want {
		t.Fatalf("workload evidence source = %q, want %q", got, want)
	}
	if got := g.Edges()[0].Evidence.Source; !strings.Contains(got, "a-service.yaml#document=1") || !strings.Contains(got, "a-deployment.yaml#document=1") {
		t.Fatalf("edge evidence source = %q, want first deterministic service and deployment sources", got)
	}
}

func TestAddRoutesIdenticalDuplicateServicesAreAccepted(t *testing.T) {
	g := graph.New()
	resources := routeResources("LoadBalancer")
	resources.Services = append(resources.Services,
		service("prod", "public-api", "LoadBalancer", map[string]string{"app": "api"}, "service-copy.yaml", 1),
	)

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 2, 1, 1)
}

func TestAddRoutesRejectsDuplicateServiceWithDifferentSelectors(t *testing.T) {
	g := graph.New()
	resources := routeResources("LoadBalancer")
	resources.Services = append(resources.Services,
		service("prod", "public-api", "LoadBalancer", map[string]string{"app": "admin"}, "service-conflict.yaml", 1),
	)

	err := AddRoutes(g, resources)
	if err == nil {
		t.Fatal("add routes error = nil, want duplicate Service conflict")
	}
	assertConflictError(t, err, "Service", "prod/public-api", "service.yaml#document=1", "service-conflict.yaml#document=1")
	assertGraphCounts(t, g, 0, 0, 0)
}

func TestAddRoutesRejectsDuplicateServiceWithDifferentNormalizedTypes(t *testing.T) {
	g := graph.New()
	resources := routeResources("LoadBalancer")
	resources.Services = append(resources.Services,
		service("prod", "public-api", "NodePort", map[string]string{"app": "api"}, "service-conflict.yaml", 1),
	)

	err := AddRoutes(g, resources)
	if err == nil {
		t.Fatal("add routes error = nil, want duplicate Service conflict")
	}
	assertConflictError(t, err, "Service", "prod/public-api", "service.yaml#document=1", "service-conflict.yaml#document=1")
	assertGraphCounts(t, g, 0, 0, 0)
}

func TestAddRoutesIdenticalDuplicateDeploymentsAreAccepted(t *testing.T) {
	g := graph.New()
	resources := routeResources("LoadBalancer")
	resources.Deployments = append(resources.Deployments,
		deployment("prod", "api", map[string]string{"app": "api"}, "deployment-copy.yaml", 1),
	)

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 2, 1, 1)
}

func TestAddRoutesRejectsDuplicateDeploymentWithDifferentPodTemplateLabels(t *testing.T) {
	g := graph.New()
	resources := routeResources("LoadBalancer")
	resources.Deployments = append(resources.Deployments,
		deployment("prod", "api", map[string]string{"app": "admin"}, "deployment-conflict.yaml", 1),
	)

	err := AddRoutes(g, resources)
	if err == nil {
		t.Fatal("add routes error = nil, want duplicate Deployment conflict")
	}
	assertConflictError(t, err, "Deployment", "prod/api", "deployment.yaml#document=1", "deployment-conflict.yaml#document=1")
	assertGraphCounts(t, g, 0, 0, 0)
}

func TestAddRoutesDuplicateMapOrderDoesNotCreateFalseConflict(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Services: []parserkubernetes.Service{
			service("prod", "public-api", "LoadBalancer", map[string]string{"app": "api", "tier": "backend"}, "service.yaml", 1),
			service("prod", "public-api", "LoadBalancer", map[string]string{"tier": "backend", "app": "api"}, "service-copy.yaml", 1),
		},
		Deployments: []parserkubernetes.Deployment{
			deployment("prod", "api", map[string]string{"app": "api", "tier": "backend"}, "deployment.yaml", 1),
			deployment("prod", "api", map[string]string{"tier": "backend", "app": "api"}, "deployment-copy.yaml", 1),
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 2, 1, 1)
}

func TestStringMapsEqualHandlesEmptyValues(t *testing.T) {
	if !stringMapsEqual(map[string]string{"app": ""}, map[string]string{"app": ""}) {
		t.Fatal("identical maps with empty values compare unequal")
	}
	if stringMapsEqual(map[string]string{"app": ""}, map[string]string{"tier": ""}) {
		t.Fatal("maps with different keys and empty values compare equal")
	}
	if stringMapsEqual(map[string]string{"app": ""}, map[string]string{}) {
		t.Fatal("present empty value compares equal to missing key")
	}
}

func TestAddRoutesRejectsDuplicateServiceWithDifferentEmptyValueSelectorKeys(t *testing.T) {
	g := graph.New()
	resources := routeResources("LoadBalancer")
	resources.Services = []parserkubernetes.Service{
		service("prod", "public-api", "LoadBalancer", map[string]string{"app": ""}, "service.yaml", 1),
		service("prod", "public-api", "LoadBalancer", map[string]string{"tier": ""}, "service-conflict.yaml", 1),
	}

	err := AddRoutes(g, resources)
	if err == nil {
		t.Fatal("add routes error = nil, want duplicate Service conflict")
	}
	assertConflictError(t, err, "Service", "prod/public-api", "service.yaml#document=1", "service-conflict.yaml#document=1")
	assertGraphCounts(t, g, 0, 0, 0)
}

func TestAddRoutesRejectsDuplicateDeploymentWithDifferentEmptyValueLabelKeys(t *testing.T) {
	g := graph.New()
	resources := routeResources("LoadBalancer")
	resources.Deployments = []parserkubernetes.Deployment{
		deployment("prod", "api", map[string]string{"app": ""}, "deployment.yaml", 1),
		deployment("prod", "api", map[string]string{"tier": ""}, "deployment-conflict.yaml", 1),
	}

	err := AddRoutes(g, resources)
	if err == nil {
		t.Fatal("add routes error = nil, want duplicate Deployment conflict")
	}
	assertConflictError(t, err, "Deployment", "prod/api", "deployment.yaml#document=1", "deployment-conflict.yaml#document=1")
	assertGraphCounts(t, g, 0, 0, 0)
}

func TestAddRoutesAcceptsIdenticalDuplicateEmptyValueMaps(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Services: []parserkubernetes.Service{
			service("prod", "public-api", "LoadBalancer", map[string]string{"app": ""}, "service.yaml", 1),
			service("prod", "public-api", "LoadBalancer", map[string]string{"app": ""}, "service-copy.yaml", 1),
		},
		Deployments: []parserkubernetes.Deployment{
			deployment("prod", "api", map[string]string{"app": ""}, "deployment.yaml", 1),
			deployment("prod", "api", map[string]string{"app": ""}, "deployment-copy.yaml", 1),
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 2, 1, 1)
}

func TestAddRoutesConflictLeavesPreviouslyPopulatedGraphUnchanged(t *testing.T) {
	g := graph.New()
	if err := AddRoutes(g, routeResources("LoadBalancer")); err != nil {
		t.Fatalf("seed graph: %v", err)
	}
	before := mustMarshalGraph(t, g)

	conflict := routeResources("NodePort")
	conflict.Services = append(conflict.Services,
		service("prod", "public-api", "LoadBalancer", map[string]string{"app": "api"}, "service-conflict.yaml", 1),
	)
	if err := AddRoutes(g, conflict); err == nil {
		t.Fatal("add routes error = nil, want duplicate Service conflict")
	}

	after := mustMarshalGraph(t, g)
	if string(after) != string(before) {
		t.Fatalf("graph changed after failed AddRoutes:\nbefore: %s\nafter:  %s", before, after)
	}
}

func TestAddRoutesConflictingResourcesCannotCreateUnionOfRoutes(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Services: []parserkubernetes.Service{
			service("prod", "public-api", "LoadBalancer", map[string]string{"app": "api"}, "service.yaml", 1),
			service("prod", "public-api", "LoadBalancer", map[string]string{"app": "admin"}, "service-conflict.yaml", 1),
		},
		Deployments: []parserkubernetes.Deployment{
			deployment("prod", "api", map[string]string{"app": "api"}, "deployment-api.yaml", 1),
			deployment("prod", "admin", map[string]string{"app": "admin"}, "deployment-admin.yaml", 1),
		},
	}

	err := AddRoutes(g, resources)
	if err == nil {
		t.Fatal("add routes error = nil, want duplicate Service conflict")
	}
	assertConflictError(t, err, "Service", "prod/public-api", "service.yaml#document=1", "service-conflict.yaml#document=1")
	assertGraphCounts(t, g, 0, 0, 0)
}

func TestAddRoutesFixturePublicRoute(t *testing.T) {
	resources, err := parserkubernetes.ParseDir("testdata/public-route")
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	g := graph.New()

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 2, 1, 1)
}

func routeResources(serviceType string) parserkubernetes.Resources {
	return parserkubernetes.Resources{
		Services: []parserkubernetes.Service{
			service("prod", "public-api", serviceType, map[string]string{"app": "api"}, "service.yaml", 1),
		},
		Deployments: []parserkubernetes.Deployment{
			deployment("prod", "api", map[string]string{"app": "api"}, "deployment.yaml", 1),
		},
	}
}

func service(namespace, name, serviceType string, selector map[string]string, filename string, document int) parserkubernetes.Service {
	return parserkubernetes.Service{
		Namespace: namespace,
		Name:      name,
		Type:      serviceType,
		Selector:  selector,
		Source:    parserkubernetes.Source{Filename: filename, Document: document},
	}
}

func deployment(namespace, name string, podLabels map[string]string, filename string, document int) parserkubernetes.Deployment {
	return parserkubernetes.Deployment{
		Namespace: namespace,
		Name:      name,
		PodLabels: podLabels,
		Source:    parserkubernetes.Source{Filename: filename, Document: document},
	}
}

func assertGraphCounts(t *testing.T, g *graph.Graph, nodes, workloads, edges int) {
	t.Helper()

	gotNodes := g.Nodes()
	if len(gotNodes) != nodes {
		t.Fatalf("node count = %d, want %d: %#v", len(gotNodes), nodes, gotNodes)
	}

	gotWorkloads := 0
	for _, node := range gotNodes {
		if node.Kind == graph.Workload {
			gotWorkloads++
		}
	}
	if gotWorkloads != workloads {
		t.Fatalf("workload count = %d, want %d: %#v", gotWorkloads, workloads, gotNodes)
	}

	gotEdges := g.Edges()
	if len(gotEdges) != edges {
		t.Fatalf("edge count = %d, want %d: %#v", len(gotEdges), edges, gotEdges)
	}
}

func mustGraphJSON(t *testing.T, resources parserkubernetes.Resources) []byte {
	t.Helper()

	g := graph.New()
	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}
	data, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal graph: %v", err)
	}
	return data
}

func mustMarshalGraph(t *testing.T, g *graph.Graph) []byte {
	t.Helper()

	data, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal graph: %v", err)
	}
	return data
}

func mustNode(t *testing.T, g *graph.Graph, id graph.NodeID) graph.Node {
	t.Helper()

	node, ok := g.Node(id)
	if !ok {
		t.Fatalf("node %q not found", id)
	}
	return node
}

func assertConflictError(t *testing.T, err error, kind, name, firstSource, secondSource string) {
	t.Helper()

	message := err.Error()
	for _, want := range []string{kind, name, firstSource, secondSource} {
		if !strings.Contains(message, want) {
			t.Fatalf("error = %q, want to contain %q", message, want)
		}
	}
}

func writeManifest(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write manifest %q: %v", name, err)
	}
	return path
}
