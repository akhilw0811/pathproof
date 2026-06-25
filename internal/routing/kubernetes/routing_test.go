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
	if len(nodes) != 3 {
		t.Fatalf("node count = %d, want 3: %#v", len(nodes), nodes)
	}
	assertEdgeKindCount(t, g, graph.RoutesTo, 1)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)

	endpoint := graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/public-api")
	workload := graph.NewNode(graph.Workload, "kubernetes://prod/deployment/api")
	if _, ok := g.Node(endpoint.ID); !ok {
		t.Fatalf("endpoint node %q not found", endpoint.ID)
	}
	if _, ok := g.Node(workload.ID); !ok {
		t.Fatalf("workload node %q not found", workload.ID)
	}
	routeEdges := edgesOfKind(g, graph.RoutesTo)
	if routeEdges[0].From != endpoint.ID || routeEdges[0].To != workload.ID {
		t.Fatalf("edge endpoints = %q -> %q, want %q -> %q", routeEdges[0].From, routeEdges[0].To, endpoint.ID, workload.ID)
	}
}

func TestAddRoutesNodePortServiceCreatesRouteToWorkload(t *testing.T) {
	g := graph.New()

	if err := AddRoutes(g, routeResources("NodePort")); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 3, 1, 2)
	assertEdgeKindCount(t, g, graph.RoutesTo, 1)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)
}

func TestAddRoutesClusterIPServiceCreatesNoPublicEndpoint(t *testing.T) {
	g := graph.New()

	if err := AddRoutes(g, routeResources("ClusterIP")); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 2, 1, 1)
	assertNodeKindCount(t, g, graph.PublicEndpoint, 0)
	assertEdgeKindCount(t, g, graph.RoutesTo, 0)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)
}

func TestAddRoutesPublicServiceWithNoMatchingDeploymentCreatesOnlyEndpoint(t *testing.T) {
	g := graph.New()
	resources := routeResources("LoadBalancer")
	resources.Deployments[0].PodLabels = map[string]string{"app": "worker"}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 3, 1, 1)
	assertNodeKindCount(t, g, graph.PublicEndpoint, 1)
	assertEdgeKindCount(t, g, graph.RoutesTo, 0)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)
}

func TestAddRoutesUnmatchedDeploymentIsModeledButNotExposed(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Deployments: []parserkubernetes.Deployment{deployment("prod", "api", map[string]string{"app": "api"}, "deployment.yaml", 1)},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 2, 1, 1)
	assertNodeKindCount(t, g, graph.PublicEndpoint, 0)
	assertEdgeKindCount(t, g, graph.RoutesTo, 0)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)
}

func TestAddRoutesSelectorMismatchCreatesNoEdge(t *testing.T) {
	g := graph.New()
	resources := routeResources("LoadBalancer")
	resources.Services[0].Selector = map[string]string{"app": "web"}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 3, 1, 1)
	assertNodeKindCount(t, g, graph.PublicEndpoint, 1)
	assertEdgeKindCount(t, g, graph.RoutesTo, 0)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)
}

func TestAddRoutesNamespaceMismatchCreatesNoEdge(t *testing.T) {
	g := graph.New()
	resources := routeResources("LoadBalancer")
	resources.Deployments[0].Namespace = "staging"

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 3, 1, 1)
	assertNodeKindCount(t, g, graph.PublicEndpoint, 1)
	assertEdgeKindCount(t, g, graph.RoutesTo, 0)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)
}

func TestAddRoutesEmptyServiceSelectorCreatesNoEdge(t *testing.T) {
	g := graph.New()
	resources := routeResources("LoadBalancer")
	resources.Services[0].Selector = nil

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 3, 1, 1)
	assertNodeKindCount(t, g, graph.PublicEndpoint, 1)
	assertEdgeKindCount(t, g, graph.RoutesTo, 0)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)
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

	assertGraphCounts(t, g, 4, 2, 4)
	assertEdgeKindCount(t, g, graph.RoutesTo, 2)
	assertEdgeKindCount(t, g, graph.RunsAs, 2)
}

func TestAddRoutesDeploymentWithAdditionalLabelsMatches(t *testing.T) {
	g := graph.New()
	resources := routeResources("LoadBalancer")
	resources.Deployments[0].PodLabels = map[string]string{"app": "api", "tier": "backend"}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 3, 1, 2)
	assertEdgeKindCount(t, g, graph.RoutesTo, 1)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)
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

	assertGraphCounts(t, g, 3, 1, 1)
	assertNodeKindCount(t, g, graph.PublicEndpoint, 1)
	assertEdgeKindCount(t, g, graph.RoutesTo, 0)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)
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

	assertGraphCounts(t, g, 3, 1, 2)
	assertEdgeKindCount(t, g, graph.RoutesTo, 1)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)
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

	routeEdges := edgesOfKind(g, graph.RoutesTo)
	if len(routeEdges) != 1 {
		t.Fatalf("route edge count = %d, want 1", len(routeEdges))
	}
	if !strings.Contains(routeEdges[0].Evidence.Source, "service service.yaml#document=1") ||
		!strings.Contains(routeEdges[0].Evidence.Source, "deployment deployment.yaml#document=1") {
		t.Fatalf("edge evidence source = %q, want service and deployment sources", routeEdges[0].Evidence.Source)
	}
}

func TestAddRoutesDeploymentRunsAsObservedServiceAccount(t *testing.T) {
	g := graph.New()
	deployment := deployment("prod", "api", map[string]string{"app": "api"}, "deployment.yaml", 1)
	deployment.ServiceAccountName = "payments-sa"
	resources := parserkubernetes.Resources{
		Deployments:     []parserkubernetes.Deployment{deployment},
		ServiceAccounts: []parserkubernetes.ServiceAccount{serviceAccount("prod", "payments-sa", nil, "service-account.yaml", 1)},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 2, 1, 1)
	assertNodeKindCount(t, g, graph.ServiceAccount, 1)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)
	workload := graph.NewNode(graph.Workload, "kubernetes://prod/deployment/api")
	account := graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/payments-sa")
	edge := edgesOfKind(g, graph.RunsAs)[0]
	if edge.From != workload.ID || edge.To != account.ID {
		t.Fatalf("runs-as endpoints = %q -> %q, want %q -> %q", edge.From, edge.To, workload.ID, account.ID)
	}
}

func TestAddRoutesDeploymentMissingServiceAccountNameRunsAsDefault(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Deployments: []parserkubernetes.Deployment{deployment("prod", "api", map[string]string{"app": "api"}, "deployment.yaml", 1)},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 2, 1, 1)
	account := graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/default")
	if _, ok := g.Node(account.ID); !ok {
		t.Fatalf("service account node %q not found", account.ID)
	}
}

func TestAddRoutesServiceAccountMatchingIsNamespaceScoped(t *testing.T) {
	g := graph.New()
	deployment := deployment("prod", "api", map[string]string{"app": "api"}, "deployment.yaml", 1)
	deployment.ServiceAccountName = "payments-sa"
	resources := parserkubernetes.Resources{
		Deployments:     []parserkubernetes.Deployment{deployment},
		ServiceAccounts: []parserkubernetes.ServiceAccount{serviceAccount("staging", "payments-sa", nil, "service-account.yaml", 1)},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 2, 1, 1)
	account := mustNode(t, g, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/payments-sa").ID)
	if got := account.Evidence[0]; !strings.Contains(got.Source, "deployment deployment.yaml#document=1") || strings.Contains(got.Source, "service-account.yaml") {
		t.Fatalf("service account evidence = %#v, want inferred deployment evidence only", account.Evidence)
	}
}

func TestAddRoutesObservedServiceAccountEvidenceIsPreserved(t *testing.T) {
	g := graph.New()
	deployment := deployment("prod", "api", map[string]string{"app": "api"}, "deployment.yaml", 1)
	deployment.ServiceAccountName = "payments-sa"
	resources := parserkubernetes.Resources{
		Deployments:     []parserkubernetes.Deployment{deployment},
		ServiceAccounts: []parserkubernetes.ServiceAccount{serviceAccount("prod", "payments-sa", boolPtr(false), "service-account.yaml", 1)},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	account := mustNode(t, g, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/payments-sa").ID)
	wantEvidence := []graph.SourceEvidence{{Source: "service-account.yaml#document=1", Detail: "observed kubernetes ServiceAccount"}}
	if !reflect.DeepEqual(account.Evidence, wantEvidence) {
		t.Fatalf("service account evidence = %#v, want %#v", account.Evidence, wantEvidence)
	}
	edge := edgesOfKind(g, graph.RunsAs)[0]
	for _, want := range []string{"deployment deployment.yaml#document=1", "serviceaccount service-account.yaml#document=1"} {
		if !strings.Contains(edge.Evidence.Source, want) {
			t.Fatalf("runs-as evidence source = %q, want %q", edge.Evidence.Source, want)
		}
	}
	if edge.Evidence.Detail != "kubernetes Deployment serviceAccountName runs as observed ServiceAccount" {
		t.Fatalf("runs-as evidence detail = %q", edge.Evidence.Detail)
	}
}

func TestAddRoutesInferredServiceAccountEvidenceIdentifiesDeploymentReference(t *testing.T) {
	g := graph.New()
	deployment := deployment("prod", "api", map[string]string{"app": "api"}, "deployment.yaml", 1)
	deployment.ServiceAccountName = "payments-sa"

	if err := AddRoutes(g, parserkubernetes.Resources{Deployments: []parserkubernetes.Deployment{deployment}}); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	account := mustNode(t, g, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/payments-sa").ID)
	if len(account.Evidence) != 1 {
		t.Fatalf("service account evidence count = %d, want 1: %#v", len(account.Evidence), account.Evidence)
	}
	if got := account.Evidence[0]; !strings.Contains(got.Source, "deployment deployment.yaml#document=1") || !strings.Contains(got.Source, "serviceAccountName payments-sa") {
		t.Fatalf("service account evidence = %#v, want deployment reference", got)
	}
	edge := edgesOfKind(g, graph.RunsAs)[0]
	if !strings.Contains(edge.Evidence.Source, "deployment deployment.yaml#document=1") || !strings.Contains(edge.Evidence.Source, "serviceAccountName payments-sa") {
		t.Fatalf("runs-as evidence = %#v, want deployment reference", edge.Evidence)
	}
	if edge.Evidence.Detail != "kubernetes Deployment serviceAccountName runs as inferred ServiceAccount" {
		t.Fatalf("runs-as evidence detail = %q", edge.Evidence.Detail)
	}
}

func TestAddRoutesMultipleDeploymentsShareOneServiceAccountNodeAndDistinctRunsAsEdges(t *testing.T) {
	g := graph.New()
	api := deployment("prod", "api", map[string]string{"app": "api"}, "api-deployment.yaml", 1)
	api.ServiceAccountName = "payments-sa"
	worker := deployment("prod", "worker", map[string]string{"app": "worker"}, "worker-deployment.yaml", 1)
	worker.ServiceAccountName = "payments-sa"
	resources := parserkubernetes.Resources{
		Deployments:     []parserkubernetes.Deployment{worker, api},
		ServiceAccounts: []parserkubernetes.ServiceAccount{serviceAccount("prod", "payments-sa", nil, "service-account.yaml", 1)},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 3, 2, 2)
	assertNodeKindCount(t, g, graph.ServiceAccount, 1)
	assertEdgeKindCount(t, g, graph.RunsAs, 2)
}

func TestAddRoutesAggregatesInferredServiceAccountEvidenceDeterministically(t *testing.T) {
	api := deployment("prod", "api", map[string]string{"app": "api"}, "api-deployment.yaml", 1)
	api.ServiceAccountName = "payments-sa"
	worker := deployment("prod", "worker", map[string]string{"app": "worker"}, "worker-deployment.yaml", 1)
	worker.ServiceAccountName = "payments-sa"
	forward := parserkubernetes.Resources{Deployments: []parserkubernetes.Deployment{api, worker}}
	reverse := parserkubernetes.Resources{Deployments: []parserkubernetes.Deployment{worker, api}}

	g := graph.New()
	if err := AddRoutes(g, reverse); err != nil {
		t.Fatalf("add routes: %v", err)
	}
	account := mustNode(t, g, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/payments-sa").ID)
	wantEvidence := []graph.SourceEvidence{
		{Source: "deployment api-deployment.yaml#document=1; serviceAccountName payments-sa", Detail: "inferred kubernetes ServiceAccount from Deployment serviceAccountName"},
		{Source: "deployment worker-deployment.yaml#document=1; serviceAccountName payments-sa", Detail: "inferred kubernetes ServiceAccount from Deployment serviceAccountName"},
	}
	if !reflect.DeepEqual(account.Evidence, wantEvidence) {
		t.Fatalf("service account evidence = %#v, want %#v", account.Evidence, wantEvidence)
	}

	firstJSON := mustGraphJSON(t, forward)
	secondJSON := mustGraphJSON(t, reverse)
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("json differs by input order:\nfirst:  %s\nsecond: %s", firstJSON, secondJSON)
	}
}

func TestAddRoutesIdenticalDuplicateServiceAccountsAreAccepted(t *testing.T) {
	g := graph.New()
	deployment := deployment("prod", "api", map[string]string{"app": "api"}, "deployment.yaml", 1)
	resources := parserkubernetes.Resources{
		Deployments: []parserkubernetes.Deployment{deployment},
		ServiceAccounts: []parserkubernetes.ServiceAccount{
			serviceAccount("prod", "default", boolPtr(false), "a-service-account.yaml", 1),
			serviceAccount("prod", "default", boolPtr(false), "z-service-account.yaml", 1),
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 2, 1, 1)
	account := mustNode(t, g, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/default").ID)
	if got, want := account.Evidence[0].Source, "a-service-account.yaml#document=1"; got != want {
		t.Fatalf("service account evidence source = %q, want %q", got, want)
	}
}

func TestAddRoutesRejectsConflictingDuplicateServiceAccountsWithoutMutation(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Deployments: []parserkubernetes.Deployment{deployment("prod", "api", map[string]string{"app": "api"}, "deployment.yaml", 1)},
		ServiceAccounts: []parserkubernetes.ServiceAccount{
			serviceAccount("prod", "default", nil, "a-service-account.yaml", 1),
			serviceAccount("prod", "default", boolPtr(false), "z-service-account.yaml", 1),
		},
	}

	err := AddRoutes(g, resources)
	if err == nil {
		t.Fatal("add routes error = nil, want duplicate ServiceAccount conflict")
	}
	assertConflictError(t, err, "ServiceAccount", "prod/default", "a-service-account.yaml#document=1", "z-service-account.yaml#document=1")
	assertGraphCounts(t, g, 0, 0, 0)
}

func TestAddRoutesRejectsConflictingDuplicateServiceAccountsLeavesPrepopulatedGraphUnchanged(t *testing.T) {
	g := graph.New()
	if err := AddRoutes(g, routeResources("LoadBalancer")); err != nil {
		t.Fatalf("seed graph: %v", err)
	}
	before := mustMarshalGraph(t, g)
	resources := parserkubernetes.Resources{
		Deployments: []parserkubernetes.Deployment{deployment("prod", "worker", map[string]string{"app": "worker"}, "worker-deployment.yaml", 1)},
		ServiceAccounts: []parserkubernetes.ServiceAccount{
			serviceAccount("prod", "default", nil, "a-service-account.yaml", 1),
			serviceAccount("prod", "default", boolPtr(true), "z-service-account.yaml", 1),
		},
	}

	if err := AddRoutes(g, resources); err == nil {
		t.Fatal("add routes error = nil, want duplicate ServiceAccount conflict")
	}
	after := mustMarshalGraph(t, g)
	if string(after) != string(before) {
		t.Fatalf("graph changed after failed AddRoutes:\nbefore: %s\nafter:  %s", before, after)
	}
}

func TestAddRoutesRejectsDuplicateDeploymentWithDifferentServiceAccountNameWithoutMutation(t *testing.T) {
	g := graph.New()
	first := deployment("prod", "api", map[string]string{"app": "api"}, "deployment.yaml", 1)
	second := deployment("prod", "api", map[string]string{"app": "api"}, "deployment-conflict.yaml", 1)
	second.ServiceAccountName = "payments-sa"

	err := AddRoutes(g, parserkubernetes.Resources{Deployments: []parserkubernetes.Deployment{first, second}})
	if err == nil {
		t.Fatal("add routes error = nil, want duplicate Deployment conflict")
	}
	assertConflictError(t, err, "Deployment", "prod/api", "deployment.yaml#document=1", "deployment-conflict.yaml#document=1")
	assertGraphCounts(t, g, 0, 0, 0)
}

func TestAddRoutesRejectsDuplicateDeploymentWithDifferentServiceAccountNameLeavesPrepopulatedGraphUnchanged(t *testing.T) {
	g := graph.New()
	if err := AddRoutes(g, routeResources("LoadBalancer")); err != nil {
		t.Fatalf("seed graph: %v", err)
	}
	before := mustMarshalGraph(t, g)
	first := deployment("prod", "worker", map[string]string{"app": "worker"}, "worker-deployment.yaml", 1)
	second := deployment("prod", "worker", map[string]string{"app": "worker"}, "worker-deployment-conflict.yaml", 1)
	second.ServiceAccountName = "worker-sa"

	if err := AddRoutes(g, parserkubernetes.Resources{Deployments: []parserkubernetes.Deployment{first, second}}); err == nil {
		t.Fatal("add routes error = nil, want duplicate Deployment conflict")
	}
	after := mustMarshalGraph(t, g)
	if string(after) != string(before) {
		t.Fatalf("graph changed after failed AddRoutes:\nbefore: %s\nafter:  %s", before, after)
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

	assertGraphCounts(t, g, 3, 1, 2)
	endpoint := mustNode(t, g, graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/public-api").ID)
	workload := mustNode(t, g, graph.NewNode(graph.Workload, "kubernetes://prod/deployment/api").ID)
	if got, want := endpoint.Evidence[0].Source, "a-service.yaml#document=1"; got != want {
		t.Fatalf("endpoint evidence source = %q, want %q", got, want)
	}
	if got, want := workload.Evidence[0].Source, "a-deployment.yaml#document=1"; got != want {
		t.Fatalf("workload evidence source = %q, want %q", got, want)
	}
	if got := edgesOfKind(g, graph.RoutesTo)[0].Evidence.Source; !strings.Contains(got, "a-service.yaml#document=1") || !strings.Contains(got, "a-deployment.yaml#document=1") {
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

	assertGraphCounts(t, g, 3, 1, 2)
	assertEdgeKindCount(t, g, graph.RoutesTo, 1)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)
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

	assertGraphCounts(t, g, 3, 1, 2)
	assertEdgeKindCount(t, g, graph.RoutesTo, 1)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)
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

	assertGraphCounts(t, g, 3, 1, 2)
	assertEdgeKindCount(t, g, graph.RoutesTo, 1)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)
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

	assertGraphCounts(t, g, 3, 1, 2)
	assertEdgeKindCount(t, g, graph.RoutesTo, 1)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)
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

func TestAddRoutesIdenticalDuplicateIngressesAreAccepted(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Ingresses: []parserkubernetes.Ingress{
			ingress("prod", "public-api", []parserkubernetes.IngressBackend{{Kind: "rule", ServiceName: "api"}}, "a-ingress.yaml", 1),
			ingress("prod", "public-api", []parserkubernetes.IngressBackend{{Kind: "rule", ServiceName: "api"}}, "z-ingress.yaml", 1),
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 1, 0, 0)
}

func TestAddRoutesDuplicateIngressesWithReversedBackendOrderAreAccepted(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Ingresses: []parserkubernetes.Ingress{
			ingress("prod", "public-api", []parserkubernetes.IngressBackend{
				{Kind: "rule", ServiceName: "api"},
				{Kind: "default", ServiceName: "fallback"},
			}, "a-ingress.yaml", 1),
			ingress("prod", "public-api", []parserkubernetes.IngressBackend{
				{Kind: "default", ServiceName: "fallback"},
				{Kind: "rule", ServiceName: "api"},
			}, "z-ingress.yaml", 1),
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 1, 0, 0)
}

func TestAddRoutesDuplicateIngressesWithRepeatedBackendReferencesAreAccepted(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Ingresses: []parserkubernetes.Ingress{
			ingress("prod", "public-api", []parserkubernetes.IngressBackend{
				{Kind: "rule", ServiceName: "api"},
				{Kind: "default", ServiceName: "fallback"},
			}, "a-ingress.yaml", 1),
			ingress("prod", "public-api", []parserkubernetes.IngressBackend{
				{Kind: "rule", ServiceName: "api"},
				{Kind: "rule", ServiceName: "api"},
				{Kind: "default", ServiceName: "fallback"},
			}, "z-ingress.yaml", 1),
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 1, 0, 0)
}

func TestAddRoutesDuplicateIngressesPreserveRuleAndDefaultBackendDistinction(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Ingresses: []parserkubernetes.Ingress{
			ingress("prod", "public-api", []parserkubernetes.IngressBackend{{Kind: "rule", ServiceName: "api"}}, "a-ingress.yaml", 1),
			ingress("prod", "public-api", []parserkubernetes.IngressBackend{{Kind: "default", ServiceName: "api"}}, "z-ingress.yaml", 1),
		},
	}

	err := AddRoutes(g, resources)
	if err == nil {
		t.Fatal("add routes error = nil, want duplicate Ingress conflict")
	}
	assertConflictError(t, err, "Ingress", "prod/public-api", "a-ingress.yaml#document=1", "z-ingress.yaml#document=1")
	assertGraphCounts(t, g, 0, 0, 0)
}

func TestAddRoutesRejectsDuplicateIngressWithDifferentCanonicalBackendSet(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Ingresses: []parserkubernetes.Ingress{
			ingress("prod", "public-api", []parserkubernetes.IngressBackend{{Kind: "rule", ServiceName: "api"}}, "a-ingress.yaml", 1),
			ingress("prod", "public-api", []parserkubernetes.IngressBackend{{Kind: "rule", ServiceName: "admin"}}, "z-ingress.yaml", 1),
		},
	}

	err := AddRoutes(g, resources)
	if err == nil {
		t.Fatal("add routes error = nil, want duplicate Ingress conflict")
	}
	assertConflictError(t, err, "Ingress", "prod/public-api", "a-ingress.yaml#document=1", "z-ingress.yaml#document=1")
	assertGraphCounts(t, g, 0, 0, 0)
}

func TestAddRoutesDuplicateIngressConflictLeavesPreviouslyPopulatedGraphUnchanged(t *testing.T) {
	g := graph.New()
	if err := AddRoutes(g, routeResources("LoadBalancer")); err != nil {
		t.Fatalf("seed graph: %v", err)
	}
	before := mustMarshalGraph(t, g)

	conflict := parserkubernetes.Resources{
		Services:    routeResources("LoadBalancer").Services,
		Deployments: routeResources("LoadBalancer").Deployments,
		Ingresses: []parserkubernetes.Ingress{
			ingress("prod", "public-api", []parserkubernetes.IngressBackend{{Kind: "rule", ServiceName: "api"}}, "a-ingress.yaml", 1),
			ingress("prod", "public-api", []parserkubernetes.IngressBackend{{Kind: "rule", ServiceName: "admin"}}, "z-ingress.yaml", 1),
		},
	}
	if err := AddRoutes(g, conflict); err == nil {
		t.Fatal("add routes error = nil, want duplicate Ingress conflict")
	}

	after := mustMarshalGraph(t, g)
	if string(after) != string(before) {
		t.Fatalf("graph changed after failed AddRoutes:\nbefore: %s\nafter:  %s", before, after)
	}
}

func TestAddRoutesIngressToClusterIPServiceCreatesRouteToWorkload(t *testing.T) {
	g := graph.New()
	resources := ingressRouteResources()

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 3, 1, 2)
	assertEdgeKindCount(t, g, graph.RoutesTo, 1)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)
	endpoint := graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/ingress/public-api")
	workload := graph.NewNode(graph.Workload, "kubernetes://prod/deployment/api")
	if _, ok := g.Node(endpoint.ID); !ok {
		t.Fatalf("endpoint node %q not found", endpoint.ID)
	}
	if _, ok := g.Node(workload.ID); !ok {
		t.Fatalf("workload node %q not found", workload.ID)
	}
	edge := edgesOfKind(g, graph.RoutesTo)[0]
	if edge.From != endpoint.ID || edge.To != workload.ID {
		t.Fatalf("edge endpoints = %q -> %q, want %q -> %q", edge.From, edge.To, endpoint.ID, workload.ID)
	}
}

func TestAddRoutesIngressMultiplePathsSameServiceDeduplicateRoute(t *testing.T) {
	g := graph.New()
	resources := ingressRouteResources()
	resources.Ingresses[0].Backends = []parserkubernetes.IngressBackend{
		{Kind: "rule", ServiceName: "api"},
		{Kind: "rule", ServiceName: "api"},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 3, 1, 2)
	routeEdge := edgesOfKind(g, graph.RoutesTo)[0]
	if got := strings.Count(routeEdge.Evidence.Source, "service service.yaml#document=1"); got != 1 {
		t.Fatalf("service evidence occurrence count = %d, want 1 in %q", got, routeEdge.Evidence.Source)
	}
}

func TestAddRoutesIngressMultiplePathsDifferentServicesResolveCorrectly(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Services: []parserkubernetes.Service{
			service("prod", "api", "ClusterIP", map[string]string{"app": "api"}, "api-service.yaml", 1),
			service("prod", "worker", "ClusterIP", map[string]string{"app": "worker"}, "worker-service.yaml", 1),
		},
		Deployments: []parserkubernetes.Deployment{
			deployment("prod", "api", map[string]string{"app": "api"}, "api-deployment.yaml", 1),
			deployment("prod", "worker", map[string]string{"app": "worker"}, "worker-deployment.yaml", 1),
		},
		Ingresses: []parserkubernetes.Ingress{
			ingress("prod", "public-api", []parserkubernetes.IngressBackend{
				{Kind: "rule", ServiceName: "api"},
				{Kind: "rule", ServiceName: "worker"},
			}, "ingress.yaml", 1),
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 4, 2, 4)
	assertEdgeKindCount(t, g, graph.RoutesTo, 2)
	assertEdgeKindCount(t, g, graph.RunsAs, 2)
}

func TestAddRoutesIngressResolvesServicesOnlyInSameNamespace(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Services: []parserkubernetes.Service{
			service("staging", "api", "ClusterIP", map[string]string{"app": "api"}, "staging-service.yaml", 1),
		},
		Deployments: []parserkubernetes.Deployment{
			deployment("staging", "api", map[string]string{"app": "api"}, "staging-deployment.yaml", 1),
		},
		Ingresses: []parserkubernetes.Ingress{
			ingress("prod", "public-api", []parserkubernetes.IngressBackend{{Kind: "rule", ServiceName: "api"}}, "ingress.yaml", 1),
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 3, 1, 1)
	assertNodeKindCount(t, g, graph.PublicEndpoint, 1)
	assertEdgeKindCount(t, g, graph.RoutesTo, 0)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)
	endpoint := graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/ingress/public-api")
	if _, ok := g.Node(endpoint.ID); !ok {
		t.Fatalf("endpoint node %q not found", endpoint.ID)
	}
}

func TestAddRoutesIngressMissingReferencedServiceCreatesOnlyEndpoint(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Ingresses: []parserkubernetes.Ingress{
			ingress("prod", "public-api", []parserkubernetes.IngressBackend{{Kind: "rule", ServiceName: "missing"}}, "ingress.yaml", 1),
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 1, 0, 0)
}

func TestAddRoutesIngressSelectorMismatchCreatesNoRoute(t *testing.T) {
	g := graph.New()
	resources := ingressRouteResources()
	resources.Services[0].Selector = map[string]string{"app": "worker"}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 3, 1, 1)
	assertNodeKindCount(t, g, graph.PublicEndpoint, 1)
	assertEdgeKindCount(t, g, graph.RoutesTo, 0)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)
}

func TestAddRoutesIngressMatchesDeploymentPodTemplateLabels(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "resources.yaml", `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: public-api
  namespace: prod
spec:
  defaultBackend:
    service:
      name: api
---
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: prod
spec:
  type: ClusterIP
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
  template:
    metadata:
      labels:
        app: api
`)
	resources, err := parserkubernetes.ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	g := graph.New()

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 3, 1, 2)
	assertEdgeKindCount(t, g, graph.RoutesTo, 1)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)
}

func TestAddRoutesIngressEvidenceIdentifiesSources(t *testing.T) {
	g := graph.New()

	if err := AddRoutes(g, ingressRouteResources()); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	endpoint := mustNode(t, g, graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/ingress/public-api").ID)
	workload := mustNode(t, g, graph.NewNode(graph.Workload, "kubernetes://prod/deployment/api").ID)
	if !reflect.DeepEqual(endpoint.Evidence, []graph.SourceEvidence{{Source: "ingress.yaml#document=1", Detail: "kubernetes Ingress"}}) {
		t.Fatalf("endpoint evidence = %#v", endpoint.Evidence)
	}
	if !reflect.DeepEqual(workload.Evidence, []graph.SourceEvidence{{Source: "deployment.yaml#document=1", Detail: "kubernetes Deployment"}}) {
		t.Fatalf("workload evidence = %#v", workload.Evidence)
	}

	routeEdges := edgesOfKind(g, graph.RoutesTo)
	if len(routeEdges) != 1 {
		t.Fatalf("route edge count = %d, want 1", len(routeEdges))
	}
	for _, want := range []string{"ingress ingress.yaml#document=1", "service service.yaml#document=1", "deployment deployment.yaml#document=1"} {
		if !strings.Contains(routeEdges[0].Evidence.Source, want) {
			t.Fatalf("edge evidence source = %q, want %q", routeEdges[0].Evidence.Source, want)
		}
	}
}

func TestAddRoutesIngressTwoServicesSameDeploymentCreateOneEdgeWithBothServiceSources(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Services: []parserkubernetes.Service{
			service("prod", "api", "ClusterIP", map[string]string{"app": "api"}, "api-service.yaml", 1),
			service("prod", "api-v2", "ClusterIP", map[string]string{"app": "api"}, "api-v2-service.yaml", 1),
		},
		Deployments: []parserkubernetes.Deployment{
			deployment("prod", "api", map[string]string{"app": "api"}, "deployment.yaml", 1),
		},
		Ingresses: []parserkubernetes.Ingress{
			ingress("prod", "public-api", []parserkubernetes.IngressBackend{
				{Kind: "rule", ServiceName: "api"},
				{Kind: "rule", ServiceName: "api-v2"},
			}, "ingress.yaml", 1),
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 3, 1, 2)
	evidence := edgesOfKind(g, graph.RoutesTo)[0].Evidence.Source
	for _, want := range []string{"service api-service.yaml#document=1", "service api-v2-service.yaml#document=1"} {
		if !strings.Contains(evidence, want) {
			t.Fatalf("edge evidence source = %q, want %q", evidence, want)
		}
	}
}

func TestAddRoutesIngressEvidenceAndJSONDeterministicWhenInputOrderChanges(t *testing.T) {
	forward := parserkubernetes.Resources{
		Services: []parserkubernetes.Service{
			service("prod", "api", "ClusterIP", map[string]string{"app": "api"}, "api-service.yaml", 1),
			service("prod", "api-v2", "ClusterIP", map[string]string{"app": "api"}, "api-v2-service.yaml", 1),
		},
		Deployments: []parserkubernetes.Deployment{
			deployment("prod", "api", map[string]string{"app": "api"}, "deployment.yaml", 1),
		},
		Ingresses: []parserkubernetes.Ingress{
			ingress("prod", "public-api", []parserkubernetes.IngressBackend{
				{Kind: "rule", ServiceName: "api"},
				{Kind: "rule", ServiceName: "api-v2"},
			}, "ingress.yaml", 1),
		},
	}
	reverse := parserkubernetes.Resources{
		Services: []parserkubernetes.Service{forward.Services[1], forward.Services[0]},
		Deployments: []parserkubernetes.Deployment{
			forward.Deployments[0],
		},
		Ingresses: []parserkubernetes.Ingress{
			ingress("prod", "public-api", []parserkubernetes.IngressBackend{
				{Kind: "rule", ServiceName: "api-v2"},
				{Kind: "rule", ServiceName: "api"},
			}, "ingress.yaml", 1),
		},
	}

	firstJSON := mustGraphJSON(t, forward)
	secondJSON := mustGraphJSON(t, reverse)
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("json differs by input order:\nfirst:  %s\nsecond: %s", firstJSON, secondJSON)
	}
}

func TestAddRoutesIngressRepeatedServiceReferencesDoNotDuplicateEvidence(t *testing.T) {
	g := graph.New()
	resources := ingressRouteResources()
	resources.Ingresses[0].Backends = []parserkubernetes.IngressBackend{
		{Kind: "rule", ServiceName: "api"},
		{Kind: "rule", ServiceName: "api"},
		{Kind: "rule", ServiceName: "api"},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertGraphCounts(t, g, 3, 1, 2)
	evidence := edgesOfKind(g, graph.RoutesTo)[0].Evidence.Source
	if got := strings.Count(evidence, "ingress ingress.yaml#document=1"); got != 1 {
		t.Fatalf("ingress evidence occurrence count = %d, want 1 in %q", got, evidence)
	}
	if got := strings.Count(evidence, "service service.yaml#document=1"); got != 1 {
		t.Fatalf("service evidence occurrence count = %d, want 1 in %q", got, evidence)
	}
	if got := strings.Count(evidence, "deployment deployment.yaml#document=1"); got != 1 {
		t.Fatalf("deployment evidence occurrence count = %d, want 1 in %q", got, evidence)
	}
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

	assertGraphCounts(t, g, 3, 1, 2)
	assertEdgeKindCount(t, g, graph.RoutesTo, 1)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)
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

func ingressRouteResources() parserkubernetes.Resources {
	return parserkubernetes.Resources{
		Services: []parserkubernetes.Service{
			service("prod", "api", "ClusterIP", map[string]string{"app": "api"}, "service.yaml", 1),
		},
		Deployments: []parserkubernetes.Deployment{
			deployment("prod", "api", map[string]string{"app": "api"}, "deployment.yaml", 1),
		},
		Ingresses: []parserkubernetes.Ingress{
			ingress("prod", "public-api", []parserkubernetes.IngressBackend{{Kind: "rule", ServiceName: "api"}}, "ingress.yaml", 1),
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
		Namespace:          namespace,
		Name:               name,
		PodLabels:          podLabels,
		ServiceAccountName: "default",
		Source:             parserkubernetes.Source{Filename: filename, Document: document},
	}
}

func ingress(namespace, name string, backends []parserkubernetes.IngressBackend, filename string, document int) parserkubernetes.Ingress {
	return parserkubernetes.Ingress{
		Namespace: namespace,
		Name:      name,
		Backends:  backends,
		Source:    parserkubernetes.Source{Filename: filename, Document: document},
	}
}

func serviceAccount(namespace, name string, automount *bool, filename string, document int) parserkubernetes.ServiceAccount {
	return parserkubernetes.ServiceAccount{
		Namespace:                    namespace,
		Name:                         name,
		AutomountServiceAccountToken: automount,
		Source:                       parserkubernetes.Source{Filename: filename, Document: document},
	}
}

func boolPtr(value bool) *bool {
	return &value
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

func assertNodeKindCount(t *testing.T, g *graph.Graph, kind graph.NodeKind, want int) {
	t.Helper()

	got := 0
	for _, node := range g.Nodes() {
		if node.Kind == kind {
			got++
		}
	}
	if got != want {
		t.Fatalf("%s node count = %d, want %d: %#v", kind, got, want, g.Nodes())
	}
}

func assertEdgeKindCount(t *testing.T, g *graph.Graph, kind graph.EdgeKind, want int) {
	t.Helper()

	got := len(edgesOfKind(g, kind))
	if got != want {
		t.Fatalf("%s edge count = %d, want %d: %#v", kind, got, want, g.Edges())
	}
}

func edgesOfKind(g *graph.Graph, kind graph.EdgeKind) []graph.Edge {
	var edges []graph.Edge
	for _, edge := range g.Edges() {
		if edge.Kind == kind {
			edges = append(edges, edge)
		}
	}
	return edges
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
