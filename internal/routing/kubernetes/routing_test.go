package kubernetes

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
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

func TestAddRoutesRoleBindingConnectsSameNamespaceServiceAccountToRole(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Roles:        []parserkubernetes.Role{role("prod", "pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "read-pods", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertNodeKindCount(t, g, graph.ServiceAccount, 1)
	assertNodeKindCount(t, g, graph.Role, 1)
	assertNodeKindCount(t, g, graph.Permission, 1)
	assertEdgeKindCount(t, g, graph.BoundTo, 1)
	assertEdgeKindCount(t, g, graph.GrantsPermission, 1)
	account := graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/api")
	role := graph.NewNode(graph.Role, "kubernetes://prod/role/pod-reader")
	edge := edgesOfKind(g, graph.BoundTo)[0]
	if edge.From != account.ID || edge.To != role.ID {
		t.Fatalf("bound-to endpoints = %q -> %q, want %q -> %q", edge.From, edge.To, account.ID, role.ID)
	}
}

func TestAddRoutesRoleBindingCanBindCrossNamespaceServiceAccount(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Roles:        []parserkubernetes.Role{role("authz", "pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{roleBinding("authz", "read-pods", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "binding.yaml", 1)},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	account := graph.NewNode(graph.ServiceAccount, "kubernetes://workloads/serviceaccount/api")
	role := graph.NewNode(graph.Role, "kubernetes://authz/role/pod-reader")
	edge := edgesOfKind(g, graph.BoundTo)[0]
	if edge.From != account.ID || edge.To != role.ID {
		t.Fatalf("bound-to endpoints = %q -> %q, want cross-namespace subject %q -> role %q", edge.From, edge.To, account.ID, role.ID)
	}
}

func TestAddRoutesRoleBindingCanReferenceClusterRoleWithNamespaceScope(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		ClusterRoles: []parserkubernetes.ClusterRole{clusterRole("pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "cluster-role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "read-pods", parserkubernetes.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "pod-reader",
		}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "role-binding.yaml", 1)},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	role := graph.NewNode(graph.Role, "kubernetes://cluster/clusterrole/pod-reader")
	if _, ok := g.Node(role.ID); !ok {
		t.Fatalf("cluster role graph node %q not found", role.ID)
	}
	edge := edgesOfKind(g, graph.BoundTo)[0]
	for _, want := range []string{"binding_kind=RoleBinding", "binding_namespace=prod", "scope_kind=namespace", "scope_name=prod"} {
		if !strings.Contains(edge.Evidence.Detail, want) {
			t.Fatalf("bound-to evidence detail = %q, want %q", edge.Evidence.Detail, want)
		}
	}
}

func TestAddRoutesClusterRoleBindingConnectsServiceAccountToClusterRoleWithClusterScope(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		ClusterRoles: []parserkubernetes.ClusterRole{clusterRole("pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "cluster-role.yaml", 1)},
		ClusterRoleBindings: []parserkubernetes.ClusterRoleBinding{clusterRoleBinding("read-pods", parserkubernetes.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "pod-reader",
		}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "cluster-role-binding.yaml", 1)},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	account := graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/api")
	role := graph.NewNode(graph.Role, "kubernetes://cluster/clusterrole/pod-reader")
	edge := edgesOfKind(g, graph.BoundTo)[0]
	if edge.From != account.ID || edge.To != role.ID {
		t.Fatalf("bound-to endpoints = %q -> %q, want %q -> %q", edge.From, edge.To, account.ID, role.ID)
	}
	for _, want := range []string{"binding_kind=ClusterRoleBinding", "scope_kind=cluster"} {
		if !strings.Contains(edge.Evidence.Detail, want) {
			t.Fatalf("bound-to evidence detail = %q, want %q", edge.Evidence.Detail, want)
		}
	}
	if strings.Contains(edge.Evidence.Detail, "binding_namespace=") || strings.Contains(edge.Evidence.Detail, "scope_name=") {
		t.Fatalf("cluster-scoped bound-to evidence detail = %q, want no namespace scope fields", edge.Evidence.Detail)
	}
}

func TestAddRoutesRoleBindingAndClusterRoleBindingScopeEvidenceAreDistinguishable(t *testing.T) {
	resources := parserkubernetes.Resources{
		ClusterRoles: []parserkubernetes.ClusterRole{clusterRole("pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "cluster-role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "read-pods", parserkubernetes.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "pod-reader",
		}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "role-binding.yaml", 1)},
		ClusterRoleBindings: []parserkubernetes.ClusterRoleBinding{clusterRoleBinding("read-pods-cluster", parserkubernetes.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "pod-reader",
		}, []parserkubernetes.Subject{serviceAccountSubject("prod", "worker")}, "cluster-role-binding.yaml", 1)},
	}

	g := graph.New()
	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	edges := edgesOfKind(g, graph.BoundTo)
	if len(edges) != 2 {
		t.Fatalf("bound-to edge count = %d, want 2: %#v", len(edges), edges)
	}
	firstDetail := edges[0].Evidence.Detail
	secondDetail := edges[1].Evidence.Detail
	if firstDetail == secondDetail {
		t.Fatalf("scope evidence details are identical: %q", firstDetail)
	}
	combined := firstDetail + "\n" + secondDetail
	for _, want := range []string{"binding_kind=RoleBinding", "scope_kind=namespace", "binding_kind=ClusterRoleBinding", "scope_kind=cluster"} {
		if !strings.Contains(combined, want) {
			t.Fatalf("scope evidence details = %q, want %q", combined, want)
		}
	}

	reversed := parserkubernetes.Resources{
		ClusterRoleBindings: resources.ClusterRoleBindings,
		RoleBindings:        resources.RoleBindings,
		ClusterRoles:        resources.ClusterRoles,
	}
	if firstJSON, secondJSON := mustGraphJSON(t, resources), mustGraphJSON(t, reversed); string(firstJSON) != string(secondJSON) {
		t.Fatalf("json differs by RBAC resource order:\nfirst:  %s\nsecond: %s", firstJSON, secondJSON)
	}
}

func TestAddRoutesAggregatesRoleBindingScopesForSameServiceAccountAndClusterRole(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		ClusterRoles: []parserkubernetes.ClusterRole{clusterRole("pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "cluster-role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{
			roleBinding("team-a", "read-pods-a", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "a-binding.yaml", 1),
			roleBinding("team-b", "read-pods-b", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "b-binding.yaml", 1),
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertEdgeKindCount(t, g, graph.BoundTo, 1)
	edge := edgesOfKind(g, graph.BoundTo)[0]
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_kind=RoleBinding", "binding_namespace=team-a", "binding_name=read-pods-a", "scope_kind=namespace", "scope_name=team-a", "binding_source=a-binding.yaml#document=1")
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_kind=RoleBinding", "binding_namespace=team-b", "binding_name=read-pods-b", "scope_kind=namespace", "scope_name=team-b", "binding_source=b-binding.yaml#document=1")
}

func TestAddRoutesAggregatesRoleBindingAndClusterRoleBindingScopesForSameServiceAccountAndClusterRole(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		ClusterRoles: []parserkubernetes.ClusterRole{clusterRole("pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "cluster-role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{
			roleBinding("prod", "read-pods", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "role-binding.yaml", 1),
		},
		ClusterRoleBindings: []parserkubernetes.ClusterRoleBinding{
			clusterRoleBinding("read-pods-cluster", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "cluster-role-binding.yaml", 1),
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertEdgeKindCount(t, g, graph.BoundTo, 1)
	edge := edgesOfKind(g, graph.BoundTo)[0]
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_kind=RoleBinding", "binding_namespace=prod", "binding_name=read-pods", "scope_kind=namespace", "scope_name=prod", "binding_source=role-binding.yaml#document=1")
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_kind=ClusterRoleBinding", "binding_name=read-pods-cluster", "scope_kind=cluster", "binding_source=cluster-role-binding.yaml#document=1")
}

func TestAddRoutesAggregatesDistinctRoleBindingsWithSameScopeAndEndpoints(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		ClusterRoles: []parserkubernetes.ClusterRole{clusterRole("pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "cluster-role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{
			roleBinding("prod", "read-pods-a", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "a-binding.yaml", 1),
			roleBinding("prod", "read-pods-b", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "b-binding.yaml", 1),
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertEdgeKindCount(t, g, graph.BoundTo, 1)
	edge := edgesOfKind(g, graph.BoundTo)[0]
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_kind=RoleBinding", "binding_namespace=prod", "binding_name=read-pods-a", "scope_kind=namespace", "scope_name=prod", "binding_source=a-binding.yaml#document=1")
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_kind=RoleBinding", "binding_namespace=prod", "binding_name=read-pods-b", "scope_kind=namespace", "scope_name=prod", "binding_source=b-binding.yaml#document=1")
}

func TestAddRoutesRepeatedIdenticalBindingDoesNotDuplicateAggregatedEvidence(t *testing.T) {
	g := graph.New()
	binding := roleBinding("prod", "read-pods", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "binding.yaml", 1)
	resources := parserkubernetes.Resources{
		ClusterRoles: []parserkubernetes.ClusterRole{clusterRole("pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "cluster-role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{
			binding,
			binding,
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertEdgeKindCount(t, g, graph.BoundTo, 1)
	edge := edgesOfKind(g, graph.BoundTo)[0]
	if got := strings.Count(edge.Evidence.Detail, "binding_name=read-pods"); got != 1 {
		t.Fatalf("binding record count = %d, want 1 in %q", got, edge.Evidence.Detail)
	}
}

func TestAddRoutesIdenticalRoleBindingSourcesArePreserved(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		ClusterRoles: []parserkubernetes.ClusterRole{clusterRole("pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "cluster-role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{
			roleBinding("prod", "read-pods", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "a-binding.yaml", 1),
			roleBinding("prod", "read-pods", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "b-binding.yaml", 1),
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertEdgeKindCount(t, g, graph.BoundTo, 1)
	edge := edgesOfKind(g, graph.BoundTo)[0]
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_kind=RoleBinding", "binding_namespace=prod", "binding_name=read-pods", "binding_source=a-binding.yaml#document=1")
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_kind=RoleBinding", "binding_namespace=prod", "binding_name=read-pods", "binding_source=b-binding.yaml#document=1")
	if got := strings.Count(edge.Evidence.Detail, "binding_name=read-pods"); got != 2 {
		t.Fatalf("binding record count = %d, want 2 in %q", got, edge.Evidence.Detail)
	}
}

func TestAddRoutesIdenticalRoleBindingDocumentSourcesArePreserved(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		ClusterRoles: []parserkubernetes.ClusterRole{clusterRole("pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "cluster-role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{
			roleBinding("prod", "read-pods", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "bindings.yaml", 1),
			roleBinding("prod", "read-pods", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "bindings.yaml", 2),
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertEdgeKindCount(t, g, graph.BoundTo, 1)
	edge := edgesOfKind(g, graph.BoundTo)[0]
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_kind=RoleBinding", "binding_namespace=prod", "binding_name=read-pods", "binding_source=bindings.yaml#document=1")
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_kind=RoleBinding", "binding_namespace=prod", "binding_name=read-pods", "binding_source=bindings.yaml#document=2")
	if got := strings.Count(edge.Evidence.Detail, "binding_name=read-pods"); got != 2 {
		t.Fatalf("binding record count = %d, want 2 in %q", got, edge.Evidence.Detail)
	}
}

func TestAddRoutesIdenticalRoleBindingSameSourceDeduplicatesEvidence(t *testing.T) {
	g := graph.New()
	binding := roleBinding("prod", "read-pods", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "bindings.yaml", 1)
	resources := parserkubernetes.Resources{
		ClusterRoles: []parserkubernetes.ClusterRole{clusterRole("pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "cluster-role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{
			binding,
			binding,
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertEdgeKindCount(t, g, graph.BoundTo, 1)
	edge := edgesOfKind(g, graph.BoundTo)[0]
	if got := strings.Count(edge.Evidence.Detail, "binding_name=read-pods"); got != 1 {
		t.Fatalf("binding record count = %d, want 1 in %q", got, edge.Evidence.Detail)
	}
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_kind=RoleBinding", "binding_namespace=prod", "binding_name=read-pods", "binding_source=bindings.yaml#document=1")
}

func TestAddRoutesIdenticalClusterRoleBindingSourcesArePreserved(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		ClusterRoles: []parserkubernetes.ClusterRole{clusterRole("pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "cluster-role.yaml", 1)},
		ClusterRoleBindings: []parserkubernetes.ClusterRoleBinding{
			clusterRoleBinding("read-pods", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "a-binding.yaml", 1),
			clusterRoleBinding("read-pods", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "b-binding.yaml", 1),
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertEdgeKindCount(t, g, graph.BoundTo, 1)
	edge := edgesOfKind(g, graph.BoundTo)[0]
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_kind=ClusterRoleBinding", "binding_name=read-pods", "binding_source=a-binding.yaml#document=1")
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_kind=ClusterRoleBinding", "binding_name=read-pods", "binding_source=b-binding.yaml#document=1")
	if got := strings.Count(edge.Evidence.Detail, "binding_name=read-pods"); got != 2 {
		t.Fatalf("binding record count = %d, want 2 in %q", got, edge.Evidence.Detail)
	}
}

func TestAddRoutesIdenticalClusterRoleBindingDocumentSourcesArePreserved(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		ClusterRoles: []parserkubernetes.ClusterRole{clusterRole("pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "cluster-role.yaml", 1)},
		ClusterRoleBindings: []parserkubernetes.ClusterRoleBinding{
			clusterRoleBinding("read-pods", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "bindings.yaml", 1),
			clusterRoleBinding("read-pods", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "bindings.yaml", 2),
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertEdgeKindCount(t, g, graph.BoundTo, 1)
	edge := edgesOfKind(g, graph.BoundTo)[0]
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_kind=ClusterRoleBinding", "binding_name=read-pods", "binding_source=bindings.yaml#document=1")
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_kind=ClusterRoleBinding", "binding_name=read-pods", "binding_source=bindings.yaml#document=2")
	if got := strings.Count(edge.Evidence.Detail, "binding_name=read-pods"); got != 2 {
		t.Fatalf("binding record count = %d, want 2 in %q", got, edge.Evidence.Detail)
	}
}

func TestAddRoutesIdenticalClusterRoleBindingSameSourceDeduplicatesEvidence(t *testing.T) {
	g := graph.New()
	binding := clusterRoleBinding("read-pods", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "bindings.yaml", 1)
	resources := parserkubernetes.Resources{
		ClusterRoles: []parserkubernetes.ClusterRole{clusterRole("pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "cluster-role.yaml", 1)},
		ClusterRoleBindings: []parserkubernetes.ClusterRoleBinding{
			binding,
			binding,
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertEdgeKindCount(t, g, graph.BoundTo, 1)
	edge := edgesOfKind(g, graph.BoundTo)[0]
	if got := strings.Count(edge.Evidence.Detail, "binding_name=read-pods"); got != 1 {
		t.Fatalf("binding record count = %d, want 1 in %q", got, edge.Evidence.Detail)
	}
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_kind=ClusterRoleBinding", "binding_name=read-pods", "binding_source=bindings.yaml#document=1")
}

func TestAddRoutesDuplicateBindingSourceEvidenceIsDeterministic(t *testing.T) {
	forward := parserkubernetes.Resources{
		ClusterRoles: []parserkubernetes.ClusterRole{
			clusterRole("pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "cluster-role.yaml", 1),
			clusterRole("unused", []parserkubernetes.PolicyRule{podGetRule()}, "unused-cluster-role.yaml", 1),
		},
		RoleBindings: []parserkubernetes.RoleBinding{
			roleBinding("prod", "read-pods", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "a-role-binding.yaml", 1),
			roleBinding("prod", "read-pods", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "b-role-binding.yaml", 1),
		},
		ClusterRoleBindings: []parserkubernetes.ClusterRoleBinding{
			clusterRoleBinding("read-pods", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "a-cluster-role-binding.yaml", 1),
			clusterRoleBinding("read-pods", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "b-cluster-role-binding.yaml", 1),
		},
	}
	reverse := parserkubernetes.Resources{
		ClusterRoleBindings: []parserkubernetes.ClusterRoleBinding{forward.ClusterRoleBindings[1], forward.ClusterRoleBindings[0]},
		RoleBindings:        []parserkubernetes.RoleBinding{forward.RoleBindings[1], forward.RoleBindings[0]},
		ClusterRoles:        []parserkubernetes.ClusterRole{forward.ClusterRoles[1], forward.ClusterRoles[0]},
	}

	first := graph.New()
	if err := AddRoutes(first, forward); err != nil {
		t.Fatalf("add forward routes: %v", err)
	}
	second := graph.New()
	if err := AddRoutes(second, reverse); err != nil {
		t.Fatalf("add reverse routes: %v", err)
	}

	if string(mustMarshalGraph(t, first)) != string(mustMarshalGraph(t, second)) {
		t.Fatalf("json differs by duplicate binding source order:\nfirst:  %s\nsecond: %s", mustMarshalGraph(t, first), mustMarshalGraph(t, second))
	}
	edge := edgesOfKind(first, graph.BoundTo)[0]
	for _, want := range []string{
		"binding_source=a-role-binding.yaml#document=1",
		"binding_source=b-role-binding.yaml#document=1",
		"binding_source=a-cluster-role-binding.yaml#document=1",
		"binding_source=b-cluster-role-binding.yaml#document=1",
	} {
		if !strings.Contains(edge.Evidence.Detail, want) {
			t.Fatalf("bound-to evidence detail = %q, want %q", edge.Evidence.Detail, want)
		}
	}
}

func TestAddRoutesAggregatedBoundToEvidenceIsDeterministic(t *testing.T) {
	forward := parserkubernetes.Resources{
		ClusterRoles: []parserkubernetes.ClusterRole{
			clusterRole("pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "cluster-role.yaml", 1),
			clusterRole("unused", []parserkubernetes.PolicyRule{podGetRule()}, "unused-cluster-role.yaml", 1),
		},
		RoleBindings: []parserkubernetes.RoleBinding{
			roleBinding("team-a", "read-pods-a", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api"), serviceAccountSubject("ignored", "worker")}, "a-binding.yaml", 1),
			roleBinding("team-b", "read-pods-b", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "b-binding.yaml", 1),
		},
		ClusterRoleBindings: []parserkubernetes.ClusterRoleBinding{
			clusterRoleBinding("read-pods-cluster", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "cluster-role-binding.yaml", 1),
		},
	}
	reverse := parserkubernetes.Resources{
		ClusterRoleBindings: forward.ClusterRoleBindings,
		RoleBindings: []parserkubernetes.RoleBinding{
			roleBinding("team-b", "read-pods-b", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "b-binding.yaml", 1),
			roleBinding("team-a", "read-pods-a", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("ignored", "worker"), serviceAccountSubject("workloads", "api")}, "a-binding.yaml", 1),
		},
		ClusterRoles: []parserkubernetes.ClusterRole{forward.ClusterRoles[1], forward.ClusterRoles[0]},
	}

	first := graph.New()
	if err := AddRoutes(first, forward); err != nil {
		t.Fatalf("add forward routes: %v", err)
	}
	second := graph.New()
	if err := AddRoutes(second, reverse); err != nil {
		t.Fatalf("add reverse routes: %v", err)
	}

	firstEvidence := edgesOfKind(first, graph.BoundTo)
	secondEvidence := edgesOfKind(second, graph.BoundTo)
	if len(firstEvidence) != len(secondEvidence) {
		t.Fatalf("bound-to counts differ: %d vs %d", len(firstEvidence), len(secondEvidence))
	}
	if string(mustMarshalGraph(t, first)) != string(mustMarshalGraph(t, second)) {
		t.Fatalf("json differs by RBAC input order:\nfirst:  %s\nsecond: %s", mustMarshalGraph(t, first), mustMarshalGraph(t, second))
	}
}

func TestAddRoutesSingleBindingProducesOneScopeRecord(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		ClusterRoles: []parserkubernetes.ClusterRole{clusterRole("pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "cluster-role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{
			roleBinding("prod", "read-pods", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "binding.yaml", 1),
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	edge := edgesOfKind(g, graph.BoundTo)[0]
	if got := strings.Count(edge.Evidence.Detail, "binding_kind="); got != 1 {
		t.Fatalf("scope record count = %d, want 1 in %q", got, edge.Evidence.Detail)
	}
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_kind=RoleBinding", "binding_namespace=prod", "binding_name=read-pods", "scope_kind=namespace", "scope_name=prod", "binding_source=binding.yaml#document=1")
}

func TestAddRoutesUnresolvedRoleAggregatesBindingScopeDeterministically(t *testing.T) {
	forward := parserkubernetes.Resources{
		RoleBindings: []parserkubernetes.RoleBinding{
			roleBinding("prod", "read-missing-a", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "missing"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "a-binding.yaml", 1),
			roleBinding("prod", "read-missing-b", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "missing"}, []parserkubernetes.Subject{serviceAccountSubject("workloads", "api")}, "b-binding.yaml", 1),
		},
	}
	reverse := parserkubernetes.Resources{RoleBindings: []parserkubernetes.RoleBinding{forward.RoleBindings[1], forward.RoleBindings[0]}}

	first := graph.New()
	if err := AddRoutes(first, forward); err != nil {
		t.Fatalf("add forward routes: %v", err)
	}
	second := graph.New()
	if err := AddRoutes(second, reverse); err != nil {
		t.Fatalf("add reverse routes: %v", err)
	}

	assertEdgeKindCount(t, first, graph.BoundTo, 1)
	edge := edgesOfKind(first, graph.BoundTo)[0]
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_kind=RoleBinding", "binding_namespace=prod", "binding_name=read-missing-a", "scope_kind=namespace", "scope_name=prod", "binding_source=a-binding.yaml#document=1")
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_kind=RoleBinding", "binding_namespace=prod", "binding_name=read-missing-b", "scope_kind=namespace", "scope_name=prod", "binding_source=b-binding.yaml#document=1")
	assertNodeKindCount(t, first, graph.Permission, 0)
	assertEdgeKindCount(t, first, graph.GrantsPermission, 0)
	if string(mustMarshalGraph(t, first)) != string(mustMarshalGraph(t, second)) {
		t.Fatalf("unresolved-role json differs by input order:\nfirst:  %s\nsecond: %s", mustMarshalGraph(t, first), mustMarshalGraph(t, second))
	}
}

func TestAddRoutesRoleBindingOmittedServiceAccountNamespaceCreatesNoBinding(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Roles: []parserkubernetes.Role{role("prod", "pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "read-pods", parserkubernetes.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "pod-reader",
		}, []parserkubernetes.Subject{{Kind: "ServiceAccount", Name: "api"}}, "binding.yaml", 1)},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertNodeKindCount(t, g, graph.ServiceAccount, 0)
	assertNodeKindCount(t, g, graph.Role, 0)
	assertNodeKindCount(t, g, graph.Permission, 0)
	assertEdgeKindCount(t, g, graph.BoundTo, 0)
}

func TestAddRoutesClusterRoleBindingOmittedServiceAccountNamespaceCreatesNoBinding(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		ClusterRoles: []parserkubernetes.ClusterRole{clusterRole("pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "cluster-role.yaml", 1)},
		ClusterRoleBindings: []parserkubernetes.ClusterRoleBinding{clusterRoleBinding("read-pods", parserkubernetes.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "pod-reader",
		}, []parserkubernetes.Subject{{Kind: "ServiceAccount", Name: "api"}}, "binding.yaml", 1)},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertNodeKindCount(t, g, graph.ServiceAccount, 0)
	assertNodeKindCount(t, g, graph.Role, 0)
	assertNodeKindCount(t, g, graph.Permission, 0)
	assertEdgeKindCount(t, g, graph.BoundTo, 0)
}

func TestAddRoutesNamespaceMismatchDoesNotBindWrongServiceAccount(t *testing.T) {
	g := graph.New()
	deployment := deployment("staging", "api", map[string]string{"app": "api"}, "deployment.yaml", 1)
	resources := parserkubernetes.Resources{
		Deployments: []parserkubernetes.Deployment{deployment},
		Roles:       []parserkubernetes.Role{role("prod", "pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "read-pods", parserkubernetes.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "pod-reader",
		}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	stagingAccount := graph.NewNode(graph.ServiceAccount, "kubernetes://staging/serviceaccount/default")
	role := graph.NewNode(graph.Role, "kubernetes://prod/role/pod-reader")
	for _, edge := range edgesOfKind(g, graph.BoundTo) {
		if edge.From == stagingAccount.ID && edge.To == role.ID {
			t.Fatalf("bound staging account to prod role: %#v", edge)
		}
	}
}

func TestAddRoutesUnsupportedRoleRefCreatesNoRBACGraph(t *testing.T) {
	tests := []struct {
		name string
		res  parserkubernetes.Resources
	}{
		{
			name: "invalid api group",
			res: parserkubernetes.Resources{
				Roles: []parserkubernetes.Role{role("prod", "pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "role.yaml", 1)},
				RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "read-pods", parserkubernetes.RoleRef{
					APIGroup: "example.io",
					Kind:     "Role",
					Name:     "pod-reader",
				}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
			},
		},
		{
			name: "invalid rolebinding kind",
			res: parserkubernetes.Resources{
				Roles: []parserkubernetes.Role{role("prod", "pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "role.yaml", 1)},
				RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "read-pods", parserkubernetes.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Secret",
					Name:     "pod-reader",
				}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
			},
		},
		{
			name: "invalid clusterrolebinding kind",
			res: parserkubernetes.Resources{
				ClusterRoles: []parserkubernetes.ClusterRole{clusterRole("pod-reader", []parserkubernetes.PolicyRule{podGetRule()}, "cluster-role.yaml", 1)},
				ClusterRoleBindings: []parserkubernetes.ClusterRoleBinding{clusterRoleBinding("read-pods", parserkubernetes.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Role",
					Name:     "pod-reader",
				}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := graph.New()
			if err := AddRoutes(g, tt.res); err != nil {
				t.Fatalf("add routes: %v", err)
			}
			assertNodeKindCount(t, g, graph.ServiceAccount, 0)
			assertNodeKindCount(t, g, graph.Role, 0)
			assertNodeKindCount(t, g, graph.Permission, 0)
			assertEdgeKindCount(t, g, graph.BoundTo, 0)
			assertEdgeKindCount(t, g, graph.GrantsPermission, 0)
		})
	}
}

func TestAddRoutesMissingRoleReferenceCreatesUnresolvedRoleWithoutPermissions(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "read-pods", parserkubernetes.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "missing",
		}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	roleNode := mustNode(t, g, graph.NewNode(graph.Role, "kubernetes://prod/role/missing").ID)
	if got := roleNode.Evidence[0]; !strings.Contains(got.Detail, "unresolved") || strings.Contains(got.Detail, "observed") {
		t.Fatalf("role evidence = %#v, want unresolved and not observed", roleNode.Evidence)
	}
	assertEdgeKindCount(t, g, graph.BoundTo, 1)
	assertNodeKindCount(t, g, graph.Permission, 0)
	assertEdgeKindCount(t, g, graph.GrantsPermission, 0)
}

func TestAddRoutesMissingClusterRoleReferenceCreatesUnresolvedClusterRoleWithoutPermissions(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		ClusterRoleBindings: []parserkubernetes.ClusterRoleBinding{clusterRoleBinding("read-pods", parserkubernetes.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "missing",
		}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	roleNode := mustNode(t, g, graph.NewNode(graph.Role, "kubernetes://cluster/clusterrole/missing").ID)
	if got := roleNode.Evidence[0]; !strings.Contains(got.Detail, "unresolved") || strings.Contains(got.Detail, "observed") {
		t.Fatalf("cluster role evidence = %#v, want unresolved and not observed", roleNode.Evidence)
	}
	assertEdgeKindCount(t, g, graph.BoundTo, 1)
	assertNodeKindCount(t, g, graph.Permission, 0)
	assertEdgeKindCount(t, g, graph.GrantsPermission, 0)
}

func TestAddRoutesReachableObservedRoleWithNoRulesCreatesNoPermissions(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Roles: []parserkubernetes.Role{role("prod", "empty", nil, "role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "bind-empty", parserkubernetes.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "empty",
		}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	mustNode(t, g, graph.NewNode(graph.Role, "kubernetes://prod/role/empty").ID)
	assertEdgeKindCount(t, g, graph.BoundTo, 1)
	assertNodeKindCount(t, g, graph.Permission, 0)
	assertEdgeKindCount(t, g, graph.GrantsPermission, 0)
}

func TestAddRoutesClusterRoleWithOnlyNonResourceURLsCreatesNoPermissions(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		ClusterRoles: []parserkubernetes.ClusterRole{clusterRole("health-reader", []parserkubernetes.PolicyRule{
			{NonResourceURLs: []string{"/healthz"}, Verbs: []string{"get"}},
		}, "cluster-role.yaml", 1)},
		ClusterRoleBindings: []parserkubernetes.ClusterRoleBinding{clusterRoleBinding("bind-health", parserkubernetes.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "health-reader",
		}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	mustNode(t, g, graph.NewNode(graph.Role, "kubernetes://cluster/clusterrole/health-reader").ID)
	assertEdgeKindCount(t, g, graph.BoundTo, 1)
	assertNodeKindCount(t, g, graph.Permission, 0)
	assertEdgeKindCount(t, g, graph.GrantsPermission, 0)
}

func TestAddRoutesRoleWithResourceAndNonResourceRulesCreatesOnlyResourcePermission(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Roles: []parserkubernetes.Role{role("prod", "mixed-reader", []parserkubernetes.PolicyRule{
			podGetRule(),
			{NonResourceURLs: []string{"/healthz"}, Verbs: []string{"get"}},
		}, "role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "bind-mixed", parserkubernetes.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "mixed-reader",
		}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertNodeKindCount(t, g, graph.Permission, 1)
	assertEdgeKindCount(t, g, graph.GrantsPermission, 1)
	permission := nodesOfKind(g, graph.Permission)[0]
	if strings.Contains(permission.Evidence[0].Detail, "nonResourceURLs") || strings.Contains(permission.Evidence[0].Detail, "healthz") {
		t.Fatalf("permission evidence = %#v, want only resource rule", permission.Evidence)
	}
}

func TestAddRoutesRuleWithNonResourceURLsAndResourceFieldsIsSkipped(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Roles: []parserkubernetes.Role{role("prod", "mixed-rule", []parserkubernetes.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, NonResourceURLs: []string{"/healthz"}, Verbs: []string{"get"}},
		}, "role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "bind-mixed-rule", parserkubernetes.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "mixed-rule",
		}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertEdgeKindCount(t, g, graph.BoundTo, 1)
	assertNodeKindCount(t, g, graph.Permission, 0)
	assertEdgeKindCount(t, g, graph.GrantsPermission, 0)
}

func TestAddRoutesRuleWithEmptyResourcesCreatesNoPermission(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Roles: []parserkubernetes.Role{role("prod", "empty-resource", []parserkubernetes.PolicyRule{
			{APIGroups: []string{""}, Verbs: []string{"get"}},
		}, "role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "bind-empty-resource", parserkubernetes.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "empty-resource",
		}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertEdgeKindCount(t, g, graph.BoundTo, 1)
	assertNodeKindCount(t, g, graph.Permission, 0)
	assertEdgeKindCount(t, g, graph.GrantsPermission, 0)
}

func TestAddRoutesNonResourceURLOrderingDoesNotAffectGraphOutput(t *testing.T) {
	forward := parserkubernetes.Resources{
		ClusterRoles: []parserkubernetes.ClusterRole{clusterRole("health-reader", []parserkubernetes.PolicyRule{
			{NonResourceURLs: []string{"/readyz", "/healthz"}, Verbs: []string{"get"}},
		}, "cluster-role.yaml", 1)},
		ClusterRoleBindings: []parserkubernetes.ClusterRoleBinding{clusterRoleBinding("bind-health", parserkubernetes.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "health-reader",
		}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
	}
	reverse := parserkubernetes.Resources{
		ClusterRoleBindings: forward.ClusterRoleBindings,
		ClusterRoles: []parserkubernetes.ClusterRole{clusterRole("health-reader", []parserkubernetes.PolicyRule{
			{NonResourceURLs: []string{"/healthz", "/readyz"}, Verbs: []string{"get"}},
		}, "cluster-role.yaml", 1)},
	}

	first := mustGraphJSON(t, forward)
	second := mustGraphJSON(t, reverse)
	if string(first) != string(second) {
		t.Fatalf("json differs by nonResourceURLs order:\nfirst:  %s\nsecond: %s", first, second)
	}
}

func TestAddRoutesMultipleRulesCreateDistinctDeterministicPermissions(t *testing.T) {
	rules := []parserkubernetes.PolicyRule{
		podGetRule(),
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"list"}},
	}
	resources := parserkubernetes.Resources{
		Roles: []parserkubernetes.Role{role("prod", "reader", rules, "role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "read", parserkubernetes.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "reader",
		}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
	}

	first := mustGraphJSON(t, resources)
	second := mustGraphJSON(t, parserkubernetes.Resources{
		RoleBindings: resources.RoleBindings,
		Roles:        []parserkubernetes.Role{role("prod", "reader", []parserkubernetes.PolicyRule{rules[1], rules[0]}, "role.yaml", 1)},
	})
	if string(first) != string(second) {
		t.Fatalf("json differs by equivalent rule ordering:\nfirst:  %s\nsecond: %s", first, second)
	}

	g := graph.New()
	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}
	assertNodeKindCount(t, g, graph.Permission, 2)
	assertEdgeKindCount(t, g, graph.GrantsPermission, 2)
}

func TestPermissionNodeCanonicalID(t *testing.T) {
	base := parserkubernetes.PolicyRule{
		APIGroups:     []string{"apps", ""},
		Resources:     []string{"pods", "deployments"},
		ResourceNames: []string{"api"},
		Verbs:         []string{"get", "list"},
	}
	reordered := parserkubernetes.PolicyRule{
		APIGroups:     []string{"", "apps"},
		Resources:     []string{"deployments", "pods"},
		ResourceNames: []string{"api"},
		Verbs:         []string{"list", "get"},
	}
	changedVerb := base
	changedVerb.Verbs = []string{"watch"}
	changedAPIGroup := base
	changedAPIGroup.APIGroups = []string{"batch"}
	noResourceNames := base
	noResourceNames.ResourceNames = nil

	baseNode, _, err := permissionNode(base)
	if err != nil {
		t.Fatalf("base permission node: %v", err)
	}
	reorderedNode, _, err := permissionNode(reordered)
	if err != nil {
		t.Fatalf("reordered permission node: %v", err)
	}
	if reorderedNode.ID != baseNode.ID {
		t.Fatalf("reordered equivalent rule ID = %q, want %q", reorderedNode.ID, baseNode.ID)
	}
	for name, rule := range map[string]parserkubernetes.PolicyRule{
		"changed verbs":         changedVerb,
		"changed api groups":    changedAPIGroup,
		"empty resource names":  noResourceNames,
		"nonempty resourceName": base,
	} {
		node, _, err := permissionNode(rule)
		if err != nil {
			t.Fatalf("%s permission node: %v", name, err)
		}
		if name != "nonempty resourceName" && node.ID == baseNode.ID {
			t.Fatalf("%s permission ID = %q, want different from base %q", name, node.ID, baseNode.ID)
		}
		if name == "nonempty resourceName" && !strings.Contains(node.Evidence[0].Detail, `"apiGroups":["","apps"]`) {
			t.Fatalf("permission evidence detail = %q, want empty core API group preserved", node.Evidence[0].Detail)
		}
	}
}

func TestAddRoutesSharedPermissionNodeEvidenceDoesNotDependOnRoleOrder(t *testing.T) {
	rule := podGetRule()
	firstResources := parserkubernetes.Resources{
		Roles: []parserkubernetes.Role{
			role("prod", "a-reader", []parserkubernetes.PolicyRule{rule}, "a-role.yaml", 1),
			role("prod", "z-reader", []parserkubernetes.PolicyRule{rule}, "z-role.yaml", 1),
		},
		RoleBindings: []parserkubernetes.RoleBinding{
			roleBinding("prod", "a-bind", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "a-reader"}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "a-binding.yaml", 1),
			roleBinding("prod", "z-bind", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "z-reader"}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "z-binding.yaml", 1),
		},
	}
	secondResources := parserkubernetes.Resources{
		Roles:        []parserkubernetes.Role{firstResources.Roles[1], firstResources.Roles[0]},
		RoleBindings: []parserkubernetes.RoleBinding{firstResources.RoleBindings[1], firstResources.RoleBindings[0]},
	}

	first := graph.New()
	if err := AddRoutes(first, firstResources); err != nil {
		t.Fatalf("add first routes: %v", err)
	}
	second := graph.New()
	if err := AddRoutes(second, secondResources); err != nil {
		t.Fatalf("add second routes: %v", err)
	}

	assertNodeKindCount(t, first, graph.Permission, 1)
	assertEdgeKindCount(t, first, graph.GrantsPermission, 2)
	firstPermission := nodesOfKind(first, graph.Permission)[0]
	secondPermission := nodesOfKind(second, graph.Permission)[0]
	if !reflect.DeepEqual(firstPermission, secondPermission) {
		t.Fatalf("permission node differs by role order:\nfirst: %#v\nsecond: %#v", firstPermission, secondPermission)
	}
	firstJSON := mustMarshalGraph(t, first)
	secondJSON := mustMarshalGraph(t, second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("json differs by role order:\nfirst:  %s\nsecond: %s", firstJSON, secondJSON)
	}
}

func TestAddRoutesIdenticalDuplicateRBACResourcesAreAccepted(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Roles: []parserkubernetes.Role{
			role("prod", "reader", []parserkubernetes.PolicyRule{podGetRule()}, "a-role.yaml", 1),
			role("prod", "reader", []parserkubernetes.PolicyRule{podGetRule()}, "z-role.yaml", 1),
		},
		RoleBindings: []parserkubernetes.RoleBinding{
			roleBinding("prod", "read", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "reader"}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "a-binding.yaml", 1),
			roleBinding("prod", "read", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "reader"}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "z-binding.yaml", 1),
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertNodeKindCount(t, g, graph.Role, 1)
	assertNodeKindCount(t, g, graph.Permission, 1)
	assertEdgeKindCount(t, g, graph.BoundTo, 1)
}

func TestAddRoutesRejectsConflictingDuplicateRBACBeforeMutation(t *testing.T) {
	tests := []struct {
		name string
		res  parserkubernetes.Resources
		kind string
		id   string
	}{
		{
			name: "role",
			res: parserkubernetes.Resources{Roles: []parserkubernetes.Role{
				role("prod", "reader", []parserkubernetes.PolicyRule{podGetRule()}, "a-role.yaml", 1),
				role("prod", "reader", []parserkubernetes.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}}, "z-role.yaml", 1),
			}},
			kind: "Role",
			id:   "prod/reader",
		},
		{
			name: "rolebinding",
			res: parserkubernetes.Resources{RoleBindings: []parserkubernetes.RoleBinding{
				roleBinding("prod", "read", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "reader"}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "a-binding.yaml", 1),
				roleBinding("prod", "read", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "other"}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "z-binding.yaml", 1),
			}},
			kind: "RoleBinding",
			id:   "prod/read",
		},
		{
			name: "clusterrole",
			res: parserkubernetes.Resources{ClusterRoles: []parserkubernetes.ClusterRole{
				clusterRole("reader", []parserkubernetes.PolicyRule{podGetRule()}, "a-cluster-role.yaml", 1),
				clusterRole("reader", []parserkubernetes.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}}, "z-cluster-role.yaml", 1),
			}},
			kind: "ClusterRole",
			id:   "reader",
		},
		{
			name: "clusterrolebinding",
			res: parserkubernetes.Resources{ClusterRoleBindings: []parserkubernetes.ClusterRoleBinding{
				clusterRoleBinding("read", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "reader"}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "a-binding.yaml", 1),
				clusterRoleBinding("read", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "other"}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "z-binding.yaml", 1),
			}},
			kind: "ClusterRoleBinding",
			id:   "read",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := graph.New()
			err := AddRoutes(g, tt.res)
			if err == nil {
				t.Fatal("add routes error = nil, want RBAC duplicate conflict")
			}
			assertConflictError(t, err, tt.kind, tt.id, "a-", "z-")
			assertGraphCounts(t, g, 0, 0, 0)
		})
	}
}

func TestAddRoutesRBACConflictLeavesPrepopulatedGraphUnchanged(t *testing.T) {
	g := graph.New()
	if err := AddRoutes(g, routeResources("LoadBalancer")); err != nil {
		t.Fatalf("seed graph: %v", err)
	}
	before := mustMarshalGraph(t, g)
	resources := parserkubernetes.Resources{
		Roles: []parserkubernetes.Role{
			role("prod", "reader", []parserkubernetes.PolicyRule{podGetRule()}, "a-role.yaml", 1),
			role("prod", "reader", []parserkubernetes.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}}, "z-role.yaml", 1),
		},
	}

	if err := AddRoutes(g, resources); err == nil {
		t.Fatal("add routes error = nil, want RBAC duplicate conflict")
	}
	after := mustMarshalGraph(t, g)
	if string(after) != string(before) {
		t.Fatalf("graph changed after failed AddRoutes:\nbefore: %s\nafter:  %s", before, after)
	}
}

func TestAddRoutesPublicDeploymentServiceAccountCanReadSecret(t *testing.T) {
	deploy := deployment("prod", "api", map[string]string{"app": "api"}, "deployment.yaml", 1)
	deploy.ServiceAccountName = "api"
	resources := parserkubernetes.Resources{
		Services:        []parserkubernetes.Service{service("prod", "public-api", "LoadBalancer", map[string]string{"app": "api"}, "service.yaml", 1)},
		Deployments:     []parserkubernetes.Deployment{deploy},
		ServiceAccounts: []parserkubernetes.ServiceAccount{serviceAccount("prod", "api", nil, "service-account.yaml", 1)},
		Secrets:         []parserkubernetes.Secret{secret("prod", "database-password", "secret.yaml", 1)},
		Roles:           []parserkubernetes.Role{role("prod", "secret-reader", []parserkubernetes.PolicyRule{secretRule([]string{""}, []string{"secrets"}, nil, []string{"get"})}, "role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "read-secrets", parserkubernetes.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "secret-reader",
		}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
	}
	g := graph.New()

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertEdgeKindCount(t, g, graph.RoutesTo, 1)
	assertEdgeKindCount(t, g, graph.RunsAs, 1)
	assertEdgeKindCount(t, g, graph.CanRead, 1)
	account := graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/api")
	secretNode := graph.NewNode(graph.Secret, "kubernetes://prod/secret/database-password")
	edge := edgesOfKind(g, graph.CanRead)[0]
	if edge.From != account.ID || edge.To != secretNode.ID {
		t.Fatalf("can-read endpoints = %q -> %q, want %q -> %q", edge.From, edge.To, account.ID, secretNode.ID)
	}
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_kind=RoleBinding", "role_kind=Role", "matched_verb=get", "secret_sources=secret.yaml#document=1")
}

func TestAddRoutesSecretNodesAggregateAllDistinctSources(t *testing.T) {
	tests := []struct {
		name    string
		secrets []parserkubernetes.Secret
		want    []graph.SourceEvidence
	}{
		{
			name: "different files",
			secrets: []parserkubernetes.Secret{
				secret("prod", "database-password", "z-secret.yaml", 1),
				secret("prod", "database-password", "a-secret.yaml", 1),
			},
			want: []graph.SourceEvidence{
				{Source: "a-secret.yaml#document=1", Detail: "kubernetes Secret metadata"},
				{Source: "z-secret.yaml#document=1", Detail: "kubernetes Secret metadata"},
			},
		},
		{
			name: "different documents",
			secrets: []parserkubernetes.Secret{
				secret("prod", "database-password", "secret.yaml", 2),
				secret("prod", "database-password", "secret.yaml", 1),
			},
			want: []graph.SourceEvidence{
				{Source: "secret.yaml#document=1", Detail: "kubernetes Secret metadata"},
				{Source: "secret.yaml#document=2", Detail: "kubernetes Secret metadata"},
			},
		},
		{
			name: "identical source deduplicates",
			secrets: []parserkubernetes.Secret{
				secret("prod", "database-password", "secret.yaml", 1),
				secret("prod", "database-password", "secret.yaml", 1),
			},
			want: []graph.SourceEvidence{
				{Source: "secret.yaml#document=1", Detail: "kubernetes Secret metadata"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := graph.New()
			if err := AddRoutes(g, parserkubernetes.Resources{Secrets: tt.secrets}); err != nil {
				t.Fatalf("add routes: %v", err)
			}

			assertNodeKindCount(t, g, graph.Secret, 1)
			secretNode := mustNode(t, g, graph.NewNode(graph.Secret, "kubernetes://prod/secret/database-password").ID)
			if !reflect.DeepEqual(secretNode.Evidence, tt.want) {
				t.Fatalf("secret evidence = %#v, want %#v", secretNode.Evidence, tt.want)
			}
		})
	}
}

func TestAddRoutesSecretSourceEvidenceIsDeterministic(t *testing.T) {
	forward := parserkubernetes.Resources{Secrets: []parserkubernetes.Secret{
		secret("prod", "database-password", "a-secret.yaml", 1),
		secret("prod", "database-password", "z-secret.yaml", 1),
	}}
	reverse := parserkubernetes.Resources{Secrets: []parserkubernetes.Secret{
		forward.Secrets[1],
		forward.Secrets[0],
	}}

	first := mustGraphJSON(t, forward)
	second := mustGraphJSON(t, reverse)
	if string(first) != string(second) {
		t.Fatalf("json differs by Secret source order:\nfirst:  %s\nsecond: %s", first, second)
	}
}

func TestAddRoutesSecretReadAuthorizationSemantics(t *testing.T) {
	tests := []struct {
		name      string
		rule      parserkubernetes.PolicyRule
		wantEdges int
		wantVerb  string
	}{
		{
			name:      "core api group",
			rule:      secretRule([]string{""}, []string{"secrets"}, nil, []string{"get"}),
			wantEdges: 1,
			wantVerb:  "get",
		},
		{
			name:      "wildcard api group",
			rule:      secretRule([]string{"*"}, []string{"secrets"}, nil, []string{"get"}),
			wantEdges: 1,
			wantVerb:  "get",
		},
		{
			name:      "secrets resource",
			rule:      secretRule([]string{""}, []string{"secrets"}, nil, []string{"get"}),
			wantEdges: 1,
			wantVerb:  "get",
		},
		{
			name:      "wildcard resource",
			rule:      secretRule([]string{""}, []string{"*"}, nil, []string{"get"}),
			wantEdges: 1,
			wantVerb:  "get",
		},
		{
			name:      "unrelated resource",
			rule:      secretRule([]string{""}, []string{"pods"}, nil, []string{"get"}),
			wantEdges: 0,
		},
		{
			name:      "wildcard verb",
			rule:      secretRule([]string{""}, []string{"secrets"}, nil, []string{"*"}),
			wantEdges: 1,
			wantVerb:  "*",
		},
		{
			name:      "unrelated verb",
			rule:      secretRule([]string{""}, []string{"secrets"}, nil, []string{"update"}),
			wantEdges: 0,
		},
		{
			name:      "matching resourceNames get",
			rule:      secretRule([]string{""}, []string{"secrets"}, []string{"database-password"}, []string{"get"}),
			wantEdges: 1,
			wantVerb:  "get",
		},
		{
			name:      "nonmatching resourceNames",
			rule:      secretRule([]string{""}, []string{"secrets"}, []string{"other-secret"}, []string{"get"}),
			wantEdges: 0,
		},
		{
			name:      "empty resourceNames list",
			rule:      secretRule([]string{""}, []string{"secrets"}, nil, []string{"list"}),
			wantEdges: 1,
			wantVerb:  "list",
		},
		{
			name:      "empty resourceNames watch",
			rule:      secretRule([]string{""}, []string{"secrets"}, nil, []string{"watch"}),
			wantEdges: 1,
			wantVerb:  "watch",
		},
		{
			name:      "list resourceNames unsupported",
			rule:      secretRule([]string{""}, []string{"secrets"}, []string{"database-password"}, []string{"list"}),
			wantEdges: 0,
		},
		{
			name:      "watch resourceNames unsupported",
			rule:      secretRule([]string{""}, []string{"secrets"}, []string{"database-password"}, []string{"watch"}),
			wantEdges: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := graph.New()
			resources := secretReadResources(tt.rule)
			if err := AddRoutes(g, resources); err != nil {
				t.Fatalf("add routes: %v", err)
			}

			assertEdgeKindCount(t, g, graph.CanRead, tt.wantEdges)
			if tt.wantEdges == 1 {
				edge := edgesOfKind(g, graph.CanRead)[0]
				assertEvidenceRecordContains(t, edge.Evidence.Detail, "matched_verb="+tt.wantVerb, "secret_name=prod/database-password")
			}
		})
	}
}

func TestAddRoutesSecretReadScopeSemantics(t *testing.T) {
	t.Run("rolebinding to clusterrole remains namespace scoped", func(t *testing.T) {
		g := graph.New()
		resources := parserkubernetes.Resources{
			Secrets: []parserkubernetes.Secret{
				secret("prod", "database-password", "prod-secret.yaml", 1),
				secret("staging", "database-password", "staging-secret.yaml", 1),
			},
			ClusterRoles: []parserkubernetes.ClusterRole{clusterRole("secret-reader", []parserkubernetes.PolicyRule{secretRule([]string{""}, []string{"secrets"}, nil, []string{"get"})}, "cluster-role.yaml", 1)},
			RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "read-secrets", parserkubernetes.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     "secret-reader",
			}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
		}

		if err := AddRoutes(g, resources); err != nil {
			t.Fatalf("add routes: %v", err)
		}

		assertEdgeKindCount(t, g, graph.CanRead, 1)
		edge := edgesOfKind(g, graph.CanRead)[0]
		prodSecret := graph.NewNode(graph.Secret, "kubernetes://prod/secret/database-password")
		stagingSecret := graph.NewNode(graph.Secret, "kubernetes://staging/secret/database-password")
		if edge.To != prodSecret.ID || edge.To == stagingSecret.ID {
			t.Fatalf("can-read destination = %q, want prod secret only", edge.To)
		}
		assertEvidenceRecordContains(t, edge.Evidence.Detail, "scope_kind=namespace", "scope_name=prod")
	})

	t.Run("clusterrolebinding grants across namespaces", func(t *testing.T) {
		g := graph.New()
		resources := parserkubernetes.Resources{
			Secrets: []parserkubernetes.Secret{
				secret("prod", "database-password", "prod-secret.yaml", 1),
				secret("staging", "database-password", "staging-secret.yaml", 1),
			},
			ClusterRoles: []parserkubernetes.ClusterRole{clusterRole("secret-reader", []parserkubernetes.PolicyRule{secretRule([]string{""}, []string{"secrets"}, nil, []string{"get"})}, "cluster-role.yaml", 1)},
			ClusterRoleBindings: []parserkubernetes.ClusterRoleBinding{clusterRoleBinding("read-secrets", parserkubernetes.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     "secret-reader",
			}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
		}

		if err := AddRoutes(g, resources); err != nil {
			t.Fatalf("add routes: %v", err)
		}

		assertEdgeKindCount(t, g, graph.CanRead, 2)
		for _, edge := range edgesOfKind(g, graph.CanRead) {
			assertEvidenceRecordContains(t, edge.Evidence.Detail, "scope_kind=cluster")
		}
	})

	t.Run("role cannot grant outside binding namespace", func(t *testing.T) {
		g := graph.New()
		resources := parserkubernetes.Resources{
			Secrets: []parserkubernetes.Secret{
				secret("staging", "database-password", "staging-secret.yaml", 1),
			},
			Roles: []parserkubernetes.Role{role("prod", "secret-reader", []parserkubernetes.PolicyRule{secretRule([]string{""}, []string{"secrets"}, nil, []string{"get"})}, "role.yaml", 1)},
			RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "read-secrets", parserkubernetes.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     "secret-reader",
			}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
		}

		if err := AddRoutes(g, resources); err != nil {
			t.Fatalf("add routes: %v", err)
		}

		assertEdgeKindCount(t, g, graph.CanRead, 0)
	})
}

func TestAddRoutesSecretReadResourceNamesAndEmptyResourceNames(t *testing.T) {
	t.Run("empty resourceNames matches all secrets in scope", func(t *testing.T) {
		g := graph.New()
		resources := secretReadResources(secretRule([]string{""}, []string{"secrets"}, nil, []string{"get"}))
		resources.Secrets = append(resources.Secrets, secret("prod", "api-token", "token-secret.yaml", 1))

		if err := AddRoutes(g, resources); err != nil {
			t.Fatalf("add routes: %v", err)
		}

		assertEdgeKindCount(t, g, graph.CanRead, 2)
	})

	t.Run("resourceNames limits access to exact names", func(t *testing.T) {
		g := graph.New()
		resources := secretReadResources(secretRule([]string{""}, []string{"secrets"}, []string{"database-password"}, []string{"get"}))
		resources.Secrets = append(resources.Secrets, secret("prod", "api-token", "token-secret.yaml", 1))

		if err := AddRoutes(g, resources); err != nil {
			t.Fatalf("add routes: %v", err)
		}

		assertEdgeKindCount(t, g, graph.CanRead, 1)
		edge := edgesOfKind(g, graph.CanRead)[0]
		wantSecret := graph.NewNode(graph.Secret, "kubernetes://prod/secret/database-password")
		otherSecret := graph.NewNode(graph.Secret, "kubernetes://prod/secret/api-token")
		if edge.To != wantSecret.ID || edge.To == otherSecret.ID {
			t.Fatalf("can-read destination = %q, want only named Secret", edge.To)
		}
	})
}

func TestAddRoutesUnsupportedSecretReadInputsCreateNoAccess(t *testing.T) {
	tests := []struct {
		name string
		res  parserkubernetes.Resources
	}{
		{
			name: "unresolved role",
			res: parserkubernetes.Resources{
				Secrets: []parserkubernetes.Secret{secret("prod", "database-password", "secret.yaml", 1)},
				RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "read-secrets", parserkubernetes.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Role",
					Name:     "missing",
				}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
			},
		},
		{
			name: "invalid roleRef apiGroup",
			res: parserkubernetes.Resources{
				Secrets: []parserkubernetes.Secret{secret("prod", "database-password", "secret.yaml", 1)},
				Roles:   []parserkubernetes.Role{role("prod", "secret-reader", []parserkubernetes.PolicyRule{secretRule([]string{""}, []string{"secrets"}, nil, []string{"get"})}, "role.yaml", 1)},
				RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "read-secrets", parserkubernetes.RoleRef{
					APIGroup: "example.io",
					Kind:     "Role",
					Name:     "secret-reader",
				}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
			},
		},
		{
			name: "invalid roleRef kind",
			res: parserkubernetes.Resources{
				Secrets: []parserkubernetes.Secret{secret("prod", "database-password", "secret.yaml", 1)},
				Roles:   []parserkubernetes.Role{role("prod", "secret-reader", []parserkubernetes.PolicyRule{secretRule([]string{""}, []string{"secrets"}, nil, []string{"get"})}, "role.yaml", 1)},
				RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "read-secrets", parserkubernetes.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Secret",
					Name:     "secret-reader",
				}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
			},
		},
		{
			name: "namespace-less subject",
			res: parserkubernetes.Resources{
				Secrets: []parserkubernetes.Secret{secret("prod", "database-password", "secret.yaml", 1)},
				Roles:   []parserkubernetes.Role{role("prod", "secret-reader", []parserkubernetes.PolicyRule{secretRule([]string{""}, []string{"secrets"}, nil, []string{"get"})}, "role.yaml", 1)},
				RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "read-secrets", parserkubernetes.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Role",
					Name:     "secret-reader",
				}, []parserkubernetes.Subject{{Kind: "ServiceAccount", Name: "api"}}, "binding.yaml", 1)},
			},
		},
		{
			name: "nonResourceURLs",
			res: parserkubernetes.Resources{
				Secrets: []parserkubernetes.Secret{secret("prod", "database-password", "secret.yaml", 1)},
				Roles: []parserkubernetes.Role{role("prod", "secret-reader", []parserkubernetes.PolicyRule{{
					APIGroups:       []string{""},
					Resources:       []string{"secrets"},
					NonResourceURLs: []string{"/healthz"},
					Verbs:           []string{"get"},
				}}, "role.yaml", 1)},
				RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "read-secrets", parserkubernetes.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Role",
					Name:     "secret-reader",
				}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := graph.New()
			if err := AddRoutes(g, tt.res); err != nil {
				t.Fatalf("add routes: %v", err)
			}
			assertEdgeKindCount(t, g, graph.CanRead, 0)
		})
	}
}

func TestAddRoutesMultipleSecretReadChainsAggregateOntoOneEdge(t *testing.T) {
	g := graph.New()
	resources := parserkubernetes.Resources{
		Secrets: []parserkubernetes.Secret{secret("prod", "database-password", "secret.yaml", 1)},
		Roles: []parserkubernetes.Role{
			role("prod", "secret-reader-a", []parserkubernetes.PolicyRule{secretRule([]string{""}, []string{"secrets"}, nil, []string{"get"})}, "a-role.yaml", 1),
			role("prod", "secret-reader-b", []parserkubernetes.PolicyRule{secretRule([]string{""}, []string{"secrets"}, nil, []string{"get"})}, "b-role.yaml", 1),
		},
		RoleBindings: []parserkubernetes.RoleBinding{
			roleBinding("prod", "read-secrets-a", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "secret-reader-a"}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "a-binding.yaml", 1),
			roleBinding("prod", "read-secrets-b", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "secret-reader-b"}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "b-binding.yaml", 1),
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertEdgeKindCount(t, g, graph.CanRead, 1)
	edge := edgesOfKind(g, graph.CanRead)[0]
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_name=read-secrets-a", "role_name=kubernetes://prod/role/secret-reader-a")
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "binding_name=read-secrets-b", "role_name=kubernetes://prod/role/secret-reader-b")
	if got := strings.Count(edge.Evidence.Detail, "binding_name="); got != 2 {
		t.Fatalf("can-read evidence record count = %d, want 2 in %q", got, edge.Evidence.Detail)
	}
}

func TestAddRoutesSecretReadEvidenceAndJSONAreDeterministic(t *testing.T) {
	forward := parserkubernetes.Resources{
		Secrets: []parserkubernetes.Secret{
			secret("prod", "database-password", "a-secret.yaml", 1),
			secret("prod", "database-password", "z-secret.yaml", 1),
		},
		Roles: []parserkubernetes.Role{
			role("prod", "secret-reader-a", []parserkubernetes.PolicyRule{secretRule([]string{""}, []string{"secrets"}, nil, []string{"get"})}, "a-role.yaml", 1),
			role("prod", "secret-reader-b", []parserkubernetes.PolicyRule{secretRule([]string{""}, []string{"secrets"}, nil, []string{"get"})}, "b-role.yaml", 1),
		},
		RoleBindings: []parserkubernetes.RoleBinding{
			roleBinding("prod", "read-secrets-a", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "secret-reader-a"}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "a-binding.yaml", 1),
			roleBinding("prod", "read-secrets-b", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "secret-reader-b"}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "b-binding.yaml", 1),
		},
	}
	reverse := parserkubernetes.Resources{
		RoleBindings: []parserkubernetes.RoleBinding{forward.RoleBindings[1], forward.RoleBindings[0]},
		Roles:        []parserkubernetes.Role{forward.Roles[1], forward.Roles[0]},
		Secrets:      []parserkubernetes.Secret{forward.Secrets[1], forward.Secrets[0]},
	}

	first := mustGraphJSON(t, forward)
	second := mustGraphJSON(t, reverse)
	if string(first) != string(second) {
		t.Fatalf("json differs by Secret read input order:\nfirst:  %s\nsecond: %s", first, second)
	}

	g := graph.New()
	if err := AddRoutes(g, forward); err != nil {
		t.Fatalf("add routes: %v", err)
	}
	edge := edgesOfKind(g, graph.CanRead)[0]
	assertEvidenceRecordContains(t, edge.Evidence.Detail, "secret_sources=a-secret.yaml#document=1,z-secret.yaml#document=1")
}

func TestAddRoutesDuplicateSecretReadEvidenceDeduplicates(t *testing.T) {
	g := graph.New()
	binding := roleBinding("prod", "read-secrets", parserkubernetes.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "secret-reader"}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)
	resources := parserkubernetes.Resources{
		Secrets: []parserkubernetes.Secret{secret("prod", "database-password", "secret.yaml", 1)},
		Roles:   []parserkubernetes.Role{role("prod", "secret-reader", []parserkubernetes.PolicyRule{secretRule([]string{""}, []string{"secrets"}, nil, []string{"get"})}, "role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{
			binding,
			binding,
		},
	}

	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	assertEdgeKindCount(t, g, graph.CanRead, 1)
	edge := edgesOfKind(g, graph.CanRead)[0]
	if got := strings.Count(edge.Evidence.Detail, "binding_name=read-secrets"); got != 1 {
		t.Fatalf("can-read evidence record count = %d, want 1 in %q", got, edge.Evidence.Detail)
	}
}

func TestAddRoutesSecretReadConflictLeavesGraphsUnchanged(t *testing.T) {
	t.Run("empty graph", func(t *testing.T) {
		g := graph.New()
		resources := secretReadResources(secretRule([]string{""}, []string{"secrets"}, nil, []string{"get"}))
		resources.Roles = append(resources.Roles, role("prod", "secret-reader", []parserkubernetes.PolicyRule{secretRule([]string{""}, []string{"pods"}, nil, []string{"get"})}, "conflict-role.yaml", 1))

		err := AddRoutes(g, resources)
		if err == nil {
			t.Fatal("add routes error = nil, want duplicate Role conflict")
		}
		assertGraphCounts(t, g, 0, 0, 0)
	})

	t.Run("prepopulated graph", func(t *testing.T) {
		g := graph.New()
		if err := AddRoutes(g, routeResources("LoadBalancer")); err != nil {
			t.Fatalf("seed graph: %v", err)
		}
		before := mustMarshalGraph(t, g)
		resources := secretReadResources(secretRule([]string{""}, []string{"secrets"}, nil, []string{"get"}))
		resources.Roles = append(resources.Roles, role("prod", "secret-reader", []parserkubernetes.PolicyRule{secretRule([]string{""}, []string{"pods"}, nil, []string{"get"})}, "conflict-role.yaml", 1))

		if err := AddRoutes(g, resources); err == nil {
			t.Fatal("add routes error = nil, want duplicate Role conflict")
		}
		after := mustMarshalGraph(t, g)
		if string(after) != string(before) {
			t.Fatalf("graph changed after failed AddRoutes:\nbefore: %s\nafter:  %s", before, after)
		}
	})
}

func TestSecretValuesNeverAppearInParserGraphErrorsOrEvidence(t *testing.T) {
	dir := t.TempDir()
	const fakeDataValue = "FAKE_SECRET_GRAPH_DATA_VALUE_DO_NOT_RETAIN"
	const fakeStringDataValue = "FAKE_SECRET_GRAPH_STRINGDATA_VALUE_DO_NOT_RETAIN"
	writeManifest(t, dir, "resources.yaml", `apiVersion: v1
kind: Secret
metadata:
  name: database-password
  namespace: prod
data:
  password: FAKE_SECRET_GRAPH_DATA_VALUE_DO_NOT_RETAIN
stringData:
  token: FAKE_SECRET_GRAPH_STRINGDATA_VALUE_DO_NOT_RETAIN
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: prod
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-secrets
  namespace: prod
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: secret-reader
subjects:
- kind: ServiceAccount
  name: api
  namespace: prod
`)
	resources, err := parserkubernetes.ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	parserJSON, err := json.Marshal(resources)
	if err != nil {
		t.Fatalf("marshal resources: %v", err)
	}
	g := graph.New()
	if err := AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}
	graphJSON := mustMarshalGraph(t, g)
	evidence := allGraphEvidence(g)

	badDir := t.TempDir()
	const malformedFakeValue = "FAKE_SECRET_MALFORMED_VALUE_DO_NOT_RETAIN"
	writeManifest(t, badDir, "bad-secret.yaml", `apiVersion: v1
kind: Secret
metadata: [
data:
  password: FAKE_SECRET_MALFORMED_VALUE_DO_NOT_RETAIN
`)
	_, parseErr := parserkubernetes.ParseDir(badDir)
	if parseErr == nil {
		t.Fatal("parse malformed Secret error = nil, want error")
	}

	for _, value := range []string{fakeDataValue, fakeStringDataValue, malformedFakeValue} {
		for name, output := range map[string]string{
			"parser resources": string(parserJSON),
			"graph json":       string(graphJSON),
			"evidence":         evidence,
			"parse error":      parseErr.Error(),
		} {
			if strings.Contains(output, value) {
				t.Fatalf("%s contains secret value %q: %s", name, value, output)
			}
		}
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

func secret(namespace, name, filename string, document int) parserkubernetes.Secret {
	return parserkubernetes.Secret{
		Namespace: namespace,
		Name:      name,
		Source:    parserkubernetes.Source{Filename: filename, Document: document},
	}
}

func role(namespace, name string, rules []parserkubernetes.PolicyRule, filename string, document int) parserkubernetes.Role {
	return parserkubernetes.Role{
		Namespace: namespace,
		Name:      name,
		Rules:     rules,
		Source:    parserkubernetes.Source{Filename: filename, Document: document},
	}
}

func clusterRole(name string, rules []parserkubernetes.PolicyRule, filename string, document int) parserkubernetes.ClusterRole {
	return parserkubernetes.ClusterRole{
		Name:   name,
		Rules:  rules,
		Source: parserkubernetes.Source{Filename: filename, Document: document},
	}
}

func roleBinding(namespace, name string, roleRef parserkubernetes.RoleRef, subjects []parserkubernetes.Subject, filename string, document int) parserkubernetes.RoleBinding {
	return parserkubernetes.RoleBinding{
		Namespace: namespace,
		Name:      name,
		RoleRef:   roleRef,
		Subjects:  subjects,
		Source:    parserkubernetes.Source{Filename: filename, Document: document},
	}
}

func clusterRoleBinding(name string, roleRef parserkubernetes.RoleRef, subjects []parserkubernetes.Subject, filename string, document int) parserkubernetes.ClusterRoleBinding {
	return parserkubernetes.ClusterRoleBinding{
		Name:     name,
		RoleRef:  roleRef,
		Subjects: subjects,
		Source:   parserkubernetes.Source{Filename: filename, Document: document},
	}
}

func serviceAccountSubject(namespace, name string) parserkubernetes.Subject {
	return parserkubernetes.Subject{
		Kind:      "ServiceAccount",
		Namespace: namespace,
		Name:      name,
	}
}

func podGetRule() parserkubernetes.PolicyRule {
	return parserkubernetes.PolicyRule{
		APIGroups: []string{""},
		Resources: []string{"pods"},
		Verbs:     []string{"get"},
	}
}

func secretRule(apiGroups, resources, resourceNames, verbs []string) parserkubernetes.PolicyRule {
	return parserkubernetes.PolicyRule{
		APIGroups:     apiGroups,
		Resources:     resources,
		ResourceNames: resourceNames,
		Verbs:         verbs,
	}
}

func secretReadResources(rule parserkubernetes.PolicyRule) parserkubernetes.Resources {
	return parserkubernetes.Resources{
		Secrets: []parserkubernetes.Secret{secret("prod", "database-password", "secret.yaml", 1)},
		Roles:   []parserkubernetes.Role{role("prod", "secret-reader", []parserkubernetes.PolicyRule{rule}, "role.yaml", 1)},
		RoleBindings: []parserkubernetes.RoleBinding{roleBinding("prod", "read-secrets", parserkubernetes.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "secret-reader",
		}, []parserkubernetes.Subject{serviceAccountSubject("prod", "api")}, "binding.yaml", 1)},
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

func nodesOfKind(g *graph.Graph, kind graph.NodeKind) []graph.Node {
	var nodes []graph.Node
	for _, node := range g.Nodes() {
		if node.Kind == kind {
			nodes = append(nodes, node)
		}
	}
	return nodes
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

func assertEvidenceRecordContains(t *testing.T, detail string, fields ...string) {
	t.Helper()

	for _, record := range strings.Split(detail, " | ") {
		matches := true
		for _, field := range fields {
			if !strings.Contains(record, field) {
				matches = false
				break
			}
		}
		if matches {
			return
		}
	}
	t.Fatalf("evidence detail = %q, want one record containing %#v", detail, fields)
}

func allGraphEvidence(g *graph.Graph) string {
	var values []string
	for _, node := range g.Nodes() {
		for _, evidence := range node.Evidence {
			values = append(values, evidence.Source, evidence.Detail)
		}
	}
	for _, edge := range g.Edges() {
		values = append(values, edge.Evidence.Source, edge.Evidence.Detail)
	}
	sort.Strings(values)
	return strings.Join(values, "\n")
}

func writeManifest(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write manifest %q: %v", name, err)
	}
	return path
}
