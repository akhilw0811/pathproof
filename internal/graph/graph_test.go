package graph

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestNewNodeStableID(t *testing.T) {
	first := NewNode(PublicEndpoint, "public-api")
	second := NewNode(PublicEndpoint, "public-api")

	if first.ID != second.ID {
		t.Fatalf("node ID = %q, want %q", second.ID, first.ID)
	}
}

func TestGraphAddNodeDeduplicates(t *testing.T) {
	g := New()
	node := NewNode(Workload, "orders-api")

	first := mustAddNode(t, g, node)
	second := mustAddNode(t, g, NewNode(Workload, "orders-api"))

	if first != node {
		t.Fatalf("first added node = %#v, want %#v", first, node)
	}
	if second != node {
		t.Fatalf("deduplicated node = %#v, want original %#v", second, node)
	}
	if got := g.Nodes(); len(got) != 1 {
		t.Fatalf("node count = %d, want 1", len(got))
	}
}

func TestGraphAddNodeAssignsEmptyCanonicalIDs(t *testing.T) {
	g := New()

	workload := mustAddNode(t, g, Node{Kind: Workload, Name: "orders-api"})
	secret := mustAddNode(t, g, Node{Kind: Secret, Name: "database-password"})

	if workload.ID != NewNode(Workload, "orders-api").ID {
		t.Fatalf("workload ID = %q, want canonical ID", workload.ID)
	}
	if secret.ID != NewNode(Secret, "database-password").ID {
		t.Fatalf("secret ID = %q, want canonical ID", secret.ID)
	}
	if workload.ID == secret.ID {
		t.Fatalf("distinct empty-ID nodes collided on ID %q", workload.ID)
	}
	if got := g.Nodes(); len(got) != 2 {
		t.Fatalf("node count = %d, want 2", len(got))
	}
}

func TestGraphAddNodeAcceptsCorrectSuppliedID(t *testing.T) {
	g := New()
	node := NewNode(ServiceAccount, "orders-sa")

	got := mustAddNode(t, g, Node{ID: node.ID, Kind: node.Kind, Name: node.Name})

	if got != node {
		t.Fatalf("node = %#v, want %#v", got, node)
	}
}

func TestGraphAddNodeRejectsIncorrectSuppliedIDWithoutMutation(t *testing.T) {
	g := New()
	existing := mustAddNode(t, g, NewNode(PublicEndpoint, "public-api"))
	staleID := NewNode(Workload, "old-workload").ID

	if _, err := g.AddNode(Node{ID: staleID, Kind: Workload, Name: "orders-api"}); !errors.Is(err, ErrInvalidNodeID) {
		t.Fatalf("invalid node ID error = %v, want %v", err, ErrInvalidNodeID)
	}

	gotNodes := g.Nodes()
	if len(gotNodes) != 1 {
		t.Fatalf("node count = %d, want 1", len(gotNodes))
	}
	if gotNodes[0] != existing {
		t.Fatalf("remaining node = %#v, want %#v", gotNodes[0], existing)
	}
	if _, ok := g.Node(staleID); ok {
		t.Fatalf("stale node ID %q was indexed", staleID)
	}
}

func TestGraphAddNodeRejectsExistingSuppliedIDBeforeDeduplication(t *testing.T) {
	g := New()
	existing := mustAddNode(t, g, NewNode(PublicEndpoint, "public-api"))

	got, err := g.AddNode(Node{ID: existing.ID, Kind: Workload, Name: "orders-api"})
	if !errors.Is(err, ErrInvalidNodeID) {
		t.Fatalf("invalid node ID error = %v, want %v", err, ErrInvalidNodeID)
	}
	if got == existing {
		t.Fatalf("invalid node returned existing duplicate %#v", got)
	}

	gotNodes := g.Nodes()
	if len(gotNodes) != 1 {
		t.Fatalf("node count = %d, want 1", len(gotNodes))
	}
	if gotNodes[0] != existing {
		t.Fatalf("remaining node = %#v, want %#v", gotNodes[0], existing)
	}
	gotExisting, ok := g.Node(existing.ID)
	if !ok {
		t.Fatalf("existing node %q not found", existing.ID)
	}
	if gotExisting != existing {
		t.Fatalf("existing node = %#v, want %#v", gotExisting, existing)
	}
}

func TestGraphNodeRetrieval(t *testing.T) {
	g := New()
	node := mustAddNode(t, g, NewNode(ServiceAccount, "orders-sa"))

	got, ok := g.Node(node.ID)
	if !ok {
		t.Fatalf("node %q not found", node.ID)
	}
	if got != node {
		t.Fatalf("node = %#v, want %#v", got, node)
	}

	if _, ok := g.Node(NodeID("node:missing")); ok {
		t.Fatal("missing node found")
	}
}

func TestGraphNodesAreSortedByID(t *testing.T) {
	g := New()
	secret := mustAddNode(t, g, NewNode(Secret, "database-password"))
	endpoint := mustAddNode(t, g, NewNode(PublicEndpoint, "public-api"))
	workload := mustAddNode(t, g, NewNode(Workload, "orders-api"))

	got := g.Nodes()
	want := []Node{endpoint, secret, workload}

	if len(got) != len(want) {
		t.Fatalf("node count = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("node[%d] = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func TestEmptyGraphNodes(t *testing.T) {
	g := New()

	if got := g.Nodes(); len(got) != 0 {
		t.Fatalf("node count = %d, want 0", len(got))
	}
	if _, ok := g.Node(NodeID("node:missing")); ok {
		t.Fatal("missing node found")
	}
}

func TestNewEdgeStableID(t *testing.T) {
	from := NewNode(PublicEndpoint, "public-api")
	to := NewNode(Workload, "orders-api")
	evidence := SourceEvidence{Source: "fixture", Detail: "route"}

	first := NewEdge(RoutesTo, from.ID, to.ID, evidence)
	second := NewEdge(RoutesTo, from.ID, to.ID, SourceEvidence{Source: "changed", Detail: "changed"})

	if first.ID != second.ID {
		t.Fatalf("edge ID = %q, want %q", second.ID, first.ID)
	}
}

func TestGraphAddEdgeDeduplicatesAndPreservesEvidence(t *testing.T) {
	g := New()
	from := mustAddNode(t, g, NewNode(PublicEndpoint, "public-api"))
	to := mustAddNode(t, g, NewNode(Workload, "orders-api"))
	evidence := SourceEvidence{Source: "fixture", Detail: "public API routes to workload"}
	edge := NewEdge(RoutesTo, from.ID, to.ID, evidence)

	first, err := g.AddEdge(edge)
	if err != nil {
		t.Fatalf("add edge: %v", err)
	}
	second, err := g.AddEdge(NewEdge(RoutesTo, from.ID, to.ID, SourceEvidence{Source: "changed", Detail: "changed"}))
	if err != nil {
		t.Fatalf("add duplicate edge: %v", err)
	}

	if first != edge {
		t.Fatalf("first added edge = %#v, want %#v", first, edge)
	}
	if second != edge {
		t.Fatalf("deduplicated edge = %#v, want original %#v", second, edge)
	}
	if got := g.Edges(); len(got) != 1 {
		t.Fatalf("edge count = %d, want 1", len(got))
	}
	got, ok := g.Edge(edge.ID)
	if !ok {
		t.Fatalf("edge %q not found", edge.ID)
	}
	if got.Evidence != evidence {
		t.Fatalf("evidence = %#v, want %#v", got.Evidence, evidence)
	}
}

func TestGraphAddEdgeEmptyIDDuplicatePreservesExistingEvidence(t *testing.T) {
	g, endpoint, workload, _, _ := exampleGraphNodes(t)
	evidenceA := SourceEvidence{Source: "fixture", Detail: "route evidence A"}
	evidenceB := SourceEvidence{Source: "fixture", Detail: "route evidence B"}
	existing := mustAddEdge(t, g, NewEdge(RoutesTo, endpoint.ID, workload.ID, evidenceA))

	got, err := g.AddEdge(Edge{
		Kind:     RoutesTo,
		From:     endpoint.ID,
		To:       workload.ID,
		Evidence: evidenceB,
	})
	if err != nil {
		t.Fatalf("add empty-ID duplicate edge: %v", err)
	}
	if got != existing {
		t.Fatalf("duplicate edge = %#v, want existing %#v", got, existing)
	}

	gotEdges := g.Edges()
	if len(gotEdges) != 1 {
		t.Fatalf("edge count = %d, want 1", len(gotEdges))
	}
	if gotEdges[0] != existing {
		t.Fatalf("stored edge = %#v, want existing %#v", gotEdges[0], existing)
	}
	gotExisting, ok := g.Edge(existing.ID)
	if !ok {
		t.Fatalf("existing edge %q not found", existing.ID)
	}
	if gotExisting.Evidence != evidenceA {
		t.Fatalf("evidence = %#v, want %#v", gotExisting.Evidence, evidenceA)
	}
	gotOutgoing := g.Outgoing(endpoint.ID)
	if len(gotOutgoing) != 1 || gotOutgoing[0] != existing {
		t.Fatalf("outgoing = %#v, want only %#v", gotOutgoing, existing)
	}
}

func TestGraphAddEdgeAssignsEmptyCanonicalIDs(t *testing.T) {
	g, endpoint, workload, serviceAccount, _ := exampleGraphNodes(t)

	routesTo := mustAddEdge(t, g, Edge{
		Kind:     RoutesTo,
		From:     endpoint.ID,
		To:       workload.ID,
		Evidence: SourceEvidence{Source: "fixture", Detail: "route"},
	})
	runsAs := mustAddEdge(t, g, Edge{
		Kind:     RunsAs,
		From:     workload.ID,
		To:       serviceAccount.ID,
		Evidence: SourceEvidence{Source: "fixture", Detail: "service account"},
	})

	if routesTo.ID != NewEdge(RoutesTo, endpoint.ID, workload.ID, routesTo.Evidence).ID {
		t.Fatalf("routesTo ID = %q, want canonical ID", routesTo.ID)
	}
	if runsAs.ID != NewEdge(RunsAs, workload.ID, serviceAccount.ID, runsAs.Evidence).ID {
		t.Fatalf("runsAs ID = %q, want canonical ID", runsAs.ID)
	}
	if routesTo.ID == runsAs.ID {
		t.Fatalf("distinct empty-ID edges collided on ID %q", routesTo.ID)
	}
	if got := g.Edges(); len(got) != 2 {
		t.Fatalf("edge count = %d, want 2", len(got))
	}
}

func TestGraphAddEdgeAcceptsCorrectSuppliedID(t *testing.T) {
	g, endpoint, workload, _, _ := exampleGraphNodes(t)
	edge := NewEdge(RoutesTo, endpoint.ID, workload.ID, SourceEvidence{Source: "fixture", Detail: "route"})

	got := mustAddEdge(t, g, Edge{
		ID:       edge.ID,
		Kind:     edge.Kind,
		From:     edge.From,
		To:       edge.To,
		Evidence: edge.Evidence,
	})

	if got != edge {
		t.Fatalf("edge = %#v, want %#v", got, edge)
	}
}

func TestGraphAddEdgeRejectsIncorrectSuppliedIDWithoutMutation(t *testing.T) {
	g, endpoint, workload, serviceAccount, _ := exampleGraphNodes(t)
	existing := mustAddEdge(t, g, NewEdge(RoutesTo, endpoint.ID, workload.ID, SourceEvidence{Source: "fixture", Detail: "route"}))
	staleID := NewEdge(CanRead, serviceAccount.ID, workload.ID, SourceEvidence{}).ID

	_, err := g.AddEdge(Edge{
		ID:       staleID,
		Kind:     RunsAs,
		From:     workload.ID,
		To:       serviceAccount.ID,
		Evidence: SourceEvidence{Source: "fixture", Detail: "service account"},
	})
	if !errors.Is(err, ErrInvalidEdgeID) {
		t.Fatalf("invalid edge ID error = %v, want %v", err, ErrInvalidEdgeID)
	}

	gotEdges := g.Edges()
	if len(gotEdges) != 1 {
		t.Fatalf("edge count = %d, want 1", len(gotEdges))
	}
	if gotEdges[0] != existing {
		t.Fatalf("remaining edge = %#v, want %#v", gotEdges[0], existing)
	}
	if got := g.Outgoing(workload.ID); len(got) != 0 {
		t.Fatalf("workload outgoing count = %d, want 0", len(got))
	}
	if got := g.Outgoing(endpoint.ID); len(got) != 1 || got[0] != existing {
		t.Fatalf("endpoint outgoing = %#v, want only %#v", got, existing)
	}
	if _, ok := g.Edge(staleID); ok {
		t.Fatalf("stale edge ID %q was indexed", staleID)
	}
}

func TestGraphAddEdgeRejectsExistingSuppliedIDBeforeDeduplication(t *testing.T) {
	g, endpoint, workload, serviceAccount, _ := exampleGraphNodes(t)
	existing := mustAddEdge(t, g, NewEdge(RoutesTo, endpoint.ID, workload.ID, SourceEvidence{Source: "fixture", Detail: "route"}))

	got, err := g.AddEdge(Edge{
		ID:       existing.ID,
		Kind:     RunsAs,
		From:     workload.ID,
		To:       serviceAccount.ID,
		Evidence: SourceEvidence{Source: "fixture", Detail: "service account"},
	})
	if !errors.Is(err, ErrInvalidEdgeID) {
		t.Fatalf("invalid edge ID error = %v, want %v", err, ErrInvalidEdgeID)
	}
	if got == existing {
		t.Fatalf("invalid edge returned existing duplicate %#v", got)
	}

	gotEdges := g.Edges()
	if len(gotEdges) != 1 {
		t.Fatalf("edge count = %d, want 1", len(gotEdges))
	}
	if gotEdges[0] != existing {
		t.Fatalf("remaining edge = %#v, want %#v", gotEdges[0], existing)
	}
	gotExisting, ok := g.Edge(existing.ID)
	if !ok {
		t.Fatalf("existing edge %q not found", existing.ID)
	}
	if gotExisting != existing {
		t.Fatalf("existing edge = %#v, want %#v", gotExisting, existing)
	}
	if got := g.Outgoing(endpoint.ID); len(got) != 1 || got[0] != existing {
		t.Fatalf("endpoint outgoing = %#v, want only %#v", got, existing)
	}
	if got := g.Outgoing(workload.ID); len(got) != 0 {
		t.Fatalf("workload outgoing count = %d, want 0", len(got))
	}
}

func TestGraphAddEdgeEmptyIDsDoNotDropUnrelatedEvidence(t *testing.T) {
	g, endpoint, workload, serviceAccount, _ := exampleGraphNodes(t)
	routeEvidence := SourceEvidence{Source: "fixture", Detail: "route evidence"}
	runsAsEvidence := SourceEvidence{Source: "fixture", Detail: "runs-as evidence"}

	route := mustAddEdge(t, g, Edge{Kind: RoutesTo, From: endpoint.ID, To: workload.ID, Evidence: routeEvidence})
	runsAs := mustAddEdge(t, g, Edge{Kind: RunsAs, From: workload.ID, To: serviceAccount.ID, Evidence: runsAsEvidence})

	if got := g.Edges(); len(got) != 2 {
		t.Fatalf("edge count = %d, want 2", len(got))
	}
	gotRoute, ok := g.Edge(route.ID)
	if !ok {
		t.Fatalf("route edge %q not found", route.ID)
	}
	if gotRoute.Evidence != routeEvidence {
		t.Fatalf("route evidence = %#v, want %#v", gotRoute.Evidence, routeEvidence)
	}
	gotRunsAs, ok := g.Edge(runsAs.ID)
	if !ok {
		t.Fatalf("runs-as edge %q not found", runsAs.ID)
	}
	if gotRunsAs.Evidence != runsAsEvidence {
		t.Fatalf("runs-as evidence = %#v, want %#v", gotRunsAs.Evidence, runsAsEvidence)
	}
}

func TestGraphAddEdgeRejectsMissingEndpoints(t *testing.T) {
	g := New()
	from := mustAddNode(t, g, NewNode(PublicEndpoint, "public-api"))
	to := NewNode(Workload, "orders-api")

	if _, err := g.AddEdge(NewEdge(RoutesTo, from.ID, to.ID, SourceEvidence{})); !errors.Is(err, ErrMissingEndpoint) {
		t.Fatalf("missing to endpoint error = %v, want %v", err, ErrMissingEndpoint)
	}
	if _, err := g.AddEdge(NewEdge(RoutesTo, NodeID("node:missing"), from.ID, SourceEvidence{})); !errors.Is(err, ErrMissingEndpoint) {
		t.Fatalf("missing from endpoint error = %v, want %v", err, ErrMissingEndpoint)
	}
	if got := g.Edges(); len(got) != 0 {
		t.Fatalf("edge count = %d, want 0", len(got))
	}
}

func TestGraphEdgesAndOutgoingAreSortedByID(t *testing.T) {
	g := New()
	endpoint := mustAddNode(t, g, NewNode(PublicEndpoint, "public-api"))
	workload := mustAddNode(t, g, NewNode(Workload, "orders-api"))
	serviceAccount := mustAddNode(t, g, NewNode(ServiceAccount, "orders-sa"))
	secret := mustAddNode(t, g, NewNode(Secret, "database-password"))

	canRead, err := g.AddEdge(NewEdge(CanRead, serviceAccount.ID, secret.ID, SourceEvidence{Source: "fixture", Detail: "secret read"}))
	if err != nil {
		t.Fatalf("add can read edge: %v", err)
	}
	routesTo, err := g.AddEdge(NewEdge(RoutesTo, endpoint.ID, workload.ID, SourceEvidence{Source: "fixture", Detail: "route"}))
	if err != nil {
		t.Fatalf("add routes to edge: %v", err)
	}
	runsAs, err := g.AddEdge(NewEdge(RunsAs, workload.ID, serviceAccount.ID, SourceEvidence{Source: "fixture", Detail: "service account"}))
	if err != nil {
		t.Fatalf("add runs as edge: %v", err)
	}

	gotEdges := g.Edges()
	wantEdges := []Edge{canRead, routesTo, runsAs}
	if len(gotEdges) != len(wantEdges) {
		t.Fatalf("edge count = %d, want %d", len(gotEdges), len(wantEdges))
	}
	for i := range wantEdges {
		if gotEdges[i] != wantEdges[i] {
			t.Fatalf("edge[%d] = %#v, want %#v", i, gotEdges[i], wantEdges[i])
		}
	}

	gotOutgoing := g.Outgoing(endpoint.ID)
	if len(gotOutgoing) != 1 || gotOutgoing[0] != routesTo {
		t.Fatalf("outgoing = %#v, want only %#v", gotOutgoing, routesTo)
	}
	if got := g.Outgoing(secret.ID); len(got) != 0 {
		t.Fatalf("secret outgoing count = %d, want 0", len(got))
	}
}

func TestFindPathFindsDirectedFourNodePath(t *testing.T) {
	g, endpoint, _, _, secret, path := exampleGraph(t)

	got, ok := g.FindPath(endpoint.ID, secret.ID, 3)
	if !ok {
		t.Fatal("path not found")
	}
	assertPath(t, got, path)
}

func TestFindPathReverseDirectionDoesNotMatch(t *testing.T) {
	g, endpoint, _, _, secret, _ := exampleGraph(t)

	if got, ok := g.FindPath(secret.ID, endpoint.ID, 3); ok {
		t.Fatalf("reverse path found: %#v", got)
	}
}

func TestFindPathMissingPath(t *testing.T) {
	g, endpoint, workload, _, _, _ := exampleGraph(t)
	isolated := mustAddNode(t, g, NewNode(Secret, "isolated-secret"))

	if got, ok := g.FindPath(endpoint.ID, isolated.ID, 3); ok {
		t.Fatalf("missing path found: %#v", got)
	}
	if got, ok := g.FindPath(workload.ID, isolated.ID, 3); ok {
		t.Fatalf("missing path found: %#v", got)
	}
}

func TestFindPathCycleDoesNotLoopForever(t *testing.T) {
	g, endpoint, workload, _, secret, path := exampleGraph(t)
	mustAddEdge(t, g, NewEdge(RoutesTo, workload.ID, endpoint.ID, SourceEvidence{Source: "fixture", Detail: "cycle"}))

	got, ok := g.FindPath(endpoint.ID, secret.ID, 4)
	if !ok {
		t.Fatal("path not found")
	}
	assertPath(t, got, path)
}

func TestFindPathMaxDepthIsEnforced(t *testing.T) {
	g, endpoint, _, _, secret, _ := exampleGraph(t)

	if got, ok := g.FindPath(endpoint.ID, secret.ID, 2); ok {
		t.Fatalf("path found below required depth: %#v", got)
	}
	if got, ok := g.FindPath(endpoint.ID, secret.ID, -1); ok {
		t.Fatalf("path found with negative max depth: %#v", got)
	}
}

func TestFindPathEmptyGraph(t *testing.T) {
	g := New()

	if got, ok := g.FindPath(NodeID("node:from"), NodeID("node:to"), 1); ok {
		t.Fatalf("path found in empty graph: %#v", got)
	}
}

func TestFindPathSameNode(t *testing.T) {
	g := New()
	node := mustAddNode(t, g, NewNode(Workload, "orders-api"))

	got, ok := g.FindPath(node.ID, node.ID, 0)
	if !ok {
		t.Fatal("same-node path not found")
	}
	if len(got) != 0 {
		t.Fatalf("same-node path length = %d, want 0", len(got))
	}
}

func TestGraphJSONSerializationIsDeterministic(t *testing.T) {
	first, _, _, _, _, _ := exampleGraph(t)
	second := exampleGraphWithReverseInsertion(t)

	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first graph: %v", err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal second graph: %v", err)
	}
	thirdJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first graph again: %v", err)
	}

	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("json differs by insertion order:\nfirst:  %s\nsecond: %s", firstJSON, secondJSON)
	}
	if string(firstJSON) != string(thirdJSON) {
		t.Fatalf("json differs across repeated marshal:\nfirst: %s\nthird: %s", firstJSON, thirdJSON)
	}
}

func TestEmptyGraphJSON(t *testing.T) {
	g := New()

	got, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal empty graph: %v", err)
	}
	if want := `{"nodes":[],"edges":[]}`; string(got) != want {
		t.Fatalf("json = %s, want %s", got, want)
	}
}

func exampleGraph(t *testing.T) (*Graph, Node, Node, Node, Node, []Edge) {
	t.Helper()

	g, endpoint, workload, serviceAccount, secret := exampleGraphNodes(t)

	routesTo := mustAddEdge(t, g, NewEdge(RoutesTo, endpoint.ID, workload.ID, SourceEvidence{Source: "fixture", Detail: "route"}))
	runsAs := mustAddEdge(t, g, NewEdge(RunsAs, workload.ID, serviceAccount.ID, SourceEvidence{Source: "fixture", Detail: "service account"}))
	canRead := mustAddEdge(t, g, NewEdge(CanRead, serviceAccount.ID, secret.ID, SourceEvidence{Source: "fixture", Detail: "secret read"}))

	return g, endpoint, workload, serviceAccount, secret, []Edge{routesTo, runsAs, canRead}
}

func exampleGraphNodes(t *testing.T) (*Graph, Node, Node, Node, Node) {
	t.Helper()

	g := New()
	endpoint := mustAddNode(t, g, NewNode(PublicEndpoint, "public-api"))
	workload := mustAddNode(t, g, NewNode(Workload, "orders-api"))
	serviceAccount := mustAddNode(t, g, NewNode(ServiceAccount, "orders-sa"))
	secret := mustAddNode(t, g, NewNode(Secret, "database-password"))

	return g, endpoint, workload, serviceAccount, secret
}

func exampleGraphWithReverseInsertion(t *testing.T) *Graph {
	t.Helper()

	g := New()
	secret := mustAddNode(t, g, NewNode(Secret, "database-password"))
	serviceAccount := mustAddNode(t, g, NewNode(ServiceAccount, "orders-sa"))
	workload := mustAddNode(t, g, NewNode(Workload, "orders-api"))
	endpoint := mustAddNode(t, g, NewNode(PublicEndpoint, "public-api"))

	mustAddEdge(t, g, NewEdge(CanRead, serviceAccount.ID, secret.ID, SourceEvidence{Source: "fixture", Detail: "secret read"}))
	mustAddEdge(t, g, NewEdge(RunsAs, workload.ID, serviceAccount.ID, SourceEvidence{Source: "fixture", Detail: "service account"}))
	mustAddEdge(t, g, NewEdge(RoutesTo, endpoint.ID, workload.ID, SourceEvidence{Source: "fixture", Detail: "route"}))

	return g
}

func mustAddEdge(t *testing.T, g *Graph, edge Edge) Edge {
	t.Helper()

	added, err := g.AddEdge(edge)
	if err != nil {
		t.Fatalf("add edge: %v", err)
	}
	return added
}

func mustAddNode(t *testing.T, g *Graph, node Node) Node {
	t.Helper()

	added, err := g.AddNode(node)
	if err != nil {
		t.Fatalf("add node: %v", err)
	}
	return added
}

func assertPath(t *testing.T, got, want []Edge) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("path length = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("path[%d] = %#v, want %#v", i, got[i], want[i])
		}
	}
}
