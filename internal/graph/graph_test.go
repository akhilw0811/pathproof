package graph

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
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

	if !reflect.DeepEqual(first, node) {
		t.Fatalf("first added node = %#v, want %#v", first, node)
	}
	if !reflect.DeepEqual(second, node) {
		t.Fatalf("deduplicated node = %#v, want original %#v", second, node)
	}
	if got := g.Nodes(); len(got) != 1 {
		t.Fatalf("node count = %d, want 1", len(got))
	}
}

func TestGraphAddNodeDeduplicatesAndPreservesEvidence(t *testing.T) {
	g := New()
	evidence := []SourceEvidence{{Source: "fixture.yaml#document=1", Detail: "kubernetes Service"}}
	node := NewNode(PublicEndpoint, "public-api")
	node.Evidence = evidence

	first := mustAddNode(t, g, node)
	second := mustAddNode(t, g, Node{
		Kind:     PublicEndpoint,
		Name:     "public-api",
		Evidence: []SourceEvidence{{Source: "changed.yaml#document=1", Detail: "changed"}},
	})

	if !reflect.DeepEqual(first, node) {
		t.Fatalf("first added node = %#v, want %#v", first, node)
	}
	if !reflect.DeepEqual(second, node) {
		t.Fatalf("deduplicated node = %#v, want original %#v", second, node)
	}
	gotNodes := g.Nodes()
	if len(gotNodes) != 1 {
		t.Fatalf("node count = %d, want 1", len(gotNodes))
	}
	if !reflect.DeepEqual(gotNodes[0].Evidence, evidence) {
		t.Fatalf("evidence = %#v, want %#v", gotNodes[0].Evidence, evidence)
	}
}

func TestGraphAddNodeClonesCallerEvidence(t *testing.T) {
	g := New()
	evidence := []SourceEvidence{{Source: "fixture.yaml#document=1", Detail: "kubernetes Service"}}
	node := NewNode(PublicEndpoint, "public-api")
	node.Evidence = evidence

	added := mustAddNode(t, g, node)
	evidence[0].Source = "changed.yaml#document=1"

	got, ok := g.Node(added.ID)
	if !ok {
		t.Fatalf("node %q not found", added.ID)
	}
	if got.Evidence[0].Source != "fixture.yaml#document=1" {
		t.Fatalf("stored evidence source = %q, want original", got.Evidence[0].Source)
	}
}

func TestGraphNodeClonesReturnedEvidence(t *testing.T) {
	g := New()
	node := NewNode(PublicEndpoint, "public-api")
	node.Evidence = []SourceEvidence{{Source: "fixture.yaml#document=1", Detail: "kubernetes Service"}}
	added := mustAddNode(t, g, node)

	got, ok := g.Node(added.ID)
	if !ok {
		t.Fatalf("node %q not found", added.ID)
	}
	got.Evidence[0].Source = "changed.yaml#document=1"

	stored, ok := g.Node(added.ID)
	if !ok {
		t.Fatalf("node %q not found after mutation", added.ID)
	}
	if stored.Evidence[0].Source != "fixture.yaml#document=1" {
		t.Fatalf("stored evidence source = %q, want original", stored.Evidence[0].Source)
	}
}

func TestGraphNodesCloneReturnedEvidence(t *testing.T) {
	g := New()
	node := NewNode(PublicEndpoint, "public-api")
	node.Evidence = []SourceEvidence{{Source: "fixture.yaml#document=1", Detail: "kubernetes Service"}}
	added := mustAddNode(t, g, node)

	nodes := g.Nodes()
	nodes[0].Evidence[0].Source = "changed.yaml#document=1"

	stored, ok := g.Node(added.ID)
	if !ok {
		t.Fatalf("node %q not found after mutation", added.ID)
	}
	if stored.Evidence[0].Source != "fixture.yaml#document=1" {
		t.Fatalf("stored evidence source = %q, want original", stored.Evidence[0].Source)
	}
}

func TestGraphAddDuplicateNodeClonesReturnedEvidence(t *testing.T) {
	g := New()
	node := NewNode(PublicEndpoint, "public-api")
	node.Evidence = []SourceEvidence{{Source: "fixture.yaml#document=1", Detail: "kubernetes Service"}}
	added := mustAddNode(t, g, node)

	duplicate := mustAddNode(t, g, NewNode(PublicEndpoint, "public-api"))
	duplicate.Evidence[0].Source = "changed.yaml#document=1"

	stored, ok := g.Node(added.ID)
	if !ok {
		t.Fatalf("node %q not found after duplicate mutation", added.ID)
	}
	if stored.Evidence[0].Source != "fixture.yaml#document=1" {
		t.Fatalf("stored evidence source = %q, want original", stored.Evidence[0].Source)
	}
}

func TestGraphAddNodeAssignsEmptyCanonicalIDs(t *testing.T) {
	g := New()

	workload := mustAddNode(t, g, Node{Kind: Workload, Name: "orders-api"})
	role := mustAddNode(t, g, Node{Kind: Role, Name: "orders-role"})
	permission := mustAddNode(t, g, Node{Kind: Permission, Name: "read-secrets"})
	secret := mustAddNode(t, g, Node{Kind: Secret, Name: "database-password"})

	if workload.ID != NewNode(Workload, "orders-api").ID {
		t.Fatalf("workload ID = %q, want canonical ID", workload.ID)
	}
	if role.ID != NewNode(Role, "orders-role").ID {
		t.Fatalf("role ID = %q, want canonical ID", role.ID)
	}
	if permission.ID != NewNode(Permission, "read-secrets").ID {
		t.Fatalf("permission ID = %q, want canonical ID", permission.ID)
	}
	if secret.ID != NewNode(Secret, "database-password").ID {
		t.Fatalf("secret ID = %q, want canonical ID", secret.ID)
	}
	seen := map[NodeID]struct{}{}
	for _, node := range []Node{workload, role, permission, secret} {
		if _, exists := seen[node.ID]; exists {
			t.Fatalf("distinct empty-ID nodes collided on ID %q", node.ID)
		}
		seen[node.ID] = struct{}{}
	}
	if got := g.Nodes(); len(got) != 4 {
		t.Fatalf("node count = %d, want 4", len(got))
	}
}

func TestGraphAddNodeAcceptsCorrectSuppliedID(t *testing.T) {
	g := New()
	node := NewNode(ServiceAccount, "orders-sa")

	got := mustAddNode(t, g, Node{ID: node.ID, Kind: node.Kind, Name: node.Name})

	if !reflect.DeepEqual(got, node) {
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
	if !reflect.DeepEqual(gotNodes[0], existing) {
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
	if reflect.DeepEqual(got, existing) {
		t.Fatalf("invalid node returned existing duplicate %#v", got)
	}

	gotNodes := g.Nodes()
	if len(gotNodes) != 1 {
		t.Fatalf("node count = %d, want 1", len(gotNodes))
	}
	if !reflect.DeepEqual(gotNodes[0], existing) {
		t.Fatalf("remaining node = %#v, want %#v", gotNodes[0], existing)
	}
	gotExisting, ok := g.Node(existing.ID)
	if !ok {
		t.Fatalf("existing node %q not found", existing.ID)
	}
	if !reflect.DeepEqual(gotExisting, existing) {
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
	if !reflect.DeepEqual(got, node) {
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
		if !reflect.DeepEqual(got[i], want[i]) {
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
	role := mustAddNode(t, g, NewNode(Role, "orders-role"))
	permission := mustAddNode(t, g, NewNode(Permission, "read-secrets"))

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
	boundTo := mustAddEdge(t, g, Edge{
		Kind:     BoundTo,
		From:     serviceAccount.ID,
		To:       role.ID,
		Evidence: SourceEvidence{Source: "fixture", Detail: "role binding"},
	})
	grantsPermission := mustAddEdge(t, g, Edge{
		Kind:     GrantsPermission,
		From:     role.ID,
		To:       permission.ID,
		Evidence: SourceEvidence{Source: "fixture", Detail: "role rule"},
	})

	if routesTo.ID != NewEdge(RoutesTo, endpoint.ID, workload.ID, routesTo.Evidence).ID {
		t.Fatalf("routesTo ID = %q, want canonical ID", routesTo.ID)
	}
	if runsAs.ID != NewEdge(RunsAs, workload.ID, serviceAccount.ID, runsAs.Evidence).ID {
		t.Fatalf("runsAs ID = %q, want canonical ID", runsAs.ID)
	}
	if boundTo.ID != NewEdge(BoundTo, serviceAccount.ID, role.ID, boundTo.Evidence).ID {
		t.Fatalf("boundTo ID = %q, want canonical ID", boundTo.ID)
	}
	if grantsPermission.ID != NewEdge(GrantsPermission, role.ID, permission.ID, grantsPermission.Evidence).ID {
		t.Fatalf("grantsPermission ID = %q, want canonical ID", grantsPermission.ID)
	}
	seen := map[EdgeID]struct{}{}
	for _, edge := range []Edge{routesTo, runsAs, boundTo, grantsPermission} {
		if _, exists := seen[edge.ID]; exists {
			t.Fatalf("distinct empty-ID edges collided on ID %q", edge.ID)
		}
		seen[edge.ID] = struct{}{}
	}
	if got := g.Edges(); len(got) != 4 {
		t.Fatalf("edge count = %d, want 4", len(got))
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

func TestGraphEdgeMetadataIsCloned(t *testing.T) {
	g, _, _, serviceAccount, secret := exampleGraphNodes(t)
	edge := NewEdge(CanRead, serviceAccount.ID, secret.ID, SourceEvidence{Source: "fixture", Detail: "secret read"})
	edge.Metadata = &EdgeMetadata{KubernetesCanReadAuthorizations: []KubernetesCanReadAuthorization{{
		BindingKind:                         "RoleBinding",
		BindingNamespace:                    "prod",
		BindingName:                         "read-secrets",
		BindingSourceReference:              "binding.yaml#document=1",
		BindingSupportedServiceAccountCount: 1,
		ServiceAccountNamespace:             "prod",
		ServiceAccountName:                  "api",
		RoleKind:                            "Role",
		RoleNamespace:                       "prod",
		RoleName:                            "secret-reader",
		RoleSourceReference:                 "role.yaml#document=1",
		PermissionSHA256:                    "abc123",
		Permission: KubernetesPermission{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get"},
		},
		MatchedVerb:            "get",
		ScopeKind:              "namespace",
		ScopeName:              "prod",
		SecretNamespace:        "prod",
		SecretName:             "database-password",
		SecretSourceReferences: []string{"secret.yaml#document=1"},
	}}}

	added := mustAddEdge(t, g, edge)
	edge.Metadata.KubernetesCanReadAuthorizations[0].BindingName = "changed"
	edge.Metadata.KubernetesCanReadAuthorizations[0].Permission.Resources[0] = "pods"
	added.Metadata.KubernetesCanReadAuthorizations[0].MatchedVerb = "watch"

	got, ok := g.Edge(added.ID)
	if !ok {
		t.Fatalf("edge %q not found", added.ID)
	}
	if got.Metadata == nil {
		t.Fatal("metadata = nil, want metadata")
	}
	auth := got.Metadata.KubernetesCanReadAuthorizations[0]
	if auth.BindingName != "read-secrets" {
		t.Fatalf("stored binding name = %q, want original", auth.BindingName)
	}
	if auth.Permission.Resources[0] != "secrets" {
		t.Fatalf("stored permission resource = %q, want original", auth.Permission.Resources[0])
	}
	if auth.MatchedVerb != "get" {
		t.Fatalf("stored matched verb = %q, want original", auth.MatchedVerb)
	}

	got.Metadata.KubernetesCanReadAuthorizations[0].SecretSourceReferences[0] = "changed-secret.yaml#document=1"
	again, ok := g.Edge(added.ID)
	if !ok {
		t.Fatalf("edge %q not found after mutation", added.ID)
	}
	if again.Metadata.KubernetesCanReadAuthorizations[0].SecretSourceReferences[0] != "secret.yaml#document=1" {
		t.Fatalf("returned metadata mutation changed graph: %#v", again.Metadata.KubernetesCanReadAuthorizations[0])
	}
}

func TestGraphGitHubActionsWorkflowNodeMetadataIsCloned(t *testing.T) {
	g := New()
	workflow := NewNode(Workflow, "githubactions://.github/workflows/build.yml")
	workflow.Metadata = &NodeMetadata{GitHubActionsWorkflow: &GitHubActionsWorkflow{
		WorkflowSourceReference:   ".github/workflows/build.yml#document=1",
		WorkflowFile:              ".github/workflows/build.yml",
		WorkflowName:              "Build",
		TriggersPullRequestTarget: true,
		PermissionGrants: []GitHubActionsPermissionGrant{{
			Scope:      "workflow",
			Permission: "contents",
			Access:     "write",
		}},
	}}

	added := mustAddNode(t, g, workflow)
	workflow.Metadata.GitHubActionsWorkflow.PermissionGrants[0].Access = "read"
	added.Metadata.GitHubActionsWorkflow.PermissionGrants[0].Permission = "actions"

	got, ok := g.Node(added.ID)
	if !ok {
		t.Fatalf("node %q not found", added.ID)
	}
	if got.Metadata == nil || got.Metadata.GitHubActionsWorkflow == nil {
		t.Fatalf("metadata = %#v, want github actions workflow metadata", got.Metadata)
	}
	grant := got.Metadata.GitHubActionsWorkflow.PermissionGrants[0]
	if grant.Permission != "contents" || grant.Access != "write" {
		t.Fatalf("stored grant = %#v, want original contents/write", grant)
	}

	got.Metadata.GitHubActionsWorkflow.PermissionGrants[0].Access = "none"
	again, ok := g.Node(added.ID)
	if !ok {
		t.Fatalf("node %q not found after mutation", added.ID)
	}
	if again.Metadata.GitHubActionsWorkflow.PermissionGrants[0].Access != "write" {
		t.Fatalf("returned metadata mutation changed graph: %#v", again.Metadata.GitHubActionsWorkflow.PermissionGrants[0])
	}
}

func TestGraphGitHubActionsWorkflowJobEdgeMetadataIsCloned(t *testing.T) {
	g := New()
	workflow := mustAddNode(t, g, NewNode(Workflow, "githubactions://.github/workflows/build.yml"))
	job := mustAddNode(t, g, NewNode(WorkflowJob, "githubactions://.github/workflows/build.yml/job/test"))
	edge := NewEdge(DefinesJob, workflow.ID, job.ID, SourceEvidence{Source: "build.yml", Detail: "defines"})
	edge.Metadata = &EdgeMetadata{GitHubActionsWorkflowJob: &GitHubActionsWorkflowJob{
		WorkflowSourceReference:   ".github/workflows/build.yml#document=1",
		WorkflowFile:              ".github/workflows/build.yml",
		WorkflowName:              "Build",
		TriggersPullRequestTarget: true,
		JobID:                     "test",
		PermissionGrants: []GitHubActionsPermissionGrant{{
			Scope:      "job",
			JobID:      "test",
			Permission: "id-token",
			Access:     "write",
		}},
	}}

	added := mustAddEdge(t, g, edge)
	edge.Metadata.GitHubActionsWorkflowJob.PermissionGrants[0].Access = "read"
	added.Metadata.GitHubActionsWorkflowJob.PermissionGrants[0].Permission = "checks"

	got, ok := g.Edge(added.ID)
	if !ok {
		t.Fatalf("edge %q not found", added.ID)
	}
	if got.Metadata == nil || got.Metadata.GitHubActionsWorkflowJob == nil {
		t.Fatalf("metadata = %#v, want github actions workflow job metadata", got.Metadata)
	}
	grant := got.Metadata.GitHubActionsWorkflowJob.PermissionGrants[0]
	if grant.Permission != "id-token" || grant.Access != "write" {
		t.Fatalf("stored grant = %#v, want original id-token/write", grant)
	}

	got.Metadata.GitHubActionsWorkflowJob.PermissionGrants[0].Access = "none"
	again, ok := g.Edge(added.ID)
	if !ok {
		t.Fatalf("edge %q not found after mutation", added.ID)
	}
	if again.Metadata.GitHubActionsWorkflowJob.PermissionGrants[0].Access != "write" {
		t.Fatalf("returned metadata mutation changed graph: %#v", again.Metadata.GitHubActionsWorkflowJob.PermissionGrants[0])
	}
}

func TestGraphGitHubActionsOIDCTokenCapabilityNodeMetadataIsCloned(t *testing.T) {
	g := New()
	capability := NewNode(OIDCTokenCapability, "githubactions://.github/workflows/build.yml/oidc-token/workflow")
	capability.Metadata = &NodeMetadata{GitHubActionsOIDCTokenCapability: &GitHubActionsOIDCTokenCapability{
		Provider:                "github-actions",
		WorkflowSourceReference: ".github/workflows/build.yml#document=1",
		WorkflowFile:            ".github/workflows/build.yml",
		WorkflowName:            "Build",
		Scope:                   "workflow",
	}}

	added := mustAddNode(t, g, capability)
	capability.Metadata.GitHubActionsOIDCTokenCapability.Scope = "job"
	added.Metadata.GitHubActionsOIDCTokenCapability.WorkflowFile = ".github/workflows/changed.yml"

	got, ok := g.Node(added.ID)
	if !ok {
		t.Fatalf("node %q not found", added.ID)
	}
	if got.Metadata == nil || got.Metadata.GitHubActionsOIDCTokenCapability == nil {
		t.Fatalf("metadata = %#v, want github actions oidc token capability metadata", got.Metadata)
	}
	if got.Metadata.GitHubActionsOIDCTokenCapability.Scope != "workflow" || got.Metadata.GitHubActionsOIDCTokenCapability.WorkflowFile != ".github/workflows/build.yml" {
		t.Fatalf("stored metadata changed: %#v", got.Metadata.GitHubActionsOIDCTokenCapability)
	}

	got.Metadata.GitHubActionsOIDCTokenCapability.Provider = "changed"
	again, ok := g.Node(added.ID)
	if !ok {
		t.Fatalf("node %q not found after mutation", added.ID)
	}
	if again.Metadata.GitHubActionsOIDCTokenCapability.Provider != "github-actions" {
		t.Fatalf("returned metadata mutation changed graph: %#v", again.Metadata.GitHubActionsOIDCTokenCapability)
	}
}

func TestGraphGitHubActionsOIDCTokenRequestEdgeMetadataIsCloned(t *testing.T) {
	g := New()
	workflow := mustAddNode(t, g, NewNode(Workflow, "githubactions://.github/workflows/build.yml"))
	capability := mustAddNode(t, g, NewNode(OIDCTokenCapability, "githubactions://.github/workflows/build.yml/oidc-token/workflow"))
	edge := NewEdge(CanRequestOIDCToken, workflow.ID, capability.ID, SourceEvidence{Source: "build.yml", Detail: "oidc"})
	edge.Metadata = &EdgeMetadata{GitHubActionsOIDCTokenRequest: &GitHubActionsOIDCTokenRequest{
		Provider:                "github-actions",
		WorkflowSourceReference: ".github/workflows/build.yml#document=1",
		WorkflowFile:            ".github/workflows/build.yml",
		WorkflowName:            "Build",
		Scope:                   "workflow",
		Permission:              "id-token",
		Access:                  "write",
	}}

	added := mustAddEdge(t, g, edge)
	edge.Metadata.GitHubActionsOIDCTokenRequest.Scope = "job"
	added.Metadata.GitHubActionsOIDCTokenRequest.WorkflowFile = ".github/workflows/changed.yml"

	got, ok := g.Edge(added.ID)
	if !ok {
		t.Fatalf("edge %q not found", added.ID)
	}
	if got.Metadata == nil || got.Metadata.GitHubActionsOIDCTokenRequest == nil {
		t.Fatalf("metadata = %#v, want github actions oidc token request metadata", got.Metadata)
	}
	if got.Metadata.GitHubActionsOIDCTokenRequest.Scope != "workflow" || got.Metadata.GitHubActionsOIDCTokenRequest.WorkflowFile != ".github/workflows/build.yml" {
		t.Fatalf("stored metadata changed: %#v", got.Metadata.GitHubActionsOIDCTokenRequest)
	}

	got.Metadata.GitHubActionsOIDCTokenRequest.Provider = "changed"
	again, ok := g.Edge(added.ID)
	if !ok {
		t.Fatalf("edge %q not found after mutation", added.ID)
	}
	if again.Metadata.GitHubActionsOIDCTokenRequest.Provider != "github-actions" {
		t.Fatalf("returned metadata mutation changed graph: %#v", again.Metadata.GitHubActionsOIDCTokenRequest)
	}
}

func TestGraphAWSIAMRoleNodeMetadataIsCloned(t *testing.T) {
	g := New()
	role := NewNode(AWSIAMRole, "aws://terraform/aws_iam_role/main.tf/deploy")
	role.Metadata = &NodeMetadata{AWSIAMRole: &AWSIAMRoleMetadata{
		Provider:        "aws",
		ResourceName:    "deploy",
		SourceReference: "main.tf#resource=aws_iam_role.deploy",
		TrustedIssuer:   "token.actions.githubusercontent.com",
		TrustStatements: []AWSOIDCTrustStatement{{
			StatementIndex: 0,
			SubjectPatterns: []AWSOIDCSubjectPattern{{
				Operator: "StringEquals",
				Pattern:  "repo:owner/repo:pull_request",
			}},
			Audiences: []string{"sts.amazonaws.com"},
		}},
	}}

	added := mustAddNode(t, g, role)
	role.Metadata.AWSIAMRole.TrustStatements[0].SubjectPatterns[0].Pattern = "changed"
	added.Metadata.AWSIAMRole.TrustStatements[0].Audiences[0] = "changed"

	got, ok := g.Node(added.ID)
	if !ok {
		t.Fatalf("node %q not found", added.ID)
	}
	if got.Metadata == nil || got.Metadata.AWSIAMRole == nil {
		t.Fatalf("metadata = %#v, want aws iam role metadata", got.Metadata)
	}
	statement := got.Metadata.AWSIAMRole.TrustStatements[0]
	if statement.SubjectPatterns[0].Pattern != "repo:owner/repo:pull_request" || statement.Audiences[0] != "sts.amazonaws.com" {
		t.Fatalf("stored metadata changed: %#v", got.Metadata.AWSIAMRole)
	}

	got.Metadata.AWSIAMRole.TrustStatements[0].SubjectPatterns[0].Operator = "changed"
	again, ok := g.Node(added.ID)
	if !ok {
		t.Fatalf("node %q not found after mutation", added.ID)
	}
	if again.Metadata.AWSIAMRole.TrustStatements[0].SubjectPatterns[0].Operator != "StringEquals" {
		t.Fatalf("returned metadata mutation changed graph: %#v", again.Metadata.AWSIAMRole)
	}
}

func TestGraphAWSPermissionNodeMetadataIsCloned(t *testing.T) {
	g := New()
	permission := NewNode(AWSPermission, "aws://terraform/aws_permission/admin")
	permission.Metadata = &NodeMetadata{AWSPermission: &AWSPermissionMetadata{
		Provider:                 "aws",
		SourceReference:          "main.tf#resource=aws_iam_role_policy.admin",
		PolicyResourceName:       "admin",
		AttachedRoleResourceName: "deploy",
		Actions:                  []string{"*"},
		Resources:                []string{"*"},
		Administrative:           true,
		AdminReason:              "action_star_resource_star",
	}}

	added := mustAddNode(t, g, permission)
	permission.Metadata.AWSPermission.Actions[0] = "s3:GetObject"
	added.Metadata.AWSPermission.Resources[0] = "changed"

	got, ok := g.Node(added.ID)
	if !ok {
		t.Fatalf("node %q not found", added.ID)
	}
	if got.Metadata == nil || got.Metadata.AWSPermission == nil {
		t.Fatalf("metadata = %#v, want aws permission metadata", got.Metadata)
	}
	if got.Metadata.AWSPermission.Actions[0] != "*" || got.Metadata.AWSPermission.Resources[0] != "*" {
		t.Fatalf("stored metadata changed: %#v", got.Metadata.AWSPermission)
	}

	got.Metadata.AWSPermission.Actions[0] = "changed"
	again, ok := g.Node(added.ID)
	if !ok {
		t.Fatalf("node %q not found after mutation", added.ID)
	}
	if again.Metadata.AWSPermission.Actions[0] != "*" {
		t.Fatalf("returned metadata mutation changed graph: %#v", again.Metadata.AWSPermission)
	}
}

func TestGraphAWSCanAssumeRoleEdgeMetadataIsCloned(t *testing.T) {
	g := New()
	capability := mustAddNode(t, g, NewNode(OIDCTokenCapability, "githubactions://.github/workflows/deploy.yml/oidc-token/workflow"))
	role := mustAddNode(t, g, NewNode(AWSIAMRole, "aws://terraform/aws_iam_role/main.tf/deploy"))
	edge := NewEdge(CanAssumeRole, capability.ID, role.ID, SourceEvidence{Source: "main.tf#resource=aws_iam_role.deploy", Detail: "assume role"})
	edge.Metadata = &EdgeMetadata{AWSCanAssumeRole: &AWSCanAssumeRoleMetadata{
		Provider:         "aws",
		RoleResourceName: "deploy",
		TrustedIssuer:    "token.actions.githubusercontent.com",
		StatementIndex:   0,
		Audience:         "sts.amazonaws.com",
		SubjectCandidate: "repo:owner/repo:pull_request",
		SubjectPattern:   "repo:owner/repo:pull_request",
		SubjectOperator:  "StringEquals",
		WorkflowFile:     ".github/workflows/deploy.yml",
		Scope:            "workflow",
		Matches: []AWSCanAssumeRoleMatch{{
			Provider:         "aws",
			RoleResourceName: "deploy",
			TrustedIssuer:    "token.actions.githubusercontent.com",
			StatementIndex:   0,
			Audience:         "sts.amazonaws.com",
			SubjectCandidate: "repo:owner/repo:pull_request",
			SubjectPattern:   "repo:owner/repo:pull_request",
			SubjectOperator:  "StringEquals",
		}},
	}}

	added := mustAddEdge(t, g, edge)
	edge.Metadata.AWSCanAssumeRole.SubjectCandidate = "changed"
	edge.Metadata.AWSCanAssumeRole.Matches[0].SubjectCandidate = "changed"
	added.Metadata.AWSCanAssumeRole.SubjectPattern = "changed"
	added.Metadata.AWSCanAssumeRole.Matches[0].SubjectPattern = "changed"

	got, ok := g.Edge(added.ID)
	if !ok {
		t.Fatalf("edge %q not found", added.ID)
	}
	if got.Metadata == nil || got.Metadata.AWSCanAssumeRole == nil {
		t.Fatalf("metadata = %#v, want aws assume-role metadata", got.Metadata)
	}
	if got.Metadata.AWSCanAssumeRole.SubjectCandidate != "repo:owner/repo:pull_request" || got.Metadata.AWSCanAssumeRole.SubjectPattern != "repo:owner/repo:pull_request" {
		t.Fatalf("stored metadata changed: %#v", got.Metadata.AWSCanAssumeRole)
	}
	if len(got.Metadata.AWSCanAssumeRole.Matches) != 1 || got.Metadata.AWSCanAssumeRole.Matches[0].SubjectCandidate != "repo:owner/repo:pull_request" || got.Metadata.AWSCanAssumeRole.Matches[0].SubjectPattern != "repo:owner/repo:pull_request" {
		t.Fatalf("stored match metadata changed: %#v", got.Metadata.AWSCanAssumeRole.Matches)
	}

	got.Metadata.AWSCanAssumeRole.SubjectOperator = "changed"
	got.Metadata.AWSCanAssumeRole.Matches[0].SubjectOperator = "changed"
	again, ok := g.Edge(added.ID)
	if !ok {
		t.Fatalf("edge %q not found after mutation", added.ID)
	}
	if again.Metadata.AWSCanAssumeRole.SubjectOperator != "StringEquals" {
		t.Fatalf("returned metadata mutation changed graph: %#v", again.Metadata.AWSCanAssumeRole)
	}
	if again.Metadata.AWSCanAssumeRole.Matches[0].SubjectOperator != "StringEquals" {
		t.Fatalf("returned match metadata mutation changed graph: %#v", again.Metadata.AWSCanAssumeRole.Matches)
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

func TestGraphEdgeJSONOmitsEmptyMetadataAndIncludesTypedMetadata(t *testing.T) {
	g, endpoint, workload, serviceAccount, secret := exampleGraphNodes(t)
	mustAddEdge(t, g, NewEdge(RoutesTo, endpoint.ID, workload.ID, SourceEvidence{Source: "fixture", Detail: "route"}))
	canRead := NewEdge(CanRead, serviceAccount.ID, secret.ID, SourceEvidence{Source: "fixture", Detail: "secret read"})
	canRead.Metadata = &EdgeMetadata{KubernetesCanReadAuthorizations: []KubernetesCanReadAuthorization{{
		BindingKind:                         "RoleBinding",
		BindingNamespace:                    "prod",
		BindingName:                         "read-secrets",
		BindingSourceReference:              "binding.yaml#document=1",
		BindingSupportedServiceAccountCount: 1,
		ServiceAccountNamespace:             "prod",
		ServiceAccountName:                  "api",
		RoleKind:                            "Role",
		RoleNamespace:                       "prod",
		RoleName:                            "secret-reader",
		RoleSourceReference:                 "role.yaml#document=1",
		PermissionSHA256:                    "abc123",
		Permission: KubernetesPermission{
			APIGroups: []string{""},
			Resources: []string{"secrets"},
			Verbs:     []string{"get"},
		},
		MatchedVerb:            "get",
		ScopeKind:              "namespace",
		ScopeName:              "prod",
		SecretNamespace:        "prod",
		SecretName:             "database-password",
		SecretSourceReferences: []string{"secret.yaml#document=1"},
	}}}
	mustAddEdge(t, g, canRead)

	data, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal graph: %v", err)
	}
	got := string(data)
	if strings.Count(got, `"metadata"`) != 1 {
		t.Fatalf("metadata count in graph JSON = %d, want 1: %s", strings.Count(got, `"metadata"`), got)
	}
	if !strings.Contains(got, `"kubernetes_can_read_authorizations"`) || !strings.Contains(got, `"binding_name":"read-secrets"`) {
		t.Fatalf("graph JSON missing typed metadata: %s", got)
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
