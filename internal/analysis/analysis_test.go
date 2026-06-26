package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"pathproof/internal/graph"
	parserkubernetes "pathproof/internal/parser/kubernetes"
	routingkubernetes "pathproof/internal/routing/kubernetes"
)

func TestAnalyzeCompletePublicWorkloadCanReadSecretPath(t *testing.T) {
	g, endpoint, workload, serviceAccount, secret, edges := completeFindingGraph(t)

	findings := Analyze(g)

	if len(findings) != 1 {
		t.Fatalf("finding count = %d, want 1: %#v", len(findings), findings)
	}
	finding := findings[0]
	if finding.ID == "" {
		t.Fatal("finding ID is empty")
	}
	if finding.RuleID != RulePublicWorkloadCanReadSecret {
		t.Fatalf("rule ID = %q, want %q", finding.RuleID, RulePublicWorkloadCanReadSecret)
	}
	if finding.Title != publicWorkloadCanReadSecretTitle {
		t.Fatalf("title = %q, want %q", finding.Title, publicWorkloadCanReadSecretTitle)
	}
	if finding.Severity != SeverityHigh {
		t.Fatalf("severity = %q, want %q", finding.Severity, SeverityHigh)
	}

	wantNodeIDs := []graph.NodeID{endpoint.ID, workload.ID, serviceAccount.ID, secret.ID}
	wantEdgeIDs := []graph.EdgeID{edges[0].ID, edges[1].ID, edges[2].ID}
	if !reflect.DeepEqual(finding.NodeIDs, wantNodeIDs) {
		t.Fatalf("node IDs = %#v, want %#v", finding.NodeIDs, wantNodeIDs)
	}
	if !reflect.DeepEqual(finding.EdgeIDs, wantEdgeIDs) {
		t.Fatalf("edge IDs = %#v, want %#v", finding.EdgeIDs, wantEdgeIDs)
	}
	if len(finding.Evidence) != 3 {
		t.Fatalf("evidence count = %d, want 3: %#v", len(finding.Evidence), finding.Evidence)
	}
	for i, edge := range edges {
		if finding.Evidence[i].EdgeID != edge.ID || finding.Evidence[i].Kind != edge.Kind || finding.Evidence[i].Source != edge.Evidence {
			t.Fatalf("evidence[%d] = %#v, want edge %#v", i, finding.Evidence[i], edge)
		}
	}
	wantRefs := []string{edges[0].Evidence.Source, edges[1].Evidence.Source, edges[2].Evidence.Source}
	if !reflect.DeepEqual(finding.SourceReferences, wantRefs) {
		t.Fatalf("source references = %#v, want %#v", finding.SourceReferences, wantRefs)
	}
}

func TestAnalyzeRequiresExactDirectedRelationships(t *testing.T) {
	tests := []struct {
		name  string
		edges []graph.EdgeKind
	}{
		{
			name:  "missing RoutesTo",
			edges: []graph.EdgeKind{graph.RunsAs, graph.CanRead},
		},
		{
			name:  "missing RunsAs",
			edges: []graph.EdgeKind{graph.RoutesTo, graph.CanRead},
		},
		{
			name:  "missing CanRead",
			edges: []graph.EdgeKind{graph.RoutesTo, graph.RunsAs},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, endpoint, workload, serviceAccount, secret := findingNodes(t)
			for _, kind := range tt.edges {
				switch kind {
				case graph.RoutesTo:
					mustAddEdge(t, g, graph.NewEdge(graph.RoutesTo, endpoint.ID, workload.ID, evidence("route")))
				case graph.RunsAs:
					mustAddEdge(t, g, graph.NewEdge(graph.RunsAs, workload.ID, serviceAccount.ID, evidence("runs-as")))
				case graph.CanRead:
					mustAddEdge(t, g, graph.NewEdge(graph.CanRead, serviceAccount.ID, secret.ID, evidence("can-read")))
				}
			}

			if findings := Analyze(g); len(findings) != 0 {
				t.Fatalf("finding count = %d, want 0: %#v", len(findings), findings)
			}
		})
	}
}

func TestAnalyzeRequiresExactEdgeKinds(t *testing.T) {
	tests := []struct {
		name        string
		routeKind   graph.EdgeKind
		runsAsKind  graph.EdgeKind
		canReadKind graph.EdgeKind
	}{
		{
			name:        "PublicEndpoint to Workload must be RoutesTo",
			routeKind:   graph.BoundTo,
			runsAsKind:  graph.RunsAs,
			canReadKind: graph.CanRead,
		},
		{
			name:        "Workload to ServiceAccount must be RunsAs",
			routeKind:   graph.RoutesTo,
			runsAsKind:  graph.RoutesTo,
			canReadKind: graph.CanRead,
		},
		{
			name:        "ServiceAccount to Secret must be CanRead",
			routeKind:   graph.RoutesTo,
			runsAsKind:  graph.RunsAs,
			canReadKind: graph.RunsAs,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, endpoint, workload, serviceAccount, secret := findingNodes(t)
			mustAddEdge(t, g, graph.NewEdge(tt.routeKind, endpoint.ID, workload.ID, evidence("route")))
			mustAddEdge(t, g, graph.NewEdge(tt.runsAsKind, workload.ID, serviceAccount.ID, evidence("runs-as")))
			mustAddEdge(t, g, graph.NewEdge(tt.canReadKind, serviceAccount.ID, secret.ID, evidence("can-read")))

			if findings := Analyze(g); len(findings) != 0 {
				t.Fatalf("finding count = %d, want 0: %#v", len(findings), findings)
			}
		})
	}
}

func TestAnalyzeRequiresExactNodeKinds(t *testing.T) {
	tests := []struct {
		name               string
		endpointKind       graph.NodeKind
		workloadKind       graph.NodeKind
		serviceAccountKind graph.NodeKind
		secretKind         graph.NodeKind
	}{
		{
			name:               "RoutesTo from must be PublicEndpoint",
			endpointKind:       graph.Workload,
			workloadKind:       graph.Workload,
			serviceAccountKind: graph.ServiceAccount,
			secretKind:         graph.Secret,
		},
		{
			name:               "RoutesTo to and RunsAs from must be Workload",
			endpointKind:       graph.PublicEndpoint,
			workloadKind:       graph.PublicEndpoint,
			serviceAccountKind: graph.ServiceAccount,
			secretKind:         graph.Secret,
		},
		{
			name:               "RunsAs to and CanRead from must be ServiceAccount",
			endpointKind:       graph.PublicEndpoint,
			workloadKind:       graph.Workload,
			serviceAccountKind: graph.Workload,
			secretKind:         graph.Secret,
		},
		{
			name:               "CanRead to must be Secret",
			endpointKind:       graph.PublicEndpoint,
			workloadKind:       graph.Workload,
			serviceAccountKind: graph.ServiceAccount,
			secretKind:         graph.Workload,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := graph.New()
			endpoint := mustAddNode(t, g, graph.NewNode(tt.endpointKind, "kubernetes://prod/service/public-api"))
			workload := mustAddNode(t, g, graph.NewNode(tt.workloadKind, "kubernetes://prod/deployment/api"))
			serviceAccount := mustAddNode(t, g, graph.NewNode(tt.serviceAccountKind, "kubernetes://prod/serviceaccount/api"))
			secret := mustAddNode(t, g, graph.NewNode(tt.secretKind, "kubernetes://prod/secret/database-password"))
			mustAddEdge(t, g, graph.NewEdge(graph.RoutesTo, endpoint.ID, workload.ID, evidence("route")))
			mustAddEdge(t, g, graph.NewEdge(graph.RunsAs, workload.ID, serviceAccount.ID, evidence("runs-as")))
			mustAddEdge(t, g, graph.NewEdge(graph.CanRead, serviceAccount.ID, secret.ID, evidence("can-read")))

			if findings := Analyze(g); len(findings) != 0 {
				t.Fatalf("finding count = %d, want 0: %#v", len(findings), findings)
			}
		})
	}
}

func TestAnalyzeReversedEdgeDirectionsCreateNoFinding(t *testing.T) {
	g, endpoint, workload, serviceAccount, secret := findingNodes(t)
	mustAddEdge(t, g, graph.NewEdge(graph.RoutesTo, workload.ID, endpoint.ID, evidence("reversed-route")))
	mustAddEdge(t, g, graph.NewEdge(graph.RunsAs, serviceAccount.ID, workload.ID, evidence("reversed-runs-as")))
	mustAddEdge(t, g, graph.NewEdge(graph.CanRead, secret.ID, serviceAccount.ID, evidence("reversed-can-read")))

	if findings := Analyze(g); len(findings) != 0 {
		t.Fatalf("finding count = %d, want 0: %#v", len(findings), findings)
	}
}

func TestAnalyzeIgnoresUnrelatedEdgesAndCycles(t *testing.T) {
	g, _, workload, _, _, _ := completeFindingGraph(t)
	otherEndpoint := mustAddNode(t, g, graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/unrelated"))
	otherWorkload := mustAddNode(t, g, graph.NewNode(graph.Workload, "kubernetes://prod/deployment/unrelated"))
	otherServiceAccount := mustAddNode(t, g, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/unrelated"))
	otherSecret := mustAddNode(t, g, graph.NewNode(graph.Secret, "kubernetes://prod/secret/unrelated"))
	mustAddEdge(t, g, graph.NewEdge(graph.RoutesTo, otherEndpoint.ID, otherWorkload.ID, evidence("unrelated-route")))
	mustAddEdge(t, g, graph.NewEdge(graph.RoutesTo, workload.ID, otherEndpoint.ID, evidence("cycle")))
	mustAddEdge(t, g, graph.NewEdge(graph.CanRead, otherServiceAccount.ID, otherSecret.ID, evidence("unrelated-can-read")))

	findings := Analyze(g)
	if len(findings) != 1 {
		t.Fatalf("finding count = %d, want 1: %#v", len(findings), findings)
	}
}

func TestAnalyzeDistinctPathCardinality(t *testing.T) {
	t.Run("two public endpoints create two findings", func(t *testing.T) {
		g, _, workload, serviceAccount, secret, _ := completeFindingGraph(t)
		endpoint := mustAddNode(t, g, graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/ingress/public-api"))
		mustAddEdge(t, g, graph.NewEdge(graph.RoutesTo, endpoint.ID, workload.ID, evidence("second-route")))

		if findings := Analyze(g); len(findings) != 2 {
			t.Fatalf("finding count = %d, want 2: %#v", len(findings), findings)
		}
		assertFindingChainsUnique(t, Analyze(g), serviceAccount.ID, secret.ID)
	})

	t.Run("two workloads create separate findings", func(t *testing.T) {
		g, endpoint, _, serviceAccount, secret, _ := completeFindingGraph(t)
		workload := mustAddNode(t, g, graph.NewNode(graph.Workload, "kubernetes://prod/deployment/worker"))
		mustAddEdge(t, g, graph.NewEdge(graph.RoutesTo, endpoint.ID, workload.ID, evidence("second-route")))
		mustAddEdge(t, g, graph.NewEdge(graph.RunsAs, workload.ID, serviceAccount.ID, evidence("second-runs-as")))

		if findings := Analyze(g); len(findings) != 2 {
			t.Fatalf("finding count = %d, want 2: %#v", len(findings), findings)
		}
		assertFindingChainsUnique(t, Analyze(g), serviceAccount.ID, secret.ID)
	})

	t.Run("two secrets create separate findings", func(t *testing.T) {
		g, _, _, serviceAccount, _, _ := completeFindingGraph(t)
		secret := mustAddNode(t, g, graph.NewNode(graph.Secret, "kubernetes://prod/secret/api-token"))
		mustAddEdge(t, g, graph.NewEdge(graph.CanRead, serviceAccount.ID, secret.ID, evidence("second-can-read")))

		if findings := Analyze(g); len(findings) != 2 {
			t.Fatalf("finding count = %d, want 2: %#v", len(findings), findings)
		}
	})
}

func TestAnalyzeDistinctServiceAccountPaths(t *testing.T) {
	g := graph.New()
	endpoint := mustAddNode(t, g, graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/public-api"))
	workload := mustAddNode(t, g, graph.NewNode(graph.Workload, "kubernetes://prod/deployment/api"))
	firstServiceAccount := mustAddNode(t, g, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/api"))
	secondServiceAccount := mustAddNode(t, g, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/worker"))
	secret := mustAddNode(t, g, graph.NewNode(graph.Secret, "kubernetes://prod/secret/database-password"))
	route := mustAddEdge(t, g, graph.NewEdge(graph.RoutesTo, endpoint.ID, workload.ID, evidence("route")))
	firstRunsAs := mustAddEdge(t, g, graph.NewEdge(graph.RunsAs, workload.ID, firstServiceAccount.ID, evidence("first-runs-as")))
	secondRunsAs := mustAddEdge(t, g, graph.NewEdge(graph.RunsAs, workload.ID, secondServiceAccount.ID, evidence("second-runs-as")))
	firstCanRead := mustAddEdge(t, g, graph.NewEdge(graph.CanRead, firstServiceAccount.ID, secret.ID, evidence("first-can-read")))
	secondCanRead := mustAddEdge(t, g, graph.NewEdge(graph.CanRead, secondServiceAccount.ID, secret.ID, evidence("second-can-read")))

	findings := Analyze(g)
	if len(findings) != 2 {
		t.Fatalf("finding count = %d, want 2: %#v", len(findings), findings)
	}

	byServiceAccount := make(map[graph.NodeID]Finding)
	for _, finding := range findings {
		if finding.NodeIDs[0] != endpoint.ID || finding.NodeIDs[1] != workload.ID || finding.NodeIDs[3] != secret.ID {
			t.Fatalf("finding node chain = %#v, want shared endpoint/workload/secret", finding.NodeIDs)
		}
		if _, exists := byServiceAccount[finding.NodeIDs[2]]; exists {
			t.Fatalf("duplicate ServiceAccount finding chain: %#v", finding.NodeIDs)
		}
		byServiceAccount[finding.NodeIDs[2]] = finding
	}

	first := byServiceAccount[firstServiceAccount.ID]
	second := byServiceAccount[secondServiceAccount.ID]
	if first.ID == "" || second.ID == "" {
		t.Fatalf("missing finding for one or both ServiceAccounts: %#v", findings)
	}
	if first.ID == second.ID {
		t.Fatalf("finding IDs are identical for distinct ServiceAccount paths: %q", first.ID)
	}
	wantFirstNodes := []graph.NodeID{endpoint.ID, workload.ID, firstServiceAccount.ID, secret.ID}
	wantSecondNodes := []graph.NodeID{endpoint.ID, workload.ID, secondServiceAccount.ID, secret.ID}
	wantFirstEdges := []graph.EdgeID{route.ID, firstRunsAs.ID, firstCanRead.ID}
	wantSecondEdges := []graph.EdgeID{route.ID, secondRunsAs.ID, secondCanRead.ID}
	if !reflect.DeepEqual(first.NodeIDs, wantFirstNodes) || !reflect.DeepEqual(second.NodeIDs, wantSecondNodes) {
		t.Fatalf("node chains = %#v and %#v, want %#v and %#v", first.NodeIDs, second.NodeIDs, wantFirstNodes, wantSecondNodes)
	}
	if !reflect.DeepEqual(first.EdgeIDs, wantFirstEdges) || !reflect.DeepEqual(second.EdgeIDs, wantSecondEdges) {
		t.Fatalf("edge chains = %#v and %#v, want %#v and %#v", first.EdgeIDs, second.EdgeIDs, wantFirstEdges, wantSecondEdges)
	}
	if first.NodeIDs[2] == second.NodeIDs[2] {
		t.Fatalf("ServiceAccount node IDs are identical: %q", first.NodeIDs[2])
	}
	if first.EdgeIDs[1] == second.EdgeIDs[1] {
		t.Fatalf("RunsAs edge IDs are identical: %q", first.EdgeIDs[1])
	}
	if first.EdgeIDs[2] == second.EdgeIDs[2] {
		t.Fatalf("CanRead edge IDs are identical: %q", first.EdgeIDs[2])
	}
}

func TestAnalyzePreservesAggregatedCanReadEvidenceOnOneFinding(t *testing.T) {
	g, _, _, _, _, _ := completeFindingGraphWithCanReadEvidence(t, graph.SourceEvidence{
		Source: "kubernetes Secret read access: binding_name=read-secrets-a | binding_name=read-secrets-b",
		Detail: "binding_name=read-secrets-a | binding_name=read-secrets-b",
	})

	findings := Analyze(g)
	if len(findings) != 1 {
		t.Fatalf("finding count = %d, want 1: %#v", len(findings), findings)
	}
	if got := findings[0].Evidence[2].Source.Detail; !strings.Contains(got, "binding_name=read-secrets-a") || !strings.Contains(got, "binding_name=read-secrets-b") {
		t.Fatalf("can-read evidence detail = %q, want both records", got)
	}
}

func TestAnalyzeFindingIDsAndOrderAreDeterministic(t *testing.T) {
	first, _, _, _, _, _ := twoFindingGraph(t)
	second := twoFindingGraphReverseInsertion(t)

	firstFindings := Analyze(first)
	secondFindings := Analyze(second)
	thirdFindings := Analyze(first)
	firstJSON := mustMarshalFindings(t, firstFindings)
	secondJSON := mustMarshalFindings(t, secondFindings)
	thirdJSON := mustMarshalFindings(t, thirdFindings)

	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("findings differ by graph insertion order:\nfirst:  %s\nsecond: %s", firstJSON, secondJSON)
	}
	if string(firstJSON) != string(thirdJSON) {
		t.Fatalf("findings differ across repeated analysis:\nfirst: %s\nthird: %s", firstJSON, thirdJSON)
	}
}

func TestAnalyzeFindingIDIgnoresEvidence(t *testing.T) {
	firstGraph, _, _, _, _, firstEdges := completeFindingGraphWithEvidence(t,
		graph.SourceEvidence{Source: "first-route.yaml#document=1", Detail: "first route evidence"},
		graph.SourceEvidence{Source: "first-runs-as.yaml#document=1", Detail: "first runs-as evidence"},
		graph.SourceEvidence{Source: "first-can-read.yaml#document=1", Detail: "first can-read evidence"},
	)
	secondGraph, _, _, _, _, secondEdges := completeFindingGraphWithEvidence(t,
		graph.SourceEvidence{Source: "second-route.yaml#document=1", Detail: "second route evidence"},
		graph.SourceEvidence{Source: "second-runs-as.yaml#document=1", Detail: "second runs-as evidence"},
		graph.SourceEvidence{Source: "second-can-read.yaml#document=1", Detail: "second can-read evidence"},
	)

	firstFindings := Analyze(firstGraph)
	secondFindings := Analyze(secondGraph)
	if len(firstFindings) != 1 || len(secondFindings) != 1 {
		t.Fatalf("finding counts = %d and %d, want 1 and 1", len(firstFindings), len(secondFindings))
	}
	first := firstFindings[0]
	second := secondFindings[0]
	if first.ID != second.ID {
		t.Fatalf("finding IDs differ by evidence: first %q second %q", first.ID, second.ID)
	}
	if reflect.DeepEqual(first.Evidence, second.Evidence) {
		t.Fatalf("finding evidence is identical, want graph-specific evidence preserved: %#v", first.Evidence)
	}
	for i, edge := range firstEdges {
		if first.Evidence[i].Source != edge.Evidence {
			t.Fatalf("first evidence[%d] = %#v, want %#v", i, first.Evidence[i].Source, edge.Evidence)
		}
	}
	for i, edge := range secondEdges {
		if second.Evidence[i].Source != edge.Evidence {
			t.Fatalf("second evidence[%d] = %#v, want %#v", i, second.Evidence[i].Source, edge.Evidence)
		}
	}
}

func TestAnalyzeFindingIDChangesWhenIdentityInputChanges(t *testing.T) {
	firstGraph, _, _, _, _, _ := completeFindingGraph(t)
	secondGraph, _, workload, _, secret, _ := completeFindingGraph(t)
	secondServiceAccount := mustAddNode(t, secondGraph, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/worker"))
	mustAddEdge(t, secondGraph, graph.NewEdge(graph.RunsAs, workload.ID, secondServiceAccount.ID, evidence("second-runs-as")))
	mustAddEdge(t, secondGraph, graph.NewEdge(graph.CanRead, secondServiceAccount.ID, secret.ID, evidence("second-can-read")))

	firstFindings := Analyze(firstGraph)
	secondFindings := Analyze(secondGraph)
	if len(firstFindings) != 1 {
		t.Fatalf("first finding count = %d, want 1: %#v", len(firstFindings), firstFindings)
	}
	var changed Finding
	for _, finding := range secondFindings {
		if finding.NodeIDs[2] == secondServiceAccount.ID {
			changed = finding
			break
		}
	}
	if changed.ID == "" {
		t.Fatalf("changed ServiceAccount finding not found: %#v", secondFindings)
	}
	if firstFindings[0].ID == changed.ID {
		t.Fatalf("finding ID did not change after ServiceAccount identity changed: %q", changed.ID)
	}
}

func TestStableFindingIDChangesWhenEdgeIDsChange(t *testing.T) {
	nodeIDs := []graph.NodeID{
		graph.NodeID("node:PublicEndpoint:same-endpoint"),
		graph.NodeID("node:Workload:same-workload"),
		graph.NodeID("node:ServiceAccount:same-service-account"),
		graph.NodeID("node:Secret:same-secret"),
	}
	firstEdgeIDs := []graph.EdgeID{
		graph.EdgeID("edge:RoutesTo:first"),
		graph.EdgeID("edge:RunsAs:first"),
		graph.EdgeID("edge:CanRead:first"),
	}
	secondEdgeIDs := []graph.EdgeID{
		graph.EdgeID("edge:RoutesTo:first"),
		graph.EdgeID("edge:RunsAs:second"),
		graph.EdgeID("edge:CanRead:first"),
	}

	first, err := stableFindingID(RulePublicWorkloadCanReadSecret, nodeIDs, firstEdgeIDs)
	if err != nil {
		t.Fatalf("first finding ID: %v", err)
	}
	second, err := stableFindingID(RulePublicWorkloadCanReadSecret, nodeIDs, secondEdgeIDs)
	if err != nil {
		t.Fatalf("second finding ID: %v", err)
	}
	if first == second {
		t.Fatalf("finding IDs are identical after edge ID changed: %q", first)
	}
}

func TestAnalyzeSourceReferencesOmitEmptyAndDeduplicateInPathOrder(t *testing.T) {
	g, _, _, _, _, _ := completeFindingGraphWithEvidence(t,
		graph.SourceEvidence{Source: "shared.yaml#document=1", Detail: "route"},
		graph.SourceEvidence{Source: "", Detail: "runs-as"},
		graph.SourceEvidence{Source: "shared.yaml#document=1", Detail: "can-read"},
	)

	findings := Analyze(g)
	if len(findings) != 1 {
		t.Fatalf("finding count = %d, want 1: %#v", len(findings), findings)
	}
	want := []string{"shared.yaml#document=1"}
	if !reflect.DeepEqual(findings[0].SourceReferences, want) {
		t.Fatalf("source references = %#v, want %#v", findings[0].SourceReferences, want)
	}
	if findings[0].Evidence[1].Source.Source != "" {
		t.Fatalf("runs-as evidence source = %q, want preserved empty source", findings[0].Evidence[1].Source.Source)
	}
}

func TestAnalyzeFindingsOwnIndependentSlices(t *testing.T) {
	g, _, _, _, _, _ := twoFindingGraph(t)
	findings := Analyze(g)
	if len(findings) != 2 {
		t.Fatalf("finding count = %d, want 2: %#v", len(findings), findings)
	}
	graphBefore := mustMarshalGraph(t, g)
	freshBefore := mustMarshalFindings(t, Analyze(g))
	secondBefore := mustMarshalFinding(t, findings[1])
	assertFindingSlicesDoNotHaveSpareCapacity(t, findings)
	assertFindingSlicesDoNotOverlap(t, findings[0], findings[1])

	findings[0].NodeIDs[0] = graph.NodeID("changed-node")
	findings[0].NodeIDs = append(findings[0].NodeIDs, graph.NodeID("node:Test:appended-node"))
	findings[0].EdgeIDs[0] = graph.EdgeID("changed-edge")
	findings[0].EdgeIDs = append(findings[0].EdgeIDs, graph.EdgeID("edge:Test:appended-edge"))
	findings[0].Evidence[0] = FindingEvidence{EdgeID: graph.EdgeID("changed-evidence")}
	findings[0].Evidence = append(findings[0].Evidence, FindingEvidence{
		EdgeID: graph.EdgeID("edge:Test:appended-evidence"),
		Kind:   graph.CanRead,
		Source: graph.SourceEvidence{Source: "appended-evidence.yaml#document=1", Detail: "appended evidence"},
	})
	findings[0].SourceReferences[0] = "changed-source"
	findings[0].SourceReferences = append(findings[0].SourceReferences, "appended-source.yaml#document=1")

	if secondAfter := mustMarshalFinding(t, findings[1]); string(secondAfter) != string(secondBefore) {
		t.Fatalf("second finding changed after mutating first finding slices:\nbefore: %s\nafter:  %s", secondBefore, secondAfter)
	}
	if graphAfter := mustMarshalGraph(t, g); string(graphAfter) != string(graphBefore) {
		t.Fatalf("graph changed after mutating returned finding:\nbefore: %s\nafter:  %s", graphBefore, graphAfter)
	}
	if freshAfter := mustMarshalFindings(t, Analyze(g)); string(freshAfter) != string(freshBefore) {
		t.Fatalf("fresh Analyze changed after mutating returned finding:\nbefore: %s\nafter:  %s", freshBefore, freshAfter)
	}
}

func TestAnalyzeDoesNotMutateGraph(t *testing.T) {
	g, _, workload, _, _, _ := completeFindingGraphWithCanReadEvidence(t, graph.SourceEvidence{
		Source: "kubernetes Secret read access: binding_name=read-secrets-a | binding_name=read-secrets-b",
		Detail: "binding_name=read-secrets-a | binding_name=read-secrets-b",
	})
	unrelatedEndpointNode := graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/unrelated")
	unrelatedEndpointNode.Evidence = []graph.SourceEvidence{{Source: "unrelated-endpoint.yaml#document=1", Detail: "unrelated endpoint node evidence"}}
	unrelatedEndpoint := mustAddNode(t, g, unrelatedEndpointNode)
	unrelatedWorkload := mustAddNode(t, g, graph.NewNode(graph.Workload, "kubernetes://prod/deployment/unrelated"))
	unrelatedRole := mustAddNode(t, g, graph.NewNode(graph.Role, "kubernetes://prod/role/unrelated"))
	mustAddEdge(t, g, graph.NewEdge(graph.RoutesTo, unrelatedEndpoint.ID, unrelatedWorkload.ID, evidence("unrelated-route")))
	mustAddEdge(t, g, graph.NewEdge(graph.BoundTo, workload.ID, unrelatedRole.ID, evidence("unrelated-bound-to")))

	before := mustMarshalGraph(t, g)
	beforeNodeCount := len(g.Nodes())
	beforeEdgeCount := len(g.Edges())

	firstFindings := Analyze(g)
	afterFirst := mustMarshalGraph(t, g)
	if string(afterFirst) != string(before) {
		t.Fatalf("graph changed after first Analyze:\nbefore: %s\nafter:  %s", before, afterFirst)
	}
	if got := len(g.Nodes()); got != beforeNodeCount {
		t.Fatalf("node count after first Analyze = %d, want %d", got, beforeNodeCount)
	}
	if got := len(g.Edges()); got != beforeEdgeCount {
		t.Fatalf("edge count after first Analyze = %d, want %d", got, beforeEdgeCount)
	}

	secondFindings := Analyze(g)
	afterSecond := mustMarshalGraph(t, g)
	if string(afterSecond) != string(before) {
		t.Fatalf("graph changed after second Analyze:\nbefore: %s\nafter:  %s", before, afterSecond)
	}
	if string(mustMarshalFindings(t, secondFindings)) != string(mustMarshalFindings(t, firstFindings)) {
		t.Fatalf("findings changed across repeated Analyze:\nfirst:  %s\nsecond: %s", mustMarshalFindings(t, firstFindings), mustMarshalFindings(t, secondFindings))
	}
}

func TestAnalyzeNilAndEmptyGraphReturnEmptyNonNilSlice(t *testing.T) {
	tests := []struct {
		name  string
		graph *graph.Graph
	}{
		{name: "nil"},
		{name: "empty", graph: graph.New()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Analyze(tt.graph)
			if findings == nil {
				t.Fatal("findings = nil, want empty non-nil slice")
			}
			if len(findings) != 0 {
				t.Fatalf("finding count = %d, want 0: %#v", len(findings), findings)
			}
		})
	}
}

func TestAnalyzeDoesNotIntroduceSecretContent(t *testing.T) {
	const fakeSecretValue = "FAKE_ANALYSIS_UNIT_SECRET_VALUE_DO_NOT_RETAIN"
	g, _, _, _, _, _ := completeFindingGraph(t)

	data := mustMarshalFindings(t, Analyze(g))
	if strings.Contains(string(data), fakeSecretValue) {
		t.Fatalf("findings contain fake Secret value %q: %s", fakeSecretValue, data)
	}
}

func TestAnalyzeSecretValuesAbsentThroughKubernetesPipeline(t *testing.T) {
	dir := t.TempDir()
	const fakeDataValue = "FAKE_ANALYSIS_PIPELINE_SECRET_DATA_VALUE_DO_NOT_RETAIN"
	const fakeStringDataValue = "FAKE_ANALYSIS_PIPELINE_SECRET_STRINGDATA_VALUE_DO_NOT_RETAIN"
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
spec:
  template:
    metadata:
      labels:
        app: api
    spec:
      serviceAccountName: api
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api
  namespace: prod
---
apiVersion: v1
kind: Secret
metadata:
  name: database-password
  namespace: prod
data:
  password: FAKE_ANALYSIS_PIPELINE_SECRET_DATA_VALUE_DO_NOT_RETAIN
stringData:
  token: FAKE_ANALYSIS_PIPELINE_SECRET_STRINGDATA_VALUE_DO_NOT_RETAIN
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
	g := graph.New()
	if err := routingkubernetes.AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}

	findings := Analyze(g)
	if len(findings) != 1 {
		t.Fatalf("finding count = %d, want 1: %#v", len(findings), findings)
	}
	data := mustMarshalFindings(t, findings)
	for _, value := range []string{fakeDataValue, fakeStringDataValue} {
		if strings.Contains(string(data), value) {
			t.Fatalf("findings contain Secret value %q: %s", value, data)
		}
	}
}

func completeFindingGraph(t *testing.T) (*graph.Graph, graph.Node, graph.Node, graph.Node, graph.Node, []graph.Edge) {
	t.Helper()
	return completeFindingGraphWithCanReadEvidence(t, evidence("can-read"))
}

func completeFindingGraphWithCanReadEvidence(t *testing.T, canReadEvidence graph.SourceEvidence) (*graph.Graph, graph.Node, graph.Node, graph.Node, graph.Node, []graph.Edge) {
	t.Helper()
	return completeFindingGraphWithEvidence(t, evidence("route"), evidence("runs-as"), canReadEvidence)
}

func completeFindingGraphWithEvidence(t *testing.T, routeEvidence, runsAsEvidence, canReadEvidence graph.SourceEvidence) (*graph.Graph, graph.Node, graph.Node, graph.Node, graph.Node, []graph.Edge) {
	t.Helper()
	g, endpoint, workload, serviceAccount, secret := findingNodes(t)
	route := mustAddEdge(t, g, graph.NewEdge(graph.RoutesTo, endpoint.ID, workload.ID, routeEvidence))
	runsAs := mustAddEdge(t, g, graph.NewEdge(graph.RunsAs, workload.ID, serviceAccount.ID, runsAsEvidence))
	canRead := mustAddEdge(t, g, graph.NewEdge(graph.CanRead, serviceAccount.ID, secret.ID, canReadEvidence))
	return g, endpoint, workload, serviceAccount, secret, []graph.Edge{route, runsAs, canRead}
}

func findingNodes(t *testing.T) (*graph.Graph, graph.Node, graph.Node, graph.Node, graph.Node) {
	t.Helper()
	g := graph.New()
	endpoint := mustAddNode(t, g, graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/public-api"))
	workload := mustAddNode(t, g, graph.NewNode(graph.Workload, "kubernetes://prod/deployment/api"))
	serviceAccount := mustAddNode(t, g, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/api"))
	secret := mustAddNode(t, g, graph.NewNode(graph.Secret, "kubernetes://prod/secret/database-password"))
	return g, endpoint, workload, serviceAccount, secret
}

func twoFindingGraph(t *testing.T) (*graph.Graph, graph.Node, graph.Node, graph.Node, graph.Node, graph.Node) {
	t.Helper()
	g, endpoint, workload, serviceAccount, secret, _ := completeFindingGraph(t)
	secondSecret := mustAddNode(t, g, graph.NewNode(graph.Secret, "kubernetes://prod/secret/api-token"))
	mustAddEdge(t, g, graph.NewEdge(graph.CanRead, serviceAccount.ID, secondSecret.ID, evidence("second-can-read")))
	return g, endpoint, workload, serviceAccount, secret, secondSecret
}

func twoFindingGraphReverseInsertion(t *testing.T) *graph.Graph {
	t.Helper()
	g := graph.New()
	secondSecret := mustAddNode(t, g, graph.NewNode(graph.Secret, "kubernetes://prod/secret/api-token"))
	secret := mustAddNode(t, g, graph.NewNode(graph.Secret, "kubernetes://prod/secret/database-password"))
	serviceAccount := mustAddNode(t, g, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/api"))
	workload := mustAddNode(t, g, graph.NewNode(graph.Workload, "kubernetes://prod/deployment/api"))
	endpoint := mustAddNode(t, g, graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/public-api"))
	mustAddEdge(t, g, graph.NewEdge(graph.CanRead, serviceAccount.ID, secondSecret.ID, evidence("second-can-read")))
	mustAddEdge(t, g, graph.NewEdge(graph.CanRead, serviceAccount.ID, secret.ID, evidence("can-read")))
	mustAddEdge(t, g, graph.NewEdge(graph.RunsAs, workload.ID, serviceAccount.ID, evidence("runs-as")))
	mustAddEdge(t, g, graph.NewEdge(graph.RoutesTo, endpoint.ID, workload.ID, evidence("route")))
	return g
}

func evidence(name string) graph.SourceEvidence {
	return graph.SourceEvidence{
		Source: name + ".yaml#document=1",
		Detail: name + " evidence",
	}
}

func mustAddNode(t *testing.T, g *graph.Graph, node graph.Node) graph.Node {
	t.Helper()
	added, err := g.AddNode(node)
	if err != nil {
		t.Fatalf("add node: %v", err)
	}
	return added
}

func mustAddEdge(t *testing.T, g *graph.Graph, edge graph.Edge) graph.Edge {
	t.Helper()
	added, err := g.AddEdge(edge)
	if err != nil {
		t.Fatalf("add edge: %v", err)
	}
	return added
}

func mustMarshalFindings(t *testing.T, findings []Finding) []byte {
	t.Helper()
	data, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("marshal findings: %v", err)
	}
	return data
}

func mustMarshalFinding(t *testing.T, finding Finding) []byte {
	t.Helper()
	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
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

func assertFindingSlicesDoNotHaveSpareCapacity(t *testing.T, findings []Finding) {
	t.Helper()
	for i, finding := range findings {
		if len(finding.NodeIDs) != cap(finding.NodeIDs) {
			t.Fatalf("finding[%d] NodeIDs len/cap = %d/%d, want no spare capacity", i, len(finding.NodeIDs), cap(finding.NodeIDs))
		}
		if len(finding.EdgeIDs) != cap(finding.EdgeIDs) {
			t.Fatalf("finding[%d] EdgeIDs len/cap = %d/%d, want no spare capacity", i, len(finding.EdgeIDs), cap(finding.EdgeIDs))
		}
		if len(finding.Evidence) != cap(finding.Evidence) {
			t.Fatalf("finding[%d] Evidence len/cap = %d/%d, want no spare capacity", i, len(finding.Evidence), cap(finding.Evidence))
		}
		if len(finding.SourceReferences) != cap(finding.SourceReferences) {
			t.Fatalf("finding[%d] SourceReferences len/cap = %d/%d, want no spare capacity", i, len(finding.SourceReferences), cap(finding.SourceReferences))
		}
	}
}

func assertFindingSlicesDoNotOverlap(t *testing.T, first, second Finding) {
	t.Helper()
	if slicesOverlap(first.NodeIDs, second.NodeIDs) {
		t.Fatal("NodeIDs backing memory overlaps between findings")
	}
	if slicesOverlap(first.EdgeIDs, second.EdgeIDs) {
		t.Fatal("EdgeIDs backing memory overlaps between findings")
	}
	if slicesOverlap(first.Evidence, second.Evidence) {
		t.Fatal("Evidence backing memory overlaps between findings")
	}
	if slicesOverlap(first.SourceReferences, second.SourceReferences) {
		t.Fatal("SourceReferences backing memory overlaps between findings")
	}
}

func slicesOverlap[T any](a, b []T) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}

	elementSize := unsafe.Sizeof(a[0])
	aStart := uintptr(unsafe.Pointer(&a[0]))
	aEnd := aStart + uintptr(len(a))*elementSize
	bStart := uintptr(unsafe.Pointer(&b[0]))
	bEnd := bStart + uintptr(len(b))*elementSize

	return aStart < bEnd && bStart < aEnd
}

func assertFindingChainsUnique(t *testing.T, findings []Finding, serviceAccountID graph.NodeID, secretID graph.NodeID) {
	t.Helper()
	seen := make(map[string]struct{})
	for _, finding := range findings {
		if finding.NodeIDs[2] != serviceAccountID || finding.NodeIDs[3] != secretID {
			t.Fatalf("unexpected service account or secret in finding: %#v", finding.NodeIDs)
		}
		key := string(finding.NodeIDs[0]) + "\x00" + string(finding.NodeIDs[1])
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate endpoint/workload chain: %#v", finding.NodeIDs)
		}
		seen[key] = struct{}{}
	}
}

func writeManifest(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}
