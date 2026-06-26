package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"pathproof/internal/graph"
)

type FindingID string
type RuleID string
type Severity string

const (
	RulePublicWorkloadCanReadSecret RuleID   = "PP-K8S-001"
	SeverityHigh                    Severity = "High"
)

const publicWorkloadCanReadSecretTitle = "Public workload can read Kubernetes Secret"

type Finding struct {
	ID               FindingID         `json:"id"`
	RuleID           RuleID            `json:"rule_id"`
	Title            string            `json:"title"`
	Severity         Severity          `json:"severity"`
	NodeIDs          []graph.NodeID    `json:"node_ids"`
	EdgeIDs          []graph.EdgeID    `json:"edge_ids"`
	Summary          string            `json:"summary"`
	Evidence         []FindingEvidence `json:"evidence"`
	SourceReferences []string          `json:"source_references"`
}

type FindingEvidence struct {
	EdgeID graph.EdgeID         `json:"edge_id"`
	Kind   graph.EdgeKind       `json:"kind"`
	Source graph.SourceEvidence `json:"source"`
}

type findingIdentity struct {
	RuleID  RuleID         `json:"rule_id"`
	NodeIDs []graph.NodeID `json:"node_ids"`
	EdgeIDs []graph.EdgeID `json:"edge_ids"`
}

func Analyze(g *graph.Graph) []Finding {
	findings := make([]Finding, 0)
	if g == nil {
		return findings
	}

	var routesTo []graph.Edge
	runsAsByWorkload := make(map[graph.NodeID][]graph.Edge)
	canReadByServiceAccount := make(map[graph.NodeID][]graph.Edge)
	for _, edge := range g.Edges() {
		switch edge.Kind {
		case graph.RoutesTo:
			routesTo = append(routesTo, edge)
		case graph.RunsAs:
			runsAsByWorkload[edge.From] = append(runsAsByWorkload[edge.From], edge)
		case graph.CanRead:
			canReadByServiceAccount[edge.From] = append(canReadByServiceAccount[edge.From], edge)
		}
	}

	for _, route := range routesTo {
		endpoint, ok := nodeOfKind(g, route.From, graph.PublicEndpoint)
		if !ok {
			continue
		}
		workload, ok := nodeOfKind(g, route.To, graph.Workload)
		if !ok {
			continue
		}

		for _, runsAs := range runsAsByWorkload[workload.ID] {
			serviceAccount, ok := nodeOfKind(g, runsAs.To, graph.ServiceAccount)
			if !ok {
				continue
			}

			for _, canRead := range canReadByServiceAccount[serviceAccount.ID] {
				secret, ok := nodeOfKind(g, canRead.To, graph.Secret)
				if !ok {
					continue
				}

				finding, err := newPublicWorkloadCanReadSecretFinding(endpoint, workload, serviceAccount, secret, route, runsAs, canRead)
				if err != nil {
					continue
				}
				findings = append(findings, finding)
			}
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].ID < findings[j].ID
	})
	return findings
}

func nodeOfKind(g *graph.Graph, id graph.NodeID, kind graph.NodeKind) (graph.Node, bool) {
	node, ok := g.Node(id)
	if !ok || node.Kind != kind {
		return graph.Node{}, false
	}
	return node, true
}

func newPublicWorkloadCanReadSecretFinding(endpoint, workload, serviceAccount, secret graph.Node, route, runsAs, canRead graph.Edge) (Finding, error) {
	nodeIDs := []graph.NodeID{endpoint.ID, workload.ID, serviceAccount.ID, secret.ID}
	edgeIDs := []graph.EdgeID{route.ID, runsAs.ID, canRead.ID}
	id, err := stableFindingID(RulePublicWorkloadCanReadSecret, nodeIDs, edgeIDs)
	if err != nil {
		return Finding{}, err
	}

	evidence := []FindingEvidence{
		findingEvidence(route),
		findingEvidence(runsAs),
		findingEvidence(canRead),
	}
	return Finding{
		ID:               id,
		RuleID:           RulePublicWorkloadCanReadSecret,
		Title:            publicWorkloadCanReadSecretTitle,
		Severity:         SeverityHigh,
		NodeIDs:          append([]graph.NodeID(nil), nodeIDs...),
		EdgeIDs:          append([]graph.EdgeID(nil), edgeIDs...),
		Summary:          "Public endpoint " + endpoint.Name + " routes to workload " + workload.Name + ", which runs as service account " + serviceAccount.Name + " that can read Secret " + secret.Name + ".",
		Evidence:         cloneFindingEvidence(evidence),
		SourceReferences: sourceReferences(evidence),
	}, nil
}

func stableFindingID(ruleID RuleID, nodeIDs []graph.NodeID, edgeIDs []graph.EdgeID) (FindingID, error) {
	data, err := json.Marshal(findingIdentity{
		RuleID:  ruleID,
		NodeIDs: append([]graph.NodeID(nil), nodeIDs...),
		EdgeIDs: append([]graph.EdgeID(nil), edgeIDs...),
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return FindingID("finding:" + string(ruleID) + ":" + hex.EncodeToString(sum[:])), nil
}

func findingEvidence(edge graph.Edge) FindingEvidence {
	return FindingEvidence{
		EdgeID: edge.ID,
		Kind:   edge.Kind,
		Source: edge.Evidence,
	}
}

func cloneFindingEvidence(evidence []FindingEvidence) []FindingEvidence {
	if evidence == nil {
		return nil
	}
	return append([]FindingEvidence(nil), evidence...)
}

func sourceReferences(evidence []FindingEvidence) []string {
	refs := make([]string, 0, len(evidence))
	seen := make(map[string]struct{})
	for _, item := range evidence {
		ref := item.Source.Source
		if ref == "" {
			continue
		}
		if _, exists := seen[ref]; exists {
			continue
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}
	return refs
}
