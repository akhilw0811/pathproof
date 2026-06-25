package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

type NodeKind string

const (
	PublicEndpoint NodeKind = "PublicEndpoint"
	Workload       NodeKind = "Workload"
	ServiceAccount NodeKind = "ServiceAccount"
	Role           NodeKind = "Role"
	Permission     NodeKind = "Permission"
	Secret         NodeKind = "Secret"
)

type NodeID string
type EdgeID string

type EdgeKind string

const (
	RoutesTo         EdgeKind = "RoutesTo"
	RunsAs           EdgeKind = "RunsAs"
	BoundTo          EdgeKind = "BoundTo"
	GrantsPermission EdgeKind = "GrantsPermission"
	CanRead          EdgeKind = "CanRead"
)

var (
	ErrInvalidNodeID   = errors.New("node ID does not match node identity")
	ErrInvalidEdgeID   = errors.New("edge ID does not match edge identity")
	ErrMissingEndpoint = errors.New("edge endpoint does not exist")
)

type Node struct {
	ID       NodeID           `json:"id"`
	Kind     NodeKind         `json:"kind"`
	Name     string           `json:"name"`
	Evidence []SourceEvidence `json:"evidence,omitempty"`
}

type SourceEvidence struct {
	Source string `json:"source"`
	Detail string `json:"detail"`
}

type Edge struct {
	ID       EdgeID         `json:"id"`
	Kind     EdgeKind       `json:"kind"`
	From     NodeID         `json:"from"`
	To       NodeID         `json:"to"`
	Evidence SourceEvidence `json:"evidence"`
}

type Graph struct {
	nodes    map[NodeID]Node
	edges    map[EdgeID]Edge
	outgoing map[NodeID]map[EdgeID]Edge
}

func New() *Graph {
	return &Graph{
		nodes:    make(map[NodeID]Node),
		edges:    make(map[EdgeID]Edge),
		outgoing: make(map[NodeID]map[EdgeID]Edge),
	}
}

func NewNode(kind NodeKind, name string) Node {
	return Node{
		ID:   nodeID(kind, name),
		Kind: kind,
		Name: name,
	}
}

func NewEdge(kind EdgeKind, from, to NodeID, evidence SourceEvidence) Edge {
	return Edge{
		ID:       edgeID(kind, from, to),
		Kind:     kind,
		From:     from,
		To:       to,
		Evidence: evidence,
	}
}

func (g *Graph) AddNode(node Node) (Node, error) {
	canonicalID := nodeID(node.Kind, node.Name)
	if node.ID == "" {
		node.ID = canonicalID
	} else if node.ID != canonicalID {
		return Node{}, fmt.Errorf("%w: got %q, want %q", ErrInvalidNodeID, node.ID, canonicalID)
	}

	if existing, ok := g.nodes[node.ID]; ok {
		return cloneNode(existing), nil
	}

	node = cloneNode(node)
	g.nodes[node.ID] = node
	return cloneNode(node), nil
}

func (g *Graph) Node(id NodeID) (Node, bool) {
	node, ok := g.nodes[id]
	if !ok {
		return Node{}, false
	}
	return cloneNode(node), true
}

func (g *Graph) Nodes() []Node {
	nodes := make([]Node, 0, len(g.nodes))
	for _, node := range g.nodes {
		nodes = append(nodes, cloneNode(node))
	}

	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].ID < nodes[j].ID
	})

	return nodes
}

func (g *Graph) AddEdge(edge Edge) (Edge, error) {
	if _, ok := g.nodes[edge.From]; !ok {
		return Edge{}, fmt.Errorf("%w: from %q", ErrMissingEndpoint, edge.From)
	}
	if _, ok := g.nodes[edge.To]; !ok {
		return Edge{}, fmt.Errorf("%w: to %q", ErrMissingEndpoint, edge.To)
	}

	canonicalID := edgeID(edge.Kind, edge.From, edge.To)
	if edge.ID == "" {
		edge.ID = canonicalID
	} else if edge.ID != canonicalID {
		return Edge{}, fmt.Errorf("%w: got %q, want %q", ErrInvalidEdgeID, edge.ID, canonicalID)
	}

	if existing, ok := g.edges[edge.ID]; ok {
		return existing, nil
	}

	g.edges[edge.ID] = edge
	if g.outgoing[edge.From] == nil {
		g.outgoing[edge.From] = make(map[EdgeID]Edge)
	}
	g.outgoing[edge.From][edge.ID] = edge

	return edge, nil
}

func (g *Graph) Edge(id EdgeID) (Edge, bool) {
	edge, ok := g.edges[id]
	return edge, ok
}

func (g *Graph) Edges() []Edge {
	edges := make([]Edge, 0, len(g.edges))
	for _, edge := range g.edges {
		edges = append(edges, edge)
	}

	sort.Slice(edges, func(i, j int) bool {
		return edges[i].ID < edges[j].ID
	})

	return edges
}

func (g *Graph) Outgoing(from NodeID) []Edge {
	edges := make([]Edge, 0, len(g.outgoing[from]))
	for _, edge := range g.outgoing[from] {
		edges = append(edges, edge)
	}

	sort.Slice(edges, func(i, j int) bool {
		return edges[i].ID < edges[j].ID
	})

	return edges
}

func (g *Graph) FindPath(from, to NodeID, maxDepth int) ([]Edge, bool) {
	if maxDepth < 0 {
		return nil, false
	}
	if _, ok := g.nodes[from]; !ok {
		return nil, false
	}
	if _, ok := g.nodes[to]; !ok {
		return nil, false
	}
	if from == to {
		return []Edge{}, true
	}

	type queuedPath struct {
		node NodeID
		path []Edge
	}

	queue := []queuedPath{{node: from}}
	visitedDepth := map[NodeID]int{from: 0}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if len(current.path) >= maxDepth {
			continue
		}

		for _, edge := range g.Outgoing(current.node) {
			nextDepth := len(current.path) + 1
			if previousDepth, seen := visitedDepth[edge.To]; seen && previousDepth <= nextDepth {
				continue
			}

			nextPath := append(append([]Edge(nil), current.path...), edge)
			if edge.To == to {
				return nextPath, true
			}

			visitedDepth[edge.To] = nextDepth
			queue = append(queue, queuedPath{node: edge.To, path: nextPath})
		}
	}

	return nil, false
}

func (g *Graph) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Nodes []Node `json:"nodes"`
		Edges []Edge `json:"edges"`
	}{
		Nodes: g.Nodes(),
		Edges: g.Edges(),
	})
}

func cloneNode(node Node) Node {
	node.Evidence = cloneEvidence(node.Evidence)
	return node
}

func cloneEvidence(evidence []SourceEvidence) []SourceEvidence {
	if evidence == nil {
		return nil
	}
	return append([]SourceEvidence(nil), evidence...)
}

func nodeID(kind NodeKind, name string) NodeID {
	return NodeID("node:" + string(kind) + ":" + stableHash("node", string(kind), name))
}

func edgeID(kind EdgeKind, from, to NodeID) EdgeID {
	return EdgeID("edge:" + string(kind) + ":" + stableHash("edge", string(kind), string(from), string(to)))
}

func stableHash(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write([]byte{0})
		hash.Write([]byte(part))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
