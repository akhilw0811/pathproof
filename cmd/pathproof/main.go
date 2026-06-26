package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"pathproof/internal/analysis"
	"pathproof/internal/graph"
	parserkubernetes "pathproof/internal/parser/kubernetes"
	"pathproof/internal/patchpreview"
	"pathproof/internal/remediation"
	routingkubernetes "pathproof/internal/routing/kubernetes"
)

const version = "pathproof dev"
const usage = "Usage: pathproof version | pathproof scan [--format human|json] [--preview-patches] <directory>"

type scanFormat string

const (
	scanFormatHuman scanFormat = "human"
	scanFormatJSON  scanFormat = "json"
)

type scanOptions struct {
	format         scanFormat
	previewPatches bool
	directory      string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printError(stderr, "missing command; "+usage)
		return 2
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "version":
		if len(args) != 1 {
			printError(stderr, fmt.Sprintf("version accepts no arguments, got %q; %s", args[1:], usage))
			return 2
		}
		fmt.Fprintln(stdout, version)
		return 0
	default:
		printError(stderr, fmt.Sprintf("unknown command %q; %s", args[0], usage))
		return 2
	}
}

func runScan(args []string, stdout, stderr io.Writer) int {
	options, err := parseScanArgs(args)
	if err != nil {
		printError(stderr, err.Error())
		return 2
	}

	findings, g, err := scanDirectory(options.directory)
	if err != nil {
		printError(stderr, err.Error())
		return 2
	}

	return writeScanResult(findings, g, options.directory, options.format, options.previewPatches, stdout, stderr)
}

func writeScanResult(findings []analysis.Finding, g *graph.Graph, root string, format scanFormat, previewPatches bool, stdout, stderr io.Writer) int {
	plans, err := remediation.Build(g, findings)
	if err != nil {
		printError(stderr, "internal scan error: build remediation plans: "+err.Error())
		return 2
	}
	var previews []patchpreview.Preview
	if previewPatches {
		previews, err = patchpreview.Build(root, plans)
		if err != nil {
			printError(stderr, "internal scan error: build patch previews: "+err.Error())
			return 2
		}
	}
	report, err := newScanReport(findings, g, plans, previews)
	if err != nil {
		printError(stderr, "internal scan error: "+err.Error())
		return 2
	}

	var output bytes.Buffer
	switch format {
	case scanFormatHuman:
		err = writeHumanReport(&output, report)
	case scanFormatJSON:
		err = writeJSONReport(&output, report)
	default:
		err = fmt.Errorf("unsupported format %q", format)
	}
	if err != nil {
		printError(stderr, "format scan report: "+err.Error())
		return 2
	}

	if err := writeAll(stdout, output.Bytes()); err != nil {
		printError(stderr, "write scan report: "+err.Error())
		return 2
	}

	if report.FindingCount > 0 {
		return 1
	}
	return 0
}

func parseScanArgs(args []string) (scanOptions, error) {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	formatValue := flags.String("format", string(scanFormatHuman), "output format")
	previewPatches := flags.Bool("preview-patches", false, "include read-only patch previews")
	if err := flags.Parse(args); err != nil {
		return scanOptions{}, fmt.Errorf("invalid scan arguments: %w; %s", err, usage)
	}
	format := scanFormat(*formatValue)
	switch format {
	case scanFormatHuman, scanFormatJSON:
	default:
		return scanOptions{}, fmt.Errorf("unsupported scan format %q; supported formats are human and json", format)
	}

	remaining := flags.Args()
	if len(remaining) != 1 {
		return scanOptions{}, fmt.Errorf("scan requires exactly one directory argument, got %d; %s", len(remaining), usage)
	}
	dir := remaining[0]
	info, err := os.Stat(dir)
	if err != nil {
		return scanOptions{}, fmt.Errorf("scan directory %q: %w", dir, err)
	}
	if !info.IsDir() {
		return scanOptions{}, fmt.Errorf("scan path %q is not a directory", dir)
	}
	return scanOptions{format: format, previewPatches: *previewPatches, directory: dir}, nil
}

func scanDirectory(dir string) ([]analysis.Finding, *graph.Graph, error) {
	resources, err := parserkubernetes.ParseDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("parse scan directory: %w", err)
	}
	g := graph.New()
	if err := routingkubernetes.AddRoutes(g, resources); err != nil {
		return nil, nil, fmt.Errorf("build scan graph: %w", err)
	}
	return analysis.Analyze(g), g, nil
}

type scanReport struct {
	Findings     []scanFinding `json:"findings"`
	FindingCount int           `json:"finding_count"`
}

type scanFinding struct {
	ID               analysis.FindingID `json:"id"`
	RuleID           analysis.RuleID    `json:"rule_id"`
	Title            string             `json:"title"`
	Severity         analysis.Severity  `json:"severity"`
	Summary          string             `json:"summary"`
	Path             []scanPathNode     `json:"path"`
	Evidence         []scanEvidence     `json:"evidence"`
	SourceReferences []string           `json:"source_references"`
	Remediation      *scanRemediation   `json:"remediation,omitempty"`
}

type scanPathNode struct {
	ID   graph.NodeID   `json:"id"`
	Kind graph.NodeKind `json:"kind"`
	Name string         `json:"name"`
}

type scanEvidence struct {
	EdgeID graph.EdgeID   `json:"edge_id"`
	Kind   graph.EdgeKind `json:"kind"`
	Source string         `json:"source"`
	Detail string         `json:"detail"`
}

type scanRemediation struct {
	ID        remediation.PlanID      `json:"id"`
	FindingID analysis.FindingID      `json:"finding_id"`
	RuleID    analysis.RuleID         `json:"rule_id"`
	Summary   string                  `json:"summary"`
	Options   []scanRemediationOption `json:"options"`
}

type scanRemediationOption struct {
	Priority           int                     `json:"priority"`
	Action             remediation.Action      `json:"action"`
	Summary            string                  `json:"summary"`
	Rationale          string                  `json:"rationale"`
	RequiresAllChanges bool                    `json:"requires_all_changes"`
	Changes            []scanRemediationChange `json:"changes"`
	Constraints        []string                `json:"constraints,omitempty"`
	PatchPreviews      []scanPatchPreview      `json:"patch_previews,omitempty"`
}

type scanRemediationChange struct {
	Action           remediation.Action    `json:"action"`
	Target           scanRemediationTarget `json:"target"`
	Summary          string                `json:"summary"`
	SourceReference  string                `json:"source_reference"`
	PermissionSHA256 string                `json:"permission_sha256,omitempty"`
	MatchedVerb      string                `json:"matched_verb,omitempty"`
	Subject          string                `json:"subject,omitempty"`
}

type scanRemediationTarget struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

type scanPatchPreview struct {
	PlanID       remediation.PlanID  `json:"plan_id"`
	OptionIndex  int                 `json:"option_index"`
	OptionAction remediation.Action  `json:"option_action"`
	ChangeIndex  int                 `json:"change_index"`
	Status       patchpreview.Status `json:"status"`
	Summary      string              `json:"summary"`
	File         string              `json:"file,omitempty"`
	Diff         string              `json:"diff,omitempty"`
	Reason       string              `json:"reason,omitempty"`
}

func newScanReport(findings []analysis.Finding, g *graph.Graph, plans []remediation.Plan, previews []patchpreview.Preview) (scanReport, error) {
	planByFinding := make(map[analysis.FindingID]remediation.Plan, len(plans))
	for _, plan := range plans {
		planByFinding[plan.FindingID] = plan
	}
	report := scanReport{
		Findings:     make([]scanFinding, 0, len(findings)),
		FindingCount: len(findings),
	}
	for _, finding := range findings {
		item, err := projectFinding(finding, g)
		if err != nil {
			return scanReport{}, err
		}
		if plan, ok := planByFinding[finding.ID]; ok {
			item.Remediation = projectRemediation(plan, previews)
		}
		report.Findings = append(report.Findings, item)
	}
	return report, nil
}

func projectFinding(finding analysis.Finding, g *graph.Graph) (scanFinding, error) {
	if g == nil {
		return scanFinding{}, fmt.Errorf("finding %q cannot be projected without a graph", finding.ID)
	}
	if len(finding.NodeIDs) != 4 {
		return scanFinding{}, fmt.Errorf("finding %q has %d path nodes, want 4", finding.ID, len(finding.NodeIDs))
	}
	if len(finding.EdgeIDs) != len(finding.NodeIDs)-1 {
		return scanFinding{}, fmt.Errorf("finding %q has edge count %d, want %d for %d path nodes", finding.ID, len(finding.EdgeIDs), len(finding.NodeIDs)-1, len(finding.NodeIDs))
	}
	if len(finding.EdgeIDs) != len(finding.Evidence) {
		return scanFinding{}, fmt.Errorf("finding %q has %d edge IDs but %d evidence entries", finding.ID, len(finding.EdgeIDs), len(finding.Evidence))
	}
	if len(finding.Evidence) != 3 {
		return scanFinding{}, fmt.Errorf("finding %q has %d evidence entries, want 3", finding.ID, len(finding.Evidence))
	}

	path := make([]scanPathNode, 0, len(finding.NodeIDs))
	for _, nodeID := range finding.NodeIDs {
		node, ok := g.Node(nodeID)
		if !ok {
			return scanFinding{}, fmt.Errorf("finding %q references missing node %q", finding.ID, nodeID)
		}
		path = append(path, scanPathNode{
			ID:   node.ID,
			Kind: node.Kind,
			Name: node.Name,
		})
	}

	evidence := make([]scanEvidence, 0, len(finding.Evidence))
	for i, item := range finding.Evidence {
		if item.EdgeID != finding.EdgeIDs[i] {
			return scanFinding{}, fmt.Errorf("finding %q evidence %d references edge %q, want %q", finding.ID, i, item.EdgeID, finding.EdgeIDs[i])
		}
		edge, ok := g.Edge(item.EdgeID)
		if !ok {
			return scanFinding{}, fmt.Errorf("finding %q references missing edge %q", finding.ID, item.EdgeID)
		}
		if edge.Kind != item.Kind || edge.Evidence != item.Source {
			return scanFinding{}, fmt.Errorf("finding %q evidence %d does not match graph edge %q", finding.ID, i, item.EdgeID)
		}
		if edge.From != finding.NodeIDs[i] || edge.To != finding.NodeIDs[i+1] {
			return scanFinding{}, fmt.Errorf("inconsistent finding projection %q: edge %q connects %q -> %q, want %q -> %q", finding.ID, item.EdgeID, edge.From, edge.To, finding.NodeIDs[i], finding.NodeIDs[i+1])
		}
		evidence = append(evidence, scanEvidence{
			EdgeID: item.EdgeID,
			Kind:   item.Kind,
			Source: item.Source.Source,
			Detail: item.Source.Detail,
		})
	}

	return scanFinding{
		ID:               finding.ID,
		RuleID:           finding.RuleID,
		Title:            finding.Title,
		Severity:         finding.Severity,
		Summary:          finding.Summary,
		Path:             path,
		Evidence:         evidence,
		SourceReferences: append([]string(nil), finding.SourceReferences...),
	}, nil
}

func projectRemediation(plan remediation.Plan, previews []patchpreview.Preview) *scanRemediation {
	projected := scanRemediation{
		ID:        plan.ID,
		FindingID: plan.FindingID,
		RuleID:    plan.RuleID,
		Summary:   plan.Summary,
		Options:   make([]scanRemediationOption, 0, len(plan.Options)),
	}
	for _, option := range plan.Options {
		projectedOption := scanRemediationOption{
			Priority:           option.Priority,
			Action:             option.Action,
			Summary:            option.Summary,
			Rationale:          option.Rationale,
			RequiresAllChanges: option.RequiresAllChanges,
			Constraints:        append([]string(nil), option.Constraints...),
			Changes:            make([]scanRemediationChange, 0, len(option.Changes)),
		}
		for _, preview := range previews {
			if preview.PlanID != plan.ID || preview.OptionIndex != len(projected.Options) {
				continue
			}
			projectedOption.PatchPreviews = append(projectedOption.PatchPreviews, scanPatchPreview{
				PlanID:       preview.PlanID,
				OptionIndex:  preview.OptionIndex,
				OptionAction: preview.OptionAction,
				ChangeIndex:  preview.ChangeIndex,
				Status:       preview.Status,
				Summary:      preview.Summary,
				File:         preview.File,
				Diff:         preview.Diff,
				Reason:       preview.Reason,
			})
		}
		for _, change := range option.Changes {
			projectedOption.Changes = append(projectedOption.Changes, scanRemediationChange{
				Action: change.Action,
				Target: scanRemediationTarget{
					Kind:      change.Target.Kind,
					Namespace: change.Target.Namespace,
					Name:      change.Target.Name,
				},
				Summary:          change.Summary,
				SourceReference:  change.SourceReference,
				PermissionSHA256: change.PermissionSHA256,
				MatchedVerb:      change.MatchedVerb,
				Subject:          change.Subject,
			})
		}
		projected.Options = append(projected.Options, projectedOption)
	}
	return &projected
}

func writeHumanReport(w io.Writer, report scanReport) error {
	if _, err := fmt.Fprintf(w, "Finding count: %d\n", report.FindingCount); err != nil {
		return err
	}
	if report.FindingCount == 0 {
		_, err := fmt.Fprintln(w, "No findings.")
		return err
	}
	for _, finding := range report.Findings {
		if _, err := fmt.Fprintf(w, "\nFinding: %s\n", finding.ID); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "Rule: %s\n", finding.RuleID); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "Title: %s\n", finding.Title); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "Severity: %s\n", finding.Severity); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "Path:"); err != nil {
			return err
		}
		for j, node := range finding.Path {
			if _, err := fmt.Fprintf(w, "  %d. %s %s (%s)\n", j+1, node.Kind, node.Name, node.ID); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w, "Evidence:"); err != nil {
			return err
		}
		for _, evidence := range finding.Evidence {
			if _, err := fmt.Fprintf(w, "  - %s %s: %s [%s]\n", evidence.Kind, evidence.EdgeID, evidence.Detail, evidence.Source); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w, "Sources:"); err != nil {
			return err
		}
		for _, source := range finding.SourceReferences {
			if _, err := fmt.Fprintf(w, "  - %s\n", source); err != nil {
				return err
			}
		}
		if finding.Remediation != nil {
			if _, err := fmt.Fprintln(w, "Remediation:"); err != nil {
				return err
			}
			for i, option := range finding.Remediation.Options {
				if _, err := fmt.Fprintf(w, "  Option %d: %s (priority %d)\n", i+1, option.Action, option.Priority); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(w, "    Summary: %s\n", option.Summary); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(w, "    Rationale: %s\n", option.Rationale); err != nil {
					return err
				}
				if option.RequiresAllChanges {
					if _, err := fmt.Fprintln(w, "    All listed changes in this option must be applied together."); err != nil {
						return err
					}
				}
				if _, err := fmt.Fprintln(w, "    Changes:"); err != nil {
					return err
				}
				for changeIndex, change := range option.Changes {
					if _, err := fmt.Fprintf(w, "      - %s %s: %s [%s]\n", change.Action, remediationTargetName(change.Target), change.Summary, change.SourceReference); err != nil {
						return err
					}
					if change.PermissionSHA256 != "" || change.MatchedVerb != "" || change.Subject != "" {
						if _, err := fmt.Fprintf(w, "        Parameters: permission_sha256=%s matched_verb=%s subject=%s\n", change.PermissionSHA256, change.MatchedVerb, change.Subject); err != nil {
							return err
						}
					}
					for _, preview := range option.PatchPreviews {
						if preview.ChangeIndex != changeIndex {
							continue
						}
						if _, err := fmt.Fprintln(w, "        Patch Preview:"); err != nil {
							return err
						}
						if _, err := fmt.Fprintf(w, "          Status: %s\n", preview.Status); err != nil {
							return err
						}
						if preview.File != "" {
							if _, err := fmt.Fprintf(w, "          File: %s\n", preview.File); err != nil {
								return err
							}
						}
						if preview.Reason != "" {
							if _, err := fmt.Fprintf(w, "          Reason: %s\n", preview.Reason); err != nil {
								return err
							}
						}
						if preview.Diff != "" {
							if _, err := fmt.Fprintln(w, "          Diff:"); err != nil {
								return err
							}
							if _, err := fmt.Fprint(w, indentPreviewDiff(preview.Diff)); err != nil {
								return err
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func indentPreviewDiff(diff string) string {
	if diff == "" {
		return ""
	}
	lines := strings.SplitAfter(diff, "\n")
	var out strings.Builder
	for _, line := range lines {
		if line == "" {
			continue
		}
		out.WriteString("            ")
		out.WriteString(line)
	}
	return out.String()
}

func remediationTargetName(target scanRemediationTarget) string {
	if target.Namespace == "" {
		return target.Kind + " " + target.Name
	}
	return target.Kind + " " + target.Namespace + "/" + target.Name
}

func writeJSONReport(w io.Writer, report scanReport) error {
	encoder := json.NewEncoder(w)
	return encoder.Encode(report)
}

func writeAll(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func printError(w io.Writer, message string) {
	message = strings.TrimSpace(strings.ReplaceAll(message, "\n", " "))
	if message == "" {
		message = "error"
	}
	fmt.Fprintln(w, message)
}
