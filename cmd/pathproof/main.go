package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"pathproof/internal/analysis"
	"pathproof/internal/graph"
	parsergithubactions "pathproof/internal/parser/githubactions"
	parserkubernetes "pathproof/internal/parser/kubernetes"
	parserterraform "pathproof/internal/parser/terraform"
	"pathproof/internal/patchpreview"
	"pathproof/internal/remediation"
	routinggithubactions "pathproof/internal/routing/githubactions"
	routingkubernetes "pathproof/internal/routing/kubernetes"
	routingterraform "pathproof/internal/routing/terraform"
	"pathproof/internal/validation"
)

const version = "pathproof dev"
const usage = "Usage: pathproof version | pathproof scan [--format human|json|sarif] [--repo OWNER/REPO] [--preview-patches] [--write-patches <output-directory>] [--validate-patches] <directory>"

type scanFormat string

const (
	scanFormatHuman scanFormat = "human"
	scanFormatJSON  scanFormat = "json"
	scanFormatSARIF scanFormat = "sarif"
)

type scanOptions struct {
	format          scanFormat
	previewPatches  bool
	writePatches    string
	validatePatches bool
	repo            string
	directory       string
}

var scanValidationDirectory = scanDirectory

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

	findings, g, err := scanDirectoryWithRepo(options.directory, options.repo)
	if err != nil {
		printError(stderr, err.Error())
		return 2
	}

	return writeScanResult(findings, g, options.directory, options.format, options.previewPatches, options.writePatches, options.validatePatches, stdout, stderr)
}

func writeScanResult(findings []analysis.Finding, g *graph.Graph, root string, format scanFormat, previewPatches bool, writePatches string, validatePatches bool, stdout, stderr io.Writer) int {
	plans, err := remediation.Build(g, findings)
	if err != nil {
		printError(stderr, "internal scan error: build remediation plans: "+err.Error())
		return 2
	}
	var reportPreviews []patchpreview.Preview
	var patchOutputs []patchpreview.WrittenFile
	var validationResults []validation.Result
	includePatchOutputs := writePatches != ""
	if writePatches != "" {
		var writePreviews []patchpreview.Preview
		patchOutputs, writePreviews, err = patchpreview.Write(root, writePatches, plans)
		if err != nil {
			printError(stderr, "write patch output: "+err.Error())
			return 2
		}
		if previewPatches {
			reportPreviews = writePreviews
		}
		if validatePatches {
			validationResults, err = validatePatchOutput(root, writePatches, findings, plans, writePreviews, patchOutputs)
			if err != nil {
				printError(stderr, "validate patch output: "+err.Error())
				return 2
			}
		}
	} else if previewPatches {
		reportPreviews, err = patchpreview.Build(root, plans)
		if err != nil {
			printError(stderr, "internal scan error: build patch previews: "+err.Error())
			return 2
		}
	}
	report, err := newScanReport(root, findings, g, plans, reportPreviews, patchOutputs, includePatchOutputs, validationResults)
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
	case scanFormatSARIF:
		err = writeSARIFReport(&output, root, report)
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
	repoValue := flags.String("repo", "", "repository identity for GitHub Actions OIDC trust matching, in OWNER/REPO form")
	previewPatches := flags.Bool("preview-patches", false, "include read-only patch previews")
	writePatches := flags.String("write-patches", "", "write patched copies to an output directory")
	validatePatches := flags.Bool("validate-patches", false, "rescan a temporary patched manifest set after writing patches")
	if err := flags.Parse(args); err != nil {
		return scanOptions{}, fmt.Errorf("invalid scan arguments: %w; %s", err, usage)
	}
	writePatchesSet := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "write-patches" {
			writePatchesSet = true
		}
	})
	format := scanFormat(*formatValue)
	switch format {
	case scanFormatHuman, scanFormatJSON, scanFormatSARIF:
	default:
		return scanOptions{}, fmt.Errorf("unsupported scan format %q; supported formats are human, json, and sarif", format)
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
	if writePatchesSet {
		if err := patchpreview.ValidateOutputRoot(dir, *writePatches); err != nil {
			return scanOptions{}, err
		}
	}
	writePatchesValue := ""
	if writePatchesSet {
		writePatchesValue = *writePatches
	}
	if *validatePatches && !writePatchesSet {
		return scanOptions{}, fmt.Errorf("--validate-patches requires --write-patches")
	}
	repo := *repoValue
	if repo != "" {
		if err := validateRepoIdentity(repo); err != nil {
			return scanOptions{}, err
		}
	}
	return scanOptions{format: format, previewPatches: *previewPatches, writePatches: writePatchesValue, validatePatches: *validatePatches, repo: repo, directory: dir}, nil
}

func scanDirectory(dir string) ([]analysis.Finding, *graph.Graph, error) {
	return scanDirectoryWithRepo(dir, "")
}

func scanDirectoryWithRepo(dir, repo string) ([]analysis.Finding, *graph.Graph, error) {
	resources, err := parserkubernetes.ParseDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("parse scan directory: %w", err)
	}
	workflows, err := parsergithubactions.ParseDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("parse scan directory: %w", err)
	}
	terraformResources, err := parserterraform.ParseDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("parse scan directory: %w", err)
	}
	g := graph.New()
	if err := routingkubernetes.AddRoutes(g, resources); err != nil {
		return nil, nil, fmt.Errorf("build scan graph: %w", err)
	}
	if err := routinggithubactions.AddRoutes(g, workflows); err != nil {
		return nil, nil, fmt.Errorf("build scan graph: %w", err)
	}
	if err := routingterraform.AddRoutes(g, terraformResources, workflows, repo); err != nil {
		return nil, nil, fmt.Errorf("build scan graph: %w", err)
	}
	return analysis.Analyze(g), g, nil
}

func validateRepoIdentity(repo string) error {
	parts := strings.Split(repo, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("invalid --repo %q: expected OWNER/REPO", repo)
	}
	for _, part := range parts {
		for _, r := range part {
			if unicode.IsSpace(r) || unicode.IsControl(r) || r == '*' || r == ':' || r == '/' || r == '\\' {
				return fmt.Errorf("invalid --repo %q: OWNER and REPO must not contain whitespace, control characters, '*', ':', or extra slashes", repo)
			}
		}
	}
	return nil
}

func validatePatchOutput(root, outputRoot string, findings []analysis.Finding, plans []remediation.Plan, previews []patchpreview.Preview, patchOutputs []patchpreview.WrittenFile) ([]validation.Result, error) {
	patchedFindingIDs := patchedFindingIDsByGeneratedOutput(plans, previews, patchOutputs)
	if len(patchedFindingIDs) == 0 {
		return validation.ValidatePatchedOutput(findings, nil, patchedFindingIDs), nil
	}

	overlay, cleanup, err := createValidationOverlay(root, outputRoot, patchOutputs)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	patchedFindings, _, err := scanValidationDirectory(overlay)
	if err != nil {
		return nil, fmt.Errorf("scan patched manifest set: %s", sanitizeValidationError(err, overlay))
	}
	return validation.ValidatePatchedOutput(findings, patchedFindings, patchedFindingIDs), nil
}

func patchedFindingIDsByGeneratedOutput(plans []remediation.Plan, previews []patchpreview.Preview, patchOutputs []patchpreview.WrittenFile) map[analysis.FindingID]bool {
	generatedSources := make(map[string]struct{})
	for _, output := range patchOutputs {
		if output.PreviewStatus != patchpreview.StatusGenerated || output.Source == "" {
			continue
		}
		generatedSources[output.Source] = struct{}{}
	}
	if len(generatedSources) == 0 {
		return nil
	}

	findingByPlanID := make(map[remediation.PlanID]analysis.FindingID, len(plans))
	for _, plan := range plans {
		findingByPlanID[plan.ID] = plan.FindingID
	}

	patched := make(map[analysis.FindingID]bool)
	for _, preview := range previews {
		if preview.Status != patchpreview.StatusGenerated || preview.File == "" {
			continue
		}
		if _, ok := generatedSources[preview.File]; !ok {
			continue
		}
		findingID, ok := findingByPlanID[preview.PlanID]
		if !ok {
			continue
		}
		patched[findingID] = true
	}
	return patched
}

func createValidationOverlay(root, outputRoot string, patchOutputs []patchpreview.WrittenFile) (string, func(), error) {
	overlay, err := os.MkdirTemp("", "pathproof-validation-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temporary validation directory")
	}
	cleanup := func() {
		_ = os.RemoveAll(overlay)
	}

	generatedOutputBySource := make(map[string]string)
	for _, output := range patchOutputs {
		if output.PreviewStatus != patchpreview.StatusGenerated || output.Source == "" {
			continue
		}
		if !isSafeRelativePath(output.Source) {
			cleanup()
			return "", nil, fmt.Errorf("prepare validation overlay")
		}
		generatedOutputBySource[output.Source] = filepath.Join(outputRoot, filepath.FromSlash(output.Source))
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("read scan directory for validation")
	}
	copied := make(map[string]struct{})
	for _, entry := range entries {
		if entry.IsDir() || !isYAMLFile(entry.Name()) {
			continue
		}
		rel := filepath.ToSlash(entry.Name())
		sourcePath := filepath.Join(root, entry.Name())
		if patchedPath, ok := generatedOutputBySource[rel]; ok {
			sourcePath = patchedPath
		}
		content, err := os.ReadFile(sourcePath)
		if err != nil {
			cleanup()
			return "", nil, fmt.Errorf("read validation manifest")
		}
		if err := os.WriteFile(filepath.Join(overlay, entry.Name()), content, 0o600); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("write validation manifest")
		}
		copied[rel] = struct{}{}
	}
	for source := range generatedOutputBySource {
		if _, ok := copied[source]; !ok {
			cleanup()
			return "", nil, fmt.Errorf("generated patch output does not match a scanned manifest")
		}
	}

	return overlay, cleanup, nil
}

func isYAMLFile(name string) bool {
	ext := filepath.Ext(name)
	return ext == ".yaml" || ext == ".yml"
}

func isSafeRelativePath(value string) bool {
	if value == "" || filepath.IsAbs(value) {
		return false
	}
	clean := filepath.Clean(filepath.FromSlash(value))
	return clean != "." && clean != ".." && !strings.HasPrefix(clean, ".."+string(filepath.Separator))
}

func sanitizeValidationError(err error, overlay string) string {
	message := strings.TrimSpace(strings.ReplaceAll(err.Error(), "\n", " "))
	if overlay != "" {
		message = strings.ReplaceAll(message, overlay, "validation-overlay")
	}
	if message == "" {
		return "validation scan failed"
	}
	return message
}

type scanReport struct {
	Findings     []scanFinding       `json:"findings"`
	FindingCount int                 `json:"finding_count"`
	PatchOutputs *[]scanPatchOutput  `json:"patch_outputs,omitempty"`
	Validation   []validation.Result `json:"validation,omitempty"`
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
	RiskSignal       *scanRiskSignal    `json:"risk_signal,omitempty"`
	Remediation      *scanRemediation   `json:"remediation,omitempty"`
	SARIFSources     []string           `json:"-"`
}

type scanRiskSignal struct {
	RuleID          analysis.RuleID             `json:"rule_id"`
	SourceReference string                      `json:"source_reference"`
	WorkflowFile    string                      `json:"workflow_file"`
	JobID           string                      `json:"job_id,omitempty"`
	StepIndex       *int                        `json:"step_index,omitempty"`
	Selectors       []scanGitHubActionsSelector `json:"selectors,omitempty"`
	Permission      string                      `json:"permission,omitempty"`
	Access          string                      `json:"access,omitempty"`
	Summary         string                      `json:"summary"`
}

type scanGitHubActionsSelector struct {
	Field             string `json:"field"`
	MatchedExpression string `json:"matched_expression"`
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

type scanPatchOutput struct {
	Source string              `json:"source"`
	Output string              `json:"output,omitempty"`
	Status patchpreview.Status `json:"status"`
	Reason string              `json:"reason,omitempty"`
}

func newScanReport(root string, findings []analysis.Finding, g *graph.Graph, plans []remediation.Plan, previews []patchpreview.Preview, patchOutputs []patchpreview.WrittenFile, includePatchOutputs bool, validationResults []validation.Result) (scanReport, error) {
	planByFinding := make(map[analysis.FindingID]remediation.Plan, len(plans))
	for _, plan := range plans {
		planByFinding[plan.FindingID] = plan
	}
	report := scanReport{
		Findings:     make([]scanFinding, 0, len(findings)),
		FindingCount: len(findings),
		Validation:   append([]validation.Result(nil), validationResults...),
	}
	for _, finding := range findings {
		item, err := projectFinding(root, finding, g)
		if err != nil {
			return scanReport{}, err
		}
		if plan, ok := planByFinding[finding.ID]; ok {
			item.Remediation = projectRemediation(root, plan, previews)
		}
		report.Findings = append(report.Findings, item)
	}
	if includePatchOutputs {
		outputs := make([]scanPatchOutput, 0, len(patchOutputs))
		for _, output := range patchOutputs {
			outputs = append(outputs, scanPatchOutput{
				Source: output.Source,
				Output: output.Output,
				Status: output.PreviewStatus,
				Reason: output.Reason,
			})
		}
		report.PatchOutputs = &outputs
	}
	return report, nil
}

func projectFinding(root string, finding analysis.Finding, g *graph.Graph) (scanFinding, error) {
	if g == nil {
		return scanFinding{}, fmt.Errorf("finding %q cannot be projected without a graph", finding.ID)
	}
	if len(finding.NodeIDs) == 0 {
		return scanFinding{}, fmt.Errorf("finding %q has 0 path nodes, want at least 1", finding.ID)
	}
	if len(finding.NodeIDs) == 1 && len(finding.EdgeIDs) != 0 {
		return scanFinding{}, fmt.Errorf("finding %q has one path node and edge count %d, want 0", finding.ID, len(finding.EdgeIDs))
	}
	if len(finding.NodeIDs) > 1 && len(finding.EdgeIDs) != len(finding.NodeIDs)-1 {
		return scanFinding{}, fmt.Errorf("finding %q has edge count %d, want %d for %d path nodes", finding.ID, len(finding.EdgeIDs), len(finding.NodeIDs)-1, len(finding.NodeIDs))
	}
	if len(finding.EdgeIDs) != len(finding.Evidence) {
		return scanFinding{}, fmt.Errorf("finding %q has %d edge IDs but %d evidence entries", finding.ID, len(finding.EdgeIDs), len(finding.Evidence))
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
			Source: normalizeDisplaySourceReferences(root, item.Source.Source),
			Detail: normalizeDisplaySourceReferences(root, item.Source.Detail),
		})
	}

	sourceReferences := make([]string, 0, len(finding.SourceReferences))
	for _, source := range finding.SourceReferences {
		sourceReferences = append(sourceReferences, normalizeDisplaySourceReferences(root, source))
	}
	sarifSources := structuredFindingSourceReferences(finding, g)
	riskSignal := projectRiskSignal(root, finding.RiskSignal)

	return scanFinding{
		ID:               finding.ID,
		RuleID:           finding.RuleID,
		Title:            finding.Title,
		Severity:         finding.Severity,
		Summary:          finding.Summary,
		Path:             path,
		Evidence:         evidence,
		SourceReferences: sourceReferences,
		RiskSignal:       riskSignal,
		SARIFSources:     sarifSources,
	}, nil
}

func projectRiskSignal(root string, risk *analysis.RiskSignal) *scanRiskSignal {
	if risk == nil {
		return nil
	}
	selectors := make([]scanGitHubActionsSelector, 0, len(risk.Selectors))
	for _, selector := range risk.Selectors {
		selectors = append(selectors, scanGitHubActionsSelector{
			Field:             selector.Field,
			MatchedExpression: selector.MatchedExpression,
		})
	}
	return &scanRiskSignal{
		RuleID:          risk.RuleID,
		SourceReference: normalizeDisplaySourceReferences(root, risk.SourceReference),
		WorkflowFile:    risk.WorkflowFile,
		JobID:           risk.JobID,
		StepIndex:       cloneIntPointer(risk.StepIndex),
		Selectors:       selectors,
		Permission:      risk.Permission,
		Access:          risk.Access,
		Summary:         risk.Summary,
	}
}

func cloneIntPointer(value *int) *int {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func structuredFindingSourceReferences(finding analysis.Finding, g *graph.Graph) []string {
	seen := make(map[string]struct{})
	refs := make([]string, 0)
	add := func(value string) {
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		refs = append(refs, value)
	}
	for _, nodeID := range finding.NodeIDs {
		node, ok := g.Node(nodeID)
		if !ok {
			continue
		}
		for _, evidence := range node.Evidence {
			add(evidence.Source)
		}
	}
	for _, edgeID := range finding.EdgeIDs {
		edge, ok := g.Edge(edgeID)
		if !ok {
			continue
		}
		add(edge.Evidence.Source)
		if edge.Metadata == nil {
			continue
		}
		for _, authorization := range edge.Metadata.KubernetesCanReadAuthorizations {
			add(authorization.BindingSourceReference)
			add(authorization.RoleSourceReference)
			for _, source := range authorization.SecretSourceReferences {
				add(source)
			}
		}
	}
	return refs
}

func projectRemediation(root string, plan remediation.Plan, previews []patchpreview.Preview) *scanRemediation {
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
				SourceReference:  normalizeDisplaySourceReferences(root, change.SourceReference),
				PermissionSHA256: change.PermissionSHA256,
				MatchedVerb:      change.MatchedVerb,
				Subject:          change.Subject,
			})
		}
		projected.Options = append(projected.Options, projectedOption)
	}
	return &projected
}

func normalizeDisplaySourceReferences(root, value string) string {
	if root == "" || value == "" || (!strings.Contains(value, "#document=") && !strings.Contains(value, "#resource=")) {
		return value
	}
	if normalized := normalizeDisplaySourceReference(root, value); normalized != value {
		return normalized
	}
	var out strings.Builder
	offset := 0
	for {
		index := strings.Index(value[offset:], "#document=")
		if index < 0 {
			out.WriteString(value[offset:])
			break
		}
		hash := offset + index
		end := sourceReferenceEnd(value, hash+len("#document="))
		start, normalized, ok := normalizeEmbeddedSourceReference(root, value[offset:end], hash-offset)
		if !ok {
			out.WriteString(value[offset:end])
			offset = end
			continue
		}
		out.WriteString(value[offset : offset+start])
		out.WriteString(normalized)
		offset = end
	}
	return out.String()
}

func sourceReferenceEnd(value string, start int) int {
	end := start
	for end < len(value) && !isSourceReferenceEndDelimiter(value[end]) {
		end++
	}
	return end
}

func isSourceReferenceEndDelimiter(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '[', ']', '(', ')', ';', ',':
		return true
	default:
		return false
	}
}

func normalizeEmbeddedSourceReference(root, value string, hash int) (int, string, bool) {
	for start := 0; start < hash; start++ {
		if start > 0 && !isPotentialSourceReferenceStart(value[start-1]) {
			continue
		}
		candidate := value[start:]
		normalized := normalizeDisplaySourceReference(root, candidate)
		if normalized != candidate {
			return start, normalized, true
		}
	}
	return 0, "", false
}

func isPotentialSourceReferenceStart(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '[', '(', ';', ',', '=':
		return true
	default:
		return false
	}
}

func normalizeDisplaySourceReference(root, value string) string {
	index := strings.LastIndex(value, "#document=")
	marker := "#document="
	if index < 0 {
		index = strings.LastIndex(value, "#resource=")
		marker = "#resource="
	}
	if index < 0 {
		return value
	}
	filename := value[:index]
	referenceValue := value[index+len(marker):]
	if filename == "" || referenceValue == "" || strings.Contains(referenceValue, "#") {
		return value
	}
	switch marker {
	case "#document=":
		for _, r := range referenceValue {
			if r < '0' || r > '9' {
				return value
			}
		}
		documentIndex, err := strconv.Atoi(referenceValue)
		if err != nil || documentIndex <= 0 {
			return value
		}
	case "#resource=":
		for _, r := range referenceValue {
			if r <= 0x20 || r == 0x7f || r == '/' || r == '\\' {
				return value
			}
		}
	}
	rel, ok := displayRelativeSourcePath(root, filename)
	if !ok {
		return value
	}
	return rel + marker + referenceValue
}

func displayRelativeSourcePath(root, filename string) (string, bool) {
	realRoot, err := filepath.EvalSymlinks(absClean(root))
	if err != nil {
		return "", false
	}
	candidates := []string{filepath.Clean(filename)}
	if !filepath.IsAbs(candidates[0]) {
		if candidates[0] == "." || candidates[0] == ".." || strings.HasPrefix(candidates[0], ".."+string(filepath.Separator)) {
			return "", false
		}
		candidates = append(candidates, filepath.Join(root, candidates[0]))
	}
	for _, candidate := range candidates {
		realCandidate, err := filepath.EvalSymlinks(absClean(candidate))
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(filepath.Clean(realRoot), filepath.Clean(realCandidate))
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		return filepath.ToSlash(filepath.Clean(rel)), true
	}
	return "", false
}

func absClean(path string) string {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return filepath.Clean(absPath)
}

func writeHumanReport(w io.Writer, report scanReport) error {
	if _, err := fmt.Fprintf(w, "Finding count: %d\n", report.FindingCount); err != nil {
		return err
	}
	if report.FindingCount == 0 {
		if _, err := fmt.Fprintln(w, "No findings."); err != nil {
			return err
		}
		if err := writeHumanPatchOutputs(w, report); err != nil {
			return err
		}
		return writeHumanValidation(w, report)
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
		if finding.Summary != "" {
			if _, err := fmt.Fprintf(w, "Summary: %s\n", finding.Summary); err != nil {
				return err
			}
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
	if err := writeHumanPatchOutputs(w, report); err != nil {
		return err
	}
	return writeHumanValidation(w, report)
}

func writeHumanPatchOutputs(w io.Writer, report scanReport) error {
	if report.PatchOutputs == nil {
		return nil
	}
	writtenCount := 0
	for _, output := range *report.PatchOutputs {
		if output.Status == patchpreview.StatusGenerated {
			writtenCount++
		}
	}
	if _, err := fmt.Fprintln(w, "\nPatch Output:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Written files: %d\n", writtenCount); err != nil {
		return err
	}
	for _, output := range *report.PatchOutputs {
		if _, err := fmt.Fprintf(w, "  - Status: %s\n", output.Status); err != nil {
			return err
		}
		if output.Source != "" {
			if _, err := fmt.Fprintf(w, "    Source: %s\n", output.Source); err != nil {
				return err
			}
		}
		if output.Output != "" {
			if _, err := fmt.Fprintf(w, "    Output: %s\n", output.Output); err != nil {
				return err
			}
		}
		if output.Reason != "" {
			if _, err := fmt.Fprintf(w, "    Reason: %s\n", output.Reason); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeHumanValidation(w io.Writer, report scanReport) error {
	if len(report.Validation) == 0 {
		return nil
	}
	if _, err := fmt.Fprintln(w, "\nValidation:"); err != nil {
		return err
	}
	for _, result := range report.Validation {
		if _, err := fmt.Fprintf(w, "Finding %s: %s\n", result.FindingID, result.Status); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "Summary: %s\n", result.Summary); err != nil {
			return err
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
