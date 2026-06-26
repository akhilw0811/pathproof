package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pathproof/internal/analysis"
	"pathproof/internal/graph"
)

type cliSARIFLog struct {
	Schema  string        `json:"$schema"`
	Version string        `json:"version"`
	Runs    []cliSARIFRun `json:"runs"`
}

type cliSARIFRun struct {
	Tool    cliSARIFTool     `json:"tool"`
	Results []cliSARIFResult `json:"results"`
}

type cliSARIFTool struct {
	Driver cliSARIFDriver `json:"driver"`
}

type cliSARIFDriver struct {
	Name  string         `json:"name"`
	Rules []cliSARIFRule `json:"rules"`
}

type cliSARIFRule struct {
	ID                   string                `json:"id"`
	Name                 string                `json:"name"`
	ShortDescription     cliSARIFMessage       `json:"shortDescription"`
	FullDescription      cliSARIFMessage       `json:"fullDescription"`
	DefaultConfiguration cliSARIFDefaultConfig `json:"defaultConfiguration"`
	Help                 cliSARIFMessage       `json:"help"`
}

type cliSARIFDefaultConfig struct {
	Level string `json:"level"`
}

type cliSARIFResult struct {
	RuleID              string             `json:"ruleId"`
	Level               string             `json:"level"`
	Message             cliSARIFMessage    `json:"message"`
	Locations           []cliSARIFLocation `json:"locations,omitempty"`
	PartialFingerprints map[string]string  `json:"partialFingerprints"`
	Properties          cliSARIFProperties `json:"properties"`
}

type cliSARIFMessage struct {
	Text string `json:"text"`
}

type cliSARIFLocation struct {
	PhysicalLocation cliSARIFPhysicalLocation `json:"physicalLocation"`
}

type cliSARIFPhysicalLocation struct {
	ArtifactLocation cliSARIFArtifactLocation `json:"artifactLocation"`
}

type cliSARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type cliSARIFProperties struct {
	FindingID        string   `json:"finding_id"`
	Severity         string   `json:"severity"`
	NodeIDs          []string `json:"node_ids"`
	EdgeIDs          []string `json:"edge_ids"`
	SourceReferences []string `json:"source_references"`
}

func TestRunScanAcceptsSARIFFormatForms(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "--format", "sarif", safeFixture},
		{"scan", "--format=sarif", safeFixture},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, stderr, code := runCommand(args...)

			assertCode(t, code, 0)
			assertString(t, "stderr", stderr, "")
			report := assertValidSARIFReport(t, stdout)
			if len(report.Runs) != 1 {
				t.Fatalf("runs len = %d, want 1", len(report.Runs))
			}
			if len(report.Runs[0].Results) != 0 {
				t.Fatalf("safe SARIF results = %#v, want none", report.Runs[0].Results)
			}
		})
	}
}

func TestRunScanSARIFOutputShapeAndFinding(t *testing.T) {
	stdout, stderr, code := runCommand("scan", "--format=sarif", vulnerableFixture)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidSARIFReport(t, stdout)
	assertString(t, "schema", report.Schema, sarifSchema)
	assertString(t, "version", report.Version, "2.1.0")
	if len(report.Runs) != 1 {
		t.Fatalf("runs len = %d, want 1", len(report.Runs))
	}
	run := report.Runs[0]
	assertString(t, "driver name", run.Tool.Driver.Name, "PathProof")
	if len(run.Tool.Driver.Rules) != 3 {
		t.Fatalf("rules len = %d, want 3", len(run.Tool.Driver.Rules))
	}
	rule := mustSARIFRule(t, run.Tool.Driver.Rules, "PP-K8S-001")
	assertString(t, "rule id", rule.ID, "PP-K8S-001")
	assertString(t, "rule name", rule.Name, "Public workload can read Kubernetes Secret")
	assertString(t, "rule short description", rule.ShortDescription.Text, "Public workload can read Kubernetes Secret")
	assertContains(t, rule.FullDescription.Text, "PublicEndpoint -> Workload -> ServiceAccount -> Secret")
	assertString(t, "rule default level", rule.DefaultConfiguration.Level, "error")
	assertContains(t, rule.Help.Text, "deterministic remediation plans")
	assertContains(t, rule.Help.Text, "NarrowBindingSubject")
	if len(run.Results) != 1 {
		t.Fatalf("results len = %d, want 1: %#v", len(run.Results), run.Results)
	}
	result := run.Results[0]
	assertString(t, "ruleId", result.RuleID, "PP-K8S-001")
	assertString(t, "level", result.Level, "error")
	assertContains(t, result.Message.Text, "PublicEndpoint kubernetes://prod/service/public-api")
	assertContains(t, result.Message.Text, "Workload kubernetes://prod/deployment/api")
	assertContains(t, result.Message.Text, "ServiceAccount kubernetes://prod/serviceaccount/api")
	assertContains(t, result.Message.Text, "Secret kubernetes://prod/secret/database-password")
	if strings.Contains(result.Message.Text, "binding_kind=") || strings.Contains(result.Message.Text, "Patch") {
		t.Fatalf("SARIF message contains evidence or patch text: %q", result.Message.Text)
	}
	if result.PartialFingerprints["pathproofFindingId"] == "" {
		t.Fatalf("partial fingerprints missing finding ID: %#v", result.PartialFingerprints)
	}
	if result.Properties.FindingID != result.PartialFingerprints["pathproofFindingId"] {
		t.Fatalf("finding_id = %q, fingerprint = %q", result.Properties.FindingID, result.PartialFingerprints["pathproofFindingId"])
	}
	assertString(t, "severity", result.Properties.Severity, "High")
	if len(result.Properties.NodeIDs) != 4 || len(result.Properties.EdgeIDs) != 3 {
		t.Fatalf("properties node_ids/edge_ids = %#v/%#v, want 4/3", result.Properties.NodeIDs, result.Properties.EdgeIDs)
	}
	if len(result.Locations) == 0 {
		t.Fatalf("SARIF locations are empty for source-backed vulnerable fixture: %#v", result)
	}
	if len(result.Properties.SourceReferences) == 0 {
		t.Fatalf("SARIF properties.source_references empty for source-backed vulnerable fixture: %#v", result.Properties)
	}
	for _, uri := range locationURIs(result.Locations) {
		if filepath.IsAbs(uri) || strings.Contains(uri, " ") || !strings.Contains(uri, "#document=") {
			t.Fatalf("SARIF artifact URI = %q, want relative URI-safe document reference", uri)
		}
	}
	assertExactlyOneTrailingNewline(t, stdout)
	assertDoesNotContainSecretPayloadFields(t, stdout, stderr)
}

func TestRunScanGitHubActionsSARIFOutputShapeAndFinding(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "build workflow.yml", `name: Build
env:
  TOKEN: FAKE_CLI_GHA_ENV_SECRET_DO_NOT_RETAIN
jobs:
  test:
    steps:
      - run: echo FAKE_CLI_GHA_RUN_SECRET_DO_NOT_RETAIN
      - name: Publish
        uses: owner/repo/path@v1.2.3
        with:
          token: FAKE_CLI_GHA_WITH_SECRET_DO_NOT_RETAIN
`)

	stdout, stderr, code := runCommand("scan", "--format=sarif", dir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidSARIFReport(t, stdout)
	run := report.Runs[0]
	if len(run.Tool.Driver.Rules) != 3 {
		t.Fatalf("rules len = %d, want 3", len(run.Tool.Driver.Rules))
	}
	rule := mustSARIFRule(t, run.Tool.Driver.Rules, "PP-GHA-001")
	assertString(t, "rule id", rule.ID, "PP-GHA-001")
	assertString(t, "rule name", rule.Name, "GitHub Actions workflow uses an action that is not pinned to a full commit SHA")
	assertContains(t, rule.FullDescription.Text, "uses:")
	assertContains(t, rule.FullDescription.Text, "40-character commit SHA")
	assertString(t, "rule default level", rule.DefaultConfiguration.Level, "warning")
	if strings.Contains(rule.Name+rule.ShortDescription.Text+rule.FullDescription.Text+rule.Help.Text, legacyGitHubActionsRuleWording()) {
		t.Fatalf("SARIF rule uses old inaccurate wording: %#v", rule)
	}
	if len(run.Results) != 1 {
		t.Fatalf("results len = %d, want 1: %#v", len(run.Results), run.Results)
	}
	result := run.Results[0]
	assertString(t, "ruleId", result.RuleID, "PP-GHA-001")
	assertString(t, "level", result.Level, "warning")
	assertContains(t, result.Message.Text, "Workflow githubactions://.github/workflows/build workflow.yml")
	assertContains(t, result.Message.Text, "GitHubAction githubactions://.github/workflows/build workflow.yml/job/test/step/1/action/owner/repo/path@v1.2.3")
	if result.PartialFingerprints["pathproofFindingId"] == "" || result.Properties.FindingID != result.PartialFingerprints["pathproofFindingId"] {
		t.Fatalf("finding fingerprint/properties mismatch: %#v", result)
	}
	assertString(t, "severity", result.Properties.Severity, "Medium")
	if len(result.Properties.NodeIDs) != 3 || len(result.Properties.EdgeIDs) != 2 {
		t.Fatalf("properties node_ids/edge_ids = %#v/%#v, want 3/2", result.Properties.NodeIDs, result.Properties.EdgeIDs)
	}
	gotURIs := locationURIs(result.Locations)
	wantURIs := []string{".github/workflows/build%20workflow.yml#document=1"}
	if !reflectDeepEqualStrings(gotURIs, wantURIs) {
		t.Fatalf("SARIF location URIs = %#v, want %#v", gotURIs, wantURIs)
	}
	wantDisplay := []string{".github/workflows/build workflow.yml#document=1"}
	if !reflectDeepEqualStrings(result.Properties.SourceReferences, wantDisplay) {
		t.Fatalf("SARIF source references = %#v, want %#v", result.Properties.SourceReferences, wantDisplay)
	}
	if strings.Contains(stdout, legacyGitHubActionsRuleWording()) {
		t.Fatalf("SARIF output contains old inaccurate wording: %s", stdout)
	}
	assertDoesNotContainGitHubActionsSecretValues(t, stdout, stderr)
}

func TestRunScanGitHubActionsUnsafeCheckoutSARIFOutputShapeAndFinding(t *testing.T) {
	dir := t.TempDir()
	writeGitHubActionsWorkflowForTest(t, dir, "unsafe workflow.yml", `name: Unsafe
on: pull_request_target
env:
  TOKEN: FAKE_CLI_GHA_ENV_SECRET_DO_NOT_RETAIN
jobs:
  test:
    steps:
      - run: echo FAKE_CLI_GHA_RUN_SECRET_DO_NOT_RETAIN
      - name: Checkout
        uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
        with:
          token: FAKE_CLI_GHA_WITH_SECRET_DO_NOT_RETAIN
          ref: ${{ github.event.pull_request.head.sha }}
`)

	stdout, stderr, code := runCommand("scan", "--format=sarif", dir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidSARIFReport(t, stdout)
	run := report.Runs[0]
	if len(run.Tool.Driver.Rules) != 3 {
		t.Fatalf("rules len = %d, want 3", len(run.Tool.Driver.Rules))
	}
	rule := mustSARIFRule(t, run.Tool.Driver.Rules, "PP-GHA-002")
	assertString(t, "rule id", rule.ID, "PP-GHA-002")
	assertString(t, "rule name", rule.Name, "pull_request_target workflow checks out untrusted pull request head code")
	assertContains(t, rule.FullDescription.Text, "pull_request_target")
	assertContains(t, rule.FullDescription.Text, "actions/checkout")
	assertString(t, "rule default level", rule.DefaultConfiguration.Level, "error")
	if len(run.Results) != 1 {
		t.Fatalf("results len = %d, want 1: %#v", len(run.Results), run.Results)
	}
	result := run.Results[0]
	assertString(t, "ruleId", result.RuleID, "PP-GHA-002")
	assertString(t, "level", result.Level, "error")
	assertContains(t, result.Message.Text, ".github/workflows/unsafe workflow.yml")
	assertContains(t, result.Message.Text, "job test step 1")
	assertContains(t, result.Message.Text, "actions/checkout@0123456789abcdef0123456789abcdef01234567")
	assertContains(t, result.Message.Text, "ref=github.event.pull_request.head.sha")
	if result.PartialFingerprints["pathproofFindingId"] == "" || result.Properties.FindingID != result.PartialFingerprints["pathproofFindingId"] {
		t.Fatalf("finding fingerprint/properties mismatch: %#v", result)
	}
	assertString(t, "severity", result.Properties.Severity, "High")
	if len(result.Properties.NodeIDs) != 3 || len(result.Properties.EdgeIDs) != 2 {
		t.Fatalf("properties node_ids/edge_ids = %#v/%#v, want 3/2", result.Properties.NodeIDs, result.Properties.EdgeIDs)
	}
	gotURIs := locationURIs(result.Locations)
	wantURIs := []string{".github/workflows/unsafe%20workflow.yml#document=1"}
	if !reflectDeepEqualStrings(gotURIs, wantURIs) {
		t.Fatalf("SARIF location URIs = %#v, want %#v", gotURIs, wantURIs)
	}
	if strings.Contains(stdout, "${{") {
		t.Fatalf("SARIF output contains raw expression: %s", stdout)
	}
	assertDoesNotContainGitHubActionsSecretValues(t, stdout, stderr)
}

func TestRunScanSARIFRealLocationsAndReferences(t *testing.T) {
	stdout, stderr, code := runCommand("scan", "--format=sarif", vulnerableFixture)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidSARIFReport(t, stdout)
	if len(report.Runs) != 1 || len(report.Runs[0].Results) != 1 {
		t.Fatalf("SARIF results = %#v, want one real finding", report.Runs)
	}
	result := report.Runs[0].Results[0]
	gotURIs := locationURIs(result.Locations)
	if len(gotURIs) == 0 {
		t.Fatal("real vulnerable scan SARIF locations are empty")
	}
	for _, uri := range gotURIs {
		if filepath.IsAbs(uri) {
			t.Fatalf("SARIF artifact URI is absolute: %q", uri)
		}
		if strings.Contains(uri, " ") {
			t.Fatalf("SARIF artifact URI is not URI-safe: %q", uri)
		}
		if !strings.HasPrefix(uri, "resources.yaml#document=") {
			t.Fatalf("SARIF artifact URI = %q, want resources.yaml document reference", uri)
		}
	}
	if len(result.Properties.SourceReferences) == 0 {
		t.Fatal("real vulnerable scan SARIF source references are empty")
	}
	for _, source := range result.Properties.SourceReferences {
		if filepath.IsAbs(source) {
			t.Fatalf("SARIF display source reference is absolute: %q", source)
		}
		if !strings.HasPrefix(source, "resources.yaml#document=") {
			t.Fatalf("SARIF display source reference = %q, want resources.yaml document reference", source)
		}
	}
	assertDoesNotContainSecretPayloadFields(t, stdout, stderr)
}

func TestRunScanSARIFDoesNotChangeHumanOrJSONOutput(t *testing.T) {
	humanStdout, humanStderr, humanCode := runCommand("scan", vulnerableFixture)
	jsonStdout, jsonStderr, jsonCode := runCommand("scan", "--format=json", safeFixture)
	_, _, sarifCode := runCommand("scan", "--format=sarif", vulnerableFixture)
	humanAgainStdout, humanAgainStderr, humanAgainCode := runCommand("scan", vulnerableFixture)
	jsonAgainStdout, jsonAgainStderr, jsonAgainCode := runCommand("scan", "--format=json", safeFixture)

	assertCode(t, humanCode, 1)
	assertCode(t, humanAgainCode, 1)
	assertCode(t, jsonCode, 0)
	assertCode(t, jsonAgainCode, 0)
	assertCode(t, sarifCode, 1)
	assertString(t, "human stderr", humanStderr, "")
	assertString(t, "human again stderr", humanAgainStderr, "")
	assertString(t, "human stdout", humanAgainStdout, humanStdout)
	assertString(t, "json stderr", jsonStderr, "")
	assertString(t, "json again stderr", jsonAgainStderr, "")
	assertString(t, "json stdout", jsonAgainStdout, jsonStdout)
	assertString(t, "safe json exact", jsonStdout, "{\"findings\":[],\"finding_count\":0}\n")
}

func TestRunScanSARIFOutputIsDeterministicAndExcludesSecretValues(t *testing.T) {
	firstOut, firstErr, firstCode := runCommand("scan", "--format=sarif", vulnerableFixture)
	secondOut, secondErr, secondCode := runCommand("scan", "--format=sarif", vulnerableFixture)

	assertCode(t, firstCode, 1)
	assertCode(t, secondCode, 1)
	assertString(t, "first stderr", firstErr, "")
	assertString(t, "second stderr", secondErr, "")
	assertString(t, "stdout", secondOut, firstOut)
	for _, value := range []string{
		"FAKE_CLI_SECRET_DATA_VALUE_DO_NOT_RETAIN",
		"FAKE_CLI_SECRET_STRINGDATA_VALUE_DO_NOT_RETAIN",
	} {
		if strings.Contains(firstOut, value) || strings.Contains(firstErr, value) {
			t.Fatalf("SARIF contains secret value %q\nstdout:%s\nstderr:%s", value, firstOut, firstErr)
		}
	}
}

func TestRunScanSARIFWithPatchFlagsKeepsStdoutFindingsOnly(t *testing.T) {
	parent := t.TempDir()
	writeSplitPreviewFixture(t, parent, "scan-preview")

	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=sarif", "--write-patches", "patched", "scan-preview")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertValidSARIFReport(t, stdout)
	if got := listDirNames(t, filepath.Join(parent, "patched")); !reflectDeepEqualStrings(got, []string{"rbac.yaml"}) {
		t.Fatalf("patched output entries = %#v, want only rbac.yaml", got)
	}
	assertSARIFOmitsPatchAndValidationText(t, stdout)

	originalScanValidationDirectory := scanValidationDirectory
	validationCalled := false
	scanValidationDirectory = func(dir string) ([]analysis.Finding, *graph.Graph, error) {
		validationCalled = true
		return originalScanValidationDirectory(dir)
	}
	defer func() {
		scanValidationDirectory = originalScanValidationDirectory
	}()

	stdout, stderr, code = runCommandInDir(t, parent, "scan", "--format=sarif", "--write-patches", "validated", "--validate-patches", "scan-preview")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertValidSARIFReport(t, stdout)
	if !validationCalled {
		t.Fatal("validation scan was not called")
	}
	assertSARIFOmitsPatchAndValidationText(t, stdout)
}

func TestSARIFSourceReferencesUseOnlyCleanStructuredFields(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	writeFileForTest(t, root, "resources file.yaml", "kind: ConfigMap\n")
	writeFileForTest(t, root, "plain.yaml", "kind: ConfigMap\n")
	outside := filepath.Join(parent, "outside.yaml")
	if err := os.WriteFile(outside, []byte("kind: ConfigMap\n"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	report := scanReport{
		Findings: []scanFinding{
			sarifTestFinding(scanFinding{
				SARIFSources: []string{
					filepath.Join(root, "resources file.yaml") + "#document=1",
					"plain.yaml#document=2",
					"plain.yaml#document=2",
					filepath.Join(root, "plain.yaml") + "#document=1x",
					filepath.Join(root, "plain.yaml") + "#document=0",
					filepath.Join(root, "plain.yaml") + "#document=999999999999999999999999999999",
					outside + "#document=1",
					"source " + filepath.Join(root, "plain.yaml") + "#document=1",
					"plain.yaml#document=3",
				},
				Evidence: []scanEvidence{
					{EdgeID: "edge:one", Kind: graph.RoutesTo, Source: "plain.yaml#document=3", Detail: "clean"},
					{EdgeID: "edge:two", Kind: graph.RunsAs, Source: "deployment plain.yaml#document=4", Detail: "prose"},
					{EdgeID: "edge:three", Kind: graph.CanRead, Source: "plain.yaml#document=2", Detail: "duplicate"},
				},
			}),
		},
		FindingCount: 1,
	}

	data, err := json.Marshal(newSARIFLog(root, report))
	if err != nil {
		t.Fatalf("marshal SARIF: %v", err)
	}
	var parsed cliSARIFLog
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal SARIF: %v\n%s", err, data)
	}
	result := parsed.Runs[0].Results[0]
	gotURIs := locationURIs(result.Locations)
	wantURIs := []string{"resources%20file.yaml#document=1", "plain.yaml#document=2", "plain.yaml#document=3"}
	if !reflectDeepEqualStrings(gotURIs, wantURIs) {
		t.Fatalf("SARIF location URIs = %#v, want %#v", gotURIs, wantURIs)
	}
	wantDisplay := []string{"resources file.yaml#document=1", "plain.yaml#document=2", "plain.yaml#document=3"}
	if !reflectDeepEqualStrings(result.Properties.SourceReferences, wantDisplay) {
		t.Fatalf("source_references = %#v, want %#v", result.Properties.SourceReferences, wantDisplay)
	}
	output := string(data)
	for _, forbidden := range []string{root, parent, "document=1x", "document=0", "999999999999999999999999999999", "outside.yaml", "deployment plain.yaml"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("SARIF contains unsafe source text %q: %s", forbidden, output)
		}
	}
}

func TestSARIFOmitLocationsWhenNoSafeStructuredSourceReferenceExists(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "scan")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	writeFileForTest(t, root, "plain.yaml", "kind: ConfigMap\n")
	report := scanReport{
		Findings: []scanFinding{
			sarifTestFinding(scanFinding{
				SARIFSources: []string{
					"service plain.yaml#document=1; deployment plain.yaml#document=2",
					"plain.yaml#document=1x",
				},
				Evidence: []scanEvidence{
					{EdgeID: "edge:one", Kind: graph.RoutesTo, Source: "prose plain.yaml#document=1", Detail: "prose"},
					{EdgeID: "edge:two", Kind: graph.RunsAs, Source: "../plain.yaml#document=1", Detail: "escape"},
					{EdgeID: "edge:three", Kind: graph.CanRead, Source: "", Detail: "empty"},
				},
			}),
		},
		FindingCount: 1,
	}

	sarif := newSARIFLog(root, report)
	result := sarif.Runs[0].Results[0]
	if len(result.Locations) != 0 {
		t.Fatalf("locations = %#v, want omitted/empty", result.Locations)
	}
	if len(result.Properties.SourceReferences) != 0 {
		t.Fatalf("source_references = %#v, want empty", result.Properties.SourceReferences)
	}
	data, err := json.Marshal(sarif)
	if err != nil {
		t.Fatalf("marshal SARIF: %v", err)
	}
	if strings.Contains(string(data), root) || strings.Contains(string(data), parent) {
		t.Fatalf("SARIF contains absolute scan-root prefix: %s", data)
	}
}

func sarifTestFinding(overrides scanFinding) scanFinding {
	finding := scanFinding{
		ID:       "finding:PP-K8S-001:test",
		RuleID:   analysis.RulePublicWorkloadCanReadSecret,
		Title:    "Public workload can read Kubernetes Secret",
		Severity: analysis.SeverityHigh,
		Path: []scanPathNode{
			{ID: "node:endpoint", Kind: graph.PublicEndpoint, Name: "kubernetes://prod/service/public-api"},
			{ID: "node:workload", Kind: graph.Workload, Name: "kubernetes://prod/deployment/api"},
			{ID: "node:serviceaccount", Kind: graph.ServiceAccount, Name: "kubernetes://prod/serviceaccount/api"},
			{ID: "node:secret", Kind: graph.Secret, Name: "kubernetes://prod/secret/database-password"},
		},
		Evidence: []scanEvidence{
			{EdgeID: "edge:route", Kind: graph.RoutesTo, Source: "route.yaml#document=1", Detail: "route"},
			{EdgeID: "edge:runs-as", Kind: graph.RunsAs, Source: "runs-as.yaml#document=1", Detail: "runs-as"},
			{EdgeID: "edge:can-read", Kind: graph.CanRead, Source: "can-read.yaml#document=1", Detail: "can-read"},
		},
		SourceReferences: []string{"route.yaml#document=1"},
	}
	if overrides.ID != "" {
		finding.ID = overrides.ID
	}
	if overrides.RuleID != "" {
		finding.RuleID = overrides.RuleID
	}
	if overrides.Title != "" {
		finding.Title = overrides.Title
	}
	if overrides.Severity != "" {
		finding.Severity = overrides.Severity
	}
	if len(overrides.Path) > 0 {
		finding.Path = overrides.Path
	}
	if len(overrides.Evidence) > 0 {
		finding.Evidence = overrides.Evidence
	}
	if overrides.SourceReferences != nil {
		finding.SourceReferences = overrides.SourceReferences
	}
	if overrides.SARIFSources != nil {
		finding.SARIFSources = overrides.SARIFSources
	}
	return finding
}

func assertValidSARIFReport(t *testing.T, output string) cliSARIFLog {
	t.Helper()
	var report cliSARIFLog
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("SARIF output is invalid JSON: %v\n%s", err, output)
	}
	if report.Schema != sarifSchema {
		t.Fatalf("SARIF schema = %q, want %q", report.Schema, sarifSchema)
	}
	if report.Version != "2.1.0" {
		t.Fatalf("SARIF version = %q, want 2.1.0", report.Version)
	}
	return report
}

func mustSARIFRule(t *testing.T, rules []cliSARIFRule, id string) cliSARIFRule {
	t.Helper()
	for _, rule := range rules {
		if rule.ID == id {
			return rule
		}
	}
	t.Fatalf("SARIF rule %q not found in %#v", id, rules)
	return cliSARIFRule{}
}

func locationURIs(locations []cliSARIFLocation) []string {
	out := make([]string, 0, len(locations))
	for _, location := range locations {
		out = append(out, location.PhysicalLocation.ArtifactLocation.URI)
	}
	return out
}

func assertSARIFOmitsPatchAndValidationText(t *testing.T, output string) {
	t.Helper()
	for _, forbidden := range []string{
		"Patch Output",
		"patch_outputs",
		"Patch Preview",
		"patch_previews",
		"Validation",
		"validation",
		"Diff:",
		"--- rbac.yaml",
		"+++ rbac.yaml",
		"remediated",
		"validated/",
		"pathproof-validation-",
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("SARIF stdout contains patch/validation text %q: %s", forbidden, output)
		}
	}
}

func reflectDeepEqualStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
