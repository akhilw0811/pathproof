package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pathproof/internal/analysis"
	"pathproof/internal/graph"
)

const (
	safeFixture       = "testdata/scan-safe"
	vulnerableFixture = "testdata/scan-vulnerable"
	invalidFixture    = "testdata/scan-invalid"
)

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run([]string{"version"}, &stdout, &stderr)

	assertCode(t, code, 0)
	assertString(t, "stdout", stdout.String(), "pathproof dev\n")
	assertString(t, "stderr", stderr.String(), "")
}

func TestRunVersionRejectsExtraArgs(t *testing.T) {
	stdout, stderr, code := runCommand("version", "--json")

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "version accepts no arguments")
}

func TestRunNoArgs(t *testing.T) {
	stdout, stderr, code := runCommand()

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "missing command")
}

func TestRunUnknownCommand(t *testing.T) {
	stdout, stderr, code := runCommand("unknown")

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "unknown command")
}

func TestRunScanRequiresExactlyOneDirectory(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing", args: []string{"scan"}, want: "got 0"},
		{name: "extra", args: []string{"scan", safeFixture, vulnerableFixture}, want: "got 2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, code := runCommand(tt.args...)

			assertCode(t, code, 2)
			assertString(t, "stdout", stdout, "")
			assertOneLineStderr(t, stderr)
			assertContains(t, stderr, "scan requires exactly one directory argument")
			assertContains(t, stderr, tt.want)
		})
	}
}

func TestRunScanAcceptsJSONFormatForms(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "--format", "json", safeFixture},
		{"scan", "--format=json", safeFixture},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, stderr, code := runCommand(args...)

			assertCode(t, code, 0)
			assertString(t, "stderr", stderr, "")
			assertValidJSONReport(t, stdout)
		})
	}
}

func TestRunScanRejectsUnsupportedFormat(t *testing.T) {
	stdout, stderr, code := runCommand("scan", "--format", "xml", safeFixture)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "unsupported scan format \"xml\"")
}

func TestRunScanRejectsUnknownFlagsWithControlledError(t *testing.T) {
	stdout, stderr, code := runCommand("scan", "--bogus", safeFixture)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "invalid scan arguments")
	assertContains(t, stderr, "flag provided but not defined")
	if strings.Contains(stderr, "Usage of scan") {
		t.Fatalf("stderr contains duplicated Go flag usage: %q", stderr)
	}
}

func TestRunScanRejectsMissingAndNonDirectoryPaths(t *testing.T) {
	file := filepath.Join(t.TempDir(), "manifest.yaml")
	if err := os.WriteFile(file, []byte("apiVersion: v1\nkind: Service\n"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "missing", path: filepath.Join(t.TempDir(), "missing"), want: "no such file"},
		{name: "file", path: file, want: "not a directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, code := runCommand("scan", tt.path)

			assertCode(t, code, 2)
			assertString(t, "stdout", stdout, "")
			assertOneLineStderr(t, stderr)
			assertContains(t, stderr, tt.want)
		})
	}
}

func TestRunScanSafeFixtureReturnsZeroAndNoFindings(t *testing.T) {
	stdout, stderr, code := runCommand("scan", safeFixture)

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	assertString(t, "stdout", stdout, "Finding count: 0\nNo findings.\n")
	assertExactlyOneTrailingNewline(t, stdout)
}

func TestRunScanVulnerableFixtureReturnsOneAndHumanFinding(t *testing.T) {
	stdout, stderr, code := runCommand("scan", vulnerableFixture)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Finding count: 1\n")
	assertContains(t, stdout, "Rule: PP-K8S-001\n")
	assertContains(t, stdout, "Severity: High\n")
	assertContains(t, stdout, "Path:\n  1. PublicEndpoint kubernetes://prod/service/public-api")
	assertContains(t, stdout, "  2. Workload kubernetes://prod/deployment/api")
	assertContains(t, stdout, "  3. ServiceAccount kubernetes://prod/serviceaccount/api")
	assertContains(t, stdout, "  4. Secret kubernetes://prod/secret/database-password")
	assertContains(t, stdout, "Evidence:\n  - RoutesTo edge:")
	assertContains(t, stdout, "  - CanRead edge:")
	assertContains(t, stdout, "Sources:")
	assertContains(t, stdout, "Remediation:")
	assertContains(t, stdout, "Option 1: RemoveSecretsResource")
	assertContains(t, stdout, "Option 2: RemoveSecretReadVerb")
	assertContains(t, stdout, "Changes:")
	if strings.Contains(stdout, "Patch Preview:") {
		t.Fatalf("default human output contains patch preview: %s", stdout)
	}
	assertExactlyOneTrailingNewline(t, stdout)
}

func TestRunScanInvalidFixtureReturnsTwoAndWritesErrorToStderr(t *testing.T) {
	stdout, stderr, code := runCommand("scan", invalidFixture)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "parse scan directory")
	assertContains(t, stderr, "document 1")
}

func TestRunScanJSONOutputIsStructured(t *testing.T) {
	stdout, stderr, code := runCommand("scan", "--format=json", vulnerableFixture)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.FindingCount != 1 || len(report.Findings) != 1 {
		t.Fatalf("finding count = %d len = %d, want 1", report.FindingCount, len(report.Findings))
	}
	finding := report.Findings[0]
	if finding.RuleID != "PP-K8S-001" {
		t.Fatalf("rule_id = %q, want PP-K8S-001", finding.RuleID)
	}
	if finding.Severity != "High" {
		t.Fatalf("severity = %q, want High", finding.Severity)
	}
	if len(finding.Path) != 4 {
		t.Fatalf("path len = %d, want 4", len(finding.Path))
	}
	for i, node := range finding.Path {
		if node.ID == "" {
			t.Fatalf("path[%d] id is empty: %#v", i, node)
		}
	}
	if got := finding.Path[0].Kind; got != "PublicEndpoint" {
		t.Fatalf("path[0].kind = %q, want PublicEndpoint", got)
	}
	if len(finding.Evidence) != 3 {
		t.Fatalf("evidence len = %d, want 3", len(finding.Evidence))
	}
	for i, evidence := range finding.Evidence {
		if evidence.EdgeID == "" {
			t.Fatalf("evidence[%d] edge_id is empty: %#v", i, evidence)
		}
		if evidence.Kind == "" || evidence.Detail == "" || evidence.Source == "" {
			t.Fatalf("evidence[%d] missing fields: %#v", i, evidence)
		}
	}
	if finding.Remediation == nil {
		t.Fatal("remediation = nil, want structured remediation plan")
	}
	if finding.Remediation.ID == "" || finding.Remediation.FindingID != finding.ID || finding.Remediation.RuleID != finding.RuleID {
		t.Fatalf("remediation identity = %#v, finding = %#v", finding.Remediation, finding)
	}
	if len(finding.Remediation.Options) == 0 {
		t.Fatalf("remediation options empty: %#v", finding.Remediation)
	}
	for _, option := range finding.Remediation.Options {
		if option.Action == "" || option.Priority == 0 || option.Summary == "" || option.Rationale == "" {
			t.Fatalf("remediation option missing fields: %#v", option)
		}
		if len(option.Changes) == 0 {
			t.Fatalf("remediation option has no changes: %#v", option)
		}
		for _, change := range option.Changes {
			if change.Action == "" || change.Target.Kind == "" || change.Target.Name == "" || change.Summary == "" || change.SourceReference == "" {
				t.Fatalf("remediation change missing fields: %#v", change)
			}
		}
	}
	assertExactlyOneTrailingNewline(t, stdout)
	if strings.Contains(stdout, "Finding count:") || strings.Contains(stdout, "Rule:") {
		t.Fatalf("json stdout contains human text: %q", stdout)
	}
	if strings.Contains(stdout, "patch_previews") {
		t.Fatalf("default JSON output contains patch previews: %s", stdout)
	}
}

func TestRunScanSafeFixtureJSONContainsNoRemediationPlans(t *testing.T) {
	stdout, stderr, code := runCommand("scan", "--format=json", safeFixture)

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.FindingCount != 0 || len(report.Findings) != 0 {
		t.Fatalf("safe report = %#v, want no findings", report)
	}
	if strings.Contains(stdout, "remediation") {
		t.Fatalf("safe stdout contains remediation: %s", stdout)
	}
}

func TestRunScanOutputIsDeterministic(t *testing.T) {
	firstOut, firstErr, firstCode := runCommand("scan", vulnerableFixture)
	secondOut, secondErr, secondCode := runCommand("scan", vulnerableFixture)

	assertCode(t, firstCode, 1)
	assertCode(t, secondCode, 1)
	assertString(t, "first stderr", firstErr, "")
	assertString(t, "second stderr", secondErr, "")
	assertString(t, "stdout", secondOut, firstOut)

	firstJSON, firstJSONErr, firstJSONCode := runCommand("scan", "--format=json", vulnerableFixture)
	secondJSON, secondJSONErr, secondJSONCode := runCommand("scan", "--format=json", vulnerableFixture)
	assertCode(t, firstJSONCode, 1)
	assertCode(t, secondJSONCode, 1)
	assertString(t, "first json stderr", firstJSONErr, "")
	assertString(t, "second json stderr", secondJSONErr, "")
	assertString(t, "json stdout", secondJSON, firstJSON)
}

func TestRunScanPreviewPatchesHumanOutputIncludesGeneratedPreview(t *testing.T) {
	parent := t.TempDir()
	writePreviewFixture(t, parent, "scan-preview", false)
	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--preview-patches", "scan-preview")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Patch Preview:")
	assertContains(t, stdout, "Status: generated")
	assertContains(t, stdout, "File: resources.yaml")
	assertContains(t, stdout, "Diff:")
	assertContains(t, stdout, "--- resources.yaml\n")
	assertContains(t, stdout, "+++ resources.yaml\n")
	assertContains(t, stdout, "@@")
	assertContains(t, stdout, "-  name: api\n")
	assertContains(t, stdout, "   name: worker\n")
	assertExactlyOneTrailingNewline(t, stdout)
}

func TestRunScanPreviewPatchesJSONOutputIncludesStructuredPreview(t *testing.T) {
	parent := t.TempDir()
	writePreviewFixture(t, parent, "scan-preview", false)
	stdout, stderr, code := runCommandInDir(t, parent, "scan", "--format=json", "--preview-patches", "scan-preview")

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.Findings[0].Remediation == nil {
		t.Fatal("remediation = nil, want remediation with patch previews")
	}
	previewCount := 0
	for _, option := range report.Findings[0].Remediation.Options {
		for _, preview := range option.PatchPreviews {
			previewCount++
			if preview.Status == "generated" {
				if preview.File != "resources.yaml" || preview.Diff == "" || preview.OptionAction != "NarrowBindingSubject" {
					t.Fatalf("generated preview = %#v", preview)
				}
			}
		}
	}
	if previewCount == 0 {
		t.Fatalf("no patch previews in JSON remediation: %#v", report.Findings[0].Remediation)
	}
	assertContains(t, stdout, `"patch_previews"`)
	assertExactlyOneTrailingNewline(t, stdout)
}

func TestRunScanPreviewPatchesShowsUnsupportedPreview(t *testing.T) {
	stdout, stderr, code := runCommand("scan", "--preview-patches", vulnerableFixture)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	assertContains(t, stdout, "Patch Preview:")
	assertContains(t, stdout, "Status: unsupported")
	assertContains(t, stdout, "NarrowBindingSubject")
}

func TestRunScanPreviewPatchesJSONFlagForms(t *testing.T) {
	parent := t.TempDir()
	writePreviewFixture(t, parent, "scan-preview", false)

	for _, args := range [][]string{
		{"scan", "--format", "json", "--preview-patches", "scan-preview"},
		{"scan", "--format=json", "--preview-patches", "scan-preview"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, stderr, code := runCommandInDir(t, parent, args...)

			assertCode(t, code, 1)
			assertString(t, "stderr", stderr, "")
			report := assertValidJSONReport(t, stdout)
			if report.Findings[0].Remediation == nil {
				t.Fatal("remediation = nil")
			}
			assertContains(t, stdout, `"patch_previews"`)
		})
	}
}

func TestRunScanPreviewPatchesSafeScanHasNoPreviews(t *testing.T) {
	stdout, stderr, code := runCommand("scan", "--preview-patches", safeFixture)

	assertCode(t, code, 0)
	assertString(t, "stderr", stderr, "")
	assertString(t, "stdout", stdout, "Finding count: 0\nNo findings.\n")
}

func TestWriteScanResultPreviewBuilderDoesNotRunWithoutFlag(t *testing.T) {
	fixture := projectionFixtureWithValidFinding(t)
	var stdout, stderr bytes.Buffer

	code := writeScanResult([]analysis.Finding{fixture.finding}, fixture.graph, "", scanFormatHuman, false, &stdout, &stderr)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr.String(), "")
	assertContains(t, stdout.String(), "Finding count: 1\n")
	if strings.Contains(stdout.String(), "Patch Preview:") {
		t.Fatalf("output contains patch preview without flag: %s", stdout.String())
	}
}

func TestWriteScanResultPreviewInternalErrorLeavesStdoutEmpty(t *testing.T) {
	fixture := projectionFixtureWithValidFinding(t)
	var stdout, stderr bytes.Buffer

	code := writeScanResult([]analysis.Finding{fixture.finding}, fixture.graph, "", scanFormatHuman, true, &stdout, &stderr)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout.String(), "")
	assertOneLineStderr(t, stderr.String())
	assertContains(t, stderr.String(), "build patch previews")
}

func TestRunScanPreviewPatchesOutputIsDeterministicAndExcludesSecretValues(t *testing.T) {
	parent := t.TempDir()
	writePreviewFixture(t, parent, "scan-preview", true)
	firstOut, firstErr, firstCode := runCommandInDir(t, parent, "scan", "--preview-patches", "scan-preview")
	secondOut, secondErr, secondCode := runCommandInDir(t, parent, "scan", "--preview-patches", "scan-preview")

	assertCode(t, firstCode, 1)
	assertCode(t, secondCode, 1)
	assertString(t, "first stderr", firstErr, "")
	assertString(t, "second stderr", secondErr, "")
	assertString(t, "stdout", secondOut, firstOut)
	for _, value := range []string{
		"FAKE_PREVIEW_CLI_SECRET_DATA_VALUE_DO_NOT_RETAIN",
		"FAKE_PREVIEW_CLI_SECRET_STRINGDATA_VALUE_DO_NOT_RETAIN",
	} {
		if strings.Contains(firstOut, value) || strings.Contains(firstErr, value) {
			t.Fatalf("preview output contains secret value %q\nstdout:%s\nstderr:%s", value, firstOut, firstErr)
		}
	}
	assertContains(t, firstOut, "Status: unsupported")
}

func TestRunScanReversedInputFileCreationOrderIsDeterministic(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fixture")
	writeSplitVulnerableFixture(t, dir, []string{"service.yaml", "deployment.yaml", "rbac.yaml", "secret.yaml"})
	firstOut, firstErr, firstCode := runCommand("scan", "--format=json", dir)

	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove fixture dir: %v", err)
	}
	writeSplitVulnerableFixture(t, dir, []string{"secret.yaml", "rbac.yaml", "deployment.yaml", "service.yaml"})
	secondOut, secondErr, secondCode := runCommand("scan", "--format=json", dir)

	assertCode(t, firstCode, 1)
	assertCode(t, secondCode, 1)
	assertString(t, "first stderr", firstErr, "")
	assertString(t, "second stderr", secondErr, "")
	assertString(t, "stdout", secondOut, firstOut)
}

func TestRunScanSecretFixtureValuesNeverAppearInOutput(t *testing.T) {
	for _, args := range [][]string{
		{"scan", vulnerableFixture},
		{"scan", "--format=json", vulnerableFixture},
		{"scan", safeFixture},
		{"scan", invalidFixture},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout, stderr, _ := runCommand(args...)
			for _, value := range []string{
				"FAKE_CLI_SECRET_DATA_VALUE_DO_NOT_RETAIN",
				"FAKE_CLI_SECRET_STRINGDATA_VALUE_DO_NOT_RETAIN",
				"FAKE_CLI_SECRET_MALFORMED_VALUE_DO_NOT_RETAIN",
			} {
				if strings.Contains(stdout, value) {
					t.Fatalf("stdout contains secret value %q: %s", value, stdout)
				}
				if strings.Contains(stderr, value) {
					t.Fatalf("stderr contains secret value %q: %s", value, stderr)
				}
			}
		})
	}
}

func TestRunScanMultipleFindingsFollowAnalysisOrder(t *testing.T) {
	dir := writeMultiFindingFixture(t)
	stdout, stderr, code := runCommand("scan", "--format=json", dir)

	assertCode(t, code, 1)
	assertString(t, "stderr", stderr, "")
	report := assertValidJSONReport(t, stdout)
	if report.FindingCount != 2 {
		t.Fatalf("finding_count = %d, want 2", report.FindingCount)
	}
	for i := 1; i < len(report.Findings); i++ {
		if report.Findings[i-1].ID > report.Findings[i].ID {
			t.Fatalf("findings are not in deterministic analysis order: %#v", report.Findings)
		}
	}
	for _, finding := range report.Findings {
		if finding.Remediation == nil {
			t.Fatalf("finding %s remediation = nil, want matching plan", finding.ID)
		}
		if finding.Remediation.FindingID != finding.ID {
			t.Fatalf("remediation finding_id = %q, want %q", finding.Remediation.FindingID, finding.ID)
		}
	}
}

func TestProjectFindingRejectsMissingNode(t *testing.T) {
	g := graph.New()
	endpoint := mustAddNode(t, g, graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/public-api"))
	workload := mustAddNode(t, g, graph.NewNode(graph.Workload, "kubernetes://prod/deployment/api"))
	serviceAccount := mustAddNode(t, g, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/api"))
	route := mustAddEdge(t, g, graph.NewEdge(graph.RoutesTo, endpoint.ID, workload.ID, graph.SourceEvidence{Source: "route", Detail: "route"}))
	runsAs := mustAddEdge(t, g, graph.NewEdge(graph.RunsAs, workload.ID, serviceAccount.ID, graph.SourceEvidence{Source: "runs-as", Detail: "runs-as"}))
	canRead := graph.NewEdge(graph.CanRead, serviceAccount.ID, graph.NodeID("node:missing-secret"), graph.SourceEvidence{Source: "can-read", Detail: "can-read"})
	finding := analysis.Finding{
		ID:       "finding:test",
		NodeIDs:  []graph.NodeID{endpoint.ID, workload.ID, serviceAccount.ID, graph.NodeID("node:missing-secret")},
		EdgeIDs:  []graph.EdgeID{route.ID, runsAs.ID, canRead.ID},
		Evidence: []analysis.FindingEvidence{{EdgeID: route.ID, Kind: route.Kind, Source: route.Evidence}, {EdgeID: runsAs.ID, Kind: runsAs.Kind, Source: runsAs.Evidence}, {EdgeID: canRead.ID, Kind: canRead.Kind, Source: canRead.Evidence}},
	}

	_, err := newScanReport([]analysis.Finding{finding}, g, nil, nil)
	if err == nil {
		t.Fatal("newScanReport error = nil, want missing node error")
	}
	if !strings.Contains(err.Error(), "missing node") {
		t.Fatalf("error = %q, want missing node", err)
	}
}

func TestProjectFindingRejectsMissingEdge(t *testing.T) {
	g := graph.New()
	endpoint := mustAddNode(t, g, graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/public-api"))
	workload := mustAddNode(t, g, graph.NewNode(graph.Workload, "kubernetes://prod/deployment/api"))
	serviceAccount := mustAddNode(t, g, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/api"))
	secret := mustAddNode(t, g, graph.NewNode(graph.Secret, "kubernetes://prod/secret/database-password"))
	route := mustAddEdge(t, g, graph.NewEdge(graph.RoutesTo, endpoint.ID, workload.ID, graph.SourceEvidence{Source: "route", Detail: "route"}))
	runsAs := mustAddEdge(t, g, graph.NewEdge(graph.RunsAs, workload.ID, serviceAccount.ID, graph.SourceEvidence{Source: "runs-as", Detail: "runs-as"}))
	canRead := graph.NewEdge(graph.CanRead, serviceAccount.ID, secret.ID, graph.SourceEvidence{Source: "can-read", Detail: "can-read"})
	finding := analysis.Finding{
		ID:       "finding:test",
		NodeIDs:  []graph.NodeID{endpoint.ID, workload.ID, serviceAccount.ID, secret.ID},
		EdgeIDs:  []graph.EdgeID{route.ID, runsAs.ID, canRead.ID},
		Evidence: []analysis.FindingEvidence{{EdgeID: route.ID, Kind: route.Kind, Source: route.Evidence}, {EdgeID: runsAs.ID, Kind: runsAs.Kind, Source: runsAs.Evidence}, {EdgeID: canRead.ID, Kind: canRead.Kind, Source: canRead.Evidence}},
	}

	_, err := newScanReport([]analysis.Finding{finding}, g, nil, nil)
	if err == nil {
		t.Fatal("newScanReport error = nil, want missing edge error")
	}
	if !strings.Contains(err.Error(), "missing edge") {
		t.Fatalf("error = %q, want missing edge", err)
	}
}

func TestWriteScanResultRejectsUnrelatedFirstEdgeWithEmptyStdout(t *testing.T) {
	fixture := projectionFixtureWithValidFinding(t)
	otherEndpoint := mustAddNode(t, fixture.graph, graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/other-api"))
	edge := mustAddEdge(t, fixture.graph, graph.NewEdge(graph.RoutesTo, otherEndpoint.ID, fixture.workload.ID, graph.SourceEvidence{Source: "other-route", Detail: "other route"}))
	fixture.finding.EdgeIDs[0] = edge.ID
	fixture.finding.Evidence[0] = analysis.FindingEvidence{EdgeID: edge.ID, Kind: edge.Kind, Source: edge.Evidence}

	stdout, stderr, code := writeScanResultForTest([]analysis.Finding{fixture.finding}, fixture.graph, scanFormatHuman)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "internal scan error")
	assertContains(t, stderr, "build remediation plans")
	assertContains(t, stderr, "connects")
}

func TestWriteScanResultRejectsReversedEdgeWithEmptyStdout(t *testing.T) {
	fixture := projectionFixtureWithValidFinding(t)
	edge := mustAddEdge(t, fixture.graph, graph.NewEdge(graph.RoutesTo, fixture.workload.ID, fixture.endpoint.ID, graph.SourceEvidence{Source: "reversed-route", Detail: "reversed route"}))
	fixture.finding.EdgeIDs[0] = edge.ID
	fixture.finding.Evidence[0] = analysis.FindingEvidence{EdgeID: edge.ID, Kind: edge.Kind, Source: edge.Evidence}

	stdout, _, code := writeScanResultForTest([]analysis.Finding{fixture.finding}, fixture.graph, scanFormatHuman)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
}

func TestWriteScanResultRejectsWrongMiddleEdgeWithEmptyStdout(t *testing.T) {
	fixture := projectionFixtureWithValidFinding(t)
	otherServiceAccount := mustAddNode(t, fixture.graph, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/other-api"))
	edge := mustAddEdge(t, fixture.graph, graph.NewEdge(graph.RunsAs, fixture.workload.ID, otherServiceAccount.ID, graph.SourceEvidence{Source: "wrong-runs-as", Detail: "wrong runs as"}))
	fixture.finding.EdgeIDs[1] = edge.ID
	fixture.finding.Evidence[1] = analysis.FindingEvidence{EdgeID: edge.ID, Kind: edge.Kind, Source: edge.Evidence}

	stdout, _, code := writeScanResultForTest([]analysis.Finding{fixture.finding}, fixture.graph, scanFormatHuman)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
}

func TestWriteScanResultRejectsWrongLastEdgeWithEmptyStdout(t *testing.T) {
	fixture := projectionFixtureWithValidFinding(t)
	otherSecret := mustAddNode(t, fixture.graph, graph.NewNode(graph.Secret, "kubernetes://prod/secret/other-password"))
	edge := mustAddEdge(t, fixture.graph, graph.NewEdge(graph.CanRead, fixture.serviceAccount.ID, otherSecret.ID, graph.SourceEvidence{Source: "wrong-can-read", Detail: "wrong can read"}))
	fixture.finding.EdgeIDs[2] = edge.ID
	fixture.finding.Evidence[2] = analysis.FindingEvidence{EdgeID: edge.ID, Kind: edge.Kind, Source: edge.Evidence}

	stdout, _, code := writeScanResultForTest([]analysis.Finding{fixture.finding}, fixture.graph, scanFormatHuman)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
}

func TestWriteScanResultRejectsEdgeCountMismatchWithEmptyStdout(t *testing.T) {
	fixture := projectionFixtureWithValidFinding(t)
	fixture.finding.EdgeIDs = fixture.finding.EdgeIDs[:2]
	fixture.finding.Evidence = fixture.finding.Evidence[:2]

	stdout, stderr, code := writeScanResultForTest([]analysis.Finding{fixture.finding}, fixture.graph, scanFormatHuman)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout, "")
	assertOneLineStderr(t, stderr)
	assertContains(t, stderr, "path edges")
}

func TestWriteScanResultValidFindingProjectsInHumanAndJSON(t *testing.T) {
	fixture := projectionFixtureWithValidFinding(t)

	humanStdout, humanStderr, humanCode := writeScanResultForTest([]analysis.Finding{fixture.finding}, fixture.graph, scanFormatHuman)
	jsonStdout, jsonStderr, jsonCode := writeScanResultForTest([]analysis.Finding{fixture.finding}, fixture.graph, scanFormatJSON)

	assertCode(t, humanCode, 1)
	assertString(t, "human stderr", humanStderr, "")
	assertContains(t, humanStdout, "Finding count: 1\n")
	assertContains(t, humanStdout, "RoutesTo "+string(fixture.route.ID))
	assertCode(t, jsonCode, 1)
	assertString(t, "json stderr", jsonStderr, "")
	report := assertValidJSONReport(t, jsonStdout)
	if report.FindingCount != 1 {
		t.Fatalf("json finding_count = %d, want 1", report.FindingCount)
	}
	if got := report.Findings[0].Path[0].ID; got != string(fixture.endpoint.ID) {
		t.Fatalf("json path[0].id = %q, want %q", got, fixture.endpoint.ID)
	}
	if got := report.Findings[0].Evidence[0].EdgeID; got != string(fixture.route.ID) {
		t.Fatalf("json evidence[0].edge_id = %q, want %q", got, fixture.route.ID)
	}
}

func TestWriteScanResultRejectsLateInconsistencyWithoutPartialOutput(t *testing.T) {
	fixture := projectionFixtureWithValidFinding(t)
	otherSecret := mustAddNode(t, fixture.graph, graph.NewNode(graph.Secret, "kubernetes://prod/secret/late-other-password"))
	edge := mustAddEdge(t, fixture.graph, graph.NewEdge(graph.CanRead, fixture.serviceAccount.ID, otherSecret.ID, graph.SourceEvidence{Source: "late-wrong-can-read", Detail: "late wrong can read"}))
	fixture.finding.EdgeIDs[2] = edge.ID
	fixture.finding.Evidence[2] = analysis.FindingEvidence{EdgeID: edge.ID, Kind: edge.Kind, Source: edge.Evidence}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := writeScanResult([]analysis.Finding{fixture.finding}, fixture.graph, ".", scanFormatHuman, false, &stdout, &stderr)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout.String(), "")
	assertOneLineStderr(t, stderr.String())
}

func TestWriteScanResultMissingNodeReturnsTwoWithEmptyStdout(t *testing.T) {
	g := graph.New()
	endpoint := mustAddNode(t, g, graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/public-api"))
	workload := mustAddNode(t, g, graph.NewNode(graph.Workload, "kubernetes://prod/deployment/api"))
	serviceAccount := mustAddNode(t, g, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/api"))
	route := mustAddEdge(t, g, graph.NewEdge(graph.RoutesTo, endpoint.ID, workload.ID, graph.SourceEvidence{Source: "route", Detail: "route"}))
	runsAs := mustAddEdge(t, g, graph.NewEdge(graph.RunsAs, workload.ID, serviceAccount.ID, graph.SourceEvidence{Source: "runs-as", Detail: "runs-as"}))
	canRead := graph.NewEdge(graph.CanRead, serviceAccount.ID, graph.NodeID("node:missing-secret"), graph.SourceEvidence{Source: "can-read", Detail: "can-read"})
	finding := analysis.Finding{
		ID:       "finding:test",
		NodeIDs:  []graph.NodeID{endpoint.ID, workload.ID, serviceAccount.ID, graph.NodeID("node:missing-secret")},
		EdgeIDs:  []graph.EdgeID{route.ID, runsAs.ID, canRead.ID},
		Evidence: []analysis.FindingEvidence{{EdgeID: route.ID, Kind: route.Kind, Source: route.Evidence}, {EdgeID: runsAs.ID, Kind: runsAs.Kind, Source: runsAs.Evidence}, {EdgeID: canRead.ID, Kind: canRead.Kind, Source: canRead.Evidence}},
	}
	var stdout, stderr bytes.Buffer

	code := writeScanResult([]analysis.Finding{finding}, g, ".", scanFormatHuman, false, &stdout, &stderr)

	assertCode(t, code, 2)
	assertString(t, "stdout", stdout.String(), "")
	assertOneLineStderr(t, stderr.String())
	assertContains(t, stderr.String(), "internal scan error")
	assertContains(t, stderr.String(), "missing node")
}

func TestRunScanFailingStdoutWriterReturnsTwo(t *testing.T) {
	var stderr bytes.Buffer

	code := run([]string{"scan", safeFixture}, failingWriter{}, &stderr)

	assertCode(t, code, 2)
	assertOneLineStderr(t, stderr.String())
	assertContains(t, stderr.String(), "write scan report")
}

func runCommand(args ...string) (string, string, int) {
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

func runCommandInDir(t *testing.T, dir string, args ...string) (string, string, int) {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	defer func() {
		if err := os.Chdir(cwd); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	}()
	return runCommand(args...)
}

func writeScanResultForTest(findings []analysis.Finding, g *graph.Graph, format scanFormat) (string, string, int) {
	var stdout, stderr bytes.Buffer
	code := writeScanResult(findings, g, ".", format, false, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

type projectionFixture struct {
	graph          *graph.Graph
	endpoint       graph.Node
	workload       graph.Node
	serviceAccount graph.Node
	secret         graph.Node
	route          graph.Edge
	runsAs         graph.Edge
	canRead        graph.Edge
	finding        analysis.Finding
}

func projectionFixtureWithValidFinding(t *testing.T) projectionFixture {
	t.Helper()
	g := graph.New()
	endpoint := mustAddNode(t, g, graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/public-api"))
	workload := mustAddNode(t, g, graph.NewNode(graph.Workload, "kubernetes://prod/deployment/api"))
	serviceAccount := mustAddNode(t, g, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/api"))
	secret := mustAddNode(t, g, graph.NewNode(graph.Secret, "kubernetes://prod/secret/database-password"))
	route := mustAddEdge(t, g, graph.NewEdge(graph.RoutesTo, endpoint.ID, workload.ID, graph.SourceEvidence{Source: "route", Detail: "route"}))
	runsAs := mustAddEdge(t, g, graph.NewEdge(graph.RunsAs, workload.ID, serviceAccount.ID, graph.SourceEvidence{Source: "runs-as", Detail: "runs-as"}))
	canRead := mustAddEdge(t, g, graph.NewEdge(graph.CanRead, serviceAccount.ID, secret.ID, graph.SourceEvidence{Source: "can-read", Detail: "can-read"}))
	finding := analysis.Finding{
		ID:               "finding:test",
		RuleID:           analysis.RulePublicWorkloadCanReadSecret,
		Title:            "Public workload can read Kubernetes Secret",
		Severity:         analysis.SeverityHigh,
		Summary:          "test finding",
		NodeIDs:          []graph.NodeID{endpoint.ID, workload.ID, serviceAccount.ID, secret.ID},
		EdgeIDs:          []graph.EdgeID{route.ID, runsAs.ID, canRead.ID},
		Evidence:         []analysis.FindingEvidence{{EdgeID: route.ID, Kind: route.Kind, Source: route.Evidence}, {EdgeID: runsAs.ID, Kind: runsAs.Kind, Source: runsAs.Evidence}, {EdgeID: canRead.ID, Kind: canRead.Kind, Source: canRead.Evidence}},
		SourceReferences: []string{route.Evidence.Source, runsAs.Evidence.Source, canRead.Evidence.Source},
	}
	return projectionFixture{
		graph:          g,
		endpoint:       endpoint,
		workload:       workload,
		serviceAccount: serviceAccount,
		secret:         secret,
		route:          route,
		runsAs:         runsAs,
		canRead:        canRead,
		finding:        finding,
	}
}

type cliJSONReport struct {
	Findings     []cliJSONFinding `json:"findings"`
	FindingCount int              `json:"finding_count"`
}

type cliJSONFinding struct {
	ID               string              `json:"id"`
	RuleID           string              `json:"rule_id"`
	Title            string              `json:"title"`
	Severity         string              `json:"severity"`
	Summary          string              `json:"summary"`
	Path             []cliJSONPathNode   `json:"path"`
	Evidence         []cliJSONEvidence   `json:"evidence"`
	SourceReferences []string            `json:"source_references"`
	Remediation      *cliJSONRemediation `json:"remediation,omitempty"`
}

type cliJSONPathNode struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type cliJSONEvidence struct {
	EdgeID string `json:"edge_id"`
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Detail string `json:"detail"`
}

type cliJSONRemediation struct {
	ID        string                     `json:"id"`
	FindingID string                     `json:"finding_id"`
	RuleID    string                     `json:"rule_id"`
	Summary   string                     `json:"summary"`
	Options   []cliJSONRemediationOption `json:"options"`
}

type cliJSONRemediationOption struct {
	Priority           int                        `json:"priority"`
	Action             string                     `json:"action"`
	Summary            string                     `json:"summary"`
	Rationale          string                     `json:"rationale"`
	RequiresAllChanges bool                       `json:"requires_all_changes"`
	Changes            []cliJSONRemediationChange `json:"changes"`
	Constraints        []string                   `json:"constraints,omitempty"`
	PatchPreviews      []cliJSONPatchPreview      `json:"patch_previews,omitempty"`
}

type cliJSONRemediationChange struct {
	Action           string                   `json:"action"`
	Target           cliJSONRemediationTarget `json:"target"`
	Summary          string                   `json:"summary"`
	SourceReference  string                   `json:"source_reference"`
	PermissionSHA256 string                   `json:"permission_sha256,omitempty"`
	MatchedVerb      string                   `json:"matched_verb,omitempty"`
	Subject          string                   `json:"subject,omitempty"`
}

type cliJSONRemediationTarget struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

type cliJSONPatchPreview struct {
	PlanID       string `json:"plan_id"`
	OptionIndex  int    `json:"option_index"`
	OptionAction string `json:"option_action"`
	ChangeIndex  int    `json:"change_index"`
	Status       string `json:"status"`
	Summary      string `json:"summary"`
	File         string `json:"file,omitempty"`
	Diff         string `json:"diff,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

func assertValidJSONReport(t *testing.T, output string) cliJSONReport {
	t.Helper()
	var report cliJSONReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("json output is invalid: %v\n%s", err, output)
	}
	return report
}

func assertCode(t *testing.T, got, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("exit code = %d, want %d", got, want)
	}
}

func assertString(t *testing.T, name, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s = %q, want %q", name, got, want)
	}
}

func assertContains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("output = %q, want substring %q", got, want)
	}
}

func assertOneLineStderr(t *testing.T, stderr string) {
	t.Helper()
	assertExactlyOneTrailingNewline(t, stderr)
	if strings.Count(stderr, "\n") != 1 {
		t.Fatalf("stderr = %q, want exactly one line", stderr)
	}
}

func assertExactlyOneTrailingNewline(t *testing.T, output string) {
	t.Helper()
	if !strings.HasSuffix(output, "\n") {
		t.Fatalf("output = %q, want trailing newline", output)
	}
	if strings.HasSuffix(strings.TrimSuffix(output, "\n"), "\n") {
		t.Fatalf("output = %q, want exactly one trailing newline", output)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("stdout failed")
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

func writeSplitVulnerableFixture(t *testing.T, dir string, order []string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create fixture dir: %v", err)
	}
	files := map[string]string{
		"service.yaml": `apiVersion: v1
kind: Service
metadata:
  name: public-api
  namespace: prod
spec:
  type: LoadBalancer
  selector:
    app: api
`,
		"deployment.yaml": `apiVersion: apps/v1
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
`,
		"secret.yaml": `apiVersion: v1
kind: Secret
metadata:
  name: database-password
  namespace: prod
data:
  password: FAKE_CLI_SECRET_DATA_VALUE_DO_NOT_RETAIN
`,
		"rbac.yaml": `apiVersion: rbac.authorization.k8s.io/v1
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
`,
	}
	for _, name := range order {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(files[name]), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

func writeMultiFindingFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	content := `apiVersion: v1
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
kind: Secret
metadata:
  name: api-token
  namespace: prod
---
apiVersion: v1
kind: Secret
metadata:
  name: database-password
  namespace: prod
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: prod
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["list"]
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
`
	if err := os.WriteFile(filepath.Join(dir, "resources.yaml"), []byte(content), 0o600); err != nil {
		t.Fatalf("write multi finding fixture: %v", err)
	}
	return dir
}

func writePreviewFixture(t *testing.T, parent, name string, secretPayload bool) {
	t.Helper()
	dir := filepath.Join(parent, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create preview fixture dir: %v", err)
	}
	secretExtra := ""
	if secretPayload {
		secretExtra = `data:
  password: FAKE_PREVIEW_CLI_SECRET_DATA_VALUE_DO_NOT_RETAIN
stringData:
  token: FAKE_PREVIEW_CLI_SECRET_STRINGDATA_VALUE_DO_NOT_RETAIN
`
	}
	content := `apiVersion: v1
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
` + secretExtra + `---
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
- kind: ServiceAccount
  name: worker
  namespace: prod
`
	if err := os.WriteFile(filepath.Join(dir, "resources.yaml"), []byte(content), 0o600); err != nil {
		t.Fatalf("write preview fixture: %v", err)
	}
}

var _ io.Writer = failingWriter{}
