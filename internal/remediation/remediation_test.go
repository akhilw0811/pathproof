package remediation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"pathproof/internal/analysis"
	"pathproof/internal/graph"
	parsergithubactions "pathproof/internal/parser/githubactions"
	parserkubernetes "pathproof/internal/parser/kubernetes"
	routinggithubactions "pathproof/internal/routing/githubactions"
	routingkubernetes "pathproof/internal/routing/kubernetes"
)

func TestBuildRoleBindingGetSecretsProducesCompleteResourceAndVerbOptions(t *testing.T) {
	g, findings := scanManifest(t, basicVulnerableManifest(`resources: ["secrets"]`, `verbs: ["get"]`, singleSubjectYAML()))

	plans := mustBuild(t, g, findings)

	if len(plans) != 1 {
		t.Fatalf("plan count = %d, want 1: %#v", len(plans), plans)
	}
	plan := plans[0]
	if plan.ID == "" || plan.FindingID != findings[0].ID || plan.RuleID != analysis.RulePublicWorkloadCanReadSecret {
		t.Fatalf("plan identity = %#v, finding = %#v", plan, findings[0])
	}
	assertActions(t, plan, []Action{RemoveSecretsResource, RemoveSecretReadVerb})
	resource := optionByAction(t, plan, RemoveSecretsResource)
	assertCompleteOption(t, resource, 1)
	change := resource.Changes[0]
	if change.Target.Kind != "Role" || change.Target.Namespace != "prod" || change.Target.Name != "secret-reader" {
		t.Fatalf("resource target = %#v, want prod Role secret-reader", change.Target)
	}
	if change.PermissionSHA256 == "" || !strings.HasSuffix(change.SourceReference, "resources.yaml#document=5") {
		t.Fatalf("resource change missing permission/source: %#v", change)
	}
	if !strings.Contains(change.Summary, "Remove the secrets resource grant") {
		t.Fatalf("resource summary = %q, want remove secrets grant", change.Summary)
	}

	verb := optionByAction(t, plan, RemoveSecretReadVerb)
	assertCompleteOption(t, verb, 1)
	if verb.Changes[0].MatchedVerb != "get" {
		t.Fatalf("matched verb = %q, want get", verb.Changes[0].MatchedVerb)
	}
	if _, ok := findOption(plan, NarrowBindingSubject); ok {
		t.Fatalf("single-subject binding produced NarrowBindingSubject: %#v", plan.Options)
	}
}

func TestLoadGitHubActionPinsValidatesLocalJSONMapping(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name:    "lowercase sha",
			content: `{"actions/checkout@v4":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
		},
		{
			name:    "uppercase sha",
			content: `{"actions/checkout@v4":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`,
		},
		{
			name:    "short sha",
			content: `{"actions/checkout@v4":"aaaaaaaa"}`,
			wantErr: "invalid commit SHA",
		},
		{
			name:    "non hex sha",
			content: `{"actions/checkout@v4":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}`,
			wantErr: "invalid commit SHA",
		},
		{
			name:    "malformed json",
			content: `{"actions/checkout@v4":"FAKE_MAPPING_SECRET_DO_NOT_RETAIN"`,
			wantErr: "not valid JSON",
		},
		{
			name:    "null",
			content: `null`,
			wantErr: "JSON object",
		},
		{
			name:    "array",
			content: `[]`,
			wantErr: "JSON object",
		},
		{
			name:    "string",
			content: `"bad"`,
			wantErr: "JSON object",
		},
		{
			name:    "number",
			content: `42`,
			wantErr: "JSON object",
		},
		{
			name:    "boolean",
			content: `true`,
			wantErr: "JSON object",
		},
		{
			name:    "invalid key",
			content: `{"${{ secrets.ACTION_REF }}":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`,
			wantErr: "invalid action ref key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pins.json")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatalf("write pins: %v", err)
			}

			pins, err := LoadGitHubActionPins(path)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("LoadGitHubActionPins error = nil, want error")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %q, want %q", err.Error(), tt.wantErr)
				}
				if strings.Contains(err.Error(), "FAKE_MAPPING_SECRET_DO_NOT_RETAIN") || strings.Contains(err.Error(), tt.content) {
					t.Fatalf("error leaks mapping content: %q", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadGitHubActionPins: %v", err)
			}
			if got, ok := pins.SHAFor("actions/checkout@v4"); !ok || got == "" {
				t.Fatalf("pin lookup = %q/%t, want SHA", got, ok)
			}
		})
	}
}

func TestBuildGitHubActionsUnpinnedActionAdvisoryOnlyWithoutMapping(t *testing.T) {
	g, findings := scanWorkflowForRemediation(t, `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	finding := onlyFindingByRuleForRemediation(t, findings, analysis.RuleGitHubActionsUnpinnedAction)

	plans := mustBuild(t, g, findings)

	if len(plans) != 1 {
		t.Fatalf("plans = %#v, want one PP-GHA-001 plan", plans)
	}
	plan := plans[0]
	if plan.FindingID != finding.ID || plan.RuleID != analysis.RuleGitHubActionsUnpinnedAction {
		t.Fatalf("plan identity = %#v, finding = %#v", plan, finding)
	}
	option := optionByAction(t, plan, PinGitHubActionToSHA)
	change := option.Changes[0]
	if !change.Advisory || change.PatchSupported || change.ActionRef != "actions/checkout@v4" || change.ReplacementSHA != "" {
		t.Fatalf("change = %#v, want advisory-only action pinning", change)
	}
	if strings.Contains(change.SourceReference, filepath.Dir(os.TempDir())) || strings.Contains(change.Reason, "FAKE") {
		t.Fatalf("change contains unsafe data: %#v", change)
	}
}

func TestBuildGitHubActionsUnpinnedActionPatchSupportedWithMapping(t *testing.T) {
	g, findings := scanWorkflowForRemediation(t, `jobs:
  test:
    steps:
      - uses: actions/checkout@v4
`)
	finding := onlyFindingByRuleForRemediation(t, findings, analysis.RuleGitHubActionsUnpinnedAction)
	pins := GitHubActionPins{"actions/checkout@v4": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}

	plans := mustBuildWithPins(t, g, findings, pins)
	repeated := mustBuildWithPins(t, g, findings, pins)

	if !reflect.DeepEqual(plans, repeated) {
		t.Fatalf("plans are not deterministic:\nfirst=%#v\nsecond=%#v", plans, repeated)
	}
	if len(plans) != 1 || plans[0].FindingID != finding.ID {
		t.Fatalf("plans = %#v, want one plan for finding %s", plans, finding.ID)
	}
	change := optionByAction(t, plans[0], PinGitHubActionToSHA).Changes[0]
	if !change.Advisory || !change.PatchSupported || change.ReplacementSHA != pins["actions/checkout@v4"] || change.ReplacementRef != "actions/checkout@"+pins["actions/checkout@v4"] {
		t.Fatalf("change = %#v, want patch-supported SHA replacement", change)
	}
	if change.SourceLine <= 0 || change.SourceColumn <= 0 {
		t.Fatalf("change source coordinates = %d/%d, want positive", change.SourceLine, change.SourceColumn)
	}
	if onlyFindingByRuleForRemediation(t, findings, analysis.RuleGitHubActionsUnpinnedAction).ID != finding.ID {
		t.Fatalf("finding ID changed after remediation planning")
	}
}

func TestBuildMultiResourceRulePreservesUnrelatedResourceAccessInSummary(t *testing.T) {
	g, findings := scanManifest(t, basicVulnerableManifest(`resources: ["secrets", "configmaps"]`, `verbs: ["get"]`, singleSubjectYAML()))

	plan := mustSinglePlan(t, g, findings)
	option := optionByAction(t, plan, RemoveSecretsResource)

	if got := option.Changes[0].Summary; !strings.Contains(got, "split the rule") || !strings.Contains(got, "unrelated resources") {
		t.Fatalf("summary = %q, want split/preserve unrelated resources", got)
	}
	if _, ok := findOption(plan, RemoveSecretReadVerb); ok {
		t.Fatalf("multi-resource rule produced unsafe RemoveSecretReadVerb option: %#v", plan.Options)
	}
}

func TestBuildRemoveSecretsResourceRequiresNonWildcardSecretResource(t *testing.T) {
	tests := []struct {
		name          string
		resources     string
		wantResource  bool
		wantSplitText bool
	}{
		{
			name:         "wildcard plus secrets",
			resources:    `resources: ["*", "secrets"]`,
			wantResource: false,
		},
		{
			name:         "wildcard only",
			resources:    `resources: ["*"]`,
			wantResource: false,
		},
		{
			name:         "secrets only",
			resources:    `resources: ["secrets"]`,
			wantResource: true,
		},
		{
			name:          "secrets and configmaps",
			resources:     `resources: ["secrets", "configmaps"]`,
			wantResource:  true,
			wantSplitText: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, findings := scanManifest(t, basicVulnerableManifest(tt.resources, `verbs: ["get"]`, singleSubjectYAML()))

			plans := mustBuild(t, g, findings)
			option, ok := findOptionInPlans(plans, RemoveSecretsResource)
			if ok != tt.wantResource {
				t.Fatalf("RemoveSecretsResource present = %t, want %t: %#v", ok, tt.wantResource, plans)
			}
			if ok && tt.wantSplitText {
				if got := option.Changes[0].Summary; !strings.Contains(got, "split the rule") || !strings.Contains(got, "unrelated resources") {
					t.Fatalf("summary = %q, want split/preserve unrelated resources", got)
				}
			}
			if ok && strings.Contains(option.Changes[0].Summary, "Remove the secrets resource grant") && strings.Contains(tt.resources, `"*"`) {
				t.Fatalf("wildcard resource rule received literal secrets removal guidance: %#v", option.Changes[0])
			}
		})
	}
}

func TestBuildRemoveSecretReadVerbRequiresSecretOnlyResourceRule(t *testing.T) {
	tests := []struct {
		name      string
		resources string
		verbs     string
		wantVerb  bool
	}{
		{
			name:      "multi-resource get",
			resources: `resources: ["secrets", "configmaps"]`,
			verbs:     `verbs: ["get"]`,
		},
		{
			name:      "secrets-only get",
			resources: `resources: ["secrets"]`,
			verbs:     `verbs: ["get"]`,
			wantVerb:  true,
		},
		{
			name:      "wildcard resource get",
			resources: `resources: ["*"]`,
			verbs:     `verbs: ["get"]`,
		},
		{
			name:      "secrets-only wildcard verb",
			resources: `resources: ["secrets"]`,
			verbs:     `verbs: ["*"]`,
			wantVerb:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, findings := scanManifest(t, basicVulnerableManifest(tt.resources, tt.verbs, singleSubjectYAML()))

			plans := mustBuild(t, g, findings)
			option, ok := findOptionInPlans(plans, RemoveSecretReadVerb)
			if ok != tt.wantVerb {
				t.Fatalf("RemoveSecretReadVerb present = %t, want %t: %#v", ok, tt.wantVerb, plans)
			}
			if ok && tt.verbs == `verbs: ["*"]` {
				got := option.Changes[0].Summary
				if !strings.Contains(got, "Replace wildcard verb *") || strings.Contains(got, "Remove the * verb") {
					t.Fatalf("wildcard verb summary = %q, want replacement guidance", got)
				}
			}
		})
	}
}

func TestBuildResourceAndVerbOptionsRequireCoreOnlyAPIGroup(t *testing.T) {
	tests := []struct {
		name         string
		apiGroups    []string
		wantResource bool
		wantVerb     bool
	}{
		{
			name:      "wildcard API group",
			apiGroups: []string{"*"},
		},
		{
			name:      "mixed core and non-core API groups",
			apiGroups: []string{"", "apps"},
		},
		{
			name:      "non-core API group",
			apiGroups: []string{"apps"},
		},
		{
			name:         "core API group only",
			apiGroups:    []string{""},
			wantResource: true,
			wantVerb:     true,
		},
		{
			name:         "empty API groups are unsafe",
			apiGroups:    nil,
			wantResource: false,
			wantVerb:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authorization := testAuthorization()
			authorization.Permission.APIGroups = append([]string(nil), tt.apiGroups...)
			g, finding := graphWithAuthorizations(t, []graph.KubernetesCanReadAuthorization{authorization}, "route", "runs-as", "can-read")

			plans := mustBuild(t, g, []analysis.Finding{finding})
			_, hasResource := findOptionInPlans(plans, RemoveSecretsResource)
			_, hasVerb := findOptionInPlans(plans, RemoveSecretReadVerb)
			if hasResource != tt.wantResource {
				t.Fatalf("RemoveSecretsResource present = %t, want %t: %#v", hasResource, tt.wantResource, plans)
			}
			if hasVerb != tt.wantVerb {
				t.Fatalf("RemoveSecretReadVerb present = %t, want %t: %#v", hasVerb, tt.wantVerb, plans)
			}
		})
	}
}

func TestBuildMultiChainOmitVerbWhenAnyChainHasNonSecretOnlyResources(t *testing.T) {
	g, findings := scanManifest(t, multipleChainMixedResourceManifest())

	plan := mustSinglePlan(t, g, findings)
	resource := optionByAction(t, plan, RemoveSecretsResource)
	assertCompleteOption(t, resource, 2)
	if _, ok := findOption(plan, RemoveSecretReadVerb); ok {
		t.Fatalf("multi-chain mixed-resource finding produced unsafe RemoveSecretReadVerb option: %#v", plan.Options)
	}
}

func TestBuildMultiChainOmitResourceAndVerbWhenAnyChainHasUnsafeAPIGroup(t *testing.T) {
	safe := testAuthorization()
	safe.BindingSupportedServiceAccountCount = 2
	unsafe := testAuthorization()
	unsafe.BindingName = "read-secrets-wildcard"
	unsafe.BindingSourceReference = "wildcard-binding.yaml#document=1"
	unsafe.RoleName = "wildcard-reader"
	unsafe.RoleSourceReference = "wildcard-role.yaml#document=1"
	unsafe.PermissionSHA256 = "wildcard-permission"
	unsafe.Permission.APIGroups = []string{"*"}
	unsafe.BindingSupportedServiceAccountCount = 2
	g, finding := graphWithAuthorizations(t, []graph.KubernetesCanReadAuthorization{safe, unsafe}, "route", "runs-as", "can-read")

	plan := mustSinglePlan(t, g, []analysis.Finding{finding})
	if _, ok := findOption(plan, RemoveSecretsResource); ok {
		t.Fatalf("multi-chain unsafe API group produced RemoveSecretsResource option: %#v", plan.Options)
	}
	if _, ok := findOption(plan, RemoveSecretReadVerb); ok {
		t.Fatalf("multi-chain unsafe API group produced RemoveSecretReadVerb option: %#v", plan.Options)
	}
	binding := optionByAction(t, plan, NarrowBindingSubject)
	assertCompleteOption(t, binding, 2)
}

func TestBuildWildcardVerbRecommendsExplicitLeastPrivilegeReplacement(t *testing.T) {
	g, findings := scanManifest(t, basicVulnerableManifest(`resources: ["secrets"]`, `verbs: ["*"]`, singleSubjectYAML()))

	plan := mustSinglePlan(t, g, findings)
	option := optionByAction(t, plan, RemoveSecretReadVerb)

	if option.Changes[0].MatchedVerb != "*" {
		t.Fatalf("matched verb = %q, want wildcard", option.Changes[0].MatchedVerb)
	}
	if got := option.Changes[0].Summary; !strings.Contains(got, "Replace wildcard verb *") || !strings.Contains(got, "explicit least-privilege verbs") {
		t.Fatalf("wildcard summary = %q, want explicit least-privilege replacement", got)
	}
	if strings.Contains(option.Changes[0].Summary, "Remove the * verb") {
		t.Fatalf("wildcard summary claims literal removal: %q", option.Changes[0].Summary)
	}
}

func TestBuildNarrowBindingSubjectOnlyForMultiSubjectBinding(t *testing.T) {
	g, findings := scanManifest(t, basicVulnerableManifest(`resources: ["secrets"]`, `verbs: ["get"]`, multiSubjectYAML()))

	plan := mustSinglePlan(t, g, findings)
	option := optionByAction(t, plan, NarrowBindingSubject)
	assertCompleteOption(t, option, 1)
	change := option.Changes[0]
	if change.Target.Kind != "RoleBinding" || change.Target.Namespace != "prod" || change.Target.Name != "read-secrets" {
		t.Fatalf("binding target = %#v", change.Target)
	}
	if change.Subject != "prod/api" {
		t.Fatalf("subject = %q, want affected ServiceAccount only", change.Subject)
	}
	if !strings.Contains(change.Summary, "Remove only ServiceAccount prod/api") || strings.Contains(change.Summary, "delete") {
		t.Fatalf("narrow subject summary = %q", change.Summary)
	}
}

func TestBuildMultipleChainsRequireCoordinatedChanges(t *testing.T) {
	g, findings := scanManifest(t, multipleChainManifest())

	plan := mustSinglePlan(t, g, findings)
	resource := optionByAction(t, plan, RemoveSecretsResource)
	verb := optionByAction(t, plan, RemoveSecretReadVerb)

	assertCompleteOption(t, resource, 2)
	assertCompleteOption(t, verb, 2)
	for _, option := range []Option{resource, verb} {
		if !option.RequiresAllChanges {
			t.Fatalf("option %s requires_all_changes = false, want true", option.Action)
		}
		if len(option.Constraints) != 1 || !strings.Contains(option.Constraints[0], "applied together") {
			t.Fatalf("option %s constraints = %#v, want applied together", option.Action, option.Constraints)
		}
	}
	if resource.Changes[0].PermissionSHA256 == resource.Changes[1].PermissionSHA256 && resource.Changes[0].SourceReference == resource.Changes[1].SourceReference {
		t.Fatalf("coordinated resource changes not distinct: %#v", resource.Changes)
	}
}

func TestBuildDuplicateAuthorizationChainsDeduplicateChanges(t *testing.T) {
	g, finding := graphWithAuthorizations(t, []graph.KubernetesCanReadAuthorization{testAuthorization(), testAuthorization()}, "route", "runs-as", "can-read")

	plans := mustBuild(t, g, []analysis.Finding{finding})

	if len(plans) != 1 {
		t.Fatalf("plan count = %d, want 1", len(plans))
	}
	for _, option := range plans[0].Options {
		if len(option.Changes) != 1 {
			t.Fatalf("option %s change count = %d, want 1: %#v", option.Action, len(option.Changes), option.Changes)
		}
	}
}

func TestBuildDoesNotRecommendResourceNamesForVulnerableSecretListOrWatch(t *testing.T) {
	for _, tt := range []struct {
		name  string
		verbs string
	}{
		{name: "get with resourceNames", verbs: `verbs: ["get"]` + "\n  resourceNames: [\"database-password\"]"},
		{name: "list only", verbs: `verbs: ["list"]`},
		{name: "watch only", verbs: `verbs: ["watch"]`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g, findings := scanManifest(t, basicVulnerableManifest(`resources: ["secrets"]`, tt.verbs, singleSubjectYAML()))
			if len(findings) != 1 {
				t.Fatalf("finding count = %d, want 1", len(findings))
			}

			plans := mustBuild(t, g, findings)
			data := mustMarshal(t, plans)
			if strings.Contains(string(data), "RestrictSecretResourceNames") || strings.Contains(string(data), "resourceNames") {
				t.Fatalf("plans contain resourceNames guidance: %s", data)
			}
		})
	}
}

func TestBuildUnsupportedRuleIDsAreSkipped(t *testing.T) {
	g, finding := graphWithAuthorizations(t, []graph.KubernetesCanReadAuthorization{testAuthorization()}, "route", "runs-as", "can-read")
	finding.RuleID = analysis.RuleID("PP-OTHER")

	plans := mustBuild(t, g, []analysis.Finding{finding})

	if len(plans) != 0 {
		t.Fatalf("plans = %#v, want none", plans)
	}
}

func TestBuildMalformedFindingsReturnDeterministicErrors(t *testing.T) {
	g, finding := graphWithAuthorizations(t, []graph.KubernetesCanReadAuthorization{testAuthorization()}, "route", "runs-as", "can-read")

	tests := []struct {
		name    string
		mutate  func(*analysis.Finding)
		wantErr string
	}{
		{
			name:    "wrong node count",
			mutate:  func(f *analysis.Finding) { f.NodeIDs = f.NodeIDs[:3] },
			wantErr: "path nodes",
		},
		{
			name:    "wrong edge count",
			mutate:  func(f *analysis.Finding) { f.EdgeIDs = f.EdgeIDs[:2] },
			wantErr: "path edges",
		},
		{
			name:    "missing node",
			mutate:  func(f *analysis.Finding) { f.NodeIDs[0] = graph.NodeID("node:missing") },
			wantErr: "missing node",
		},
		{
			name: "wrong continuity",
			mutate: func(f *analysis.Finding) {
				f.NodeIDs[0], f.NodeIDs[1] = f.NodeIDs[1], f.NodeIDs[0]
			},
			wantErr: "has kind",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := cloneFinding(finding)
			tt.mutate(&candidate)

			_, err := Build(g, []analysis.Finding{candidate})
			if err == nil {
				t.Fatal("Build error = nil, want deterministic error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestBuildIsDeterministicAndReadOnly(t *testing.T) {
	g, findings := scanManifest(t, multipleFindingManifest())
	reversedFindings := append([]analysis.Finding(nil), findings...)
	for i, j := 0, len(reversedFindings)-1; i < j; i, j = i+1, j-1 {
		reversedFindings[i], reversedFindings[j] = reversedFindings[j], reversedFindings[i]
	}
	graphBefore := mustMarshal(t, g)
	findingsBefore := mustMarshal(t, findings)

	first := mustBuild(t, g, findings)
	second := mustBuild(t, g, findings)
	reversed := mustBuild(t, g, reversedFindings)

	firstJSON := mustMarshal(t, first)
	if string(firstJSON) != string(mustMarshal(t, second)) {
		t.Fatalf("repeated Build differs:\nfirst:  %s\nsecond: %s", firstJSON, mustMarshal(t, second))
	}
	if string(firstJSON) != string(mustMarshal(t, reversed)) {
		t.Fatalf("reversed input Build differs:\nfirst:    %s\nreversed: %s", firstJSON, mustMarshal(t, reversed))
	}
	if string(mustMarshal(t, g)) != string(graphBefore) {
		t.Fatalf("graph changed after Build:\nbefore: %s\nafter:  %s", graphBefore, mustMarshal(t, g))
	}
	if string(mustMarshal(t, findings)) != string(findingsBefore) {
		t.Fatalf("findings changed after Build:\nbefore: %s\nafter:  %s", findingsBefore, mustMarshal(t, findings))
	}
	if len(first) != 2 {
		t.Fatalf("plan count = %d, want one per finding", len(first))
	}
	if first[0].FindingID > first[1].FindingID {
		t.Fatalf("plans not ordered by finding ID: %#v", first)
	}
}

func TestBuildPlanIDStabilityAndIdentityInputs(t *testing.T) {
	g, finding := graphWithAuthorizations(t, []graph.KubernetesCanReadAuthorization{testAuthorization()}, "route A", "runs-as A", "can-read A")
	plans := mustBuild(t, g, []analysis.Finding{finding})
	repeated := mustBuild(t, g, []analysis.Finding{finding})
	if plans[0].ID != repeated[0].ID {
		t.Fatalf("plan ID changed across repeated Build: %q vs %q", plans[0].ID, repeated[0].ID)
	}

	sameIdentityGraph, sameIdentityFinding := graphWithAuthorizations(t, []graph.KubernetesCanReadAuthorization{testAuthorization()}, "route B", "runs-as B", "can-read B")
	sameIdentityPlans := mustBuild(t, sameIdentityGraph, []analysis.Finding{sameIdentityFinding})
	if plans[0].ID != sameIdentityPlans[0].ID {
		t.Fatalf("plan ID changed when only evidence prose changed: %q vs %q", plans[0].ID, sameIdentityPlans[0].ID)
	}

	changed := testAuthorization()
	changed.RoleName = "other-reader"
	changed.RoleSourceReference = "other-role.yaml#document=1"
	changed.PermissionSHA256 = "changed-permission"
	changedGraph, changedFinding := graphWithAuthorizations(t, []graph.KubernetesCanReadAuthorization{changed}, "route A", "runs-as A", "can-read A")
	changedPlans := mustBuild(t, changedGraph, []analysis.Finding{changedFinding})
	if plans[0].ID == changedPlans[0].ID {
		t.Fatalf("plan ID did not change after identity input changed: %q", plans[0].ID)
	}
}

func TestBuildSecretValuesNeverAppearInPlansOrErrors(t *testing.T) {
	const secretValue = "FAKE_REMEDIATION_SECRET_VALUE_DO_NOT_RETAIN"
	manifest := strings.Replace(
		basicVulnerableManifest(`resources: ["secrets"]`, `verbs: ["get"]`, singleSubjectYAML()),
		"metadata:\n  name: database-password\n  namespace: prod\n---",
		"metadata:\n  name: database-password\n  namespace: prod\ndata:\n  password: "+secretValue+"\n---",
		1,
	)
	g, findings := scanManifest(t, manifest)

	plans := mustBuild(t, g, findings)
	data := mustMarshal(t, plans)
	if strings.Contains(string(data), secretValue) {
		t.Fatalf("plan JSON contains Secret value %q: %s", secretValue, data)
	}

	badFinding := cloneFinding(findings[0])
	badFinding.NodeIDs = badFinding.NodeIDs[:3]
	_, err := Build(g, []analysis.Finding{badFinding})
	if err == nil {
		t.Fatal("Build error = nil, want malformed finding error")
	}
	if strings.Contains(err.Error(), secretValue) {
		t.Fatalf("error contains Secret value %q: %v", secretValue, err)
	}
}

func scanManifest(t *testing.T, content string) (*graph.Graph, []analysis.Finding) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "resources.yaml"), []byte(content), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	resources, err := parserkubernetes.ParseDir(dir)
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	g := graph.New()
	if err := routingkubernetes.AddRoutes(g, resources); err != nil {
		t.Fatalf("add routes: %v", err)
	}
	findings := analysis.Analyze(g)
	return g, findings
}

func basicVulnerableManifest(resources, verbs, subjects string) string {
	return `apiVersion: v1
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
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: prod
rules:
- apiGroups: [""]
  ` + resources + `
  ` + verbs + `
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
` + subjects
}

func singleSubjectYAML() string {
	return `- kind: ServiceAccount
  name: api
  namespace: prod
`
}

func multiSubjectYAML() string {
	return `- kind: ServiceAccount
  name: api
  namespace: prod
- kind: ServiceAccount
  name: worker
  namespace: prod
`
}

func multipleChainManifest() string {
	return `apiVersion: v1
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
  name: database-password
  namespace: prod
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader-a
  namespace: prod
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader-b
  namespace: prod
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-secrets-a
  namespace: prod
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: secret-reader-a
subjects:
- kind: ServiceAccount
  name: api
  namespace: prod
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-secrets-b
  namespace: prod
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: secret-reader-b
subjects:
- kind: ServiceAccount
  name: api
  namespace: prod
`
}

func multipleChainMixedResourceManifest() string {
	return `apiVersion: v1
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
  name: database-password
  namespace: prod
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader-a
  namespace: prod
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader-b
  namespace: prod
rules:
- apiGroups: [""]
  resources: ["secrets", "configmaps"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-secrets-a
  namespace: prod
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: secret-reader-a
subjects:
- kind: ServiceAccount
  name: api
  namespace: prod
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-secrets-b
  namespace: prod
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: secret-reader-b
subjects:
- kind: ServiceAccount
  name: api
  namespace: prod
`
}

func multipleFindingManifest() string {
	return basicVulnerableManifest(`resources: ["secrets"]`, `verbs: ["list"]`, singleSubjectYAML()) + `---
apiVersion: v1
kind: Secret
metadata:
  name: api-token
  namespace: prod
`
}

func graphWithAuthorizations(t *testing.T, authorizations []graph.KubernetesCanReadAuthorization, routeDetail, runsAsDetail, canReadDetail string) (*graph.Graph, analysis.Finding) {
	t.Helper()
	g := graph.New()
	endpoint := mustAddNode(t, g, graph.NewNode(graph.PublicEndpoint, "kubernetes://prod/service/public-api"))
	workload := mustAddNode(t, g, graph.NewNode(graph.Workload, "kubernetes://prod/deployment/api"))
	serviceAccount := mustAddNode(t, g, graph.NewNode(graph.ServiceAccount, "kubernetes://prod/serviceaccount/api"))
	secret := mustAddNode(t, g, graph.NewNode(graph.Secret, "kubernetes://prod/secret/database-password"))
	mustAddEdge(t, g, graph.NewEdge(graph.RoutesTo, endpoint.ID, workload.ID, graph.SourceEvidence{Source: "route.yaml#document=1", Detail: routeDetail}))
	mustAddEdge(t, g, graph.NewEdge(graph.RunsAs, workload.ID, serviceAccount.ID, graph.SourceEvidence{Source: "runs-as.yaml#document=1", Detail: runsAsDetail}))
	canRead := graph.NewEdge(graph.CanRead, serviceAccount.ID, secret.ID, graph.SourceEvidence{Source: "can-read.yaml#document=1", Detail: canReadDetail})
	canRead.Metadata = &graph.EdgeMetadata{KubernetesCanReadAuthorizations: authorizations}
	mustAddEdge(t, g, canRead)
	findings := analysis.Analyze(g)
	if len(findings) != 1 {
		t.Fatalf("finding count = %d, want 1", len(findings))
	}
	return g, findings[0]
}

func testAuthorization() graph.KubernetesCanReadAuthorization {
	return graph.KubernetesCanReadAuthorization{
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
		PermissionSHA256:                    "permission-a",
		Permission: graph.KubernetesPermission{
			APIGroups:     []string{""},
			Resources:     []string{"secrets"},
			ResourceNames: nil,
			Verbs:         []string{"get"},
		},
		MatchedVerb:            "get",
		ScopeKind:              "namespace",
		ScopeName:              "prod",
		SecretNamespace:        "prod",
		SecretName:             "database-password",
		SecretSourceReferences: []string{"secret.yaml#document=1"},
	}
}

func mustBuild(t *testing.T, g *graph.Graph, findings []analysis.Finding) []Plan {
	t.Helper()
	plans, err := Build(g, findings)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return plans
}

func mustBuildWithPins(t *testing.T, g *graph.Graph, findings []analysis.Finding, pins GitHubActionPins) []Plan {
	t.Helper()
	plans, err := BuildWithGitHubActionPins(g, findings, pins)
	if err != nil {
		t.Fatalf("BuildWithGitHubActionPins: %v", err)
	}
	return plans
}

func mustSinglePlan(t *testing.T, g *graph.Graph, findings []analysis.Finding) Plan {
	t.Helper()
	plans := mustBuild(t, g, findings)
	if len(plans) != 1 {
		t.Fatalf("plan count = %d, want 1: %#v", len(plans), plans)
	}
	return plans[0]
}

func scanWorkflowForRemediation(t *testing.T, content string) (*graph.Graph, []analysis.Finding) {
	t.Helper()
	root := t.TempDir()
	workflowDir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o700); err != nil {
		t.Fatalf("mkdir workflow dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "build.yml"), []byte(content), 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}
	resources, err := parsergithubactions.ParseDir(root)
	if err != nil {
		t.Fatalf("parse workflow: %v", err)
	}
	g := graph.New()
	if err := routinggithubactions.AddRoutes(g, resources); err != nil {
		t.Fatalf("route workflow: %v", err)
	}
	return g, analysis.Analyze(g)
}

func onlyFindingByRuleForRemediation(t *testing.T, findings []analysis.Finding, ruleID analysis.RuleID) analysis.Finding {
	t.Helper()
	var matches []analysis.Finding
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			matches = append(matches, finding)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("finding count for %s = %d, want 1: %#v", ruleID, len(matches), findings)
	}
	return matches[0]
}

func optionByAction(t *testing.T, plan Plan, action Action) Option {
	t.Helper()
	option, ok := findOption(plan, action)
	if !ok {
		t.Fatalf("option %s not found in %#v", action, plan.Options)
	}
	return option
}

func findOption(plan Plan, action Action) (Option, bool) {
	for _, option := range plan.Options {
		if option.Action == action {
			return option, true
		}
	}
	return Option{}, false
}

func findOptionInPlans(plans []Plan, action Action) (Option, bool) {
	for _, plan := range plans {
		if option, ok := findOption(plan, action); ok {
			return option, true
		}
	}
	return Option{}, false
}

func assertActions(t *testing.T, plan Plan, want []Action) {
	t.Helper()
	got := make([]Action, 0, len(plan.Options))
	for _, option := range plan.Options {
		got = append(got, option.Action)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("actions = %#v, want %#v", got, want)
	}
}

func assertCompleteOption(t *testing.T, option Option, wantChanges int) {
	t.Helper()
	if len(option.Changes) != wantChanges {
		t.Fatalf("option %s change count = %d, want %d: %#v", option.Action, len(option.Changes), wantChanges, option.Changes)
	}
	for _, change := range option.Changes {
		if change.SourceReference == "" {
			t.Fatalf("change missing source reference: %#v", change)
		}
		if change.Target.Kind == "" || change.Target.Name == "" {
			t.Fatalf("change missing target: %#v", change)
		}
		if change.Summary == "" {
			t.Fatalf("change missing summary: %#v", change)
		}
	}
	if option.Summary == "" || option.Rationale == "" {
		t.Fatalf("option missing summary/rationale: %#v", option)
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

func cloneFinding(finding analysis.Finding) analysis.Finding {
	finding.NodeIDs = append([]graph.NodeID(nil), finding.NodeIDs...)
	finding.EdgeIDs = append([]graph.EdgeID(nil), finding.EdgeIDs...)
	finding.Evidence = append([]analysis.FindingEvidence(nil), finding.Evidence...)
	finding.SourceReferences = append([]string(nil), finding.SourceReferences...)
	return finding
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}
