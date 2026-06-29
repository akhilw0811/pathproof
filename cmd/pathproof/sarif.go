package main

import (
	"encoding/json"
	"io"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"pathproof/internal/analysis"
)

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string                    `json:"id"`
	Name                 string                    `json:"name"`
	ShortDescription     sarifMessage              `json:"shortDescription"`
	FullDescription      sarifMessage              `json:"fullDescription"`
	DefaultConfiguration sarifDefaultConfiguration `json:"defaultConfiguration"`
	Help                 sarifMessage              `json:"help"`
}

type sarifDefaultConfiguration struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID              string                `json:"ruleId"`
	Level               string                `json:"level,omitempty"`
	Message             sarifMessage          `json:"message"`
	Locations           []sarifLocation       `json:"locations,omitempty"`
	PartialFingerprints map[string]string     `json:"partialFingerprints"`
	Properties          sarifResultProperties `json:"properties"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifResultProperties struct {
	FindingID        string   `json:"finding_id"`
	Severity         string   `json:"severity"`
	BaselineStatus   string   `json:"baseline_status,omitempty"`
	NodeIDs          []string `json:"node_ids"`
	EdgeIDs          []string `json:"edge_ids"`
	SourceReferences []string `json:"source_references"`
}

type sarifSourceReference struct {
	display string
	uri     string
}

func writeSARIFReport(w io.Writer, root string, report scanReport) error {
	encoder := json.NewEncoder(w)
	return encoder.Encode(newSARIFLog(root, report))
}

func newSARIFLog(root string, report scanReport) sarifLog {
	results := make([]sarifResult, 0, len(report.Findings))
	for _, finding := range report.Findings {
		results = append(results, newSARIFResult(root, finding))
	}
	return sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name: "PathProof",
						Rules: []sarifRule{
							sarifPublicWorkloadCanReadSecretRule(),
							sarifGitHubActionsUnpinnedActionRule(),
							sarifGitHubActionsUnsafePullRequestTargetCheckoutRule(),
							sarifGitHubActionsDangerousPermissionsRule(),
							sarifAWSIAMRoleAdministrativePermissionsRule(),
							sarifCrossDomainRiskyGitHubActionsCanAssumeAWSRoleRule(),
							sarifCrossDomainRiskyGitHubActionsCanAssumeAWSAdminRoleRule(),
							sarifCrossDomainRiskyGitHubActionsCanAccessAWSS3BucketRule(),
							sarifCrossDomainRiskyGitHubActionsCanAccessSensitiveAWSS3BucketRule(),
						},
					},
				},
				Results: results,
			},
		},
	}
}

func sarifPublicWorkloadCanReadSecretRule() sarifRule {
	const title = "Public workload can read Kubernetes Secret"
	return sarifRule{
		ID:               string(analysis.RulePublicWorkloadCanReadSecret),
		Name:             title,
		ShortDescription: sarifMessage{Text: title},
		FullDescription:  sarifMessage{Text: "Detects a deterministic attack path: PublicEndpoint -> Workload -> ServiceAccount -> Secret."},
		DefaultConfiguration: sarifDefaultConfiguration{
			Level: "error",
		},
		Help: sarifMessage{Text: "PathProof provides deterministic remediation plans for verified paths. Where applicable, NarrowBindingSubject patch support can remove the implicated ServiceAccount subject from a RoleBinding or ClusterRoleBinding."},
	}
}

func sarifGitHubActionsUnpinnedActionRule() sarifRule {
	const title = "GitHub Actions workflow uses an action that is not pinned to a full commit SHA"
	return sarifRule{
		ID:               string(analysis.RuleGitHubActionsUnpinnedAction),
		Name:             title,
		ShortDescription: sarifMessage{Text: title},
		FullDescription:  sarifMessage{Text: "Detects GitHub Actions uses: references that are not pinned to a 40-character commit SHA."},
		DefaultConfiguration: sarifDefaultConfiguration{
			Level: "warning",
		},
		Help: sarifMessage{Text: "Pin GitHub Actions uses: references to a full 40-character commit SHA. Local actions and docker:// actions are outside this rule."},
	}
}

func sarifGitHubActionsUnsafePullRequestTargetCheckoutRule() sarifRule {
	const title = "pull_request_target workflow checks out untrusted pull request head code"
	return sarifRule{
		ID:               string(analysis.RuleGitHubActionsUnsafePullRequestTargetCheckout),
		Name:             title,
		ShortDescription: sarifMessage{Text: title},
		FullDescription:  sarifMessage{Text: "Detects GitHub Actions pull_request_target workflows where actions/checkout is configured to check out pull request head code."},
		DefaultConfiguration: sarifDefaultConfiguration{
			Level: "error",
		},
		Help: sarifMessage{Text: "Avoid checking out untrusted pull request head code in pull_request_target workflows. Use pull_request for untrusted code, or check out a trusted base ref before privileged operations."},
	}
}

func sarifGitHubActionsDangerousPermissionsRule() sarifRule {
	const title = "pull_request_target workflow grants dangerous token permissions"
	return sarifRule{
		ID:               string(analysis.RuleGitHubActionsDangerousPermissions),
		Name:             title,
		ShortDescription: sarifMessage{Text: title},
		FullDescription:  sarifMessage{Text: "Detects GitHub Actions pull_request_target workflows with explicit workflow-level or job-level dangerous token permission grants."},
		DefaultConfiguration: sarifDefaultConfiguration{
			Level: "error",
		},
		Help: sarifMessage{Text: "Avoid granting write-like token permissions in pull_request_target workflows unless explicitly required. PathProof reports explicit workflow-level and job-level grants; exact GitHub permission inheritance and override modeling is future work."},
	}
}

func sarifAWSIAMRoleAdministrativePermissionsRule() sarifRule {
	const title = "AWS IAM role grants administrative permissions"
	return sarifRule{
		ID:               string(analysis.RuleAWSIAMRoleAdministrativePermissions),
		Name:             title,
		ShortDescription: sarifMessage{Text: title},
		FullDescription:  sarifMessage{Text: "Detects local Terraform AWS IAM role permissions that obviously grant administrative access."},
		DefaultConfiguration: sarifDefaultConfiguration{
			Level: "error",
		},
		Help: sarifMessage{Text: "Review the static local Terraform role policy or AdministratorAccess attachment. PathProof does not call AWS APIs, execute Terraform, simulate IAM, or provide remediation for this rule."},
	}
}

func sarifCrossDomainRiskyGitHubActionsCanAssumeAWSRoleRule() sarifRule {
	const title = "Risky GitHub Actions workflow can assume AWS IAM role"
	return sarifRule{
		ID:               string(analysis.RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole),
		Name:             title,
		ShortDescription: sarifMessage{Text: title},
		FullDescription:  sarifMessage{Text: "Detects a deterministic local cross-domain path where a risky GitHub Actions workflow or job has OIDC capability that can assume a statically modeled AWS IAM role trust."},
		DefaultConfiguration: sarifDefaultConfiguration{
			Level: "error",
		},
		Help: sarifMessage{Text: "Review the risky pull_request_target workflow condition and the AWS IAM role trust. PathProof does not execute workflows, generate OIDC tokens, call cloud APIs, simulate IAM permissions, or provide remediation for this rule."},
	}
}

func sarifCrossDomainRiskyGitHubActionsCanAssumeAWSAdminRoleRule() sarifRule {
	const title = "Risky GitHub Actions workflow can assume administrative AWS IAM role"
	return sarifRule{
		ID:               string(analysis.RuleCrossDomainRiskyGitHubActionsCanAssumeAWSAdminRole),
		Name:             title,
		ShortDescription: sarifMessage{Text: title},
		FullDescription:  sarifMessage{Text: "Detects a deterministic local cross-domain path where a risky GitHub Actions workflow or job has OIDC capability that can assume a statically modeled AWS IAM role with administrative permissions."},
		DefaultConfiguration: sarifDefaultConfiguration{
			Level: "error",
		},
		Help: sarifMessage{Text: "Review the risky pull_request_target workflow condition, AWS IAM role trust, and administrative permission. PathProof does not execute workflows, generate OIDC tokens, call cloud APIs, simulate IAM permissions, or provide remediation for this rule."},
	}
}

func sarifCrossDomainRiskyGitHubActionsCanAccessAWSS3BucketRule() sarifRule {
	const title = "Risky GitHub Actions workflow can access AWS S3 bucket"
	return sarifRule{
		ID:               string(analysis.RuleCrossDomainRiskyGitHubActionsCanAccessAWSS3Bucket),
		Name:             title,
		ShortDescription: sarifMessage{Text: title},
		FullDescription:  sarifMessage{Text: "Detects a deterministic local cross-domain path where a risky GitHub Actions workflow or job has OIDC capability that can assume a statically modeled AWS IAM role with explicit static S3 access to a modeled bucket."},
		DefaultConfiguration: sarifDefaultConfiguration{
			Level: "error",
		},
		Help: sarifMessage{Text: "Review the risky pull_request_target workflow condition, AWS IAM role trust, and explicit S3 policy grant. PathProof does not execute workflows, generate OIDC tokens, call cloud APIs, simulate IAM permissions, parse S3 bucket policies, or provide remediation for this rule."},
	}
}

func sarifCrossDomainRiskyGitHubActionsCanAccessSensitiveAWSS3BucketRule() sarifRule {
	const title = "Risky GitHub Actions workflow can access sensitive AWS S3 bucket"
	return sarifRule{
		ID:               string(analysis.RuleCrossDomainRiskyGitHubActionsCanAccessSensitiveAWSS3Bucket),
		Name:             title,
		ShortDescription: sarifMessage{Text: title},
		FullDescription:  sarifMessage{Text: "Detects a deterministic local cross-domain path where a risky GitHub Actions workflow or job has OIDC capability that can assume a statically modeled AWS IAM role with explicit static S3 access to a modeled bucket classified sensitive by conservative local metadata."},
		DefaultConfiguration: sarifDefaultConfiguration{
			Level: "error",
		},
		Help: sarifMessage{Text: "Review the risky pull_request_target workflow condition, AWS IAM role trust, explicit S3 policy grant, and conservative S3 sensitivity reason. PathProof does not execute workflows, generate OIDC tokens, call cloud APIs, simulate IAM permissions, parse S3 bucket policies, perform data discovery, model KMS, or provide remediation for this rule."},
	}
}

func newSARIFResult(root string, finding scanFinding) sarifResult {
	sourceReferences := sarifSourceReferences(root, finding)
	locations := make([]sarifLocation, 0, len(sourceReferences))
	displayReferences := make([]string, 0, len(sourceReferences))
	for _, ref := range sourceReferences {
		locations = append(locations, sarifLocation{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: ref.uri},
			},
		})
		displayReferences = append(displayReferences, ref.display)
	}

	return sarifResult{
		RuleID:    string(finding.RuleID),
		Level:     sarifLevel(finding.Severity),
		Message:   sarifMessage{Text: sarifFindingMessage(finding)},
		Locations: locations,
		PartialFingerprints: map[string]string{
			"pathproofFindingId": string(finding.ID),
		},
		Properties: sarifResultProperties{
			FindingID:        string(finding.ID),
			Severity:         string(finding.Severity),
			BaselineStatus:   string(finding.BaselineStatus),
			NodeIDs:          sarifNodeIDs(finding.Path),
			EdgeIDs:          sarifEdgeIDs(finding.Evidence),
			SourceReferences: displayReferences,
		},
	}
}

func sarifFindingMessage(finding scanFinding) string {
	if (finding.RuleID == analysis.RuleGitHubActionsUnsafePullRequestTargetCheckout || finding.RuleID == analysis.RuleGitHubActionsDangerousPermissions || finding.RuleID == analysis.RuleAWSIAMRoleAdministrativePermissions || finding.RuleID == analysis.RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole || finding.RuleID == analysis.RuleCrossDomainRiskyGitHubActionsCanAssumeAWSAdminRole || finding.RuleID == analysis.RuleCrossDomainRiskyGitHubActionsCanAccessAWSS3Bucket || finding.RuleID == analysis.RuleCrossDomainRiskyGitHubActionsCanAccessSensitiveAWSS3Bucket) && finding.Summary != "" {
		return finding.Summary
	}
	parts := make([]string, 0, len(finding.Path))
	for _, node := range finding.Path {
		parts = append(parts, string(node.Kind)+" "+node.Name)
	}
	return strings.Join(parts, " -> ") + "."
}

func sarifLevel(severity analysis.Severity) string {
	switch severity {
	case analysis.SeverityHigh:
		return "error"
	case analysis.Severity("Medium"):
		return "warning"
	case analysis.Severity("Low"):
		return "note"
	case "":
		return ""
	default:
		return "warning"
	}
}

func sarifNodeIDs(nodes []scanPathNode) []string {
	out := make([]string, 0, len(nodes))
	for _, node := range nodes {
		out = append(out, string(node.ID))
	}
	return out
}

func sarifEdgeIDs(evidence []scanEvidence) []string {
	out := make([]string, 0, len(evidence))
	for _, item := range evidence {
		out = append(out, string(item.EdgeID))
	}
	return out
}

func sarifSourceReferences(root string, finding scanFinding) []sarifSourceReference {
	seen := make(map[string]struct{})
	refs := make([]sarifSourceReference, 0)
	add := func(value string) {
		ref, ok := sarifSourceReferenceFromCleanValue(root, value)
		if !ok {
			return
		}
		if _, exists := seen[ref.display]; exists {
			return
		}
		seen[ref.display] = struct{}{}
		refs = append(refs, ref)
	}
	for _, source := range finding.SARIFSources {
		add(source)
	}
	return refs
}

func sarifSourceReferenceFromCleanValue(root, value string) (sarifSourceReference, bool) {
	if value == "" || strings.TrimSpace(value) != value {
		return sarifSourceReference{}, false
	}
	filename, documentValue, ok := strings.Cut(value, "#document=")
	if ok {
		if filename == "" || documentValue == "" || strings.Contains(documentValue, "#") {
			return sarifSourceReference{}, false
		}
		for _, r := range documentValue {
			if r < '0' || r > '9' {
				return sarifSourceReference{}, false
			}
		}
		document, err := strconv.Atoi(documentValue)
		if err != nil || document <= 0 {
			return sarifSourceReference{}, false
		}
		rel, ok := displayRelativeSourcePath(root, filename)
		if !ok {
			return sarifSourceReference{}, false
		}
		return sarifSourceReference{
			display: rel + "#document=" + documentValue,
			uri:     sarifArtifactURI(rel, "document="+documentValue),
		}, true
	}

	filename, resourceValue, ok := strings.Cut(value, "#resource=")
	if !ok || filename == "" || resourceValue == "" || strings.Contains(resourceValue, "#") || !supportedTerraformSARIFResource(resourceValue) {
		return sarifSourceReference{}, false
	}
	rel, ok := displayRelativeSourcePath(root, filename)
	if !ok {
		return sarifSourceReference{}, false
	}
	return sarifSourceReference{
		display: rel + "#resource=" + resourceValue,
		uri:     sarifArtifactURI(rel, "resource="+resourceValue),
	}, true
}

func supportedTerraformSARIFResource(value string) bool {
	resourceType, resourceName, ok := strings.Cut(value, ".")
	if !ok || resourceName == "" || strings.Contains(resourceName, ".") {
		return false
	}
	switch resourceType {
	case "aws_iam_role_policy", "aws_iam_role_policy_attachment", "aws_s3_bucket":
	default:
		return false
	}
	for _, r := range resourceName {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

func sarifArtifactURI(relPath, fragment string) string {
	uri := url.URL{
		Path:     filepath.ToSlash(relPath),
		Fragment: fragment,
	}
	return uri.String()
}
