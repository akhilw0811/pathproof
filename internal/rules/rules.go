package rules

import "fmt"

type Severity string
type Category string

const (
	RulePublicWorkloadCanReadSecret                                = "PP-K8S-001"
	RuleGitHubActionsUnpinnedAction                                = "PP-GHA-001"
	RuleGitHubActionsUnsafePullRequestTargetCheckout               = "PP-GHA-002"
	RuleGitHubActionsDangerousPermissions                          = "PP-GHA-003"
	RuleAWSIAMRoleAdministrativePermissions                        = "PP-AWS-001"
	RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole              = "PP-XDOMAIN-001"
	RuleCrossDomainRiskyGitHubActionsCanAssumeAWSAdminRole         = "PP-XDOMAIN-002"
	RuleCrossDomainRiskyGitHubActionsCanAccessAWSS3Bucket          = "PP-XDOMAIN-003"
	RuleCrossDomainRiskyGitHubActionsCanAccessSensitiveAWSS3Bucket = "PP-XDOMAIN-004"

	SeverityHigh   Severity = "High"
	SeverityMedium Severity = "Medium"

	CategoryKubernetes    Category = "kubernetes"
	CategoryGitHubActions Category = "github-actions"
	CategoryAWS           Category = "aws"
	CategoryCrossDomain   Category = "cross-domain"
)

type Rule struct {
	ID          string
	Title       string
	Severity    Severity
	SARIFLevel  string
	Category    Category
	Description string
}

var orderedRules = []Rule{
	{
		ID:          RulePublicWorkloadCanReadSecret,
		Title:       "Public workload can read Kubernetes Secret",
		Severity:    SeverityHigh,
		SARIFLevel:  "error",
		Category:    CategoryKubernetes,
		Description: "Detects a deterministic attack path: PublicEndpoint -> Workload -> ServiceAccount -> Secret.",
	},
	{
		ID:          RuleGitHubActionsUnpinnedAction,
		Title:       "GitHub Actions workflow uses an action that is not pinned to a full commit SHA",
		Severity:    SeverityMedium,
		SARIFLevel:  "warning",
		Category:    CategoryGitHubActions,
		Description: "Detects GitHub Actions uses: references that are not pinned to a 40-character commit SHA.",
	},
	{
		ID:          RuleGitHubActionsUnsafePullRequestTargetCheckout,
		Title:       "pull_request_target workflow checks out untrusted pull request head code",
		Severity:    SeverityHigh,
		SARIFLevel:  "error",
		Category:    CategoryGitHubActions,
		Description: "Detects GitHub Actions pull_request_target workflows where actions/checkout is configured to check out pull request head code.",
	},
	{
		ID:          RuleGitHubActionsDangerousPermissions,
		Title:       "pull_request_target workflow grants dangerous token permissions",
		Severity:    SeverityHigh,
		SARIFLevel:  "error",
		Category:    CategoryGitHubActions,
		Description: "Detects GitHub Actions pull_request_target workflows with explicit workflow-level or job-level dangerous token permission grants.",
	},
	{
		ID:          RuleAWSIAMRoleAdministrativePermissions,
		Title:       "AWS IAM role grants administrative permissions",
		Severity:    SeverityHigh,
		SARIFLevel:  "error",
		Category:    CategoryAWS,
		Description: "Detects local Terraform AWS IAM role permissions that obviously grant administrative access.",
	},
	{
		ID:          RuleCrossDomainRiskyGitHubActionsCanAssumeAWSRole,
		Title:       "Risky GitHub Actions workflow can assume AWS IAM role",
		Severity:    SeverityHigh,
		SARIFLevel:  "error",
		Category:    CategoryCrossDomain,
		Description: "Detects a deterministic local cross-domain path where a risky GitHub Actions workflow or job has OIDC capability that can assume a statically modeled AWS IAM role trust.",
	},
	{
		ID:          RuleCrossDomainRiskyGitHubActionsCanAssumeAWSAdminRole,
		Title:       "Risky GitHub Actions workflow can assume administrative AWS IAM role",
		Severity:    SeverityHigh,
		SARIFLevel:  "error",
		Category:    CategoryCrossDomain,
		Description: "Detects a deterministic local cross-domain path where a risky GitHub Actions workflow or job has OIDC capability that can assume a statically modeled AWS IAM role with administrative permissions.",
	},
	{
		ID:          RuleCrossDomainRiskyGitHubActionsCanAccessAWSS3Bucket,
		Title:       "Risky GitHub Actions workflow can access AWS S3 bucket",
		Severity:    SeverityHigh,
		SARIFLevel:  "error",
		Category:    CategoryCrossDomain,
		Description: "Detects a deterministic local cross-domain path where a risky GitHub Actions workflow or job has OIDC capability that can assume a statically modeled AWS IAM role with explicit static S3 access to a modeled bucket.",
	},
	{
		ID:          RuleCrossDomainRiskyGitHubActionsCanAccessSensitiveAWSS3Bucket,
		Title:       "Risky GitHub Actions workflow can access sensitive AWS S3 bucket",
		Severity:    SeverityHigh,
		SARIFLevel:  "error",
		Category:    CategoryCrossDomain,
		Description: "Detects a deterministic local cross-domain path where a risky GitHub Actions workflow or job has OIDC capability that can assume a statically modeled AWS IAM role with explicit static S3 access to a modeled bucket classified sensitive by conservative local metadata.",
	},
}

var rulesByID = func() map[string]Rule {
	out := make(map[string]Rule, len(orderedRules))
	for _, rule := range orderedRules {
		out[rule.ID] = rule
	}
	return out
}()

func All() []Rule {
	return append([]Rule(nil), orderedRules...)
}

func IDs() []string {
	out := make([]string, 0, len(orderedRules))
	for _, rule := range orderedRules {
		out = append(out, rule.ID)
	}
	return out
}

func Lookup(id string) (Rule, bool) {
	rule, ok := rulesByID[id]
	return rule, ok
}

func MustLookup(id string) Rule {
	rule, ok := Lookup(id)
	if !ok {
		panic(fmt.Sprintf("unknown PathProof rule ID %q", id))
	}
	return rule
}
