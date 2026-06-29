package terraform

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestParseDirParsesAWSIAMRoleHeredocTrustPolicy(t *testing.T) {
	root := t.TempDir()
	path := writeTerraform(t, root, "main.tf", `resource "aws_iam_role" "deploy" {
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:owner/repo:ref:refs/heads/main"
        }
      }
    }
  ]
}
EOF
}
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := Resources{IAMRoles: []IAMRole{{
		ResourceType: "aws_iam_role",
		ResourceName: "deploy",
		Source:       Source{Filename: path, RelativePath: "main.tf", ResourceType: "aws_iam_role", ResourceName: "deploy"},
		Trusts: []OIDCTrust{{
			StatementIndex: 0,
			Issuer:         githubActionsIssuer,
			SubjectPatterns: []SubjectPattern{{
				Operator: "StringEquals",
				Pattern:  "repo:owner/repo:ref:refs/heads/main",
			}},
			Audiences: []string{"sts.amazonaws.com"},
		}},
	}}}
	if !reflect.DeepEqual(resources, want) {
		t.Fatalf("resources = %#v, want %#v", resources, want)
	}
}

func TestParseDirParsesAWSIAMRoleQuotedJSONTrustPolicy(t *testing.T) {
	root := t.TempDir()
	policy := `{"Statement":{"Effect":"Allow","Principal":{"Federated":["arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"]},"Action":["sts:AssumeRoleWithWebIdentity"],"Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":["repo:owner/repo:*"],"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}}}`
	writeTerraform(t, root, "role.tf", `resource "aws_iam_role" "deploy" {
  assume_role_policy = `+strconvQuote(policy)+`
}
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	if len(resources.IAMRoles) != 1 || len(resources.IAMRoles[0].Trusts) != 1 {
		t.Fatalf("resources = %#v, want one role trust", resources)
	}
	trust := resources.IAMRoles[0].Trusts[0]
	if trust.SubjectPatterns[0] != (SubjectPattern{Operator: "StringLike", Pattern: "repo:owner/repo:*"}) {
		t.Fatalf("subject patterns = %#v", trust.SubjectPatterns)
	}
}

func TestParseDirParsesAWSIAMRolePolicyStaticHeredocPermission(t *testing.T) {
	root := t.TempDir()
	path := writeTerraform(t, root, "iam.tf", `resource "aws_iam_role" "deploy" {
}

resource "aws_iam_role_policy" "admin" {
  role = aws_iam_role.deploy.id
  policy = <<EOF
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF
}
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if len(resources.IAMRoles) != 1 || len(resources.IAMRoles[0].Permissions) != 1 {
		t.Fatalf("resources = %#v, want one role permission", resources)
	}
	permission := resources.IAMRoles[0].Permissions[0]
	if permission.Kind != iamPermissionKindInlinePolicy || permission.PolicyResourceName != "admin" || permission.AttachedRoleResourceName != "deploy" {
		t.Fatalf("permission = %#v, want inline admin policy attached to deploy", permission)
	}
	if !permission.Administrative || permission.AdminReason != adminReasonActionStarResourceStar {
		t.Fatalf("permission admin = %v reason %q, want %q", permission.Administrative, permission.AdminReason, adminReasonActionStarResourceStar)
	}
	if !reflect.DeepEqual(permission.Actions, []string{"*"}) || !reflect.DeepEqual(permission.Resources, []string{"*"}) {
		t.Fatalf("permission action/resource = %#v/%#v, want */*", permission.Actions, permission.Resources)
	}
	if permission.Source != (Source{Filename: path, RelativePath: "iam.tf", ResourceType: "aws_iam_role_policy", ResourceName: "admin"}) {
		t.Fatalf("permission source = %#v", permission.Source)
	}
}

func TestParseDirParsesAWSIAMRolePolicyQuotedStaticJSONPermission(t *testing.T) {
	root := t.TempDir()
	policy := `{"Statement":{"Effect":"Allow","Action":"*:*","Resource":"*"}}`
	writeTerraform(t, root, "iam.tf", `resource "aws_iam_role" "deploy" {
}

resource "aws_iam_role_policy" "admin" {
  role = aws_iam_role.deploy.name
  policy = `+strconvQuote(policy)+`
}
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if len(resources.IAMRoles) != 1 || len(resources.IAMRoles[0].Permissions) != 1 {
		t.Fatalf("resources = %#v, want one role permission", resources)
	}
	permission := resources.IAMRoles[0].Permissions[0]
	if !permission.Administrative || permission.AdminReason != adminReasonActionServiceStarResource {
		t.Fatalf("permission = %#v, want *:* admin reason", permission)
	}
	if !reflect.DeepEqual(permission.Actions, []string{"*:*"}) || !reflect.DeepEqual(permission.Resources, []string{"*"}) {
		t.Fatalf("permission action/resource = %#v/%#v, want *:*/ *", permission.Actions, permission.Resources)
	}
}

func TestParseDirParsesAdministratorAccessRolePolicyAttachment(t *testing.T) {
	root := t.TempDir()
	writeTerraform(t, root, "iam.tf", `resource "aws_iam_role" "deploy" {
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.deploy.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if len(resources.IAMRoles) != 1 || len(resources.IAMRoles[0].Permissions) != 1 {
		t.Fatalf("resources = %#v, want one role permission", resources)
	}
	permission := resources.IAMRoles[0].Permissions[0]
	if permission.Kind != iamPermissionKindManagedPolicy || permission.ManagedPolicyARN != administratorAccessPolicyARN {
		t.Fatalf("permission = %#v, want AdministratorAccess managed policy", permission)
	}
	if !permission.Administrative || permission.AdminReason != adminReasonAdministratorAccess {
		t.Fatalf("permission = %#v, want administrator access admin reason", permission)
	}
}

func TestParseDirParsesAWSS3BucketWithLiteralBucketName(t *testing.T) {
	root := t.TempDir()
	path := writeTerraform(t, root, "s3.tf", `resource "aws_s3_bucket" "artifacts" {
  bucket = "prod-artifacts"
}
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []S3Bucket{{
		ResourceType: "aws_s3_bucket",
		ResourceName: "artifacts",
		BucketName:   "prod-artifacts",
		Source:       Source{Filename: path, RelativePath: "s3.tf", ResourceType: "aws_s3_bucket", ResourceName: "artifacts"},
		SensitivityReasons: []S3BucketSensitivityReason{{
			Source:       "bucket_name",
			MatchedToken: "prod",
			SourceRef:    "s3.tf#resource=aws_s3_bucket.artifacts",
		}},
	}}
	if !reflect.DeepEqual(resources.S3Buckets, want) {
		t.Fatalf("s3 buckets = %#v, want %#v", resources.S3Buckets, want)
	}
}

func TestParseDirClassifiesAWSS3BucketSensitivityFromNameTokens(t *testing.T) {
	tests := []struct {
		name       string
		bucketName string
		wantTokens []string
	}{
		{name: "prod data backups", bucketName: "prod-data-backups", wantTokens: []string{"backups", "prod"}},
		{name: "mixed case prod data backups", bucketName: "Prod-Data-Backups", wantTokens: []string{"backups", "prod"}},
		{name: "customer pii store", bucketName: "customer-pii-store", wantTokens: []string{"customer", "pii"}},
		{name: "product is not prod", bucketName: "myproduct-assets"},
		{name: "catalogs is not logs", bucketName: "catalogs"},
		{name: "db full token only", bucketName: "db-backup", wantTokens: []string{"backup", "db"}},
		{name: "dbbackup is not db", bucketName: "dbbackup"},
		{name: "customerdb is not db", bucketName: "customerdb"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeTerraform(t, root, "s3.tf", `resource "aws_s3_bucket" "artifacts" {
  bucket = "`+tt.bucketName+`"
}
`)

			resources, err := ParseDir(root)
			if err != nil {
				t.Fatalf("parse dir: %v", err)
			}
			if len(resources.S3Buckets) != 1 {
				t.Fatalf("s3 buckets = %#v, want one bucket", resources.S3Buckets)
			}
			if resources.S3Buckets[0].BucketName != tt.bucketName {
				t.Fatalf("bucket name = %q, want literal %q", resources.S3Buckets[0].BucketName, tt.bucketName)
			}
			gotTokens := sensitivityNameTokens(resources.S3Buckets[0].SensitivityReasons)
			if !reflect.DeepEqual(gotTokens, tt.wantTokens) {
				t.Fatalf("tokens = %#v, want %#v", gotTokens, tt.wantTokens)
			}
			data, err := json.Marshal(resources)
			if err != nil {
				t.Fatalf("marshal resources: %v", err)
			}
			for _, forbidden := range []string{"resource \"aws_s3_bucket\"", "bucket ="} {
				if strings.Contains(string(data), forbidden) {
					t.Fatalf("parser output contains raw Terraform %q: %s", forbidden, data)
				}
			}
		})
	}
}

func TestParseDirClassifiesAWSS3BucketSensitivityFromAllowedStaticTags(t *testing.T) {
	root := t.TempDir()
	writeTerraform(t, root, "s3.tf", `resource "aws_s3_bucket" "artifacts" {
  bucket = "assets"
  tags = {
    DataClassification = "Sensitive"
    "Classification" = "CONFIDENTIAL"
    Environment = "production"
  }
}
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if len(resources.S3Buckets) != 1 {
		t.Fatalf("s3 buckets = %#v, want one bucket", resources.S3Buckets)
	}
	got := resources.S3Buckets[0].SensitivityReasons
	want := []S3BucketSensitivityReason{
		{Source: "tag", Key: "Classification", Value: "confidential", SourceRef: "s3.tf#resource=aws_s3_bucket.artifacts"},
		{Source: "tag", Key: "DataClassification", Value: "sensitive", SourceRef: "s3.tf#resource=aws_s3_bucket.artifacts"},
		{Source: "tag", Key: "Environment", Value: "production", SourceRef: "s3.tf#resource=aws_s3_bucket.artifacts"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sensitivity reasons = %#v, want %#v", got, want)
	}
}

func TestParseDirIgnoresUnsupportedAWSS3BucketSensitivityTags(t *testing.T) {
	root := t.TempDir()
	writeTerraform(t, root, "s3.tf", `provider "aws" {
  default_tags {
    tags = {
      Environment = "production"
      DataClassification = "FAKE_TF_PROVIDER_TAG_SECRET_DO_NOT_RETAIN"
    }
  }
}

resource "aws_iam_role" "tagged" {
  tags = {
    DataClassification = "Sensitive"
  }
}

resource "aws_s3_bucket" "artifacts" {
  bucket = "assets"
  tags = {
    Owner = "FAKE_TF_UNRELATED_TAG_SECRET_DO_NOT_RETAIN"
    DataClassification = var.classification
    Classification = "${var.classification}"
    Sensitivity = upper("sensitive")
    Environment = "dev"
    "${var.dynamic_key}" = "Sensitive"
  }
}
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if len(resources.S3Buckets) != 1 {
		t.Fatalf("s3 buckets = %#v, want one bucket", resources.S3Buckets)
	}
	if len(resources.S3Buckets[0].SensitivityReasons) != 0 {
		t.Fatalf("sensitivity reasons = %#v, want none", resources.S3Buckets[0].SensitivityReasons)
	}
	data, err := json.Marshal(resources)
	if err != nil {
		t.Fatalf("marshal resources: %v", err)
	}
	for _, forbidden := range []string{
		"FAKE_TF_PROVIDER_TAG_SECRET_DO_NOT_RETAIN",
		"FAKE_TF_UNRELATED_TAG_SECRET_DO_NOT_RETAIN",
		"Owner",
		"dev",
		"var.classification",
		"${",
		"upper(",
		"default_tags",
		"tags",
	} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("parser output contains %q: %s", forbidden, data)
		}
	}
}

func TestParseDirAWSS3BucketSensitivityReasonsAreDedupeSortedAndSanitized(t *testing.T) {
	root := t.TempDir()
	writeTerraform(t, root, "s3.tf", `resource "aws_s3_bucket" "artifacts" {
  bucket = "prod-prod-pii"
  tags = {
    Environment = "PROD"
    Environment = "prod"
    Sensitivity = "PII"
    Owner = "FAKE_TF_SORTED_TAG_SECRET_DO_NOT_RETAIN"
  }
}
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if len(resources.S3Buckets) != 1 {
		t.Fatalf("s3 buckets = %#v, want one bucket", resources.S3Buckets)
	}
	got := resources.S3Buckets[0].SensitivityReasons
	want := []S3BucketSensitivityReason{
		{Source: "bucket_name", MatchedToken: "pii", SourceRef: "s3.tf#resource=aws_s3_bucket.artifacts"},
		{Source: "bucket_name", MatchedToken: "prod", SourceRef: "s3.tf#resource=aws_s3_bucket.artifacts"},
		{Source: "tag", Key: "Environment", Value: "prod", SourceRef: "s3.tf#resource=aws_s3_bucket.artifacts"},
		{Source: "tag", Key: "Sensitivity", Value: "pii", SourceRef: "s3.tf#resource=aws_s3_bucket.artifacts"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sensitivity reasons = %#v, want %#v", got, want)
	}
	data, err := json.Marshal(resources)
	if err != nil {
		t.Fatalf("marshal resources: %v", err)
	}
	if strings.Contains(string(data), "FAKE_TF_SORTED_TAG_SECRET_DO_NOT_RETAIN") || strings.Contains(string(data), "Owner") {
		t.Fatalf("parser output retained unrelated tag: %s", data)
	}
}

func TestParseDirIgnoresAWSS3BucketWithoutStaticLiteralBucketName(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
	}{
		{
			name: "omitted bucket",
			terraform: `resource "aws_s3_bucket" "artifacts" {
}
`,
		},
		{
			name: "interpolated bucket",
			terraform: `resource "aws_s3_bucket" "artifacts" {
  bucket = "prod-${var.name}"
}
`,
		},
		{
			name: "reference bucket",
			terraform: `resource "aws_s3_bucket" "artifacts" {
  bucket = local.bucket_name
}
`,
		},
		{
			name: "underscore bucket",
			terraform: `resource "aws_s3_bucket" "artifacts" {
  bucket = "prod_data_backups"
}
`,
		},
		{
			name: "secret-like bucket",
			terraform: `resource "aws_s3_bucket" "artifacts" {
  bucket = "prod-token-artifacts"
}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeTerraform(t, root, "s3.tf", tt.terraform)

			resources, err := ParseDir(root)
			if err != nil {
				t.Fatalf("parse dir: %v", err)
			}
			if len(resources.S3Buckets) != 0 {
				t.Fatalf("s3 buckets = %#v, want none", resources.S3Buckets)
			}
			data, err := json.Marshal(resources)
			if err != nil {
				t.Fatalf("marshal resources: %v", err)
			}
			for _, forbidden := range []string{"${", "local.bucket_name", "prod_data_backups", "prod-token-artifacts"} {
				if strings.Contains(string(data), forbidden) {
					t.Fatalf("parser output contains %q: %s", forbidden, data)
				}
			}
		})
	}
}

func TestParseDirAWSS3BucketOutputExcludesTagsAndProviderValues(t *testing.T) {
	root := t.TempDir()
	writeTerraform(t, root, "s3.tf", `provider "aws" {
  access_key = "FAKE_TF_S3_ACCESS_KEY_DO_NOT_RETAIN"
}

resource "aws_s3_bucket" "artifacts" {
  bucket = "prod-artifacts"
  tags = {
    Owner = "FAKE_TF_S3_TAG_SECRET_DO_NOT_RETAIN"
  }
}
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if len(resources.S3Buckets) != 1 {
		t.Fatalf("s3 buckets = %#v, want one", resources.S3Buckets)
	}
	data, err := json.Marshal(resources)
	if err != nil {
		t.Fatalf("marshal resources: %v", err)
	}
	for _, forbidden := range []string{"FAKE_TF_S3_ACCESS_KEY_DO_NOT_RETAIN", "FAKE_TF_S3_TAG_SECRET_DO_NOT_RETAIN", "access_key", "tags"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("parser output contains %q: %s", forbidden, data)
		}
	}
}

func TestParseDirParsesInlineS3ReadPolicyForStaticBucketARNs(t *testing.T) {
	root := t.TempDir()
	writeTerraform(t, root, "iam.tf", `resource "aws_iam_role" "deploy" {
}

resource "aws_iam_role_policy" "read_artifacts" {
  role = aws_iam_role.deploy.id
  policy = `+strconvQuote(`{"Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::prod-artifacts"},{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::prod-artifacts/*"}]}`)+`
}
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if len(resources.IAMRoles) != 1 || len(resources.IAMRoles[0].Permissions) != 2 {
		t.Fatalf("resources = %#v, want two S3 read permissions", resources)
	}
	gotActions := []string{resources.IAMRoles[0].Permissions[0].Actions[0], resources.IAMRoles[0].Permissions[1].Actions[0]}
	gotResources := []string{resources.IAMRoles[0].Permissions[0].Resources[0], resources.IAMRoles[0].Permissions[1].Resources[0]}
	wantActions := []string{"s3:ListBucket", "s3:GetObject"}
	wantResources := []string{"arn:aws:s3:::prod-artifacts", "arn:aws:s3:::prod-artifacts/*"}
	if !reflect.DeepEqual(gotActions, wantActions) || !reflect.DeepEqual(gotResources, wantResources) {
		t.Fatalf("actions/resources = %#v/%#v, want %#v/%#v", gotActions, gotResources, wantActions, wantResources)
	}
}

func TestParseDirParsesInlineS3WritePolicyForStaticObjectARNs(t *testing.T) {
	root := t.TempDir()
	writeTerraform(t, root, "iam.tf", `resource "aws_iam_role" "deploy" {
}

resource "aws_iam_role_policy" "write_artifacts" {
  role = aws_iam_role.deploy.id
  policy = `+strconvQuote(`{"Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::prod-artifacts/*"},{"Effect":"Allow","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::prod-artifacts/*"}]}`)+`
}
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if len(resources.IAMRoles) != 1 || len(resources.IAMRoles[0].Permissions) != 2 {
		t.Fatalf("resources = %#v, want two S3 write permissions", resources)
	}
	gotActions := []string{resources.IAMRoles[0].Permissions[0].Actions[0], resources.IAMRoles[0].Permissions[1].Actions[0]}
	wantActions := []string{"s3:PutObject", "s3:DeleteObject"}
	if !reflect.DeepEqual(gotActions, wantActions) {
		t.Fatalf("actions = %#v, want %#v", gotActions, wantActions)
	}
}

func TestParseDirIgnoresUnsupportedS3PolicyInputs(t *testing.T) {
	root := t.TempDir()
	writeTerraform(t, root, "iam.tf", `variable "bucket" {
  default = "FAKE_TF_S3_VARIABLE_SECRET_DO_NOT_RETAIN"
}

resource "aws_iam_role" "deploy" {
}

resource "aws_iam_role_policy" "unsupported" {
  role = aws_iam_role.deploy.id
  policy = `+strconvQuote(`{"Statement":[
    {"Effect":"Allow","Action":"s3:*Object","Resource":"arn:aws:s3:::prod-artifacts/*"},
    {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::*"},
    {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::prod-artifacts/prefix/*"},
    {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::prod-*"},
    {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::${bucket}/*"},
    {"Effect":"Allow","NotAction":"s3:DeleteObject","Resource":"arn:aws:s3:::prod-artifacts/*"},
    {"Effect":"Allow","Action":"s3:GetObject","NotResource":"arn:aws:s3:::prod-artifacts/*"},
    {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::prod-artifacts/*","Condition":{"StringEquals":{"aws:username":"FAKE_TF_S3_CONDITION_SECRET_DO_NOT_RETAIN"}}}
  ]}`)+`
}
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if len(resources.IAMRoles) != 0 {
		t.Fatalf("resources = %#v, want unsupported S3 policy ignored", resources)
	}
	data, err := json.Marshal(resources)
	if err != nil {
		t.Fatalf("marshal resources: %v", err)
	}
	for _, forbidden := range []string{"s3:*Object", "arn:aws:s3:::*", "prefix", "prod-*", "${bucket}", "NotAction", "NotResource", "Condition", "FAKE_TF_S3_VARIABLE_SECRET_DO_NOT_RETAIN", "FAKE_TF_S3_CONDITION_SECRET_DO_NOT_RETAIN"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("parser output contains %q: %s", forbidden, data)
		}
	}
}

func TestParseDirIAMRolePolicyRoleReferenceMustBeExact(t *testing.T) {
	tests := []struct {
		name      string
		roleValue string
		wantPerms int
	}{
		{name: "exact id reference", roleValue: "aws_iam_role.deploy.id", wantPerms: 1},
		{name: "exact name reference", roleValue: "aws_iam_role.deploy.name", wantPerms: 1},
		{name: "indexed id reference", roleValue: "aws_iam_role.deploy.id[count.index]", wantPerms: 0},
		{name: "trailing attribute", roleValue: "aws_iam_role.deploy.id.foo", wantPerms: 0},
		{name: "unsupported role attribute", roleValue: "aws_iam_role.deploy.arn", wantPerms: 0},
		{name: "comparison expression", roleValue: `aws_iam_role.deploy.id == "x"`, wantPerms: 0},
		{name: "function expression", roleValue: `try(aws_iam_role.deploy.id, "")`, wantPerms: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeTerraform(t, root, "iam.tf", `resource "aws_iam_role" "deploy" {
}

resource "aws_iam_role_policy" "admin" {
  role = `+tt.roleValue+`
  policy = "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}}"
}
`)

			resources, err := ParseDir(root)
			if err != nil {
				t.Fatalf("parse dir: %v", err)
			}
			gotPerms := 0
			for _, role := range resources.IAMRoles {
				gotPerms += len(role.Permissions)
			}
			if gotPerms != tt.wantPerms {
				t.Fatalf("permission count = %d, want %d: %#v", gotPerms, tt.wantPerms, resources)
			}
			data, err := json.Marshal(resources)
			if err != nil {
				t.Fatalf("marshal resources: %v", err)
			}
			for _, forbidden := range []string{"count.index", "try(", " == ", ".arn", ".id.foo", "${"} {
				if strings.Contains(string(data), forbidden) {
					t.Fatalf("parser output contains dynamic role expression %q: %s", forbidden, data)
				}
			}
		})
	}
}

func TestParseDirIAMRolePolicyInterpolatedRoleExpressionIsIgnored(t *testing.T) {
	root := t.TempDir()
	writeTerraform(t, root, "iam.tf", `resource "aws_iam_role" "deploy" {
}

resource "aws_iam_role_policy" "admin" {
  role = "${aws_iam_role.deploy.id}"
  policy = "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}}"
}
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if len(resources.IAMRoles) != 0 {
		t.Fatalf("resources = %#v, want no modeled permission role", resources)
	}
	data, err := json.Marshal(resources)
	if err != nil {
		t.Fatalf("marshal resources: %v", err)
	}
	if strings.Contains(string(data), "aws_iam_role.deploy.id") || strings.Contains(string(data), "${") {
		t.Fatalf("parser output contains interpolated role expression: %s", data)
	}
}

func TestParseDirQuotedLiteralRoleValuesAreIgnored(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
	}{
		{
			name: "does not match explicit static name",
			terraform: `resource "aws_iam_role" "deploy" {
  name = "prod-deploy"
}

resource "aws_iam_role_policy" "admin" {
  role = "prod-deploy"
  policy = "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}}"
}
`,
		},
		{
			name: "does not match resource label",
			terraform: `resource "aws_iam_role" "deploy" {
}

resource "aws_iam_role_policy" "admin" {
  role = "deploy"
  policy = "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}}"
}
`,
		},
		{
			name: "duplicate static names are ambiguous",
			terraform: `resource "aws_iam_role" "deploy_a" {
  name = "prod-deploy"
}

resource "aws_iam_role" "deploy_b" {
  name = "prod-deploy"
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = "prod-deploy"
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
`,
		},
		{
			name: "arn string ignored",
			terraform: `resource "aws_iam_role" "deploy" {
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = "arn:aws:iam::123456789012:role/prod-deploy"
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeTerraform(t, root, "iam.tf", tt.terraform)

			resources, err := ParseDir(root)
			if err != nil {
				t.Fatalf("parse dir: %v", err)
			}
			gotPerms := 0
			for _, role := range resources.IAMRoles {
				gotPerms += len(role.Permissions)
			}
			if gotPerms != 0 {
				t.Fatalf("permission count = %d, want 0: %#v", gotPerms, resources)
			}
		})
	}
}

func TestParseDirIgnoresUnsupportedIAMPermissionInputs(t *testing.T) {
	root := t.TempDir()
	writeTerraform(t, root, "iam.tf", `variable "secret" {
  default = "FAKE_TF_IAM_VARIABLE_SECRET_DO_NOT_RETAIN"
}

provider "aws" {
  access_key = "FAKE_TF_IAM_ACCESS_KEY_DO_NOT_RETAIN"
}

resource "aws_iam_role" "deploy" {
  assume_role_policy = <<EOF
`+validTrustPolicyJSON("repo:owner/repo:pull_request")+`
EOF
}

resource "aws_iam_role_policy" "dynamic" {
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.admin.json
}

resource "aws_iam_role_policy" "not_action" {
  role = aws_iam_role.deploy.id
  policy = "{\"Statement\":{\"Effect\":\"Allow\",\"NotAction\":\"iam:DeleteUser\",\"Resource\":\"*\"}}"
}

resource "aws_iam_role_policy" "conditioned" {
  role = aws_iam_role.deploy.id
  policy = "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\",\"Condition\":{\"StringEquals\":{\"aws:username\":\"FAKE_TF_IAM_CONDITION_SECRET_DO_NOT_RETAIN\"}}}}"
}

resource "aws_iam_role_policy" "secret_action" {
  role = aws_iam_role.deploy.id
  policy = "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"secretsmanager:GetSecretValue\",\"Resource\":\"*\"}}"
}

resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.deploy.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_policy" "ignored" {
  policy = "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}}"
}
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if len(resources.IAMRoles) != 1 || len(resources.IAMRoles[0].Permissions) != 0 {
		t.Fatalf("resources = %#v, want trust role with no supported permissions", resources)
	}
	data, err := json.Marshal(resources)
	if err != nil {
		t.Fatalf("marshal resources: %v", err)
	}
	for _, forbidden := range []string{
		"FAKE_TF_IAM_VARIABLE_SECRET_DO_NOT_RETAIN",
		"FAKE_TF_IAM_ACCESS_KEY_DO_NOT_RETAIN",
		"FAKE_TF_IAM_CONDITION_SECRET_DO_NOT_RETAIN",
		"secretsmanager:GetSecretValue",
		"ReadOnlyAccess",
		"aws_iam_policy_document",
		"aws_iam_policy",
		"Condition",
		"NotAction",
	} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("parser output contains %q: %s", forbidden, data)
		}
	}
}

func TestParseDirMalformedInlinePolicyJSONErrorIsSanitized(t *testing.T) {
	root := t.TempDir()
	writeTerraform(t, root, "iam.tf", `resource "aws_iam_role" "deploy" {
}

resource "aws_iam_role_policy" "admin" {
  role = aws_iam_role.deploy.id
  policy = <<EOF
{"Statement": []} FAKE_TF_IAM_TRAILING_SECRET_DO_NOT_RETAIN
EOF
}
`)

	resources, err := ParseDir(root)
	if err == nil {
		t.Fatalf("parse dir error = nil, resources = %#v", resources)
	}
	message := err.Error()
	if !strings.Contains(message, "aws_iam_role_policy.admin") || !strings.Contains(message, "invalid policy JSON") {
		t.Fatalf("error = %q, want sanitized policy JSON error with resource context", message)
	}
	for _, forbidden := range []string{"FAKE_TF_IAM_TRAILING_SECRET_DO_NOT_RETAIN", "Statement", "policy ="} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("error contains %q: %s", forbidden, message)
		}
	}
}

func TestParseDirRequiresExactGitHubOIDCProviderPath(t *testing.T) {
	tests := []struct {
		name        string
		principal   string
		wantTrusts  int
		wantMessage string
	}{
		{
			name:       "exact provider path",
			principal:  "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
			wantTrusts: 1,
		},
		{
			name:       "exact provider path in aws us gov partition",
			principal:  "arn:aws-us-gov:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
			wantTrusts: 1,
		},
		{
			name:      "evil prefix",
			principal: "arn:aws:iam::123456789012:oidc-provider/evil-token.actions.githubusercontent.com",
		},
		{
			name:      "evil suffix",
			principal: "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com.evil.com",
		},
		{
			name:      "extra path prefix",
			principal: "arn:aws:iam::123456789012:oidc-provider/example.com/token.actions.githubusercontent.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeTerraform(t, root, "role.tf", roleWithFederatedPrincipal("deploy", tt.principal))

			resources, err := ParseDir(root)
			if err != nil {
				t.Fatalf("parse dir: %v", err)
			}
			gotTrusts := 0
			if len(resources.IAMRoles) == 1 {
				gotTrusts = len(resources.IAMRoles[0].Trusts)
			}
			if gotTrusts != tt.wantTrusts {
				t.Fatalf("trust count = %d, want %d: %#v", gotTrusts, tt.wantTrusts, resources)
			}
		})
	}
}

func TestParseDirIgnoresUnsupportedTerraformInputs(t *testing.T) {
	root := t.TempDir()
	writeTerraform(t, root, "unsupported.tf", `variable "secret" {
  default = "FAKE_TF_VARIABLE_SECRET_DO_NOT_RETAIN"
}

resource "aws_s3_bucket" "bucket" {
  bucket = "example-${var.name}"
}

resource "aws_iam_role" "dynamic" {
  assume_role_policy = data.aws_iam_policy_document.trust.json
}

resource "aws_iam_role" "jsonencode" {
  assume_role_policy = jsonencode({
    secret = "FAKE_TF_JSONENCODE_SECRET_DO_NOT_RETAIN"
  })
}
`)

	resources, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if len(resources.IAMRoles) != 0 {
		t.Fatalf("iam roles = %#v, want none", resources.IAMRoles)
	}
	data, err := json.Marshal(resources)
	if err != nil {
		t.Fatalf("marshal resources: %v", err)
	}
	for _, forbidden := range []string{"FAKE_TF_VARIABLE_SECRET_DO_NOT_RETAIN", "FAKE_TF_JSONENCODE_SECRET_DO_NOT_RETAIN", "aws_iam_policy_document", "jsonencode"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("parser output contains %q: %s", forbidden, data)
		}
	}
}

func TestParseDirMalformedTerraformErrorIsSanitized(t *testing.T) {
	root := t.TempDir()
	writeTerraform(t, root, "bad.tf", `resource "aws_iam_role" "deploy" {
  assume_role_policy = <<EOF
  FAKE_TF_HEREDOC_SECRET_DO_NOT_RETAIN
`)

	resources, err := ParseDir(root)
	if err == nil {
		t.Fatalf("parse dir error = nil, resources = %#v", resources)
	}
	message := err.Error()
	if !strings.Contains(message, "bad.tf") || !strings.Contains(message, "invalid Terraform syntax") {
		t.Fatalf("error = %q, want sanitized terraform syntax error with filename", message)
	}
	for _, forbidden := range []string{"FAKE_TF_HEREDOC_SECRET_DO_NOT_RETAIN", "assume_role_policy", "<<EOF"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("error contains %q: %s", forbidden, message)
		}
	}
}

func TestParseDirTrustJSONTrailingContent(t *testing.T) {
	tests := []struct {
		name    string
		suffix  string
		wantErr bool
	}{
		{
			name:   "whitespace only",
			suffix: "\n \t\r\n",
		},
		{
			name:    "trailing non whitespace",
			suffix:  " FAKE_TF_TRAILING_SECRET_DO_NOT_RETAIN",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeTerraform(t, root, "role.tf", `resource "aws_iam_role" "deploy" {
  assume_role_policy = <<EOF
`+validTrustPolicyJSON("repo:owner/repo:pull_request")+tt.suffix+`
EOF
}
`)

			resources, err := ParseDir(root)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parse dir error = nil, resources = %#v", resources)
				}
				message := err.Error()
				if !strings.Contains(message, "aws_iam_role.deploy") || !strings.Contains(message, "invalid assume_role_policy JSON") {
					t.Fatalf("error = %q, want sanitized trust JSON error with resource context", message)
				}
				for _, forbidden := range []string{"FAKE_TF_TRAILING_SECRET_DO_NOT_RETAIN", "Statement", "Principal", "Condition"} {
					if strings.Contains(message, forbidden) {
						t.Fatalf("error contains %q: %s", forbidden, message)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("parse dir: %v", err)
			}
			if len(resources.IAMRoles) != 1 || len(resources.IAMRoles[0].Trusts) != 1 {
				t.Fatalf("resources = %#v, want one role trust", resources)
			}
		})
	}
}

func TestParseDirMalformedTrustJSONErrorIsSanitized(t *testing.T) {
	root := t.TempDir()
	writeTerraform(t, root, "role.tf", `resource "aws_iam_role" "deploy" {
  assume_role_policy = <<EOF
{"Statement": [ FAKE_TF_POLICY_SECRET_DO_NOT_RETAIN
EOF
}
`)

	resources, err := ParseDir(root)
	if err == nil {
		t.Fatalf("parse dir error = nil, resources = %#v", resources)
	}
	message := err.Error()
	if !strings.Contains(message, "aws_iam_role.deploy") || !strings.Contains(message, "invalid assume_role_policy JSON") {
		t.Fatalf("error = %q, want sanitized trust JSON error with resource context", message)
	}
	for _, forbidden := range []string{"FAKE_TF_POLICY_SECRET_DO_NOT_RETAIN", "Statement", "Principal", "Condition"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("error contains %q: %s", forbidden, message)
		}
	}
}

func TestParseDirTrustPolicyDetectionCases(t *testing.T) {
	tests := []struct {
		name       string
		statement  string
		wantTrusts int
	}{
		{
			name: "deny effect",
			statement: `{
  "Effect": "Deny",
  "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com", "token.actions.githubusercontent.com:sub": "repo:owner/repo:pull_request"}}
}`,
		},
		{
			name: "missing issuer",
			statement: `{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/example.com"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com", "token.actions.githubusercontent.com:sub": "repo:owner/repo:pull_request"}}
}`,
		},
		{
			name: "missing action",
			statement: `{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
  "Action": "sts:AssumeRole",
  "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com", "token.actions.githubusercontent.com:sub": "repo:owner/repo:pull_request"}}
}`,
		},
		{
			name: "missing audience",
			statement: `{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {"StringEquals": {"token.actions.githubusercontent.com:sub": "repo:owner/repo:pull_request"}}
}`,
		},
		{
			name: "unsupported subject pattern",
			statement: `{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {"StringLike": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com", "token.actions.githubusercontent.com:sub": "repo:${var.owner}/repo:*"}}
}`,
		},
		{
			name: "string equals and string like",
			statement: `{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
  "Action": ["sts:AssumeRoleWithWebIdentity"],
  "Condition": {
    "StringEquals": {"token.actions.githubusercontent.com:aud": ["sts.amazonaws.com"], "token.actions.githubusercontent.com:sub": "repo:owner/repo:pull_request"},
    "StringLike": {"token.actions.githubusercontent.com:sub": "repo:owner/repo:ref:refs/heads/release-*"}
  }
}`,
			wantTrusts: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeTerraform(t, root, "role.tf", `resource "aws_iam_role" "deploy" {
  assume_role_policy = <<EOF
{"Statement": [`+tt.statement+`]}
EOF
}
`)

			resources, err := ParseDir(root)
			if err != nil {
				t.Fatalf("parse dir: %v", err)
			}
			got := 0
			if len(resources.IAMRoles) == 1 {
				got = len(resources.IAMRoles[0].Trusts)
			}
			if got != tt.wantTrusts {
				t.Fatalf("trust count = %d, want %d: %#v", got, tt.wantTrusts, resources)
			}
		})
	}
}

func TestParseDirSortsTerraformFilesAndRolesDeterministically(t *testing.T) {
	root := t.TempDir()
	writeTerraform(t, root, "z.tf", validRole("z"))
	writeTerraform(t, root, filepath.Join("nested", "a.tf"), validRole("a"))

	first, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse first: %v", err)
	}
	second, err := ParseDir(root)
	if err != nil {
		t.Fatalf("parse second: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("parse output differs:\nfirst=%#v\nsecond=%#v", first, second)
	}
	got := []string{first.IAMRoles[0].Source.RelativePath, first.IAMRoles[1].Source.RelativePath}
	want := []string{"nested/a.tf", "z.tf"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("relative paths = %#v, want %#v", got, want)
	}
}

func TestParseDirWithOptionsExcludesTerraformFileBeforeParsing(t *testing.T) {
	root := t.TempDir()
	writeTerraform(t, root, "ignored.tf", validRole("ignored"))
	writeTerraform(t, root, "kept.tf", validRole("kept"))

	resources, err := ParseDirWithOptions(root, ParseOptions{
		ExcludePath: func(rel string) bool { return rel == "ignored.tf" },
	})
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if len(resources.IAMRoles) != 1 || resources.IAMRoles[0].ResourceName != "kept" {
		t.Fatalf("roles = %#v, want only kept role", resources.IAMRoles)
	}
}

func TestParseDirWithOptionsExcludedMalformedTerraformDoesNotError(t *testing.T) {
	root := t.TempDir()
	writeTerraform(t, root, "bad.tf", `resource "aws_iam_role" "bad" {
  assume_role_policy = <<EOF
  FAKE_TF_EXCLUDED_SECRET_DO_NOT_RETAIN
`)

	resources, err := ParseDirWithOptions(root, ParseOptions{
		ExcludePath: func(rel string) bool { return rel == "bad.tf" },
	})
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if !reflect.DeepEqual(resources, Resources{}) {
		t.Fatalf("resources = %#v, want empty", resources)
	}
}

func TestParseDirWithOptionsDirectoryExclusionExcludesNestedTerraformFiles(t *testing.T) {
	root := t.TempDir()
	writeTerraform(t, root, filepath.Join("infra", "nested", "ignored.tf"), validRole("ignored"))
	writeTerraform(t, root, "kept.tf", validRole("kept"))

	resources, err := ParseDirWithOptions(root, ParseOptions{
		ExcludePath: func(rel string) bool { return rel == "infra/" },
	})
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if len(resources.IAMRoles) != 1 || resources.IAMRoles[0].ResourceName != "kept" {
		t.Fatalf("roles = %#v, want only kept role", resources.IAMRoles)
	}
}

func TestParseDirWithOptionsExactTerraformExclusionDoesNotExcludeSibling(t *testing.T) {
	root := t.TempDir()
	writeTerraform(t, root, filepath.Join("infra", "ignored.tf"), validRole("ignored"))
	writeTerraform(t, root, filepath.Join("infra", "kept.tf"), validRole("kept"))

	resources, err := ParseDirWithOptions(root, ParseOptions{
		ExcludePath: func(rel string) bool { return rel == "infra/ignored.tf" || rel == "infra" },
	})
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if len(resources.IAMRoles) != 1 || resources.IAMRoles[0].ResourceName != "kept" {
		t.Fatalf("roles = %#v, want exact file exclusion to leave sibling", resources.IAMRoles)
	}
}

func TestParseDirWithOptionsExcludesTerraformPathWithSpaces(t *testing.T) {
	root := t.TempDir()
	writeTerraform(t, root, filepath.Join("with spaces", "ignored.tf"), validRole("ignored"))

	resources, err := ParseDirWithOptions(root, ParseOptions{
		ExcludePath: func(rel string) bool { return rel == "with spaces/" },
	})
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if len(resources.IAMRoles) != 0 {
		t.Fatalf("roles = %#v, want none", resources.IAMRoles)
	}
}

func validRole(name string) string {
	return `resource "aws_iam_role" "` + name + `" {
  assume_role_policy = <<EOF
` + validTrustPolicyJSON("repo:owner/repo:pull_request") + `
EOF
}
`
}

func roleWithFederatedPrincipal(name, principal string) string {
	return `resource "aws_iam_role" "` + name + `" {
  assume_role_policy = <<EOF
{"Statement":{"Effect":"Allow","Principal":{"Federated":"` + principal + `"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com","token.actions.githubusercontent.com:sub":"repo:owner/repo:pull_request"}}}}
EOF
}
`
}

func validTrustPolicyJSON(subject string) string {
	return `{"Statement":{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com","token.actions.githubusercontent.com:sub":"` + subject + `"}}}}`
}

func sensitivityNameTokens(reasons []S3BucketSensitivityReason) []string {
	var tokens []string
	for _, reason := range reasons {
		if reason.Source == "bucket_name" {
			tokens = append(tokens, reason.MatchedToken)
		}
	}
	sort.Strings(tokens)
	return tokens
}

func writeTerraform(t *testing.T, root, name, content string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write terraform: %v", err)
	}
	return path
}

func strconvQuote(value string) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(data)
}
