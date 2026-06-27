package terraform

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const githubActionsIssuer = "token.actions.githubusercontent.com"

type Resources struct {
	IAMRoles  []IAMRole  `json:"iam_roles,omitempty"`
	S3Buckets []S3Bucket `json:"s3_buckets,omitempty"`
}

type Source struct {
	Filename     string `json:"filename"`
	RelativePath string `json:"relative_path"`
	ResourceType string `json:"resource_type"`
	ResourceName string `json:"resource_name"`
}

type IAMRole struct {
	ResourceType string          `json:"resource_type"`
	ResourceName string          `json:"resource_name"`
	StaticName   string          `json:"static_name,omitempty"`
	Source       Source          `json:"source"`
	Trusts       []OIDCTrust     `json:"trusts,omitempty"`
	Permissions  []IAMPermission `json:"permissions,omitempty"`
}

type S3Bucket struct {
	ResourceType       string                      `json:"resource_type"`
	ResourceName       string                      `json:"resource_name"`
	BucketName         string                      `json:"bucket_name"`
	Source             Source                      `json:"source"`
	SensitivityReasons []S3BucketSensitivityReason `json:"sensitivity_reasons,omitempty"`
}

type S3BucketSensitivityReason struct {
	Source       string `json:"source"`
	MatchedToken string `json:"matched_token,omitempty"`
	Key          string `json:"key,omitempty"`
	Value        string `json:"value,omitempty"`
	SourceRef    string `json:"source_ref"`
}

type OIDCTrust struct {
	StatementIndex  int              `json:"statement_index"`
	Issuer          string           `json:"issuer"`
	SubjectPatterns []SubjectPattern `json:"subject_patterns,omitempty"`
	Audiences       []string         `json:"audiences,omitempty"`
}

type SubjectPattern struct {
	Operator string `json:"operator"`
	Pattern  string `json:"pattern"`
}

type IAMPermission struct {
	Kind                     string   `json:"kind"`
	Source                   Source   `json:"source"`
	PolicyResourceName       string   `json:"policy_resource_name,omitempty"`
	AttachmentResourceName   string   `json:"attachment_resource_name,omitempty"`
	AttachedRoleResourceName string   `json:"attached_role_resource_name"`
	StatementIndex           int      `json:"statement_index,omitempty"`
	Actions                  []string `json:"actions,omitempty"`
	Resources                []string `json:"resources,omitempty"`
	ManagedPolicyARN         string   `json:"managed_policy_arn,omitempty"`
	Administrative           bool     `json:"administrative"`
	AdminReason              string   `json:"admin_reason,omitempty"`
}

type resourceBlock struct {
	resourceType string
	resourceName string
	body         string
	source       Source
}

type literalValue struct {
	value string
	ok    bool
}

type attributeValue struct {
	value     string
	quoted    bool
	reference bool
	ok        bool
}

type iamRoleRecord struct {
	role    IAMRole
	include bool
}

const (
	iamPermissionKindInlinePolicy        = "inline_policy"
	iamPermissionKindManagedPolicy       = "managed_policy"
	adminReasonActionStarResourceStar    = "action_star_resource_star"
	adminReasonActionServiceStarResource = "action_service_star_resource_star"
	adminReasonAdministratorAccess       = "administrator_access_managed_policy"
	administratorAccessPolicyARN         = "arn:aws:iam::aws:policy/AdministratorAccess"
)

func ParseDir(root string) (Resources, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("read terraform path %q: %w", path, err)
		}
		if entry.IsDir() {
			return nil
		}
		if filepath.Ext(entry.Name()) != ".tf" {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return Resources{}, err
	}
	sort.Strings(paths)

	var resources Resources
	for _, path := range paths {
		fileResources, err := parseFile(root, path)
		if err != nil {
			return Resources{}, err
		}
		resources.IAMRoles = append(resources.IAMRoles, fileResources.IAMRoles...)
		resources.S3Buckets = append(resources.S3Buckets, fileResources.S3Buckets...)
	}
	sort.SliceStable(resources.IAMRoles, func(i, j int) bool {
		a := resources.IAMRoles[i]
		b := resources.IAMRoles[j]
		if a.Source.RelativePath != b.Source.RelativePath {
			return a.Source.RelativePath < b.Source.RelativePath
		}
		return a.ResourceName < b.ResourceName
	})
	sort.SliceStable(resources.S3Buckets, func(i, j int) bool {
		a := resources.S3Buckets[i]
		b := resources.S3Buckets[j]
		if a.Source.RelativePath != b.Source.RelativePath {
			return a.Source.RelativePath < b.Source.RelativePath
		}
		return a.ResourceName < b.ResourceName
	})
	return resources, nil
}

func parseFile(root, path string) (Resources, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Resources{}, fmt.Errorf("open terraform file %q: %w", path, err)
	}
	return parseTerraform(root, path, string(data))
}

func parseTerraform(root, filename, content string) (Resources, error) {
	blocks, err := resourceBlocks(root, filename, content)
	if err != nil {
		return Resources{}, err
	}
	roles := make(map[string]*iamRoleRecord)
	var roleOrder []string
	var buckets []S3Bucket
	var permissionBlocks []resourceBlock
	for _, block := range blocks {
		switch block.resourceType {
		case "aws_iam_role":
			role := IAMRole{
				ResourceType: block.resourceType,
				ResourceName: block.resourceName,
				StaticName:   staticNameLiteral(block.body),
				Source:       block.source,
			}
			policy := assumeRolePolicyLiteral(block.body)
			include := false
			if policy.ok {
				trusts, err := parseTrustPolicy(policy.value, block.source)
				if err != nil {
					return Resources{}, err
				}
				role.Trusts = trusts
				include = true
			}
			roles[block.resourceName] = &iamRoleRecord{role: role, include: include}
			roleOrder = append(roleOrder, block.resourceName)
		case "aws_s3_bucket":
			bucketName := quotedStringAttribute(block.body, "bucket")
			if !bucketName.ok || !supportedS3BucketName(bucketName.value) {
				continue
			}
			reasons := s3BucketSensitivityReasons(block.body, bucketName.value, block.source)
			buckets = append(buckets, S3Bucket{
				ResourceType:       block.resourceType,
				ResourceName:       block.resourceName,
				BucketName:         bucketName.value,
				Source:             block.source,
				SensitivityReasons: reasons,
			})
		case "aws_iam_role_policy", "aws_iam_role_policy_attachment":
			permissionBlocks = append(permissionBlocks, block)
		}
	}

	for _, block := range permissionBlocks {
		role, ok := resolveAttachedRole(block.body, roles)
		if !ok {
			continue
		}
		var permissions []IAMPermission
		switch block.resourceType {
		case "aws_iam_role_policy":
			policy := topLevelAttributeLiteral(block.body, "policy")
			if !policy.ok {
				continue
			}
			parsed, err := parsePermissionPolicy(policy.value, block.source, role.role.ResourceName)
			if err != nil {
				return Resources{}, err
			}
			permissions = parsed
		case "aws_iam_role_policy_attachment":
			policyARN := quotedStringAttribute(block.body, "policy_arn")
			if !policyARN.ok || policyARN.value != administratorAccessPolicyARN {
				continue
			}
			permissions = []IAMPermission{{
				Kind:                     iamPermissionKindManagedPolicy,
				Source:                   block.source,
				AttachmentResourceName:   block.resourceName,
				AttachedRoleResourceName: role.role.ResourceName,
				ManagedPolicyARN:         administratorAccessPolicyARN,
				Administrative:           true,
				AdminReason:              adminReasonAdministratorAccess,
			}}
		}
		if len(permissions) == 0 {
			continue
		}
		role.role.Permissions = append(role.role.Permissions, permissions...)
		role.role.Permissions = dedupePermissions(role.role.Permissions)
		role.include = true
	}

	resources := Resources{
		IAMRoles:  make([]IAMRole, 0, len(roles)),
		S3Buckets: append([]S3Bucket(nil), buckets...),
	}
	for _, name := range roleOrder {
		record := roles[name]
		if !record.include {
			continue
		}
		sortPermissions(record.role.Permissions)
		resources.IAMRoles = append(resources.IAMRoles, record.role)
	}
	sort.SliceStable(resources.S3Buckets, func(i, j int) bool {
		a := resources.S3Buckets[i]
		b := resources.S3Buckets[j]
		if a.Source.RelativePath != b.Source.RelativePath {
			return a.Source.RelativePath < b.Source.RelativePath
		}
		return a.ResourceName < b.ResourceName
	})
	return resources, nil
}

func resourceBlocks(root, filename, content string) ([]resourceBlock, error) {
	var blocks []resourceBlock
	depth := 0
	for i := 0; i < len(content); {
		next, err := skipIgnored(content, i)
		if err != nil {
			return nil, terraformParseError(filename)
		}
		if next != i {
			i = next
			continue
		}
		if depth == 0 && hasIdentifierAt(content, i, "resource") {
			block, end, ok, err := parseResourceBlock(root, filename, content, i)
			if err != nil {
				return nil, err
			}
			if ok && supportedResourceType(block.resourceType) {
				blocks = append(blocks, block)
			}
			if end > i {
				i = end
				continue
			}
		}
		switch content[i] {
		case '{':
			depth++
		case '}':
			if depth == 0 {
				return nil, terraformParseError(filename)
			}
			depth--
		}
		i++
	}
	if depth != 0 {
		return nil, terraformParseError(filename)
	}
	return blocks, nil
}

func supportedResourceType(resourceType string) bool {
	switch resourceType {
	case "aws_iam_role", "aws_iam_role_policy", "aws_iam_role_policy_attachment", "aws_s3_bucket":
		return true
	default:
		return false
	}
}

func parseResourceBlock(root, filename, content string, start int) (resourceBlock, int, bool, error) {
	i := start + len("resource")
	first, next, ok := parseQuotedLabel(content, skipSpaceAndComments(content, i))
	if !ok {
		return resourceBlock{}, start + len("resource"), false, nil
	}
	second, next, ok := parseQuotedLabel(content, skipSpaceAndComments(content, next))
	if !ok {
		return resourceBlock{}, next, false, nil
	}
	i = skipSpaceAndComments(content, next)
	if i >= len(content) || content[i] != '{' {
		return resourceBlock{}, i, false, nil
	}
	bodyStart := i + 1
	bodyEnd, err := matchingBrace(content, i)
	if err != nil {
		return resourceBlock{}, 0, false, terraformResourceParseError(filename, first, second)
	}
	source := Source{
		Filename:     filename,
		RelativePath: relativePath(root, filename),
		ResourceType: first,
		ResourceName: second,
	}
	return resourceBlock{
		resourceType: first,
		resourceName: second,
		body:         content[bodyStart:bodyEnd],
		source:       source,
	}, bodyEnd + 1, true, nil
}

func assumeRolePolicyLiteral(body string) literalValue {
	return topLevelAttributeLiteral(body, "assume_role_policy")
}

func topLevelAttributeLiteral(body, name string) literalValue {
	depth := 0
	for i := 0; i < len(body); {
		next, err := skipIgnored(body, i)
		if err != nil {
			return literalValue{}
		}
		if next != i {
			i = next
			continue
		}
		if depth == 0 && hasIdentifierAt(body, i, name) {
			i += len(name)
			i = skipSpaceAndComments(body, i)
			if i >= len(body) || body[i] != '=' {
				continue
			}
			i = skipSpaceAndComments(body, i+1)
			if i >= len(body) {
				return literalValue{}
			}
			if body[i] == '"' {
				value, end, ok := parseQuotedString(body, i)
				if !ok || containsTerraformTemplate(value) {
					return literalValue{}
				}
				return literalValue{value: value, ok: end > i}
			}
			if strings.HasPrefix(body[i:], "<<") {
				value, _, ok := parseHeredoc(body, i)
				if !ok || containsTerraformTemplate(value) {
					return literalValue{}
				}
				return literalValue{value: value, ok: true}
			}
			return literalValue{}
		}
		switch body[i] {
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		}
		i++
	}
	return literalValue{}
}

func staticNameLiteral(body string) string {
	value := quotedStringAttribute(body, "name")
	if !value.ok {
		return ""
	}
	return value.value
}

func quotedStringAttribute(body, name string) literalValue {
	value := topLevelAttributeValue(body, name)
	if !value.ok || !value.quoted || containsTerraformTemplate(value.value) {
		return literalValue{}
	}
	return literalValue{value: value.value, ok: true}
}

func topLevelAttributeValue(body, name string) attributeValue {
	depth := 0
	for i := 0; i < len(body); {
		next, err := skipIgnored(body, i)
		if err != nil {
			return attributeValue{}
		}
		if next != i {
			i = next
			continue
		}
		if depth == 0 && hasIdentifierAt(body, i, name) {
			i += len(name)
			i = skipSpaceAndComments(body, i)
			if i >= len(body) || body[i] != '=' {
				continue
			}
			i = skipSpaceAndComments(body, i+1)
			if i >= len(body) {
				return attributeValue{}
			}
			if body[i] == '"' {
				value, end, ok := parseQuotedString(body, i)
				if !ok || containsTerraformTemplate(value) || !attributeValueEnds(body, end) {
					return attributeValue{}
				}
				return attributeValue{value: value, quoted: true, ok: true}
			}
			start := i
			for i < len(body) && isReferenceByte(body[i]) {
				i++
			}
			if i == start {
				return attributeValue{}
			}
			value := body[start:i]
			if containsTerraformTemplate(value) || !attributeValueEnds(body, i) {
				return attributeValue{}
			}
			return attributeValue{value: value, reference: true, ok: true}
		}
		switch body[i] {
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		}
		i++
	}
	return attributeValue{}
}

func isReferenceByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '-' || b == '.'
}

func attributeValueEnds(body string, i int) bool {
	for i < len(body) && (body[i] == ' ' || body[i] == '\t') {
		i++
	}
	if i >= len(body) {
		return true
	}
	if body[i] == '\n' || body[i] == '\r' || body[i] == '}' || body[i] == '#' || strings.HasPrefix(body[i:], "//") {
		return true
	}
	return false
}

func resolveAttachedRole(body string, roles map[string]*iamRoleRecord) (*iamRoleRecord, bool) {
	value := topLevelAttributeValue(body, "role")
	if !value.ok {
		return nil, false
	}
	if value.reference {
		parts := strings.Split(value.value, ".")
		if len(parts) != 3 || parts[0] != "aws_iam_role" || (parts[2] != "id" && parts[2] != "name") {
			return nil, false
		}
		role, ok := roles[parts[1]]
		return role, ok
	}
	return nil, false
}

func parseTrustPolicy(raw string, source Source) ([]OIDCTrust, error) {
	var policy struct {
		Statement any `json:"Statement"`
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&policy); err != nil {
		return nil, terraformTrustJSONError(source)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, terraformTrustJSONError(source)
	}
	statements := statementObjects(policy.Statement)
	trusts := make([]OIDCTrust, 0, len(statements))
	for index, statement := range statements {
		trust, ok := oidcTrustFromStatement(index, statement)
		if ok {
			trusts = append(trusts, trust)
		}
	}
	sort.SliceStable(trusts, func(i, j int) bool {
		return trusts[i].StatementIndex < trusts[j].StatementIndex
	})
	return trusts, nil
}

func parsePermissionPolicy(raw string, source Source, roleResourceName string) ([]IAMPermission, error) {
	var policy struct {
		Statement any `json:"Statement"`
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&policy); err != nil {
		return nil, terraformPermissionJSONError(source)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, terraformPermissionJSONError(source)
	}
	statements := statementObjects(policy.Statement)
	permissions := make([]IAMPermission, 0, len(statements))
	for index, statement := range statements {
		permissions = append(permissions, permissionsFromStatement(index, statement, source, roleResourceName)...)
	}
	return dedupePermissions(permissions), nil
}

func permissionsFromStatement(index int, statement map[string]any, source Source, roleResourceName string) []IAMPermission {
	if _, hasNotAction := statement["NotAction"]; hasNotAction {
		return nil
	}
	if _, hasNotResource := statement["NotResource"]; hasNotResource {
		return nil
	}
	if _, hasCondition := statement["Condition"]; hasCondition {
		return nil
	}
	effect, ok := statement["Effect"].(string)
	if !ok || effect != "Allow" {
		return nil
	}
	actions := supportedIAMActions(statement["Action"])
	resources := supportedIAMResources(statement["Resource"])
	if len(actions) == 0 || len(resources) == 0 {
		return nil
	}
	base := IAMPermission{
		Kind:                     iamPermissionKindInlinePolicy,
		Source:                   source,
		PolicyResourceName:       source.ResourceName,
		AttachedRoleResourceName: roleResourceName,
		StatementIndex:           index,
		Actions:                  actions,
		Resources:                resources,
	}
	reasons := adminReasons(actions, resources)
	if len(reasons) == 0 {
		return []IAMPermission{base}
	}
	out := make([]IAMPermission, 0, len(reasons))
	for _, reason := range reasons {
		permission := base
		permission.Administrative = true
		permission.AdminReason = reason
		switch reason {
		case adminReasonActionStarResourceStar:
			permission.Actions = []string{"*"}
		case adminReasonActionServiceStarResource:
			permission.Actions = []string{"*:*"}
		}
		permission.Resources = []string{"*"}
		out = append(out, permission)
	}
	return out
}

func supportedIAMActions(value any) []string {
	values, ok := strictStringList(value)
	if !ok {
		return nil
	}
	var supported []string
	for _, value := range values {
		if !supportedIAMAction(value) {
			continue
		}
		supported = append(supported, value)
	}
	return uniqueStrings(supported)
}

func supportedIAMAction(value string) bool {
	if value == "" || containsTerraformTemplate(value) || containsSecretLike(value) {
		return false
	}
	switch value {
	case "*", "*:*", "s3:GetObject", "s3:ListBucket", "s3:PutObject", "s3:DeleteObject", "s3:*":
		return true
	default:
		return false
	}
}

func supportedIAMResources(value any) []string {
	values, ok := strictStringList(value)
	if !ok {
		return nil
	}
	var supported []string
	for _, value := range values {
		if value == "*" || supportedS3ResourceARN(value) {
			supported = append(supported, value)
		}
	}
	return uniqueStrings(supported)
}

func supportedS3ResourceARN(value string) bool {
	if value == "" || containsTerraformTemplate(value) || containsSecretLike(value) {
		return false
	}
	const prefix = "arn:aws:s3:::"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	target := strings.TrimPrefix(value, prefix)
	bucket := target
	if strings.HasSuffix(target, "/*") {
		bucket = strings.TrimSuffix(target, "/*")
	} else if strings.Contains(target, "/") {
		return false
	}
	return supportedS3BucketName(bucket)
}

func supportedS3BucketName(value string) bool {
	if value == "" || containsTerraformTemplate(value) || containsSecretLike(value) {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-':
		default:
			return false
		}
	}
	return !strings.Contains(value, "*") && !strings.Contains(value, "/")
}

func s3BucketSensitivityReasons(body, bucketName string, source Source) []S3BucketSensitivityReason {
	reasons := make([]S3BucketSensitivityReason, 0)
	sourceRef := relativeSourceRef(source)
	for _, token := range s3BucketNameSensitivityTokens(bucketName) {
		reasons = append(reasons, S3BucketSensitivityReason{
			Source:       "bucket_name",
			MatchedToken: token,
			SourceRef:    sourceRef,
		})
	}
	for _, tag := range s3BucketSensitivityTags(body, sourceRef) {
		reasons = append(reasons, tag)
	}
	return dedupeSortS3BucketSensitivityReasons(reasons)
}

func s3BucketNameSensitivityTokens(bucketName string) []string {
	seen := make(map[string]struct{})
	var tokens []string
	for _, token := range splitS3BucketNameTokens(bucketName) {
		if !s3SensitiveNameToken(token) {
			continue
		}
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		tokens = append(tokens, token)
	}
	sort.Strings(tokens)
	return tokens
}

func splitS3BucketNameTokens(bucketName string) []string {
	var tokens []string
	var current strings.Builder
	flush := func() {
		if current.Len() == 0 {
			return
		}
		tokens = append(tokens, strings.ToLower(current.String()))
		current.Reset()
	}
	for _, r := range bucketName {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			current.WriteRune(unicode.ToLower(r))
			continue
		}
		flush()
	}
	flush()
	return tokens
}

func s3SensitiveNameToken(token string) bool {
	switch token {
	case "prod", "production", "backup", "backups", "db", "database", "customer", "customers", "pii", "phi", "financial", "finance", "payroll", "billing", "invoice", "invoices", "logs", "audit":
		return true
	default:
		return false
	}
}

func s3BucketSensitivityTags(body, sourceRef string) []S3BucketSensitivityReason {
	tagBody, ok := topLevelObjectAttributeBody(body, "tags")
	if !ok {
		return nil
	}
	var reasons []S3BucketSensitivityReason
	for _, tag := range staticLiteralObjectStringPairs(tagBody) {
		key, value := tag[0], tag[1]
		if !s3SensitiveTagKey(key) {
			continue
		}
		canonicalValue := strings.ToLower(value)
		if !s3SensitiveTagValue(canonicalValue) {
			continue
		}
		reasons = append(reasons, S3BucketSensitivityReason{
			Source:    "tag",
			Key:       key,
			Value:     canonicalValue,
			SourceRef: sourceRef,
		})
	}
	return dedupeSortS3BucketSensitivityReasons(reasons)
}

func topLevelObjectAttributeBody(body, name string) (string, bool) {
	depth := 0
	for i := 0; i < len(body); {
		next, err := skipIgnored(body, i)
		if err != nil {
			return "", false
		}
		if next != i {
			i = next
			continue
		}
		if depth == 0 && hasIdentifierAt(body, i, name) {
			i += len(name)
			i = skipSpaceAndComments(body, i)
			if i >= len(body) || body[i] != '=' {
				continue
			}
			i = skipSpaceAndComments(body, i+1)
			if i >= len(body) || body[i] != '{' {
				return "", false
			}
			end, err := matchingBrace(body, i)
			if err != nil {
				return "", false
			}
			return body[i+1 : end], true
		}
		switch body[i] {
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		}
		i++
	}
	return "", false
}

func staticLiteralObjectStringPairs(body string) [][2]string {
	var pairs [][2]string
	depth := 0
	for i := 0; i < len(body); {
		if depth == 0 {
			next := skipSpaceAndComments(body, i)
			if next != i {
				i = next
				continue
			}
			if i >= len(body) {
				break
			}
			key, next, ok := parseStaticObjectKey(body, i)
			if ok {
				i = skipSpaceAndComments(body, next)
				if i < len(body) && body[i] == '=' {
					i = skipSpaceAndComments(body, i+1)
					if i < len(body) && body[i] == '"' {
						value, end, ok := parseQuotedString(body, i)
						if ok && !containsTerraformTemplate(value) && objectValueEnds(body, end) {
							pairs = append(pairs, [2]string{key, value})
							i = end
							continue
						}
					}
				}
			}
		}
		next, err := skipIgnored(body, i)
		if err != nil {
			return pairs
		}
		if next != i {
			i = next
			continue
		}
		if i >= len(body) {
			break
		}
		switch body[i] {
		case '{', '[', '(':
			depth++
		case '}', ']', ')':
			if depth > 0 {
				depth--
			}
		}
		i++
	}
	return pairs
}

func parseStaticObjectKey(body string, i int) (string, int, bool) {
	if i >= len(body) {
		return "", i, false
	}
	if body[i] == '"' {
		value, end, ok := parseQuotedString(body, i)
		if !ok || value == "" || containsTerraformTemplate(value) {
			return "", i, false
		}
		return value, end, true
	}
	if !(body[i] == '_' || unicode.IsLetter(rune(body[i]))) {
		return "", i, false
	}
	start := i
	for i < len(body) {
		r := rune(body[i])
		if !(r == '_' || r == '-' || unicode.IsLetter(r) || unicode.IsDigit(r)) {
			break
		}
		i++
	}
	if i == start {
		return "", start, false
	}
	return body[start:i], i, true
}

func objectValueEnds(body string, i int) bool {
	for i < len(body) && (body[i] == ' ' || body[i] == '\t') {
		i++
	}
	if i >= len(body) {
		return true
	}
	if body[i] == '\n' || body[i] == '\r' || body[i] == ',' || body[i] == '}' || body[i] == '#' || strings.HasPrefix(body[i:], "//") {
		return true
	}
	return false
}

func s3SensitiveTagKey(key string) bool {
	switch key {
	case "DataClassification", "Classification", "Sensitivity", "Environment":
		return true
	default:
		return false
	}
}

func s3SensitiveTagValue(value string) bool {
	switch value {
	case "sensitive", "confidential", "restricted", "private", "pii", "phi", "production", "prod":
		return true
	default:
		return false
	}
}

func dedupeSortS3BucketSensitivityReasons(reasons []S3BucketSensitivityReason) []S3BucketSensitivityReason {
	if len(reasons) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(reasons))
	out := make([]S3BucketSensitivityReason, 0, len(reasons))
	for _, reason := range reasons {
		key := s3BucketSensitivityReasonKey(reason)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, reason)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return s3BucketSensitivityReasonKey(out[i]) < s3BucketSensitivityReasonKey(out[j])
	})
	return out
}

func s3BucketSensitivityReasonKey(reason S3BucketSensitivityReason) string {
	data, err := json.Marshal(struct {
		Source       string `json:"source"`
		MatchedToken string `json:"matched_token,omitempty"`
		Key          string `json:"key,omitempty"`
		Value        string `json:"value,omitempty"`
		SourceRef    string `json:"source_ref"`
	}{
		Source:       reason.Source,
		MatchedToken: reason.MatchedToken,
		Key:          reason.Key,
		Value:        reason.Value,
		SourceRef:    reason.SourceRef,
	})
	if err != nil {
		return ""
	}
	return string(data)
}

func strictStringList(value any) ([]string, bool) {
	switch typed := value.(type) {
	case string:
		return []string{typed}, true
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			value, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, value)
		}
		return out, true
	default:
		return nil, false
	}
}

func adminReasons(actions, resources []string) []string {
	if !stringListContainsExact(resources, "*") {
		return nil
	}
	var reasons []string
	if stringListContainsExact(actions, "*") {
		reasons = append(reasons, adminReasonActionStarResourceStar)
	}
	if stringListContainsExact(actions, "*:*") {
		reasons = append(reasons, adminReasonActionServiceStarResource)
	}
	return reasons
}

func dedupePermissions(permissions []IAMPermission) []IAMPermission {
	if len(permissions) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(permissions))
	out := make([]IAMPermission, 0, len(permissions))
	for _, permission := range permissions {
		permission.Actions = uniqueStrings(permission.Actions)
		permission.Resources = uniqueStrings(permission.Resources)
		key := permissionKey(permission)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, permission)
	}
	sortPermissions(out)
	return out
}

func permissionKey(permission IAMPermission) string {
	data, err := json.Marshal(struct {
		Kind                     string   `json:"kind"`
		Source                   Source   `json:"source"`
		PolicyResourceName       string   `json:"policy_resource_name,omitempty"`
		AttachmentResourceName   string   `json:"attachment_resource_name,omitempty"`
		AttachedRoleResourceName string   `json:"attached_role_resource_name"`
		StatementIndex           int      `json:"statement_index,omitempty"`
		Actions                  []string `json:"actions,omitempty"`
		Resources                []string `json:"resources,omitempty"`
		ManagedPolicyARN         string   `json:"managed_policy_arn,omitempty"`
		Administrative           bool     `json:"administrative"`
		AdminReason              string   `json:"admin_reason,omitempty"`
	}{
		Kind:                     permission.Kind,
		Source:                   permission.Source,
		PolicyResourceName:       permission.PolicyResourceName,
		AttachmentResourceName:   permission.AttachmentResourceName,
		AttachedRoleResourceName: permission.AttachedRoleResourceName,
		StatementIndex:           permission.StatementIndex,
		Actions:                  permission.Actions,
		Resources:                permission.Resources,
		ManagedPolicyARN:         permission.ManagedPolicyARN,
		Administrative:           permission.Administrative,
		AdminReason:              permission.AdminReason,
	})
	if err != nil {
		return ""
	}
	return string(data)
}

func sortPermissions(permissions []IAMPermission) {
	sort.SliceStable(permissions, func(i, j int) bool {
		a := permissions[i]
		b := permissions[j]
		if a.Source.RelativePath != b.Source.RelativePath {
			return a.Source.RelativePath < b.Source.RelativePath
		}
		if a.Source.ResourceType != b.Source.ResourceType {
			return a.Source.ResourceType < b.Source.ResourceType
		}
		if a.Source.ResourceName != b.Source.ResourceName {
			return a.Source.ResourceName < b.Source.ResourceName
		}
		if a.AttachedRoleResourceName != b.AttachedRoleResourceName {
			return a.AttachedRoleResourceName < b.AttachedRoleResourceName
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.StatementIndex != b.StatementIndex {
			return a.StatementIndex < b.StatementIndex
		}
		if a.AdminReason != b.AdminReason {
			return a.AdminReason < b.AdminReason
		}
		if strings.Join(a.Actions, "\x00") != strings.Join(b.Actions, "\x00") {
			return strings.Join(a.Actions, "\x00") < strings.Join(b.Actions, "\x00")
		}
		if strings.Join(a.Resources, "\x00") != strings.Join(b.Resources, "\x00") {
			return strings.Join(a.Resources, "\x00") < strings.Join(b.Resources, "\x00")
		}
		return a.ManagedPolicyARN < b.ManagedPolicyARN
	})
}

func containsSecretLike(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"secret", "password", "token", "accesskey", "access_key"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func statementObjects(value any) []map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return []map[string]any{typed}
	case []any:
		out := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			if object, ok := item.(map[string]any); ok {
				out = append(out, object)
			}
		}
		return out
	default:
		return nil
	}
}

func oidcTrustFromStatement(index int, statement map[string]any) (OIDCTrust, bool) {
	if effect, ok := statement["Effect"].(string); !ok || effect != "Allow" {
		return OIDCTrust{}, false
	}
	if !federatedPrincipalTrustsGitHub(statement["Principal"]) {
		return OIDCTrust{}, false
	}
	if !stringListContainsExact(stringList(statement["Action"]), "sts:AssumeRoleWithWebIdentity") {
		return OIDCTrust{}, false
	}
	subjects, audiences := supportedConditions(statement["Condition"])
	if len(subjects) == 0 || !stringListContainsExact(audiences, "sts.amazonaws.com") {
		return OIDCTrust{}, false
	}
	return OIDCTrust{
		StatementIndex:  index,
		Issuer:          githubActionsIssuer,
		SubjectPatterns: subjects,
		Audiences:       []string{"sts.amazonaws.com"},
	}, true
}

func federatedPrincipalTrustsGitHub(value any) bool {
	object, ok := value.(map[string]any)
	if !ok {
		return false
	}
	for _, principal := range stringList(object["Federated"]) {
		if federatedPrincipalProviderPath(principal) == githubActionsIssuer {
			return true
		}
	}
	return false
}

func federatedPrincipalProviderPath(principal string) string {
	const arnPrefix = "arn:"
	const iamMarker = ":iam::"
	const marker = ":oidc-provider/"
	if !strings.HasPrefix(principal, arnPrefix) {
		return ""
	}
	afterARN := principal[len(arnPrefix):]
	iamIndex := strings.Index(afterARN, iamMarker)
	if iamIndex < 0 {
		return ""
	}
	partition := afterARN[:iamIndex]
	if partition != "aws" && !strings.HasPrefix(partition, "aws-") {
		return ""
	}
	index := strings.Index(afterARN[iamIndex+len(iamMarker):], marker)
	if index < 0 {
		return ""
	}
	return afterARN[iamIndex+len(iamMarker)+index+len(marker):]
}

func supportedConditions(value any) ([]SubjectPattern, []string) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, nil
	}
	var subjects []SubjectPattern
	var audiences []string
	for _, operator := range []string{"StringEquals", "StringLike"} {
		conditions, ok := object[operator].(map[string]any)
		if !ok {
			continue
		}
		for _, subject := range stringList(conditions[githubActionsIssuer+":sub"]) {
			if !supportedSubjectPattern(operator, subject) {
				continue
			}
			subjects = append(subjects, SubjectPattern{Operator: operator, Pattern: subject})
		}
		for _, audience := range stringList(conditions[githubActionsIssuer+":aud"]) {
			if audience == "sts.amazonaws.com" {
				audiences = append(audiences, audience)
			}
		}
	}
	sort.SliceStable(subjects, func(i, j int) bool {
		if subjects[i].Operator != subjects[j].Operator {
			return subjects[i].Operator < subjects[j].Operator
		}
		return subjects[i].Pattern < subjects[j].Pattern
	})
	audiences = uniqueStrings(audiences)
	return subjects, audiences
}

func supportedSubjectPattern(operator, value string) bool {
	if value == "" || containsTerraformTemplate(value) {
		return false
	}
	if operator == "StringEquals" && strings.Contains(value, "*") {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case strings.ContainsRune(":/._-*", r):
		default:
			return false
		}
	}
	return strings.HasPrefix(value, "repo:")
}

func stringList(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if value, ok := item.(string); ok {
				out = append(out, value)
			}
		}
		return out
	default:
		return nil
	}
}

func stringListContainsExact(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func matchingBrace(content string, open int) (int, error) {
	depth := 1
	for i := open + 1; i < len(content); {
		next, err := skipIgnored(content, i)
		if err != nil {
			return 0, err
		}
		if next != i {
			i = next
			continue
		}
		switch content[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i, nil
			}
		}
		i++
	}
	return 0, fmt.Errorf("unterminated block")
}

func skipIgnored(content string, i int) (int, error) {
	if i >= len(content) {
		return i, nil
	}
	switch {
	case content[i] == '"':
		_, end, ok := parseQuotedString(content, i)
		if !ok {
			return i, fmt.Errorf("unterminated string")
		}
		return end, nil
	case strings.HasPrefix(content[i:], "/*"):
		end := strings.Index(content[i+2:], "*/")
		if end < 0 {
			return i, fmt.Errorf("unterminated comment")
		}
		return i + 2 + end + 2, nil
	case strings.HasPrefix(content[i:], "//"):
		return skipLine(content, i), nil
	case content[i] == '#':
		return skipLine(content, i), nil
	case strings.HasPrefix(content[i:], "<<"):
		_, end, ok := parseHeredoc(content, i)
		if !ok {
			return i, fmt.Errorf("unterminated heredoc")
		}
		return end, nil
	default:
		return i, nil
	}
}

func skipLine(content string, i int) int {
	for i < len(content) && content[i] != '\n' {
		i++
	}
	return i
}

func parseQuotedLabel(content string, i int) (string, int, bool) {
	value, end, ok := parseQuotedString(content, i)
	if !ok || value == "" || containsTerraformTemplate(value) || strings.ContainsAny(value, " \t\r\n*/:{}") {
		return "", i, false
	}
	return value, end, true
}

func parseQuotedString(content string, i int) (string, int, bool) {
	if i >= len(content) || content[i] != '"' {
		return "", i, false
	}
	for j := i + 1; j < len(content); j++ {
		if content[j] == '\n' || content[j] == '\r' {
			return "", i, false
		}
		if content[j] == '\\' {
			j++
			continue
		}
		if content[j] == '"' {
			value, err := strconv.Unquote(content[i : j+1])
			if err != nil {
				return "", i, false
			}
			return value, j + 1, true
		}
	}
	return "", i, false
}

func parseHeredoc(content string, i int) (string, int, bool) {
	if !strings.HasPrefix(content[i:], "<<") {
		return "", i, false
	}
	j := i + 2
	allowIndented := false
	if j < len(content) && content[j] == '-' {
		allowIndented = true
		j++
	}
	for j < len(content) && (content[j] == ' ' || content[j] == '\t') {
		j++
	}
	markerStart := j
	for j < len(content) && content[j] != '\n' && content[j] != '\r' {
		j++
	}
	marker := strings.TrimSpace(content[markerStart:j])
	if !validHeredocMarker(marker) {
		return "", i, false
	}
	if j < len(content) && content[j] == '\r' {
		j++
	}
	if j < len(content) && content[j] == '\n' {
		j++
	}
	bodyStart := j
	for j <= len(content) {
		lineStart := j
		for j < len(content) && content[j] != '\n' && content[j] != '\r' {
			j++
		}
		line := content[lineStart:j]
		candidate := line
		if allowIndented {
			candidate = strings.TrimLeft(line, " \t")
		}
		if candidate == marker {
			return content[bodyStart:lineStart], lineEnd(content, j), true
		}
		if j >= len(content) {
			break
		}
		j = lineEnd(content, j)
	}
	return "", i, false
}

func lineEnd(content string, i int) int {
	if i < len(content) && content[i] == '\r' {
		i++
	}
	if i < len(content) && content[i] == '\n' {
		i++
	}
	return i
}

func validHeredocMarker(marker string) bool {
	if marker == "" {
		return false
	}
	for _, r := range marker {
		if !(r == '_' || r == '-' || unicode.IsLetter(r) || unicode.IsDigit(r)) {
			return false
		}
	}
	return true
}

func skipSpaceAndComments(content string, i int) int {
	for i < len(content) {
		for i < len(content) && unicode.IsSpace(rune(content[i])) {
			i++
		}
		if strings.HasPrefix(content[i:], "//") || (i < len(content) && content[i] == '#') {
			i = skipLine(content, i)
			continue
		}
		if strings.HasPrefix(content[i:], "/*") {
			end := strings.Index(content[i+2:], "*/")
			if end < 0 {
				return i
			}
			i = i + 2 + end + 2
			continue
		}
		return i
	}
	return i
}

func hasIdentifierAt(content string, i int, ident string) bool {
	if i < 0 || i+len(ident) > len(content) || content[i:i+len(ident)] != ident {
		return false
	}
	if i > 0 && isIdentifierByte(content[i-1]) {
		return false
	}
	if i+len(ident) < len(content) && isIdentifierByte(content[i+len(ident)]) {
		return false
	}
	return true
}

func isIdentifierByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '-'
}

func containsTerraformTemplate(value string) bool {
	return strings.Contains(value, "${") || strings.Contains(value, "%{")
}

func relativePath(root, filename string) string {
	rel, err := filepath.Rel(root, filename)
	if err != nil {
		rel = filename
	}
	return filepath.ToSlash(filepath.Clean(rel))
}

func sourceRef(source Source) string {
	return fmt.Sprintf("%s#resource=%s.%s", source.Filename, source.ResourceType, source.ResourceName)
}

func relativeSourceRef(source Source) string {
	filename := source.RelativePath
	if filename == "" {
		filename = filepath.Base(source.Filename)
	}
	return fmt.Sprintf("%s#resource=%s.%s", filepath.ToSlash(filepath.Clean(filename)), source.ResourceType, source.ResourceName)
}

func terraformParseError(filename string) error {
	return fmt.Errorf("terraform file %s: invalid Terraform syntax in supported scan scope", filepath.ToSlash(filepath.Clean(filename)))
}

func terraformResourceParseError(filename, resourceType, resourceName string) error {
	if resourceType == "" || resourceName == "" {
		return terraformParseError(filename)
	}
	return fmt.Errorf("terraform resource %s.%s in %s: invalid Terraform syntax in supported scan scope", resourceType, resourceName, filepath.ToSlash(filepath.Clean(filename)))
}

func terraformTrustJSONError(source Source) error {
	return fmt.Errorf("terraform resource %s in %s: invalid assume_role_policy JSON", source.ResourceType+"."+source.ResourceName, sourceRef(source))
}

func terraformPermissionJSONError(source Source) error {
	return fmt.Errorf("terraform resource %s in %s: invalid policy JSON", source.ResourceType+"."+source.ResourceName, relativeSourceRef(source))
}
