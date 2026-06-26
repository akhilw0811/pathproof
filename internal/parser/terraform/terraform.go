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
	IAMRoles []IAMRole `json:"iam_roles,omitempty"`
}

type Source struct {
	Filename     string `json:"filename"`
	RelativePath string `json:"relative_path"`
	ResourceType string `json:"resource_type"`
	ResourceName string `json:"resource_name"`
}

type IAMRole struct {
	ResourceType string      `json:"resource_type"`
	ResourceName string      `json:"resource_name"`
	Source       Source      `json:"source"`
	Trusts       []OIDCTrust `json:"trusts,omitempty"`
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
	}
	sort.SliceStable(resources.IAMRoles, func(i, j int) bool {
		a := resources.IAMRoles[i]
		b := resources.IAMRoles[j]
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
	resources := Resources{IAMRoles: make([]IAMRole, 0, len(blocks))}
	for _, block := range blocks {
		policy := assumeRolePolicyLiteral(block.body)
		if !policy.ok {
			continue
		}
		trusts, err := parseTrustPolicy(policy.value, block.source)
		if err != nil {
			return Resources{}, err
		}
		resources.IAMRoles = append(resources.IAMRoles, IAMRole{
			ResourceType: block.resourceType,
			ResourceName: block.resourceName,
			Source:       block.source,
			Trusts:       trusts,
		})
	}
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
			if ok && block.resourceType == "aws_iam_role" {
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
		if depth == 0 && hasIdentifierAt(body, i, "assume_role_policy") {
			i += len("assume_role_policy")
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
