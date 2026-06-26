package patchpreview

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"pathproof/internal/remediation"

	"gopkg.in/yaml.v3"
)

type Status string

const (
	StatusGenerated   Status = "generated"
	StatusUnsupported Status = "unsupported"
)

type Preview struct {
	PlanID       remediation.PlanID `json:"plan_id"`
	OptionIndex  int                `json:"option_index"`
	OptionAction remediation.Action `json:"option_action"`
	ChangeIndex  int                `json:"change_index"`
	Status       Status             `json:"status"`
	Summary      string             `json:"summary"`
	File         string             `json:"file,omitempty"`
	Diff         string             `json:"diff,omitempty"`
	Reason       string             `json:"reason,omitempty"`
}

type sourceRef struct {
	filename string
	document int
}

type resolvedSource struct {
	fullPath string
	relPath  string
	document int
}

type documentRange struct {
	start int
	end   int
}

type diffOpKind int

const (
	diffEqual diffOpKind = iota
	diffDelete
	diffInsert
)

type diffOp struct {
	kind diffOpKind
	line string
}

func Build(root string, plans []remediation.Plan) ([]Preview, error) {
	if root == "" {
		return nil, fmt.Errorf("patch preview root is empty")
	}

	orderedPlans := append([]remediation.Plan(nil), plans...)
	sort.SliceStable(orderedPlans, func(i, j int) bool {
		return orderedPlans[i].ID < orderedPlans[j].ID
	})

	var previews []Preview
	for _, plan := range orderedPlans {
		for optionIndex, option := range plan.Options {
			for changeIndex, change := range option.Changes {
				generated := buildChangePreview(root, plan.ID, optionIndex, option.Action, changeIndex, change)
				generated.Summary = change.Summary
				previews = append(previews, generated)
			}
		}
	}
	sort.SliceStable(previews, func(i, j int) bool {
		if previews[i].PlanID != previews[j].PlanID {
			return previews[i].PlanID < previews[j].PlanID
		}
		if previews[i].OptionIndex != previews[j].OptionIndex {
			return previews[i].OptionIndex < previews[j].OptionIndex
		}
		if previews[i].ChangeIndex != previews[j].ChangeIndex {
			return previews[i].ChangeIndex < previews[j].ChangeIndex
		}
		return previews[i].File < previews[j].File
	})
	return previews, nil
}

func buildChangePreview(root string, planID remediation.PlanID, optionIndex int, optionAction remediation.Action, changeIndex int, change remediation.Change) Preview {
	preview := Preview{
		PlanID:       planID,
		OptionIndex:  optionIndex,
		OptionAction: optionAction,
		ChangeIndex:  changeIndex,
		Status:       StatusUnsupported,
		Summary:      change.Summary,
	}
	if change.Action != remediation.NarrowBindingSubject || optionAction != remediation.NarrowBindingSubject {
		preview.Reason = "patch previews support only NarrowBindingSubject"
		return preview
	}

	source, reason := resolveSourceReference(root, change.SourceReference)
	if reason != "" {
		preview.Reason = reason
		return preview
	}
	preview.File = source.relPath

	original, err := os.ReadFile(source.fullPath)
	if err != nil {
		preview.Reason = "source file cannot be read"
		return preview
	}
	normalizedOriginal := normalizeLineEndings(string(original))
	documents, reason := parseDocuments(normalizedOriginal)
	if reason != "" {
		preview.Reason = reason
		return preview
	}
	if source.document < 1 || source.document > len(documents) {
		preview.Reason = "source reference document is outside the file"
		return preview
	}
	if sourceFileContainsSecretPayload(documents) {
		preview.Reason = "source file contains a Secret payload, so patch preview is disabled for this file"
		return preview
	}

	ranges := splitDocumentRanges(normalizedOriginal)
	if len(ranges) != len(documents) {
		preview.Reason = "source YAML document structure is unsupported"
		return preview
	}

	patchedDocument, reason := patchBindingDocument(documents[source.document-1], change)
	if reason != "" {
		preview.Reason = reason
		return preview
	}
	encoded, err := encodeDocument(patchedDocument)
	if err != nil {
		preview.Reason = "patched YAML cannot be encoded"
		return preview
	}

	patched := replaceDocument(normalizedOriginal, ranges[source.document-1], encoded)
	if _, reason := parseDocuments(patched); reason != "" {
		preview.Reason = "patched YAML cannot be parsed"
		return preview
	}
	diff := unifiedDiff(source.relPath, normalizedOriginal, patched)
	if diff == "" {
		preview.Reason = "patch preview produced no changes"
		return preview
	}

	preview.Status = StatusGenerated
	preview.Reason = ""
	preview.Diff = diff
	return preview
}

func resolveSourceReference(root, value string) (resolvedSource, string) {
	ref, reason := parseSourceReference(value)
	if reason != "" {
		return resolvedSource{}, reason
	}
	if filepath.IsAbs(ref.filename) {
		return resolvedSource{}, "source reference path must be relative"
	}

	cleanRoot := filepath.Clean(root)
	cleanFilename := filepath.Clean(ref.filename)
	if cleanFilename == "." || strings.HasPrefix(cleanFilename, ".."+string(filepath.Separator)) || cleanFilename == ".." {
		return resolvedSource{}, "source reference path escapes the scan root"
	}

	fullPath := filepath.Join(root, cleanFilename)
	relPath := cleanFilename
	if rel, ok := relativeToRoot(cleanRoot, cleanFilename); ok {
		fullPath = cleanFilename
		relPath = rel
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return resolvedSource{}, "scan root cannot be resolved"
	}
	absFull, err := filepath.Abs(fullPath)
	if err != nil {
		return resolvedSource{}, "source reference path cannot be resolved"
	}
	rel, err := filepath.Rel(absRoot, absFull)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return resolvedSource{}, "source reference path escapes the scan root"
	}
	relPath = filepath.ToSlash(filepath.Clean(relPath))
	if relPath == "." || strings.HasPrefix(relPath, "../") || relPath == ".." {
		return resolvedSource{}, "source reference path escapes the scan root"
	}

	return resolvedSource{fullPath: fullPath, relPath: relPath, document: ref.document}, ""
}

func parseSourceReference(value string) (sourceRef, string) {
	filename, documentValue, ok := strings.Cut(value, "#document=")
	if !ok || filename == "" || documentValue == "" || strings.Contains(documentValue, "#") {
		return sourceRef{}, "source reference must use filename#document=N"
	}
	document, err := strconv.Atoi(documentValue)
	if err != nil || document < 1 {
		return sourceRef{}, "source reference document must be a positive integer"
	}
	return sourceRef{filename: filename, document: document}, ""
}

func relativeToRoot(root, filename string) (string, bool) {
	if filepath.IsAbs(root) || filepath.IsAbs(filename) {
		return "", false
	}
	rel, err := filepath.Rel(root, filename)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}

func parseDocuments(content string) ([]*yaml.Node, string) {
	decoder := yaml.NewDecoder(strings.NewReader(content))
	var documents []*yaml.Node
	for {
		var document yaml.Node
		err := decoder.Decode(&document)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "source YAML cannot be parsed"
		}
		documents = append(documents, &document)
	}
	return documents, ""
}

func sourceFileContainsSecretPayload(documents []*yaml.Node) bool {
	for _, document := range documents {
		root := documentRoot(document)
		if root == nil || root.Kind != yaml.MappingNode {
			continue
		}
		if scalarValue(mappingValue(root, "apiVersion")) != "v1" || scalarValue(mappingValue(root, "kind")) != "Secret" {
			continue
		}
		if mappingValue(root, "data") != nil || mappingValue(root, "stringData") != nil {
			return true
		}
	}
	return false
}

func splitDocumentRanges(content string) []documentRange {
	if content == "" {
		return []documentRange{{start: 0, end: 0}}
	}
	var ranges []documentRange
	start := 0
	offset := 0
	for offset < len(content) {
		lineEnd := strings.IndexByte(content[offset:], '\n')
		next := len(content)
		if lineEnd >= 0 {
			next = offset + lineEnd + 1
		}
		line := content[offset:next]
		if offset != 0 && strings.TrimSpace(strings.TrimSuffix(line, "\n")) == "---" {
			ranges = append(ranges, documentRange{start: start, end: offset})
			start = offset
		}
		offset = next
	}
	ranges = append(ranges, documentRange{start: start, end: len(content)})
	return ranges
}

func patchBindingDocument(document *yaml.Node, change remediation.Change) (*yaml.Node, string) {
	root := documentRoot(document)
	if root == nil || root.Kind != yaml.MappingNode {
		return nil, "referenced document is not the target binding"
	}
	kind := scalarValue(mappingValue(root, "kind"))
	apiVersion := scalarValue(mappingValue(root, "apiVersion"))
	if apiVersion != "rbac.authorization.k8s.io/v1" || (kind != "RoleBinding" && kind != "ClusterRoleBinding") {
		return nil, "referenced document is not the target binding"
	}
	if kind != change.Target.Kind {
		return nil, "referenced document is not the target binding"
	}
	metadata := mappingValue(root, "metadata")
	if metadata == nil || metadata.Kind != yaml.MappingNode {
		return nil, "referenced document is not the target binding"
	}
	if scalarValue(mappingValue(metadata, "name")) != change.Target.Name {
		return nil, "referenced document is not the target binding"
	}
	namespace := scalarValue(mappingValue(metadata, "namespace"))
	if kind == "RoleBinding" {
		if roleBindingNamespaceOrDefault(namespace) != change.Target.Namespace {
			return nil, "referenced document is not the target binding"
		}
	} else if change.Target.Namespace != "" || namespace != "" {
		return nil, "referenced document is not the target binding"
	}

	subjectNamespace, subjectName, ok := strings.Cut(change.Subject, "/")
	if !ok || subjectNamespace == "" || subjectName == "" {
		return nil, "affected ServiceAccount subject is unsupported"
	}
	subjects := mappingValue(root, "subjects")
	if subjects == nil || subjects.Kind != yaml.SequenceNode {
		return nil, "target binding subjects are unsupported"
	}
	if len(subjects.Content) <= 1 {
		return nil, "removing the subject would leave subjects empty"
	}

	matchIndex := -1
	for i, subject := range subjects.Content {
		if subject.Kind != yaml.MappingNode {
			continue
		}
		if scalarValue(mappingValue(subject, "kind")) != "ServiceAccount" {
			continue
		}
		if scalarValue(mappingValue(subject, "name")) != subjectName {
			continue
		}
		if scalarValue(mappingValue(subject, "namespace")) != subjectNamespace {
			continue
		}
		if matchIndex != -1 {
			return nil, "target ServiceAccount subject is ambiguous"
		}
		matchIndex = i
	}
	if matchIndex == -1 {
		return nil, "target ServiceAccount subject was not found"
	}

	cloned := cloneNode(document)
	clonedRoot := documentRoot(cloned)
	clonedSubjects := mappingValue(clonedRoot, "subjects")
	clonedSubjects.Content = append(clonedSubjects.Content[:matchIndex], clonedSubjects.Content[matchIndex+1:]...)
	return cloned, ""
}

func roleBindingNamespaceOrDefault(namespace string) string {
	if namespace == "" {
		return "default"
	}
	return namespace
}

func documentRoot(document *yaml.Node) *yaml.Node {
	if document == nil {
		return nil
	}
	if document.Kind == yaml.DocumentNode {
		if len(document.Content) == 0 {
			return nil
		}
		return document.Content[0]
	}
	return document
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Kind == yaml.ScalarNode && node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func scalarValue(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return node.Value
}

func cloneNode(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	cloned := *node
	if len(node.Content) > 0 {
		cloned.Content = make([]*yaml.Node, len(node.Content))
		for i, child := range node.Content {
			cloned.Content[i] = cloneNode(child)
		}
	}
	return &cloned
}

func encodeDocument(document *yaml.Node) (string, error) {
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(document); err != nil {
		_ = encoder.Close()
		return "", err
	}
	if err := encoder.Close(); err != nil {
		return "", err
	}
	return ensureTrailingNewline(normalizeLineEndings(out.String())), nil
}

func replaceDocument(content string, r documentRange, encoded string) string {
	segment := content[r.start:r.end]
	header := ""
	if strings.HasPrefix(segment, "---\n") {
		header = "---\n"
	} else if strings.HasPrefix(segment, "---\r\n") {
		header = "---\n"
	}
	return content[:r.start] + header + encoded + content[r.end:]
}

func unifiedDiff(path, oldContent, newContent string) string {
	oldLines := splitLines(ensureTrailingNewline(oldContent))
	newLines := splitLines(ensureTrailingNewline(newContent))
	ops := diffLines(oldLines, newLines)
	hasChange := false
	for _, op := range ops {
		if op.kind != diffEqual {
			hasChange = true
			break
		}
	}
	if !hasChange {
		return ""
	}

	var out strings.Builder
	fmt.Fprintf(&out, "--- %s\n", filepath.ToSlash(path))
	fmt.Fprintf(&out, "+++ %s\n", filepath.ToSlash(path))
	writeHunks(&out, ops)
	return ensureTrailingNewline(out.String())
}

func splitLines(content string) []string {
	content = normalizeLineEndings(content)
	if content == "" {
		return nil
	}
	parts := strings.SplitAfter(content, "\n")
	if parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

func diffLines(oldLines, newLines []string) []diffOp {
	m, n := len(oldLines), len(newLines)
	lcs := make([][]int, m+1)
	for i := range lcs {
		lcs[i] = make([]int, n+1)
	}
	for i := m - 1; i >= 0; i-- {
		for j := n - 1; j >= 0; j-- {
			if oldLines[i] == newLines[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}

	var ops []diffOp
	i, j := 0, 0
	for i < m && j < n {
		if oldLines[i] == newLines[j] {
			ops = append(ops, diffOp{kind: diffEqual, line: oldLines[i]})
			i++
			j++
		} else if lcs[i+1][j] >= lcs[i][j+1] {
			ops = append(ops, diffOp{kind: diffDelete, line: oldLines[i]})
			i++
		} else {
			ops = append(ops, diffOp{kind: diffInsert, line: newLines[j]})
			j++
		}
	}
	for i < m {
		ops = append(ops, diffOp{kind: diffDelete, line: oldLines[i]})
		i++
	}
	for j < n {
		ops = append(ops, diffOp{kind: diffInsert, line: newLines[j]})
		j++
	}
	return ops
}

func writeHunks(out *strings.Builder, ops []diffOp) {
	const context = 3
	oldLine, newLine := 1, 1
	oldBefore := make([]int, len(ops)+1)
	newBefore := make([]int, len(ops)+1)
	for i, op := range ops {
		oldBefore[i] = oldLine
		newBefore[i] = newLine
		if op.kind == diffEqual || op.kind == diffDelete {
			oldLine++
		}
		if op.kind == diffEqual || op.kind == diffInsert {
			newLine++
		}
	}
	oldBefore[len(ops)] = oldLine
	newBefore[len(ops)] = newLine

	for i := 0; i < len(ops); {
		for i < len(ops) && ops[i].kind == diffEqual {
			i++
		}
		if i >= len(ops) {
			break
		}
		start := i - context
		if start < 0 {
			start = 0
		}
		lastChange := i
		trailingEquals := 0
		j := i
		for j < len(ops) {
			if ops[j].kind == diffEqual {
				trailingEquals++
				if trailingEquals > context {
					break
				}
			} else {
				trailingEquals = 0
				lastChange = j
			}
			j++
		}
		end := lastChange + context + 1
		if end > len(ops) {
			end = len(ops)
		}

		oldStart := oldBefore[start]
		newStart := newBefore[start]
		oldCount, newCount := 0, 0
		for _, op := range ops[start:end] {
			if op.kind == diffEqual || op.kind == diffDelete {
				oldCount++
			}
			if op.kind == diffEqual || op.kind == diffInsert {
				newCount++
			}
		}
		fmt.Fprintf(out, "@@ -%d,%d +%d,%d @@\n", oldStart, oldCount, newStart, newCount)
		for _, op := range ops[start:end] {
			switch op.kind {
			case diffEqual:
				out.WriteString(" ")
			case diffDelete:
				out.WriteString("-")
			case diffInsert:
				out.WriteString("+")
			}
			out.WriteString(op.line)
			if !strings.HasSuffix(op.line, "\n") {
				out.WriteString("\n")
			}
		}
		i = end
	}
}

func normalizeLineEndings(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	return strings.ReplaceAll(value, "\r", "\n")
}

func ensureTrailingNewline(value string) string {
	value = normalizeLineEndings(value)
	if value == "" || strings.HasSuffix(value, "\n") {
		return value
	}
	return value + "\n"
}
