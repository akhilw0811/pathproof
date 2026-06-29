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

var openOutputFile = os.OpenFile

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

type WrittenFile struct {
	Source        string `json:"source"`
	Output        string `json:"output,omitempty"`
	PreviewStatus Status `json:"status"`
	Reason        string `json:"reason,omitempty"`
}

func ValidateOutputRoot(root string, outputRoot string) error {
	_, _, err := validateOutputRoot(root, outputRoot)
	return err
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

type sourceState struct {
	source    resolvedSource
	original  string
	documents []*yaml.Node
	ranges    []documentRange
}

type writeCandidate struct {
	preview Preview
	source  resolvedSource
	change  remediation.Change
	state   *sourceState
}

type preparedOutput struct {
	sourceRel string
	display   string
	fullPath  string
	content   []byte
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

func Write(root string, outputRoot string, plans []remediation.Plan) ([]WrittenFile, []Preview, error) {
	if root == "" {
		return nil, nil, fmt.Errorf("patch preview root is empty")
	}
	outputRoot, displayRoot, err := validateOutputRoot(root, outputRoot)
	if err != nil {
		return nil, nil, err
	}

	written, previews, outputs, err := prepareWrite(root, outputRoot, displayRoot, plans)
	if err != nil {
		return nil, nil, err
	}
	if len(outputs) == 0 {
		return written, previews, nil
	}
	if err := writePreparedOutputs(outputRoot, outputs); err != nil {
		return nil, nil, err
	}
	return written, previews, nil
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
	if change.Action == remediation.PinGitHubActionToSHA || optionAction == remediation.PinGitHubActionToSHA {
		return buildGitHubActionPinPreview(root, preview, optionAction, change)
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

func buildGitHubActionPinPreview(root string, preview Preview, optionAction remediation.Action, change remediation.Change) Preview {
	if change.Action != remediation.PinGitHubActionToSHA || optionAction != remediation.PinGitHubActionToSHA {
		preview.Reason = "patch previews support only PinGitHubActionToSHA"
		return preview
	}
	patched, source, reason := buildGitHubActionPatchedContent(root, change)
	if reason != "" {
		preview.Reason = reason
		if source.relPath != "" {
			preview.File = source.relPath
		}
		return preview
	}
	preview.File = source.relPath
	diff := unifiedDiffWithContext(source.relPath, patched.original, patched.content, 0)
	if diff == "" {
		preview.Reason = "patch preview produced no changes"
		return preview
	}
	preview.Status = StatusGenerated
	preview.Reason = ""
	preview.Diff = diff
	return preview
}

func prepareWrite(root, outputRoot, displayRoot string, plans []remediation.Plan) ([]WrittenFile, []Preview, []preparedOutput, error) {
	candidates, previews, err := collectWriteCandidates(root, plans)
	if err != nil {
		return nil, nil, nil, err
	}
	unsupported := make([]WrittenFile, 0)
	bySource := make(map[string][]writeCandidate)
	for _, candidate := range candidates {
		previews = append(previews, candidate.preview)
		if candidate.preview.Status != StatusGenerated {
			unsupported = append(unsupported, WrittenFile{
				Source:        candidate.preview.File,
				PreviewStatus: candidate.preview.Status,
				Reason:        candidate.preview.Reason,
			})
			continue
		}
		bySource[candidate.source.relPath] = append(bySource[candidate.source.relPath], candidate)
	}
	sortPreviews(previews)

	sourcePaths := make([]string, 0, len(bySource))
	for source := range bySource {
		sourcePaths = append(sourcePaths, source)
	}
	sort.Strings(sourcePaths)

	written := make([]WrittenFile, 0, len(sourcePaths)+len(unsupported))
	outputs := make([]preparedOutput, 0, len(sourcePaths))
	for _, source := range sourcePaths {
		output, ok, reason, err := prepareSourceOutput(outputRoot, displayRoot, bySource[source])
		if err != nil {
			return nil, nil, nil, err
		}
		if !ok {
			written = append(written, WrittenFile{
				Source:        source,
				PreviewStatus: StatusUnsupported,
				Reason:        reason,
			})
			continue
		}
		outputs = append(outputs, output)
		written = append(written, WrittenFile{
			Source:        output.sourceRel,
			Output:        output.display,
			PreviewStatus: StatusGenerated,
		})
	}
	written = append(written, unsupported...)
	sort.SliceStable(written, func(i, j int) bool {
		if written[i].PreviewStatus != written[j].PreviewStatus {
			return written[i].PreviewStatus < written[j].PreviewStatus
		}
		if written[i].Source != written[j].Source {
			return written[i].Source < written[j].Source
		}
		if written[i].Output != written[j].Output {
			return written[i].Output < written[j].Output
		}
		return written[i].Reason < written[j].Reason
	})
	return written, previews, outputs, nil
}

func collectWriteCandidates(root string, plans []remediation.Plan) ([]writeCandidate, []Preview, error) {
	orderedPlans := append([]remediation.Plan(nil), plans...)
	sort.SliceStable(orderedPlans, func(i, j int) bool {
		return orderedPlans[i].ID < orderedPlans[j].ID
	})
	sourceCache := make(map[string]*sourceState)
	candidates := make([]writeCandidate, 0)
	for _, plan := range orderedPlans {
		for optionIndex, option := range plan.Options {
			for changeIndex, change := range option.Changes {
				candidate := buildWriteCandidate(root, sourceCache, plan.ID, optionIndex, option.Action, changeIndex, change)
				candidates = append(candidates, candidate)
			}
		}
	}
	return candidates, nil, nil
}

func buildWriteCandidate(root string, sourceCache map[string]*sourceState, planID remediation.PlanID, optionIndex int, optionAction remediation.Action, changeIndex int, change remediation.Change) writeCandidate {
	preview := Preview{
		PlanID:       planID,
		OptionIndex:  optionIndex,
		OptionAction: optionAction,
		ChangeIndex:  changeIndex,
		Status:       StatusUnsupported,
		Summary:      change.Summary,
	}
	if change.Action == remediation.PinGitHubActionToSHA || optionAction == remediation.PinGitHubActionToSHA {
		preview = buildGitHubActionPinPreview(root, preview, optionAction, change)
		source, reason := resolveSourceReference(root, change.SourceReference)
		if reason == "" {
			return writeCandidate{preview: preview, source: source, change: change}
		}
		return writeCandidate{preview: preview, change: change}
	}
	if change.Action != remediation.NarrowBindingSubject || optionAction != remediation.NarrowBindingSubject {
		preview.Reason = "patch previews support only NarrowBindingSubject"
		return writeCandidate{preview: preview, change: change}
	}

	source, reason := resolveSourceReference(root, change.SourceReference)
	if reason != "" {
		preview.Reason = reason
		return writeCandidate{preview: preview, change: change}
	}
	preview.File = source.relPath

	state, reason := loadSourceState(sourceCache, source)
	if reason != "" {
		preview.Reason = reason
		return writeCandidate{preview: preview, source: source, change: change}
	}
	if source.document < 1 || source.document > len(state.documents) {
		preview.Reason = "source reference document is outside the file"
		return writeCandidate{preview: preview, source: source, change: change, state: state}
	}
	if sourceFileContainsSecretPayload(state.documents) {
		preview.Reason = "source file contains a Secret payload, so patch preview is disabled for this file"
		return writeCandidate{preview: preview, source: source, change: change, state: state}
	}
	if len(state.ranges) != len(state.documents) {
		preview.Reason = "source YAML document structure is unsupported"
		return writeCandidate{preview: preview, source: source, change: change, state: state}
	}

	patchedDocument, reason := patchBindingDocument(state.documents[source.document-1], change)
	if reason != "" {
		preview.Reason = reason
		return writeCandidate{preview: preview, source: source, change: change, state: state}
	}
	encoded, err := encodeDocument(patchedDocument)
	if err != nil {
		preview.Reason = "patched YAML cannot be encoded"
		return writeCandidate{preview: preview, source: source, change: change, state: state}
	}

	patched := replaceDocument(state.original, state.ranges[source.document-1], encoded)
	if _, reason := parseDocuments(patched); reason != "" {
		preview.Reason = "patched YAML cannot be parsed"
		return writeCandidate{preview: preview, source: source, change: change, state: state}
	}
	diff := unifiedDiff(source.relPath, state.original, patched)
	if diff == "" {
		preview.Reason = "patch preview produced no changes"
		return writeCandidate{preview: preview, source: source, change: change, state: state}
	}

	preview.Status = StatusGenerated
	preview.Reason = ""
	preview.Diff = diff
	return writeCandidate{preview: preview, source: source, change: change, state: state}
}

func loadSourceState(sourceCache map[string]*sourceState, source resolvedSource) (*sourceState, string) {
	if state, ok := sourceCache[source.fullPath]; ok {
		return state, ""
	}
	original, err := os.ReadFile(source.fullPath)
	if err != nil {
		return nil, "source file cannot be read"
	}
	normalizedOriginal := normalizeLineEndings(string(original))
	documents, reason := parseDocuments(normalizedOriginal)
	if reason != "" {
		return nil, reason
	}
	ranges := splitDocumentRanges(normalizedOriginal)
	state := &sourceState{
		source:    source,
		original:  normalizedOriginal,
		documents: documents,
		ranges:    ranges,
	}
	sourceCache[source.fullPath] = state
	return state, ""
}

func prepareSourceOutput(outputRoot, displayRoot string, candidates []writeCandidate) (preparedOutput, bool, string, error) {
	if len(candidates) == 0 {
		return preparedOutput{}, false, "no generated patch previews for source file", nil
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i].preview, candidates[j].preview
		if a.PlanID != b.PlanID {
			return a.PlanID < b.PlanID
		}
		if a.OptionIndex != b.OptionIndex {
			return a.OptionIndex < b.OptionIndex
		}
		if a.ChangeIndex != b.ChangeIndex {
			return a.ChangeIndex < b.ChangeIndex
		}
		return a.File < b.File
	})

	if candidates[0].change.Action == remediation.PinGitHubActionToSHA {
		return prepareGitHubActionSourceOutput(outputRoot, displayRoot, candidates)
	}
	for _, candidate := range candidates {
		if candidate.change.Action != remediation.NarrowBindingSubject {
			return preparedOutput{}, false, "multiple generated patches for this source file conflict", nil
		}
	}

	state := candidates[0].state
	if state == nil {
		return preparedOutput{}, false, "source file could not be prepared for writing", nil
	}
	working := make([]*yaml.Node, len(state.documents))
	for i, document := range state.documents {
		working[i] = cloneNode(document)
	}

	seen := make(map[string]struct{}, len(candidates))
	changed := make(map[int]struct{}, len(candidates))
	for _, candidate := range candidates {
		identity := writeChangeIdentity(candidate)
		if _, ok := seen[identity]; ok {
			continue
		}
		seen[identity] = struct{}{}

		documentIndex := candidate.source.document - 1
		if documentIndex < 0 || documentIndex >= len(working) {
			return preparedOutput{}, false, "source reference document is outside the file", nil
		}
		patchedDocument, reason := patchBindingDocument(working[documentIndex], candidate.change)
		if reason != "" {
			return preparedOutput{}, false, "multiple generated patches for this source file conflict", nil
		}
		working[documentIndex] = patchedDocument
		changed[documentIndex] = struct{}{}
	}
	if len(changed) == 0 {
		return preparedOutput{}, false, "patch output produced no changes", nil
	}

	indexes := make([]int, 0, len(changed))
	for index := range changed {
		indexes = append(indexes, index)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(indexes)))

	patched := state.original
	for _, index := range indexes {
		encoded, err := encodeDocument(working[index])
		if err != nil {
			return preparedOutput{}, false, "patched YAML cannot be encoded", nil
		}
		patched = replaceDocument(patched, state.ranges[index], encoded)
	}
	if _, reason := parseDocuments(patched); reason != "" {
		return preparedOutput{}, false, reason, nil
	}

	sourceRel := candidates[0].source.relPath
	fullPath := filepath.Join(outputRoot, filepath.FromSlash(sourceRel))
	if !pathWithinRoot(outputRoot, fullPath) {
		return preparedOutput{}, false, "", fmt.Errorf("patch output path escapes output directory")
	}
	return preparedOutput{
		sourceRel: sourceRel,
		display:   filepath.ToSlash(filepath.Join(displayRoot, filepath.FromSlash(sourceRel))),
		fullPath:  fullPath,
		content:   []byte(ensureTrailingNewline(patched)),
	}, true, "", nil
}

type githubActionPatchedContent struct {
	original string
	content  string
}

func buildGitHubActionPatchedContent(root string, change remediation.Change) (githubActionPatchedContent, resolvedSource, string) {
	if !change.PatchSupported {
		if change.Reason != "" {
			return githubActionPatchedContent{}, resolvedSource{}, change.Reason
		}
		return githubActionPatchedContent{}, resolvedSource{}, "patching is not supported for this advisory remediation"
	}
	if change.ActionRef == "" || change.ReplacementRef == "" || change.ReplacementSHA == "" {
		return githubActionPatchedContent{}, resolvedSource{}, "replacement metadata is incomplete"
	}
	if change.SourceLine <= 0 || change.SourceColumn <= 0 {
		return githubActionPatchedContent{}, resolvedSource{}, "uses source location is not precise enough to patch"
	}
	source, reason := resolveSourceReference(root, change.SourceReference)
	if reason != "" {
		return githubActionPatchedContent{}, resolvedSource{}, reason
	}
	originalBytes, err := os.ReadFile(source.fullPath)
	if err != nil {
		return githubActionPatchedContent{}, source, "source file cannot be read"
	}
	original := normalizeLineEndings(string(originalBytes))
	patched, reason := replaceGitHubActionRef(original, change)
	if reason != "" {
		return githubActionPatchedContent{}, source, reason
	}
	return githubActionPatchedContent{original: original, content: patched}, source, ""
}

func prepareGitHubActionSourceOutput(outputRoot, displayRoot string, candidates []writeCandidate) (preparedOutput, bool, string, error) {
	for _, candidate := range candidates {
		if candidate.change.Action != remediation.PinGitHubActionToSHA {
			return preparedOutput{}, false, "multiple generated patches for this source file conflict", nil
		}
	}
	source := candidates[0].source
	originalBytes, err := os.ReadFile(source.fullPath)
	if err != nil {
		return preparedOutput{}, false, "source file cannot be read", nil
	}
	working := normalizeLineEndings(string(originalBytes))
	ordered := append([]writeCandidate(nil), candidates...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i].change, ordered[j].change
		if a.SourceLine != b.SourceLine {
			return a.SourceLine > b.SourceLine
		}
		if a.SourceColumn != b.SourceColumn {
			return a.SourceColumn > b.SourceColumn
		}
		return githubActionWriteChangeIdentity(ordered[i]) < githubActionWriteChangeIdentity(ordered[j])
	})
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range ordered {
		identity := githubActionWriteChangeIdentity(candidate)
		if _, ok := seen[identity]; ok {
			continue
		}
		seen[identity] = struct{}{}
		patched, reason := replaceGitHubActionRef(working, candidate.change)
		if reason != "" {
			return preparedOutput{}, false, "multiple generated patches for this source file conflict", nil
		}
		working = patched
	}
	if working == normalizeLineEndings(string(originalBytes)) {
		return preparedOutput{}, false, "patch output produced no changes", nil
	}
	fullPath := filepath.Join(outputRoot, filepath.FromSlash(source.relPath))
	if !pathWithinRoot(outputRoot, fullPath) {
		return preparedOutput{}, false, "", fmt.Errorf("patch output path escapes output directory")
	}
	return preparedOutput{
		sourceRel: source.relPath,
		display:   filepath.ToSlash(filepath.Join(displayRoot, filepath.FromSlash(source.relPath))),
		fullPath:  fullPath,
		content:   []byte(ensureTrailingNewline(working)),
	}, true, "", nil
}

func githubActionWriteChangeIdentity(candidate writeCandidate) string {
	return strings.Join([]string{
		candidate.source.relPath,
		strconv.Itoa(candidate.change.SourceLine),
		strconv.Itoa(candidate.change.SourceColumn),
		candidate.change.ActionRef,
		candidate.change.ReplacementRef,
	}, "\x00")
}

func replaceGitHubActionRef(content string, change remediation.Change) (string, string) {
	lines := splitLines(ensureTrailingNewline(content))
	lineIndex := change.SourceLine - 1
	if lineIndex < 0 || lineIndex >= len(lines) {
		return "", "uses source location is outside the file"
	}
	line := strings.TrimSuffix(lines[lineIndex], "\n")
	columnIndex := change.SourceColumn - 1
	if columnIndex < 0 || columnIndex > len(line) {
		return "", "uses source location is outside the line"
	}
	if !strings.HasPrefix(line[columnIndex:], change.ActionRef) {
		return "", "uses source location does not match the action ref"
	}
	if _, ref, ok := strings.Cut(change.ActionRef, "@"); !ok || ref == "" {
		return "", "action ref has no explicit ref to replace"
	}
	lineEnd := columnIndex + len(change.ActionRef)
	if strings.Contains(line[lineEnd:], "#") {
		return "", "uses value has a same-line comment"
	}
	patchedLine := line[:columnIndex] + change.ReplacementRef + line[lineEnd:]
	lines[lineIndex] = patchedLine + "\n"
	return strings.Join(lines, ""), ""
}

func writeChangeIdentity(candidate writeCandidate) string {
	target := candidate.change.Target
	return strings.Join([]string{
		candidate.source.relPath,
		strconv.Itoa(candidate.source.document),
		target.Kind,
		target.Namespace,
		target.Name,
		candidate.change.Subject,
	}, "\x00")
}

func sortPreviews(previews []Preview) {
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
}

func resolveSourceReference(root, value string) (resolvedSource, string) {
	ref, reason := parseSourceReference(value)
	if reason != "" {
		return resolvedSource{}, reason
	}

	realRoot, err := evaluateExistingPath(root)
	if err != nil {
		return resolvedSource{}, "scan root cannot be resolved"
	}
	candidate, reason := sourceCandidatePath(root, ref.filename)
	if reason != "" {
		return resolvedSource{}, reason
	}
	realFull, err := evaluatePathForCreation(candidate)
	if err != nil {
		return resolvedSource{}, "source reference path cannot be resolved"
	}
	if realFull == realRoot || !isPathInside(realFull, realRoot) {
		return resolvedSource{}, "source reference path escapes the scan root"
	}
	relPath, err := filepath.Rel(realRoot, realFull)
	if err != nil || relPath == "." || relPath == ".." || strings.HasPrefix(relPath, ".."+string(filepath.Separator)) {
		return resolvedSource{}, "source reference path escapes the scan root"
	}
	relPath = filepath.ToSlash(filepath.Clean(relPath))

	return resolvedSource{fullPath: candidate, relPath: relPath, document: ref.document}, ""
}

func validateOutputRoot(root, outputRoot string) (string, string, error) {
	if outputRoot == "" {
		return "", "", fmt.Errorf("patch output directory is required")
	}
	cleanOutput := filepath.Clean(outputRoot)
	realRoot, err := evaluateExistingPath(root)
	if err != nil {
		return "", "", fmt.Errorf("scan root cannot be resolved")
	}
	realOutput, err := evaluatePathForCreation(cleanOutput)
	if err != nil {
		return "", "", fmt.Errorf("patch output directory cannot be resolved")
	}
	if realRoot == realOutput {
		return "", "", fmt.Errorf("patch output directory must differ from scan directory")
	}
	if isPathInside(realOutput, realRoot) {
		return "", "", fmt.Errorf("patch output directory must not be inside scan directory")
	}
	if isPathInside(realRoot, realOutput) {
		return "", "", fmt.Errorf("scan directory must not be inside patch output directory")
	}
	info, err := os.Stat(cleanOutput)
	if err == nil {
		if !info.IsDir() {
			return "", "", fmt.Errorf("patch output path exists and is not a directory")
		}
		entries, err := os.ReadDir(cleanOutput)
		if err != nil {
			return "", "", fmt.Errorf("patch output directory cannot be inspected")
		}
		if len(entries) > 0 {
			return "", "", fmt.Errorf("patch output directory must be empty")
		}
	} else if !os.IsNotExist(err) {
		return "", "", fmt.Errorf("patch output path cannot be inspected")
	}
	displayRoot := filepath.Base(cleanOutput)
	if displayRoot == "" || displayRoot == "." || displayRoot == string(filepath.Separator) {
		displayRoot = "output"
	}
	return cleanOutput, displayRoot, nil
}

func sourceCandidatePath(root, filename string) (string, string) {
	cleanFilename := filepath.Clean(filename)
	if filepath.IsAbs(cleanFilename) {
		return cleanFilename, ""
	}
	if cleanFilename == "." || strings.HasPrefix(cleanFilename, ".."+string(filepath.Separator)) || cleanFilename == ".." {
		return "", "source reference path escapes the scan root"
	}
	cleanRoot := filepath.Clean(root)
	if rel, ok := relativeToRoot(cleanRoot, cleanFilename); ok {
		return filepath.Clean(filepath.Join(cleanRoot, rel)), ""
	}
	return filepath.Join(root, cleanFilename), ""
}

func evaluateExistingPath(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

func evaluatePathForCreation(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absPath = filepath.Clean(absPath)
	if resolved, err := filepath.EvalSymlinks(absPath); err == nil {
		return filepath.Clean(resolved), nil
	}

	current := absPath
	missing := []string{}
	for {
		if _, err := os.Lstat(current); err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", err
			}
			parts := append([]string{resolved}, missing...)
			return filepath.Clean(filepath.Join(parts...)), nil
		} else if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", os.ErrNotExist
		}
		missing = append([]string{filepath.Base(current)}, missing...)
		current = parent
	}
}

func isPathInside(child, parent string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func pathWithinRoot(root, path string) bool {
	realRoot, err := evaluatePathForCreation(root)
	if err != nil {
		return false
	}
	realPath, err := evaluatePathForCreation(path)
	if err != nil {
		return false
	}
	return realPath == realRoot || isPathInside(realPath, realRoot)
}

func writePreparedOutputs(outputRoot string, outputs []preparedOutput) error {
	sort.SliceStable(outputs, func(i, j int) bool {
		return outputs[i].sourceRel < outputs[j].sourceRel
	})
	var createdFiles []string
	var createdDirs []string
	for _, output := range outputs {
		if err := mkdirAllTracked(filepath.Dir(output.fullPath), outputRoot, &createdDirs); err != nil {
			cleanupCreated(createdFiles, createdDirs)
			return fmt.Errorf("write patch output: %w", err)
		}
		file, err := openOutputFile(output.fullPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			cleanupCreated(createdFiles, createdDirs)
			return fmt.Errorf("write patch output file: %w", err)
		}
		createdFiles = append(createdFiles, output.fullPath)
		if _, err := file.Write(output.content); err != nil {
			_ = file.Close()
			cleanupCreated(createdFiles, createdDirs)
			return fmt.Errorf("write patch output file: %w", err)
		}
		if err := file.Close(); err != nil {
			cleanupCreated(createdFiles, createdDirs)
			return fmt.Errorf("write patch output file: %w", err)
		}
	}
	return nil
}

func mkdirAllTracked(dir, root string, created *[]string) error {
	cleanRoot := filepath.Clean(root)
	cleanDir := filepath.Clean(dir)
	if !pathWithinRoot(cleanRoot, cleanDir) {
		return fmt.Errorf("patch output path escapes output directory")
	}
	stack := []string{}
	for current := cleanDir; ; current = filepath.Dir(current) {
		stack = append(stack, current)
		if current == cleanRoot {
			break
		}
		next := filepath.Dir(current)
		if next == current {
			return fmt.Errorf("patch output path escapes output directory")
		}
	}
	for i := len(stack) - 1; i >= 0; i-- {
		path := stack[i]
		info, err := os.Stat(path)
		if err == nil {
			if !info.IsDir() {
				return fmt.Errorf("patch output parent exists and is not a directory")
			}
			continue
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("patch output directory cannot be inspected")
		}
		if err := os.Mkdir(path, 0o755); err != nil {
			return err
		}
		*created = append(*created, path)
	}
	return nil
}

func cleanupCreated(files, dirs []string) {
	for i := len(files) - 1; i >= 0; i-- {
		_ = os.Remove(files[i])
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		_ = os.Remove(dirs[i])
	}
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
	return unifiedDiffWithContext(path, oldContent, newContent, 3)
}

func unifiedDiffWithContext(path, oldContent, newContent string, context int) string {
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
	writeHunksWithContext(&out, ops, context)
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
	writeHunksWithContext(out, ops, 3)
}

func writeHunksWithContext(out *strings.Builder, ops []diffOp, context int) {
	if context < 0 {
		context = 0
	}
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
