package githubactions

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

type Resources struct {
	Workflows []Workflow `json:"workflows,omitempty"`
}

type Source struct {
	Filename     string `json:"filename"`
	RelativePath string `json:"relative_path"`
	Document     int    `json:"document"`
}

type Workflow struct {
	Name   string `json:"name,omitempty"`
	Source Source `json:"source"`
	Jobs   []Job  `json:"jobs,omitempty"`
}

type Job struct {
	ID    string `json:"id"`
	Steps []Step `json:"steps,omitempty"`
}

type Step struct {
	Index int    `json:"index"`
	Name  string `json:"name,omitempty"`
	Uses  string `json:"uses"`
}

func ParseDir(root string) (Resources, error) {
	workflowDir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(workflowDir)
	if errors.Is(err, os.ErrNotExist) {
		return Resources{}, nil
	}
	if err != nil {
		return Resources{}, fmt.Errorf("read github actions workflow directory %q: %w", workflowDir, err)
	}

	var paths []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := filepath.Ext(name)
		if ext != ".yml" && ext != ".yaml" {
			continue
		}
		paths = append(paths, filepath.Join(workflowDir, name))
	}
	sort.Strings(paths)

	resources := Resources{Workflows: make([]Workflow, 0, len(paths))}
	for _, path := range paths {
		workflow, err := parseFile(root, path)
		if err != nil {
			return Resources{}, err
		}
		resources.Workflows = append(resources.Workflows, workflow)
	}
	sortWorkflows(resources.Workflows)
	return resources, nil
}

func parseFile(root, path string) (Workflow, error) {
	file, err := os.Open(path)
	if err != nil {
		return Workflow{}, fmt.Errorf("open github actions workflow %q: %w", path, err)
	}
	defer file.Close()

	return parseWorkflow(file, root, path)
}

func parseWorkflow(r io.Reader, root, filename string) (Workflow, error) {
	relPath := workflowRelativePath(root, filename)
	decoder := yaml.NewDecoder(r)
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		if errors.Is(err, io.EOF) {
			document = yaml.Node{Kind: yaml.MappingNode}
		} else {
			return Workflow{}, invalidYAMLError(relPath, 1)
		}
	}

	for documentIndex := 2; ; documentIndex++ {
		var extra yaml.Node
		err := decoder.Decode(&extra)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Workflow{}, invalidYAMLError(relPath, documentIndex)
		}
	}
	source := Source{
		Filename:     filename,
		RelativePath: relPath,
		Document:     1,
	}
	if document.Kind == yaml.DocumentNode && len(document.Content) > 0 {
		document = *document.Content[0]
	}
	if document.Kind != yaml.MappingNode {
		return Workflow{Source: source}, nil
	}

	workflow := Workflow{Source: source}
	if name := scalarMappingValue(&document, "name"); name != nil {
		workflow.Name = name.Value
	}
	if jobs := mappingValue(&document, "jobs"); jobs != nil && jobs.Kind == yaml.MappingNode {
		workflow.Jobs = parseJobs(jobs)
	}
	sortJobs(workflow.Jobs)
	return workflow, nil
}

func workflowRelativePath(root, filename string) string {
	relPath, err := filepath.Rel(root, filename)
	if err != nil {
		relPath = filename
	}
	return filepath.ToSlash(filepath.Clean(relPath))
}

func invalidYAMLError(relPath string, document int) error {
	return fmt.Errorf("github actions workflow %s document %d: invalid YAML", relPath, document)
}

func parseJobs(jobs *yaml.Node) []Job {
	out := make([]Job, 0, len(jobs.Content)/2)
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		key := jobs.Content[i]
		value := jobs.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Value == "" || value.Kind != yaml.MappingNode {
			continue
		}
		job := Job{ID: key.Value}
		if steps := mappingValue(value, "steps"); steps != nil && steps.Kind == yaml.SequenceNode {
			job.Steps = parseSteps(steps)
		}
		out = append(out, job)
	}
	sortJobs(out)
	return out
}

func parseSteps(steps *yaml.Node) []Step {
	out := make([]Step, 0, len(steps.Content))
	for i, stepNode := range steps.Content {
		if stepNode.Kind != yaml.MappingNode {
			continue
		}
		uses := scalarMappingValue(stepNode, "uses")
		if uses == nil || uses.Value == "" {
			continue
		}
		step := Step{
			Index: i,
			Uses:  uses.Value,
		}
		if name := scalarMappingValue(stepNode, "name"); name != nil {
			step.Name = name.Value
		}
		out = append(out, step)
	}
	return out
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

func scalarMappingValue(node *yaml.Node, key string) *yaml.Node {
	value := mappingValue(node, key)
	if value == nil || value.Kind != yaml.ScalarNode {
		return nil
	}
	return value
}

func sortWorkflows(workflows []Workflow) {
	sort.SliceStable(workflows, func(i, j int) bool {
		return workflows[i].Source.RelativePath < workflows[j].Source.RelativePath
	})
}

func sortJobs(jobs []Job) {
	sort.SliceStable(jobs, func(i, j int) bool {
		return jobs[i].ID < jobs[j].ID
	})
}
