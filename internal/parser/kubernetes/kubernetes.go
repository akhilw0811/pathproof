package kubernetes

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
	Services    []Service
	Deployments []Deployment
}

type Source struct {
	Filename string
	Document int
}

type Service struct {
	Namespace string
	Name      string
	Type      string
	Selector  map[string]string
	Source    Source
}

type Deployment struct {
	Namespace string
	Name      string
	PodLabels map[string]string
	Source    Source
}

func ParseDir(dir string) (Resources, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Resources{}, fmt.Errorf("read kubernetes manifest directory %q: %w", dir, err)
	}

	var paths []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := filepath.Ext(name)
		if ext == ".yaml" || ext == ".yml" {
			paths = append(paths, filepath.Join(dir, name))
		}
	}
	sort.Strings(paths)

	var resources Resources
	for _, path := range paths {
		fileResources, err := parseFile(path)
		if err != nil {
			return Resources{}, err
		}
		resources.Services = append(resources.Services, fileResources.Services...)
		resources.Deployments = append(resources.Deployments, fileResources.Deployments...)
	}

	sortResources(resources)
	return resources, nil
}

func parseFile(path string) (Resources, error) {
	file, err := os.Open(path)
	if err != nil {
		return Resources{}, fmt.Errorf("open kubernetes manifest %q: %w", path, err)
	}
	defer file.Close()

	return parseDocuments(file, path)
}

func parseDocuments(r io.Reader, filename string) (Resources, error) {
	decoder := yaml.NewDecoder(r)
	var resources Resources

	for document := 1; ; document++ {
		var documentNode yaml.Node
		err := decoder.Decode(&documentNode)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Resources{}, fmt.Errorf("parse kubernetes manifest %q document %d: %w", filename, document, err)
		}

		var meta documentMetadata
		if err := documentNode.Decode(&meta); err != nil {
			return Resources{}, fmt.Errorf("parse kubernetes manifest %q document %d metadata: %w", filename, document, err)
		}
		if meta.Kind == "" {
			continue
		}

		source := Source{Filename: filename, Document: document}
		switch meta.Kind {
		case "Service":
			var manifest serviceManifest
			if err := documentNode.Decode(&manifest); err != nil {
				return Resources{}, fmt.Errorf("parse kubernetes Service %q document %d: %w", filename, document, err)
			}
			resources.Services = append(resources.Services, Service{
				Namespace: namespaceOrDefault(manifest.Metadata.Namespace),
				Name:      manifest.Metadata.Name,
				Type:      manifest.Spec.Type,
				Selector:  copyMap(manifest.Spec.Selector),
				Source:    source,
			})
		case "Deployment":
			var manifest deploymentManifest
			if err := documentNode.Decode(&manifest); err != nil {
				return Resources{}, fmt.Errorf("parse kubernetes Deployment %q document %d: %w", filename, document, err)
			}
			resources.Deployments = append(resources.Deployments, Deployment{
				Namespace: namespaceOrDefault(manifest.Metadata.Namespace),
				Name:      manifest.Metadata.Name,
				PodLabels: copyMap(manifest.Spec.Template.Metadata.Labels),
				Source:    source,
			})
		}
	}

	return resources, nil
}

func sortResources(resources Resources) {
	sort.SliceStable(resources.Services, func(i, j int) bool {
		return serviceLess(resources.Services[i], resources.Services[j])
	})
	sort.SliceStable(resources.Deployments, func(i, j int) bool {
		return deploymentLess(resources.Deployments[i], resources.Deployments[j])
	})
}

func serviceLess(a, b Service) bool {
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return sourceLess(a.Source, b.Source)
}

func deploymentLess(a, b Deployment) bool {
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return sourceLess(a.Source, b.Source)
}

func sourceLess(a, b Source) bool {
	if a.Filename != b.Filename {
		return a.Filename < b.Filename
	}
	return a.Document < b.Document
}

func namespaceOrDefault(namespace string) string {
	if namespace == "" {
		return "default"
	}
	return namespace
}

func copyMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

type documentMetadata struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
}

type serviceManifest struct {
	Metadata metadata    `yaml:"metadata"`
	Spec     serviceSpec `yaml:"spec"`
}

type deploymentManifest struct {
	Metadata metadata       `yaml:"metadata"`
	Spec     deploymentSpec `yaml:"spec"`
}

type metadata struct {
	Name      string            `yaml:"name"`
	Namespace string            `yaml:"namespace"`
	Labels    map[string]string `yaml:"labels"`
}

type serviceSpec struct {
	Type     string            `yaml:"type"`
	Selector map[string]string `yaml:"selector"`
}

type deploymentSpec struct {
	Template template `yaml:"template"`
}

type template struct {
	Metadata metadata `yaml:"metadata"`
}
