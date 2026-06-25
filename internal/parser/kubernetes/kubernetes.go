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
	Services            []Service
	Deployments         []Deployment
	Ingresses           []Ingress
	ServiceAccounts     []ServiceAccount
	Roles               []Role
	ClusterRoles        []ClusterRole
	RoleBindings        []RoleBinding
	ClusterRoleBindings []ClusterRoleBinding
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
	Namespace          string
	Name               string
	PodLabels          map[string]string
	ServiceAccountName string
	Source             Source
}

type Ingress struct {
	Namespace string
	Name      string
	Backends  []IngressBackend
	Source    Source
}

type IngressBackend struct {
	Kind        string
	ServiceName string
}

type ServiceAccount struct {
	Namespace                    string
	Name                         string
	AutomountServiceAccountToken *bool
	Source                       Source
}

type PolicyRule struct {
	APIGroups       []string
	Resources       []string
	ResourceNames   []string
	Verbs           []string
	NonResourceURLs []string
}

type Role struct {
	Namespace string
	Name      string
	Rules     []PolicyRule
	Source    Source
}

type ClusterRole struct {
	Name   string
	Rules  []PolicyRule
	Source Source
}

type RoleRef struct {
	APIGroup string
	Kind     string
	Name     string
}

type Subject struct {
	Kind      string
	Namespace string
	Name      string
}

type RoleBinding struct {
	Namespace string
	Name      string
	RoleRef   RoleRef
	Subjects  []Subject
	Source    Source
}

type ClusterRoleBinding struct {
	Name     string
	RoleRef  RoleRef
	Subjects []Subject
	Source   Source
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
		resources.Ingresses = append(resources.Ingresses, fileResources.Ingresses...)
		resources.ServiceAccounts = append(resources.ServiceAccounts, fileResources.ServiceAccounts...)
		resources.Roles = append(resources.Roles, fileResources.Roles...)
		resources.ClusterRoles = append(resources.ClusterRoles, fileResources.ClusterRoles...)
		resources.RoleBindings = append(resources.RoleBindings, fileResources.RoleBindings...)
		resources.ClusterRoleBindings = append(resources.ClusterRoleBindings, fileResources.ClusterRoleBindings...)
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
				Namespace:          namespaceOrDefault(manifest.Metadata.Namespace),
				Name:               manifest.Metadata.Name,
				PodLabels:          copyMap(manifest.Spec.Template.Metadata.Labels),
				ServiceAccountName: serviceAccountNameOrDefault(manifest.Spec.Template.Spec.ServiceAccountName),
				Source:             source,
			})
		case "Ingress":
			if meta.APIVersion != "networking.k8s.io/v1" {
				continue
			}
			var manifest ingressManifest
			if err := documentNode.Decode(&manifest); err != nil {
				return Resources{}, fmt.Errorf("parse kubernetes Ingress %q document %d: %w", filename, document, err)
			}
			resources.Ingresses = append(resources.Ingresses, Ingress{
				Namespace: namespaceOrDefault(manifest.Metadata.Namespace),
				Name:      manifest.Metadata.Name,
				Backends:  ingressBackends(manifest.Spec),
				Source:    source,
			})
		case "ServiceAccount":
			if meta.APIVersion != "v1" {
				continue
			}
			var manifest serviceAccountManifest
			if err := documentNode.Decode(&manifest); err != nil {
				return Resources{}, fmt.Errorf("parse kubernetes ServiceAccount %q document %d: %w", filename, document, err)
			}
			resources.ServiceAccounts = append(resources.ServiceAccounts, ServiceAccount{
				Namespace:                    namespaceOrDefault(manifest.Metadata.Namespace),
				Name:                         manifest.Metadata.Name,
				AutomountServiceAccountToken: manifest.AutomountServiceAccountToken,
				Source:                       source,
			})
		case "Role":
			if meta.APIVersion != "rbac.authorization.k8s.io/v1" {
				continue
			}
			var manifest roleManifest
			if err := documentNode.Decode(&manifest); err != nil {
				return Resources{}, fmt.Errorf("parse kubernetes Role %q document %d: %w", filename, document, err)
			}
			resources.Roles = append(resources.Roles, Role{
				Namespace: namespaceOrDefault(manifest.Metadata.Namespace),
				Name:      manifest.Metadata.Name,
				Rules:     canonicalPolicyRules(manifest.Rules),
				Source:    source,
			})
		case "ClusterRole":
			if meta.APIVersion != "rbac.authorization.k8s.io/v1" {
				continue
			}
			var manifest clusterRoleManifest
			if err := documentNode.Decode(&manifest); err != nil {
				return Resources{}, fmt.Errorf("parse kubernetes ClusterRole %q document %d: %w", filename, document, err)
			}
			resources.ClusterRoles = append(resources.ClusterRoles, ClusterRole{
				Name:   manifest.Metadata.Name,
				Rules:  canonicalPolicyRules(manifest.Rules),
				Source: source,
			})
		case "RoleBinding":
			if meta.APIVersion != "rbac.authorization.k8s.io/v1" {
				continue
			}
			var manifest roleBindingManifest
			if err := documentNode.Decode(&manifest); err != nil {
				return Resources{}, fmt.Errorf("parse kubernetes RoleBinding %q document %d: %w", filename, document, err)
			}
			resources.RoleBindings = append(resources.RoleBindings, RoleBinding{
				Namespace: namespaceOrDefault(manifest.Metadata.Namespace),
				Name:      manifest.Metadata.Name,
				RoleRef:   roleRef(manifest.RoleRef),
				Subjects:  serviceAccountSubjects(manifest.Subjects),
				Source:    source,
			})
		case "ClusterRoleBinding":
			if meta.APIVersion != "rbac.authorization.k8s.io/v1" {
				continue
			}
			var manifest clusterRoleBindingManifest
			if err := documentNode.Decode(&manifest); err != nil {
				return Resources{}, fmt.Errorf("parse kubernetes ClusterRoleBinding %q document %d: %w", filename, document, err)
			}
			resources.ClusterRoleBindings = append(resources.ClusterRoleBindings, ClusterRoleBinding{
				Name:     manifest.Metadata.Name,
				RoleRef:  roleRef(manifest.RoleRef),
				Subjects: serviceAccountSubjects(manifest.Subjects),
				Source:   source,
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
	sort.SliceStable(resources.Ingresses, func(i, j int) bool {
		return ingressLess(resources.Ingresses[i], resources.Ingresses[j])
	})
	sort.SliceStable(resources.ServiceAccounts, func(i, j int) bool {
		return serviceAccountLess(resources.ServiceAccounts[i], resources.ServiceAccounts[j])
	})
	sort.SliceStable(resources.Roles, func(i, j int) bool {
		return roleLess(resources.Roles[i], resources.Roles[j])
	})
	sort.SliceStable(resources.ClusterRoles, func(i, j int) bool {
		return clusterRoleLess(resources.ClusterRoles[i], resources.ClusterRoles[j])
	})
	sort.SliceStable(resources.RoleBindings, func(i, j int) bool {
		return roleBindingLess(resources.RoleBindings[i], resources.RoleBindings[j])
	})
	sort.SliceStable(resources.ClusterRoleBindings, func(i, j int) bool {
		return clusterRoleBindingLess(resources.ClusterRoleBindings[i], resources.ClusterRoleBindings[j])
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

func ingressLess(a, b Ingress) bool {
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return sourceLess(a.Source, b.Source)
}

func serviceAccountLess(a, b ServiceAccount) bool {
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return sourceLess(a.Source, b.Source)
}

func roleLess(a, b Role) bool {
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return sourceLess(a.Source, b.Source)
}

func clusterRoleLess(a, b ClusterRole) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return sourceLess(a.Source, b.Source)
}

func roleBindingLess(a, b RoleBinding) bool {
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return sourceLess(a.Source, b.Source)
}

func clusterRoleBindingLess(a, b ClusterRoleBinding) bool {
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

func serviceAccountNameOrDefault(name string) string {
	if name == "" {
		return "default"
	}
	return name
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

func roleRef(in roleRefManifest) RoleRef {
	return RoleRef{
		APIGroup: in.APIGroup,
		Kind:     in.Kind,
		Name:     in.Name,
	}
}

func serviceAccountSubjects(in []subjectManifest) []Subject {
	var subjects []Subject
	seen := make(map[Subject]struct{}, len(in))
	for _, subject := range in {
		if subject.Kind != "ServiceAccount" {
			continue
		}
		item := Subject{
			Kind:      subject.Kind,
			Namespace: subject.Namespace,
			Name:      subject.Name,
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		subjects = append(subjects, item)
	}
	sort.Slice(subjects, func(i, j int) bool {
		if subjects[i].Namespace != subjects[j].Namespace {
			return subjects[i].Namespace < subjects[j].Namespace
		}
		if subjects[i].Name != subjects[j].Name {
			return subjects[i].Name < subjects[j].Name
		}
		return subjects[i].Kind < subjects[j].Kind
	})
	return subjects
}

func canonicalPolicyRules(in []policyRuleManifest) []PolicyRule {
	rules := make([]PolicyRule, 0, len(in))
	for _, rule := range in {
		rules = append(rules, PolicyRule{
			APIGroups:       canonicalStrings(rule.APIGroups),
			Resources:       canonicalStrings(rule.Resources),
			ResourceNames:   canonicalStrings(rule.ResourceNames),
			Verbs:           canonicalStrings(rule.Verbs),
			NonResourceURLs: canonicalStrings(rule.NonResourceURLs),
		})
	}
	sort.Slice(rules, func(i, j int) bool {
		return policyRuleLess(rules[i], rules[j])
	})
	return rules
}

func canonicalStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	values := append([]string(nil), in...)
	sort.Strings(values)
	out := values[:0]
	for _, value := range values {
		if len(out) > 0 && out[len(out)-1] == value {
			continue
		}
		out = append(out, value)
	}
	return out
}

func policyRuleLess(a, b PolicyRule) bool {
	if c := compareStrings(a.APIGroups, b.APIGroups); c != 0 {
		return c < 0
	}
	if c := compareStrings(a.Resources, b.Resources); c != 0 {
		return c < 0
	}
	if c := compareStrings(a.ResourceNames, b.ResourceNames); c != 0 {
		return c < 0
	}
	if c := compareStrings(a.Verbs, b.Verbs); c != 0 {
		return c < 0
	}
	return compareStrings(a.NonResourceURLs, b.NonResourceURLs) < 0
}

func compareStrings(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
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

type ingressManifest struct {
	Metadata metadata    `yaml:"metadata"`
	Spec     ingressSpec `yaml:"spec"`
}

type serviceAccountManifest struct {
	Metadata                     metadata `yaml:"metadata"`
	AutomountServiceAccountToken *bool    `yaml:"automountServiceAccountToken"`
}

type roleManifest struct {
	Metadata metadata             `yaml:"metadata"`
	Rules    []policyRuleManifest `yaml:"rules"`
}

type clusterRoleManifest struct {
	Metadata metadata             `yaml:"metadata"`
	Rules    []policyRuleManifest `yaml:"rules"`
}

type roleBindingManifest struct {
	Metadata metadata          `yaml:"metadata"`
	RoleRef  roleRefManifest   `yaml:"roleRef"`
	Subjects []subjectManifest `yaml:"subjects"`
}

type clusterRoleBindingManifest struct {
	Metadata metadata          `yaml:"metadata"`
	RoleRef  roleRefManifest   `yaml:"roleRef"`
	Subjects []subjectManifest `yaml:"subjects"`
}

type policyRuleManifest struct {
	APIGroups       []string `yaml:"apiGroups"`
	Resources       []string `yaml:"resources"`
	ResourceNames   []string `yaml:"resourceNames"`
	Verbs           []string `yaml:"verbs"`
	NonResourceURLs []string `yaml:"nonResourceURLs"`
}

type roleRefManifest struct {
	APIGroup string `yaml:"apiGroup"`
	Kind     string `yaml:"kind"`
	Name     string `yaml:"name"`
}

type subjectManifest struct {
	Kind      string `yaml:"kind"`
	Namespace string `yaml:"namespace"`
	Name      string `yaml:"name"`
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
	Spec     podSpec  `yaml:"spec"`
}

type podSpec struct {
	ServiceAccountName string `yaml:"serviceAccountName"`
}

type ingressSpec struct {
	DefaultBackend ingressBackendManifest `yaml:"defaultBackend"`
	Rules          []ingressRule          `yaml:"rules"`
}

type ingressRule struct {
	HTTP ingressHTTPRule `yaml:"http"`
}

type ingressHTTPRule struct {
	Paths []ingressPath `yaml:"paths"`
}

type ingressPath struct {
	Backend ingressBackendManifest `yaml:"backend"`
}

type ingressBackendManifest struct {
	Service ingressBackendService `yaml:"service"`
}

type ingressBackendService struct {
	Name string `yaml:"name"`
}

func ingressBackends(spec ingressSpec) []IngressBackend {
	var backends []IngressBackend
	if spec.DefaultBackend.Service.Name != "" {
		backends = append(backends, IngressBackend{Kind: "default", ServiceName: spec.DefaultBackend.Service.Name})
	}
	for _, rule := range spec.Rules {
		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service.Name == "" {
				continue
			}
			backends = append(backends, IngressBackend{Kind: "rule", ServiceName: path.Backend.Service.Name})
		}
	}
	return backends
}
