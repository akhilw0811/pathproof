package kubernetes

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseDirParsesValidService(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "service.yaml", `apiVersion: v1
kind: Service
metadata:
  name: public-api
  namespace: prod
spec:
  type: LoadBalancer
  selector:
    app: api
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []Service{{
		Namespace: "prod",
		Name:      "public-api",
		Type:      "LoadBalancer",
		Selector:  map[string]string{"app": "api"},
		Source:    Source{Filename: path, Document: 1},
	}}
	if !reflect.DeepEqual(resources.Services, want) {
		t.Fatalf("services = %#v, want %#v", resources.Services, want)
	}
	if len(resources.Deployments) != 0 {
		t.Fatalf("deployment count = %d, want 0", len(resources.Deployments))
	}
}

func TestParseDirParsesValidDeployment(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "deployment.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
spec:
  template:
    metadata:
      labels:
        app: api
        tier: backend
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []Deployment{{
		Namespace: "prod",
		Name:      "api",
		PodLabels: map[string]string{"app": "api", "tier": "backend"},
		Source:    Source{Filename: path, Document: 1},
	}}
	if !reflect.DeepEqual(resources.Deployments, want) {
		t.Fatalf("deployments = %#v, want %#v", resources.Deployments, want)
	}
	if len(resources.Services) != 0 {
		t.Fatalf("service count = %d, want 0", len(resources.Services))
	}
}

func TestParseDirParsesDeploymentWithSelectorMatchLabels(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "deployment.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
  labels:
    app: metadata-only
spec:
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
        tier: backend
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []Deployment{{
		Namespace: "prod",
		Name:      "api",
		PodLabels: map[string]string{"app": "api", "tier": "backend"},
		Source:    Source{Filename: path, Document: 1},
	}}
	if !reflect.DeepEqual(resources.Deployments, want) {
		t.Fatalf("deployments = %#v, want %#v", resources.Deployments, want)
	}
}

func TestParseDirParsesMultiDocumentYAML(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "resources.yaml", `apiVersion: v1
kind: Service
metadata:
  name: public-api
spec:
  type: NodePort
  selector:
    app: api
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    metadata:
      labels:
        app: api
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	wantServices := []Service{{
		Namespace: "default",
		Name:      "public-api",
		Type:      "NodePort",
		Selector:  map[string]string{"app": "api"},
		Source:    Source{Filename: path, Document: 1},
	}}
	wantDeployments := []Deployment{{
		Namespace: "default",
		Name:      "api",
		PodLabels: map[string]string{"app": "api"},
		Source:    Source{Filename: path, Document: 2},
	}}
	if !reflect.DeepEqual(resources.Services, wantServices) {
		t.Fatalf("services = %#v, want %#v", resources.Services, wantServices)
	}
	if !reflect.DeepEqual(resources.Deployments, wantDeployments) {
		t.Fatalf("deployments = %#v, want %#v", resources.Deployments, wantDeployments)
	}
}

func TestParseDirDefaultsNamespaceToDefault(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "service.yaml", `apiVersion: v1
kind: Service
metadata:
  name: public-api
spec:
  type: LoadBalancer
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	if got := resources.Services[0].Namespace; got != "default" {
		t.Fatalf("namespace = %q, want default", got)
	}
}

func TestParseDirMalformedYAMLReturnsActionableError(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "bad.yaml", `apiVersion: v1
kind: Service
metadata: [
`)

	resources, err := ParseDir(dir)
	if err == nil {
		t.Fatal("parse dir error = nil, want malformed YAML error")
	}
	if !reflect.DeepEqual(resources, Resources{}) {
		t.Fatalf("resources = %#v, want empty result on error", resources)
	}
	if got := err.Error(); !strings.Contains(got, path) || !strings.Contains(got, "document 1") {
		t.Fatalf("error = %q, want filename and document", got)
	}
}

func TestParseDirValidFileFollowedByMalformedFileReturnsNoUsableResources(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "a-valid.yaml", `apiVersion: v1
kind: Service
metadata:
  name: public-api
spec:
  type: LoadBalancer
`)
	writeManifest(t, dir, "b-bad.yaml", `apiVersion: apps/v1
kind: Deployment
spec:
  template:
    metadata: [
`)

	resources, err := ParseDir(dir)
	if err == nil {
		t.Fatal("parse dir error = nil, want malformed YAML error")
	}
	if !reflect.DeepEqual(resources, Resources{}) {
		t.Fatalf("resources = %#v, want empty result on error", resources)
	}
}

func TestParseDirIgnoresUnsupportedKinds(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "configmap.yaml", `apiVersion: v1
kind: ConfigMap
metadata:
  name: ignored
data:
  key: value
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if !reflect.DeepEqual(resources, Resources{}) {
		t.Fatalf("resources = %#v, want no supported resources", resources)
	}
}

func TestParseDirIgnoresUnsupportedKindWithDifferentlyShapedSpec(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "custom.yaml", `apiVersion: example.io/v1
kind: CustomResource
metadata:
  name: example
spec:
  selector:
  - app
  - backend
  template:
    metadata:
      labels: "not-a-map"
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if !reflect.DeepEqual(resources, Resources{}) {
		t.Fatalf("resources = %#v, want no supported resources", resources)
	}
}

func TestParseDirUnsupportedKindAndServiceInSameFileParsesService(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "resources.yaml", `apiVersion: example.io/v1
kind: CustomResource
metadata:
  name: example
spec:
  selector:
  - app
  - backend
  template:
    metadata:
      labels: "not-a-map"
---
apiVersion: v1
kind: Service
metadata:
  name: public-api
spec:
  type: LoadBalancer
  selector:
    app: api
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []Service{{
		Namespace: "default",
		Name:      "public-api",
		Type:      "LoadBalancer",
		Selector:  map[string]string{"app": "api"},
		Source:    Source{Filename: path, Document: 2},
	}}
	if !reflect.DeepEqual(resources.Services, want) {
		t.Fatalf("services = %#v, want %#v", resources.Services, want)
	}
}

func TestParseDirUnsupportedKindDoesNotInterfereWithDeploymentInSameDirectory(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "unsupported.yaml", `apiVersion: example.io/v1
kind: CustomResource
metadata:
  name: example
spec:
  selector:
  - app
  - backend
  template:
    metadata:
      labels: "not-a-map"
`)
	path := writeManifest(t, dir, "deployment.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []Deployment{{
		Namespace: "default",
		Name:      "api",
		PodLabels: map[string]string{"app": "api"},
		Source:    Source{Filename: path, Document: 1},
	}}
	if !reflect.DeepEqual(resources.Deployments, want) {
		t.Fatalf("deployments = %#v, want %#v", resources.Deployments, want)
	}
}

func TestParseDirIgnoresEmptyDocuments(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "resources.yaml", `---
---
apiVersion: v1
kind: Service
metadata:
  name: public-api
spec:
  type: LoadBalancer
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []Service{{
		Namespace: "default",
		Name:      "public-api",
		Type:      "LoadBalancer",
		Source:    Source{Filename: path, Document: 2},
	}}
	if !reflect.DeepEqual(resources.Services, want) {
		t.Fatalf("services = %#v, want %#v", resources.Services, want)
	}
}

func TestParseDirPreservesSourceFilenameAndDocument(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "resources.yaml", `apiVersion: v1
kind: ConfigMap
metadata:
  name: ignored
---
apiVersion: v1
kind: Service
metadata:
  name: public-api
spec:
  type: LoadBalancer
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := Source{Filename: path, Document: 2}
	if got := resources.Services[0].Source; got != want {
		t.Fatalf("source = %#v, want %#v", got, want)
	}
}

func TestParseDirReturnsDeterministicResourceOrdering(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "z.yaml", `apiVersion: v1
kind: Service
metadata:
  name: z-api
  namespace: prod
spec:
  type: LoadBalancer
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: z-api
  namespace: prod
spec:
  template:
    metadata:
      labels:
        app: z
`)
	writeManifest(t, dir, "a.yaml", `apiVersion: v1
kind: Service
metadata:
  name: a-api
  namespace: prod
spec:
  type: NodePort
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: a-api
  namespace: prod
spec:
  template:
    metadata:
      labels:
        app: a
`)

	first, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir first: %v", err)
	}
	second, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir second: %v", err)
	}

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("resources differ across repeated parse:\nfirst: %#v\nsecond: %#v", first, second)
	}
	if got := []string{first.Services[0].Name, first.Services[1].Name}; !reflect.DeepEqual(got, []string{"a-api", "z-api"}) {
		t.Fatalf("service order = %#v, want sorted by resource identity", got)
	}
	if got := []string{first.Deployments[0].Name, first.Deployments[1].Name}; !reflect.DeepEqual(got, []string{"a-api", "z-api"}) {
		t.Fatalf("deployment order = %#v, want sorted by resource identity", got)
	}
}

func TestParseDirPreservesDuplicateSupportedDocuments(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "duplicates.yaml", `apiVersion: v1
kind: Service
metadata:
  name: public-api
spec:
  type: LoadBalancer
---
apiVersion: v1
kind: Service
metadata:
  name: public-api
spec:
  type: LoadBalancer
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []Service{
		{Namespace: "default", Name: "public-api", Type: "LoadBalancer", Source: Source{Filename: path, Document: 1}},
		{Namespace: "default", Name: "public-api", Type: "LoadBalancer", Source: Source{Filename: path, Document: 2}},
	}
	if !reflect.DeepEqual(resources.Services, want) {
		t.Fatalf("services = %#v, want %#v", resources.Services, want)
	}
}

func writeManifest(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write manifest %q: %v", name, err)
	}
	return path
}
