package kubernetes

import (
	"encoding/json"
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
		Namespace:          "prod",
		Name:               "api",
		PodLabels:          map[string]string{"app": "api", "tier": "backend"},
		ServiceAccountName: "default",
		Source:             Source{Filename: path, Document: 1},
	}}
	if !reflect.DeepEqual(resources.Deployments, want) {
		t.Fatalf("deployments = %#v, want %#v", resources.Deployments, want)
	}
	if len(resources.Services) != 0 {
		t.Fatalf("service count = %d, want 0", len(resources.Services))
	}
}

func TestParseDirParsesValidServiceAccount(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "service-account.yaml", `apiVersion: v1
kind: ServiceAccount
metadata:
  name: payments-sa
  namespace: prod
automountServiceAccountToken: false
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []ServiceAccount{{
		Namespace:                    "prod",
		Name:                         "payments-sa",
		AutomountServiceAccountToken: boolPtr(false),
		Source:                       Source{Filename: path, Document: 1},
	}}
	if !reflect.DeepEqual(resources.ServiceAccounts, want) {
		t.Fatalf("service accounts = %#v, want %#v", resources.ServiceAccounts, want)
	}
}

func TestParseDirPreservesServiceAccountAutomountTokenStates(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "service-accounts.yaml", `apiVersion: v1
kind: ServiceAccount
metadata:
  name: omitted
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: explicit-false
automountServiceAccountToken: false
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: explicit-true
automountServiceAccountToken: true
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []ServiceAccount{
		{Namespace: "default", Name: "explicit-false", AutomountServiceAccountToken: boolPtr(false), Source: Source{Filename: path, Document: 2}},
		{Namespace: "default", Name: "explicit-true", AutomountServiceAccountToken: boolPtr(true), Source: Source{Filename: path, Document: 3}},
		{Namespace: "default", Name: "omitted", Source: Source{Filename: path, Document: 1}},
	}
	if !reflect.DeepEqual(resources.ServiceAccounts, want) {
		t.Fatalf("service accounts = %#v, want %#v", resources.ServiceAccounts, want)
	}
}

func TestParseDirParsesValidSecretMetadata(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "secret.yaml", `apiVersion: v1
kind: Secret
metadata:
  name: database-password
  namespace: prod
type: Opaque
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []Secret{{
		Namespace: "prod",
		Name:      "database-password",
		Source:    Source{Filename: path, Document: 1},
	}}
	if !reflect.DeepEqual(resources.Secrets, want) {
		t.Fatalf("secrets = %#v, want %#v", resources.Secrets, want)
	}
}

func TestParseDirDefaultsSecretNamespaceToDefault(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "secret.yaml", `apiVersion: v1
kind: Secret
metadata:
  name: database-password
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	if got := resources.Secrets[0].Namespace; got != "default" {
		t.Fatalf("namespace = %q, want default", got)
	}
}

func TestParseDirIgnoresUnsupportedSecretBeforeTypedDecode(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "legacy-secret.yaml", `apiVersion: example.io/v1
kind: Secret
metadata:
  name:
  - unsupported
data:
  token:
    nested: unsupported
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if !reflect.DeepEqual(resources, Resources{}) {
		t.Fatalf("resources = %#v, want unsupported Secret skipped", resources)
	}
}

func TestParseDirSecretDataAndStringDataAreNotRetained(t *testing.T) {
	dir := t.TempDir()
	const fakeDataValue = "FAKE_SECRET_DATA_VALUE_DO_NOT_RETAIN"
	const fakeStringDataValue = "FAKE_SECRET_STRINGDATA_VALUE_DO_NOT_RETAIN"
	path := writeManifest(t, dir, "secret.yaml", `apiVersion: v1
kind: Secret
metadata:
  name: database-password
  namespace: prod
data:
  password: FAKE_SECRET_DATA_VALUE_DO_NOT_RETAIN
stringData:
  token: FAKE_SECRET_STRINGDATA_VALUE_DO_NOT_RETAIN
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []Secret{{Namespace: "prod", Name: "database-password", Source: Source{Filename: path, Document: 1}}}
	if !reflect.DeepEqual(resources.Secrets, want) {
		t.Fatalf("secrets = %#v, want %#v", resources.Secrets, want)
	}
	data, err := json.Marshal(resources)
	if err != nil {
		t.Fatalf("marshal resources: %v", err)
	}
	for _, value := range []string{fakeDataValue, fakeStringDataValue, `"data"`, `"stringData"`, `"Data"`, `"StringData"`} {
		if strings.Contains(string(data), value) {
			t.Fatalf("serialized parser resources contain %q: %s", value, data)
		}
	}
}

func TestParseDirMalformedCoreV1SecretReturnsActionableErrorWithoutValues(t *testing.T) {
	dir := t.TempDir()
	const fakeValue = "FAKE_SECRET_VALUE_IN_BAD_FIXTURE"
	path := writeManifest(t, dir, "bad-secret.yaml", `apiVersion: v1
kind: Secret
metadata: [
data:
  password: FAKE_SECRET_VALUE_IN_BAD_FIXTURE
`)

	resources, err := ParseDir(dir)
	if err == nil {
		t.Fatal("parse dir error = nil, want malformed Secret error")
	}
	if !reflect.DeepEqual(resources, Resources{}) {
		t.Fatalf("resources = %#v, want empty result on error", resources)
	}
	if got := err.Error(); !strings.Contains(got, path) || !strings.Contains(got, "document 1") || strings.Contains(got, fakeValue) {
		t.Fatalf("error = %q, want filename and document without secret value", got)
	}
}

func TestParseDirSecretOrderingIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "z.yaml", `apiVersion: v1
kind: Secret
metadata:
  name: z-secret
  namespace: prod
`)
	writeManifest(t, dir, "a.yaml", `apiVersion: v1
kind: Secret
metadata:
  name: a-secret
  namespace: prod
---
apiVersion: v1
kind: Secret
metadata:
  name: default-secret
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
	if got := []string{
		first.Secrets[0].Namespace + "/" + first.Secrets[0].Name,
		first.Secrets[1].Namespace + "/" + first.Secrets[1].Name,
		first.Secrets[2].Namespace + "/" + first.Secrets[2].Name,
	}; !reflect.DeepEqual(got, []string{"default/default-secret", "prod/a-secret", "prod/z-secret"}) {
		t.Fatalf("secret order = %#v, want sorted by resource identity", got)
	}
}

func TestParseDirPreservesDuplicateSecretDocuments(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "secrets.yaml", `apiVersion: v1
kind: Secret
metadata:
  name: database-password
---
apiVersion: v1
kind: Secret
metadata:
  name: database-password
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []Secret{
		{Namespace: "default", Name: "database-password", Source: Source{Filename: path, Document: 1}},
		{Namespace: "default", Name: "database-password", Source: Source{Filename: path, Document: 2}},
	}
	if !reflect.DeepEqual(resources.Secrets, want) {
		t.Fatalf("secrets = %#v, want %#v", resources.Secrets, want)
	}
}

func TestParseDirIgnoresUnsupportedServiceAccountBeforeTypedDecode(t *testing.T) {
	dir := t.TempDir()
	resourcesPath := writeManifest(t, dir, "resources.yaml", `apiVersion: example.io/v1
kind: ServiceAccount
metadata:
  name: unsupported
automountServiceAccountToken:
  mode: custom
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: payments-sa
  namespace: prod
automountServiceAccountToken: true
`)
	deploymentPath := writeManifest(t, dir, "deployment.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
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

	wantServiceAccounts := []ServiceAccount{{
		Namespace:                    "prod",
		Name:                         "payments-sa",
		AutomountServiceAccountToken: boolPtr(true),
		Source:                       Source{Filename: resourcesPath, Document: 2},
	}}
	if !reflect.DeepEqual(resources.ServiceAccounts, wantServiceAccounts) {
		t.Fatalf("service accounts = %#v, want %#v", resources.ServiceAccounts, wantServiceAccounts)
	}

	wantDeployments := []Deployment{{
		Namespace:          "prod",
		Name:               "api",
		PodLabels:          map[string]string{"app": "api"},
		ServiceAccountName: "default",
		Source:             Source{Filename: deploymentPath, Document: 1},
	}}
	if !reflect.DeepEqual(resources.Deployments, wantDeployments) {
		t.Fatalf("deployments = %#v, want %#v", resources.Deployments, wantDeployments)
	}
}

func TestParseDirMalformedCoreV1ServiceAccountReturnsActionableError(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "bad-service-account.yaml", `apiVersion: v1
kind: ServiceAccount
metadata:
  name: bad
automountServiceAccountToken:
  mode: custom
`)

	resources, err := ParseDir(dir)
	if err == nil {
		t.Fatal("parse dir error = nil, want malformed ServiceAccount field error")
	}
	if !reflect.DeepEqual(resources, Resources{}) {
		t.Fatalf("resources = %#v, want empty result on error", resources)
	}
	if got := err.Error(); !strings.Contains(got, path) || !strings.Contains(got, "ServiceAccount") || !strings.Contains(got, "document 1") {
		t.Fatalf("error = %q, want filename, ServiceAccount kind, and document", got)
	}
}

func TestParseDirParsesDeploymentServiceAccountName(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "deployment.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: prod
spec:
  template:
    spec:
      serviceAccountName: payments-sa
    metadata:
      labels:
        app: api
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []Deployment{{
		Namespace:          "prod",
		Name:               "api",
		PodLabels:          map[string]string{"app": "api"},
		ServiceAccountName: "payments-sa",
		Source:             Source{Filename: path, Document: 1},
	}}
	if !reflect.DeepEqual(resources.Deployments, want) {
		t.Fatalf("deployments = %#v, want %#v", resources.Deployments, want)
	}
}

func TestParseDirDefaultsMissingDeploymentServiceAccountName(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "deployment.yaml", `apiVersion: apps/v1
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

	if got := resources.Deployments[0].ServiceAccountName; got != "default" {
		t.Fatalf("service account name = %q, want default", got)
	}
}

func TestParseDirDefaultsEmptyDeploymentServiceAccountName(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "deployment.yaml", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      serviceAccountName: ""
    metadata:
      labels:
        app: api
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	if got := resources.Deployments[0].ServiceAccountName; got != "default" {
		t.Fatalf("service account name = %q, want default", got)
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
		Namespace:          "prod",
		Name:               "api",
		PodLabels:          map[string]string{"app": "api", "tier": "backend"},
		ServiceAccountName: "default",
		Source:             Source{Filename: path, Document: 1},
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
		Namespace:          "default",
		Name:               "api",
		PodLabels:          map[string]string{"app": "api"},
		ServiceAccountName: "default",
		Source:             Source{Filename: path, Document: 2},
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
		Namespace:          "default",
		Name:               "api",
		PodLabels:          map[string]string{"app": "api"},
		ServiceAccountName: "default",
		Source:             Source{Filename: path, Document: 1},
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
apiVersion: v1
kind: ServiceAccount
metadata:
  name: z-api
  namespace: prod
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
apiVersion: v1
kind: ServiceAccount
metadata:
  name: a-api
  namespace: prod
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
	if got := []string{first.ServiceAccounts[0].Name, first.ServiceAccounts[1].Name}; !reflect.DeepEqual(got, []string{"a-api", "z-api"}) {
		t.Fatalf("service account order = %#v, want sorted by resource identity", got)
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

func TestParseDirParsesValidNetworkingV1Ingress(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "ingress.yaml", `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: public-api
  namespace: prod
spec:
  rules:
  - http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: api
            port:
              number: 80
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []Ingress{{
		Namespace: "prod",
		Name:      "public-api",
		Backends:  []IngressBackend{{Kind: "rule", ServiceName: "api"}},
		Source:    Source{Filename: path, Document: 1},
	}}
	if !reflect.DeepEqual(resources.Ingresses, want) {
		t.Fatalf("ingresses = %#v, want %#v", resources.Ingresses, want)
	}
}

func TestParseDirParsesIngressRuleBackendServiceName(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "ingress.yaml", `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: public-api
spec:
  rules:
  - http:
      paths:
      - backend:
          service:
            name: api
      - backend:
          service:
            name: worker
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []Ingress{{
		Namespace: "default",
		Name:      "public-api",
		Backends: []IngressBackend{
			{Kind: "rule", ServiceName: "api"},
			{Kind: "rule", ServiceName: "worker"},
		},
		Source: Source{Filename: path, Document: 1},
	}}
	if !reflect.DeepEqual(resources.Ingresses, want) {
		t.Fatalf("ingresses = %#v, want %#v", resources.Ingresses, want)
	}
}

func TestParseDirParsesIngressDefaultBackendServiceName(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "ingress.yaml", `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: public-api
spec:
  defaultBackend:
    service:
      name: api
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []Ingress{{
		Namespace: "default",
		Name:      "public-api",
		Backends:  []IngressBackend{{Kind: "default", ServiceName: "api"}},
		Source:    Source{Filename: path, Document: 1},
	}}
	if !reflect.DeepEqual(resources.Ingresses, want) {
		t.Fatalf("ingresses = %#v, want %#v", resources.Ingresses, want)
	}
}

func TestParseDirDefaultsIngressNamespaceToDefault(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "ingress.yaml", `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: public-api
spec:
  defaultBackend:
    service:
      name: api
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	if got := resources.Ingresses[0].Namespace; got != "default" {
		t.Fatalf("namespace = %q, want default", got)
	}
}

func TestParseDirIgnoresLegacyIngressBeforeTypedDecode(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "legacy-ingress.yaml", `apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  name: legacy
spec:
  backend:
    serviceName: api
    servicePort: 80
  rules:
  - http:
      paths:
      - backend:
          serviceName: api
          servicePort: 80
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if !reflect.DeepEqual(resources, Resources{}) {
		t.Fatalf("resources = %#v, want legacy Ingress skipped", resources)
	}
}

func TestParseDirIgnoresIngressUnsupportedBackendsAndEmptyServiceNames(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "ingress.yaml", `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: public-api
spec:
  defaultBackend:
    resource:
      apiGroup: example.io
      kind: StorageBucket
      name: static-assets
  rules:
  - http:
      paths:
      - backend:
          resource:
            apiGroup: example.io
            kind: StorageBucket
            name: static-assets
      - backend:
          service:
            name: ""
      - backend:
          service:
            name: api
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []Ingress{{
		Namespace: "default",
		Name:      "public-api",
		Backends:  []IngressBackend{{Kind: "rule", ServiceName: "api"}},
		Source:    Source{Filename: path, Document: 1},
	}}
	if !reflect.DeepEqual(resources.Ingresses, want) {
		t.Fatalf("ingresses = %#v, want %#v", resources.Ingresses, want)
	}
}

func TestParseDirMalformedIngressYAMLReturnsActionableError(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "bad-ingress.yaml", `apiVersion: networking.k8s.io/v1
kind: Ingress
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

func TestParseDirMalformedIngressSupportedBackendReturnsActionableError(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "bad-ingress.yaml", `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: public-api
spec:
  defaultBackend:
    service:
    - name: api
`)

	resources, err := ParseDir(dir)
	if err == nil {
		t.Fatal("parse dir error = nil, want malformed Ingress backend error")
	}
	if !reflect.DeepEqual(resources, Resources{}) {
		t.Fatalf("resources = %#v, want empty result on error", resources)
	}
	if got := err.Error(); !strings.Contains(got, path) || !strings.Contains(got, "Ingress") || !strings.Contains(got, "document 1") {
		t.Fatalf("error = %q, want filename, Ingress kind, and document", got)
	}
}

func TestParseDirParsesValidRole(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "role.yaml", `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: prod
rules:
- apiGroups: ["apps", ""]
  resources: ["pods", "deployments", "pods"]
  resourceNames: ["api", "worker"]
  verbs: ["watch", "get", "get"]
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []Role{{
		Namespace: "prod",
		Name:      "pod-reader",
		Rules: []PolicyRule{{
			APIGroups:     []string{"", "apps"},
			Resources:     []string{"deployments", "pods"},
			ResourceNames: []string{"api", "worker"},
			Verbs:         []string{"get", "watch"},
		}},
		Source: Source{Filename: path, Document: 1},
	}}
	if !reflect.DeepEqual(resources.Roles, want) {
		t.Fatalf("roles = %#v, want %#v", resources.Roles, want)
	}
}

func TestParseDirParsesValidClusterRole(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "cluster-role.yaml", `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["list", "get"]
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []ClusterRole{{
		Name: "pod-reader",
		Rules: []PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list"},
		}},
		Source: Source{Filename: path, Document: 1},
	}}
	if !reflect.DeepEqual(resources.ClusterRoles, want) {
		t.Fatalf("cluster roles = %#v, want %#v", resources.ClusterRoles, want)
	}
}

func TestParseDirParsesValidRoleBinding(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "role-binding.yaml", `apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: prod
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-reader
subjects:
- kind: ServiceAccount
  name: api
  namespace: workloads
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []RoleBinding{{
		Namespace: "prod",
		Name:      "read-pods",
		RoleRef:   RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "pod-reader"},
		Subjects:  []Subject{{Kind: "ServiceAccount", Namespace: "workloads", Name: "api"}},
		Source:    Source{Filename: path, Document: 1},
	}}
	if !reflect.DeepEqual(resources.RoleBindings, want) {
		t.Fatalf("role bindings = %#v, want %#v", resources.RoleBindings, want)
	}
}

func TestParseDirParsesValidClusterRoleBinding(t *testing.T) {
	dir := t.TempDir()
	path := writeManifest(t, dir, "cluster-role-binding.yaml", `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: read-pods
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: pod-reader
subjects:
- kind: ServiceAccount
  name: api
  namespace: prod
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []ClusterRoleBinding{{
		Name:     "read-pods",
		RoleRef:  RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "pod-reader"},
		Subjects: []Subject{{Kind: "ServiceAccount", Namespace: "prod", Name: "api"}},
		Source:   Source{Filename: path, Document: 1},
	}}
	if !reflect.DeepEqual(resources.ClusterRoleBindings, want) {
		t.Fatalf("cluster role bindings = %#v, want %#v", resources.ClusterRoleBindings, want)
	}
}

func TestParseDirIgnoresUnsupportedRBACVersionBeforeTypedDecode(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "legacy-role.yaml", `apiVersion: rbac.authorization.k8s.io/v1beta1
kind: Role
metadata:
  name: legacy
rules:
- apiGroups:
    bad: shape
  resources: pods
  verbs: get
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if !reflect.DeepEqual(resources, Resources{}) {
		t.Fatalf("resources = %#v, want unsupported RBAC skipped", resources)
	}
}

func TestParseDirRoleRulesPreserveWildcardsAndCoreAPIGroup(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "role.yaml", `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: wildcard
rules:
- apiGroups: ["", "*"]
  resources: ["*", "pods"]
  verbs: ["*", "get"]
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	rule := resources.Roles[0].Rules[0]
	if !reflect.DeepEqual(rule.APIGroups, []string{"", "*"}) {
		t.Fatalf("api groups = %#v, want core and wildcard preserved", rule.APIGroups)
	}
	if !reflect.DeepEqual(rule.Resources, []string{"*", "pods"}) {
		t.Fatalf("resources = %#v, want wildcard preserved", rule.Resources)
	}
	if !reflect.DeepEqual(rule.Verbs, []string{"*", "get"}) {
		t.Fatalf("verbs = %#v, want wildcard preserved", rule.Verbs)
	}
}

func TestParseDirRoleResourceNamesAreDeterministic(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "role.yaml", `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: named-resources
rules:
- apiGroups: [""]
  resources: ["pods"]
  resourceNames: ["worker", "api", "api"]
  verbs: ["get"]
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	if got, want := resources.Roles[0].Rules[0].ResourceNames, []string{"api", "worker"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("resource names = %#v, want %#v", got, want)
	}
}

func TestParseDirRoleNonResourceURLsAreDeterministic(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "role.yaml", `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: health-reader
rules:
- nonResourceURLs: ["/readyz", "/healthz", "/readyz"]
  verbs: ["get"]
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	if got, want := resources.ClusterRoles[0].Rules[0].NonResourceURLs, []string{"/healthz", "/readyz"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("nonResourceURLs = %#v, want %#v", got, want)
	}
}

func TestParseDirNonResourceURLOrderingDoesNotAffectParse(t *testing.T) {
	firstDir := t.TempDir()
	writeManifest(t, firstDir, "role.yaml", `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: health-reader
rules:
- nonResourceURLs: ["/readyz", "/healthz"]
  verbs: ["get"]
`)
	secondDir := t.TempDir()
	writeManifest(t, secondDir, "role.yaml", `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: health-reader
rules:
- nonResourceURLs: ["/healthz", "/readyz"]
  verbs: ["get"]
`)

	first, err := ParseDir(firstDir)
	if err != nil {
		t.Fatalf("parse first dir: %v", err)
	}
	second, err := ParseDir(secondDir)
	if err != nil {
		t.Fatalf("parse second dir: %v", err)
	}

	first.ClusterRoles[0].Source = Source{}
	second.ClusterRoles[0].Source = Source{}
	if !reflect.DeepEqual(first.ClusterRoles, second.ClusterRoles) {
		t.Fatalf("cluster roles differ by nonResourceURLs order:\nfirst: %#v\nsecond: %#v", first.ClusterRoles, second.ClusterRoles)
	}
}

func TestParseDirRoleBindingDoesNotDefaultServiceAccountSubjectNamespace(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "role-binding.yaml", `apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: prod
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-reader
subjects:
- kind: ServiceAccount
  name: api
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	if got := resources.RoleBindings[0].Subjects[0].Namespace; got != "" {
		t.Fatalf("subject namespace = %q, want empty unresolved namespace", got)
	}
}

func TestParseDirClusterRoleBindingMissingServiceAccountNamespaceRemainsEmpty(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "cluster-role-binding.yaml", `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: read-pods
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: pod-reader
subjects:
- kind: ServiceAccount
  name: api
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	if got := resources.ClusterRoleBindings[0].Subjects[0].Namespace; got != "" {
		t.Fatalf("subject namespace = %q, want empty unresolved namespace", got)
	}
}

func TestParseDirIgnoresUnsupportedRBACSubjects(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "role-binding.yaml", `apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-reader
subjects:
- kind: User
  name: alice
- kind: Group
  name: developers
- kind: ServiceAccount
  name: api
  namespace: prod
`)

	resources, err := ParseDir(dir)
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []Subject{{Kind: "ServiceAccount", Namespace: "prod", Name: "api"}}
	if got := resources.RoleBindings[0].Subjects; !reflect.DeepEqual(got, want) {
		t.Fatalf("subjects = %#v, want %#v", got, want)
	}
}

func TestParseDirReturnsDeterministicRBACResourceOrdering(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "z.yaml", `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: z-role
  namespace: prod
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: z-cluster-role
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: z-binding
  namespace: prod
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: z-role
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: z-cluster-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: z-cluster-role
`)
	writeManifest(t, dir, "a.yaml", `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: a-role
  namespace: prod
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: a-cluster-role
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: a-binding
  namespace: prod
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: a-role
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: a-cluster-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: a-cluster-role
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
	if got := []string{first.Roles[0].Name, first.Roles[1].Name}; !reflect.DeepEqual(got, []string{"a-role", "z-role"}) {
		t.Fatalf("role order = %#v, want sorted by identity", got)
	}
	if got := []string{first.ClusterRoles[0].Name, first.ClusterRoles[1].Name}; !reflect.DeepEqual(got, []string{"a-cluster-role", "z-cluster-role"}) {
		t.Fatalf("cluster role order = %#v, want sorted by identity", got)
	}
	if got := []string{first.RoleBindings[0].Name, first.RoleBindings[1].Name}; !reflect.DeepEqual(got, []string{"a-binding", "z-binding"}) {
		t.Fatalf("role binding order = %#v, want sorted by identity", got)
	}
	if got := []string{first.ClusterRoleBindings[0].Name, first.ClusterRoleBindings[1].Name}; !reflect.DeepEqual(got, []string{"a-cluster-binding", "z-cluster-binding"}) {
		t.Fatalf("cluster role binding order = %#v, want sorted by identity", got)
	}
}

func TestParseDirWithOptionsExcludesKubernetesYAMLBeforeParsing(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "ignored.yaml", `apiVersion: v1
kind: Service
metadata:
  name: ignored
`)
	path := writeManifest(t, dir, "kept.yaml", `apiVersion: v1
kind: Service
metadata:
  name: kept
`)

	resources, err := ParseDirWithOptions(dir, ParseOptions{
		ExcludePath: func(rel string) bool { return rel == "ignored.yaml" },
	})
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}

	want := []Service{{Namespace: "default", Name: "kept", Source: Source{Filename: path, Document: 1}}}
	if !reflect.DeepEqual(resources.Services, want) {
		t.Fatalf("services = %#v, want %#v", resources.Services, want)
	}
}

func TestParseDirWithOptionsExcludedMalformedKubernetesYAMLDoesNotError(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "bad.yaml", `apiVersion: v1
kind: Service
metadata: [
`)

	resources, err := ParseDirWithOptions(dir, ParseOptions{
		ExcludePath: func(rel string) bool { return rel == "bad.yaml" },
	})
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if !reflect.DeepEqual(resources, Resources{}) {
		t.Fatalf("resources = %#v, want empty", resources)
	}
}

func TestParseDirWithOptionsExcludesKubernetesPathWithSpaces(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "ignored service.yaml", `apiVersion: v1
kind: Service
metadata:
  name: ignored
`)

	resources, err := ParseDirWithOptions(dir, ParseOptions{
		ExcludePath: func(rel string) bool { return rel == "ignored service.yaml" },
	})
	if err != nil {
		t.Fatalf("parse dir: %v", err)
	}
	if len(resources.Services) != 0 {
		t.Fatalf("services = %#v, want none", resources.Services)
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

func boolPtr(value bool) *bool {
	return &value
}
