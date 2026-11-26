IMG ?= ghcr.io/nolankisser/secret-rotation-operator:dev
ENVTEST_K8S_VERSION ?= 1.37.0
KIND_CLUSTER ?= secret-rotation

LOCALBIN ?= $(shell pwd)/bin
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
SETUP_ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT ?= $(LOCALBIN)/golangci-lint

CONTROLLER_TOOLS_VERSION ?= v0.23.0
GOLANGCI_LINT_VERSION ?= v2.15.0

.DEFAULT_GOAL := help

##@ General

.PHONY: help
help: ## Show this help.
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make <target>\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: generate
generate: controller-gen ## Generate DeepCopy code.
	$(CONTROLLER_GEN) object:headerFile=hack/boilerplate.go.txt paths=./api/v1alpha1/...

.PHONY: manifests
manifests: controller-gen ## Generate CRD and RBAC manifests from markers.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd paths=./api/v1alpha1/... paths=./internal/controller/... output:crd:artifacts:config=config/crd/bases

.PHONY: verify-generated
verify-generated: generate manifests ## Fail if generated files are out of date.
	git diff --exit-code -- api config

.PHONY: fmt
fmt: ## go fmt
	go fmt ./...

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: lint
lint: golangci-lint ## Run golangci-lint.
	$(GOLANGCI_LINT) run

.PHONY: test
test: generate manifests vet ## Unit tests with race detector and coverage.
	go test -race -coverprofile=cover.out ./internal/...

.PHONY: test-integration
test-integration: manifests setup-envtest ## Integration tests against a real kube-apiserver + etcd.
	KUBEBUILDER_ASSETS="$(shell $(SETUP_ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" \
		go test -count=1 -v ./test/integration/...

.PHONY: run
run: manifests generate ## Run the operator against the current kubeconfig.
	go run ./cmd --metrics-secure=false --metrics-bind-address=:8080

##@ Build & Deploy

.PHONY: build
build: generate ## Build the manager binary.
	go build -o bin/manager ./cmd

.PHONY: docker-build
docker-build: ## Build the container image.
	docker build -t $(IMG) .

.PHONY: install
install: manifests ## Install CRDs into the current cluster.
	kubectl apply --server-side -k config/crd

.PHONY: deploy
deploy: manifests ## Deploy the operator into the current cluster.
	cd config/manager && kustomize edit set image controller=$(IMG)
	kubectl apply --server-side -k config/default

.PHONY: undeploy
undeploy: ## Remove the operator from the current cluster.
	kubectl delete --ignore-not-found -k config/default

.PHONY: build-installer
build-installer: manifests ## Render a single install.yaml for a release.
	mkdir -p dist
	cd config/manager && kustomize edit set image controller=$(IMG)
	kustomize build config/default > dist/install.yaml

.PHONY: e2e
e2e: ## Spin up kind, deploy the operator, and verify a rotation end to end.
	KIND_CLUSTER=$(KIND_CLUSTER) IMG=$(IMG) ./hack/e2e-kind.sh

##@ Tools

$(LOCALBIN):
	mkdir -p $(LOCALBIN)

.PHONY: controller-gen
controller-gen: $(LOCALBIN)
	@test -s $(CONTROLLER_GEN) || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: setup-envtest
setup-envtest: $(LOCALBIN)
	@test -s $(SETUP_ENVTEST) || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@release-0.25

.PHONY: golangci-lint
golangci-lint: $(LOCALBIN)
	@test -s $(GOLANGCI_LINT) || GOBIN=$(LOCALBIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
