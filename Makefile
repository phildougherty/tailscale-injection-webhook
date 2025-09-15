# Tailscale Injection Webhook Makefile

# Build variables
VERSION ?= $(shell git describe --tags --always --dirty)
COMMIT ?= $(shell git rev-parse HEAD)
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -w -s -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

# Docker variables
REGISTRY ?= tailscale
IMAGE_NAME ?= tailscale-injection-webhook
IMAGE_TAG ?= $(VERSION)
IMAGE := $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

# Go variables
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
CGO_ENABLED ?= 0

# Kubernetes variables
NAMESPACE ?= tailscale-system
KUBECONFIG ?= ~/.kube/config

# Test variables
COVERAGE_DIR ?= coverage
COVERAGE_PROFILE ?= $(COVERAGE_DIR)/coverage.out

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: deps
deps: ## Install dependencies
	go mod download
	go mod verify

.PHONY: generate
generate: ## Generate code
	go generate ./...

.PHONY: build
build: ## Build the webhook binary
	@echo "Building webhook binary..."
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
		-ldflags="$(LDFLAGS)" \
		-o bin/webhook \
		./cmd/webhook

.PHONY: build-all
build-all: ## Build binaries for all platforms
	@echo "Building for linux/amd64..."
	@GOOS=linux GOARCH=amd64 $(MAKE) build
	@mv bin/webhook bin/webhook-linux-amd64

	@echo "Building for linux/arm64..."
	@GOOS=linux GOARCH=arm64 $(MAKE) build
	@mv bin/webhook bin/webhook-linux-arm64

	@echo "Building for darwin/amd64..."
	@GOOS=darwin GOARCH=amd64 $(MAKE) build
	@mv bin/webhook bin/webhook-darwin-amd64

	@echo "Building for darwin/arm64..."
	@GOOS=darwin GOARCH=arm64 $(MAKE) build
	@mv bin/webhook bin/webhook-darwin-arm64

.PHONY: run
run: build ## Run the webhook locally
	./bin/webhook \
		--kubeconfig=$(KUBECONFIG) \
		--tls-cert-file=certs/tls.crt \
		--tls-key-file=certs/tls.key \
		--port=8443 \
		--v=2

.PHONY: clean
clean: ## Clean build artifacts
	rm -rf bin/
	rm -rf $(COVERAGE_DIR)
	go clean -cache

##@ Testing

.PHONY: test
test: ## Run all tests
	go test -v -race ./...

.PHONY: test-unit
test-unit: ## Run unit tests
	@mkdir -p $(COVERAGE_DIR)
	go test -v -race -coverprofile=$(COVERAGE_PROFILE) -covermode=atomic ./pkg/...

.PHONY: test-integration
test-integration: ## Run integration tests
	go test -v -race -tags=integration ./test/integration/...

.PHONY: test-e2e
test-e2e: ## Run end-to-end tests
	go test -v -race -tags=e2e ./test/e2e/...

.PHONY: coverage
coverage: test-unit ## Generate coverage report
	go tool cover -html=$(COVERAGE_PROFILE) -o $(COVERAGE_DIR)/coverage.html
	@echo "Coverage report generated: $(COVERAGE_DIR)/coverage.html"

.PHONY: benchmark
benchmark: ## Run benchmarks
	go test -v -bench=. -benchmem ./...

##@ Code Quality

.PHONY: fmt
fmt: ## Format code
	go fmt ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: lint
lint: ## Run golangci-lint
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Install it from https://golangci-lint.run/usage/install/"; \
		exit 1; \
	fi

.PHONY: security
security: ## Run security scanner
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not installed. Install it with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
		exit 1; \
	fi

.PHONY: check
check: fmt vet lint security test ## Run all checks

##@ Docker

.PHONY: docker-build
docker-build: ## Build Docker image
	@echo "Building Docker image: $(IMAGE)"
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t $(IMAGE) \
		.

.PHONY: docker-push
docker-push: docker-build ## Push Docker image
	@echo "Pushing Docker image: $(IMAGE)"
	docker push $(IMAGE)

.PHONY: docker-run
docker-run: docker-build ## Run Docker container
	docker run --rm -p 8443:8443 -p 8080:8080 $(IMAGE)

.PHONY: docker-scan
docker-scan: docker-build ## Scan Docker image for vulnerabilities
	@if command -v trivy >/dev/null 2>&1; then \
		trivy image $(IMAGE); \
	else \
		echo "trivy not installed. Install it from https://aquasecurity.github.io/trivy/"; \
	fi

##@ Kubernetes

.PHONY: deploy
deploy: ## Deploy to Kubernetes
	@echo "Deploying to namespace: $(NAMESPACE)"
	kubectl apply -f deploy/manifests/rbac.yaml
	kubectl apply -f deploy/manifests/certificates.yaml
	kubectl apply -f deploy/manifests/webhook.yaml

.PHONY: undeploy
undeploy: ## Remove from Kubernetes
	kubectl delete -f deploy/manifests/webhook.yaml --ignore-not-found
	kubectl delete -f deploy/manifests/certificates.yaml --ignore-not-found
	kubectl delete -f deploy/manifests/rbac.yaml --ignore-not-found

.PHONY: logs
logs: ## Show webhook logs
	kubectl logs -n $(NAMESPACE) deployment/tailscale-injection-webhook -f

.PHONY: status
status: ## Show deployment status
	kubectl get pods -n $(NAMESPACE) -l app=tailscale-injection-webhook
	kubectl get svc -n $(NAMESPACE) -l app=tailscale-injection-webhook

.PHONY: port-forward
port-forward: ## Port forward to webhook service
	kubectl port-forward -n $(NAMESPACE) svc/tailscale-injection-webhook 8443:443 8080:8080

##@ Development Tools

.PHONY: certs
certs: ## Generate development certificates
	@echo "Generating development certificates..."
	@mkdir -p certs
	@openssl req -x509 -newkey rsa:4096 -keyout certs/tls.key -out certs/tls.crt \
		-days 365 -nodes -subj "/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
	@echo "Certificates generated in certs/ directory"

.PHONY: webhook-config
webhook-config: ## Generate webhook configuration
	@echo "Generating webhook configuration..."
	@kubectl create configmap tailscale-injection-webhook-config \
		--from-file=config/injection-template.yaml \
		--namespace=$(NAMESPACE) \
		--dry-run=client -o yaml > deploy/manifests/webhook-config.yaml
	@echo "Configuration generated: deploy/manifests/webhook-config.yaml"

.PHONY: auth-key
auth-key: ## Create auth key secret (requires TAILSCALE_AUTH_KEY)
	@if [ -z "$(TAILSCALE_AUTH_KEY)" ]; then \
		echo "Error: TAILSCALE_AUTH_KEY environment variable is required"; \
		echo "Usage: make auth-key TAILSCALE_AUTH_KEY=tskey-auth-your-key"; \
		exit 1; \
	fi
	@kubectl create secret generic tailscale-auth-key \
		--from-literal=authkey=$(TAILSCALE_AUTH_KEY) \
		--namespace=$(NAMESPACE) \
		--dry-run=client -o yaml | kubectl apply -f -
	@echo "Auth key secret created in namespace: $(NAMESPACE)"

##@ Helm

.PHONY: helm-lint
helm-lint: ## Lint Helm chart
	helm lint deploy/helm/tailscale-injector

.PHONY: helm-template
helm-template: ## Generate Helm templates
	helm template tailscale-injector deploy/helm/tailscale-injector \
		--namespace $(NAMESPACE) \
		--set image.tag=$(VERSION)

.PHONY: helm-install
helm-install: ## Install Helm chart
	helm upgrade --install tailscale-injector deploy/helm/tailscale-injector \
		--namespace $(NAMESPACE) \
		--create-namespace \
		--set image.tag=$(VERSION) \
		--wait

.PHONY: helm-uninstall
helm-uninstall: ## Uninstall Helm chart
	helm uninstall tailscale-injector --namespace $(NAMESPACE)

.PHONY: helm-package
helm-package: ## Package Helm chart
	helm package deploy/helm/tailscale-injector --destination dist/

##@ Examples

.PHONY: example-basic
example-basic: ## Deploy basic example
	kubectl apply -f examples/basic-pod.yaml

.PHONY: example-advanced
example-advanced: ## Deploy advanced example
	kubectl apply -f examples/advanced-deployment.yaml

.PHONY: example-subnet-router
example-subnet-router: ## Deploy subnet router example
	kubectl apply -f examples/subnet-router.yaml

.PHONY: example-exit-node
example-exit-node: ## Deploy exit node example
	kubectl apply -f examples/exit-node.yaml

.PHONY: example-userspace
example-userspace: ## Deploy userspace mode example
	kubectl apply -f examples/userspace-mode.yaml

.PHONY: examples-clean
examples-clean: ## Clean up examples
	kubectl delete -f examples/ --ignore-not-found

##@ Release

.PHONY: tag
tag: ## Create a new git tag
	@if [ -z "$(TAG)" ]; then \
		echo "Error: TAG variable is required"; \
		echo "Usage: make tag TAG=v1.0.0"; \
		exit 1; \
	fi
	git tag -a $(TAG) -m "Release $(TAG)"
	git push origin $(TAG)

.PHONY: release
release: check docker-build docker-push helm-package ## Create a release
	@echo "Release $(VERSION) created successfully"
	@echo "Docker image: $(IMAGE)"
	@echo "Helm chart: dist/tailscale-injector-$(VERSION).tgz"

##@ Utilities

.PHONY: version
version: ## Show version information
	@echo "Version: $(VERSION)"
	@echo "Commit: $(COMMIT)"
	@echo "Date: $(DATE)"
	@echo "Image: $(IMAGE)"

.PHONY: env
env: ## Show environment variables
	@echo "GOOS: $(GOOS)"
	@echo "GOARCH: $(GOARCH)"
	@echo "CGO_ENABLED: $(CGO_ENABLED)"
	@echo "KUBECONFIG: $(KUBECONFIG)"
	@echo "NAMESPACE: $(NAMESPACE)"

.PHONY: tools
tools: ## Install development tools
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	@echo "Tools installed successfully"

# Default target
.DEFAULT_GOAL := help