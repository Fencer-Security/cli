.PHONY: build build-prod check-release-version cross generate generate-check lint fmt test notices clean

BINARY := build/fencer
# Vendored copy of the repo-root schema.yaml so the CLI module builds standalone
# (e.g. in the public source mirror) without the Django app. The monorepo keeps
# this in sync via `bun run api` and the check-cli-api-client pre-commit hook.
SCHEMA := schema.yaml
VERSION ?= 0.0.0
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PROD_BASE_URL := https://app.fencer.dev
OAPI_CODEGEN_VERSION := v2.8.0
GO_LICENSES_VERSION := v1.6.0
GOBIN := $(shell go env GOPATH)/bin
export PATH := $(GOBIN):$(PATH)
export CGO_ENABLED := 0

LDFLAGS_BASE := -s -w -X fencer/cli/internal/version.Version=$(VERSION) -X fencer/cli/internal/version.Commit=$(COMMIT) -X fencer/cli/internal/version.Date=$(DATE)
LDFLAGS_PROD := $(LDFLAGS_BASE) -X fencer/cli/internal/config.DefaultBaseURL=$(PROD_BASE_URL)

PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

# Local build: defaults to the local dev domain (config.DefaultBaseURL's
# compiled-in default) until the first `fencer login`.
build:
	mkdir -p build
	go build -trimpath -ldflags="$(LDFLAGS_BASE)" -o $(BINARY) ./cmd/fencer/

# Prod build: bakes in the production base URL, for distributing to
# customers/CI where a local dev domain is never applicable.
build-prod: check-release-version
	mkdir -p build
	go build -trimpath -ldflags="$(LDFLAGS_PROD)" -o $(BINARY) ./cmd/fencer/

check-release-version:
	@if [ "$(VERSION)" = "0.0.0" ] || [ "$(VERSION)" = "v0.0.0" ] || [ -z "$(VERSION)" ]; then \
		echo "error: production/release builds require VERSION (got '$(VERSION)'). Example: make build-prod VERSION=1.2.3" >&2; \
		exit 1; \
	fi

cross: check-release-version
	@mkdir -p build
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		out="build/fencer-$$os-$$arch$$ext"; \
		echo "building $$out"; \
		GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags="$(LDFLAGS_PROD)" -o "$$out" ./cmd/fencer/; \
	done

generate:
	@installed=$$(oapi-codegen -version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1); \
	if [ "$$installed" != "$(OAPI_CODEGEN_VERSION)" ]; then \
		echo "Installing oapi-codegen $(OAPI_CODEGEN_VERSION) (found: $${installed:-none})"; \
		go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_CODEGEN_VERSION); \
	fi
	mkdir -p api/schema
	oapi-codegen -generate types,client -package schema $(SCHEMA) > api/schema/generated.go
	go run ./internal/operations/genenums -schema api/schema/generated.go -out internal/operations/schema_enums_gen.go

generate-check: generate
	@git diff --exit-code -- api/schema/generated.go internal/operations/schema_enums_gen.go || { \
		echo "CLI generated OpenAPI artifacts are stale. Run 'make -C cli generate' and commit the result."; \
		exit 1; \
	}

lint:
	@command -v golangci-lint >/dev/null 2>&1 || (echo "golangci-lint not found, run: brew install golangci-lint"; exit 1)
	golangci-lint run ./...

fmt:
	gofmt -w .

test:
	go test ./...

notices:
	go run github.com/google/go-licenses@$(GO_LICENSES_VERSION) report ./cmd/fencer --ignore fencer/cli > /tmp/fencer-cli-licenses.csv
	rm -rf /tmp/fencer-cli-license-files
	go run github.com/google/go-licenses@$(GO_LICENSES_VERSION) save ./cmd/fencer --save_path /tmp/fencer-cli-license-files --ignore fencer/cli
	./scripts/generate-notices.sh /tmp/fencer-cli-licenses.csv /tmp/fencer-cli-license-files THIRD_PARTY_NOTICES

clean:
	rm -rf build/ dist/
