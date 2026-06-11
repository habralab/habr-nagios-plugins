BUILD_DIR := build
GOCACHE := $(CURDIR)/.gocache
GOMODCACHE := $(CURDIR)/.gomodcache
GO ?= go
MODULE := github.com/habralab/habr-nagios-plugins

GIT_TAG := $(shell git describe --tags --exact-match 2>/dev/null || true)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || true)
GIT_COMMIT := $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
GIT_DIRTY := $(shell test -n "$$(git status --porcelain 2>/dev/null)" && echo -dirty || true)
VERSION ?= $(if $(strip $(GIT_TAG)),$(GIT_TAG),$(if $(strip $(GIT_BRANCH)),$(if $(filter HEAD,$(GIT_BRANCH)),dev,$(GIT_BRANCH)),dev))
COMMIT ?= $(if $(filter unknown,$(GIT_COMMIT)),unknown,$(GIT_COMMIT)$(GIT_DIRTY))
LDFLAGS := -X '$(MODULE)/internal/core/buildinfo.Version=$(VERSION)' -X '$(MODULE)/internal/core/buildinfo.Commit=$(COMMIT)'

CMD_TARGETS := $(patsubst cmd/%/main.go,%,$(wildcard cmd/*/main.go))
PLATFORMS := linux/386 linux/amd64 linux/arm linux/arm64 darwin/amd64 darwin/arm64

.PHONY: build build-all check fmt test clean distclean cross help FORCE

build: build-all

build-all: $(CMD_TARGETS:%=build/%)

build/%: FORCE
	mkdir -p $(BUILD_DIR)
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$* ./cmd/$*

check:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) build -ldflags="$(LDFLAGS)" ./...

fmt:
	$(GO)fmt ./...

test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) test ./...

cross:
	mkdir -p $(BUILD_DIR)
	@for cmd in $(CMD_TARGETS); do \
		for platform in $(PLATFORMS); do \
			os=$${platform%/*}; \
			arch=$${platform#*/}; \
			echo "building $$cmd for $$os/$$arch"; \
			CGO_ENABLED=0 GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags="-s -w $(LDFLAGS)" -o $(BUILD_DIR)/$$cmd-$$os-$$arch ./cmd/$$cmd || exit 1; \
		done; \
	done

clean:
	rm -rf $(BUILD_DIR)

distclean: clean
	rm -rf $(GOCACHE)
	rm -rf $(GOMODCACHE)

help:
	@printf "%s\n" \
		"Targets:" \
		"  build       Build all binaries from ./cmd/* into ./build/" \
		"  check       Compile all packages" \
		"  fmt         Run gofmt recursively" \
		"  test        Run go test ./..." \
		"  cross       Cross-build every binary for supported Linux/macOS targets" \
		"  clean       Remove build artifacts" \
		"  distclean   Remove build artifacts and local Go cache" \
		"" \
		"Binaries:" \
		$(foreach cmd,$(CMD_TARGETS),"  $(cmd)")

FORCE:
