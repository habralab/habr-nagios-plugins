BUILD_DIR := build
GOCACHE := $(CURDIR)/.gocache
GOMODCACHE := $(CURDIR)/.gomodcache
GO ?= go
MODULE := github.com/habralab/habr-nagios-plugins
DEV_BIN_PREFIX ?= check

GIT_TAG := $(shell git describe --tags --exact-match 2>/dev/null || true)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || true)
VERSION_BRANCH := $(subst /,-,$(GIT_BRANCH))
GIT_COMMIT := $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
GIT_DIRTY := $(shell test -n "$$(git status --porcelain 2>/dev/null)" && echo -dirty || true)
VERSION ?= $(if $(strip $(GIT_TAG)),$(GIT_TAG),$(if $(strip $(VERSION_BRANCH)),$(if $(filter HEAD,$(GIT_BRANCH)),dev,$(VERSION_BRANCH)),dev))
COMMIT ?= $(if $(filter unknown,$(GIT_COMMIT)),unknown,$(GIT_COMMIT)$(GIT_DIRTY))
LDFLAGS := -X '$(MODULE)/internal/core/buildinfo.Version=$(VERSION)' -X '$(MODULE)/internal/core/buildinfo.Commit=$(COMMIT)'
RELEASE_LDFLAGS := -s -w $(LDFLAGS)

CMD_TARGETS := $(patsubst cmd/%/main.go,%,$(wildcard cmd/*/main.go))
BUILD_TARGETS := $(foreach cmd,$(CMD_TARGETS),$(BUILD_DIR)/$(DEV_BIN_PREFIX)_$(cmd))
PLATFORMS := linux/386 linux/amd64 linux/arm linux/arm64 darwin/amd64 darwin/arm64

.PHONY: build build-all build-debug check fmt test test-live clean distclean cross help FORCE

build: build-all

build-all: $(BUILD_TARGETS)

$(BUILD_DIR)/$(DEV_BIN_PREFIX)_%: FORCE
	mkdir -p $(BUILD_DIR)
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) build -trimpath -ldflags="$(RELEASE_LDFLAGS)" -o $@ ./cmd/$*

build-debug: FORCE
	mkdir -p $(BUILD_DIR)
	@for cmd in $(CMD_TARGETS); do \
		bin="$(DEV_BIN_PREFIX)_$$cmd"; \
		echo "building $$bin (debug-friendly)"; \
		GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$$bin ./cmd/$$cmd || exit 1; \
	done

check:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) build -ldflags="$(LDFLAGS)" ./...

fmt:
	$(GO)fmt ./...

test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) test ./...

test-live:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) test -tags=live ./...

cross:
	mkdir -p $(BUILD_DIR)
	@for cmd in $(CMD_TARGETS); do \
		bin="$(DEV_BIN_PREFIX)_$$cmd"; \
		for platform in $(PLATFORMS); do \
			os=$${platform%/*}; \
			arch=$${platform#*/}; \
			echo "building $$bin for $$os/$$arch"; \
			CGO_ENABLED=0 GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags="$(RELEASE_LDFLAGS)" -o $(BUILD_DIR)/$$bin-$$os-$$arch ./cmd/$$cmd || exit 1; \
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
		"  build       Build stripped release-like binaries from ./cmd/* into ./build/" \
		"  build-debug Build debug-friendly binaries with symbols into ./build/" \
		"  check       Compile all packages" \
		"  fmt         Run gofmt recursively" \
		"  test        Run go test ./..." \
		"  test-live   Run integration tests that use a local live HTTP server" \
		"  cross       Cross-build every binary for supported Linux/macOS targets" \
		"  clean       Remove build artifacts" \
		"  distclean   Remove build artifacts and local Go cache" \
		"" \
		"Binaries:" \
		$(foreach cmd,$(CMD_TARGETS),"  $(DEV_BIN_PREFIX)_$(cmd)")

FORCE:
