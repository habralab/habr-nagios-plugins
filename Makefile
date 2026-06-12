BUILD_DIR := build
GOCACHE := $(CURDIR)/.gocache
GOMODCACHE := $(CURDIR)/.gomodcache
GO ?= go
MODULE := github.com/habralab/habr-nagios-plugins
BIN_PREFIX ?= check
BIN_VENDOR ?=
DEB_VENDOR ?= habr
DEB_REVISION ?= 1
DEB_DISTRIBUTION ?= $(shell . /etc/os-release 2>/dev/null && printf '%s\n' "$$VERSION_CODENAME" || echo unstable)
DEB_URGENCY ?= medium
GO_BUILDMODE ?=
GO_EXTRA_LDFLAGS ?=
PACKMETA := GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) run ./cmd/tools/packmeta

GIT_TAG := $(shell git describe --tags --exact-match 2>/dev/null || true)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || true)
VERSION_BRANCH := $(subst /,-,$(GIT_BRANCH))
GIT_COMMIT := $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
GIT_DIRTY := $(shell test -n "$$(git status --porcelain 2>/dev/null)" && echo -dirty || true)
VERSION ?= $(if $(strip $(GIT_TAG)),$(GIT_TAG),$(if $(strip $(VERSION_BRANCH)),$(if $(filter HEAD,$(GIT_BRANCH)),dev,$(VERSION_BRANCH)),dev))
COMMIT ?= $(if $(filter unknown,$(GIT_COMMIT)),unknown,$(GIT_COMMIT)$(GIT_DIRTY))
LDFLAGS := -X '$(MODULE)/internal/core/buildinfo.Version=$(VERSION)' -X '$(MODULE)/internal/core/buildinfo.Commit=$(COMMIT)'
GO_BUILD_MODE_FLAG := $(if $(strip $(GO_BUILDMODE)),-buildmode=$(GO_BUILDMODE),)
RELEASE_LDFLAGS := -s -w $(LDFLAGS) $(GO_EXTRA_LDFLAGS)
DEBUG_LDFLAGS := $(LDFLAGS) $(GO_EXTRA_LDFLAGS)

PROBE_TARGETS := $(patsubst cmd/probes/%/main.go,%,$(wildcard cmd/probes/*/main.go))
TOOL_TARGETS := $(patsubst cmd/tools/%/main.go,%,$(wildcard cmd/tools/*/main.go))
PLATFORMS := linux/386 linux/amd64 linux/arm linux/arm64 darwin/amd64 darwin/arm64

define BIN_NAME
$(if $(strip $(BIN_VENDOR)),$(BIN_PREFIX)_$(BIN_VENDOR)_$(1),$(BIN_PREFIX)_$(1))
endef

.PHONY: build build-all build-debug check fmt test test-live package-prepare package-changelog package-deb package-deb-source package-lint package-clean clean distclean cross help FORCE

build: build-all

build-all: FORCE
	mkdir -p $(BUILD_DIR)
	@for cmd in $(PROBE_TARGETS); do \
		bin="$(call BIN_NAME,$$cmd)"; \
		echo "building $$bin"; \
		GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) build $(GO_BUILD_MODE_FLAG) -trimpath -ldflags="$(RELEASE_LDFLAGS)" -o $(BUILD_DIR)/$$bin ./cmd/probes/$$cmd || exit 1; \
	done

build-debug: FORCE
	mkdir -p $(BUILD_DIR)
	@for cmd in $(PROBE_TARGETS); do \
		bin="$(call BIN_NAME,$$cmd)"; \
		echo "building $$bin (debug-friendly)"; \
		GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) build $(GO_BUILD_MODE_FLAG) -ldflags="$(DEBUG_LDFLAGS)" -o $(BUILD_DIR)/$$bin ./cmd/probes/$$cmd || exit 1; \
	done

check:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) build -ldflags="$(LDFLAGS)" ./...

fmt:
	$(GO)fmt ./...

test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) test ./...

test-live:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) test -tags=live ./...

package-prepare:
	$(PACKMETA) debian --vendor $(DEB_VENDOR)

package-changelog:
	$(PACKMETA) changelog --version "$(VERSION)" --commit "$(COMMIT)" --revision "$(DEB_REVISION)" --distribution "$(DEB_DISTRIBUTION)" --urgency "$(DEB_URGENCY)"

package-deb:
	dpkg-buildpackage -us -uc -b

package-deb-source:
	dpkg-buildpackage -us -uc -S

package-lint:
	lintian ../$(shell basename $(CURDIR))_*.changes

package-clean:
	rm -rf debian/.debhelper
	rm -f debian/*.debhelper.log debian/*.substvars debian/files debian/debhelper-build-stamp
	find debian -mindepth 1 -maxdepth 1 -type d -name 'habr-nagios-plugin-*' -exec rm -rf {} +

cross:
	mkdir -p $(BUILD_DIR)
	@for cmd in $(PROBE_TARGETS); do \
		bin="$(call BIN_NAME,$$cmd)"; \
		for platform in $(PLATFORMS); do \
			os=$${platform%/*}; \
			arch=$${platform#*/}; \
			echo "building $$bin for $$os/$$arch"; \
			CGO_ENABLED=0 GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOOS=$$os GOARCH=$$arch $(GO) build $(GO_BUILD_MODE_FLAG) -trimpath -ldflags="$(RELEASE_LDFLAGS)" -o $(BUILD_DIR)/$$bin-$$os-$$arch ./cmd/probes/$$cmd || exit 1; \
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
		"  build       Build stripped release-like probe binaries from ./cmd/probes/* into ./build/" \
		"  build-debug Build debug-friendly binaries with symbols into ./build/" \
		"  check       Compile all packages" \
		"  fmt         Run gofmt recursively" \
		"  test        Run go test ./..." \
		"  test-live   Run integration tests that use a local live HTTP server" \
		"  package-prepare Refresh committed probe-specific Debian install/docs metadata from probe metadata" \
		"  package-changelog Generate a snapshot Debian changelog entry for local or CI package builds" \
		"  package-deb Assemble a Debian binary package with dpkg-buildpackage; assumes prepared manifests and suitable debian/changelog" \
		"  package-deb-source Assemble a Debian source package with dpkg-buildpackage; assumes prepared manifests and suitable debian/changelog" \
		"  package-lint Run lintian against ../$(shell basename $(CURDIR))_*.changes" \
		"  package-clean Remove Debian build staging artifacts without touching committed manifests" \
		"  cross       Cross-build every binary for supported Linux/macOS targets" \
		"  clean       Remove build artifacts" \
		"  distclean   Remove build artifacts and local Go cache" \
		"" \
		"Probes:" \
		$(foreach cmd,$(PROBE_TARGETS),"  $(call BIN_NAME,$(cmd))") \
		"" \
		"Tools:" \
		$(foreach cmd,$(TOOL_TARGETS),"  $(cmd)")

FORCE:
