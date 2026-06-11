BUILD_DIR := build
GOCACHE := $(CURDIR)/.gocache
GO ?= go

CMD_TARGETS := $(patsubst cmd/%/main.go,%,$(wildcard cmd/*/main.go))
PLATFORMS := linux/386 linux/amd64 linux/arm linux/arm64 darwin/amd64 darwin/arm64

.PHONY: build build-all check fmt test clean distclean cross help

build: build-all

build-all: $(CMD_TARGETS:%=build/%)

build/%:
	mkdir -p $(BUILD_DIR)
	GOCACHE=$(GOCACHE) $(GO) build -o $(BUILD_DIR)/$* ./cmd/$*

check:
	GOCACHE=$(GOCACHE) $(GO) build ./...

fmt:
	$(GO)fmt ./...

test:
	GOCACHE=$(GOCACHE) $(GO) test ./...

cross:
	mkdir -p $(BUILD_DIR)
	@for cmd in $(CMD_TARGETS); do \
		for platform in $(PLATFORMS); do \
			os=$${platform%/*}; \
			arch=$${platform#*/}; \
			echo "building $$cmd for $$os/$$arch"; \
			CGO_ENABLED=0 GOCACHE=$(GOCACHE) GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/$$cmd-$$os-$$arch ./cmd/$$cmd || exit 1; \
		done; \
	done

clean:
	rm -rf $(BUILD_DIR)

distclean: clean
	rm -rf $(GOCACHE)

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
