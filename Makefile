.PHONY: help clean test test-network vet build frontend assets asset-check dist check release

GO ?= go
NPM ?= npm
VERSION ?= $(shell git describe --tags --always --dirty)
DIST_DIR ?= dist
WAILS_TAGS ?= desktop,production
HOST_OS := $(shell uname -s)
ifeq ($(HOST_OS),Darwin)
BUILD_CGO_LDFLAGS := $(strip $(CGO_LDFLAGS) -framework UniformTypeIdentifiers)
else
BUILD_CGO_LDFLAGS := $(CGO_LDFLAGS)
endif
LD_FLAGS ?= -s -w -X github.com/overkazaf/cap/internal/buildinfo.version=$(VERSION)

help:
	@printf 'cap build targets\n'
	@printf '  make check       run network-safe tests, frontend build, and asset sync check\n'
	@printf '  make test        run network-safe package tests\n'
	@printf '  make test-network run all tests, including local network integration tests\n'
	@printf '  make build       build the cap CLI for the host platform\n'
	@printf '  make frontend    install exact frontend dependencies and build Vite assets\n'
	@printf '  make assets      build frontend assets and sync them into cmd/cap\n'
	@printf '  make asset-check verify embedded frontend assets match the source build\n'
	@printf '  make dist        build release archives for supported platforms\n'

clean:
	@rm -rf $(DIST_DIR)

test:
	@CAP_SKIP_NETWORK=1 $(GO) test $(LOCAL_TEST_PACKAGES)

test-network:
	@$(GO) test ./...

vet:
	@$(GO) vet ./...

frontend:
	@cd frontend && { [ -d node_modules ] && [ ! package-lock.json -nt node_modules ] || $(NPM) ci; } && $(NPM) run build

assets: frontend
	@mkdir -p cmd/cap/frontend/dist
	@find cmd/cap/frontend/dist -mindepth 1 -maxdepth 1 ! -name .asset-check -exec rm -rf {} +
	@cp -R frontend/dist/. cmd/cap/frontend/dist/

asset-check: frontend
	@frontend_hash=$$(find frontend/dist -type f -print0 | sort -z | xargs -0 shasum -a 256 | sed 's#  frontend/dist/#  #' | shasum -a 256 | cut -d' ' -f1); \
	embedded_hash=$$(find cmd/cap/frontend/dist -type f ! -name .asset-check -print0 | sort -z | xargs -0 shasum -a 256 | sed 's#  cmd/cap/frontend/dist/#  #' | shasum -a 256 | cut -d' ' -f1); \
	if [ "$$frontend_hash" != "$$embedded_hash" ]; then \
		echo "embedded frontend assets are stale; run: make assets" >&2; \
		echo "  source:    $$frontend_hash" >&2; \
		echo "  embedded:  $$embedded_hash" >&2; \
		exit 1; \
	fi

build: asset-check
	@mkdir -p $(DIST_DIR)
	@CGO_ENABLED=1 CGO_LDFLAGS='$(BUILD_CGO_LDFLAGS)' $(GO) build -trimpath -tags '$(WAILS_TAGS)' -ldflags '$(LD_FLAGS)' -o $(DIST_DIR)/cap ./cmd/cap

check: test asset-check

release: dist

include Makefile.targets
