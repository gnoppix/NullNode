# ------------------------------------------------------------------ #
#  NullNode P2P Messenger — Build System                             #
#  Date: 2002-2026 by Gnoppix Linux                                  #
#  Author: Andreas Mueller                                           #
#  Licence: Business Source License (BSL / BUSL)                     #
#  You can use the code for free if your company or organisation     #
#  doesn't have more than 2 people.                                  #
# ------------------------------------------------------------------ #

# ---- Configuration ----
CARGO      ?= cargo
BUILD_MODE  ?= release
TARGET_DIR  := target/$(BUILD_MODE)

# Binary names
BIN_CLIENT   := nullnode
BIN_RELAY    := nullnode-relay
BIN_BOOTSTRAP := nullnode-bootstrap

# Source directories
SRC_DIR      := src
DOC_DIR      := doc

# Install prefix (default: /usr/local)
PREFIX      ?= /usr/local
BINDIR      := $(PREFIX)/bin

# Build metadata
VERSION     := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*= *"//;s/"//')
GIT_HASH    := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE  := $(shell date -u +%Y-%m-%d)
RUSTFLAGS   ?=

# ------------------------------------------------------------------ #
#  Targets                                                           #
# ------------------------------------------------------------------ #

.PHONY: all client relay bootstrap install clean test check docs docker help

## Build all binaries (release)
all: client relay bootstrap

## Build client binary (nullnode)
client:
	@echo "Building nullnode client ($(BUILD_MODE))..."
	RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) build --package nullnode-client --$(BUILD_MODE)
	@echo "  -> $(TARGET_DIR)/$(BIN_CLIENT)"

## Build relay binary (nullnode-relay)
relay:
	@echo "Building nullnode relay ($(BUILD_MODE))..."
	RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) build --package nullnode-relay --$(BUILD_MODE)
	@echo "  -> $(TARGET_DIR)/$(BIN_RELAY)"

## Build bootstrap binary (nullnode-bootstrap)
bootstrap:
	@echo "Building nullnode bootstrap ($(BUILD_MODE))..."
	RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) build --package nullnode-bootstrap --$(BUILD_MODE)
	@echo "  -> $(TARGET_DIR)/$(BIN_BOOTSTRAP)"

## Build all in debug mode
debug: BUILD_MODE = debug
debug: all

## Build all in release mode (default)
release: BUILD_MODE = release
release: all

## Install binaries to $(PREFIX)/bin
install: all
	@echo "Installing binaries to $(BINDIR)..."
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET_DIR)/$(BIN_CLIENT) $(DESTDIR)$(BINDIR)/
	install -m 755 $(TARGET_DIR)/$(BIN_RELAY) $(DESTDIR)$(BINDIR)/
	install -m 755 $(TARGET_DIR)/$(BIN_BOOTSTRAP) $(DESTDIR)$(BINDIR)/
	@echo "Installed: $(BIN_CLIENT), $(BIN_RELAY), $(BIN_BOOTSTRAP)"

## Uninstall binaries
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN_CLIENT)
	rm -f $(DESTDIR)$(BINDIR)/$(BIN_RELAY)
	rm -f $(DESTDIR)$(BINDIR)/$(BIN_BOOTSTRAP)

## Run all tests
test:
	@echo "Running all tests..."
	$(CARGO) test --workspace
	@echo "All tests passed."

## Run tests for a specific package
test-client:
	$(CARGO) test --package nullnode-client

test-relay:
	$(CARGO) test --package nullnode-relay

test-p2p:
	$(CARGO) test --package nullnode-p2p

test-dht:
	$(CARGO) test --package nullnode-dht-core

test-crypto:
	$(CARGO) test --package nullnode-crypto

test-protocol:
	$(CARGO) test --package nullnode-protocol

## Check compilation (fast, no code generation)
check:
	@echo "Checking workspace..."
	$(CARGO) check --workspace
	@echo "OK."

## Run clippy linter
lint:
	@echo "Running clippy..."
	$(CARGO) clippy --workspace --all-targets -- -D warnings
	@echo "No warnings."

## Format check
fmt:
	@echo "Checking formatting..."
	$(CARGO) fmt -- --check
	@echo "All files formatted."

## Auto-format code
format:
	$(CARGO) fmt --all

## Build documentation
docs:
	@echo "Building documentation..."
	$(CARGO) doc --workspace --no-deps
	@echo "Docs available in target/doc/"

## Build man pages from doc/ directory
man:
	@echo "Building man pages..."
	@mkdir -p $(DOC_DIR)
	$(CARGO) run --package nullnode-client -- --help > $(DOC_DIR)/nullnode.1 2>/dev/null || true
	@echo "  -> $(DOC_DIR)/nullnode.1"

## Clean build artifacts
clean:
	@echo "Cleaning..."
	$(CARGO) clean
	rm -rf target/

## Show build info
info:
	@echo "NullNode P2P Messenger"
	@echo "  Version:   $(VERSION)"
	@echo "  Git hash:  $(GIT_HASH)"
	@echo "  Build:     $(BUILD_DATE)"
	@echo "  Mode:      $(BUILD_MODE)"
	@echo "  Prefix:    $(PREFIX)"

## Build Debian package (requires cargo-deb)
deb: client
	@echo "Building Debian package..."
	$(CARGO) deb --package nullnode-client --$(BUILD_MODE)
	@echo "  -> $(TARGET_DIR)/nullnode-client_$(VERSION)_amd64.deb"

## Build static binary (musl target required)
static:
	@echo "Building static binary (musl)..."
	$(CARGO) build --package nullnode-client --$(BUILD_MODE) --target x86_64-unknown-linux-musl
	@echo "  -> target/x86_64-unknown-linux-musl/$(BUILD_MODE)/$(BIN_CLIENT)"

## Build Docker image
docker:
	@echo "Building Docker image nullnode:latest..."
	docker build -t nullnode:latest .
	@echo "  -> nullnode:latest"

## Show this help
help:
	@echo "NullNode P2P Messenger — Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build targets:"
	@echo "  all          Build all binaries (default: release)"
	@echo "  client       Build nullnode client binary"
	@echo "  relay        Build nullnode relay binary"
	@echo "  bootstrap    Build nullnode bootstrap server binary"
	@echo "  debug        Build in debug mode"
	@echo "  release      Build in release mode (optimized)"
	@echo "  static       Build static binary (requires musl target)"
	@echo ""
	@echo "Quality targets:"
	@echo "  test         Run all tests"
	@echo "  check        Fast compilation check"
	@echo "  lint         Run clippy linter"
	@echo "  fmt          Check formatting"
	@echo "  format       Auto-format code"
	@echo "  docs         Build documentation"
	@echo "  man          Generate man page"
	@echo ""
	@echo "Install targets:"
	@echo "  install      Install binaries to $(PREFIX)/bin"
	@echo "  uninstall    Remove installed binaries"
	@echo "  deb          Build Debian package"
	@echo ""
	Utility targets:
	  clean        Remove build artifacts
	  info         Show build metadata
	  docker       Build Docker image
	  help         Show this help
	@echo ""
	@echo "Variables:"
	@echo "  BUILD_MODE=release|debug   (default: release)"
	@echo "  PREFIX=/path               (default: /usr/local)"
	@echo "  CARGO=path/to/cargo        (default: cargo)"
