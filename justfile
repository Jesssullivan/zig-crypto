# zig-crypto — Portable cryptographic primitives
# Run `just` to see all available recipes.

default:
    @just --list

# Build static library (ReleaseFast)
build:
    zig build -Doptimize=ReleaseFast

# Build debug library
build-debug:
    zig build

# Run unit tests
test:
    zig build test

# Run property-based tests
test-pbt:
    zig build test-pbt

# Run all tests (unit + PBT)
test-all: test test-pbt

# Clean build artifacts
clean:
    rm -rf .zig-cache zig-out

# Scan for leaked secrets
secrets-scan:
    detect-secrets scan --baseline .secrets.baseline
    detect-secrets audit --report --baseline .secrets.baseline

# Update secrets baseline
secrets-baseline:
    detect-secrets scan > .secrets.baseline

# Install pre-commit hooks
hooks:
    pre-commit install

# Nix: enter dev shell
dev:
    nix develop

# Nix: build library package
nix-build:
    nix build

# Nix: check flake
nix-check:
    nix flake check

# Show library info
info:
    @echo "zig-crypto v0.1.1"
    @echo "License: Zlib OR MIT"
    @echo ""
    @echo "Source files:"
    @wc -l src/*.zig | tail -1
    @echo "Test files:"
    @wc -l tests/*.zig | tail -1
    @echo ""
    @zig version
