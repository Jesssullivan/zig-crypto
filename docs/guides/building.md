# Building

## Requirements

- Zig 0.15.2+
- macOS or Linux

## Static Library

```bash
zig build -Doptimize=ReleaseFast
```

Produces `zig-out/lib/libzig_crypto.a` with the C header at `include/zig_crypto.h`.

## With just

```bash
just build         # ReleaseFast static library
just test-all      # unit + PBT tests
just               # list all recipes
```

## With Nix

```bash
nix develop        # dev shell
nix build          # build package
```

## Running Tests

```bash
# Unit tests
zig build test

# Property-based tests
zig build test-pbt
```

## Cross-Compilation

All crypto primitives are pure Zig with no platform dependencies (CSPRNG uses `std.crypto.random`):

```bash
zig build -Dtarget=aarch64-macos
zig build -Dtarget=x86_64-linux
zig build -Dtarget=aarch64-linux
```
