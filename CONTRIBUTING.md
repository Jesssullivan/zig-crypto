# Contributing to zig-crypto

## Where to Start

The best entry points are issues labeled [`good first issue`](https://github.com/Jesssullivan/zig-crypto/labels/good%20first%20issue). These are scoped for contributors who want to improve Swift/Objective-C interop, examples, docs, or header ergonomics without changing cryptographic behavior.

Issues labeled [`help wanted`](https://github.com/Jesssullivan/zig-crypto/labels/help%20wanted) are also open for contributor help, but may require more context or API design.

Read the [Apple interop guide](docs/guides/apple-interop.md) before working on Swift, Objective-C, CryptoKit, CommonCrypto, or Security.framework migration examples. It defines what is available today and what is intentionally out of scope.

## Installation

### Zig Package Manager (recommended)

```bash
zig fetch --save git+https://github.com/Jesssullivan/zig-crypto.git
```

Then in your `build.zig`:

```zig
const dep = b.dependency("zig_crypto", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("zig-crypto", dep.module("zig-crypto"));
```

### Git Submodule (C FFI consumers)

```bash
git submodule add https://github.com/Jesssullivan/zig-crypto.git vendor/crypto
cd vendor/crypto && zig build -Doptimize=ReleaseFast
```

Link `-lzig-crypto` and include `zig_crypto.h`.

## Development

### Prerequisites

- Zig 0.15.2+
- No platform-specific dependencies (pure `std.crypto`)

### Build & Test

```bash
zig build                        # static library
zig build test                   # unit tests
zig build test-pbt               # property-based tests (1000 iterations)
zig build docs                   # generate API documentation
zig build example                # build and run C example
```

### Code Style

- `zig fmt` for formatting
- All `pub` and `export` functions need `///` doc comments
- C FFI exports go in `src/ffi.zig`
- Module implementations in `src/<module>.zig`
- Property-based tests in `tests/pbt_<module>.zig`

### Adding a new primitive

1. Create `src/<primitive>.zig` with the Zig API
2. Add `export fn zig_crypto_<primitive>_*` wrappers in `src/ffi.zig`
3. Add the C declarations to `include/zig_crypto.h`
4. Add unit tests in the module and a PBT in `tests/pbt_<primitive>.zig`
5. Wire the test files into `build.zig`

## Filing Issues

Open an issue at [github.com/Jesssullivan/zig-crypto/issues](https://github.com/Jesssullivan/zig-crypto/issues). Use the issue templates when possible; they are there to keep reports actionable.

For security-sensitive reports, do not paste secrets, keys, tokens, credentials, private logs, or unpublished vulnerability details into a public issue.

## License

Dual-licensed under [Zlib](https://opensource.org/licenses/Zlib) and [MIT](https://opensource.org/licenses/MIT).
