# Integration Guide

zig-crypto is meant to sit behind application code as a small portable native boundary. Use the Zig package API when the consumer is Zig, and use the C ABI when integrating with Swift, C, C++, Python, GTK, WebKit, or another runtime with C interop.

## FFI De-attestation Boundary

Treat the C ABI as the stable contract between application developer experience and native capability implementation. For example, a SwiftUI or Cocoa application can keep its UI and app lifecycle code while moving crypto behavior behind `zig_crypto.h`; the same contract can be linked from a Linux-native GTK, WebKit, or CLI application.

This keeps platform-specific framework assumptions out of the core application model. In sibling libraries, the same shape applies to keychain storage, notifications, and CTAP2/WebAuthn device flows.

## As a Zig Dependency

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .zig_crypto = .{
        .url = "https://github.com/Jesssullivan/zig-crypto/archive/refs/heads/main.tar.gz",
    },
},
```

Then in `build.zig`:

```zig
const crypto_dep = b.dependency("zig_crypto", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zig-crypto", crypto_dep.module("zig-crypto"));
```

## As a C Static Library

Build the library:

```bash
zig build -Doptimize=ReleaseFast
```

Link against `zig-out/lib/libzig-crypto.a` and include `include/zig_crypto.h`:

```c
#include "zig_crypto.h"
#include <stdio.h>

int main() {
    uint8_t hash[32];
    const char *msg = "hello";
    zig_crypto_sha256((const uint8_t *)msg, 5, hash);

    uint8_t hex[64];
    zig_crypto_sha256_hex((const uint8_t *)msg, 5, hex);
    printf("SHA-256: %.64s\n", hex);
    return 0;
}
```

## Swift Integration

1. Add `libzig-crypto.a` and `zig_crypto.h` to your Xcode project
2. Add `zig_crypto.h` to your bridging header
3. Link the static library

```swift
import Foundation

var hash = [UInt8](repeating: 0, count: 32)
let data = Array("hello".utf8)
zig_crypto_sha256(data, data.count, &hash)
```

## Relationship to zig-ctap2

zig-crypto provides the cryptographic primitives used by [zig-ctap2](https://github.com/Jesssullivan/zig-ctap2) for PIN protocol v2 (ECDH P-256 key agreement, AES-256-CBC encryption, HMAC-SHA-256 authentication).
