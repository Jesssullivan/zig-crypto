# Source Tree: zig-crypto

```
zig-crypto/
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── docs.yml
├── docs/
│   ├── api/
│   │   ├── c-ffi.md  (C FFI API Reference: zig-crypto)
│   │   └── zig-api.md  (Zig API Reference: zig-crypto)
│   ├── guides/
│   │   ├── building.md  (Building)
│   │   └── integration.md  (Integration Guide)
│   ├── agents.md  (AGENTS.md)
│   ├── index.md  (zig-crypto)
│   ├── llms.txt
│   └── source-tree.md  (Source Tree: zig-crypto)
├── include/
│   └── zig_crypto.h  (C header -- 17 functions)
├── scripts/
│   ├── gen_api_docs.py
│   └── gen_docs.py
├── src/
│   ├── aes.zig  (AES-128/256-CBC)
│   ├── ecdh.zig  (ECDH P-256)
│   ├── ed25519.zig  (Ed25519 signing)
│   ├── ffi.zig  (C FFI exports)
│   ├── hmac.zig  (HMAC-SHA-256)
│   ├── pbkdf2.zig  (PBKDF2-SHA1)
│   ├── random.zig  (CSPRNG)
│   └── sha256.zig  (SHA-256 hash)
├── tests/
│   ├── pbt_aes.zig
│   ├── pbt_ecdh.zig
│   ├── pbt_ed25519.zig
│   └── pbt_sha256.zig
├── .coderabbit.yaml
├── .envrc
├── .gitignore
├── .pre-commit-config.yaml
├── .secrets.baseline
├── AGENTS.md  (AGENTS.md -- zig-crypto)
├── LICENSE  (License)
├── LLMS.txt
├── README.md  (zig-crypto)
├── build.zig
├── flake.nix  (Nix flake)
├── justfile  (Just task runner recipes)
└── mkdocs.yml  (MkDocs configuration)
```
