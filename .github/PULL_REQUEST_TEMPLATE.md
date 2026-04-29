## Summary

-

## Scope

- [ ] Keeps the existing C ABI stable, or documents any ABI addition in `include/zig_crypto.h`, README, and docs.
- [ ] Keeps C FFI exports in `src/ffi.zig`.
- [ ] Keeps cryptographic behavior independent of OpenSSL, BoringSSL, CommonCrypto, or other system crypto dependencies.
- [ ] Updates docs or examples when public behavior changes.

## Validation

- [ ] `zig build test`
- [ ] `zig build test-pbt`
- [ ] `zig build example`
- [ ] `zig build docs`

## Notes

Link related issues and call out any platform-specific caveats.
