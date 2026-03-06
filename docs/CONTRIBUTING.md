# Contributing to PicoKeys v2

Thank you for your interest in contributing! PicoKeys is a security-sensitive project,
so please read these guidelines carefully.

## Getting Started

1. Fork the repository and clone your fork
2. Install dependencies: `./scripts/install-deps.sh`
3. Build the CLI: `./scripts/build.sh cli`
4. Run tests: `./scripts/test.sh unit`
5. Run lints: `./scripts/lint.sh`

## Code Style

### Formatting

All code must pass `cargo fmt --all -- --check`. Run `./scripts/lint.sh --fix` to
auto-format before committing.

### Clippy

All code must pass Clippy with `-D warnings`:

```bash
cargo clippy -p picokeys-cli -- -D warnings
cargo clippy -p pico-rs-sdk -- -D warnings
```

### Naming Conventions

- Types: `PascalCase` (`ResidentCredential`, `FileStore`)
- Functions/methods: `snake_case` (`handle_make_credential`, `read_file`)
- Constants: `SCREAMING_SNAKE_CASE` (`MAX_CREDENTIALS`, `HID_REPORT_SIZE`)
- Feature flags: `lowercase` (`rp2040`, `esp32s3`, `alloc`)
- Binary names: `kebab-case` (`picokeys-fido-rp2040`, `picokeys-cli`)

### Documentation

- All public types and functions must have doc comments (`///`)
- Module-level docs (`//!`) for each module explaining its purpose
- Use `# Examples` sections in doc comments where helpful
- Keep comments concise — prefer self-documenting code

## Pull Request Process

1. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/my-change
   ```

2. **Make your changes** with clear, atomic commits

3. **Ensure all checks pass**:
   ```bash
   ./scripts/lint.sh
   ./scripts/test.sh unit
   ./scripts/build.sh cli
   ```

4. **Open a PR** against `main` with:
   - Clear title describing the change
   - Description of what and why
   - Link to any related issues
   - For security changes: note the threat model impact

5. **Address review feedback** with fixup commits, then squash before merge

### PR Requirements

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy -p <crate> -- -D warnings` passes for affected crates
- [ ] Unit tests pass (`cargo test`)
- [ ] New public API has doc comments
- [ ] No new `unsafe` without justification and safety comments
- [ ] No new dependencies without justification

## Testing Requirements

### Unit Tests

- New logic should have unit tests where feasible
- Crypto functions should have known-answer tests (KAT)
- Parser code should have tests for valid, invalid, and edge-case inputs

### Integration Tests

- Hardware-dependent tests use `#[ignore]` and require a connected device
- Run with: `cargo test -- --ignored`
- See `tests/fido2/` and `tests/hsm/` for test stubs

### Fuzz Testing

- Parser/deserializer changes should be covered by fuzz targets
- Existing fuzz targets are in `fuzz/fuzz_targets/`
- Run with: `cargo fuzz run <target>`

## Security-Sensitive Code Rules

PicoKeys handles cryptographic keys and user credentials. All contributors must follow
these rules for security-critical code:

### Secret Handling

- **Zeroize all secrets**: Use `zeroize::Zeroize` and `ZeroizeOnDrop` on any struct
  holding key material, PINs, or session tokens
- **Use `SecretBox<T>`** for long-lived secrets that must remain in memory
- **Explicitly zeroize temporaries**: Call `.zeroize()` on stack buffers holding
  intermediate crypto values before they go out of scope
- **No logging secrets**: Never log, print, or include key material in error messages

### Constant-Time Operations

- **Use `subtle::ConstantTimeEq`** for all secret comparisons (PINs, HMACs, MACs)
- **Use `subtle::Choice`** for secret-dependent conditionals
- **No branching on secrets**: Avoid `if secret == expected` patterns
- **No early returns on secrets**: Functions comparing secrets must always execute
  the full comparison

### Cryptographic Code

- **Use RustCrypto crates** — do not implement custom crypto primitives
- **Never reuse nonces**: AES-GCM nonces must be unique per encryption. Use the
  RNG to generate 12-byte random nonces
- **Validate all inputs**: Check key sizes, nonce lengths, and buffer sizes before
  passing to crypto functions
- **Handle errors explicitly**: Never `.unwrap()` on crypto operations in production code

### Memory Safety

- **Minimize `unsafe`**: If `unsafe` is truly necessary, add a `// SAFETY:` comment
  explaining the invariants
- **No `unsafe` in crypto paths** unless required by FFI and thoroughly reviewed
- **Stack allocation preferred**: Use `heapless::Vec` over heap allocation in
  embedded firmware

### PIN and Authentication

- **PBKDF2 with 256,000 iterations** minimum for PIN hashing
- **Random 16-byte salt** per device
- **Retry counter**: Must decrement before verification attempt (not after)
- **Lock at 0 retries**: Device must become unusable for that function

## Module Ownership

| Area | Primary Files | Notes |
|------|--------------|-------|
| Platform SDK | `pico-rs-sdk/src/` | Core traits, must not break API |
| Crypto | `pico-rs-sdk/src/crypto/` | KAT required for changes |
| Storage | `pico-rs-sdk/src/store/` | Backward-compatible serialization |
| CTAP2/FIDO2 | `pico-rs-fido/src/fido/` | Conformance-critical |
| U2F | `pico-rs-fido/src/u2f/` | Legacy compatibility |
| OATH | `pico-rs-fido/src/oath/` | YKOATH protocol compatibility |
| HSM | `pico-rs-hsm/src/` | SmartCard-HSM protocol compatibility |
| CLI | `picokeys-cli/src/` | User-facing, needs good UX |
| Platform adapters | `pico-rs-sdk/src/platform/` | Hardware-specific, test on hardware |

## Reporting Security Issues

**Do not open public issues for security vulnerabilities.**

See [SECURITY.md](../SECURITY.md) for responsible disclosure instructions.

## License

Contributions are licensed under MIT OR Apache-2.0 (dual license), matching the project.
By submitting a PR, you agree to license your contribution under these terms.
