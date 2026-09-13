# Contributor instructions

## Scope and language

- Write all repository content, documentation, comments, diagnostics, and commit messages in English. Conversation may follow the user's language.
- `plan.md` owns milestones and acceptance criteria; `docs/api-design.md` owns API contracts; README describes implemented features and build commands. Never describe a design target as implemented.
- Implement and test only this repository. `references/` contains read-only upstream clones: never modify, commit, or use them as build dependencies. Do not integrate consumers without instructions.
- Original workspace code is Apache-2.0, authored by canokeys.org. New crates must inherit workspace license, license-file, authors, and homepage metadata; retain upstream notices for any third-party code. Keep one canonical root LICENSE.
- Deliver buildable, reviewable increments. Do not substitute empty implementations or constant Unsupported responses for unfinished protocols.

## Architecture and ownership

- The core has no I/O, transport trait, async runtime, enumeration, threads, or mutable globals. No handle registry, global locks, credential cache, or thread-local last_error. Immutable protocol constants are allowed.
- Callers own `DeviceProfile` and `Operation<T>`. Constructors own required configuration and inputs; never retain borrowed FFI buffers, connections, or application sessions.
- Only start/advance drive execution. Command/result getters never advance or resend. take_result transfers ownership once. Cancel/drop never send APDUs, roll back, or reconnect.
- Reuse maintained dependencies for standard cryptography and key formats; do not implement cryptographic primitives or constant-time comparison locally. Add dependencies with their first concrete use, choose minimal features, and check MSRV, licenses, secret handling and native/wasm dependency closure. Randomness remains caller-supplied.
- Put protocol logic in its applet crate, firmware rules in compat, and probe orchestration in the facade. The internal machine interface is for composition, not transport callbacks.
- Distinguish Unknown from Unsupported. PIV compatibility versions are not actual firmware versions. Generic YubiKey support is not CanoKey support evidence.

## Protocol and secrets

- Exchange complete command APDUs and complete response data plus status words. The core owns SELECT, authentication, continuation, chaining, and parsing.
- Bound all card-controlled parsing and allocation; malformed responses return errors, never panic. Interpret status words in command context; do not swallow failures as empty objects.
- Never insert SELECT between authentication and its target command, try default credentials implicitly, or replay mutations automatically.
- Redact PINs, keys, APDUs, temporary plaintext, and sensitive results from Debug/logs. Zeroize secret buffers, including old allocations during growth.
- The C ABI has only profile/operation opaque handles. Copy input descriptors; errors are caller-owned POD; getters use query-size/copy.
- Document FFI pointer, aliasing, and concurrency contracts. Catch unwindable panics. Keep fixed integer mappings synchronized with the header; expose neither Rust layouts nor borrowed internal pointers.

## Verification and commits

- Document every public API in English rustdoc: purpose, ownership, byte formats, state requirements and relevant errors; unsafe FFI entries need explicit Safety contracts. Keep executable examples as doctests and retain `deny(missing_docs)` in every crate.
- Add meaningful golden/transcript, failure-path, and lifecycle tests for protocol changes. Documentation-only changes do not need new tests.
- Before committing Rust changes, run fmt, relevant tests (including doctests), strict workspace/all-target clippy, and `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked` when public documentation changes. Verify wasm and dependency boundaries at core milestones.
- C ABI changes also require `scripts/test-c-abi.sh`: C/C++ headers, linking, buffer queries, ownership, and errors.
- Investigate toolchain/build failures autonomously. Report unrun checks honestly; offline transcripts are not hardware verification.
- Commit coherent stages promptly using Conventional Commits, imperative English subjects preferably within 72 characters.
- Inspect staged changes, `git diff --check`, and status before committing. Exclude reference clones, target, caches, secrets, and binaries; track Cargo.lock.
- Use the configured repository identity or the user's specified identity. Do not change global Git settings, force-push, or revert user changes.
