# canokey-c

Experimental C ABI (version 0.1) for the CanoKey host protocol library. It
exposes the `canokey` facade to C consumers through opaque caller-owned profile
and operation handles, query-size/copy getters, and caller-owned POD errors.
The library performs no I/O: the caller owns the transport and feeds complete
APDU exchanges to each operation.

## Building and linking

The crate builds as a `cdylib`, `staticlib`, and `rlib`. Build the shared or
static library with Cargo:

```sh
cargo build -p canokey-c --locked
```

The C header `include/canokey.h` is the authoritative interface. A runnable,
offline example lives at `examples/probe.c`; from the repository root, run
`bash scripts/run-c-example.sh` to build the library, compile the example
against the header, and execute it.

## Feature flags

The default feature set is `piv`, `admin`, `oath`, and `openpgp`. Embedders
that only need PIV can select the `piv` feature alone to drop the unrelated
applet factories and erased-operation variants.

## Integration

See `docs/guides/pkcs11-integration.md` for guidance on embedding this ABI in a
larger module: executor loops, error mapping, and the split of session state
between the application and the library.

License: Apache-2.0
