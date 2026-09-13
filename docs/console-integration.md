# Console integration boundary

This is **future integration pseudocode**, not a shipped FRB binding or a modification to Console. The underlying probe and certificate-read Rust APIs exist today; the runnable equivalents are linked from [README](../README.md). Common ownership and protocol rules live in [design](api-design.md).

## Responsibilities

| Layer | Owns |
| --- | --- |
| Flutter UI | Input, navigation, cancellation requests, localized error display |
| Dart service | Connection generation, device lock/lease, async executor, profile lifetime |
| Dart transport | One raw PCSC/USB/WebUSB/NFC exchange and transport errors |
| Console Rust FRB wrapper | Opaque owned wrappers, concrete factories, DTO/error conversion |
| libcanokey facade | Probe and PIV operations; protocol state, APDUs, parsing, compatibility |

Dart retains the opaque operation across await points. Rust holds no Dart callback, connection, registry or global state. The FRB wrapper calls the Rust facade directly; C ABI is unnecessary. Console-specific hashing, CSR and certificate policy may live in Console Rust pure functions without becoming libcanokey responsibilities.

## Rust wrapper sketch

The following illustrates generated-binding shapes; `dispatch_*` denotes a match over the core operations, not another state machine. An actual FRB implementation must use its supported opaque annotations and DTO types.

```rust,ignore
pub struct ProtocolProfile { inner: Option<canokey::DeviceProfile> }
pub struct ProtocolOp { inner: Option<AnyOperation> }
enum AnyOperation {
    Probe(canokey::Operation<canokey::DeviceProfile>),
    Certificate(canokey::Operation<canokey::piv::Certificate>),
}
pub enum BridgeStep { Exchange, Done, Failed(ProtocolErrorDto) }
pub struct CertificateDto { pub der: Vec<u8>, pub was_compressed: bool }

pub fn new_read_certificate(profile: &ProtocolProfile, slot: SlotDto,
                            options: OptionsDto) -> Result<ProtocolOp, BridgeError> {
    let op = canokey::piv::read_certificate(
        profile.require_open()?, slot.try_into()?,
        canokey::piv::Access::None, options.try_into()?)?;
    Ok(ProtocolOp { inner: Some(AnyOperation::Certificate(op)) })
}
impl ProtocolOp {
    pub fn start(&mut self) -> BridgeStep { self.dispatch_start() }
    pub fn advance(&mut self, response: Vec<u8>) -> BridgeStep {
        let response = Zeroizing::new(response);
        self.dispatch_advance(&response)
    }
    pub fn command_bytes(&self) -> Result<Vec<u8>, BridgeError> {
        Ok(self.dispatch_command()?.as_bytes().to_vec())
    }
    pub fn certificate_result(&self) -> Result<CertificateDto, BridgeError> {
        let result = self.require_certificate()?.result()?;
        Ok(CertificateDto {
            der: result.der().to_vec(), was_compressed: result.was_compressed(),
        })
    }
    pub fn take_profile(&mut self) -> Result<ProtocolProfile, BridgeError> {
        Ok(ProtocolProfile { inner: Some(self.require_probe_mut()?.take_result()?) })
    }
    pub fn close(&mut self) { self.inner.take(); }
}
```

`newProbe` wraps `probe_device`; profile also exposes copied info DTOs and idempotent close. Factory/getter errors preserve typed details rather than only strings. Wrappers do not cache commands, results, errors or terminal states. For PIN-protected reads, copy the bridge input into a zeroizing temporary and pass `Access::Pin(Pin::from_bytes(...))`; constructor completion releases the caller input lifetime.

## Dart executor and service

`CardLease` is an application object holding the lock and physical connection across the complete use case. `readResult` is a local Dart function and never crosses FRB.

```dart
// Pseudocode: generated union names depend on the FRB adapter.
Future<T> execute<T>(ProtocolOp op, CardLease lease, CancellationToken cancel,
                     T Function(ProtocolOp) readResult) async {
  try {
    lease.assertCurrentGeneration();
    cancel.throwIfCancelled();
    var step = op.start();
    while (true) {
      switch (step) {
        case BridgeExchange():
          final command = op.commandBytes();
          Uint8List? response;
          try {
            lease.assertCurrentGeneration();
            cancel.throwIfCancelled();
            response = await lease.exchangeRaw(command);
            lease.assertCurrentGeneration();
            cancel.throwIfCancelled();
            step = op.advance(response);
          } finally {
            wipe(command);
            wipe(response);
          }
          break;
        case BridgeDone():
          return readResult(op);
        case BridgeFailed(:final error):
          throw ProtocolFailure(error);
      }
    }
  } finally {
    op.close();
  }
}

Future<CertificateDto> readCertificate(slot, cancel) {
  return sessions.withExclusiveSession((lease) async {
    final profile = await execute(
      newProbe(lease.options), lease, cancel, (op) => op.takeProfile());
    try {
      return await execute(newReadCertificate(profile, slot, lease.options),
          lease, cancel, (op) => op.certificateResult());
    } finally {
      profile.close();
    }
  });
}
```

Use a raw exchange that does not issue identity APDUs, log credentials, or process 61xx/6Cxx itself. Synchronous bridge methods must consume/copy their inputs before returning so Dart may wipe its copy. A transport timeout must drain/cancel or isolate old I/O before releasing the lease; simply timing out a Future and unlocking is insufficient.

Per-use-case probing is conservative and convenient for NFC. A stable USB device context may cache the profile by connection generation and close it on replacement/disconnection. The operation stays local either way. UI disposal requests cancellation; it must not race the executor to close the operation. Show protocol errors separately from transport failures. Immutable UI/plugin strings cannot be guaranteed erasable.

## Certificate inspection

Console can enable `canokey`'s `x509` feature in its Rust wrapper and replace its local certificate metadata extraction with `canokey::x509::parse_der` or `parse_pem`. These are implemented pure functions returning owned `CertificateInfo`; they need no operation or card lease. The wrapper maps `DistinguishedName`, numeric validity bounds, OIDs, raw key/SPKI and extension data to concrete FRB DTOs. Format dates and labels in Dart. Map unknown key size to an optional DTO field instead of substituting encoded key length.

If another caller needs JSON, enable the `serde` feature and serialize the same result in that caller. Do not require Console to encode/decode JSON merely to cross FRB. Card/PIV errors and local X.509 errors remain distinguishable in the wrapper. MacOS role policy, trust decisions, CSR construction, private-key import and QR decoding still belong to the application.

## Planned private operations

When signing is implemented, add a Sign variant and `newSign` factory with the same lifecycle. It will perform SELECT, explicit VERIFY where needed, GENERAL AUTHENTICATE and continuation internally. Dart will still only exchange bytes and display typed results/errors. Management mutual-authentication challenges come from the application's CSPRNG.

A planned Batch handles known AUTH/IMPORT/WRITE CERT sequences under one SELECT. Workflows depending on an intermediate public key, such as CSR construction, remain service orchestration plus application pure functions. None of this requires a long-lived Rust device or session object.
