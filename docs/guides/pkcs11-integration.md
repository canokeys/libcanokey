# PKCS#11 integration

Use the C header for ABI declarations and the runnable probe for the operation
loop and buffer ownership. [C header](../../crates/canokey-c/include/canokey.h)
· [C probe](../../crates/canokey-c/examples/probe.c)

- Keep connection generation, token login, sessions, objects and mechanism
  state in the module. Invalidate the old profile before probing a replacement
  connection. Hold the card lease across SELECT, authentication and the target
  operation.
- Commit `C_Login` state after successful verification. Scope
  `CKU_CONTEXT_SPECIFIC` authorization to one operation. For a PIN-always
  key, pass the PIN in the same PIV operation as the private-key command.
- Record mechanism and key parameters in `C_SignInit`. For a size query or
  an undersized buffer, report the required width before taking a card lease.
  Execute signing only when producing output. For `CKM_ECDSA`, the
  `cnk_operation_signature_p1363` getter returns fixed-width `r || s`.
- Map protocol errors by the command's purpose. Preserve the distinction
  between an absent object, rejected authentication and a malformed response.
  Inspect batch progress before freeing a failed operation so caches reflect
  completed mutations.
- Keep hashing, RSA padding, KDFs, mechanism advertisement and secret erasure
  in the module. Derive mechanism availability from the observed profile and
  the module's implemented adapter.

See the API contracts for buffer queries, selected transactions and
authentication. [API contracts](../design/api-design.md#bindings)
