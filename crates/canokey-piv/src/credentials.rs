//! Credential commands reuse the shared PIV encoding and authentication parser.
use crate::*;

/// Owned credential action; Debug redacts every credential and drop wipes it.
#[derive(Debug)]
pub enum CredentialAction {
    /// Verify the supplied user PIN without updating a host credential cache.
    VerifyPin(Pin),
    /// Explicitly clear PIN verification on the selected applet.
    Logout,
    /// Replace the user PIN; caller owns host-cache update and uncertain outcomes.
    ChangePin {
        /// Existing user PIN.
        old: Pin,
        /// Replacement user PIN.
        new: Pin,
    },
    /// Replace the PUK; this may reset its retry counter on success.
    ChangePuk {
        /// Existing PUK.
        old: Puk,
        /// Replacement PUK.
        new: Puk,
    },
    /// Reset PIN retries and replace the PIN using the PUK.
    UnblockPin {
        /// Existing PUK.
        puk: Puk,
        /// Replacement user PIN.
        new_pin: Pin,
    },
}

/// Run one explicit credential command in the caller's selected transaction.
/// No SELECT, extra VERIFY, implicit retry or host-cache update occurs. The
/// action owns credentials; the operation owns encoded temporary copies.
/// All successes have Unchanged profile effect, not a reusable authorization.
/// # Errors
/// Profile/options/command limits fail at construction. At execution, failed
/// verification/replacement retains PIN versus PUK reference and retries;
/// malformed replies and uncertain I/O remain terminal. Drop is not rollback.
pub fn credential_in_context(
    context: &PivAccessContext,
    action: CredentialAction,
    options: OperationOptions,
) -> Result<Operation<MutationResult>, Error> {
    let (command, reference) = match action {
        CredentialAction::VerifyPin(pin) => (command::verify_pin(&pin), Some(SecretReference::Pin)),
        CredentialAction::Logout => (command::logout(), None),
        CredentialAction::ChangePin { old, new } => (
            command::change(0x24, 0x80, &old.0, &new.0),
            Some(SecretReference::Pin),
        ),
        CredentialAction::ChangePuk { old, new } => (
            command::change(0x24, 0x81, &old.0, &new.0),
            Some(SecretReference::Puk),
        ),
        CredentialAction::UnblockPin { puk, new_pin } => (
            command::change(0x2c, 0x80, &puk.0, &new_pin.0),
            Some(SecretReference::Puk),
        ),
    };
    super::make(
        context.profile(),
        vec![super::request(command, Phase::Authentication, reference)],
        options,
        move |response| {
            if !response.data.is_empty() {
                return Err(Error::new(ErrorKind::InvalidResponse).at(Phase::Parsing));
            }
            if let Some(reference) = reference {
                super::require_auth(&response, reference)?;
            } else {
                response.ensure_success(Phase::Authentication)?;
            }
            Ok(super::unchanged())
        },
    )
}
