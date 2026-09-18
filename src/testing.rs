//! Helpers shared by the crate's unit tests.

use std::sync::OnceLock;

use rsa::RsaPrivateKey;

/// A process-wide RSA key for tests.
///
/// Generating a 2048-bit key takes up to a second on CI hardware and dozens of
/// tests each minted their own; the mock OAuth endpoints accept any token, so a
/// single key shared per test process is indistinguishable to them. Each caller
/// gets a clone, so accidental mutation cannot leak between tests.
pub(crate) fn test_private_key() -> RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap())
        .clone()
}
