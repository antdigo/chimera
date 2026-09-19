//! Helpers shared by the crate's unit tests.

use std::sync::OnceLock;

use rsa::RsaPrivateKey;

#[derive(Clone, Default)]
pub(crate) struct CapturedLogs(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLogs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl CapturedLogs {
    pub(crate) fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync + 'static {
        let writer = self.clone();
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .without_time()
            .with_writer(move || writer.clone())
            .finish()
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

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
