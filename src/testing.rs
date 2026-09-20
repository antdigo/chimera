//! Helpers shared by the crate's unit tests.

use std::io::Write;
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};

use rsa::RsaPrivateKey;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
pub(crate) struct TracingWriter(Arc<Mutex<Vec<u8>>>);

impl Write for TracingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for TracingWriter {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

impl TracingWriter {
    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
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
