use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

/// A one-shot filesystem boundary pause. Synchronization is explicit; timeouts
/// in the callers only bound failures rather than arrange the race.
#[derive(Default)]
pub(crate) struct PausePoint(Mutex<Option<Arc<Pause>>>);

#[derive(Default)]
pub(crate) struct Pause {
    pub reached: Notify,
    pub resume: Notify,
}

impl PausePoint {
    pub fn arm(&self) -> Arc<Pause> {
        let pause = Arc::new(Pause::default());
        *self.0.lock().unwrap() = Some(pause.clone());
        pause
    }

    pub async fn wait(&self) {
        let pause = self.0.lock().unwrap().take();
        if let Some(pause) = pause {
            pause.reached.notify_one();
            pause.resume.notified().await;
        }
    }
}
