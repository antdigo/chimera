use std::sync::{Arc, Condvar, Mutex};

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

#[derive(Default)]
pub(crate) struct BlockingPausePoint(Mutex<Option<Arc<BlockingPause>>>);

#[derive(Default)]
pub(crate) struct BlockingPause {
    pub reached: Notify,
    resumed: Mutex<bool>,
    resume: Condvar,
}

impl BlockingPausePoint {
    pub fn arm(&self) -> Arc<BlockingPause> {
        let pause = Arc::new(BlockingPause::default());
        *self.0.lock().unwrap() = Some(pause.clone());
        pause
    }

    pub fn take(&self) -> Option<Arc<BlockingPause>> {
        self.0.lock().unwrap().take()
    }
}

impl BlockingPause {
    pub fn wait(&self) {
        self.reached.notify_one();
        let mut resumed = self.resumed.lock().unwrap();
        while !*resumed {
            resumed = self.resume.wait(resumed).unwrap();
        }
    }

    pub fn resume(&self) {
        *self.resumed.lock().unwrap() = true;
        self.resume.notify_one();
    }
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
