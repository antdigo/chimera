use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info, warn};

use crate::github::broker::{AgentStatus, BrokerClient, BrokerError, MessageType};

const CANCEL_POLL_DELAY: Duration = Duration::from_millis(2000);
const CANCEL_POLL_ERROR_DELAY: Duration = Duration::from_millis(5000);

/// Spawn a background task that polls the broker for cancellation messages
/// while a job executes, reporting the session as Busy so the broker routes
/// the running job's cancellation to it. When a `JobCancellation` arrives,
/// it triggers the token.
pub fn spawn_cancel_poller(
    broker: &BrokerClient,
    cancel_token: CancellationToken,
) -> JoinHandle<()> {
    let client = broker.client().clone();
    let server_url = broker.server_url().to_string();
    let session_id = broker.session_id().to_string();
    let token_manager = broker.token_manager_arc();

    // Carry the runner's tracing span into the spawned task: without it the
    // poller's logs are unattributable when several runners are busy at once.
    let span = tracing::Span::current();

    tokio::spawn(
        async move {
            let poller = BrokerClient::new(client, server_url, session_id, token_manager);
            loop {
                if cancel_token.is_cancelled() {
                    return;
                }

                // Logged before the request so a poll held open until the job
                // ends (and thus never completing) still leaves a trace.
                debug!("polling broker for job cancellation");

                let poll_result = tokio::select! {
                    result = poller.poll_message(AgentStatus::Busy) => result,
                    _ = cancel_token.cancelled() => return,
                };

                match poll_result {
                    Ok(Some(msg)) if msg.message_type == MessageType::JobCancellation => {
                        let job_id = msg
                            .parse_cancellation_job_id()
                            .unwrap_or_else(|_| "unknown".into());
                        info!(job_id, "received job cancellation from broker");
                        cancel_token.cancel();
                        return;
                    }
                    Ok(Some(msg)) => {
                        // Anything the broker routes to a Busy session matters
                        // when debugging cancellation delivery, so make it
                        // visible.
                        info!(
                            message_id = msg.message_id,
                            message_type = %msg.message_type,
                            "received non-cancellation message while busy, ignoring"
                        );
                        pause(CANCEL_POLL_DELAY, &cancel_token).await;
                    }
                    Ok(None) => {
                        debug!("no cancellation pending");
                        pause(CANCEL_POLL_DELAY, &cancel_token).await;
                    }
                    Err(error) => {
                        // The broker holding a Busy long-poll past the client
                        // timeout is a normal empty cycle (same as the idle
                        // loop), not a failure worth warning about.
                        let timed_out = error
                            .downcast_ref::<BrokerError>()
                            .is_some_and(|be| matches!(be, BrokerError::Timeout));
                        if timed_out {
                            debug!("busy long-poll window expired without a message");
                        } else {
                            warn!(error = %error, cause = ?error, "cancellation poll failed");
                        }
                        pause(CANCEL_POLL_ERROR_DELAY, &cancel_token).await;
                    }
                }
            }
        }
        .instrument(span),
    )
}

/// Sleep between poll cycles, returning early once the job ends.
async fn pause(delay: Duration, cancel_token: &CancellationToken) {
    let delay = if cfg!(test) {
        Duration::from_millis(10)
    } else {
        delay
    };
    tokio::select! {
        _ = tokio::time::sleep(delay) => {}
        _ = cancel_token.cancelled() => {}
    }
}

#[cfg(test)]
#[path = "cancel_test.rs"]
mod cancel_test;
