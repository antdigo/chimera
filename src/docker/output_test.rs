use super::{DockerErrorDiagnostic, DockerLogFramer, LineFramer, OutputProcessor};
use crate::job::logs::{LogLine, LogSender};
use bollard::container::LogOutput;

fn make_processor(debug_enabled: bool) -> (OutputProcessor, tokio::sync::mpsc::Receiver<LogLine>) {
    let masks = crate::job::secret_masker::shared_masker_for_test(&[]);
    let (tx, rx) = tokio::sync::mpsc::channel(256);
    let sender = LogSender::new_for_test(tx, masks.clone());
    let processor = OutputProcessor::new(sender, masks, debug_enabled);
    (processor, rx)
}

#[test]
fn line_framer_reassembles_secret_at_every_byte_split() {
    let bytes = "safe=α-canary-secret\r\nnext=line\n".as_bytes();
    for split in 0..=bytes.len() {
        let mut framer = LineFramer::default();
        let mut got = framer.push(&bytes[..split]);
        got.extend(framer.push(&bytes[split..]));
        got.extend(framer.finish());
        assert_eq!(got, ["safe=α-canary-secret", "next=line"]);
    }
}

#[test]
fn line_framer_handles_empty_lf_split_crlf_and_repeated_finish() {
    let mut framer = LineFramer::default();
    assert!(framer.push(b"").is_empty());
    assert!(framer.push(b"one\r").is_empty());
    assert_eq!(framer.push(b"\ntwo\n"), ["one", "two"]);
    assert_eq!(framer.finish(), None);
    assert_eq!(framer.finish(), None);
}

#[test]
fn line_framer_decodes_invalid_utf8_lossily_at_eof_once() {
    let mut framer = LineFramer::default();
    assert!(framer.push(b"bad-\xff").is_empty());
    assert_eq!(framer.finish().as_deref(), Some("bad-�"));
    assert_eq!(framer.finish(), None);
}

#[test]
fn docker_log_framer_keeps_stdout_and_stderr_partial_lines_separate() {
    let mut framer = DockerLogFramer::default();
    assert!(
        framer
            .push(LogOutput::StdOut {
                message: b"out-".to_vec().into(),
            })
            .is_empty()
    );
    assert!(
        framer
            .push(LogOutput::StdErr {
                message: b"err-".to_vec().into(),
            })
            .is_empty()
    );
    assert_eq!(
        framer.push(LogOutput::StdOut {
            message: b"done\n".to_vec().into(),
        }),
        ["out-done"]
    );
    assert_eq!(
        framer.push(LogOutput::StdErr {
            message: b"done\n".to_vec().into(),
        }),
        ["err-done"]
    );
    assert!(framer.finish().is_empty());
}

#[test]
fn docker_error_diagnostic_discards_daemon_payload() {
    let response_error = bollard::errors::Error::DockerResponseServerError {
        status_code: 500,
        message: "CANARY-DOCKER-RESPONSE".into(),
    };
    let stream_error = bollard::errors::Error::DockerStreamError {
        error: "CANARY-DOCKER-STREAM".into(),
    };

    let response = DockerErrorDiagnostic::from(&response_error);
    let stream = DockerErrorDiagnostic::from(&stream_error);
    let rendered = format!("{response:?} {stream:?}");

    assert_eq!(response.kind, "response");
    assert_eq!(response.status_code, Some(500));
    assert_eq!(stream.kind, "stream");
    assert!(!rendered.contains("CANARY-DOCKER"), "{rendered}");
}

#[tokio::test]
async fn split_add_mask_command_is_processed_only_after_complete_line() {
    let (processor, mut rx) = make_processor(false);
    let mut framer = LineFramer::default();
    assert!(framer.push(b"::add-mask::frame-").is_empty());
    for line in framer.push(b"secret\nvalue=frame-secret\n") {
        processor.process_line(&line).await;
    }

    assert_eq!(rx.recv().await.unwrap().content, "value=***");
}

#[tokio::test]
async fn plain_line_forwarded() {
    let (proc, mut rx) = make_processor(false);
    proc.process_line("hello world").await;
    assert_eq!(rx.recv().await.unwrap().content, "hello world");
}

#[tokio::test]
async fn set_env_collected() {
    let (proc, _rx) = make_processor(false);
    proc.process_line("::set-env name=FOO::bar").await;

    let state = proc.take_workflow_state_for_test().await;
    assert_eq!(state.env(), &[("FOO".into(), "bar".into())]);
}

#[tokio::test]
async fn set_output_collected() {
    let (proc, _rx) = make_processor(false);
    proc.process_line("::set-output name=result::42").await;

    let state = proc.take_workflow_state_for_test().await;
    assert_eq!(state.output(), &[("result".into(), "42".into())]);
}

#[tokio::test]
async fn add_path_collected() {
    let (proc, _rx) = make_processor(false);
    proc.process_line("::add-path::/usr/local/bin").await;

    let state = proc.take_workflow_state_for_test().await;
    assert_eq!(state.path(), &["/usr/local/bin"]);
}

#[tokio::test]
async fn add_mask_causes_masking() {
    let (proc, mut rx) = make_processor(false);
    proc.process_line("::add-mask::supersecret").await;
    proc.process_line("the supersecret value is here").await;

    // The LogSender masks content before sending, so the secret should be replaced
    assert_eq!(rx.recv().await.unwrap().content, "the *** value is here");
}

#[tokio::test]
async fn add_mask_registers_encoded_variants_for_all_sender_clones() {
    let (processor, mut rx) = make_processor(false);
    let clone = processor.clone();
    processor.process_line("::add-mask::quote-\"slash\\").await;
    clone.process_line(r#"json=quote-\"slash\\"#).await;

    assert_eq!(rx.recv().await.unwrap().content, "json=***");
}

#[tokio::test]
async fn save_state_collected() {
    let (proc, _rx) = make_processor(false);
    proc.process_line("::save-state name=key::val").await;

    let state = proc.take_workflow_state_for_test().await;
    assert_eq!(state.state(), &[("key".into(), "val".into())]);
}

#[tokio::test]
async fn warning_forwarded() {
    let (proc, mut rx) = make_processor(false);
    proc.process_line("::warning::something fishy").await;
    assert_eq!(
        rx.recv().await.unwrap().content,
        "##[warning]something fishy"
    );
}

#[tokio::test]
async fn error_forwarded() {
    let (proc, mut rx) = make_processor(false);
    proc.process_line("::error::oh no").await;
    assert_eq!(rx.recv().await.unwrap().content, "##[error]oh no");
}

#[tokio::test]
async fn group_and_endgroup_forwarded() {
    let (proc, mut rx) = make_processor(false);
    proc.process_line("::group::My Group").await;
    proc.process_line("::endgroup::").await;
    assert_eq!(rx.recv().await.unwrap().content, "##[group]My Group");
    assert_eq!(rx.recv().await.unwrap().content, "##[endgroup]");
}

#[tokio::test]
async fn debug_suppressed_when_disabled() {
    let (proc, mut rx) = make_processor(false);
    proc.process_line("::debug::secret info").await;
    proc.process_line("visible line").await;

    // Only the plain line should come through
    assert_eq!(rx.recv().await.unwrap().content, "visible line");
}

#[tokio::test]
async fn debug_forwarded_when_enabled() {
    let (proc, mut rx) = make_processor(true);
    proc.process_line("::debug::secret info").await;
    assert_eq!(rx.recv().await.unwrap().content, "##[debug]secret info");
}

#[tokio::test]
async fn apply_drains_buffers() {
    let (proc, _rx) = make_processor(false);
    proc.process_line("::set-env name=A::1").await;
    proc.process_line("::set-output name=B::2").await;

    let state = proc.take_workflow_state_for_test().await;
    assert_eq!(state.env(), &[("A".into(), "1".into())]);
    assert_eq!(state.output(), &[("B".into(), "2".into())]);

    // The next drain should find all command buffers empty.
    assert!(proc.take_workflow_state_for_test().await.is_empty());
}
