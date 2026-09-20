use super::protocol::*;
use super::{AttemptIdentity, CancelReason, CommandEvent, CommandSpec, CommandTarget, DomainPath};
use std::collections::HashMap;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

fn identity() -> AttemptIdentity {
    AttemptIdentity::from_uuid(uuid::Uuid::from_u128(7)).unwrap()
}

#[test]
fn incremental_transport_services_partial_frames_without_waiting() {
    let (a, mut b) = UnixStream::pair().unwrap();
    let mut connection = ControlConnection::new(a, identity()).unwrap();
    let bytes = encode(&hello(1)).unwrap();
    b.write_all(&bytes[..7]).unwrap();
    assert!(connection.try_receive().unwrap().is_none());
    b.write_all(&bytes[7..]).unwrap();
    let mut received = None;
    for _ in 0..3 {
        received = received.or(connection.try_receive().unwrap());
    }
    assert!(matches!(received, Some(Message::Request(Request::Hello))));
    connection
        .start_send(Message::Response(Response::KernelReady))
        .unwrap();
    assert!(
        connection
            .start_send(Message::Response(Response::KernelReady))
            .is_err()
    );
    assert!(connection.try_flush().unwrap());
    let mut peer = ControlConnection::new(b, identity()).unwrap();
    assert!(matches!(
        peer.receive(Instant::now() + Duration::from_secs(1))
            .unwrap(),
        Message::Response(Response::KernelReady)
    ));
}

#[test]
fn command_rejection_preserves_the_rejected_command_identity() {
    let frame = Frame {
        message: Message::Response(Response::CommandRejected {
            command_id: 9,
            category: super::FailureCategory::Unavailable,
        }),
        ..hello(1)
    };
    let decoded = decode(&encode(&frame).unwrap()).unwrap();
    assert!(matches!(
        decoded.message,
        Message::Response(Response::CommandRejected { command_id: 9, .. })
    ));
    let (a, mut b) = UnixStream::pair().unwrap();
    b.write_all(&encode(&frame).unwrap()).unwrap();
    let Message::Request(Request::Run { spec, .. }) = command(Duration::from_secs(1)).message
    else {
        panic!()
    };
    assert!(
        ControlConnection::new(a, identity())
            .unwrap()
            .request(Request::Run {
                command_id: 8,
                spec
            })
            .is_err()
    );
}

fn hello(sequence: u64) -> Frame {
    Frame {
        version: 1,
        sequence,
        attempt: identity(),
        message: Message::Request(Request::Hello),
    }
}

#[test]
fn protocol_rejects_invalid_header_before_reading_body() {
    for (version, sequence, length) in [
        (2u16, 1u64, 16u32),
        (1, 0, 16),
        (1, 1, MAX_FRAME_BYTES + 1),
        (1, 1, 0),
    ] {
        assert!(decode_header(version, sequence, length).is_err());
        let mut bytes = Vec::new();
        bytes.extend(version.to_be_bytes());
        bytes.extend(sequence.to_be_bytes());
        bytes.extend(length.to_be_bytes());
        assert!(decode(&bytes).is_err());
    }
}

#[test]
fn protocol_requires_complete_known_typed_body() {
    let bytes = encode(&hello(1)).unwrap();
    assert!(matches!(
        decode(&bytes).unwrap().message,
        Message::Request(Request::Hello)
    ));
    for end in 0..bytes.len() {
        assert!(decode(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode(&trailing).is_err());
    for body in [
        r#"{"attempt":"00000000000000000000000000000007","message":{"direction":"Request","message":{"op":"Unknown"}}}"#,
        r#"{"attempt":"00000000000000000000000000000007","message":{"direction":"Request","message":{"op":"Hello","secret":"CANARY"}}}"#,
        r#"{"attempt":"00000000000000000000000000000000","message":{"direction":"Request","message":{"op":"Hello"}}}"#,
    ] {
        let error = decode(&raw_frame(body.as_bytes(), 1)).unwrap_err();
        assert!(!format!("{error:?} {error}").contains("CANARY"));
    }
}

fn raw_frame(body: &[u8], sequence: u64) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend(1u16.to_be_bytes());
    data.extend(sequence.to_be_bytes());
    data.extend((body.len() as u32).to_be_bytes());
    data.extend(body);
    data
}

#[test]
fn connection_rejects_wrong_identity_sequence_direction_and_eof() {
    for invalid in [
        hello(2),
        Frame {
            attempt: AttemptIdentity::new(),
            ..hello(1)
        },
    ] {
        let (a, mut b) = UnixStream::pair().unwrap();
        let mut connection = ControlConnection::new(a, identity()).unwrap();
        b.write_all(&encode(&invalid).unwrap()).unwrap();
        assert!(
            connection
                .receive(Instant::now() + Duration::from_secs(1))
                .is_err()
        );
    }
    let (a, mut b) = UnixStream::pair().unwrap();
    let mut connection = ControlConnection::new(a, identity()).unwrap();
    b.write_all(&encode(&hello(1)).unwrap()).unwrap();
    connection
        .receive(Instant::now() + Duration::from_secs(1))
        .unwrap();
    b.write_all(&encode(&hello(1)).unwrap()).unwrap();
    assert!(
        connection
            .receive(Instant::now() + Duration::from_secs(1))
            .is_err()
    );
    let (a, b) = UnixStream::pair().unwrap();
    drop(b);
    assert!(
        ControlConnection::new(a, identity())
            .unwrap()
            .request(Request::Hello)
            .is_err()
    );
    let (a, mut b) = UnixStream::pair().unwrap();
    b.write_all(&encode(&hello(1)).unwrap()).unwrap();
    assert!(
        ControlConnection::new(a, identity())
            .unwrap()
            .request(Request::Hello)
            .is_err()
    );
}

fn command(timeout: Duration) -> Frame {
    Frame {
        message: Message::Request(Request::Run {
            command_id: 1,
            spec: CommandSpec {
                target: CommandTarget::Sandboxed {
                    program: DomainPath::parse("/usr/bin/sh").unwrap(),
                    args: vec!["CANARY".into()],
                    cwd: DomainPath::parse("/work").unwrap(),
                },
                env: HashMap::from([("SECRET".into(), "CANARY".into())]),
                timeout,
                state: None,
            },
        }),
        ..hello(1)
    }
}

#[test]
fn command_wire_timeout_is_checked_and_trusted_commands_are_refused() {
    for duration in [Duration::ZERO, Duration::from_nanos(1), Duration::MAX] {
        assert!(encode(&command(duration)).is_err());
    }
    let original = command(Duration::from_millis(2000));
    let bytes = encode(&original).unwrap();
    assert!(String::from_utf8_lossy(&bytes[14..]).contains("\"timeout_ms\":2000"));
    assert!(!format!("{original:?}").contains("CANARY"));
    let Message::Request(Request::Run { spec, .. }) = decode(&bytes).unwrap().message else {
        panic!()
    };
    assert_eq!(spec.timeout, Duration::from_secs(2));
    let mut value: serde_json::Value = serde_json::from_slice(&bytes[14..]).unwrap();
    value["message"]["message"]["spec"]["timeout_ms"] = 0.into();
    assert!(decode(&raw_frame(&serde_json::to_vec(&value).unwrap(), 1)).is_err());
    value["message"]["message"]["spec"]["timeout_ms"] =
        serde_json::Value::String("18446744073709551616".into());
    assert!(decode(&raw_frame(&serde_json::to_vec(&value).unwrap(), 1)).is_err());
    let mut frame = command(Duration::from_secs(1));
    if let Message::Request(Request::Run { spec, .. }) = &mut frame.message {
        spec.target = CommandTarget::Trusted {
            program: "sh".into(),
            args: vec![],
            cwd: "/".into(),
        };
    }
    assert!(encode(&frame).is_err());
}

#[test]
fn queue_is_bounded_and_cancel_overtakes_full_output_queue() {
    let mut queue = OutboundQueue::new();
    for _ in 0..32 {
        queue
            .push(Message::Response(Response::Output {
                command_id: 1,
                event: CommandEvent::Stdout(vec![0; 32 * 1024]),
            }))
            .unwrap();
    }
    assert!(
        queue
            .push(Message::Response(Response::Bootstrapped))
            .is_err()
    );
    queue
        .push(Message::Request(Request::CancelCommand {
            command_id: 1,
            reason: CancelReason::User,
        }))
        .unwrap();
    assert!(matches!(
        queue.pop(),
        Some(Message::Request(Request::CancelCommand { .. }))
    ));
    assert!(
        queue
            .push(Message::Response(Response::Output {
                command_id: 1,
                event: CommandEvent::Stderr(vec![0; 32 * 1024 + 1])
            }))
            .is_err()
    );
    for _ in 0..32 {
        queue
            .push(Message::Request(Request::Shutdown {
                reason: CancelReason::Shutdown,
            }))
            .unwrap();
    }
    assert!(
        queue
            .push(Message::Request(Request::Shutdown {
                reason: CancelReason::Shutdown
            }))
            .is_err()
    );
}

fn snapshot() -> super::StepStateSnapshot {
    super::StepStateSnapshot {
        env: "€".repeat(20000),
        path: String::new(),
        output: "x".repeat(1024 * 1024),
        state: "CANARY".into(),
        summary: "summary".into(),
    }
}

#[test]
fn snapshot_chunks_round_trip_across_utf8_boundaries_and_validate_totals() {
    let id = super::StepFilesId::new();
    let chunks = snapshot_chunks(9, &id, &snapshot()).unwrap();
    assert!(chunks.len() > 32);
    let Response::SnapshotChunk { bytes, .. } = &chunks[0] else {
        panic!("expected first snapshot chunk");
    };
    assert_eq!(bytes.len(), 32 * 1024);
    assert!(std::str::from_utf8(bytes).is_err());
    let mut assembly = SnapshotAssembler::new(9, id.clone());
    let mut result = None;
    for chunk in chunks.clone() {
        result = assembly.push(chunk).unwrap();
    }
    assert_eq!(result.unwrap(), snapshot());
    assert!(assembly.push(chunks[0].clone()).is_err());
    for (request_id, step) in [(10, id.clone()), (9, super::StepFilesId::new())] {
        assert!(
            SnapshotAssembler::new(request_id, step)
                .push(chunks[0].clone())
                .is_err()
        );
    }
    assert!(
        SnapshotAssembler::new(9, id.clone())
            .push(chunks[1].clone())
            .is_err()
    );
    let mut duplicate = SnapshotAssembler::new(9, id.clone());
    duplicate.push(chunks[0].clone()).unwrap();
    assert!(duplicate.push(chunks[0].clone()).is_err());
    for (length, bytes) in [
        (1024 * 1024 + 1, vec![]),
        (1, vec![1, 2]),
        (2, vec![0xff, 0xff]),
        (40000, vec![1; 32769]),
    ] {
        let mut assembly = SnapshotAssembler::new(9, id.clone());
        assert!(
            assembly
                .push(Response::SnapshotChunk {
                    request_id: 9,
                    id: id.clone(),
                    field: SnapshotField::Env,
                    total_bytes: length,
                    chunk_index: 0,
                    bytes
                })
                .is_err()
        );
    }
    let mut oversized = snapshot();
    oversized.summary = "x".repeat(1024 * 1024 + 1);
    assert!(snapshot_chunks(9, &id, &oversized).is_err());
}

#[test]
fn snapshot_transport_uses_bounded_frames_and_correlates_request() {
    let (a, b) = UnixStream::pair().unwrap();
    let id = super::StepFilesId::new();
    let peer = std::thread::spawn(move || {
        let mut connection = ControlConnection::new(b, identity()).unwrap();
        let Message::Request(Request::ReadStep { id }) = connection
            .receive(Instant::now() + Duration::from_secs(3))
            .unwrap()
        else {
            panic!()
        };
        connection
            .send_snapshot(1, &id, &snapshot(), Instant::now() + Duration::from_secs(3))
            .unwrap();
    });
    let response = ControlConnection::new(a, identity())
        .unwrap()
        .request(Request::ReadStep { id })
        .unwrap();
    assert!(
        matches!(response, Response::StepSnapshot { snapshot: ref value, .. } if *value == snapshot())
    );
    peer.join().unwrap();
}

#[test]
fn request_refuses_wrong_response_operation_or_step() {
    for response in [
        Response::KernelReady,
        Response::StepPrepared {
            id: super::StepFilesId::new(),
        },
    ] {
        let (a, mut b) = UnixStream::pair().unwrap();
        b.write_all(
            &encode(&Frame {
                message: Message::Response(response),
                ..hello(1)
            })
            .unwrap(),
        )
        .unwrap();
        assert!(
            ControlConnection::new(a, identity())
                .unwrap()
                .request(Request::PrepareStep {
                    id: super::StepFilesId::new(),
                    event: vec![]
                })
                .is_err()
        );
    }
}

#[test]
fn header_only_oversize_is_refused_without_waiting_for_payload() {
    let (a, mut b) = UnixStream::pair().unwrap();
    let mut header = Vec::new();
    header.extend(1u16.to_be_bytes());
    header.extend(1u64.to_be_bytes());
    header.extend(u32::MAX.to_be_bytes());
    b.write_all(&header).unwrap();
    let start = Instant::now();
    let mut connection = ControlConnection::new(a, identity()).unwrap();
    assert!(connection.receive(start + Duration::from_secs(3)).is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(
        connection
            .send(
                Message::Request(Request::Hello),
                Instant::now() + Duration::from_secs(1)
            )
            .is_err()
    );
}

#[test]
fn incomplete_frame_deadline_does_not_reset_for_each_byte() {
    let (a, mut b) = UnixStream::pair().unwrap();
    b.write_all(&[0, 1]).unwrap();
    let start = Instant::now();
    let mut connection = ControlConnection::new(a, identity()).unwrap();
    assert!(matches!(
        connection.receive(start + Duration::from_millis(30)),
        Err(super::ExecutionDomainError::Backend {
            category: super::FailureCategory::Timeout,
            ..
        })
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
}
