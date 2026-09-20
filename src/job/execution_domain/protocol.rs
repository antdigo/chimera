use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::linux::rootfs::RootfsPlan;
use super::{
    AttemptIdentity, CancelReason, CommandEvent, CommandOutcome, CommandSpec, CommandTarget,
    DomainPath, ExecutionDomainError, FailureCategory, Stage, StepFilesId, StepStateSnapshot,
};

pub(super) const MAX_FRAME_BYTES: u32 = 1024 * 1024;
pub(super) const OUTPUT_CHUNK_BYTES: usize = 32 * 1024;
const HEADER_BYTES: usize = 14;
#[cfg(test)]
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) struct Frame {
    pub version: u16,
    pub sequence: u64,
    pub attempt: AttemptIdentity,
    pub message: Message,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BootstrapSpec {
    pub attempt: AttemptIdentity,
    pub rootfs: RootfsPlan,
    pub hostname: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub(super) enum Request {
    Bootstrap {
        spec: BootstrapSpec,
    },
    Hello,
    Run {
        command_id: u64,
        #[serde(with = "command_wire")]
        spec: CommandSpec,
    },
    CancelCommand {
        command_id: u64,
        #[serde(with = "ReasonWire")]
        reason: CancelReason,
    },
    PrepareStep {
        id: StepFilesId,
        event: Vec<u8>,
    },
    PrepareStepChunk {
        request_id: u64,
        id: StepFilesId,
        total_bytes: u32,
        chunk_index: u32,
        bytes: Vec<u8>,
    },
    ReadStep {
        id: StepFilesId,
    },
    Shutdown {
        #[serde(with = "ReasonWire")]
        reason: CancelReason,
    },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub(super) enum Response {
    Bootstrapped,
    KernelReady,
    CommandStarted {
        command_id: u64,
    },
    CommandRejected {
        command_id: u64,
        category: FailureCategory,
    },
    Output {
        command_id: u64,
        #[serde(with = "EventWire")]
        event: CommandEvent,
    },
    CommandFinished {
        command_id: u64,
        #[serde(with = "OutcomeWire")]
        outcome: CommandOutcome,
    },
    StepPrepared {
        id: StepFilesId,
    },
    StepSnapshot {
        id: StepFilesId,
        snapshot: StepStateSnapshot,
    },
    SnapshotChunk {
        request_id: u64,
        id: StepFilesId,
        field: SnapshotField,
        total_bytes: u32,
        chunk_index: u32,
        bytes: Vec<u8>,
    },
    ShuttingDown,
    Rejected {
        category: FailureCategory,
    },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "direction", content = "message", deny_unknown_fields)]
pub(super) enum Message {
    Request(Request),
    Response(Response),
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub(super) enum SnapshotField {
    Env,
    Path,
    Output,
    State,
    Summary,
}

macro_rules! redacted_debug {
    ($($name:ty),+ $(,)?) => { $(impl fmt::Debug for $name {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(stringify!($name)) }
    })+ };
}
redacted_debug!(Frame, BootstrapSpec, Request, Response, Message);

#[derive(Serialize)]
struct BodyRef<'a> {
    attempt: AttemptIdentity,
    message: &'a Message,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    attempt: AttemptIdentity,
    message: Message,
}

pub(super) fn decode_header(
    version: u16,
    sequence: u64,
    length: u32,
) -> Result<(), ExecutionDomainError> {
    if version != 1 || sequence == 0 || length == 0 || length > MAX_FRAME_BYTES {
        return Err(failure(FailureCategory::Protocol));
    }
    Ok(())
}

pub(super) fn encode(frame: &Frame) -> Result<Vec<u8>, ExecutionDomainError> {
    decode_header(frame.version, frame.sequence, 1)?;
    validate_message(&frame.message)?;
    let mut writer = BoundedWriter(Vec::new());
    serde_json::to_writer(
        &mut writer,
        &BodyRef {
            attempt: frame.attempt,
            message: &frame.message,
        },
    )
    .map_err(|_| failure(FailureCategory::Protocol))?;
    let length = writer.0.len() as u32;
    let mut result = Vec::with_capacity(HEADER_BYTES + writer.0.len());
    result.extend(frame.version.to_be_bytes());
    result.extend(frame.sequence.to_be_bytes());
    result.extend(length.to_be_bytes());
    result.extend(writer.0);
    Ok(result)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Frame, ExecutionDomainError> {
    let (version, sequence, length) = header(bytes)?;
    if bytes.len() != HEADER_BYTES + length as usize {
        return Err(failure(FailureCategory::Protocol));
    }
    let body: Body = serde_json::from_slice(&bytes[HEADER_BYTES..])
        .map_err(|_| failure(FailureCategory::Protocol))?;
    // Serde's internally-tagged unit variants ignore additional map entries
    // despite deny_unknown_fields. Enforce their zero-field wire shape too.
    if matches!(
        body.message,
        Message::Request(Request::Hello)
            | Message::Response(
                Response::Bootstrapped | Response::KernelReady | Response::ShuttingDown
            )
    ) {
        let value: serde_json::Value = serde_json::from_slice(&bytes[HEADER_BYTES..])
            .map_err(|_| failure(FailureCategory::Protocol))?;
        if value["message"]["message"]
            .as_object()
            .is_none_or(|object| object.len() != 1)
        {
            return Err(failure(FailureCategory::Protocol));
        }
    }
    validate_message(&body.message)?;
    Ok(Frame {
        version,
        sequence,
        attempt: body.attempt,
        message: body.message,
    })
}

fn header(bytes: &[u8]) -> Result<(u16, u64, u32), ExecutionDomainError> {
    if bytes.len() < HEADER_BYTES {
        return Err(failure(FailureCategory::Protocol));
    }
    let mut sequence = [0; 8];
    sequence.copy_from_slice(&bytes[2..10]);
    let mut length = [0; 4];
    length.copy_from_slice(&bytes[10..14]);
    let fields = (
        u16::from_be_bytes([bytes[0], bytes[1]]),
        u64::from_be_bytes(sequence),
        u32::from_be_bytes(length),
    );
    decode_header(fields.0, fields.1, fields.2)?;
    Ok(fields)
}

fn validate_message(message: &Message) -> Result<(), ExecutionDomainError> {
    match message {
        Message::Request(Request::PrepareStep { event, .. }) if event.len() > EVENT_LIMIT => {
            return Err(failure(FailureCategory::Protocol));
        }
        Message::Request(Request::PrepareStepChunk {
            request_id,
            total_bytes,
            bytes,
            ..
        }) if *request_id == 0
            || *total_bytes as usize > EVENT_LIMIT
            || bytes.len() > OUTPUT_CHUNK_BYTES
            || bytes.len() > *total_bytes as usize =>
        {
            return Err(failure(FailureCategory::Protocol));
        }
        _ => {}
    }
    if let Message::Response(Response::SnapshotChunk {
        request_id,
        total_bytes,
        bytes,
        ..
    }) = message
        && (*request_id == 0
            || *total_bytes > MAX_FRAME_BYTES
            || bytes.len() > OUTPUT_CHUNK_BYTES
            || bytes.len() > *total_bytes as usize)
    {
        return Err(failure(FailureCategory::Protocol));
    }
    if let Message::Response(Response::Output {
        event: CommandEvent::Stdout(bytes) | CommandEvent::Stderr(bytes),
        ..
    }) = message
        && bytes.len() > OUTPUT_CHUNK_BYTES
    {
        return Err(failure(FailureCategory::Protocol));
    }
    let id = match message {
        Message::Request(
            Request::Run { command_id, .. } | Request::CancelCommand { command_id, .. },
        )
        | Message::Response(
            Response::CommandStarted { command_id }
            | Response::CommandRejected { command_id, .. }
            | Response::Output { command_id, .. }
            | Response::CommandFinished { command_id, .. },
        ) => Some(*command_id),
        _ => None,
    };
    if id == Some(0) {
        return Err(failure(FailureCategory::Protocol));
    }
    Ok(())
}

struct BoundedWriter(Vec<u8>);
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_FRAME_BYTES as usize - self.0.len() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) struct ControlConnection {
    stream: UnixStream,
    attempt: AttemptIdentity,
    outgoing: u64,
    incoming: u64,
    failed: bool,
    interrupted: Option<&'static AtomicBool>,
    received: Vec<u8>,
    sending: Option<(Vec<u8>, usize)>,
}

impl ControlConnection {
    #[cfg(target_os = "linux")]
    pub(super) fn last_request_id(&self) -> u64 {
        self.incoming - 1
    }
    #[cfg(target_os = "linux")]
    pub(super) fn control_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.stream.as_fd()
    }

    pub(super) fn new(
        stream: UnixStream,
        attempt: AttemptIdentity,
    ) -> Result<Self, ExecutionDomainError> {
        stream.set_nonblocking(true).map_err(io_failure)?;
        Ok(Self {
            stream,
            attempt,
            outgoing: 1,
            incoming: 1,
            failed: false,
            interrupted: None,
            received: Vec::new(),
            sending: None,
        })
    }

    // One nonblocking read per tick: a partial peer frame cannot monopolize init.
    pub(super) fn try_receive(&mut self) -> Result<Option<Message>, ExecutionDomainError> {
        if self.failed {
            return Err(failure(FailureCategory::Protocol));
        }
        let result = self.try_receive_inner();
        self.failed |= result.is_err();
        result
    }

    fn try_receive_inner(&mut self) -> Result<Option<Message>, ExecutionDomainError> {
        let wanted = if self.received.len() < HEADER_BYTES {
            HEADER_BYTES
        } else {
            let (_, sequence, length) = header(&self.received)?;
            if sequence != self.incoming {
                return Err(failure(FailureCategory::Protocol));
            }
            HEADER_BYTES + length as usize
        };
        let mut buffer = [0u8; OUTPUT_CHUNK_BYTES];
        let take = (wanted - self.received.len()).min(buffer.len());
        if take > 0 {
            match self.stream.read(&mut buffer[..take]) {
                Ok(0) => return Err(failure(FailureCategory::Protocol)),
                Ok(n) => self.received.extend_from_slice(&buffer[..n]),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(None);
                }
                Err(error) => return Err(io_failure(error)),
            }
        }
        if self.received.len() < HEADER_BYTES {
            return Ok(None);
        }
        let (_, sequence, length) = header(&self.received)?;
        if sequence != self.incoming {
            return Err(failure(FailureCategory::Protocol));
        }
        if self.received.len() != HEADER_BYTES + length as usize {
            return Ok(None);
        }
        let frame = decode(&self.received)?;
        if frame.attempt != self.attempt {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        self.incoming = self
            .incoming
            .checked_add(1)
            .ok_or_else(|| failure(FailureCategory::Protocol))?;
        self.received.clear();
        Ok(Some(frame.message))
    }

    pub(super) fn start_send(&mut self, message: Message) -> Result<(), ExecutionDomainError> {
        if self.failed || self.sending.is_some() {
            return Err(failure(FailureCategory::Unavailable));
        }
        let bytes = encode(&Frame {
            version: 1,
            sequence: self.outgoing,
            attempt: self.attempt,
            message,
        })?;
        self.outgoing = self
            .outgoing
            .checked_add(1)
            .ok_or_else(|| failure(FailureCategory::Protocol))?;
        self.sending = Some((bytes, 0));
        Ok(())
    }

    pub(super) fn try_flush(&mut self) -> Result<bool, ExecutionDomainError> {
        if self.failed {
            return Err(failure(FailureCategory::Protocol));
        }
        let Some((bytes, sent)) = &mut self.sending else {
            return Ok(true);
        };
        match self.stream.write(&bytes[*sent..]) {
            Ok(0) => {
                self.failed = true;
                return Err(failure(FailureCategory::Protocol));
            }
            Ok(n) => *sent += n,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(false);
            }
            Err(error) => {
                self.failed = true;
                return Err(io_failure(error));
            }
        }
        if *sent == bytes.len() {
            self.sending = None;
        }
        Ok(self.sending.is_none())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn interrupt_on(&mut self, flag: &'static AtomicBool) {
        self.interrupted = Some(flag);
    }

    // The supervisor is promoted together with its manager in Task 9.
    #[cfg(test)]
    pub(super) fn request(&mut self, request: Request) -> Result<Response, ExecutionDomainError> {
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        self.request_until(request, deadline)
    }

    #[cfg(test)]
    pub(super) fn request_until(
        &mut self,
        request: Request,
        deadline: Instant,
    ) -> Result<Response, ExecutionDomainError> {
        let request_id = self.outgoing;
        let step = if let Request::ReadStep { id } = &request {
            Some(id.clone())
        } else {
            None
        };
        let expected = ExpectedResponse::for_request(&request);
        if let Request::PrepareStep { id, event } = request {
            for chunk in event_chunks(request_id, &id, &event)? {
                self.send(Message::Request(chunk), deadline)?;
            }
        } else {
            self.send(Message::Request(request), deadline)?;
        }
        match self.receive(deadline)? {
            Message::Response(chunk @ Response::SnapshotChunk { .. }) => {
                let Some(id) = step else {
                    self.failed = true;
                    return Err(failure(FailureCategory::Protocol));
                };
                let mut assembly = SnapshotAssembler::new(request_id, id.clone());
                let mut chunk = chunk;
                loop {
                    match assembly.push(chunk) {
                        Ok(Some(snapshot)) => return Ok(Response::StepSnapshot { id, snapshot }),
                        Ok(None) => {}
                        Err(error) => {
                            self.failed = true;
                            return Err(error);
                        }
                    }
                    let Message::Response(next) = self.receive(deadline)? else {
                        self.failed = true;
                        return Err(failure(FailureCategory::Protocol));
                    };
                    chunk = next;
                }
            }
            Message::Response(response) if expected.accepts(&response) => Ok(response),
            _ => {
                self.failed = true;
                Err(failure(FailureCategory::Protocol))
            }
        }
    }

    #[cfg(test)]
    pub(super) fn send_snapshot(
        &mut self,
        request_id: u64,
        id: &StepFilesId,
        snapshot: &StepStateSnapshot,
        deadline: Instant,
    ) -> Result<(), ExecutionDomainError> {
        for chunk in snapshot_chunks(request_id, id, snapshot)? {
            self.send(Message::Response(chunk), deadline)?;
        }
        Ok(())
    }

    pub(super) fn send(
        &mut self,
        message: Message,
        deadline: Instant,
    ) -> Result<(), ExecutionDomainError> {
        if self.failed {
            return Err(failure(FailureCategory::Protocol));
        }
        let result = self.send_inner(message, deadline);
        self.failed |= result.is_err();
        result
    }

    fn send_inner(
        &mut self,
        message: Message,
        deadline: Instant,
    ) -> Result<(), ExecutionDomainError> {
        let bytes = encode(&Frame {
            version: 1,
            sequence: self.outgoing,
            attempt: self.attempt,
            message,
        })?;
        let next = self
            .outgoing
            .checked_add(1)
            .ok_or_else(|| failure(FailureCategory::Protocol))?;
        let mut sent = 0;
        while sent < bytes.len() {
            self.wait(libc::POLLOUT, deadline)?;
            match self.stream.write(&bytes[sent..]) {
                Ok(0) => return Err(failure(FailureCategory::Protocol)),
                Ok(n) => sent += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(io_failure(e)),
            }
        }
        self.outgoing = next;
        Ok(())
    }

    pub(super) fn receive(&mut self, deadline: Instant) -> Result<Message, ExecutionDomainError> {
        if self.failed {
            return Err(failure(FailureCategory::Protocol));
        }
        let result = self.receive_inner(deadline);
        self.failed |= result.is_err();
        result
    }

    fn receive_inner(&mut self, deadline: Instant) -> Result<Message, ExecutionDomainError> {
        let mut bytes = vec![0; HEADER_BYTES];
        self.read_exact(&mut bytes, deadline)?;
        let (_, sequence, length) = header(&bytes)?;
        if sequence != self.incoming {
            return Err(failure(FailureCategory::Protocol));
        }
        let next = self
            .incoming
            .checked_add(1)
            .ok_or_else(|| failure(FailureCategory::Protocol))?;
        // The fixed header is validated before any peer-sized allocation.
        bytes.resize(HEADER_BYTES + length as usize, 0);
        self.read_exact(&mut bytes[HEADER_BYTES..], deadline)?;
        let frame = decode(&bytes)?;
        if frame.attempt != self.attempt {
            return Err(failure(FailureCategory::IdentityMismatch));
        }
        self.incoming = next;
        Ok(frame.message)
    }

    fn read_exact(
        &mut self,
        bytes: &mut [u8],
        deadline: Instant,
    ) -> Result<(), ExecutionDomainError> {
        let mut offset = 0;
        while offset < bytes.len() {
            self.wait(libc::POLLIN, deadline)?;
            match self.stream.read(&mut bytes[offset..]) {
                Ok(0) => return Err(failure(FailureCategory::Protocol)),
                Ok(n) => offset += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(io_failure(e)),
            }
        }
        Ok(())
    }

    fn wait(&self, events: i16, deadline: Instant) -> Result<(), ExecutionDomainError> {
        loop {
            if self
                .interrupted
                .is_some_and(|flag| flag.load(Ordering::Relaxed))
            {
                return Err(failure(FailureCategory::Unavailable));
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| failure(FailureCategory::Timeout))?;
            let timeout = remaining.as_millis().clamp(1, 100) as i32;
            let mut fd = libc::pollfd {
                fd: self.stream.as_raw_fd(),
                events,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut fd, 1, timeout) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(io_failure(error));
            }
            if result > 0 {
                if fd.revents & (events | libc::POLLHUP) != 0 {
                    return Ok(());
                }
                return Err(failure(FailureCategory::Protocol));
            }
        }
    }
}

#[cfg(test)]
enum ExpectedResponse {
    Bootstrap,
    Hello,
    Started(u64),
    Finished(u64),
    Prepared(StepFilesId),
    Snapshot(StepFilesId),
    Shutdown,
}

#[cfg(test)]
impl ExpectedResponse {
    fn for_request(request: &Request) -> Self {
        match request {
            Request::Bootstrap { .. } => Self::Bootstrap,
            Request::Hello => Self::Hello,
            Request::Run { command_id, .. } => Self::Started(*command_id),
            Request::CancelCommand { command_id, .. } => Self::Finished(*command_id),
            Request::PrepareStep { id, .. } | Request::PrepareStepChunk { id, .. } => {
                Self::Prepared(id.clone())
            }
            Request::ReadStep { id } => Self::Snapshot(id.clone()),
            Request::Shutdown { .. } => Self::Shutdown,
        }
    }
    fn accepts(&self, response: &Response) -> bool {
        match (self, response) {
            (_, Response::Rejected { .. })
            | (Self::Bootstrap, Response::Bootstrapped)
            | (Self::Hello, Response::KernelReady)
            | (Self::Shutdown, Response::ShuttingDown) => true,
            (Self::Started(expected), Response::CommandStarted { command_id })
            | (Self::Started(expected), Response::CommandRejected { command_id, .. })
            | (Self::Finished(expected), Response::CommandRejected { command_id, .. })
            | (Self::Finished(expected), Response::CommandFinished { command_id, .. }) => {
                expected == command_id
            }
            (Self::Prepared(expected), Response::StepPrepared { id })
            | (Self::Snapshot(expected), Response::StepSnapshot { id, .. }) => expected == id,
            _ => false,
        }
    }
}

const EVENT_LIMIT: usize = 4 * 1024 * 1024;

#[cfg(test)]
pub(super) fn event_chunks(
    request_id: u64,
    id: &StepFilesId,
    event: &[u8],
) -> Result<Vec<Request>, ExecutionDomainError> {
    if request_id == 0 || event.len() > EVENT_LIMIT {
        return Err(failure(FailureCategory::Protocol));
    }
    let chunks: Vec<_> = if event.is_empty() {
        vec![&[][..]]
    } else {
        event.chunks(OUTPUT_CHUNK_BYTES).collect()
    };
    Ok(chunks
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| Request::PrepareStepChunk {
            request_id,
            id: id.clone(),
            total_bytes: event.len() as u32,
            chunk_index: index as u32,
            bytes: bytes.to_vec(),
        })
        .collect())
}

pub(super) struct EventAssembler {
    request_id: u64,
    id: StepFilesId,
    index: u32,
    total: Option<u32>,
    bytes: Vec<u8>,
    finished: bool,
}

impl EventAssembler {
    pub(super) fn new(request_id: u64, id: StepFilesId) -> Self {
        Self {
            request_id,
            id,
            index: 0,
            total: None,
            bytes: Vec::new(),
            finished: false,
        }
    }

    pub(super) fn push(
        &mut self,
        request: Request,
    ) -> Result<Option<Vec<u8>>, ExecutionDomainError> {
        let result = self.push_inner(request);
        if result.is_err() {
            self.finished = true;
        }
        result
    }

    fn push_inner(&mut self, request: Request) -> Result<Option<Vec<u8>>, ExecutionDomainError> {
        let Request::PrepareStepChunk {
            request_id,
            id,
            total_bytes,
            chunk_index,
            bytes,
        } = request
        else {
            return Err(failure(FailureCategory::Protocol));
        };
        if self.finished
            || request_id == 0
            || request_id != self.request_id
            || id != self.id
            || chunk_index != self.index
            || total_bytes as usize > EVENT_LIMIT
            || self.total.is_some_and(|total| total != total_bytes)
            || bytes.len() > OUTPUT_CHUNK_BYTES
            || self.bytes.len() + bytes.len() > total_bytes as usize
            || bytes.is_empty() && total_bytes != 0
        {
            return Err(failure(FailureCategory::Protocol));
        }
        self.total = Some(total_bytes);
        self.bytes.extend(bytes);
        self.index += 1;
        if self.bytes.len() != total_bytes as usize {
            return Ok(None);
        }
        self.finished = true;
        Ok(Some(std::mem::take(&mut self.bytes)))
    }
}

pub(super) fn snapshot_chunks(
    request_id: u64,
    id: &StepFilesId,
    snapshot: &StepStateSnapshot,
) -> Result<Vec<Response>, ExecutionDomainError> {
    let fields = [
        (SnapshotField::Env, &snapshot.env),
        (SnapshotField::Path, &snapshot.path),
        (SnapshotField::Output, &snapshot.output),
        (SnapshotField::State, &snapshot.state),
        (SnapshotField::Summary, &snapshot.summary),
    ];
    if request_id == 0
        || fields
            .iter()
            .any(|(_, value)| value.len() > MAX_FRAME_BYTES as usize)
    {
        return Err(failure(FailureCategory::Protocol));
    }
    let mut result = Vec::new();
    for (field, value) in fields {
        if value.is_empty() {
            result.push(Response::SnapshotChunk {
                request_id,
                id: id.clone(),
                field,
                total_bytes: 0,
                chunk_index: 0,
                bytes: vec![],
            });
        } else {
            for (index, bytes) in value.as_bytes().chunks(OUTPUT_CHUNK_BYTES).enumerate() {
                result.push(Response::SnapshotChunk {
                    request_id,
                    id: id.clone(),
                    field,
                    total_bytes: value.len() as u32,
                    chunk_index: index as u32,
                    bytes: bytes.to_vec(),
                });
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
pub(super) struct SnapshotAssembler {
    request_id: u64,
    id: StepFilesId,
    field: usize,
    index: u32,
    total: Option<u32>,
    partial: Vec<u8>,
    values: Vec<String>,
    failed: bool,
}

#[cfg(test)]
impl SnapshotAssembler {
    pub(super) fn new(request_id: u64, id: StepFilesId) -> Self {
        Self {
            request_id,
            id,
            field: 0,
            index: 0,
            total: None,
            partial: Vec::new(),
            values: Vec::new(),
            failed: false,
        }
    }
    pub(super) fn push(
        &mut self,
        response: Response,
    ) -> Result<Option<StepStateSnapshot>, ExecutionDomainError> {
        if self.failed {
            return Err(failure(FailureCategory::Protocol));
        }
        let result = self.push_inner(response);
        self.failed |= result.is_err();
        result
    }
    fn push_inner(
        &mut self,
        response: Response,
    ) -> Result<Option<StepStateSnapshot>, ExecutionDomainError> {
        let Response::SnapshotChunk {
            request_id,
            id,
            field,
            total_bytes,
            chunk_index,
            bytes,
        } = response
        else {
            return Err(failure(FailureCategory::Protocol));
        };
        let fields = [
            SnapshotField::Env,
            SnapshotField::Path,
            SnapshotField::Output,
            SnapshotField::State,
            SnapshotField::Summary,
        ];
        if self.field >= 5
            || fields[self.field] != field
            || request_id != self.request_id
            || request_id == 0
            || id != self.id
            || chunk_index != self.index
            || total_bytes > MAX_FRAME_BYTES
            || self.total.is_some_and(|total| total != total_bytes)
            || bytes.len() > OUTPUT_CHUNK_BYTES
            || self.partial.len() + bytes.len() > total_bytes as usize
            || bytes.is_empty() && total_bytes != 0
        {
            return Err(failure(FailureCategory::Protocol));
        }
        self.total = Some(total_bytes);
        self.partial.extend(bytes);
        self.index += 1;
        if self.partial.len() != total_bytes as usize {
            return Ok(None);
        }
        let value = String::from_utf8(std::mem::take(&mut self.partial))
            .map_err(|_| failure(FailureCategory::Protocol))?;
        self.values.push(value);
        self.field += 1;
        self.index = 0;
        self.total = None;
        if self.field != 5 {
            return Ok(None);
        }
        let mut values = std::mem::take(&mut self.values).into_iter();
        let mut next = || {
            values
                .next()
                .ok_or_else(|| failure(FailureCategory::Protocol))
        };
        Ok(Some(StepStateSnapshot {
            env: next()?,
            path: next()?,
            output: next()?,
            state: next()?,
            summary: next()?,
        }))
    }
}

pub(super) struct OutboundQueue {
    control: std::collections::VecDeque<Message>,
    data: std::collections::VecDeque<Message>,
}

impl OutboundQueue {
    pub(super) fn new() -> Self {
        Self {
            control: Default::default(),
            data: Default::default(),
        }
    }
    pub(super) fn push(&mut self, message: Message) -> Result<(), ExecutionDomainError> {
        validate_message(&message)?;
        let priority = matches!(
            message,
            Message::Request(Request::CancelCommand { .. } | Request::Shutdown { .. })
        );
        // Validate the serialized cap before taking ownership of payload memory.
        let mut bounded = BoundedWriter(Vec::new());
        serde_json::to_writer(&mut bounded, &message)
            .map_err(|_| failure(FailureCategory::Protocol))?;
        let queue = if priority {
            &mut self.control
        } else {
            &mut self.data
        };
        if queue.len() >= 32 {
            return Err(failure(FailureCategory::Unavailable));
        }
        queue.push_back(message);
        Ok(())
    }
    pub(super) fn pop(&mut self) -> Option<Message> {
        self.control.pop_front().or_else(|| self.data.pop_front())
    }
    #[cfg(target_os = "linux")]
    pub(super) fn has_capacity(&self) -> bool {
        self.data.len() < 30
    }
}

pub(super) fn failure(category: FailureCategory) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::Protocol,
        category,
        errno: None,
    }
}
fn io_failure(error: io::Error) -> ExecutionDomainError {
    ExecutionDomainError::Backend {
        attempt: None,
        stage: Stage::Protocol,
        category: FailureCategory::Io,
        errno: error.raw_os_error(),
    }
}

#[derive(Deserialize, Serialize)]
#[serde(remote = "CancelReason")]
enum ReasonWire {
    User,
    Timeout,
    Shutdown,
    HandleDropped,
    ProtocolFailure,
}
#[derive(Deserialize, Serialize)]
#[serde(remote = "CommandOutcome")]
enum OutcomeWire {
    Exited(i32),
    Signalled(i32),
    Cancelled,
    TimedOut,
}
#[derive(Deserialize, Serialize)]
#[serde(remote = "CommandEvent")]
enum EventWire {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
}

mod command_wire {
    use super::*;
    use serde::{Deserializer, Serializer, de::Error as _, ser::Error as _};
    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        program: DomainPath,
        args: Vec<String>,
        cwd: DomainPath,
        env: std::collections::HashMap<String, String>,
        timeout_ms: u64,
        state: Option<StepFilesId>,
    }
    pub(super) fn serialize<S: Serializer>(
        spec: &CommandSpec,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let CommandTarget::Sandboxed { program, args, cwd } = &spec.target else {
            return Err(S::Error::custom("invalid command target"));
        };
        let timeout_ms = u64::try_from(spec.timeout.as_millis())
            .map_err(|_| S::Error::custom("invalid timeout"))?;
        if timeout_ms == 0 || !spec.timeout.subsec_nanos().is_multiple_of(1_000_000) {
            return Err(S::Error::custom("invalid timeout"));
        }
        Wire {
            program: program.clone(),
            args: args.clone(),
            cwd: cwd.clone(),
            env: spec.env.clone(),
            timeout_ms,
            state: spec.state.clone(),
        }
        .serialize(serializer)
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<CommandSpec, D::Error> {
        let wire = Wire::deserialize(deserializer)?;
        if wire.timeout_ms == 0 {
            return Err(D::Error::custom("invalid timeout"));
        }
        Ok(CommandSpec {
            target: CommandTarget::Sandboxed {
                program: wire.program,
                args: wire.args,
                cwd: wire.cwd,
            },
            env: wire.env,
            timeout: Duration::from_millis(wire.timeout_ms),
            state: wire.state,
        })
    }
}
