//! SCP (rcp) transfer protocol state machine over an injected stream seam.
//!
//! This module implements the classic `rcp`/SCP wire protocol as used by
//! OpenSSH's `scp` in *legacy* (non-SFTP) mode. The SSH channel that carries
//! the protocol is abstracted behind the [`ScpStream`] seam so the state
//! machines can be exercised without a real SSH connection; the in-memory
//! [`MemStream`] host double stands in for the channel in tests and lets a
//! sink parse exactly the bytes a source produced.
//!
//! ## Wire format
//!
//! The protocol is a sequence of newline-terminated **control messages** sent
//! by the *source* (sender), each acknowledged by the *sink* (receiver):
//!
//! | Message | Meaning |
//! |---------|---------|
//! | `C<mode> <length> <name>\n` | File header; `length` bytes of content follow |
//! | `D<mode> <length> <name>\n` | Enter directory (`length` is `0`) |
//! | `E\n` | Leave the current directory |
//! | `T<mtime> 0 <atime> 0\n` | Optional modification/access times for the next node |
//!
//! After a `C` header the source writes the raw file bytes followed by a single
//! `\0` status byte. Every control message and the file trailer is answered by
//! the receiver with a one-byte **response**:
//!
//! | Byte | Meaning |
//! |------|---------|
//! | `\0` (`0x00`) | ok / ack |
//! | `\x01` (`0x01`) | warning, followed by a message line |
//! | `\x02` (`0x02`) | fatal, followed by a message line |
//!
//! The exchange opens with the sink sending a single `\0` to signal it is ready.
//!
//! ## Fail-closed posture
//!
//! Every deviation is rejected rather than tolerated: malformed headers, a
//! length that does not parse, a stream that ends before the declared byte
//! count, an out-of-range response byte, or any non-`\0` response where an ack
//! is required all abort the transfer with an [`ScpProtoError`].

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::Write as _;

// =============================================================================
// Stream seam
// =============================================================================

/// The byte-stream transport seam for the SCP protocol.
///
/// A real implementation writes to / reads from an SSH channel; the
/// [`MemStream`] host double backs it with in-memory buffers. Reads are
/// **exact**: [`read_exact`](ScpStream::read_exact) must fill the whole buffer
/// or fail, which is what makes the protocol fail closed on a short stream.
pub trait ScpStream {
    /// Write every byte of `buf` to the stream.
    ///
    /// # Errors
    ///
    /// Returns [`ScpProtoError::StreamClosed`] if the underlying channel can no
    /// longer accept bytes.
    fn write_all(&mut self, buf: &[u8]) -> Result<(), ScpProtoError>;

    /// Read exactly `buf.len()` bytes into `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`ScpProtoError::StreamClosed`] if the stream ends before `buf`
    /// is full.
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ScpProtoError>;
}

// =============================================================================
// MemStream host double
// =============================================================================

/// An in-memory host double for [`ScpStream`].
///
/// Reads are served from a fixed `inbound` script; writes are appended to
/// `outbound` where they can be inspected. A source can be run against a stream
/// pre-loaded with ack bytes ([`with_ok_acks`](MemStream::with_ok_acks)), and
/// the captured [`outbound`](MemStream::outbound) transcript can then be fed to
/// a sink as *its* `inbound` — a genuine sink↔source round trip in one thread.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemStream {
    inbound: Vec<u8>,
    pos: usize,
    outbound: Vec<u8>,
}

impl MemStream {
    /// A stream whose reads are served from `inbound`.
    #[must_use]
    pub fn new(inbound: Vec<u8>) -> Self {
        Self {
            inbound,
            pos: 0,
            outbound: Vec::new(),
        }
    }

    /// A stream pre-loaded with `n` `\0` (ok) response bytes.
    ///
    /// Used to drive a source through a happy-path exchange without a live sink.
    #[must_use]
    pub fn with_ok_acks(n: usize) -> Self {
        Self::new(alloc::vec![0u8; n])
    }

    /// The bytes written to the stream so far.
    #[must_use]
    pub fn outbound(&self) -> &[u8] {
        &self.outbound
    }

    /// Consume the stream, returning the captured outbound transcript.
    #[must_use]
    pub fn into_outbound(self) -> Vec<u8> {
        self.outbound
    }
}

impl ScpStream for MemStream {
    fn write_all(&mut self, buf: &[u8]) -> Result<(), ScpProtoError> {
        self.outbound.extend_from_slice(buf);
        Ok(())
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ScpProtoError> {
        let end = self
            .pos
            .checked_add(buf.len())
            .ok_or(ScpProtoError::StreamClosed)?;
        let slice = self
            .inbound
            .get(self.pos..end)
            .ok_or(ScpProtoError::StreamClosed)?;
        buf.copy_from_slice(slice);
        self.pos = end;
        Ok(())
    }
}

// =============================================================================
// Data model
// =============================================================================

/// Modification and access times carried by an optional `T` message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScpTimes {
    /// Modification time, seconds since the Unix epoch.
    pub mtime: u64,
    /// Access time, seconds since the Unix epoch.
    pub atime: u64,
}

/// A single regular file transferred over the protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScpFile {
    /// File name (no path separators in the classic protocol).
    pub name: String,
    /// Unix permission bits (e.g. `0o644`).
    pub mode: u16,
    /// Raw file contents.
    pub contents: Vec<u8>,
    /// Optional times, emitted as a leading `T` message when present.
    pub times: Option<ScpTimes>,
}

/// A directory subtree transferred recursively (`scp -r`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScpDir {
    /// Directory name.
    pub name: String,
    /// Unix permission bits (e.g. `0o755`).
    pub mode: u16,
    /// Directory entries, in transfer order.
    pub entries: Vec<ScpNode>,
    /// Optional times, emitted as a leading `T` message when present.
    pub times: Option<ScpTimes>,
}

/// A node in a transfer: either a file or a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScpNode {
    /// A regular file.
    File(ScpFile),
    /// A directory and its subtree.
    Dir(ScpDir),
}

// =============================================================================
// Errors
// =============================================================================

/// Errors raised by the source and sink state machines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScpProtoError {
    /// The stream ended before the required bytes could be read or written.
    StreamClosed,
    /// A control message (`C`/`D`/`T`/`E`) was structurally invalid.
    MalformedHeader,
    /// A declared length could not be parsed or did not match the stream.
    BadLength,
    /// A response byte was neither `\0`, `\x01`, nor `\x02`.
    UnexpectedAck,
    /// The peer returned a warning (`\x01`) with this message.
    RemoteWarning(String),
    /// The peer returned a fatal error (`\x02`) with this message.
    RemoteFatal(String),
}

// =============================================================================
// Public entry points
// =============================================================================

/// Drive the **source** (sender) state machine, transmitting `node`.
///
/// Waits for the sink's opening ready ack, then emits the node — recursively
/// for a directory — acknowledging each control message.
///
/// # Errors
///
/// Any [`ScpProtoError`] from the stream or a non-ok response from the sink.
pub fn source_send<S: ScpStream>(stream: &mut S, node: &ScpNode) -> Result<(), ScpProtoError> {
    // The sink opens the exchange by signalling it is ready.
    expect_ok(read_response(stream)?)?;
    emit_node(stream, node)
}

/// Emit one node (recursively, for directories), acknowledging each step.
fn emit_node<S: ScpStream>(stream: &mut S, node: &ScpNode) -> Result<(), ScpProtoError> {
    match node {
        ScpNode::File(f) => emit_file(stream, f),
        ScpNode::Dir(d) => emit_dir(stream, d),
    }
}

/// Emit an optional `T` times message, if the node carries one.
fn emit_times<S: ScpStream>(stream: &mut S, times: Option<&ScpTimes>) -> Result<(), ScpProtoError> {
    if let Some(t) = times {
        let mut header = String::new();
        writeln!(header, "T{} 0 {} 0", t.mtime, t.atime)
            .map_err(|_| ScpProtoError::MalformedHeader)?;
        stream.write_all(header.as_bytes())?;
        expect_ok(read_response(stream)?)?;
    }
    Ok(())
}

/// Emit a `C` file header, the raw bytes, the `\0` status trailer, and ack each.
fn emit_file<S: ScpStream>(stream: &mut S, f: &ScpFile) -> Result<(), ScpProtoError> {
    emit_times(stream, f.times.as_ref())?;

    let mut header = String::new();
    writeln!(header, "C{:04o} {} {}", f.mode, f.contents.len(), f.name)
        .map_err(|_| ScpProtoError::MalformedHeader)?;
    stream.write_all(header.as_bytes())?;
    expect_ok(read_response(stream)?)?;

    stream.write_all(&f.contents)?;
    // Single `\0` status byte marking a successful file body.
    stream.write_all(&[0])?;
    expect_ok(read_response(stream)?)?;
    Ok(())
}

/// Emit a `D` header, every entry recursively, and the closing `E`.
fn emit_dir<S: ScpStream>(stream: &mut S, d: &ScpDir) -> Result<(), ScpProtoError> {
    emit_times(stream, d.times.as_ref())?;

    let mut header = String::new();
    // The length field is unused for directories and is always `0`.
    writeln!(header, "D{:04o} 0 {}", d.mode, d.name).map_err(|_| ScpProtoError::MalformedHeader)?;
    stream.write_all(header.as_bytes())?;
    expect_ok(read_response(stream)?)?;

    for entry in &d.entries {
        emit_node(stream, entry)?;
    }

    stream.write_all(b"E\n")?;
    expect_ok(read_response(stream)?)?;
    Ok(())
}

/// Drive the **sink** (receiver) state machine, reconstructing one node.
///
/// Sends the opening ready ack, reads one control message and, for a directory,
/// recurses until the matching `E`. Acknowledges each step with `\0`.
///
/// # Errors
///
/// Any [`ScpProtoError`] from the stream or a malformed / short transfer.
pub fn sink_receive<S: ScpStream>(stream: &mut S) -> Result<ScpNode, ScpProtoError> {
    // Signal readiness, then read and reconstruct exactly one node.
    stream.write_all(&[0])?;
    let line = read_line(stream)?;
    recv_node(stream, line)
}

/// Reconstruct a node whose (already read) control line is `line`.
fn recv_node<S: ScpStream>(stream: &mut S, line: String) -> Result<ScpNode, ScpProtoError> {
    // An optional leading `T` message decorates the node that follows.
    let (times, line) = if line.starts_with('T') {
        let times = parse_times(&line)?;
        stream.write_all(&[0])?;
        (Some(times), read_line(stream)?)
    } else {
        (None, line)
    };

    match line.as_bytes().first() {
        Some(b'C') => {
            let (mode, len, name) = parse_file_header(&line)?;
            stream.write_all(&[0])?;

            let mut contents = alloc::vec![0u8; len];
            stream.read_exact(&mut contents)?;

            // Consume the sender's `\0` status trailer; anything else is invalid.
            let mut status = [0u8; 1];
            stream.read_exact(&mut status)?;
            if status[0] != 0 {
                return Err(ScpProtoError::MalformedHeader);
            }
            stream.write_all(&[0])?;

            Ok(ScpNode::File(ScpFile {
                name,
                mode,
                contents,
                times,
            }))
        }
        Some(b'D') => {
            let (mode, name) = parse_dir_header(&line)?;
            stream.write_all(&[0])?;

            let mut entries = Vec::new();
            loop {
                let entry_line = read_line(stream)?;
                if entry_line.starts_with('E') {
                    stream.write_all(&[0])?;
                    break;
                }
                entries.push(recv_node(stream, entry_line)?);
            }

            Ok(ScpNode::Dir(ScpDir {
                name,
                mode,
                entries,
                times,
            }))
        }
        _ => Err(ScpProtoError::MalformedHeader),
    }
}

// =============================================================================
// Wire helpers
// =============================================================================

/// A parsed one-byte response.
enum Response {
    /// `\0` — ok / ack.
    Ok,
    /// `\x01` — recoverable warning with message.
    Warning(String),
    /// `\x02` — fatal error with message.
    Fatal(String),
}

/// Read and classify a single response byte (and its message line, if any).
fn read_response<S: ScpStream>(stream: &mut S) -> Result<Response, ScpProtoError> {
    let mut byte = [0u8; 1];
    stream.read_exact(&mut byte)?;
    match byte[0] {
        0 => Ok(Response::Ok),
        1 => Ok(Response::Warning(read_line(stream)?)),
        2 => Ok(Response::Fatal(read_line(stream)?)),
        _ => Err(ScpProtoError::UnexpectedAck),
    }
}

/// Require an ok response, mapping warning / fatal to the matching error.
///
/// Fail-closed: any non-ok response aborts the transfer.
fn expect_ok(response: Response) -> Result<(), ScpProtoError> {
    match response {
        Response::Ok => Ok(()),
        Response::Warning(m) => Err(ScpProtoError::RemoteWarning(m)),
        Response::Fatal(m) => Err(ScpProtoError::RemoteFatal(m)),
    }
}

/// Read bytes up to and including the next `\n`, returning the line without it.
fn read_line<S: ScpStream>(stream: &mut S) -> Result<String, ScpProtoError> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            break;
        }
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes).map_err(|_| ScpProtoError::MalformedHeader)
}

/// Parse a `C<mode> <length> <name>` header into `(mode, length, name)`.
fn parse_file_header(line: &str) -> Result<(u16, usize, String), ScpProtoError> {
    // Strip the leading `C`.
    let rest = line.get(1..).ok_or(ScpProtoError::MalformedHeader)?;
    let (mode_str, rest) = rest.split_once(' ').ok_or(ScpProtoError::MalformedHeader)?;
    let (len_str, name) = rest.split_once(' ').ok_or(ScpProtoError::MalformedHeader)?;

    let mode = u16::from_str_radix(mode_str, 8).map_err(|_| ScpProtoError::MalformedHeader)?;
    let len = len_str
        .parse::<usize>()
        .map_err(|_| ScpProtoError::BadLength)?;
    if name.is_empty() {
        return Err(ScpProtoError::MalformedHeader);
    }
    Ok((mode, len, name.to_string()))
}

/// Parse a `D<mode> <length> <name>` header into `(mode, name)`.
///
/// The length field is present in the wire format but unused for directories.
fn parse_dir_header(line: &str) -> Result<(u16, String), ScpProtoError> {
    let rest = line.get(1..).ok_or(ScpProtoError::MalformedHeader)?;
    let (mode_str, rest) = rest.split_once(' ').ok_or(ScpProtoError::MalformedHeader)?;
    let (_len_str, name) = rest.split_once(' ').ok_or(ScpProtoError::MalformedHeader)?;

    let mode = u16::from_str_radix(mode_str, 8).map_err(|_| ScpProtoError::MalformedHeader)?;
    if name.is_empty() {
        return Err(ScpProtoError::MalformedHeader);
    }
    Ok((mode, name.to_string()))
}

/// Parse a `T<mtime> 0 <atime> 0` header into [`ScpTimes`].
fn parse_times(line: &str) -> Result<ScpTimes, ScpProtoError> {
    let rest = line.get(1..).ok_or(ScpProtoError::MalformedHeader)?;
    let mut fields = rest.split(' ');
    let mtime = fields
        .next()
        .ok_or(ScpProtoError::MalformedHeader)?
        .parse::<u64>()
        .map_err(|_| ScpProtoError::BadLength)?;
    // Field after mtime is a reserved `0`.
    fields.next().ok_or(ScpProtoError::MalformedHeader)?;
    let atime = fields
        .next()
        .ok_or(ScpProtoError::MalformedHeader)?
        .parse::<u64>()
        .map_err(|_| ScpProtoError::BadLength)?;
    // Trailing reserved `0`.
    fields.next().ok_or(ScpProtoError::MalformedHeader)?;

    Ok(ScpTimes { mtime, atime })
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str, mode: u16, contents: &[u8]) -> ScpNode {
        ScpNode::File(ScpFile {
            name: name.to_string(),
            mode,
            contents: contents.to_vec(),
            times: None,
        })
    }

    /// Run a full sink↔source round trip over the memory double.
    fn round_trip(node: &ScpNode) -> (ScpNode, Vec<u8>) {
        let mut src = MemStream::with_ok_acks(64);
        source_send(&mut src, node).expect("source_send");
        let transcript = src.into_outbound();

        let mut sink = MemStream::new(transcript);
        let received = sink_receive(&mut sink).expect("sink_receive");
        (received, sink.into_outbound())
    }

    #[test]
    fn round_trip_single_file_preserves_bytes_and_mode() {
        let node = file("hello.txt", 0o644, b"Hello, SCP!\n");
        let (received, sink_out) = round_trip(&node);
        assert_eq!(received, node);
        // Every response the sink emitted is an ok ack.
        assert!(sink_out.iter().all(|&b| b == 0));
    }

    #[test]
    fn round_trip_empty_file() {
        let node = file("empty", 0o600, b"");
        let (received, _) = round_trip(&node);
        assert_eq!(received, node);
    }

    #[test]
    fn round_trip_file_with_times() {
        let node = ScpNode::File(ScpFile {
            name: "stamped".to_string(),
            mode: 0o640,
            contents: b"data".to_vec(),
            times: Some(ScpTimes {
                mtime: 1_700_000_000,
                atime: 1_700_000_500,
            }),
        });
        let (received, _) = round_trip(&node);
        assert_eq!(received, node);
    }

    #[test]
    fn round_trip_directory_tree() {
        let node = ScpNode::Dir(ScpDir {
            name: "project".to_string(),
            mode: 0o755,
            times: None,
            entries: alloc::vec![
                file("readme.md", 0o644, b"# hi\n"),
                ScpNode::Dir(ScpDir {
                    name: "src".to_string(),
                    mode: 0o750,
                    times: None,
                    entries: alloc::vec![file("main.rs", 0o644, b"fn main() {}\n")],
                }),
                file("LICENSE", 0o644, b"MIT"),
            ],
        });
        let (received, sink_out) = round_trip(&node);
        assert_eq!(received, node);
        assert!(sink_out.iter().all(|&b| b == 0));
    }

    #[test]
    fn source_aborts_on_fatal_ack() {
        // Fatal response at the opening ready handshake.
        let mut stream = MemStream::new(alloc::vec![
            0x02, b'n', b'o', b' ', b'r', b'o', b'o', b'm', b'\n'
        ]);
        let err = source_send(&mut stream, &file("x", 0o644, b"y")).unwrap_err();
        assert_eq!(err, ScpProtoError::RemoteFatal("no room".to_string()));
    }

    #[test]
    fn source_aborts_on_warning_ack() {
        let mut stream = MemStream::new(alloc::vec![0x01, b'h', b'm', b'm', b'\n']);
        let err = source_send(&mut stream, &file("x", 0o644, b"y")).unwrap_err();
        assert_eq!(err, ScpProtoError::RemoteWarning("hmm".to_string()));
    }

    #[test]
    fn source_rejects_unexpected_ack_byte() {
        let mut stream = MemStream::new(alloc::vec![0x05]);
        let err = source_send(&mut stream, &file("x", 0o644, b"y")).unwrap_err();
        assert_eq!(err, ScpProtoError::UnexpectedAck);
    }

    #[test]
    fn sink_rejects_malformed_c_header() {
        // Wrong leading type byte.
        let mut stream = MemStream::new(b"Zgarbage 1 a\n".to_vec());
        assert_eq!(
            sink_receive(&mut stream),
            Err(ScpProtoError::MalformedHeader)
        );

        // Non-octal mode.
        let mut stream = MemStream::new(b"Cxyz 1 a\nq\0".to_vec());
        assert_eq!(
            sink_receive(&mut stream),
            Err(ScpProtoError::MalformedHeader)
        );

        // Missing fields.
        let mut stream = MemStream::new(b"C0644\n".to_vec());
        assert_eq!(
            sink_receive(&mut stream),
            Err(ScpProtoError::MalformedHeader)
        );
    }

    #[test]
    fn sink_rejects_non_numeric_length() {
        let mut stream = MemStream::new(b"C0644 xx a.txt\n".to_vec());
        assert_eq!(sink_receive(&mut stream), Err(ScpProtoError::BadLength));
    }

    #[test]
    fn sink_fails_closed_on_length_mismatch() {
        // Header declares 100 bytes but only 2 are present.
        let mut stream = MemStream::new(b"C0644 100 a.txt\nhi".to_vec());
        assert_eq!(sink_receive(&mut stream), Err(ScpProtoError::StreamClosed));
    }
}
