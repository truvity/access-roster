//! The `spool` audit transport (ADR 0028 "Transport"; ADR 0029 "Sealing"): a local, bounded,
//! fsync'd queue between the emitters and the writer.
//!
//! - **Layout.** The directory holds segments `<first seq, 20 digits>.seg`, each a run of frames,
//!   and for a segment with acknowledgements a file `<same>.ack` of frames that each hold one
//!   acknowledged sequence number. A frame is `len u32 BE | sum [u8; 16] | payload`; the sum is the
//!   first 16 bytes of SHA-384 of the payload. A segment frame holds `seq u64 BE | emitter len u16
//!   BE | emitter | AuditMessage`. The sequence number is the delivery id.
//! - **Durable.** [`Spool::append`] writes one frame and `fdatasync`s the segment before it
//!   returns; a segment is `fsync`ed in its directory when it is created or removed. Blocking and
//!   non-blocking emits take the same path: the spool has no cheaper way to accept a message.
//! - **Ordered, at least once.** [`Spool::read_from`] returns the unacknowledged messages in
//!   sequence order. [`Spool::ack`] records acknowledgements durably, and a segment whose messages
//!   are all acknowledged is removed. After a restart the unacknowledged messages come again.
//! - **Bounded.** The files of the directory never exceed [`Config::limit`]. A message that does
//!   not fit is refused with [`Error::Full`]; the spool never drops a fact (0029).
//! - **Torn tail.** A crash can leave half a frame at the end of the newest segment (or of an
//!   `.ack` file). On start the tail is cut at the last frame whose length and sum hold. A bad
//!   frame anywhere else is not a torn write: the start is refused.

pub mod service;
pub mod suite;

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use anyhow::{Context, ensure};
use aws_lc_rs::digest;
use rustix::fs::{FlockOperation, Mode, OFlags};
use tokio::sync::watch;

/// The most bytes of one encoded `AuditMessage`.
pub const MAX_MESSAGE: usize = 1 << 20;
/// The most bytes of an emitter name (`<actor>@<boundary>`).
pub const MAX_EMITTER: usize = 255;
/// The default bound of the directory: boards have small disks, and 0029 says to keep it drained.
pub const DEFAULT_LIMIT: u64 = 256 << 20;
/// The default size at which the newest segment is closed and the next one started.
pub const DEFAULT_SEGMENT: u64 = 8 << 20;

const SUM: usize = 16;
const HEADER: usize = 4 + SUM;
const MAX_PAYLOAD: usize = 8 + 2 + MAX_EMITTER + MAX_MESSAGE;
const FILE_MODE: u32 = 0o600;
const DIR_MODE: u32 = 0o700;

/// Sizes of one spool.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// The most bytes the directory may hold (segments and acknowledgements).
    pub limit: u64,
    /// The size at which a segment is closed.
    pub segment: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            limit: DEFAULT_LIMIT,
            segment: DEFAULT_SEGMENT,
        }
    }
}

/// Why an operation was refused. [`service`] turns each into a Connect code and reason.
#[derive(Debug)]
pub enum Error {
    /// The message does not fit in the bound. It is refused, never dropped.
    Full,
    /// The message or the emitter name is longer than the contract allows.
    Bound,
    /// A frame read back does not hold its sum.
    Corrupt,
    /// An earlier I/O failure left the files in a state the spool cannot vouch for. Every call
    /// is refused until the process restarts and recovers the directory.
    Poisoned,
    /// The filesystem failed.
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => f.write_str("full"),
            Self::Bound => f.write_str("bound"),
            Self::Corrupt => f.write_str("corrupt"),
            Self::Poisoned => f.write_str("poisoned"),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<rustix::io::Errno> for Error {
    fn from(e: rustix::io::Errno) -> Self {
        Self::Io(e.into())
    }
}

type Result<T> = std::result::Result<T, Error>;

/// One message as the spool holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The delivery id.
    pub seq: u64,
    /// `<actor>@<boundary>`, from the peer uid.
    pub emitter: String,
    /// The encoded `AuditMessage`.
    pub message: Vec<u8>,
}

/// How many times the spool asked the disk to make something durable. A test reads it.
#[derive(Debug, Default)]
pub struct Syncs {
    /// `fdatasync` of a segment or an acknowledgement file.
    pub file: AtomicU64,
    /// `fsync` of the directory.
    pub dir: AtomicU64,
}

/// The places a test can make the disk fail. Compiled in tests only.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Point {
    Write,
    SetLen,
    SyncData,
    SyncDir,
}

#[cfg(test)]
#[derive(Default)]
struct Faults(Vec<Point>);

/// Fails once at `point` when a test armed it.
#[cfg(test)]
fn fault_at(faults: &mut Faults, point: Point) -> std::io::Result<()> {
    match faults.0.iter().position(|p| *p == point) {
        Some(i) => {
            faults.0.remove(i);
            Err(std::io::Error::other("injected fault"))
        }
        None => Ok(()),
    }
}

/// `fault!(self, Write)`: an I/O error when a test armed that point, and nothing at all in a
/// product build. Takes the field, so it can be used while another field is borrowed.
macro_rules! fault {
    ($inner:ident, $point:ident) => {{
        #[cfg(test)]
        let r = fault_at(&mut $inner.faults, Point::$point);
        #[cfg(not(test))]
        let r = Ok::<(), std::io::Error>(());
        r
    }};
}

struct Segment {
    bytes: u64,
    unacked: usize,
    ack_bytes: u64,
}

struct Loc {
    segment: u64,
    /// Offset of the payload; the header is `HEADER` bytes before it.
    offset: u64,
    len: usize,
}

struct Inner {
    /// Holds the exclusive lock of the directory for as long as the spool lives.
    dir: OwnedFd,
    root: PathBuf,
    cfg: Config,
    segments: BTreeMap<u64, Segment>,
    /// The newest segment, open for append.
    active: Option<(u64, File)>,
    /// The unacknowledged messages by sequence number.
    pending: BTreeMap<u64, Loc>,
    next_seq: u64,
    total: u64,
    /// Set by an I/O failure that leaves the files uncertain; see [`Error::Poisoned`].
    poisoned: bool,
    #[cfg(test)]
    faults: Faults,
}

struct Shared {
    inner: Mutex<Inner>,
    tail: watch::Sender<u64>,
    closed: watch::Sender<bool>,
    receiver: AtomicBool,
    syncs: Syncs,
}

/// An open spool. Cheap to clone; clones share the directory and its lock.
#[derive(Clone)]
pub struct Spool(Arc<Shared>);

/// The right to be the one consumer; dropping it frees the slot.
pub struct ReceiverSlot(Arc<Shared>);

impl Drop for ReceiverSlot {
    fn drop(&mut self) {
        self.0.receiver.store(false, Ordering::SeqCst);
    }
}

fn seg_name(first: u64) -> String {
    format!("{first:020}.seg")
}

fn ack_name(first: u64) -> String {
    format!("{first:020}.ack")
}

/// The first sequence number in a file name of the form `<20 digits><suffix>`.
fn parse_name(name: &str, suffix: &str) -> Option<u64> {
    let digits = name.strip_suffix(suffix)?;
    (digits.len() == 20 && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| digits.parse().ok())
        .flatten()
}

fn sum(payload: &[u8]) -> [u8; SUM] {
    let d = digest::digest(&digest::SHA384, payload);
    let mut s = [0u8; SUM];
    s.copy_from_slice(d.as_ref().get(..SUM).unwrap_or(&[0; SUM]));
    s
}

fn frame(payload: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(payload.len()).map_err(|_| Error::Bound)?;
    let mut f = Vec::with_capacity(HEADER + payload.len());
    f.extend_from_slice(&len.to_be_bytes());
    f.extend_from_slice(&sum(payload));
    f.extend_from_slice(payload);
    Ok(f)
}

/// The end of the frame at `pos` when it holds its length and sum.
fn frame_end(buf: &[u8], pos: usize) -> Option<usize> {
    let head = buf.get(pos..pos + HEADER)?;
    let (len, want) = head.split_at(4);
    let len = usize::try_from(u32::from_be_bytes(len.try_into().ok()?)).ok()?;
    let (start, end) = (pos + HEADER, pos.checked_add(HEADER)?.checked_add(len)?);
    let payload = (len <= MAX_PAYLOAD)
        .then(|| buf.get(start..end))
        .flatten()?;
    (sum(payload) == want).then_some(end)
}

/// The payload ranges of the frames of `buf` that hold their length and sum, and the offset where
/// the first frame that does not begins (the length of `buf` when all do).
fn frames(buf: &[u8]) -> (Vec<(usize, usize)>, usize) {
    let (mut out, mut pos) = (Vec::new(), 0usize);
    while let Some(end) = frame_end(buf, pos) {
        out.push((pos + HEADER, end));
        pos = end;
    }
    (out, pos)
}

/// Whether a frame that holds its length and sum begins anywhere after `bad`. `fdatasync` runs
/// after each frame, so only the last frame can be torn: a good frame after a bad one means the
/// bad one was damaged at rest, and cutting there would drop acknowledged facts.
fn good_frame_after(buf: &[u8], bad: usize) -> bool {
    (bad + 1..buf.len()).any(|p| frame_end(buf, p).is_some())
}

fn entry_payload(seq: u64, emitter: &str, message: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(10 + emitter.len() + message.len());
    p.extend_from_slice(&seq.to_be_bytes());
    // MAX_EMITTER fits in u16; append checked it.
    p.extend_from_slice(&u16::try_from(emitter.len()).unwrap_or(0).to_be_bytes());
    p.extend_from_slice(emitter.as_bytes());
    p.extend_from_slice(message);
    p
}

fn parse_entry(p: &[u8]) -> Option<Entry> {
    let seq = u64::from_be_bytes(p.get(..8)?.try_into().ok()?);
    let n = usize::from(u16::from_be_bytes(p.get(8..10)?.try_into().ok()?));
    let emitter = std::str::from_utf8(p.get(10..10 + n)?).ok()?.to_owned();
    Some(Entry {
        seq,
        emitter,
        message: p.get(10 + n..)?.to_vec(),
    })
}

/// Checks that `root` is a directory (not a symlink), owned by this process's uid and closed to
/// everybody else. The spool holds audit records in the clear until the writer seals them.
///
/// # Errors
///
/// Fails when the directory is missing or not so.
pub fn check_root(root: &Path) -> anyhow::Result<()> {
    let m = std::fs::symlink_metadata(root).context("the spool directory")?;
    ensure!(
        m.is_dir(),
        "the spool directory is not a directory (a symlink is refused)"
    );
    let me = rustix::process::geteuid().as_raw();
    ensure!(
        m.uid() == me,
        "the spool directory is owned by uid {}, not by this driver's uid {me}",
        m.uid()
    );
    ensure!(
        m.mode() & !(0o40000 | DIR_MODE) == 0,
        "the spool directory has mode {:o}, wider than {DIR_MODE:o}",
        m.mode() & 0o7777
    );
    Ok(())
}

impl Spool {
    /// Opens `root` and recovers it: cuts a torn tail, rebuilds the unacknowledged set and removes
    /// the segments that are fully acknowledged. Holds an exclusive lock on the directory, so a
    /// second spool on it is refused.
    ///
    /// # Errors
    ///
    /// Fails when the directory is not acceptable ([`check_root`]), is locked, or holds a file
    /// that is damaged somewhere other than its tail.
    pub fn open(root: &Path, cfg: Config) -> anyhow::Result<Self> {
        check_root(root)?;
        let dir = rustix::fs::open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .context("open the spool directory")?;
        rustix::fs::flock(&dir, FlockOperation::NonBlockingLockExclusive)
            .context("another spool holds this directory")?;
        let syncs = Syncs::default();
        let mut inner = Inner {
            dir,
            root: root.to_path_buf(),
            cfg,
            segments: BTreeMap::new(),
            active: None,
            pending: BTreeMap::new(),
            next_seq: 1,
            total: 0,
            poisoned: false,
            #[cfg(test)]
            faults: Faults::default(),
        };
        inner.recover(&syncs)?;
        let tail = inner.next_seq - 1;
        Ok(Self(Arc::new(Shared {
            inner: Mutex::new(inner),
            tail: watch::channel(tail).0,
            closed: watch::channel(false).0,
            receiver: AtomicBool::new(false),
            syncs,
        })))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.0.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The durability calls made so far.
    #[must_use]
    pub fn syncs(&self) -> &Syncs {
        &self.0.syncs
    }

    /// The number of messages waiting for an acknowledgement.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.lock().pending.len()
    }

    /// The bytes the directory holds.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.lock().total
    }

    /// Appends one message and returns its sequence number once it is on disk.
    ///
    /// # Errors
    ///
    /// [`Error::Bound`] for a message or emitter name over its limit, [`Error::Full`] when the
    /// bound would be passed, [`Error::Io`] when the disk fails. On a failure the message is not
    /// in the spool.
    pub fn append(&self, emitter: &str, message: &[u8]) -> Result<u64> {
        if emitter.len() > MAX_EMITTER || message.len() > MAX_MESSAGE {
            return Err(Error::Bound);
        }
        let mut inner = self.lock();
        let seq = inner.append(emitter, message, &self.0.syncs)?;
        drop(inner);
        // Never backwards: another append may already have published a later number.
        self.0.tail.send_modify(|t| *t = (*t).max(seq));
        Ok(seq)
    }

    /// The unacknowledged messages after `after`, in order, at most `max` of them and about
    /// `max_bytes` of message; at least one when there is one. Also returns the newest sequence
    /// number at the time of the read: a reader that found nothing waits for a newer one.
    ///
    /// # Errors
    ///
    /// [`Error::Corrupt`] when a frame no longer holds its sum, [`Error::Io`] on a read failure.
    pub fn read_from(&self, after: u64, max: usize, max_bytes: usize) -> Result<(Vec<Entry>, u64)> {
        let inner = self.lock();
        if inner.poisoned {
            return Err(Error::Poisoned);
        }
        let mut files: HashMap<u64, File> = HashMap::new();
        let (mut out, mut bytes) = (Vec::new(), 0usize);
        for (seq, loc) in inner.pending.range(after.saturating_add(1)..) {
            if out.len() >= max || (!out.is_empty() && bytes + loc.len > max_bytes) {
                break;
            }
            if let std::collections::hash_map::Entry::Vacant(v) = files.entry(loc.segment) {
                v.insert(File::open(inner.root.join(seg_name(loc.segment)))?);
            }
            let file = files.get(&loc.segment).ok_or(Error::Corrupt)?;
            let mut buf = vec![0u8; HEADER + loc.len];
            file.read_exact_at(&mut buf, loc.offset - HEADER as u64)?;
            let (head, payload) = buf.split_at(HEADER);
            if head.get(4..) != Some(&sum(payload)[..]) {
                return Err(Error::Corrupt);
            }
            let e = parse_entry(payload).filter(|e| e.seq == *seq);
            let e = e.ok_or(Error::Corrupt)?;
            bytes += e.message.len();
            out.push(e);
        }
        Ok((out, inner.next_seq - 1))
    }

    /// Records that the writer sealed these messages; unknown ids are ignored, so a repeat is
    /// harmless. The record is on disk before this returns.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the disk fails; the messages then stay unacknowledged.
    pub fn ack(&self, ids: &[u64]) -> Result<()> {
        self.lock().ack(ids, &self.0.syncs)
    }

    /// Takes the one consumer slot; `None` while another consumer holds it.
    #[must_use]
    pub fn take_receiver(&self) -> Option<ReceiverSlot> {
        self.0
            .receiver
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
            .then(|| ReceiverSlot(self.0.clone()))
    }

    /// A receiver that sees the newest sequence number.
    #[must_use]
    pub fn watch_tail(&self) -> watch::Receiver<u64> {
        self.0.tail.subscribe()
    }

    /// Ends the open consumer streams and lets the servers stop.
    pub fn close(&self) {
        self.0.closed.send_replace(true);
    }

    /// Resolves once [`close`](Self::close) was called.
    pub fn closed(&self) -> impl Future<Output = ()> + Send + use<> {
        let mut rx = self.0.closed.subscribe();
        async move {
            let _ = rx.wait_for(|c| *c).await;
        }
    }
}

fn count(c: &AtomicU64) {
    c.fetch_add(1, Ordering::SeqCst);
}

impl Inner {
    fn sync_dir(&mut self, syncs: &Syncs) -> Result<()> {
        fault!(self, SyncDir)?;
        rustix::fs::fsync(&self.dir)?;
        count(&syncs.dir);
        Ok(())
    }

    fn open_new(&self, name: &str) -> std::io::Result<File> {
        OpenOptions::new()
            .create_new(true)
            .append(true)
            .mode(FILE_MODE)
            .open(self.root.join(name))
    }

    fn recover(&mut self, syncs: &Syncs) -> anyhow::Result<()> {
        let (mut firsts, mut acks) = (Vec::new(), Vec::new());
        for e in std::fs::read_dir(&self.root)? {
            let e = e?;
            let name = e.file_name();
            let Some(name) = name.to_str() else { continue };
            let found = parse_name(name, ".seg")
                .map(|f| (&mut firsts, f))
                .or_else(|| parse_name(name, ".ack").map(|f| (&mut acks, f)));
            if let Some((list, first)) = found {
                ensure!(e.file_type()?.is_file(), "{name}: not a regular file");
                list.push(first);
            }
        }
        firsts.sort_unstable();
        let last = firsts.last().copied();
        for &first in &firsts {
            let path = self.root.join(seg_name(first));
            let buf = std::fs::read(&path)?;
            let (ranges, good) = frames(&buf);
            if good < buf.len() {
                // A torn write can only be the newest segment's tail: every earlier segment was
                // complete when the next was started.
                ensure!(
                    Some(first) == last,
                    "{}: damaged before its end; refusing to start",
                    seg_name(first)
                );
                ensure!(
                    !good_frame_after(&buf, good),
                    "{}: a damaged frame at offset {good} is followed by good ones; this is \
                     corruption, not a torn write: refusing to start",
                    seg_name(first)
                );
                let f = OpenOptions::new().write(true).open(&path)?;
                f.set_len(good as u64)?;
                f.sync_data()?;
                tracing::warn!(
                    segment = %seg_name(first), cut = buf.len() - good,
                    "torn tail cut; it was never acknowledged to an emitter"
                );
            }
            let mut prev = None;
            for &(start, end) in &ranges {
                let e = buf.get(start..end).and_then(parse_entry);
                let e = e.with_context(|| format!("{}: unreadable entry", seg_name(first)))?;
                ensure!(
                    e.seq >= first && prev.is_none_or(|p| e.seq > p),
                    "{}: sequence numbers out of order",
                    seg_name(first)
                );
                prev = Some(e.seq);
                self.pending.insert(
                    e.seq,
                    Loc {
                        segment: first,
                        offset: start as u64,
                        len: end - start,
                    },
                );
            }
            self.next_seq = self.next_seq.max(prev.map_or(first, |p| p + 1));
            self.segments.insert(
                first,
                Segment {
                    bytes: good as u64,
                    unacked: ranges.len(),
                    ack_bytes: 0,
                },
            );
        }
        let mut removed = false;
        for first in acks {
            let path = self.root.join(ack_name(first));
            let Some(seg) = self.segments.get_mut(&first) else {
                std::fs::remove_file(&path)?;
                removed = true;
                continue;
            };
            let buf = std::fs::read(&path)?;
            let (ranges, good) = frames(&buf);
            if good < buf.len() {
                // A lost acknowledgement only means a repeat delivery.
                let f = OpenOptions::new().write(true).open(&path)?;
                f.set_len(good as u64)?;
                f.sync_data()?;
            }
            for (start, end) in ranges {
                let id = buf.get(start..end).and_then(|p| p.try_into().ok());
                if id
                    .map(u64::from_be_bytes)
                    .and_then(|id| self.pending.remove(&id))
                    .is_some()
                {
                    seg.unacked -= 1;
                }
            }
            seg.ack_bytes = good as u64;
        }
        for first in firsts {
            if self.segments.get(&first).is_some_and(|s| s.unacked == 0) && Some(first) != last {
                self.remove_segment(first)?;
                removed = true;
            }
        }
        if removed {
            self.sync_dir(syncs)?;
        }
        self.total = self.segments.values().map(|s| s.bytes + s.ack_bytes).sum();
        if let Some((&first, seg)) = self.segments.iter().next_back()
            && seg.bytes < self.cfg.segment
        {
            let f = OpenOptions::new()
                .append(true)
                .open(self.root.join(seg_name(first)))?;
            self.active = Some((first, f));
        }
        Ok(())
    }

    /// Removes a segment and its acknowledgements from the disk and the books; the caller syncs
    /// the directory.
    fn remove_segment(&mut self, first: u64) -> std::io::Result<()> {
        std::fs::remove_file(self.root.join(seg_name(first)))?;
        match std::fs::remove_file(self.root.join(ack_name(first))) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        if let Some(s) = self.segments.remove(&first) {
            self.total -= s.bytes + s.ack_bytes;
        }
        Ok(())
    }

    /// Closes the newest segment and starts the next at `next_seq`; removes the old one if it has
    /// nothing left to deliver. The new segment is used only once its name is durable in the
    /// directory. Any failure poisons the spool: the directory is not what the books say.
    fn roll(&mut self, syncs: &Syncs) -> Result<()> {
        let r = self.roll_steps(syncs);
        if r.is_err() {
            self.poisoned = true;
        }
        r
    }

    fn roll_steps(&mut self, syncs: &Syncs) -> Result<()> {
        let first = self.next_seq;
        let file = self.open_new(&seg_name(first))?;
        self.sync_dir(syncs)?;
        let old = self.active.take().map(|(first, _)| first);
        self.segments.insert(
            first,
            Segment {
                bytes: 0,
                unacked: 0,
                ack_bytes: 0,
            },
        );
        self.active = Some((first, file));
        if let Some(old) = old.filter(|o| self.segments.get(o).is_some_and(|s| s.unacked == 0)) {
            self.remove_segment(old)?;
            self.sync_dir(syncs)?;
        }
        Ok(())
    }

    fn append(&mut self, emitter: &str, message: &[u8], syncs: &Syncs) -> Result<u64> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let seq = self.next_seq;
        let frame = frame(&entry_payload(seq, emitter, message))?;
        let need = frame.len() as u64;
        let (first, bytes) = self.active_state();
        if bytes.is_none_or(|b| b >= self.cfg.segment) {
            self.roll(syncs)?;
        } else if self.total + need > self.cfg.limit
            && self
                .segments
                .get(&first)
                .is_some_and(|s| s.unacked == 0 && s.bytes > 0)
        {
            // The newest segment holds only acknowledged messages: it is the one thing that can
            // be given back.
            self.roll(syncs)?;
        }
        if self.total + need > self.cfg.limit {
            return Err(Error::Full);
        }
        let (first, _) = self.active_state();
        let (_, file) = self.active.as_mut().ok_or(Error::Corrupt)?;
        let before = self.segments.get(&first).map_or(0, |s| s.bytes);
        if let Err(e) = fault!(self, Write).and_then(|()| file.write_all(&frame)) {
            // Take the half frame back so the next append does not follow it. If that fails
            // too, a half frame stays and later frames would follow it: poison.
            if fault!(self, SetLen)
                .and_then(|()| file.set_len(before))
                .is_err()
            {
                self.poisoned = true;
            }
            return Err(e.into());
        }
        if let Err(e) = fault!(self, SyncData).and_then(|()| file.sync_data()) {
            // After a failed fsync the kernel may have dropped the pages: what is on disk is
            // unknown until the next start reads it.
            self.poisoned = true;
            return Err(e.into());
        }
        count(&syncs.file);
        self.pending.insert(
            seq,
            Loc {
                segment: first,
                offset: before + HEADER as u64,
                len: frame.len() - HEADER,
            },
        );
        if let Some(s) = self.segments.get_mut(&first) {
            s.bytes += need;
            s.unacked += 1;
        }
        self.total += need;
        self.next_seq += 1;
        Ok(seq)
    }

    /// The first sequence number of the newest segment, and its size when it is open for append.
    fn active_state(&self) -> (u64, Option<u64>) {
        self.active.as_ref().map_or((0, None), |(first, _)| {
            (*first, self.segments.get(first).map(|s| s.bytes))
        })
    }

    fn ack(&mut self, ids: &[u64], syncs: &Syncs) -> Result<()> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let mut by_segment: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        for id in ids {
            if let Some(loc) = self.pending.get(id) {
                let list = by_segment.entry(loc.segment).or_default();
                if !list.contains(id) {
                    list.push(*id);
                }
            }
        }
        let mut created = false;
        let mut drained = Vec::new();
        for (first, ids) in &by_segment {
            let mut buf = Vec::new();
            for id in ids {
                buf.extend_from_slice(&frame(&id.to_be_bytes())?);
            }
            let path = self.root.join(ack_name(*first));
            created |= !path.exists();
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .mode(FILE_MODE)
                .open(&path)?;
            let before = f.metadata()?.len();
            if let Err(e) = fault!(self, Write).and_then(|()| f.write_all(&buf)) {
                if fault!(self, SetLen)
                    .and_then(|()| f.set_len(before))
                    .is_err()
                {
                    self.poisoned = true;
                }
                return Err(e.into());
            }
            if let Err(e) = fault!(self, SyncData).and_then(|()| f.sync_data()) {
                self.poisoned = true;
                return Err(e.into());
            }
            count(&syncs.file);
            for id in ids {
                self.pending.remove(id);
            }
            if let Some(s) = self.segments.get_mut(first) {
                s.unacked -= ids.len();
                s.ack_bytes += buf.len() as u64;
                self.total += buf.len() as u64;
                if s.unacked == 0 && self.active.as_ref().is_none_or(|(a, _)| a != first) {
                    drained.push(*first);
                }
            }
        }
        let removed = drained
            .iter()
            .try_for_each(|first| self.remove_segment(*first).map_err(Error::from));
        let synced = removed.and_then(|()| {
            if created || !drained.is_empty() {
                self.sync_dir(syncs)
            } else {
                Ok(())
            }
        });
        if synced.is_err() {
            self.poisoned = true;
        }
        synced
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn root() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    fn arm(s: &Spool, points: &[Point]) {
        s.lock().faults.0.extend_from_slice(points);
    }

    fn ids(s: &Spool) -> Vec<u64> {
        s.read_from(0, usize::MAX, usize::MAX)
            .unwrap()
            .0
            .iter()
            .map(|e| e.seq)
            .collect()
    }

    fn poisoned(s: &Spool) {
        assert!(matches!(s.append("e@d", b"x"), Err(Error::Poisoned)));
        assert!(matches!(s.ack(&[1]), Err(Error::Poisoned)));
        assert!(matches!(s.read_from(0, 1, 1), Err(Error::Poisoned)));
    }

    #[test]
    fn a_failed_write_that_is_taken_back_leaves_the_spool_usable() {
        let r = root();
        let s = Spool::open(r.path(), Config::default()).unwrap();
        s.append("e@d", b"one").unwrap();
        arm(&s, &[Point::Write]);
        assert!(matches!(s.append("e@d", b"two"), Err(Error::Io(_))));
        assert_eq!(s.append("e@d", b"three").unwrap(), 2);
        assert_eq!(ids(&s), [1, 2]);
    }

    #[test]
    fn a_half_frame_that_cannot_be_taken_back_poisons_the_spool_and_a_restart_recovers() {
        let r = root();
        let s = Spool::open(r.path(), Config::default()).unwrap();
        s.append("e@d", b"one").unwrap();
        arm(&s, &[Point::Write, Point::SetLen]);
        assert!(s.append("e@d", b"two").is_err());
        poisoned(&s);
        drop(s);
        let s = Spool::open(r.path(), Config::default()).unwrap();
        assert_eq!(ids(&s), [1]);
        assert_eq!(s.append("e@d", b"again").unwrap(), 2);
    }

    #[test]
    fn a_failed_fsync_of_a_frame_poisons_the_spool() {
        let r = root();
        let s = Spool::open(r.path(), Config::default()).unwrap();
        s.append("e@d", b"one").unwrap();
        arm(&s, &[Point::SyncData]);
        assert!(s.append("e@d", b"two").is_err());
        poisoned(&s);
        drop(s);
        // The frame reached the file; the emitter was told it failed, so a repeat is possible
        // and the writer removes it by uid (0029: at least once).
        let s = Spool::open(r.path(), Config::default()).unwrap();
        assert_eq!(ids(&s), [1, 2]);
    }

    #[test]
    fn a_new_segment_whose_directory_entry_cannot_be_synced_is_never_used() {
        let r = root();
        let s = Spool::open(r.path(), Config::default()).unwrap();
        arm(&s, &[Point::SyncDir]);
        // The first append makes the first segment.
        assert!(s.append("e@d", b"one").is_err());
        poisoned(&s);
        assert_eq!(s.depth(), 0);
        drop(s);
        let s = Spool::open(r.path(), Config::default()).unwrap();
        assert_eq!(s.append("e@d", b"one").unwrap(), 1);

        // The same on a roll later, and the old segment is still there to recover from.
        let small = Config {
            limit: 1 << 20,
            segment: 64,
        };
        let r = root();
        let s = Spool::open(r.path(), small).unwrap();
        s.append("e@d", &[1u8; 80]).unwrap();
        arm(&s, &[Point::SyncDir]);
        assert!(s.append("e@d", &[2u8; 80]).is_err());
        poisoned(&s);
        drop(s);
        let s = Spool::open(r.path(), small).unwrap();
        assert_eq!(ids(&s), [1]);
        assert_eq!(s.append("e@d", &[2u8; 80]).unwrap(), 2);
    }

    #[test]
    fn a_failed_ack_fsync_poisons_the_spool_and_the_message_comes_again() {
        let r = root();
        let s = Spool::open(r.path(), Config::default()).unwrap();
        s.append("e@d", b"one").unwrap();
        arm(&s, &[Point::SyncData]);
        assert!(s.ack(&[1]).is_err());
        poisoned(&s);
        drop(s);
        let s = Spool::open(r.path(), Config::default()).unwrap();
        assert!(ids(&s).len() <= 1);
    }

    #[test]
    fn the_tail_never_goes_backwards() {
        let r = root();
        let s = Spool::open(r.path(), Config::default()).unwrap();
        let rx = s.watch_tail();
        s.append("e@d", b"one").unwrap();
        s.append("e@d", b"two").unwrap();
        s.0.tail.send_modify(|t| *t = (*t).max(1));
        assert_eq!(*rx.borrow(), 2);
    }
}
