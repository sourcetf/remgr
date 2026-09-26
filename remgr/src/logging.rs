//! In-memory log hub: ring buffer for the console + broadcast for live WS tail,
//! plus an append-only file so history survives a restart.

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

const RING_SIZE: usize = 1000;
/// Rotate to `<file>.1` once the file passes this size (one generation kept).
const LOG_MAX_BYTES: u64 = 8 * 1024 * 1024;
/// Longest unterminated fragment held while reassembling a log line.
const MAX_PARTIAL: usize = 64 * 1024;

/// Descriptor of the current log file, or -1 while there is none.
#[cfg(unix)]
static RAW_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// Writer that hands bytes straight to a descriptor and drops what cannot be
/// written.
///
/// As a service this process is started by rc.subr(8) with its output piped into
/// `logger -isp daemon.info -t remgr` — and `-s` makes that logger echo every
/// line to its own stderr, which for a daemon started over SSH is a channel that
/// closes with the session. A logger that stopped draining was found blocked for
/// hours on this box, and once the 64 KiB pipe fills up, a *blocking* write in
/// the logging path freezes whatever is logging — with tracing's lock held, that
/// is the whole daemon, console included.
///
/// So: no buffering (a `BufWriter` would instead hoard the failed write and grow
/// without bound while the pipe stays full), the descriptor is set non-blocking
/// by `unblock_stdout`, and a full or closed pipe is treated as "nobody is
/// listening right now" instead of an error. `eprintln!`/`println!` cannot be
/// used for this: they panic on a failed write.
pub struct DirectFd(pub i32);

impl std::io::Write for DirectFd {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        #[cfg(unix)]
        {
            // SAFETY: writing bytes we own to a descriptor this process holds.
            let written = unsafe { libc::write(self.0, buf.as_ptr().cast(), buf.len()) };
            if written < 0 {
                let e = std::io::Error::last_os_error();
                return match e.kind() {
                    // full (the reader is slow or gone) or closed: drop the line
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::BrokenPipe => {
                        Ok(buf.len())
                    }
                    // interrupted: nothing was written, let the caller retry
                    std::io::ErrorKind::Interrupted => Err(e),
                    _ => Err(e),
                };
            }
            Ok(written as usize)
        }
        #[cfg(not(unix))]
        {
            // Windows has no descriptors to write to directly; the standard
            // handles are all there is, and they block rather than fail.
            let n = if self.0 == 2 {
                std::io::Write::write(&mut std::io::stderr(), buf)
            } else {
                std::io::Write::write(&mut std::io::stdout(), buf)
            }?;
            Ok(n)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Write a line to stdout, ignoring failure — for the lines meant for whoever
/// started the process (an operator at a terminal, or rc.subr's logger pipe).
pub fn say(line: &str) {
    write_line_fd(1, line);
}

/// The same for stderr, where the start-up and logging complaints go.
pub fn say_err(line: &str) {
    write_line_fd(2, line);
}

fn write_line_fd(fd: i32, line: &str) {
    use std::io::Write;
    let mut out = DirectFd(fd);
    let _ = out.write_all(line.as_bytes());
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

/// Keep stdout from being able to stall this process.
///
/// Only for non-terminals: an interactive run must keep normal blocking writes,
/// and a terminal does not fill up. See `DirectFd` for why a service needs this.
#[cfg(unix)]
pub fn unblock_stdout() {
    use std::os::unix::io::AsRawFd;
    let fd = std::io::stdout().as_raw_fd();
    // SAFETY: fcntl on a descriptor this process owns.
    if unsafe { libc::isatty(fd) } == 1 {
        return;
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return;
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0 {
        tracing::debug!(
            "stdout is non-blocking: as a service it is a pipe to logger(1), and a \
             stuck logger must not be able to freeze the daemon"
        );
    }
}

#[cfg(not(unix))]
pub fn unblock_stdout() {}

/// The log file's descriptor, for the signal handler in `signals.rs`.
///
/// A signal handler cannot take the sink's mutex, allocate, or ask the clock for
/// a timestamp — but a record of who terminated the process has to reach the
/// disk even if the process dies immediately afterwards, so the handler writes
/// it straight here. The descriptor is a `dup` of the sink's handle, so a later
/// rotation (which replaces the handle) cannot close it from under the handler;
/// the next successful open replaces it here and closes the previous one.
#[cfg(unix)]
pub fn raw_fd() -> i32 {
    RAW_FD.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(unix)]
fn remember_raw_fd(file: &std::fs::File) {
    use std::os::unix::io::AsRawFd;
    let dup = unsafe { libc::dup(file.as_raw_fd()) };
    if dup < 0 {
        return;
    }
    let previous = RAW_FD.swap(dup, std::sync::atomic::Ordering::Relaxed);
    if previous >= 0 {
        unsafe { libc::close(previous) };
    }
}

/// The on-disk half of the log hub. `/var/log/remgr` is unveiled for it; a
/// filesystem that refuses the write (read-only, full, absent directory) must
/// never break logging, so the file is best-effort and opened lazily.
struct FileSink {
    path: PathBuf,
    file: Option<std::fs::File>,
    written: u64,
    complained: bool,
}

impl FileSink {
    fn new(path: PathBuf) -> Self {
        Self { path, file: None, written: 0, complained: false }
    }

    fn open(&mut self) {
        // The very first start-up lines carry the bootstrap console password,
        // so the file is created root-only rather than with the process umask.
        #[cfg(unix)]
        let opened = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&self.path)
        };
        #[cfg(not(unix))]
        let opened = OpenOptions::new().create(true).append(true).open(&self.path);

        match opened {
            Ok(f) => {
                // an existing file keeps whatever mode it has: tighten it too,
                // the file may predate this and be world-readable
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
                    remember_raw_fd(&f);
                }
                self.written = f.metadata().map(|m| m.len()).unwrap_or(0);
                self.file = Some(f);
            }
            Err(e) => {
                if !self.complained {
                    self.complained = true;
                    // say_err, not eprintln!: stderr here is also rc.subr's
                    // logger pipe, and a full pipe makes eprintln! panic.
                    say_err(&format!(
                        "remgr: file logging disabled ({}: {e})",
                        self.path.display()
                    ));
                }
            }
        }
    }

    fn write_line(&mut self, line: &str) {
        if self.file.is_none() {
            self.open();
        }
        if self.written >= LOG_MAX_BYTES {
            self.rotate();
        }
        // Collect the error instead of acting inside the borrow: the handle is
        // dropped below so the next line retries the open.
        let mut failed: Option<std::io::Error> = None;
        if let Some(f) = self.file.as_mut() {
            match writeln!(f, "{line}") {
                Ok(()) => {
                    self.written += line.len() as u64 + 1;
                    // a later failure is a new episode and gets reported again
                    self.complained = false;
                }
                Err(e) => failed = Some(e),
            }
        }
        if let Some(e) = failed {
            // A full or read-only filesystem used to stop the on-disk history
            // *silently*: the console keeps working (its ring buffer is in
            // memory), so an operator would only notice much later. Report it
            // once per episode and keep retrying, so history resumes by itself
            // when space is freed.
            if !self.complained {
                self.complained = true;
                say_err(&format!(
                    "remgr: cannot write the log file ({}: {e}) — on-disk history is \
                     paused until a write succeeds; the console's in-memory log is unaffected",
                    self.path.display()
                ));
            }
            self.file = None;
        }
    }

    fn rotate(&mut self) {
        if let Some(f) = self.file.as_mut() {
            let _ = f.flush();
        }
        self.file = None;
        let rolled = self.path.with_file_name("remgr.log.1");
        let _ = std::fs::rename(&self.path, rolled);
        self.written = 0;
        self.open();
    }
}

pub struct LogHub {
    entries: Mutex<VecDeque<String>>,
    partial: Mutex<String>,
    tx: broadcast::Sender<String>,
    file: Mutex<FileSink>,
}

impl LogHub {
    pub fn new() -> Arc<Self> {
        let (tx, _) = broadcast::channel(256);
        Arc::new(Self {
            entries: Mutex::new(VecDeque::with_capacity(RING_SIZE)),
            partial: Mutex::new(String::new()),
            tx,
            file: Mutex::new(FileSink::new(crate::platform::log_file())),
        })
    }

    fn push_line(&self, line: &str) {
        // plain std mutexes: a panic elsewhere while one was held must not turn
        // every later log line (and /api/logs) into a panic
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() == RING_SIZE {
            entries.pop_front();
        }
        entries.push_back(line.to_string());
        drop(entries);
        self.file
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .write_line(line);
        let _ = self.tx.send(line.to_string());
    }

    pub fn snapshot(&self, n: usize) -> Vec<String> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let skip = entries.len().saturating_sub(n);
        entries.iter().skip(skip).cloned().collect()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.tx.subscribe()
    }

    fn ingest(&self, buf: &str) {
        let mut partial = self.partial.lock().unwrap_or_else(|e| e.into_inner());
        partial.push_str(buf);
        while let Some(pos) = partial.find('\n') {
            let line: String = partial.drain(..=pos).collect();
            let line = line.trim_end();
            if !line.is_empty() {
                self.push_line(line);
            }
        }
        // A writer that never emits a newline (a very long message) would
        // otherwise grow this buffer for the lifetime of the process.
        if partial.len() > MAX_PARTIAL {
            let line = partial.trim_end().to_string();
            partial.clear();
            drop(partial);
            if !line.is_empty() {
                self.push_line(&line);
            }
        }
    }
}

/// `tracing_subscriber` writer adapter.
pub struct HubWriter {
    hub: Arc<LogHub>,
}

impl Write for HubWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let s = String::from_utf8_lossy(buf);
        self.hub.ingest(&s);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn init(hub: Arc<LogHub>) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let writer_layer = tracing_subscriber::fmt::layer()
        .with_writer(move || HubWriter { hub: hub.clone() })
        .with_target(false)
        .with_ansi(false);

    // stdout carries the same stream for whoever started this process (rc.subr's
    // logger pipe, or a terminal). DirectFd, not std::io::stdout: see its comment.
    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_writer(|| DirectFd(1))
        .with_ansi(false);

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,remgr_frps=info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(writer_layer)
        .with(stdout_layer)
        .init();

    // After `.init()`, so the one line it logs about itself is visible, and
    // before anything can log to a piped stdout (see unblock_stdout).
    unblock_stdout();
}
