//! In-memory log hub: ring buffer for the console + broadcast for live WS tail,
//! plus an append-only file so history survives a restart.

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

const RING_SIZE: usize = 1000;
const LOG_FILE: &str = "/var/log/remgr/remgr.log";
/// Rotate to `<file>.1` once the file passes this size (one generation kept).
const LOG_MAX_BYTES: u64 = 8 * 1024 * 1024;
/// Longest unterminated fragment held while reassembling a log line.
const MAX_PARTIAL: usize = 64 * 1024;

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
    fn new(path: &str) -> Self {
        Self { path: PathBuf::from(path), file: None, written: 0, complained: false }
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
                }
                self.written = f.metadata().map(|m| m.len()).unwrap_or(0);
                self.file = Some(f);
            }
            Err(e) => {
                if !self.complained {
                    self.complained = true;
                    eprintln!("remgr: file logging disabled ({}: {e})", self.path.display());
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
        if let Some(f) = self.file.as_mut() {
            if writeln!(f, "{line}").is_ok() {
                self.written += line.len() as u64 + 1;
            }
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
            file: Mutex::new(FileSink::new(LOG_FILE)),
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

impl HubWriter {
    pub fn make(hub: Arc<LogHub>) -> Self {
        Self { hub }
    }
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

    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stdout)
        .with_ansi(false);

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,remgr_frps=info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(writer_layer)
        .with(stdout_layer)
        .init();
}
