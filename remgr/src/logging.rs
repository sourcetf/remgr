//! In-memory log hub: ring buffer for the console + broadcast for live WS tail.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

const RING_SIZE: usize = 1000;

pub struct LogHub {
    entries: Mutex<VecDeque<String>>,
    partial: Mutex<String>,
    tx: broadcast::Sender<String>,
}

impl LogHub {
    pub fn new() -> Arc<Self> {
        let (tx, _) = broadcast::channel(256);
        Arc::new(Self {
            entries: Mutex::new(VecDeque::with_capacity(RING_SIZE)),
            partial: Mutex::new(String::new()),
            tx,
        })
    }

    fn push_line(&self, line: &str) {
        let mut entries = self.entries.lock().unwrap();
        if entries.len() == RING_SIZE {
            entries.pop_front();
        }
        entries.push_back(line.to_string());
        drop(entries);
        let _ = self.tx.send(line.to_string());
    }

    pub fn snapshot(&self, n: usize) -> Vec<String> {
        let entries = self.entries.lock().unwrap();
        let skip = entries.len().saturating_sub(n);
        entries.iter().skip(skip).cloned().collect()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.tx.subscribe()
    }

    fn ingest(&self, buf: &str) {
        let mut partial = self.partial.lock().unwrap();
        partial.push_str(buf);
        while let Some(pos) = partial.find('\n') {
            let line: String = partial.drain(..=pos).collect();
            let line = line.trim_end();
            if !line.is_empty() {
                self.push_line(line);
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
