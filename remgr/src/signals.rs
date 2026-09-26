//! Termination signals, and where they came from.
//!
//! rc.d stops this daemon with SIGTERM (rc.subr(8)'s default `rc_stop_signal`),
//! and that is the expected way for the process to end. Everything else that can
//! send one — a `pkill` whose pattern happened to match this command line, a
//! `kill` typed at the wrong prompt, an `rcctl stop` fired by a deploy script
//! that then failed before its `start` — leaves the same trace afterwards: a log
//! line saying a signal arrived, and nothing saying from whom. For a service
//! that is supposed to run unattended that is a bad property, so the line logged
//! here names the sender: the sending pid and the reason the kernel attached
//! (`si_code`), which is what separates "a process asked for this" from "the
//! kernel delivered it".
//!
//! tokio's signal API cannot report any of that — it turns a signal into a unit
//! in a stream and drops the `siginfo` — so this installs its own SA_SIGINFO
//! handler, after the embedded servers have registered theirs (whoever installs
//! last wins), and deliberately does *not* forward to them: RustDesk's hbbs waits
//! for SIGTERM inside a `tokio::select!` and answers it with `process::exit(0)`
//! (`rendezvous_server.rs`, where the exit is spelled out as taking "this server
//! in-process" with it). Forwarding would hand the exit to hbbs mid-shutdown and
//! truncate the log — the observed symptom was a shutdown that stopped dead at
//! EasyTier's "I/O error: socket closed" with no final line. Shutdown is decided
//! in one place instead: this handler, then `main`'s module stops, then exit.
//!
//! One honest limit: OpenBSD does not record who sent a `kill(2)`. `si_code` says
//! `SI_USER` (0), but `si_pid`/`si_uid` come back zero — measured with a C probe
//! for a signal from another process, from a shell, and from the process itself —
//! and there is no `sigqueue(3)` to carry a value instead. The line logged here
//! therefore always names the signal and its class, and the sender on platforms
//! that do report it; on OpenBSD the accounting tail that `acct.rs` logs next to
//! it is what names the commands that ran just before.
//!
//! A signal handler may only call async-signal-safe functions. This one formats
//! a fixed record into a stack buffer using integer arithmetic (no allocation,
//! no locks, no clock), writes it to a pipe for the async side to log properly,
//! and writes the same bytes straight to the log file's descriptor: a second
//! signal ends the process immediately (that is also what `STOPPING` below is
//! for), and by then the record has to be on disk already.
//!
//! Policy: SIGTERM and SIGINT stop the modules and exit. SIGHUP is logged and
//! then ignored — this daemon has nothing to re-read from disk (the console
//! writes settings through the config file and rebinds its own listener), and
//! dying silently on `rcctl reload` (rc.subr's default reload signal is HUP, and
//! `rcctl reload` is what an operator reaches for when they want the daemon to
//! *keep* running) is worse than saying so.

#[cfg(unix)]
mod imp {
    use std::io;
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use std::sync::OnceLock;

    use tokio::sync::mpsc;

    /// Signals recorded by the handler, in the order they are installed.
    const HANDLED_LEN: usize = 3;
    const HANDLED: [libc::c_int; HANDLED_LEN] = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP];

    /// The part of a `siginfo_t` that says who sent a signal, read at the offsets
    /// OpenBSD actually uses.
    ///
    /// `si_signo`, `si_code` and `si_errno` are three ints, then four bytes of
    /// padding before the union — its members include 8-byte types, so
    /// `sizeof(siginfo_t)` is 136, while the libc crate's OpenBSD definition says
    /// 128 and its `si_pid()` accessor therefore reads past the union into zeros
    /// (which is why this does not use it). A C probe on the target printed
    /// `offsetof(siginfo_t, si_pid) == 16` and `si_uid == 20`.
    ///
    /// On OpenBSD both of those are zero for every `kill(2)`: the kernel reports
    /// `SI_USER` but not the sender, so `sender_pid` is 0 in practice and the
    /// accounting tail in `acct.rs` is what identifies the actor.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SiginfoKill {
        si_signo: i32,
        si_code: i32,
        si_errno: i32,
        _pad: i32,
        si_pid: i32,
        si_uid: u32,
    }

    /// One signal, with where it came from.
    #[derive(Debug, Clone, Copy)]
    pub struct Termination {
        /// The signal number.
        pub signal: i32,
        /// Sending process, as `siginfo.si_pid` reported it — 0 when the kernel
        /// reported none, which on OpenBSD is always the case for `kill(2)` (and
        /// also true for kernel-generated signals, e.g. a login-class limit).
        pub sender_pid: i32,
        /// The sender's effective uid, when the kernel reported one.
        pub sender_uid: u32,
        /// `siginfo.si_code`, the reason the kernel attached to the signal.
        pub code: i32,
    }

    impl Termination {
        pub fn name(&self) -> &'static str {
            match self.signal {
                libc::SIGTERM => "SIGTERM",
                libc::SIGINT => "SIGINT",
                libc::SIGHUP => "SIGHUP",
                _ => "signal",
            }
        }

        /// SIGTERM/SIGINT end the process; SIGHUP must not (see the module docs).
        pub fn stops(&self) -> bool {
            matches!(self.signal, libc::SIGTERM | libc::SIGINT)
        }

        /// The whole event as one line for the log.
        pub fn describe(&self) -> String {
            let who = if self.sender_pid > 0 {
                format!("from pid {} (uid {})", self.sender_pid, self.sender_uid)
            } else {
                "with no sender reported by the kernel".to_string()
            };
            format!(
                "{} received {} ({}): {}",
                self.name(),
                who,
                self.origin(),
                if self.stops() {
                    "stopping the modules"
                } else {
                    "kept running — remgr has nothing to reload from disk"
                }
            )
        }

        /// `si_code` in words. The numbering is not portable (BSD and the rest
        /// disagree on `SI_USER`, `SI_QUEUE` and `SI_KERNEL`), so every convention
        /// that can appear is recognised and the raw value is always printed — the
        /// raw value is the fact, this is only the reading. OpenBSD's numbers are
        /// in `<sys/siginfo.h>`: SI_USER 0, SI_LWP -1, SI_QUEUE -2, SI_TIMER -3.
        fn origin(&self) -> String {
            match self.code {
                0 | 0x10001 => "sent by a process: kill(2)/raise(3)".to_string(),
                -1 | 0x10002 => "sent by a process: lwp_kill(2)/sigqueue(3)".to_string(),
                -2 => "an expiring timer".to_string(),
                -3 | -5 => "a message queue (SIGEV_*)".to_string(),
                -4 => "asynchronous I/O completion".to_string(),
                0x80 => "the kernel".to_string(),
                other => format!("si_code={other}"),
            }
        }
    }

    /// Write end of the record pipe; -1 until `install()` runs.
    static PIPE_WRITE: AtomicI32 = AtomicI32::new(-1);
    /// Set by the first termination signal, so a second one stops asking nicely.
    static STOPPING: AtomicBool = AtomicBool::new(false);
    /// Records for the async side.
    static CHANNEL: OnceLock<tokio::sync::Mutex<mpsc::UnboundedReceiver<Termination>>> =
        OnceLock::new();

    /// Append to a fixed buffer. Kept to plain arithmetic: this runs in a signal
    /// handler, where `format!` (allocation, locks) is not allowed.
    fn put(buf: &mut [u8], at: usize, bytes: &[u8]) -> usize {
        let mut n = at;
        for b in bytes {
            if n >= buf.len() {
                return n;
            }
            buf[n] = *b;
            n += 1;
        }
        n
    }

    fn put_int(buf: &mut [u8], at: usize, v: i64) -> usize {
        let mut n = at;
        let mut digits = [0u8; 20];
        let mut len = 0;
        let negative = v < 0;
        let mut rest = v.unsigned_abs();
        loop {
            digits[len] = b'0' + (rest % 10) as u8;
            len += 1;
            rest /= 10;
            if rest == 0 {
                break;
            }
        }
        if negative {
            n = put(buf, n, b"-");
        }
        while len > 0 {
            len -= 1;
            n = put(buf, n, &[digits[len]]);
        }
        n
    }

    /// The shape of one record, written by the handler and read back by `parse`.
    ///
    /// Constants for a reason: the writer grew a "from" that the reader had never
    /// learned, so every record was written, read, parsed into nothing and
    /// dropped — and a signal that never reaches its consumer is a shutdown that
    /// never happens (the observed symptom was a process that ignored SIGTERM and
    /// had to be killed). `what_the_handler_writes_is_what_the_parser_reads`
    /// builds a record with the formatter below and parses it, which is what keeps
    /// the two sides from drifting apart again.
    const REC_SIGNAL: &str = "signal ";
    const REC_PID: &str = " from pid=";
    const REC_UID: &str = " uid=";
    const REC_CODE: &str = " code=";

    /// Render one record: "signal <sig> from pid=<pid> uid=<uid> code=<code>\n".
    /// Plain integer formatting and buffer copies only — this runs in the signal
    /// handler, where allocation, locks and the clock are all off limits.
    pub(super) fn record_bytes(sig: i32, pid: i32, uid: u32, code: i32) -> ([u8; 80], usize) {
        let mut buf = [0u8; 80];
        let mut n = 0;
        n = put(&mut buf, n, REC_SIGNAL.as_bytes());
        n = put_int(&mut buf, n, sig as i64);
        n = put(&mut buf, n, REC_PID.as_bytes());
        n = put_int(&mut buf, n, pid as i64);
        n = put(&mut buf, n, REC_UID.as_bytes());
        n = put_int(&mut buf, n, uid as i64);
        n = put(&mut buf, n, REC_CODE.as_bytes());
        n = put_int(&mut buf, n, code as i64);
        n = put(&mut buf, n, b"\n");
        (buf, n.min(buf.len()))
    }

    /// The handler: record where the signal came from, and let the process end.
    extern "C" fn record(sig: libc::c_int, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
        let (pid, uid, code) = if info.is_null() {
            (0i32, 0u32, 0i32)
        } else {
            // SAFETY: for SA_SIGINFO the kernel passes a valid siginfo_t; the
            // mirror covers the fields read, and read_unaligned is used because
            // the kernel's own alignment is not guaranteed to match a Rust type.
            let raw: SiginfoKill = unsafe { std::ptr::read_unaligned(info.cast()) };
            (raw.si_pid, raw.si_uid, raw.si_code)
        };

        let (buf, bytes) = record_bytes(sig, pid, uid, code);

        let pipe = PIPE_WRITE.load(Ordering::Relaxed);
        if pipe >= 0 {
            unsafe { libc::write(pipe, buf.as_ptr().cast(), bytes) };
        }
        // Straight to the log file as well: if a second signal (or any exit path)
        // ends the process right away, the async side may never log anything.
        let log = crate::logging::raw_fd();
        if log >= 0 {
            unsafe { libc::write(log, buf.as_ptr().cast(), bytes) };
        }

        // A second termination signal means the first one is not being obeyed:
        // stop waiting for the graceful path and go.
        if sig != libc::SIGHUP && STOPPING.swap(true, Ordering::SeqCst) {
            unsafe { libc::_exit(128 + sig) };
        }
    }

    /// Read back one record. The literals come from the same constants the
    /// handler writes, so a change on one side fails the contract test on the
    /// other instead of silently dropping every signal.
    fn parse(line: &str) -> Option<Termination> {
        let rest = line.strip_prefix(REC_SIGNAL)?;
        let (signal, rest) = rest.split_once(' ')?;
        let signal: i32 = signal.parse().ok()?;
        let rest = rest.strip_prefix(REC_PID.trim_start())?;
        let (sender_pid, rest) = rest.split_once(' ')?;
        let sender_pid: i32 = sender_pid.parse().ok()?;
        let rest = rest.strip_prefix(REC_UID.trim_start())?;
        let (sender_uid, rest) = rest.split_once(' ')?;
        let sender_uid: u32 = sender_uid.parse().ok()?;
        let rest = rest.strip_prefix(REC_CODE.trim_start())?;
        let code: i32 = rest.trim_end().parse().ok()?;
        Some(Termination { signal, sender_pid, sender_uid, code })
    }

    /// Every record in one read. A read returns whatever the pipe holds, so two
    /// signals close together arrive as two lines — parsing only the first would
    /// swallow a SIGTERM that followed a SIGHUP and leave the daemon running.
    pub(super) fn parse_all(text: &str) -> Vec<Termination> {
        text.lines().filter_map(parse).collect()
    }

    /// Record termination signals. Safe to call more than once, and meant to be
    /// called twice: once before the modules start, so a signal that arrives
    /// during start-up is recorded and obeyed like any other (otherwise nothing
    /// stops the process and rc.subr has to wait out `daemon_timeout` before it
    /// escalates to SIGKILL), and once after they are up, because the embedded
    /// servers register handlers of their own while starting and the last one
    /// installed is the one that runs. The pipe and its reader are created once;
    /// every call re-asserts the dispositions.
    pub fn install() -> io::Result<()> {
        if PIPE_WRITE.load(Ordering::SeqCst) < 0 {
            let (tx, rx) = mpsc::unbounded_channel();
            let _ = CHANNEL.set(tokio::sync::Mutex::new(rx));

            let mut fds = [0 as libc::c_int; 2];
            // SAFETY: plain pipe(2) into a two-element array.
            if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            PIPE_WRITE.store(fds[1], Ordering::SeqCst);

            // A dedicated thread doing a blocking read: the reader must survive
            // whatever the async side is doing, and it must not need the runtime.
            std::thread::Builder::new()
                .name("signals".into())
                .spawn(move || {
                    let mut buf = [0u8; 128];
                    loop {
                        // SAFETY: reading into a buffer we own.
                        let n = unsafe { libc::read(fds[0], buf.as_mut_ptr().cast(), buf.len()) };
                        if n > 0 {
                            let text = String::from_utf8_lossy(&buf[..n as usize]);
                            if parse_all(&text).into_iter().any(|t| tx.send(t).is_err()) {
                                break;
                            }
                            continue;
                        }
                        match io::Error::last_os_error().raw_os_error() {
                            // interrupted by a signal: read again
                            Some(libc::EINTR) => continue,
                            // pipe gone: nothing left to do on this thread
                            _ => break,
                        }
                    }
                })?;
        }

        for sig in HANDLED {
            // SAFETY: a zeroed sigaction is the documented starting point; the
            // handler is a plain extern "C" fn and stays alive for the process.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            let handler: extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) =
                record;
            action.sa_sigaction = handler as *const () as libc::sighandler_t;
            action.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
            // SAFETY: initialising the mask of a sigaction we own.
            unsafe { libc::sigemptyset(&mut action.sa_mask) };
            // SAFETY: the action pointer is valid; nothing is requested back,
            // on purpose — see the module docs on why nothing is forwarded.
            if unsafe { libc::sigaction(sig, &action, std::ptr::null_mut()) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        tracing::debug!("signal handlers installed (SIGTERM/SIGINT stop, SIGHUP is ignored)");
        Ok(())
    }

    /// Await the next recorded signal. The record is parsed on the reader thread,
    /// so what comes back is exactly what the handler wrote.
    pub async fn next() -> Termination {
        let channel = CHANNEL
            .get()
            .expect("signals::install() must run before signals::next()");
        let mut rx = channel.lock().await;
        rx.recv()
            .await
            .unwrap_or(Termination { signal: 0, sender_pid: 0, sender_uid: 0, code: 0 })
    }
}

#[cfg(not(unix))]
mod imp {
    /// Never produced: signals are a unix concept, and on Windows this daemon is
    /// stopped through the service manager instead.
    #[derive(Debug, Clone, Copy)]
    pub struct Termination {
        pub signal: i32,
        pub sender_pid: i32,
        pub sender_uid: u32,
        pub code: i32,
    }

    impl Termination {
        pub fn name(&self) -> &'static str {
            "signal"
        }
        pub fn stops(&self) -> bool {
            false
        }
        pub fn describe(&self) -> String {
            String::new()
        }
    }

    pub fn install() -> std::io::Result<()> {
        Ok(())
    }

    /// Never resolves: nothing sends this process a signal on this platform.
    pub async fn next() -> Termination {
        std::future::pending().await
    }
}

pub use imp::{install, next, Termination};

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn describe_names_the_sender_and_the_reason() {
        let t = Termination { signal: libc::SIGTERM, sender_pid: 4711, sender_uid: 0, code: 0 };
        let line = t.describe();
        assert!(line.contains("SIGTERM"), "{line}");
        assert!(line.contains("from pid 4711 (uid 0)"), "{line}");
        assert!(line.contains("kill(2)"), "{line}");
        assert!(t.stops(), "SIGTERM must stop the process");
    }

    #[test]
    fn hup_is_reported_but_does_not_stop_the_service() {
        // An `rcctl reload` sends SIGHUP. Losing a relay server to it, without a
        // word in the log, is exactly what this policy exists to prevent.
        let t = Termination { signal: libc::SIGHUP, sender_pid: 1, sender_uid: 0, code: 0x80 };
        assert!(!t.stops(), "SIGHUP must not stop the process");
        assert!(t.describe().contains("kept running"), "{}", t.describe());
        assert!(t.describe().contains("the kernel"), "{}", t.describe());
    }

    /// Format one record exactly the way the handler does.
    fn written(sig: i32, pid: i32, uid: u32, code: i32) -> String {
        let (buf, n) = super::imp::record_bytes(sig, pid, uid, code);
        String::from_utf8(buf[..n].to_vec()).expect("records are ASCII")
    }

    #[test]
    fn what_the_handler_writes_is_what_the_parser_reads() {
        // The regression this exists for: the writer had a "from" the parser did
        // not know, so every record parsed into nothing, the consumer never woke,
        // and SIGTERM left the daemon running until rc.subr escalated.
        for (sig, pid, uid, code) in [
            (libc::SIGTERM, 0, 0, 0),
            (libc::SIGINT, 4711, 0, 0x10001),
            (libc::SIGHUP, 12345, 1000, -2),
        ] {
            let text = written(sig, pid, uid, code);
            let parsed = super::imp::parse_all(&text);
            assert_eq!(parsed.len(), 1, "did not parse: {text:?}");
            let t = parsed[0];
            assert_eq!(t.signal, sig, "{text:?}");
            assert_eq!(t.sender_pid, pid, "{text:?}");
            assert_eq!(t.sender_uid, uid, "{text:?}");
            assert_eq!(t.code, code, "{text:?}");
        }
    }

    #[test]
    fn a_read_holding_two_records_yields_both() {
        // One read can carry two records: a SIGHUP immediately followed by a
        // SIGTERM lands in the same read, and dropping the second record would
        // leave the daemon running after a SIGTERM.
        let both = format!(
            "{}{}",
            written(libc::SIGHUP, 10, 0, 0),
            written(libc::SIGTERM, 10, 0, 0)
        );
        let parsed = super::imp::parse_all(&both);
        assert_eq!(parsed.len(), 2, "{parsed:?}");
        assert_eq!(parsed[0].signal, libc::SIGHUP);
        assert_eq!(parsed[1].signal, libc::SIGTERM);
        assert!(parsed[1].stops());
    }

    #[test]
    fn a_signal_without_a_sender_is_logged_honestly() {
        // OpenBSD reports SI_USER for kill(2) with si_pid left at 0, so this is
        // the line an operator will actually see there; it must not claim a pid
        // that was never reported, nor imply the kernel sent the signal.
        let t = Termination { signal: libc::SIGTERM, sender_pid: 0, sender_uid: 0, code: 0 };
        let line = t.describe();
        assert!(line.contains("no sender reported"), "{line}");
        assert!(line.contains("kill(2)"), "{line}");
        assert!(t.stops());
    }
}
