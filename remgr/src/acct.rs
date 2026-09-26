//! What ran just before the signal: the kernel's own process accounting.
//!
//! `signals.rs` names the signal and its `si_code`, but on OpenBSD it cannot name
//! the sender: `kill(2)` delivers `SI_USER` with `si_pid`/`si_uid` left at zero
//! (measured — a C probe receiving a signal from another process, from a shell,
//! and from itself all read 0), and OpenBSD has no `sigqueue(3)` to carry a value
//! instead. So the log line alone cannot answer "who stopped my service".
//!
//! What does record the actor is the accounting file: the kernel writes one
//! fixed-size record per process as it exits — command name, uid, pid, tty, start
//! time, and the flags that say how it ended (a signal, a pledge or unveil
//! violation, a core dump). Reading its tail right after a termination signal
//! therefore lists the commands that ran in the seconds before it, and it names
//! the sender itself as soon as that process exits.
//!
//! One limit of the source, not of the reading: a shell script is recorded under
//! the interpreter's name. Measured on the target by running each kind — a
//! `rcctl check` leaves `ksh`, while `/bin/kill` leaves `kill` and `pkill` leaves
//! `pkill`. An actor that is a real binary is therefore named; one that is a shell
//! command is visible as a shell, with the pid, uid, tty and start time that let
//! an operator line it up against the session log.
//!
//! The file only exists while accounting is on (`accounting=YES` in
//! rc.conf.local plus `accton(8)`); when it is not, the log says so rather than
//! pretending.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Where the kernel writes accounting records; unveiled read-only by `secure.rs`.
pub const ACCT_PATH: &str = "/var/account/acct";

/// Size of one accounting record. `struct acct` is 64 bytes; the assertion below
/// keeps the mirror in step with it.
pub const ACCT_RECORD_SIZE: usize = 64;

/// Mirror of OpenBSD's `struct acct`, field for field.
///
/// Not guesswork: `sizeof(struct acct)` is 64 and the fields sit at comm=0,
/// utime=24, btime=32, uid=40, gid=44, mem=48, tty=52, pid=56, flag=60, as a C
/// probe against `/usr/include/sys/acct.h` printed on the target machine. The
/// record is read through this type rather than parsed field by field, and the
/// size assertion fails the build the moment the two disagree.
#[repr(C)]
#[derive(Clone, Copy)]
struct AcctRecord {
    /// `char ac_comm[_MAXCOMLEN]` — the command name, NUL-padded (24 bytes).
    comm: [u8; 24],
    utime: u16,
    stime: u16,
    etime: u16,
    io: u16,
    /// `time_t ac_btime` — when the process started, in unix seconds.
    btime: i64,
    uid: u32,
    gid: u32,
    mem: u32,
    /// `dev_t ac_tty` — controlling terminal, or -1.
    tty: u32,
    pid: i32,
    flag: u32,
}

const _: () = assert!(
    std::mem::size_of::<AcctRecord>() == ACCT_RECORD_SIZE,
    "the mirror of struct acct must stay 64 bytes — re-run the C probe in the module docs"
);

// Accounting flags, from <sys/acct.h>. AFORK means "forked, never exec'd", which
// is how a shell builtin (a `kill`, say) shows up: the record carries the shell's
// name, not a command name.
const AFORK: u32 = 0x0000_0001;
const AMAP: u32 = 0x0000_0004;
const ACORE: u32 = 0x0000_0008;
const AXSIG: u32 = 0x0000_0010;
const APLEDGE: u32 = 0x0000_0020;
const ATRAP: u32 = 0x0000_0040;
const AUNVEIL: u32 = 0x0000_0080;

/// One recorded process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Command name as the kernel recorded it (NUL-padded, 24 bytes at most).
    pub comm: String,
    pub pid: i32,
    pub uid: u32,
    /// Controlling terminal as the kernel recorded it: a `pts/N` name for an
    /// interactive session, `none` for a daemon or for a command run over a
    /// non-interactive SSH channel.
    pub tty: String,
    /// When the process started, in unix seconds.
    pub btime: i64,
    pub flag: u32,
}

impl Entry {
    /// How the process ended, in words.
    pub fn outcome(&self) -> String {
        let mut parts = Vec::new();
        if self.flag & AXSIG != 0 {
            parts.push("killed by a signal");
        }
        if self.flag & ACORE != 0 {
            parts.push("dumped core");
        }
        if self.flag & APLEDGE != 0 {
            parts.push("killed by pledge");
        }
        if self.flag & AUNVEIL != 0 {
            parts.push("killed by unveil");
        }
        if self.flag & ATRAP != 0 || self.flag & AMAP != 0 {
            parts.push("memory/syscall violation");
        }
        if self.flag & AFORK != 0 {
            parts.push("forked, no exec");
        }
        if parts.is_empty() {
            "normal exit".to_string()
        } else {
            parts.join(", ")
        }
    }

    /// One log line, stamped the way the rest of the log is (UTC).
    pub fn describe(&self) -> String {
        let when = time::OffsetDateTime::from_unix_timestamp(self.btime)
            .ok()
            .and_then(|t| {
                t.format(&time::format_description::well_known::Rfc3339).ok()
            })
            .unwrap_or_else(|| format!("btime={}", self.btime));
        format!(
            "{when} {} uid={} pid={} tty={} ({})",
            self.comm,
            self.uid,
            self.pid,
            self.tty,
            self.outcome()
        )
    }
}

/// The last `limit` records, oldest first. An empty file (or one that is all
/// partial records) yields an empty vector, not an error.
pub fn recent(path: &Path, limit: usize) -> std::io::Result<Vec<Entry>> {
    let mut file = std::fs::File::open(path)?;
    let size = file.metadata()?.len();
    // Records are appended in order, so the last complete record ends at EOF;
    // rounding down drops a record that is still being written.
    let complete = (size / ACCT_RECORD_SIZE as u64) as usize;
    let take = limit.min(complete);
    if take == 0 {
        return Ok(Vec::new());
    }
    file.seek(SeekFrom::Start(
        (complete - take) as u64 * ACCT_RECORD_SIZE as u64,
    ))?;
    let mut buf = vec![0u8; take * ACCT_RECORD_SIZE];
    file.read_exact(&mut buf)?;

    let mut entries = Vec::with_capacity(take);
    for chunk in buf.chunks_exact(ACCT_RECORD_SIZE) {
        // SAFETY: the record layout is asserted to be 64 bytes and the buffer is
        // exactly that per chunk; read_unaligned is used because a &[u8] has no
        // alignment guarantee.
        let record: AcctRecord = unsafe { std::ptr::read_unaligned(chunk.as_ptr().cast()) };
        let comm: String = record
            .comm
            .iter()
            .take_while(|b| **b != 0)
            .map(|b| *b as char)
            .collect();
        // dev_t: -1 means "no controlling terminal" — a daemon, or a command run
        // over a session that has no tty, which is how rcctl/su start things here.
        // Anything else is a terminal device and is logged raw: decoding the pts
        // number would need OpenBSD's dev_t layout, and the distinction that
        // matters in the log is terminal versus none.
        let tty = if record.tty == u32::MAX {
            "none".to_string()
        } else {
            format!("dev=0x{:08x}", record.tty)
        };
        entries.push(Entry {
            comm: comm.trim().to_string(),
            pid: record.pid,
            uid: record.uid,
            tty,
            btime: record.btime,
            flag: record.flag,
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_bytes(comm: &str, pid: i32, uid: u32, btime: i64, flag: u32) -> [u8; ACCT_RECORD_SIZE] {
        let mut record = AcctRecord {
            comm: [0; 24],
            utime: 0,
            stime: 0,
            etime: 0,
            io: 0,
            btime,
            uid,
            gid: 0,
            mem: 0,
            tty: u32::MAX,
            pid,
            flag,
        };
        let n = comm.len().min(record.comm.len() - 1);
        record.comm[..n].copy_from_slice(&comm.as_bytes()[..n]);
        let mut bytes = [0u8; ACCT_RECORD_SIZE];
        // SAFETY: both sides are ACCT_RECORD_SIZE bytes long.
        unsafe {
            std::ptr::copy_nonoverlapping(
                &record as *const AcctRecord as *const u8,
                bytes.as_mut_ptr(),
                ACCT_RECORD_SIZE,
            );
        }
        bytes
    }

    #[test]
    fn the_mirror_matches_the_record_the_kernel_writes() {
        assert_eq!(std::mem::size_of::<AcctRecord>(), ACCT_RECORD_SIZE);
        // the offsets the C probe printed, recomputed here
        let probes = [
            (std::mem::offset_of!(AcctRecord, comm), 0),
            (std::mem::offset_of!(AcctRecord, utime), 24),
            (std::mem::offset_of!(AcctRecord, btime), 32),
            (std::mem::offset_of!(AcctRecord, uid), 40),
            (std::mem::offset_of!(AcctRecord, pid), 56),
            (std::mem::offset_of!(AcctRecord, flag), 60),
        ];
        for (got, want) in probes {
            assert_eq!(got, want, "field offset drifted from struct acct");
        }
    }

    #[test]
    fn the_tail_is_read_oldest_first() {
        let path = std::env::temp_dir().join(format!("remgr-acct-test-{}", std::process::id()));
        let mut data = Vec::new();
        data.extend_from_slice(&record_bytes("rcctl", 4711, 0, 1_790_412_427, 0));
        data.extend_from_slice(&record_bytes("sh", 4712, 0, 1_790_412_428, AFORK));
        data.extend_from_slice(&record_bytes("reboot", 4713, 0, 1_790_412_429, AXSIG));
        std::fs::write(&path, &data).unwrap();

        let entries = recent(&path, 2).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 2, "only the tail was asked for");
        assert_eq!(entries[0].comm, "sh", "oldest first");
        assert_eq!(entries[1].comm, "reboot");
        assert_eq!(entries[0].pid, 4712);
        assert_eq!(entries[0].tty, "none", "u32::MAX in ac_tty means no terminal");
        assert_eq!(entries[1].uid, 0);
        assert_eq!(entries[1].btime, 1_790_412_429);
        assert_eq!(entries[1].outcome(), "killed by a signal");
        assert_eq!(entries[0].outcome(), "forked, no exec");
        assert!(entries[1].describe().starts_with("2026-09-26T"), "{}", entries[1].describe());
    }

    #[test]
    fn a_torn_record_at_the_end_is_ignored() {
        let path = std::env::temp_dir().join(format!("remgr-acct-torn-{}", std::process::id()));
        let mut data = record_bytes("rcctl", 1, 0, 1_790_412_427, 0).to_vec();
        data.extend_from_slice(&[0u8; 10]); // a record still being written
        std::fs::write(&path, &data).unwrap();
        let entries = recent(&path, 4).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(entries.len(), 1, "the partial record must be dropped");
        assert_eq!(entries[0].comm, "rcctl");
    }
}
