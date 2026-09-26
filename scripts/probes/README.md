# Probes

Small C programs that establish facts this project depends on. They exist because
several load-bearing claims in the README and in the code comments are *measured*
rather than assumed — and a claim nobody can re-measure is just a story.

Build and run them where they belong: on the target (OpenBSD), as root, with the
service in the state the comment describes. Each one prints what it measured.

| probe | measures | backs |
|---|---|---|
| `siginfo.c` | what `kill(2)` puts in `siginfo_t` on OpenBSD (and where the fields are) | "OpenBSD does not report the sender": `si_code = 0` (`SI_USER`) with `si_pid = 0` for a signal from another process, from a shell, and from the process itself; `offsetof(siginfo_t, si_pid) == 16`, `si_uid == 20`, `sizeof == 136` — the libc crate's OpenBSD definition says 128 and reads offset 128, which is why `remgr/src/signals.rs` reads the fields itself |
| `acct-layout.c` | the size and field offsets of `struct acct`, plus the last records in the accounting file | `remgr/src/acct.rs`'s `#[repr(C)]` mirror and its size assertion (64 bytes; comm=0, btime=32, uid=40, pid=56, flag=60), and the tail format the daemon logs |
| `unveil-flag.c` | which access sets `AUNVEIL` in the accounting flags | the README's flag legend: opening a path outside a locked unveil set sets `U`, which is why remgr's own record carrying `-U` is normal and `dmesg` stays silent about it |
| `turn-allocation.c` | a TURN (RFC 5766) allocation over UDP, unauthenticated 401 then authenticated 200 | the STUN/TURN module: a successful allocation also proves the per-allocation counters the console reads |

```sh
cc -O1 -o /tmp/probe scripts/probes/siginfo.c && /tmp/probe
cc -O1 -o /tmp/acct  scripts/probes/acct-layout.c && /tmp/acct /var/account/acct
cc -O1 -o /tmp/uf    scripts/probes/unveil-flag.c && /tmp/uf
# TURN credentials come from [stun_turn].users in /etc/remgr/config.toml —
# never hard-coded here, and never committed:
cc -O1 -o /tmp/turn scripts/probes/turn-allocation.c -lcrypto
TURN_USER=... TURN_PASS=... /tmp/turn 127.0.0.1 3478
```

`turn-allocation.c` takes the credentials of a configured TURN user
(`[stun_turn].users`) as arguments or in `TURN_USER`/`TURN_PASS`, and holds the
allocation open for a few seconds so it can be seen in the console.
