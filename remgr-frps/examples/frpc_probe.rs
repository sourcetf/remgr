//! Dev tool for `remgr_frps::client` (the frpc side): drive a real frp client
//! session against a real frps and watch it work, without building the whole
//! ReMgr binary.
//!
//! Modes:
//!   --self-test                in-process end-to-end check: starts ReMgr's own
//!                              frps on 127.0.0.1:7001, a tcp echo service and a
//!                              udp echo service, an frpc pointing at it, then
//!                              pushes a tcp and a udp payload through the
//!                              upstream ports and asserts they arrive.
//!   --upstream HOST:PORT       talk to an external frps (default 127.0.0.1:7000)
//!   --token TOKEN              auth token (must match the upstream)
//!   --tls [--tls-ca FILE] [--server-name NAME]
//!                              wrap the connection in frp's 0x17+TLS handshake,
//!                              optionally verifying against a CA bundle
//!   --no-mux                   transport.tcpMux = false (separate work conns)
//!   --pool N                   transport.poolCount (default 5)
//!   --timeout SECS             connect/login timeout (default 10)
//!   --proxy "name tcp 127.0.0.1 8080 7001"   publish a local service (repeatable)
//!   --echo PORT                run a local tcp echo service on PORT
//!   --udp-echo PORT            run a local udp echo service on PORT
//!   --fetch PORT               connect to a port of the upstream and print the reply
//!   --udp-fetch PORT           same over udp
//!   --run SECS                 keep the session up for SECS, printing status
//!                              every 5s (default: until Ctrl-C)
//!   --quiet                    only print the status snapshot and errors
//!
//! Examples:
//!   frpc_probe --self-test
//!   frpc_probe --upstream 127.0.0.1:7000 --token secret --echo 8080 \
//!              --proxy "web tcp 127.0.0.1 8080 7001" --run 240
//!   frpc_probe --upstream 127.0.0.1:7000 --token secret --fetch 7001

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use remgr_frps::client::{FrpcClient, FrpcConfig, FrpcProxyConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

struct Args {
    upstream: String,
    token: String,
    tls: bool,
    tls_ca: Option<String>,
    server_name: String,
    tcp_mux: bool,
    pool: u32,
    timeout: u64,
    proxies: Vec<String>,
    echoes: Vec<u16>,
    udp_echoes: Vec<u16>,
    fetches: Vec<(u16, Option<String>)>,
    udp_fetches: Vec<(u16, Option<String>)>,
    run_secs: Option<u64>,
    self_test: bool,
    quiet: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            upstream: "127.0.0.1:7000".into(),
            token: String::new(),
            tls: false,
            tls_ca: None,
            server_name: String::new(),
            tcp_mux: true,
            pool: 5,
            timeout: 10,
            proxies: Vec::new(),
            echoes: Vec::new(),
            udp_echoes: Vec::new(),
            fetches: Vec::new(),
            udp_fetches: Vec::new(),
            run_secs: None,
            self_test: false,
            quiet: false,
        }
    }
}

fn parse_args() -> Result<Args> {
    let mut a = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = |name: &str| -> Result<String> {
            it.next().ok_or_else(|| anyhow!("{name} needs a value"))
        };
        match arg.as_str() {
            "--upstream" => a.upstream = value("--upstream")?,
            "--token" => a.token = value("--token")?,
            "--tls" => a.tls = true,
            "--tls-ca" => {
                a.tls = true;
                a.tls_ca = Some(value("--tls-ca")?);
            }
            "--server-name" => a.server_name = value("--server-name")?,
            "--no-mux" => a.tcp_mux = false,
            "--pool" => a.pool = value("--pool")?.parse()?,
            "--timeout" => a.timeout = value("--timeout")?.parse()?,
            "--proxy" => a.proxies.push(value("--proxy")?),
            "--echo" => a.echoes.push(value("--echo")?.parse()?),
            "--udp-echo" => a.udp_echoes.push(value("--udp-echo")?.parse()?),
            "--fetch" => {
                let port = value("--fetch")?.parse()?;
                a.fetches.push((port, None));
            }
            "--udp-fetch" => {
                let port = value("--udp-fetch")?.parse()?;
                a.udp_fetches.push((port, None));
            }
            "--run" => a.run_secs = Some(value("--run")?.parse()?),
            "--self-test" => a.self_test = true,
            "--quiet" => a.quiet = true,
            "--help" | "-h" => {
                println!("{}", HELP);
                std::process::exit(0);
            }
            other => bail!("unknown argument {other:?} (see --help)"),
        }
    }
    Ok(a)
}

const HELP: &str = "\
frpc_probe — drive remgr_frps::client against an frps

  --self-test                in-process end-to-end check (frps on 7001 + echo services)
  --upstream HOST:PORT       upstream frps (default 127.0.0.1:7000)
  --token TOKEN              auth token
  --tls [--tls-ca FILE] [--server-name NAME]
  --no-mux                   tcp_mux off (one TCP connection per work conn)
  --pool N                   transport.poolCount (default 5)
  --timeout SECS             connect/login timeout (default 10)
  --proxy \"name tcp 127.0.0.1 8080 7001\"   publish a local service (repeatable)
  --echo PORT                local tcp echo service
  --udp-echo PORT            local udp echo service
  --fetch PORT               connect to the upstream port and print the reply
  --udp-fetch PORT           same over udp
  --run SECS                 stay up for SECS seconds (default: until Ctrl-C)
  --quiet                    status snapshots only";

/// TCP echo service: replies with what it received, prefixed so the probe can
/// tell an echo from its own bytes.
async fn spawn_tcp_echo(port: u16) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    println!("tcp echo service on 127.0.0.1:{port}");
    tokio::spawn(async move {
        loop {
            let Ok((mut s, peer)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let mut out = format!("echo({peer}): ").into_bytes();
                            out.extend_from_slice(&buf[..n]);
                            if s.write_all(&out).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    Ok(())
}

async fn spawn_udp_echo(port: u16) -> Result<()> {
    let sock = UdpSocket::bind(("127.0.0.1", port)).await?;
    println!("udp echo service on 127.0.0.1:{port}");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else { break };
            let mut out = b"echo: ".to_vec();
            out.extend_from_slice(&buf[..n]);
            let _ = sock.send_to(&out, peer).await;
        }
    });
    Ok(())
}

/// Push a payload through an upstream port over tcp and print what comes back.
async fn fetch_tcp(port: u16, payload: &str) -> Result<()> {
    let mut s = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(("127.0.0.1", port)))
        .await
        .map_err(|_| anyhow!("timed out connecting to 127.0.0.1:{port}"))??;
    s.write_all(payload.as_bytes()).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut buf))
        .await
        .map_err(|_| anyhow!("timed out waiting for the tunnel reply"))??;
    println!(
        "FETCH tcp 127.0.0.1:{port} sent {:?} -> got {:?}",
        payload,
        String::from_utf8_lossy(&buf[..n])
    );
    Ok(())
}

async fn fetch_udp(port: u16, payload: &str) -> Result<()> {
    let sock = UdpSocket::bind(("127.0.0.1", 0)).await?;
    sock.connect(("127.0.0.1", port)).await?;
    sock.send(payload.as_bytes()).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(10), sock.recv(&mut buf))
        .await
        .map_err(|_| anyhow!("timed out waiting for the udp reply"))??;
    println!(
        "FETCH udp 127.0.0.1:{port} sent {:?} -> got {:?}",
        payload,
        String::from_utf8_lossy(&buf[..n])
    );
    Ok(())
}

async fn print_status(client: &FrpcClient, quiet: bool) {
    let st = client.status().await;
    if quiet {
        let proxies: Vec<String> = st
            .proxies
            .iter()
            .map(|p| {
                format!(
                    "{}={} in={} out={}{}",
                    p.name,
                    p.state,
                    p.bytes_in,
                    p.bytes_out,
                    if p.error.is_empty() { String::new() } else { format!(" err={:?}", p.error) }
                )
            })
            .collect();
        println!(
            "STATUS connected={} run_id={} uptime={}s logins={} work_conns={} in={} out={} proxies=[{}] last_error={:?}",
            st.connected,
            if st.run_id.is_empty() { "-" } else { &st.run_id },
            st.session_uptime_secs,
            st.total_logins,
            st.total_work_conns,
            st.bytes_in,
            st.bytes_out,
            proxies.join(", "),
            st.last_error
        );
        return;
    }
    println!("--- frpc status");
    println!(
        "  running={} connected={} upstream={} run_id={} tcp_mux={} tls={} uptime={}s",
        st.running,
        st.connected,
        st.upstream,
        if st.run_id.is_empty() { "-" } else { &st.run_id },
        st.tcp_mux,
        st.tls,
        st.session_uptime_secs
    );
    println!(
        "  logins={} work_conns={} bytes_in={} bytes_out={} last_error={:?}",
        st.total_logins, st.total_work_conns, st.bytes_in, st.bytes_out, st.last_error
    );
    for p in &st.proxies {
        println!(
            "  proxy {:<12} {:<4} {:<7} local={:<20} remote_port={} remote_addr={} conns={} in={} out={}{}",
            p.name,
            p.proxy_type,
            p.state,
            p.local_addr,
            p.remote_port,
            if p.remote_addr.is_empty() { "-" } else { &p.remote_addr },
            p.conns_total,
            p.bytes_in,
            p.bytes_out,
            if p.error.is_empty() { String::new() } else { format!(" error={:?}", p.error) }
        );
    }
}

fn config_from(args: &Args) -> Result<FrpcConfig> {
    let (host, port) = args
        .upstream
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("--upstream needs HOST:PORT"))?;
    let mut proxies: Vec<FrpcProxyConfig> = Vec::new();
    for (i, line) in args.proxies.iter().enumerate() {
        let p = FrpcProxyConfig::parse_line(line)
            .map_err(|e| anyhow!("--proxy #{} {line:?}: {e}", i + 1))?;
        proxies.push(p);
    }
    Ok(FrpcConfig {
        enabled: true,
        server_addr: host.to_string(),
        server_port: port.parse()?,
        token: args.token.clone(),
        tls: args.tls,
        trusted_ca_file: args.tls_ca.clone(),
        server_name: args.server_name.clone(),
        tcp_mux: args.tcp_mux,
        connect_timeout: args.timeout,
        pool_count: args.pool,
        proxies,
    })
}

fn main() -> Result<()> {
    let args = parse_args()?;
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,remgr_frps=debug"));
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async move {
        tracing_subscriber::fmt().with_env_filter(filter).with_target(true).init();
        if args.self_test {
            return self_test().await;
        }
        run_probe(args).await
    })
}

async fn run_probe(args: Args) -> Result<()> {
    for p in &args.echoes {
        spawn_tcp_echo(*p).await?;
    }
    for p in &args.udp_echoes {
        spawn_udp_echo(*p).await?;
    }
    for (p, _) in &args.fetches {
        println!("upstream port for tcp fetch: {p}");
    }
    for (p, _) in &args.udp_fetches {
        println!("upstream port for udp fetch: {p}");
    }

    let cfg = config_from(&args)?;
    println!(
        "frpc -> {}:{} tcp_mux={} tls={} proxies={:?}",
        cfg.server_addr,
        cfg.server_port,
        cfg.tcp_mux,
        cfg.tls,
        cfg.proxies.iter().map(|p| format!("{}({})", p.name, p.proxy_type)).collect::<Vec<_>>()
    );
    let client = Arc::new(FrpcClient::new(cfg));
    client.start().await?;

    // Give the upstream a moment to answer the registrations, then do the
    // requested round trips.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    for (port, payload) in &args.fetches {
        let payload = payload.clone().unwrap_or_else(|| "remgr-frpc-probe\n".into());
        if let Err(e) = fetch_tcp(*port, &payload).await {
            println!("FETCH tcp {port} FAILED: {e:#}");
        }
    }
    for (port, payload) in &args.udp_fetches {
        let payload = payload.clone().unwrap_or_else(|| "remgr-frpc-probe-udp\n".into());
        if let Err(e) = fetch_udp(*port, &payload).await {
            println!("FETCH udp {port} FAILED: {e:#}");
        }
    }
    print_status(&client, args.quiet).await;

    match args.run_secs {
        Some(secs) => {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
            while tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_secs(5)).await;
                print_status(&client, true).await;
            }
        }
        None => {
            println!("running until Ctrl-C (status every 5s)");
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => break,
                    _ = tick.tick() => print_status(&client, true).await,
                }
            }
        }
    }

    client.stop().await?;
    print_status(&client, args.quiet).await;
    Ok(())
}

/// In-process end-to-end check: ReMgr's own frps, two echo services, an frpc
/// through the tunnel. Exercises tcp and udp, the pooling, the crypto control
/// channel and the work-connection handshake without any external binary.
async fn self_test() -> Result<()> {
    let token = "probetoken";
    let mut srvs_cfg = remgr_frps::FrpsConfig::default();
    srvs_cfg.server_port = 7001;
    srvs_cfg.token = token.into();
    let srv = Arc::new(remgr_frps::FrpsServer::new(srvs_cfg));
    srv.start().await?;
    spawn_tcp_echo(18080).await?;
    spawn_udp_echo(18081).await?;

    let cfg = FrpcConfig {
        enabled: true,
        server_addr: "127.0.0.1".into(),
        server_port: 7001,
        token: token.into(),
        tls: false,
        trusted_ca_file: None,
        server_name: String::new(),
        tcp_mux: true,
        connect_timeout: 10,
        pool_count: 3,
        proxies: vec![
            FrpcProxyConfig {
                name: "echo-tcp".into(),
                proxy_type: "tcp".into(),
                local_ip: "127.0.0.1".into(),
                local_port: 18080,
                remote_port: 17080,
            },
            FrpcProxyConfig {
                name: "echo-udp".into(),
                proxy_type: "udp".into(),
                local_ip: "127.0.0.1".into(),
                local_port: 18081,
                remote_port: 17081,
            },
        ],
    };
    let client = Arc::new(FrpcClient::new(cfg));
    client.start().await?;

    let mut failures = 0;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let st = client.status().await;
        if st.connected && st.proxies.iter().all(|p| p.state == "running") {
            break;
        }
    }
    print_status(&client, false).await;

    let sent = AtomicU64::new(0);
    for i in 0..3 {
        let payload = format!("tcp-payload-{i}\n");
        let mut s = TcpStream::connect(("127.0.0.1", 17080u16)).await?;
        s.write_all(payload.as_bytes()).await?;
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await??;
        let reply = String::from_utf8_lossy(&buf[..n]).to_string();
        let ok = reply.contains(&payload);
        println!("SELFTEST tcp #{i}: {ok} {reply:?}");
        if !ok {
            failures += 1;
        }
        sent.fetch_add(payload.len() as u64, Ordering::Relaxed);
    }

    for i in 0..3 {
        let payload = format!("udp-payload-{i}\n");
        let sock = UdpSocket::bind(("127.0.0.1", 0)).await?;
        sock.connect(("127.0.0.1", 17081u16)).await?;
        sock.send(payload.as_bytes()).await?;
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                let reply = String::from_utf8_lossy(&buf[..n]).to_string();
                let ok = reply.contains(&payload);
                println!("SELFTEST udp #{i}: {ok} {reply:?}");
                if !ok {
                    failures += 1;
                }
            }
            other => {
                println!("SELFTEST udp #{i}: timeout/error {other:?}");
                failures += 1;
            }
        }
    }

    print_status(&client, false).await;
    let st = client.status().await;
    println!(
        "SELFTEST totals: bytes_in={} bytes_out={} work_conns={} logins={}",
        st.bytes_in, st.bytes_out, st.total_work_conns, st.total_logins
    );
    if st.bytes_in == 0 || st.bytes_out == 0 {
        println!("SELFTEST FAILED: counters did not move");
        failures += 1;
    }

    // The console path: an edit while running must be adopted without a
    // stop/start from the caller (update_config signals the live session).
    println!("SELFTEST update_config: adding a second tcp proxy to the live session");
    let mut cfg2 = client.config().await;
    cfg2.proxies.push(FrpcProxyConfig {
        name: "echo-tcp2".into(),
        proxy_type: "tcp".into(),
        local_ip: "127.0.0.1".into(),
        local_port: 18080,
        remote_port: 17082,
    });
    client.update_config(cfg2).await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let st = client.status().await;
    let new_up = st.proxies.iter().any(|p| p.name == "echo-tcp2" && p.state == "running");
    let old_up = st.proxies.iter().any(|p| p.name == "echo-tcp" && p.state == "running");
    println!("SELFTEST update_config: new proxy running={new_up} old proxy still running={old_up}");
    if !new_up || !old_up {
        failures += 1;
    } else {
        // and it really carries traffic
        let mut s = TcpStream::connect(("127.0.0.1", 17082u16)).await?;
        s.write_all(b"after-update\n").await?;
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await??;
        let reply = String::from_utf8_lossy(&buf[..n]).to_string();
        println!("SELFTEST update_config: fetch through the new proxy -> {reply:?}");
        if !reply.contains("after-update") {
            failures += 1;
        }
    }

    // Stop/start must come back up (the console's stop then start).
    client.stop().await?;
    client.start().await?;
    tokio::time::sleep(Duration::from_millis(2000)).await;
    let st = client.status().await;
    println!(
        "SELFTEST restart: connected={} running={} proxies_running={}",
        st.connected,
        st.running,
        st.proxies.iter().filter(|p| p.state == "running").count()
    );
    if !st.connected || !st.running || st.proxies.iter().any(|p| p.state != "running") {
        failures += 1;
    }

    client.stop().await?;
    srv.stop().await?;
    if failures == 0 {
        println!("SELFTEST PASS");
        Ok(())
    } else {
        bail!("SELFTEST FAILED ({failures} checks)")
    }
}
