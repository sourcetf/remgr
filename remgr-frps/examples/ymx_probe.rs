//! Standalone frps on a spare port (7001) with tracing, used to reproduce and
//! verify wire behaviour against a real frpc. Also runs a small self-test of the
//! UDP packet shape frpc sends.
fn main() -> anyhow::Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,remgr_frps=debug"));
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async move {
        tracing_subscriber::fmt().with_env_filter(filter).with_target(true).init();

        let sample = r#"{"c":"ARMAOCESpEJAQUJDREVGR0hJSksACQAEAAAEAQAVACBmODFlMzMzOWFhZjhkYjU5ZDg5YWZmMjgzN2I3MmI1MwAUAAVyZW1ncgAAAA==","r":{"IP":"127.0.0.1","Port":24653,"Zone":""}}"#;
        match serde_json::from_str::<remgr_frps::msg::UdpPacket>(sample) {
            Ok(p) => println!(
                "SELFTEST udp packet: parse OK, remote={:?}, content_len={:?}",
                p.remote_socket_addr(),
                p.content().map(|c| c.len())
            ),
            Err(e) => println!("SELFTEST udp packet: parse FAILED: {e}"),
        }

        let mut cfg = remgr_frps::FrpsConfig::default();
        cfg.server_port = 7001;
        cfg.token = std::env::var("PROBE_TOKEN").unwrap_or_else(|_| "probetoken".into());
        let srv = std::sync::Arc::new(remgr_frps::FrpsServer::new(cfg));
        srv.start().await?;
        println!("probe frps listening on 7001");
        tokio::signal::ctrl_c().await?;
        srv.stop().await?;
        Ok(())
    })
}
