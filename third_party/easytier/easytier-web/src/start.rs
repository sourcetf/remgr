//! Embedded startup for the easytier-web stack.
//!
//! Mirrors what the binary's `main` does: open the sqlite db, start the
//! config server (instances register here), then the REST api server.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use easytier::tunnel::websocket::WsTunnelListener;
use easytier::{
    common::{
        network::{local_ipv4, local_ipv6},
    },
    proto::rpc::standalone::{runtime_rpc_listener, runtime_udp_tunnel_listener},
};
use easytier_core::{socket::SocketListener, tunnel::Tunnel};
use tokio_util::sync::CancellationToken;

use crate::client_manager::ClientManager;
use crate::db;
use crate::restful;
use crate::webhook::{WebhookConfig, SharedWebhookConfig};
use crate::FeatureFlags;

#[derive(Debug, Clone)]
pub struct WebConfig {
    pub db_path: String,
    /// "udp" (default) or "tcp"/"ws"
    pub config_server_protocol: String,
    pub config_server_port: u16,
    pub api_addr: IpAddr,
    pub api_port: u16,
    pub geoip_db: Option<String>,
    pub heartbeat_min_response_ms: u64,
    pub feature_flags: Arc<FeatureFlags>,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            db_path: "et.db".into(),
            config_server_protocol: "udp".into(),
            config_server_port: 22020,
            api_addr: "0.0.0.0".parse().unwrap(),
            api_port: 11211,
            geoip_db: None,
            heartbeat_min_response_ms: 0,
            feature_flags: Arc::new(FeatureFlags::default()),
        }
    }
}

pub struct RunningEasyTierWeb {
    /// Cancel to tear the whole stack down.
    pub token: CancellationToken,
    pub api_addr: SocketAddr,
    pub config_server_port: u16,
    /// db handle for console-side queries (e.g. default user bootstrap)
    pub db: db::Db,
}

fn get_listener_by_url(
    scheme: easytier::tunnel::IpScheme,
    l: &url::Url,
) -> Option<Box<dyn SocketListener<Accepted = Box<dyn Tunnel>>>> {
    Some(match scheme {
        easytier::tunnel::IpScheme::Tcp => {
            let addr = l.socket_addrs(|| Some(11010)).ok()?.into_iter().next()?;
            Box::new(runtime_rpc_listener(addr))
        }
        easytier::tunnel::IpScheme::Udp => {
            let addr = l.socket_addrs(|| Some(11010)).ok()?.into_iter().next()?;
            Box::new(runtime_udp_tunnel_listener(l.clone(), addr))
        }
        easytier::tunnel::IpScheme::Ws => Box::new(WsTunnelListener::new(l.clone())),
        _ => return None,
    })
}

async fn get_dual_stack_listener(
    protocol: &str,
    port: u16,
) -> Result<
    (
        Option<Box<dyn SocketListener<Accepted = Box<dyn Tunnel>>>>,
        Option<Box<dyn SocketListener<Accepted = Box<dyn Tunnel>>>>,
    ),
    easytier::common::error::Error,
> {
    let scheme = protocol
        .parse()
        .map_err(|_| easytier::common::error::Error::InvalidUrl(protocol.to_string()))?;
    let v6_listener =
        if local_ipv6().await.is_ok() && matches!(scheme, easytier::tunnel::IpScheme::Tcp | easytier::tunnel::IpScheme::Udp) {
            get_listener_by_url(
                scheme,
                &format!("{protocol}://[::]:{port}").parse().unwrap(),
            )
        } else {
            None
        };
    let v4_listener = if local_ipv4().await.is_ok() {
        get_listener_by_url(
            scheme,
            &format!("{protocol}://0.0.0.0:{port}").parse().unwrap(),
        )
    } else {
        None
    };
    Ok((v6_listener, v4_listener))
}

/// Start the embedded easytier-web stack. Returns immediately after the
/// servers are bound; drop/abort the returned token to stop.
pub async fn start_web(cfg: WebConfig) -> anyhow::Result<RunningEasyTierWeb> {
    let db = crate::db::Db::new(&cfg.db_path).await?;
    let feature_flags = cfg.feature_flags.clone();
    let webhook_config: SharedWebhookConfig = Arc::new(WebhookConfig::new(None, None, None, None, None));

    let mut mgr = crate::client_manager::ClientManager::new(
        db.clone(),
        cfg.geoip_db.clone(),
        Duration::from_millis(cfg.heartbeat_min_response_ms),
        feature_flags.clone(),
        webhook_config.clone(),
    );
    let (v6_listener, v4_listener) =
        get_dual_stack_listener(&cfg.config_server_protocol, cfg.config_server_port).await?;
    if v4_listener.is_none() && v6_listener.is_none() {
        anyhow::bail!("easytier-web config server: failed to listen on both stacks");
    }
    if let Some(l) = v6_listener {
        mgr.add_listener(l).await?;
    }
    if let Some(l) = v4_listener {
        mgr.add_listener(l).await?;
    }
    let mgr = Arc::new(mgr);

    let token = CancellationToken::new();

    let restful_server = crate::restful::RestfulServer::new(
        SocketAddr::new(cfg.api_addr, cfg.api_port),
        mgr,
        db.clone(),
        None,
        feature_flags,
        restful::oidc::OidcConfig::disabled(),
        webhook_config,
    )
    .await?;

    // Bind the REST api synchronously so bind failures surface here, then keep
    // the returned AbortOnDropHandles alive until shutdown is requested.
    // Dropping them tears down the axum server *and* the ClientManager they
    // hold, which also closes the config-server (udp) listener.
    let (api_task, delete_task) = restful_server.start().await?;
    let abort_token = token.clone();
    tokio::spawn(async move {
        abort_token.cancelled().await;
        drop(api_task);
        drop(delete_task);
    });

    tracing::info!(
        "easytier-web started: config_server={}:{}, api={}",
        cfg.config_server_protocol,
        cfg.config_server_port,
        SocketAddr::new(cfg.api_addr, cfg.api_port)
    );

    Ok(RunningEasyTierWeb {
        token,
        api_addr: SocketAddr::new(cfg.api_addr, cfg.api_port),
        config_server_port: cfg.config_server_port,
        db,
    })
}
