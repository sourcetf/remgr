use axum::{
    Router,
    extract::State,
    http::header,
    response::{IntoResponse, Response},
    routing,
};
use axum_embed::ServeEmbed;
use rust_embed::RustEmbed;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio_util::task::AbortOnDropHandle;

/// Embed assets for web dashboard, build frontend first
#[derive(RustEmbed, Clone)]
#[folder = "frontend/dist/"]
struct Assets;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ApiMetaResponse {
    api_host: String,
}

async fn handle_api_meta(State(api_host): State<Option<url::Url>>) -> impl IntoResponse {
    // When an explicit api_host is configured, emit it. Otherwise resolve the
    // *mount point* of this very script at runtime.
    //
    // `document.currentScript` is this response, so its directory is exactly
    // where the dashboard was mounted — `new URL('.', src)` yields the trailing
    // slash and the SPA's own `cleanUrl` trims it. That is the only value
    // correct in both deployment shapes: served standalone at `/` it gives the
    // bare origin, and when a host application reverse-proxies the dashboard
    // under a prefix — ReMgr serves it at `/et/` so it stays same-origin with
    // the console — it gives `origin/et`, which is where its API calls must
    // land. The bare origin would instead hit the host application's own router
    // and the SPA would never reach its API. The `location` fallback covers the
    // (unreachable in practice) case of `currentScript` being unavailable.
    let body = match api_host {
        Some(u) => format!(
            "window.apiMeta = {}",
            serde_json::to_string(&ApiMetaResponse {
                api_host: u.to_string()
            })
            .unwrap(),
        ),
        None => concat!(
            "window.apiMeta = {api_host: (function(){",
            "var s=document.currentScript&&document.currentScript.src;",
            "if(s){return new URL('.',s).href;}",
            "return window.location.origin+window.location.pathname;",
            "})()}"
        )
        .to_string(),
    };
    Response::builder()
        .header(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )
        .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
        .header(header::PRAGMA, "no-cache")
        .header(header::EXPIRES, "0")
        .body(body)
        .unwrap()
}

pub fn build_router(api_host: Option<url::Url>) -> Router {
    let service = ServeEmbed::<Assets>::new();
    let router = Router::new();

    // Always override /api_meta.js so the embedded frontend never falls back
    // to the public default host shipped inside frontend/dist.
    let router = router
        .route(
            "/api_meta.js",
            routing::get(handle_api_meta).with_state(api_host),
        );

    router.fallback_service(service)
}

pub struct WebServer {
    bind_addr: SocketAddr,
    router: Router,
    serve_task: Option<AbortOnDropHandle<()>>,
}

impl WebServer {
    pub async fn new(bind_addr: SocketAddr, router: Router) -> anyhow::Result<Self> {
        Ok(WebServer {
            bind_addr,
            router,
            serve_task: None,
        })
    }

    pub async fn start(self) -> Result<AbortOnDropHandle<()>, anyhow::Error> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        let app = self.router;

        let task = AbortOnDropHandle::new(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));

        Ok(task)
    }
}
