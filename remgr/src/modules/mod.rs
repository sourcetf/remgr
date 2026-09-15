//! Module framework: services run as tokio task trees inside this process.

use async_trait::async_trait;

pub mod easytier;
pub mod frps;
pub mod rustdesk;
pub mod stun_turn;

#[async_trait]
pub trait ServiceModule: Send + Sync {
    fn name(&self) -> &'static str;

    /// JSON summary for the console (status + current settings).
    async fn status(&self) -> serde_json::Value;

    /// Idempotent start.
    async fn start(&self) -> anyhow::Result<()>;

    /// Idempotent stop.
    async fn stop(&self) -> anyhow::Result<()>;

    /// Called after the config section changed; restart if running.
    async fn apply_config(&self) -> anyhow::Result<()>;
}

pub async fn restart_if_running(module: &dyn ServiceModule) -> anyhow::Result<()> {
    // Only bounce the module when it is running; config changes while stopped
    // take effect at the next start.
    let was_running = module
        .status()
        .await
        .get("running")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !was_running {
        return Ok(());
    }
    module.stop().await?;
    module.start().await
}
