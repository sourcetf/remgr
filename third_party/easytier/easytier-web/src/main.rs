//! easytier-web binary — thin CLI wrapper around the embeddable library.

#[macro_use]
extern crate rust_i18n;

use std::sync::Arc;

use clap::Parser;
use easytier::common::{
    config::{ConsoleLoggerConfig, FileLoggerConfig, LoggingConfigLoader},
    constants::EASYTIER_VERSION,
    log,
    utils::panic::setup_panic_handler,
};

use easytier_web::start::{self, WebConfig};
use easytier_web::FeatureFlags;

rust_i18n::i18n!("locales", fallback = "en");

#[global_allocator]
static GLOBAL_MIMALLOC: mimalloc::MiMalloc = MiMalloc;

#[derive(Parser, Debug)]
#[command(name = "easytier-web", author, version = EASYTIER_VERSION, about, long_about = None)]
struct Cli {
    #[arg(
        short,
        long,
        env = "ET_WEB_DB",
        default_value = "et.db",
        help = t!("cli.db").to_string()
    )]
    db: String,

    #[arg(
        long,
        env = "ET_WEB_CONSOLE_LOG_LEVEL",
        help = t!("cli.console_log_level").to_string()
    )]
    console_log_level: Option<String>,

    #[arg(
        long,
        env = "ET_WEB_FILE_LOG_LEVEL",
        help = t!("cli.file_log_level").to_string()
    )]
    file_log_level: Option<String>,

    #[arg(
        long,
        env = "ET_WEB_FILE_LOG_DIR",
        help = t!("cli.file_log_dir").to_string()
    )]
    file_log_dir: Option<String>,

    #[arg(
        long,
        short = 'c',
        env = "ET_CONFIG_SERVER_PORT",
        default_value = "22020",
        help = t!("cli.config_server_port").to_string()
    )]
    config_server_port: u16,

    #[arg(
        long,
        short = 'p',
        env = "ET_CONFIG_SERVER_PROTOCOL",
        default_value = "udp",
        help = t!("cli.config_server_protocol").to_string()
    )]
    config_server_protocol: String,

    #[arg(
        long,
        short = 'a',
        env = "ET_API_SERVER_PORT",
        default_value = "11211",
        help = t!("cli.api_server_port").to_string()
    )]
    api_server_port: u16,

    #[arg(
        long,
        env = "ET_API_SERVER_ADDR",
        default_value = "0.0.0.0",
        help = t!("cli.api_server_addr").to_string()
    )]
    api_server_addr: std::net::IpAddr,

    #[arg(
        long,
        env = "ET_GEOIP_DB",
        help = t!("cli.geoip_db").to_string()
    )]
    geoip_db: Option<String>,

    #[arg(
        long,
        env = "ET_HEARTBEAT_MIN_RESPONSE_MS",
        default_value = "0",
        help = t!("cli.heartbeat_min_response_ms").to_string()
    )]
    heartbeat_min_response_ms: u64,

    #[arg(
        long,
        env = "ET_DISABLE_REGISTRATION",
        default_value = "false",
        help = t!("cli.disable_registration").to_string()
    )]
    disable_registration: bool,

    #[arg(
        long,
        env = "ET_ALLOW_AUTO_CREATE_USER",
        default_value = "false",
        help = t!("cli.allow_auto_create_user").to_string()
    )]
    allow_auto_create_user: bool,
}

impl LoggingConfigLoader for &Cli {
    fn get_console_logger_config(&self) -> ConsoleLoggerConfig {
        ConsoleLoggerConfig {
            level: self.console_log_level.clone(),
        }
    }

    fn get_file_logger_config(&self) -> FileLoggerConfig {
        FileLoggerConfig {
            dir: self.file_log_dir.clone(),
            level: self.file_log_level.clone(),
            file: None,
            size_mb: None,
            count: None,
        }
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let locale = sys_locale::get_locale().unwrap_or_else(|| String::from("en-US"));
    rust_i18n::set_locale(&locale);
    setup_panic_handler();

    let cli = Cli::parse();
    log::init(&cli, false).unwrap();

    let running = start::start_web(WebConfig {
        db_path: cli.db.clone(),
        config_server_protocol: cli.config_server_protocol.clone(),
        config_server_port: cli.config_server_port,
        api_addr: cli.api_server_addr,
        api_port: cli.api_server_port,
        geoip_db: cli.geoip_db.clone(),
        heartbeat_min_response_ms: cli.heartbeat_min_response_ms,
        feature_flags: Arc::new(FeatureFlags {
            disable_registration: cli.disable_registration,
            allow_auto_create_user: cli.allow_auto_create_user,
        }),
    })
    .await
    .unwrap();

    log::info!(
        "easytier-web listening: api={}",
        running.api_addr
    );

    tokio::signal::ctrl_c().await.unwrap();
}
