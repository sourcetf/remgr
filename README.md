# ReMgr - Relay Manager

All-in-one relay server manager for OpenBSD.

## Features

- **EasyTier Center Server** - P2P VPN management server with web interface
- **STUN/TURN Server** - Native Rust implementation for NAT traversal
- **RustDesk Relay** - HBBR (relay) and HBBS (broker) server integration
- **Frps Server** - Fast Reverse Proxy server with dashboard

## Build (OpenBSD)

```bash
# Install Rust (if not already installed)
doas pkg_add rust

# Clone and build
git clone https://github.com/username/remgr.git
cd remgr
cargo build --release

# Or with pledge/unveil integrated (OpenBSD only)
cargo build --release --features openbsd
```

## Docker

```bash
docker build -t remgr .
docker run -d -p 9000:9000 remgr
```

## Usage

Start with default configuration:

```bash
./target/release/remgr
```

Access the web console at `http://<server-ip>:9000/`

## Configuration

Configuration is stored at `~/.config/remgr/config.toml`.

Example configuration:

```toml
web_port = 9000

[easytier]
config_port = 22020
api_port = 11211
db_path = "/var/db/remgr/easytier/et.db"

[stun_turn]
stun_port = 3478
domain = "turn.example.com"

[rustdesk]
relay_port = 21116
broker_port = 21115

[frps]
server_port = 7000
dashboard_port = 7500
token = "your-secret-token"
```

## BSD License

See LICENSE file for details.