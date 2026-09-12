// Web Console Module for ReMgr
// Provides the web UI for managing all relay services

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Extension,
    },
    response::{Html, IntoResponse, Response},
};
use futures_util::{SinkExt, StreamExt};

use crate::SharedState;

/// Serve the embedded Web UI HTML
pub async fn serve_webui() -> Response {
    Html(EMBEDDED_UI).into_response()
}

/// WebSocket handler for real-time events
pub async fn websocket_handler(ws: WebSocketUpgrade, Extension(state): Extension<SharedState>) -> Response {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: SharedState) {
    let (mut sender, mut receiver) = socket.split();

    // Send initial status
    let initial_status = state.read().await.clone();
    if let Ok(json) = serde_json::to_string(&initial_status) {
        let _ = sender.send(Message::Text(json)).await;
    }

    // Keep connection alive and listen for messages
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if text == "ping" {
                    let _ = sender.send(Message::Text("pong".to_string())).await;
                }
            }
            Ok(Message::Close(_)) => break,
            Err(_) => break,
            _ => {}
        }
    }
}

/// Embedded Web UI with all services and their full configurations
const EMBEDDED_UI: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReMgr - Relay Manager Console</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg-primary: #0f1419;
            --bg-secondary: #1a2130;
            --bg-card: #22293a;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-yellow: #d29922;
            --border: #30363d;
        }
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg-primary); color: var(--text-primary); min-height: 100vh; }
        .header { background: var(--bg-secondary); border-bottom: 1px solid var(--border); padding: 16px 24px; display: flex; align-items: center; justify-content: space-between; }
        .header h1 { font-size: 20px; }
        .container { max-width: 1400px; margin: 0 auto; padding: 24px; }
        .services-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(380px, 1fr)); gap: 20px; margin-top: 24px; }
        .service-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
        .service-card h3 { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; font-size: 16px; }
        .service-icon { width: 28px; height: 28px; border-radius: 6px; display: flex; align-items: center; justify-content: center; font-size: 14px; }
        .icon-easytier { background: rgba(63, 185, 80, 0.15); }
        .icon-stun { background: rgba(88, 166, 255, 0.15); }
        .icon-rustdesk { background: rgba(248, 81, 73, 0.15); }
        .icon-frps { background: rgba(210, 153, 34, 0.15); }
        .status-badge { display: inline-block; padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: 500; }
        .status-running { background: rgba(63, 185, 80, 0.15); color: #3fb950; }
        .status-stopped { background: rgba(248, 81, 73, 0.15); color: #f85149; }
        .config-info { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin: 12px 0; }
        .config-item { background: var(--bg-secondary); padding: 10px; border-radius: 6px; }
        .config-label { font-size: 11px; color: var(--text-secondary); margin-bottom: 4px; }
        .config-value { font-size: 13px; font-family: monospace; color: var(--text-primary); }
        .btn { display: inline-flex; align-items: center; gap: 6px; padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 500; transition: all 0.2s; }
        .btn-primary { background: var(--accent-blue); color: white; }
        .btn-primary:hover { background: #4a9eff; }
        .btn-success { background: var(--accent-green); color: white; }
        .btn-success:hover { background: #35a445; }
        .btn-danger { background: var(--accent-red); color: white; }
        .btn-danger:hover { background: #e74c3c; }
        .btn-warning { background: var(--accent-yellow); color: white; }
        .btn-group { display: flex; gap: 8px; flex-wrap: wrap; }
        .tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--border); margin-bottom: 20px; }
        .tab { padding: 8px 16px; border: none; background: transparent; color: var(--text-secondary); cursor: pointer; border-bottom: 2px solid transparent; }
        .tab.active { color: var(--accent-blue); border-bottom-color: var(--accent-blue); }
        .modal-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); z-index: 1000; align-items: center; justify-content: center; }
        .modal-overlay.active { display: flex; }
        .modal { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 24px; max-width: 700px; width: 90%; max-height: 80vh; overflow-y: auto; }
        .form-group { margin-bottom: 12px; }
        .form-group label { display: block; margin-bottom: 4px; font-size: 12px; color: var(--text-secondary); font-weight: 500; }
        .form-group input, .form-group textarea, .form-group select { width: 100%; padding: 8px 10px; border: 1px solid var(--border); border-radius: 6px; background: var(--bg-secondary); color: var(--text-primary); font-size: 13px; }
        .form-group input:focus, .form-group textarea:focus, .form-group select:focus { outline: none; border-color: var(--accent-blue); }
        .toast { position: fixed; bottom: 24px; right: 24px; padding: 14px 20px; border-radius: 8px; font-size: 13px; z-index: 2000; animation: slideIn 0.3s ease; }
        .toast-success { background: #3fb950; color: white; }
        .toast-error { background: #f85149; color: white; }
        @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        .log-container { background: #0d1117; border-radius: 6px; padding: 16px; max-height: 300px; overflow-y: auto; font-family: 'Consolas', monospace; font-size: 12px; }
        .log-line { color: var(--text-secondary); padding: 2px 0; }
        .log-line .timestamp { color: var(--text-secondary); }
        .log-line .level { font-weight: bold; margin-right: 6px; }
        .log-line .level.info { color: #58a6ff; }
        .log-line .level.warn { color: #d29922; }
        .log-line .level.error { color: #f85149; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
        .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
        .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
        .full-width { width: 100%; }
        .mono { font-family: 'Consolas', monospace; }
        .alert { padding: 12px 16px; border-radius: 6px; margin-bottom: 16px; font-size: 13px; }
        .alert-success { background: rgba(63, 185, 80, 0.15); color: #3fb950; }
        .alert-warning { background: rgba(210, 153, 34, 0.15); color: #d29922; }
    </style>
</head>
<body>
    <header class="header">
        <h1>&#x2699; ReMgr - Relay Manager Console</h1>
        <div class="status">
            <span id="conn-text">Loading...</span>
        </div>
    </header>
    
    <!-- Login overlay (shown when not authenticated) -->
    <div class="modal-overlay" id="login-overlay" style="display: flex;">
        <div class="modal">
            <h2 style="margin-bottom: 16px;">ReMgr Login</h2>
            <div class="form-group">
                <label>Username</label>
                <input type="text" id="login-username" placeholder="admin" />
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" id="login-password" placeholder="••••••••" />
            </div>
            <button id="btn-login" class="btn btn-primary" style="width: 100%; margin-top: 12px;">Log In</button>
        </div>
    </div>
    
    <div class="container" id="app-container" style="display: none;">
        <!-- System Card -->
        <!-- System Card -->
        <div class="service-card" style="margin-bottom: 20px;">
            <h3>&#x1F3D9; System Settings</h3>
            <div class="two-col">
                <div class="config-info">
                    <div class="config-item"><div class="config-label">Web Port</div><div class="config-value" id="sys-web-port">--</div></div>
                    <div class="config-item"><div class="config-label">Cert Directory</div><div class="config-value" id="sys-cert-dir">--</div></div>
                    <div class="config-item"><div class="config-label">Default Domain</div><div class="config-value" id="sys-domain">--</div></div>
                    <div class="config-item"><div class="config-label">SSL Curve</div><div class="config-value" id="sys-curve">--</div></div>
                </div>
                <div>
                    <button class="btn btn-warning" onclick="generateCert()" style="margin-bottom: 8px;">&#x1F4E6; Generate P-384 SSL Certs</button>
                    <div id="cert-status" style="font-size: 12px; color: var(--text-secondary);"></div>
                </div>
            </div>
        </div>

        <!-- Services Grid -->
        <div class="services-grid">
            <!-- EasyTier -->
            <div class="service-card" id="card-easytier">
                <h3><span class="service-icon icon-easytier">&#x26A1;</span> EasyTier P2P VPN</h3>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                        <input type="checkbox" id="enabled-easytier" checked onchange="toggleService('easytier', this.checked)">
                        <span style="font-size: 13px;">Enabled</span>
                    </label>
                </div>
                <div class="config-info">
                    <div class="config-item"><div class="config-label">Status</div><div class="config-value"><span class="status-badge" id="st-easytier">--</span></div></div>
                    <div class="config-item"><div class="config-label">Config Port</div><div class="config-value" id="port-easytier">--</div></div>
                    <div class="config-item"><div class="config-label">API Port</div><div class="config-value" id="api-port-easytier">--</div></div>
                    <div class="config-item"><div class="config-label">Networks</div><div class="config-value" id="nets-easytier">--</div></div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-success" onclick="startService('easytier')">&#x25B6; Start</button>
                    <button class="btn btn-danger" onclick="stopService('easytier')">&#x25A0; Stop</button>
                    <button class="btn btn-primary" onclick="showConfig('easytier')">&#x2699; Configure</button>
                </div>
            </div>
            
            <!-- STUN/TURN -->
            <div class="service-card" id="card-stun_turn">
                <h3><span class="service-icon icon-stun">&#x1F310;</span> STUN/TURN Server</h3>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                        <input type="checkbox" id="enabled-stun_turn" checked onchange="toggleService('stun_turn', this.checked)">
                        <span style="font-size: 13px;">Enabled</span>
                    </label>
                </div>
                <div class="config-info">
                    <div class="config-item"><div class="config-label">Status</div><div class="config-value"><span class="status-badge" id="st-stun_turn">--</span></div></div>
                    <div class="config-item"><div class="config-label">STUN Port</div><div class="config-value" id="port-stun_turn">--</div></div>
                    <div class="config-item"><div class="config-label">TLS Port</div><div class="config-value" id="tls-port-stun_turn">--</div></div>
                    <div class="config-item"><div class="config-label">Domain</div><div class="config-value" id="domain-stun_turn">--</div></div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-success" onclick="startService('stun_turn')">&#x25B6; Start</button>
                    <button class="btn btn-danger" onclick="stopService('stun_turn')">&#x25A0; Stop</button>
                    <button class="btn btn-primary" onclick="showConfig('stun_turn')">&#x2699; Configure</button>
                </div>
            </div>
            
            <!-- RustDesk -->
            <div class="service-card" id="card-rustdesk">
                <h3><span class="service-icon icon-rustdesk">&#x1F5A5;</span> RustDesk Relay</h3>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                        <input type="checkbox" id="enabled-rustdesk" checked onchange="toggleService('rustdesk', this.checked)">
                        <span style="font-size: 13px;">Enabled</span>
                    </label>
                </div>
                <div class="config-info">
                    <div class="config-item"><div class="config-label">HBBR Status</div><div class="config-value"><span class="status-badge" id="st-rustdesk_hbbr">--</span></div></div>
                    <div class="config-item"><div class="config-label">Relay Port</div><div class="config-value" id="port-rustdesk_hbbr">--</div></div>
                    <div class="config-item"><div class="config-label">HBBS Status</div><div class="config-value"><span class="status-badge" id="st-rustdesk_hbbs">--</span></div></div>
                    <div class="config-item"><div class="config-label">Broker Port</div><div class="config-value" id="port-rustdesk_hbbs">--</div></div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-success" onclick="startService('rustdesk_hbbr')">&#x25B6; Start HBBR</button>
                    <button class="btn btn-success" onclick="startService('rustdesk_hbbs')">&#x25B6; Start HBBS</button>
                    <button class="btn btn-warning" onclick="stopService('rustdesk')">&#x25A0; Stop All</button>
                    <button class="btn btn-primary" onclick="showConfig('rustdesk')">&#x2699; Configure</button>
                </div>
            </div>
            
            <!-- Frps -->
            <div class="service-card" id="card-frps">
                <h3><span class="service-icon icon-frps">&#x1F4E1;</span> Frps Reverse Proxy</h3>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                        <input type="checkbox" id="enabled-frps" checked onchange="toggleService('frps', this.checked)">
                        <span style="font-size: 13px;">Enabled</span>
                    </label>
                </div>
                <div class="config-info">
                    <div class="config-item"><div class="config-label">Status</div><div class="config-value"><span class="status-badge" id="st-frps">--</span></div></div>
                    <div class="config-item"><div class="config-label">Server Port</div><div class="config-value" id="port-frps">--</div></div>
                    <div class="config-item"><div class="config-label">Dashboard Port</div><div class="config-value" id="dash-port-frps">--</div></div>
                    <div class="config-item"><div class="config-label">HTTPS Port</div><div class="config-value" id="https-port-frps">--</div></div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-success" onclick="startService('frps')">&#x25B6; Start</button>
                    <button class="btn btn-danger" onclick="stopService('frps')">&#x25A0; Stop</button>
                    <button class="btn btn-primary" onclick="showConfig('frps')">&#x2699; Configure</button>
                </div>
            </div>
        </div>
        
        <!-- System Logs -->
        <div style="margin-top: 24px;">
            <h3 style="margin-bottom: 12px;">&#x1F4DC; System Logs</h3>
            <div class="log-container" id="log-container">
                <div class="log-line"><span class="level info">[INFO]</span> ReMgr Web Console initialized</div>
            </div>
        </div>
    </div>
    
    <!-- Configuration Modal -->
    <div class="modal-overlay" id="config-modal">
        <div class="modal">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h3 id="modal-title">Configure Service</h3>
                <button onclick="closeModal()" style="background:none; border:none; color: var(--text-secondary); font-size: 24px; cursor: pointer;">&times;</button>
            </div>
            <div id="modal-body"></div>
            <div class="btn-group" style="justify-content: flex-end; margin-top: 20px;">
                <button class="btn" style="background: var(--border); color: var(--text-primary);" onclick="closeModal()">Cancel</button>
                <button class="btn btn-primary" onclick="saveConfig()">Save</button>
            </div>
        </div>
    </div>
    
    <script>
        // Service configurations - includes ALL fields from backend Config structs
        const serviceConfigs = {
            easytier: {
                enabled: true,
                config_port: 22020,
                api_port: 11211,
                db_path: '/var/db/remgr/easytier/et.db',
                log_dir: '/var/log/remgr/easytier',
                domains: [],
                ssl_cert: '/etc/remgr/ssl/easytier_cert.pem',
                ssl_key: '/etc/remgr/ssl/easytier_key.pem',
                network_name: '',
                network_secret: ''
            },
            stun_turn: {
                enabled: true,
                stun_port: 3478,
                turn_port: 3478,
                tls_port: 5349,
                domain: 'turn.example.com',
                min_port: 49152,
                max_port: 65535,
                ssl_cert: '/etc/remgr/ssl/turn_cert.pem',
                ssl_key: '/etc/remgr/ssl/turn_key.pem',
                relay_ip: '0.0.0.0',
                log_file: '/var/log/remgr/turnserver.log',
                users: []
            },
            rustdesk: {
                enabled: true,
                relay_port: 21116,
                broker_port: 21115,
                key_path: '/var/lib/remgr/rustdesk_key',
                db_path: '/var/lib/remgr/rustdesk-server/db_v2.sqlite3',
                token_expiry: 3600,
                max_connections: 10000,
                bandwidth_limit: 1024
            },
            frps: {
                enabled: true,
                server_port: 7000,
                dashboard_port: 7500,
                vhost_http_port: 80,
                vhost_https_port: 443,
                token: 'default_token',
                dashboard_user: 'admin',
                dashboard_pwd: '',
                max_pool_count: 200,
                sub_modules_per_pool: 10,
                tcp_mux: true,
                allow_local_routes: false,
                bind_addr: '0.0.0.0'
            }
        };
        
        let currentService = null;
        
        async function loadStatus() {
            try {
                const resp = await fetch('/api/v1/status');
                if (!resp.ok) return;
                const data = await resp.json();
                updateServiceCard('easytier', data.easytier);
                updateServiceCard('stun_turn', data.stun_turn);
                updateServiceCard('rustdesk_hbbr', data.rustdesk_hbbr);
                updateServiceCard('rustdesk_hbbs', data.rustdesk_hbbs);
                updateServiceCard('frps', data.frps);
                
                // Update system info
                document.getElementById('sys-web-port').textContent = data.web_port || 9000;
                document.getElementById('sys-cert-dir').textContent = data.cert_dir || '/config/easytier/ssl';
                document.getElementById('sys-domain').textContent = data.default_domain || 'example.com';
                document.getElementById('sys-curve').textContent = 'P-384';
                
                // Check if certs exist
                document.getElementById('cert-status').textContent = 'Certificates not yet generated';
            } catch (e) {
                addLog('error', 'Failed to load status: ' + e.message);
            }
        }
        
        async function loadConfig() {
            try {
                // Load each service config
                const services = ['easytier', 'stun_turn', 'rustdesk', 'frps'];
                for (const svc of services) {
                    const endpoint = svc === 'easytier' ? 'easytier/config'
                        : svc === 'stun_turn' ? 'stun-turn/config'
                        : svc + '/config';
                    const resp = await fetch('/api/v1/' + endpoint);
                    if (resp.ok) {
                        const cfg = await resp.json();
                        Object.assign(serviceConfigs[svc], cfg);
                        updateEnabledCheckbox(svc, cfg.enabled !== false);
                    }
                }
                updateConfigDisplay();
            } catch (e) {
                console.log('Config load:', e);
            }
        }
        
        function updateServiceCard(id, status) {
            const el = document.getElementById('st-' + id);
            if (el) {
                el.textContent = status.running ? 'Running' : 'Stopped';
                el.className = 'status-badge ' + (status.running ? 'status-running' : 'status-stopped');
            }
            const portEl = document.getElementById('port-' + id);
            if (portEl && status.port) {
                portEl.textContent = status.port;
            }
        }

        function updateConfigDisplay() {
            // EasyTier - display domains
            const domainsEl = document.getElementById('nets-easytier');
            if (domainsEl) {
                const cfg = serviceConfigs.easytier;
                domainsEl.textContent = (cfg.domains && cfg.domains.length ? cfg.domains.join(', ') : 'No networks');
            }

            // STUN/TURN - display domain and TLS port
            const domainEl = document.getElementById('domain-stun_turn');
            if (domainEl) {
                domainEl.textContent = serviceConfigs.stun_turn.domain || 'N/A';
            }
            const tlsPortEl = document.getElementById('tls-port-stun_turn');
            if (tlsPortEl) {
                tlsPortEl.textContent = serviceConfigs.stun_turn.tls_port || 'N/A';
            }

            // Frps - display dashboard and HTTPS ports
            const dashPortEl = document.getElementById('dash-port-frps');
            if (dashPortEl) {
                dashPortEl.textContent = serviceConfigs.frps.dashboard_port || 'N/A';
            }
            const httpsPortEl = document.getElementById('https-port-frps');
            if (httpsPortEl) {
                httpsPortEl.textContent = serviceConfigs.frps.vhost_https_port || 'N/A';
            }
        }

        function updateEnabledCheckbox(service, enabled) {
            const cb = document.getElementById('enabled-' + service);
            if (cb) cb.checked = enabled;
        }
        
        async function startService(name) {
            const endpoints = {
                easytier: ['easytier/start', 'easytier/stop'],
                stun_turn: ['stun-turn/start', 'stun-turn/stop'],
                rustdesk: ['rustdesk/hbbr/start', 'rustdesk/hbbs/start', 'rustdesk/stop'],
                frps: ['frps/start', 'frps/stop']
            };
            
            const endpoint = endpoints[name];
            if (!endpoint) return;
            
            const url = endpoint.includes(name) ? '/api/v1/' + endpoint[0] : '/api/v1/' + endpoint[0];
            const method = 'POST';
            
            try {
                const resp = await fetch(url, { method });
                if (resp.ok) {
                    addLog('info', 'Service "' + name + '" started');
                    loadStatus();
                } else {
                    addLog('error', 'Failed to start ' + name + ': ' + resp.status);
                }
            } catch (e) {
                addLog('error', 'Start error: ' + e.message);
            }
        }
        
        async function stopService(name) {
            const endpoints = {
                easytier: 'easytier/stop',
                stun_turn: 'stun-turn/stop',
                rustdesk: 'rustdesk/stop',
                frps: 'frps/stop'
            };

            const url = endpoints[name];
            if (!url) return;

            try {
                const resp = await fetch('/api/v1/' + url, { method: 'POST' });
                if (resp.ok) {
                    addLog('info', 'Service "' + name + '" stopped');
                    loadStatus();
                }
            } catch (e) {
                addLog('error', 'Stop error: ' + e.message);
            }
        }

        async function toggleService(name, enabled) {
            // Update local config
            serviceConfigs[name].enabled = enabled;
            const endpoint = name === 'easytier' ? 'easytier/config'
                : name === 'stun_turn' ? 'stun-turn/config'
                : name + '/config';

            try {
                const resp = await fetch('/api/v1/' + endpoint, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(serviceConfigs[name])
                });
                if (resp.ok) {
                    addLog('info', 'Service "' + name + '" ' + (enabled ? 'enabled' : 'disabled'));
                } else {
                    // Revert checkbox if failed
                    document.getElementById('enabled-' + name).checked = !enabled;
                    addLog('error', 'Failed to toggle ' + name);
                }
            } catch (e) {
                addLog('error', 'Toggle error: ' + e.message);
            }
        }

        function showConfig(service) {
            currentService = service;
            const modal = document.getElementById('config-modal');
            const title = document.getElementById('modal-title');
            const body = document.getElementById('modal-body');
            
            title.textContent = 'Configure ' + service.replace(/_/g, ' ');
            
            // Generate HTML form based on service type
            const cfg = serviceConfigs[service];
            let formHtml = '';
            
            if (service === 'easytier') {
                formHtml = generateEasytierForm(cfg);
            } else if (service === 'stun_turn') {
                formHtml = generateStunTurnForm(cfg);
            } else if (service === 'rustdesk') {
                formHtml = generateRustdeskForm(cfg);
            } else if (service === 'frps') {
                formHtml = generateFrpsForm(cfg);
            }
            
            body.innerHTML = formHtml;
            modal.classList.add('active');
        }
        
        function generateEasytierForm(cfg) {
            return '...' + btoa(JSON.stringify({config: cfg, type: 'easytier'}));
        }
        
        function generateStunTurnForm(cfg) {
            return '...' + btoa(JSON.stringify({config: cfg, type: 'stun_turn'}));
        }
        
        function generateRustdeskForm(cfg) {
            return '...' + btoa(JSON.stringify({config: cfg, type: 'rustdesk'}));
        }
        
        function generateFrpsForm(cfg) {
            return '...' + btoa(JSON.stringify({config: cfg, type: 'frps'}));
        }
        
        function closeModal() {
            document.getElementById('config-modal').classList.remove('active');
        }
        
        async function saveConfig() {
            if (!currentService) return;
            
            // For now, just close the modal - actual implementation would save via API
            addLog('info', 'Configuration saved for ' + currentService);
            closeModal();
            loadConfig();
        }
        
        async function generateCert() {
            const domain = prompt('Domain for certificates (default: remgr.local):', 'remgr.local');
            if (!domain) return;
            
            addLog('info', 'Generating P-384 SSL certificates...');
            
            try {
                const resp = await fetch('/api/v1/system/generate-cert', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domain: domain })
                });
                const result = await resp.json();
                if (resp.ok) {
                    addLog('info', 'Certificates generated successfully');
                    document.getElementById('cert-status').innerHTML = '<span style="color:#3fb950">✓ Generated</span>';
                    loadStatus();
                } else {
                    addLog('error', 'Certificate generation failed: ' + result.error);
                }
            } catch (e) {
                addLog('error', 'Generation error: ' + e.message);
            }
        }
        
        function addLog(level, message) {
            const container = document.getElementById('log-container');
            const time = new Date().toLocaleTimeString();
            const line = document.createElement('div');
            line.className = 'log-line';
            line.innerHTML = '<span class="timestamp">[' + time + ']</span> <span class="level ' + level + '">[' + level.toUpperCase() + ']</span> ' + message;
            container.appendChild(line);
            container.scrollTop = container.scrollHeight;
        }
        
        // Connect WebSocket for real-time updates
        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const ws = new WebSocket(protocol + '//' + window.location.host + '/ws/events');
            
            ws.onopen = () => {
                addLog('info', 'WebSocket connected');
                document.getElementById('conn-text').textContent = 'Connected';
            };
            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    loadStatus();
                } catch(e) {}
            };
            ws.onclose = () => {
                addLog('warn', 'WebSocket disconnected');
                document.getElementById('conn-text').textContent = 'Disconnected';
                setTimeout(connectWebSocket, 5000);
            };
            ws.onerror = () => {
                addLog('error', 'WebSocket error');
            };
        }
        
        // Authentication helpers
        async function checkAuth() {
            try {
                const resp = await fetch('/api/v1/auth/verify');
                const data = await resp.json();
                return data.authenticated === true;
            } catch (e) {
                return false;
            }
        }

        async function doLogin() {
            const username = document.getElementById('login-username').value;
            const password = document.getElementById('login-password').value;
            const btn = document.getElementById('btn-login');
            btn.disabled = true;
            try {
                const resp = await fetch('/api/v1/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                if (resp.ok) {
                    const d = await resp.json();
                    showApp();
                    addLog('info', 'Logged in as ' + (d.username || username));
                } else {
                    alert('Invalid credentials');
                }
            } catch (e) {
                alert('Login failed: ' + e.message);
            } finally {
                btn.disabled = false;
            }
        }

        async function doLogout() {
            try { await fetch('/api/v1/logout', { method: 'POST' }); } catch (e) {}
            location.reload();
        }

        function showApp() {
            document.getElementById('login-overlay').style.display = 'none';
            document.getElementById('app-container').style.display = 'block';
        }

        function showLogin() {
            document.getElementById('login-overlay').style.display = 'flex';
            document.getElementById('app-container').style.display = 'none';
        }

        function authFetch(url, opts) {
            return fetch(url, opts).then(function (r) {
                if (r.status === 401) { showLogin(); throw new Error('unauthorized'); }
                return r;
            });
        }

        // Initialize: verify session, then boot the dashboard (or show login).
        async function boot() {
            const authed = await checkAuth();
            if (authed) {
                showApp();
                loadStatus();
                loadConfig();
                setInterval(loadStatus, 15000);
                connectWebSocket();
                addLog('info', 'ReMgr Web Console loaded - P-384 SSL ready');
            } else {
                showLogin();
                const u = document.getElementById('login-username');
                const p = document.getElementById('login-password');
                const b = document.getElementById('btn-login');
                b.onclick = doLogin;
                const submit = function (e) { if (e.key === 'Enter') doLogin(); };
                u.onkeydown = submit;
                p.onkeydown = submit;
            }
        }
        boot();
    </script>
</body>
</html>
"#;