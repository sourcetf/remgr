// Web Console Module for ReMgr
// Provides the web UI for managing all relay services

use axum::{
    extract::{ws::{WebSocketUpgrade, WebSocket, Message}, State, Extension, WebSocketUpgrade as WS},
    http::{StatusCode, HeaderMap},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use std::sync::Arc;
use parking_lot::RwLock;

use crate::{SharedState, ManagerState, web_console::websocket_handler};

/// Serve the embedded Web UI HTML
pub async fn serve_webui() -> Response {
    Html(EMBEDDED_UI).into_response()
}

/// Authentication middleware
pub async fn auth_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    // Check if the request is for a static resource or API auth endpoint
    let path = req.uri().path();
    if path.starts_with("/api/v1/login") 
        || path.starts_with("/api/v1/auth/captcha")
        || path.starts_with("/ws/")
    {
        return next.run(req).await;
    }
    
    // TODO: Implement proper session-based authentication
    // For now, allow all requests (to be secured later)
    next.run(req).await
}

/// WebSocket handler for real-time events
pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    Extension(state): Extension<SharedState>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: SharedState) {
    let (mut sender, mut receiver) = socket.split();
    
    // Send initial status
    let initial_status = ManagerState {
        easytier: state.read().easytier.clone(),
        stun_turn: state.read().stun_turn.clone(),
        rustdesk_hbbr: state.read().rustdesk_hbbr.clone(),
        rustdesk_hbbs: state.read().rustdesk_hbbs.clone(),
        frps: state.read().frps.clone(),
    };
    
    if let Ok(json) = serde_json::to_string(&initial_status) {
        let _ = sender.send(Message::Text(json)).await;
    }
    
    // Keep connection alive and listen for messages
    while let Some(Ok(msg)) = receiver.recv().await {
        // Handle client messages (ping, commands, etc.)
        match msg {
            Message::Text(text) => {
                if text == "ping" {
                    let _ = sender.send(Message::Text("pong".to_string())).await;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
}

/// Status endpoint handler
pub async fn get_status(Extension(state): Extension<SharedState>) -> Json<ManagerState> {
    state.read().clone()
}

/// Embedded Web UI
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
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }
        .header {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border);
            padding: 16px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .header h1 {
            font-size: 24px;
            color: var(--accent-blue);
        }
        .header .status {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--accent-green);
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 24px;
        }
        .services-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 24px;
            margin-top: 24px;
        }
        .service-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }
        .service-card h3 {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 16px;
            font-size: 18px;
        }
        .service-icon {
            width: 32px;
            height: 32px;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
        }
        .icon-easytier { background: rgba(63, 185, 80, 0.15); }
        .icon-stun { background: rgba(88, 166, 255, 0.15); }
        .icon-rustdesk { background: rgba(248, 81, 73, 0.15); }
        .icon-frps { background: rgba(210, 153, 34, 0.15); }
        .status-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 500;
        }
        .status-running { background: rgba(63, 185, 80, 0.15); color: var(--accent-green); }
        .status-stopped { background: rgba(248, 81, 73, 0.15); color: var(--accent-red); }
        .status-unknown { background: rgba(139, 148, 158, 0.15); color: var(--text-secondary); }
        .config-info {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin: 16px 0;
        }
        .config-item {
            background: var(--bg-secondary);
            padding: 12px;
            border-radius: 6px;
        }
        .config-label {
            font-size: 12px;
            color: var(--text-secondary);
            margin-bottom: 4px;
        }
        .config-value {
            font-size: 14px;
            font-weight: 500;
        }
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.2s;
        }
        .btn-primary { background: var(--accent-blue); color: white; }
        .btn-primary:hover { background: #4a9eff; }
        .btn-success { background: var(--accent-green); color: white; }
        .btn-success:hover { background: #35a445; }
        .btn-danger { background: var(--accent-red); color: white; }
        .btn-danger:hover { background: #e74c3d; }
        .btn-warning { background: var(--accent-yellow); color: white; }
        .btn-group {
            display: flex;
            gap: 8px;
            margin-top: 16px;
        }
        .tabs {
            display: flex;
            gap: 4px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 20px;
        }
        .tab {
            padding: 8px 16px;
            border: none;
            background: transparent;
            color: var(--text-secondary);
            cursor: pointer;
            border-bottom: 2px solid transparent;
        }
        .tab.active { color: var(--accent-blue); border-bottom-color: var(--accent-blue); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .modal-overlay {
            display: none;
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.7);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        .modal-overlay.active { display: flex; }
        .modal {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            max-width: 600px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
        }
        .form-group { margin-bottom: 16px; }
        .form-group label {
            display: block;
            margin-bottom: 6px;
            font-size: 14px;
            color: var(--text-secondary);
        }
        .form-group input,
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid var(--border);
            border-radius: 6px;
            background: var(--bg-secondary);
            color: var(--text-primary);
            font-size: 14px;
        }
        .form-group input:focus,
        .form-group select:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: var(--accent-blue);
        }
        .toast {
            position: fixed;
            bottom: 24px;
            right: 24px;
            padding: 14px 20px;
            border-radius: 8px;
            font-size: 14px;
            z-index: 2000;
            animation: slideIn 0.3s ease;
        }
        .toast-success { background: var(--accent-green); color: white; }
        .toast-error { background: var(--accent-red); color: white; }
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        .log-container {
            background: #0d1117;
            border-radius: 6px;
            padding: 16px;
            max-height: 400px;
            overflow-y: auto;
            font-family: 'Consolas', monospace;
            font-size: 13px;
        }
        .log-line { color: var(--text-secondary); padding: 2px 0; }
        .log-line .timestamp { color: var(--text-secondary); }
        .log-line .level { font-weight: bold; margin-right: 8px; }
        .log-line .level.info { color: var(--accent-blue); }
        .log-line .level.warn { color: var(--accent-yellow); }
        .log-line .level.error { color: var(--accent-red); }
    </style>
</head>
<body>
    <header class="header">
        <h1>&#x2699; ReMgr - Relay Manager</h1>
        <div class="status">
            <div class="status-dot" id="conn-dot"></div>
            <span id="conn-text">Connected</span>
        </div>
    </header>
    
    <div class="container">
        <!-- Services Grid -->
        <div class="services-grid">
            <!-- EasyTier -->
            <div class="service-card" id="card-easytier">
                <h3><span class="service-icon icon-easytier">&#x26A1;</span> EasyTier P2P VPN</h3>
                <div class="config-info">
                    <div class="config-item">
                        <div class="config-label">Status</div>
                        <div class="config-value"><span class="status-badge" id="st-easytier">--</span></div>
                    </div>
                    <div class="config-item">
                        <div class="config-label">Config Port</div>
                        <div class="config-value" id="port-easytier">--</div>
                    </div>
                    <div class="config-item">
                        <div class="config-label">API Port</div>
                        <div class="config-value" id="api-port-easytier">--</div>
                    </div>
                    <div class="config-item">
                        <div class="config-label">Networks</div>
                        <div class="config-value" id="nets-easytier">--</div>
                    </div>
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
                <div class="config-info">
                    <div class="config-item">
                        <div class="config-label">Status</div>
                        <div class="config-value"><span class="status-badge" id="st-stun_turn">--</span></div>
                    </div>
                    <div class="config-item">
                        <div class="config-label">STUN Port</div>
                        <div class="config-value" id="port-stun_turn">--</div>
                    </div>
                    <div class="config-item">
                        <div class="config-label">Domain</div>
                        <div class="config-value" id="domain-stun_turn">--</div>
                    </div>
                    <div class="config-item">
                        <div class="config-label">TLS Port</div>
                        <div class="config-value" id="tls-port-stun_turn">--</div>
                    </div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-success" onclick="startService('stun_turn')">&#x25B6; Start</button>
                    <button class="btn btn-danger" onclick="stopService('stun_turn')">&#x25A0; Stop</button>
                    <button class="btn btn-primary" onclick="showConfig('stun_turn')">&#x2699; Configure</button>
                </div>
            </div>
            
            <!-- RustDesk HBBR -->
            <div class="service-card" id="card-rustdesk">
                <h3><span class="service-icon icon-rustdesk">&#x1F5A5;</span> RustDesk Relay</h3>
                <div class="config-info">
                    <div class="config-item">
                        <div class="config-label">Relay Status</div>
                        <div class="config-value"><span class="status-badge" id="st-rustdesk_hbbr">--</span></div>
                    </div>
                    <div class="config-item">
                        <div class="config-label">Relay Port</div>
                        <div class="config-value" id="port-rustdesk_hbbr">--</div>
                    </div>
                    <div class="config-item">
                        <div class="config-label">Broker Status</div>
                        <div class="config-value"><span class="status-badge" id="st-rustdesk_hbbs">--</span></div>
                    </div>
                    <div class="config-item">
                        <div class="config-label">Broker Port</div>
                        <div class="config-value" id="port-rustdesk_hbbs">--</div>
                    </div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-success" onclick="startService('rustdesk_hbbr')">&#x25B6; Start HBBR</button>
                    <button class="btn btn-success" onclick="startService('rustdesk_hbbs')">&#x25B6; Start HBBS</button>
                    <button class="btn btn-danger" onclick="stopService('rustdesk_hbbr')">&#x25A0; Stop All</button>
                    <button class="btn btn-primary" onclick="showConfig('rustdesk')">&#x2699; Configure</button>
                </div>
            </div>
            
            <!-- Frps -->
            <div class="service-card" id="card-frps">
                <h3><span class="service-icon icon-frps">&#x1F4E1;</span> Frps Reverse Proxy</h3>
                <div class="config-info">
                    <div class="config-item">
                        <div class="config-label">Status</div>
                        <div class="config-value"><span class="status-badge" id="st-frps">--</span></div>
                    </div>
                    <div class="config-item">
                        <div class="config-label">Server Port</div>
                        <div class="config-value" id="port-frps">--</div>
                    </div>
                    <div class="config-item">
                        <div class="config-label">Dashboard Port</div>
                        <div class="config-value" id="dash-port-frps">--</div>
                    </div>
                    <div class="config-item">
                        <div class="config-label">Clients</div>
                        <div class="config-value" id="clients-frps">--</div>
                    </div>
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
                <div class="log-line"><span class="level info">[INFO]</span> ReMgr initialized, monitoring services...</div>
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
        let serviceConfigs = {
            easytier: {
                config_port: 22020,
                api_port: 11211,
                db_path: '/var/db/easytier/et.db',
                log_dir: '/var/log/easytier',
                domains: [],
                network_name: '',
                network_secret: ''
            },
            stun_turn: {
                stun_port: 3478,
                tls_port: 5349,
                domain: '',
                min_port: 49152,
                max_port: 65535,
                ssl_cert: '',
                ssl_key: ''
            },
            rustdesk: {
                relay_port: 21116,
                broker_port: 21115,
                key_path: '/root/rustdesk_key',
                db_path: '/var/lib/rustdesk-server/db_v2.sqlite3'
            },
            frps: {
                server_port: 7000,
                dashboard_port: 7500,
                vhost_http_port: 80,
                token: '',
                dashboard_user: 'admin'
            }
        };
        
        let currentService = null;
        
        async function loadStatus() {
            try {
                const resp = await fetch('/api/v1/status');
                if (!resp.ok) return;
                const data = await resp.json();
                
                // Update all service statuses
                updateServiceCard('easytier', data.easytier);
                updateServiceCard('stun_turn', data.stun_turn);
                updateServiceCard('rustdesk_hbbr', data.rustdesk_hbbr);
                updateServiceCard('rustdesk_hbbs', data.rustdesk_hbbs);
                updateServiceCard('frps', data.frps);
            } catch (e) {
                console.error('Status load error:', e);
            }
        }
        
        function updateServiceCard(id, status) {
            const el = document.getElementById(`st-${id}`);
            if (el) {
                el.textContent = status.running ? 'Running' : 'Stopped';
                el.className = 'status-badge ' + (status.running ? 'status-running' : 'status-stopped');
            }
            
            const portEl = document.getElementById(`port-${id}`);
            if (portEl && status.port) {
                portEl.textContent = status.port;
            }
        }
        
        async function startService(name) {
            try {
                const resp = await fetch(`/api/v1/${name}/start`, { method: 'POST' });
                if (resp.ok) {
                    addLog('info', `Service '${name}' started successfully`);
                    loadStatus();
                } else {
                    addLog('error', `Failed to start '${name}': ${resp.status}`);
                }
            } catch (e) {
                addLog('error', `Start error: ${e.message}`);
            }
        }
        
        async function stopService(name) {
            try {
                const resp = await fetch(`/api/v1/${name}/stop`, { method: 'POST' });
                if (resp.ok) {
                    addLog('info', `Service '${name}' stopped`);
                    loadStatus();
                }
            } catch (e) {
                addLog('error', `Stop error: ${e.message}`);
            }
        }
        
        function showConfig(service) {
            currentService = service;
            const modal = document.getElementById('config-modal');
            const title = document.getElementById('modal-title');
            const body = document.getElementById('modal-body');
            
            title.textContent = `Configure ${service.replace(/_/g, ' ')}`;
            
            let formHtml = '<div class="form-group"><label>Service Configuration (JSON)</label>';
            formHtml += `<textarea id="config-json" rows="15" style="width:100%; font-family:monospace; background:var(--bg-secondary); color:var(--text-primary); border:1px solid var(--border); border-radius:6px; padding:12px;">${JSON.stringify(serviceConfigs[service], null, 2)}</textarea></div>`;
            body.innerHTML = formHtml;
            modal.classList.add('active');
        }
        
        function closeModal() {
            document.getElementById('config-modal').classList.remove('active');
        }
        
        async function saveConfig() {
            if (!currentService) return;
            
            try {
                const configEl = document.getElementById('config-json');
                const config = JSON.parse(configEl.value);
                serviceConfigs[currentService] = config;
                
                const resp = await fetch(`/api/v1/${currentService}/config`, {
                    method: currentService === 'stun_turn' ? 'PUT' : 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(config)
                });
                
                if (resp.ok) {
                    addLog('info', `Configuration saved for ${currentService}`);
                    closeModal();
                } else {
                    addLog('error', `Save failed: ${resp.status}`);
                }
            } catch (e) {
                addLog('error', `Parse error: ${e.message}`);
            }
        }
        
        function addLog(level, message) {
            const container = document.getElementById('log-container');
            const time = new Date().toLocaleTimeString();
            const line = document.createElement('div');
            line.className = 'log-line';
            line.innerHTML = `<span class="level ${level}">[${level.toUpperCase()}]</span> ${message}`;
            container.appendChild(line);
            container.scrollTop = container.scrollHeight;
        }
        
        // Connect WebSocket for real-time updates
        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const ws = new WebSocket(`${protocol}//${window.location.host}/ws/events`);
            
            ws.onopen = () => {
                addLog('info', 'WebSocket connected for real-time updates');
                document.getElementById('conn-dot').style.background = 'var(--accent-green)';
                document.getElementById('conn-text').textContent = 'Connected';
            };
            
            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    addLog('info', `Update: ${JSON.stringify(data).substring(0, 100)}...`);
                } catch(e) {
                    addLog('warn', `WebSocket message: ${event.data}`);
                }
            };
            
            ws.onclose = () => {
                addLog('warn', 'WebSocket disconnected, reconnecting in 5s...');
                document.getElementById('conn-dot').style.background = 'var(--accent-red)';
                document.getElementById('conn-text').textContent = 'Disconnected';
                setTimeout(connectWebSocket, 5000);
            };
            
            ws.onerror = () => {
                addLog('error', 'WebSocket error');
            };
        }
        
        // Initialize
        loadStatus();
        setInterval(loadStatus, 10000);
        connectWebSocket();
        addLog('info', 'ReMgr Web Console loaded');
    </script>
</body>
</html>
"#;