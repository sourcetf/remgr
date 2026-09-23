//! frp message types + wire v1 codec.
//!
//! Wire format (github.com/fatedier/golib msg/json):
//! `[1-byte type][8-byte BE body length][JSON body]`, body length <= 10240.

use anyhow::{anyhow, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const MAX_MSG_LEN: i64 = 10240;

pub const TYPE_LOGIN: u8 = b'o';
pub const TYPE_LOGIN_RESP: u8 = b'1';
pub const TYPE_NEW_PROXY: u8 = b'p';
pub const TYPE_NEW_PROXY_RESP: u8 = b'2';
pub const TYPE_CLOSE_PROXY: u8 = b'c';
pub const TYPE_NEW_WORK_CONN: u8 = b'w';
pub const TYPE_REQ_WORK_CONN: u8 = b'r';
pub const TYPE_START_WORK_CONN: u8 = b's';
pub const TYPE_NEW_VISITOR_CONN: u8 = b'v';
pub const TYPE_NEW_VISITOR_CONN_RESP: u8 = b'3';
pub const TYPE_PING: u8 = b'h';
pub const TYPE_PONG: u8 = b'4';
pub const TYPE_UDP_PACKET: u8 = b'u';

/// frp wire v2 magic — detected on connect and rejected.
pub const V2_MAGIC: &[u8] = b"FRP\x00\x02\r\n";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct ClientSpec {
    #[serde(rename = "type", skip_serializing_if = "String::is_empty")]
    pub client_type: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub always_auth_pass: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct Login {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub os: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub arch: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub user: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub privilege_key: String,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub timestamp: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub run_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metas: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_spec: Option<ClientSpec>,
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub pool_count: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct LoginResp {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub run_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct NewProxy {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub proxy_name: String,
    #[serde(rename = "proxy_type", skip_serializing_if = "String::is_empty")]
    pub proxy_type: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub use_encryption: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub use_compression: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub bandwidth_limit: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub bandwidth_limit_mode: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub group: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub group_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metas: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "is_zero_u16")]
    pub remote_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_domains: Option<Vec<String>>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub subdomain: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub sk: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub multiplexer: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct NewProxyResp {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub proxy_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub remote_addr: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct CloseProxy {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub proxy_name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct NewWorkConn {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub run_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub privilege_key: String,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub timestamp: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct ReqWorkConn {}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct StartWorkConn {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub proxy_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub src_addr: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub dst_addr: String,
    #[serde(skip_serializing_if = "is_zero_u16")]
    pub src_port: u16,
    #[serde(skip_serializing_if = "is_zero_u16")]
    pub dst_port: u16,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct Ping {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub privilege_key: String,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub timestamp: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct Pong {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// `net.UDPAddr` JSON shape used by Go: `{"IP":"1.2.3.4","Port":53,"Zone":""}`.
///
/// serde matches field names case-sensitively (Go's decoder does not), so the
/// capitalised spelling has to be reproduced exactly: with lower-case keys every
/// datagram from the client lost its `r` field, and the server dropped it for
/// having no destination. Note `rename_all = "PascalCase"` is *not* enough here —
/// it spells the `ip` field "Ip", which still does not match Go's "IP".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UdpAddrJson {
    #[serde(rename = "IP", alias = "ip", skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(rename = "Port", alias = "port", skip_serializing_if = "is_zero_u16")]
    pub port: u16,
    #[serde(rename = "Zone", alias = "zone", skip_serializing_if = "String::is_empty")]
    pub zone: String,
}

/// `UDPPacket` — Go `[]byte` marshals to a base64 std string.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct UdpPacket {
    #[serde(rename = "c", skip_serializing_if = "String::is_empty")]
    pub content_b64: String,
    #[serde(rename = "l", skip_serializing_if = "Option::is_none")]
    pub local_addr: Option<UdpAddrJson>,
    #[serde(rename = "r", skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<UdpAddrJson>,
}

impl UdpPacket {
    pub fn content(&self) -> Result<Vec<u8>> {
        use base64::Engine;
        Ok(base64::engine::general_purpose::STANDARD.decode(&self.content_b64)?)
    }

    pub fn from_content(content: &[u8], local: Option<std::net::SocketAddr>, remote: std::net::SocketAddr) -> Self {
        use base64::Engine;
        let addr_json = |a: std::net::SocketAddr| UdpAddrJson {
            ip: Some(a.ip().to_string()),
            port: a.port(),
            zone: String::new(),
        };
        Self {
            content_b64: base64::engine::general_purpose::STANDARD.encode(content),
            local_addr: local.map(addr_json),
            remote_addr: Some(addr_json(remote)),
        }
    }

    pub fn remote_socket_addr(&self) -> Option<std::net::SocketAddr> {
        let r = self.remote_addr.as_ref()?;
        let ip: std::net::IpAddr = r.ip.as_ref()?.parse().ok()?;
        Some(std::net::SocketAddr::new(ip, r.port))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Message {
    Login(Login),
    LoginResp(LoginResp),
    NewProxy(NewProxy),
    NewProxyResp(NewProxyResp),
    CloseProxy(CloseProxy),
    NewWorkConn(NewWorkConn),
    ReqWorkConn(ReqWorkConn),
    StartWorkConn(StartWorkConn),
    Ping(Ping),
    Pong(Pong),
    UdpPacket(UdpPacket),
}

impl Message {
    pub fn type_byte(&self) -> u8 {
        match self {
            Message::Login(_) => TYPE_LOGIN,
            Message::LoginResp(_) => TYPE_LOGIN_RESP,
            Message::NewProxy(_) => TYPE_NEW_PROXY,
            Message::NewProxyResp(_) => TYPE_NEW_PROXY_RESP,
            Message::CloseProxy(_) => TYPE_CLOSE_PROXY,
            Message::NewWorkConn(_) => TYPE_NEW_WORK_CONN,
            Message::ReqWorkConn(_) => TYPE_REQ_WORK_CONN,
            Message::StartWorkConn(_) => TYPE_START_WORK_CONN,
            Message::Ping(_) => TYPE_PING,
            Message::Pong(_) => TYPE_PONG,
            Message::UdpPacket(_) => TYPE_UDP_PACKET,
        }
    }

    pub fn decode(type_byte: u8, body: &[u8]) -> Result<Self> {
        let m = match type_byte {
            TYPE_LOGIN => Message::Login(serde_json::from_slice(body)?),
            TYPE_LOGIN_RESP => Message::LoginResp(serde_json::from_slice(body)?),
            TYPE_NEW_PROXY => Message::NewProxy(serde_json::from_slice(body)?),
            TYPE_NEW_PROXY_RESP => Message::NewProxyResp(serde_json::from_slice(body)?),
            TYPE_CLOSE_PROXY => Message::CloseProxy(serde_json::from_slice(body)?),
            TYPE_NEW_WORK_CONN => Message::NewWorkConn(serde_json::from_slice(body)?),
            TYPE_REQ_WORK_CONN => Message::ReqWorkConn(serde_json::from_slice(body)?),
            TYPE_START_WORK_CONN => Message::StartWorkConn(serde_json::from_slice(body)?),
            TYPE_PING => Message::Ping(serde_json::from_slice(body)?),
            TYPE_PONG => Message::Pong(serde_json::from_slice(body)?),
            TYPE_UDP_PACKET => Message::UdpPacket(serde_json::from_slice(body)?),
            other => return Err(anyhow!("unknown frp message type byte {other:#04x}")),
        };
        Ok(m)
    }
}

fn is_zero_i64(v: &i64) -> bool { *v == 0 }
fn is_zero_u32(v: &u32) -> bool { *v == 0 }
fn is_zero_u16(v: &u16) -> bool { *v == 0 }

/// Raw framed message: (type byte, body).
pub type RawMsg = (u8, Vec<u8>);

/// Read one framed message body.
pub async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<RawMsg> {
    let mut tb = [0u8; 1];
    r.read_exact(&mut tb).await?;
    let mut lb = [0u8; 8];
    r.read_exact(&mut lb).await?;
    let len = i64::from_be_bytes(lb);
    if len < 0 || len > MAX_MSG_LEN {
        return Err(anyhow!("frp message length out of range: {len}"));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    Ok((tb[0], body))
}

/// Write one framed message.
pub async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, type_byte: u8, body: &[u8]) -> Result<()> {
    if body.len() as i64 > MAX_MSG_LEN {
        return Err(anyhow!("frp message too large: {}", body.len()));
    }
    let mut buf = Vec::with_capacity(9 + body.len());
    buf.push(type_byte);
    buf.extend_from_slice(&(body.len() as i64).to_be_bytes());
    buf.extend_from_slice(body);
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

pub async fn write_msg<W: AsyncWriteExt + Unpin, T: Serialize>(w: &mut W, m: &T, type_byte: u8) -> Result<()> {
    let body = serde_json::to_vec(m)?;
    write_frame(w, type_byte, &body).await
}

pub async fn read_typed<T: DeserializeOwned, R: AsyncReadExt + Unpin>(r: &mut R) -> Result<T> {
    let (_, body) = read_frame(r).await?;
    Ok(serde_json::from_slice(&body)?)
}

/// `privilege_key = hex(md5(token + timestamp))` — mirrors frp `util.GetAuthKey`.
pub fn auth_key(token: &str, timestamp: i64) -> String {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(token.as_bytes());
    h.update(timestamp.to_string().as_bytes());
    hex_lower(&h.finalize())
}

fn hex_lower(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
