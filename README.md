# ReMgr (RelayManager)

全合一中继服务器管理器，为 OpenBSD 设计。**单一二进制、单进程、零子进程、零 IPC** —— 所有服务以库/FFI 形式进程内集成，通过内置 Web 控制台统一开关与配置。

## 功能

| 模块 | 实现 | 集成方式 |
|---|---|---|
| EasyTier 中心服务器 + easytier-web 全功能 | `third_party/easytier`（含 OpenBSD 移植补丁：rust-tun / boringtun / guarden） | Rust 库进程内链接（easytier-web 库化 + `NativeInstanceManager` 本地节点） |
| STUN/TURN | STUN：RFC 5389 纯 Rust；TURN：coturn 内核 | coturn C 静态库 + C FFI（`-Dmain=turnserver_main`，配置经文件传入） |
| RustDesk 中继 (hbbr) + ID 服务器 (hbbs) | `third_party/rustdesk-server` | Rust 库进程内链接（新增 lib 导出层） |
| frps 服务端 | `remgr-frps`（自研，与 fatedier/frp 线协议兼容：V1 帧、yamux/tcp_mux、TLS 首字节、md5 token 认证、tcp/udp 代理、工作连接池） | 纯 Rust 进程内 |

Web 控制台（axum + 内嵌 SPA）：每个服务的全部可配置项、启停开关、实时日志（WebSocket）、证书生成/上传（P-384 自签或 PEM 上传）、流量统计。

## OpenBSD 安全声明

二进制自带 `pledge(2)` / `unveil(2)`：

- pledge：`stdio rpath wpath cpath fattr flock inet unix dns getpw` —— **无 `exec`**，架构上杜绝子进程。
- unveil：`/etc/remgr`、`/var/lib/remgr`、`/var/db/remgr`、`/var/log/remgr`、
`/var/run/remgr`（rwc）、`/etc/ssl`、`/etc/resolv.conf`、`/etc/hosts`、
`/etc/services`（r）、`/dev/tun0-7`（rw，EasyTier TUN）、`/dev/urandom`（r）。

## 目录约定（OpenBSD）

```
/etc/remgr/config.toml     配置（控制台/各服务全部字段）
/etc/remgr/ssl/            证书
/var/lib/remgr/            数据（easytier-web sqlite、rustdesk key/db）
/var/log/remgr/            文件日志
/var/run/remgr/            运行时（首次启动的初始口令）
```

## 构建（OpenBSD 7.x）

```sh
pkg_add rust llvm19    # llvm19 供 bindgen/cbakend 使用
./scripts/openbsd-build.sh
```

产物：`target/release/remgr`（单文件）。

## 部署

```sh
install -m 755 target/release/remgr /usr/local/bin/remgr
install -m 555 scripts/rc.d/remgr /etc/rc.d/remgr
rcctl set remgr status on
rcctl start remgr
```

控制台默认 `http://<host>:9443`；首次启动生成随机管理口令，写入 syslog 与 `/var/run/remgr/initial_password`（0600）。

## frp 客户端兼容性说明

- 与 fatedier/frp 客户端（V1 线协议 + yamux/tcp_mux + TLS 首字节）兼容。
- frpc 建议：`transport.wireProtocol` 保持默认 `v1`；`transport.tls.enable` 默认值即可（服务端自动生成自签证书）。
- 支持 `tcp` / `udp` 代理；`http/https/stcp/xtcp/tcpmux` 类型会返回协议错误（后续版本补充）。

## License

- ReMgr：AGPL-3.0
- 第三方源码随各自许可证（见 `third_party/` 内相应 LICENSE）。
