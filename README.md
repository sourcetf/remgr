# ReMgr (RelayManager)

全合一中继服务器管理器，为 OpenBSD 设计。**单一二进制、单进程、零子进程、零 IPC** —— 所有服务以库形式进程内集成，通过内置 Web 控制台统一开关与配置。

## 功能

| 模块 | 实现 | 集成方式 |
|---|---|---|
| EasyTier 中心服务器 + easytier-web 全功能 | `third_party/easytier`（含 OpenBSD 移植补丁：rust-tun / boringtun / guarden） | Rust 库进程内链接（easytier-web 库化 + `NativeInstanceManager` 本地节点）；REST API 由控制台以 `/et` 同源反代暴露 |
| STUN/TURN | STUN：RFC 5389 纯 Rust；TURN：`turn` crate（RFC 5766，纯 Rust） | Rust 库进程内链接；UDP 3478 + TURN over TLS 5349（RFC 5766 §11.5 流式分帧），分配数/中继字节数取自真实运行时 |
| RustDesk 中继 (hbbr) + ID 服务器 (hbbs) | `third_party/rustdesk-server` | Rust 库进程内链接（新增 lib 导出层） |
| frps 服务端 | `remgr-frps`（自研，与 fatedier/frp 线协议兼容：V1 帧、yamux/tcp_mux、TLS 首字节、md5 token 认证、tcp/udp 代理、工作连接池） | 纯 Rust 进程内 |

Web 控制台（axum + 内嵌 SPA）：每个服务的全部可配置项、启停开关、实时日志（WebSocket）、证书生成/上传（P-384 自签或 PEM 上传）、流量统计。

## OpenBSD 安全声明

二进制自带 `pledge(2)` / `unveil(2)`：

- pledge：`stdio rpath wpath cpath fattr flock inet unix dns getpw route wroute` —— **无 `exec`**，架构上杜绝子进程。
  - `route` / `wroute` 供 EasyTier 节点做接口与路由 ioctl：`SIOCGIFADDR`、`SIOCAIFADDR`、`SIOCDIFADDR`、`SIOCSIFMTU`。
  - `tun(4)` 在 `open(2)` 时已置 `IFF_UP | IFF_RUNNING`，无需 `SIOCSIFFLAGS`（该 ioctl 不被任何 promise 授权）。
- 路由表增删通过**启动时（pledge 之前）打开的路由套接字**完成：pledge 会拒绝 `socket(AF_ROUTE)`，但已打开的 fd 仍可 `write(2)` RTM_ADD / RTM_DELETE。
- unveil：`/etc/remgr`、`/var/lib/remgr`、`/var/db/remgr`、`/var/log/remgr`、`/var/run/remgr`（rwc）、`/etc/ssl`、`/etc/resolv.conf`、`/etc/hosts`、`/etc/services`（r）、`/dev/tun0-7`（rw，EasyTier TUN）、`/dev/urandom`（r）。

> 注意：`unveil(2)` 在调用当下即收窄可见命名空间（而非锁定之时），因此这些调用必须**无条件执行**，不能在之前用 `exists()` 之类的探测做前置判断，否则首个路径之后的条目会被静默跳过。

## 目录约定（OpenBSD）

```
/etc/remgr/config.toml     配置（控制台/各服务全部字段）
/etc/remgr/ssl/            证书（turn_cert.pem / turn_key.pem 缺失时按域名自签生成）
/var/lib/remgr/            数据（easytier-web sqlite、rustdesk key/db）
/var/log/remgr/            文件日志
/var/run/remgr/            运行时（首次启动的初始口令）
```

## 端口

| 端口 | 服务 |
|---|---|
| 9443 | Web 控制台（`/et` 为 easytier-web REST API 的同源反代） |
| 3478 | STUN / TURN（UDP） |
| 5349 | TURN over TLS（需证书；`tls_port = 0` 关闭） |
| 22020 | EasyTier 配置服务器（UDP） |
| 11211 | easytier-web REST API（默认仅 127.0.0.1） |
| 11010-11013 | EasyTier 节点监听器（tcp/udp/wg/ws/wss/faketcp） |
| 21115-21119 | RustDesk hbbs / hbbr |
| 7000 | frps |

## 构建（OpenBSD 7.x）

```sh
pkg_add rust llvm19    # llvm19 供 bindgen/cbakend 使用
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

## EasyTier 仪表盘（easytier-web）

嵌入式 easytier-web 的完整仪表盘由 REST API 同源提供，控制台以 `/et/` 反代，从控制台 EasyTier 页即可打开：**`http://<host>:9443/et/`**。

- 登录账户为 `admin`。easytier-web 的迁移只预置一个未公开的哈希，ReMgr 在首次启动时把它替换为随机口令，写入 syslog 与 `/var/run/remgr/easytier_dashboard_password`（0600）；此后不再改动，可在仪表盘内自行修改。
- 本地中心节点以 `admin` 账户注册到内置配置服务器，因此会作为一台设备出现在仪表盘中，可直接在其中管理网络实例——与在控制台里改 `[easytier]` 是同一个进程、同一个 `NativeInstanceManager`。
- 仪表盘只监听 `api_addr:api_port`（默认 `127.0.0.1:11211`），对外仅通过控制台的 `/et/` 暴露；不要把 11211 直接暴露到公网。

## frp 客户端兼容性说明

- 与 fatedier/frp 客户端（V1 线协议 + yamux/tcp_mux + TLS 首字节）兼容。
- frpc 建议：`transport.wireProtocol` 保持默认 `v1`；`transport.tls.enable` 默认值即可（服务端自动生成自签证书）。
- 支持 `tcp` / `udp` 代理；`http/https/stcp/xtcp/tcpmux` 类型会返回协议错误（后续版本补充）。

## License

- ReMgr：AGPL-3.0
- 第三方源码随各自许可证（见 `third_party/` 内相应 LICENSE）。
