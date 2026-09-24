# ReMgr (RelayManager)

全合一中继服务器管理器，为 OpenBSD 设计。**单一二进制、单进程、零子进程、零 IPC** —— 所有服务以库形式进程内集成，通过内置 Web 控制台统一开关与配置。

## 功能

| 模块 | 实现 | 集成方式 |
|---|---|---|
| EasyTier 中心服务器 + easytier-web 全功能 | `third_party/easytier`（含 OpenBSD 移植补丁：rust-tun / boringtun / guarden） | Rust 库进程内链接（easytier-web 库化 + `NativeInstanceManager` 本地节点）；REST API 由控制台以 `/et` 同源反代暴露 |
| STUN/TURN | STUN：RFC 5389 纯 Rust；TURN：`turn` crate（RFC 5766，纯 Rust） | Rust 库进程内链接；UDP 3478 + TURN over TLS 5349（RFC 5766 §11.5 流式分帧），分配数/中继字节数取自真实运行时 |
| RustDesk 中继 (hbbr) + ID 服务器 (hbbs) | `third_party/rustdesk-server` | Rust 库进程内链接（新增 lib 导出层） |
| frps 服务端 | `remgr-frps`（自研，与 fatedier/frp 线协议兼容：V1 帧、yamux/tcp_mux、TLS 首字节、md5 token 认证、tcp/udp 代理、工作连接池） | 纯 Rust 进程内 |
| **frpc 客户端** | `remgr-frps::client`（自研：登录/令牌认证 + golib 控制通道加密 + yamux + TLS(0x17) + tcp/udp 代理 + 工作连接池 + 断线重连退避） | 纯 Rust 进程内；把本机服务发布到上游 frps（fatedier/frp 或另一台 ReMgr），控制台 frpc 页可配 |

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
| 9443 | Web 控制台 **HTTPS**（首次启动自签 P-384 证书；`/et` 为 easytier-web REST API 的同源反代） |
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

控制台默认 **`https://<host>:9443`**：首次启动会自签一张 P-384 证书（SAN 含主机名、`localhost`、回环地址与本机出站 IP），并把 `[console] tls` 打开；自签名证书浏览器会提示不受信任，接受即可，或在控制台「系统」页上传正式证书（生成/上传后路径会自动写入配置）。首次启动安装**默认口令 `admin`**（写入 syslog 与 `/var/run/remgr/initial_password`，0600），登录后请在「系统」页立即修改——控制台可能暴露在公网。已设置过的口令永不覆盖（仅当哈希为空时才安装默认值）。

## EasyTier 仪表盘（easytier-web）

嵌入式 easytier-web 的完整仪表盘由 REST API 同源提供，控制台以 `/et/` 反代，从控制台 EasyTier 页即可打开：**`https://<host>:9443/et/`**（控制台已是 HTTPS）。

- 登录账户为 `admin` / **默认口令 `admin`**（与控制台一致，写入 syslog 与 `/var/run/remgr/easytier_dashboard_password`，0600），可在仪表盘内自行修改。已安装的有效凭据不会在重启时被覆盖。
- 注意：仪表盘前端会先对输入的密码做 **MD5** 再提交（`frontend/src/modules/api.ts` 的 `Md5.hashStr`），后端存的是该摘要的 argon2 哈希，所以用 API 直接登录时 `password` 字段要填 `md5(明文)` 而不是明文。ReMgr 的引导流程按同样约定安装凭据，并在每次启动时校验它是否仍然可用（数据库被重建、或旧版本装错了哈希时会自动重新生成）。
- 上游迁移还预置了一个密码为 `user` 的 demo 账户；ReMgr 检测到它仍是默认口令时会轮换为随机口令，写入 `/var/run/remgr/easytier_dashboard_password_user`（0600）。
- 本地中心节点以 `admin` 账户注册到内置配置服务器，因此会作为一台设备出现在仪表盘中，可直接在其中管理网络实例——与在控制台里改 `[easytier]` 是同一个进程、同一个 `NativeInstanceManager`。
- 仪表盘只监听 `api_addr:api_port`（默认 `127.0.0.1:11211`），对外仅通过控制台的 `/et/` 暴露；不要把 11211 直接暴露到公网。

## frp 客户端兼容性说明

- 与 fatedier/frp 客户端（V1 线协议 + yamux/tcp_mux + TLS 首字节 + golib 控制通道加密）兼容。
  已用 **frpc 0.71.0（openbsd/amd64 官方 release）** 实测：登录、注册 tcp/udp 代理、
  经隧道 GET 控制台首页（200，31 KB）、持续 4 分钟无重连；`tcp` 与 `udp` 代理均验证通过。
  另外验证：`poolCount=3`（4/4 会话的 udp 都通）、`tcp_mux=false` 非多路复用路径、TLS 首字节 0x17、错 token 被拒并明确报错。
- frpc 建议：`transport.wireProtocol` 保持默认 `"v1"`（0.52+ 的默认值，也是本服务端实现的协议）；
  `transport.tls.enable` 用默认值即可（服务端自动生成自签证书，客户端默认不校验）。
- 控制通道加密：登录之后的所有控制消息用 AES-128-CFB 加密，密钥为 `PBKDF2-HMAC-SHA1(token, salt, 64, 16)`。
  frp 自 **0.44.0** 起在 `client/service.go` 与 `cmd/frps/main.go` 里把 golib 的默认盐覆盖为 `"frp"`，
  因此默认值 `crypto_salt = "frp"`；只有 0.44 之前的客户端才需要改成 golib 的默认值 `"crypto"`（可在控制台 frps 配置里改）。
- 心跳差异（已在服务端分别适配）：frp ≤ 0.51 的客户端每 30 秒发一次控制通道 Ping；
  **0.52 起心跳被移除**，链路存活改由传输层负责（yamux 自身的 30 秒 keepalive，服务端看不到应用层消息）。
  因此服务端的「空闲控制连接回收」只对 ≤ 0.51 的客户端生效，对其余客户端依赖 TCP keepalive 回收半死连接。
- 支持 `tcp` / `udp` 代理（udp 走工作连接帧，与 frp 的 base64 `UDPPacket` 一致）；`http/https/stcp/xtcp/tcpmux` 类型会返回协议错误（后续版本补充）。
- 未实现 frp 的 `use_encryption` / `use_compression`（客户端开启时该代理会收到明确错误，不会静默失败）。

## frpc 模块（本机作为 frp 客户端）

控制台新增 **frpc** 页，把本机服务发布到上游 frps（fatedier/frp 或另一台 ReMgr）：

- 必填：上游 `server_addr` / `server_port`、`token`（与上游 `auth.token` 一致）；
  `tcp_mux` 必须与上游一致（默认开启）；上游用自签证书时保持 TLS 开启（默认不校验证书，也可填 `trusted_ca_file` 做校验）。
- 代理列表每行一个：`名称 类型 本地IP 本地端口 远程端口`，类型支持 `tcp` / `udp`。
  例：`web tcp 127.0.0.1 8080 7001`。
- 状态页显示上游连通性、会话时长、累计登录/工作连接、每代理的状态与流量（入=上游→本地服务，出=本地服务→上游）。
  上游拒绝登录等失败会写在「最近错误」里，重连按 1s→30s 退避（认证失败后固定 30s，不会风暴）。
- 只支持 `tcp`/`udp` 代理；http/https/stcp/xtcp 在配置校验阶段就会报错，不会半途失败。

## 控制台可配置项（控制台自身）

系统页可直接修改控制台端口、TLS 开关与证书路径、会话有效期，并支持：
改控制台密码、生成/上传控制台与各服务证书、下载日志（优先取 `/var/log/remgr/remgr.log`，含重启前历史）。

- 保存后点「应用」才重新绑定监听（`POST /api/console/apply`）：新监听先绑定成功并加载好证书，才关闭旧监听，
  端口被占用或证书不可读时旧控制台继续服务并返回错误，不会把自己锁死。
- 证书生成/上传后，路径会自动写入对应服务配置（`stun_turn.cert_path`、`frps.tls_cert_path`、`console.tls_cert`），
  并重启该服务使其生效。

## License

- ReMgr：AGPL-3.0
- 第三方源码随各自许可证（见 `third_party/` 内相应 LICENSE）。
