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
- unveil：`/etc/remgr`、`/var/lib/remgr`、`/var/db/remgr`、`/var/log/remgr`、`/var/run/remgr`（rwc）、`/etc/ssl`、`/etc/resolv.conf`、`/etc/hosts`、`/etc/services`、`/var/account`（r，内核记账尾巴：终止信号的取证依据，见「安全与运维约束」）、`/dev/tun0-15`（rw，EasyTier TUN）、`/dev/urandom`（r）。

实测核对（2026-09-25，运行中的服务）：`fstat -p <pid>` 里只有这几个 unveiled 路径 —— 工作目录 `/var/lib/remgr`（inode 与 `ls -di` 一致）、`remgr.log`、`et.db`/`et.db-wal`/`et.db-shm`、`db_v2.sqlite3`、`/dev/tun0`，加上启动时打开的路由套接字（`route raw`）与各监听 socket；`pgrep -P <pid>` **无输出**（进程没有任何子进程，与「无 `exec`」一致）；`dmesg` 里从无 pledge/unveil 违例。把控制台/服务全部功能（启停、保存配置、生成与上传证书、下载日志、WebSocket 日志、frpc 隧道、STUN/TURN 分配、easytier `/et` 反代）跑一遍，日志里没有 `EPERM`、也没有新的 `ENOENT`。

promise 集合与实际需要的对应关系：不需要 `prot_exec`（无 JIT）、不需要 `proc`/`exec`（无子进程）、不需要 `recvfd`（模块间没有 fd 传递，进程内的 socketpair 不受 pledge 限制）。`/dev/tun5` 在本机是个普通文件（历史遗留），`open(2)` 能成功但 ioctl 会失败 —— 如果 EasyTier 报「找不到可用 tun」，先 `ls -l /dev/tun*` 看看节点是不是设备文件。

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

## 支持的系统

ReMgr 以 **OpenBSD 为首要目标**（pledge/unveil 沙箱、rc.d、login.conf.d 都是为此写的），同一份代码也可在 **Linux 与 Windows** 上构建运行。三者的差异是**平台能力**，不是功能分支：

| | OpenBSD | Linux | Windows |
|---|---|---|---|
| 沙箱 | `pledge` + `unveil`（见下节） | 无（代码里已 `#[cfg]` 关掉） | 无 |
| 配置/数据/日志/运行目录 | `/etc/remgr`、`/var/lib/remgr`、`/var/log/remgr`、`/var/run/remgr` | 同左（FHS） | `%ProgramData%\ReMgr`（`config.toml`、`ssl`、`lib`、`log`、`run`） |
| 服务管理 | `rc.d` + `login.conf.d`（随仓库提供） | 自备 systemd 单元（未随仓库提供） | 自备服务包装器（NSSM 等，未随仓库提供） |
| EasyTier 中心节点所需的 TUN | `tun(4)`，开箱可用 | `/dev/net/tun`，需要权限 | 需要安装 **wintun 驱动** |
| 构建期额外依赖 | `llvm19`（libclang）、`protobuf`（protoc） | 同左（libclang-dev、protobuf-compiler、libprotobuf-dev） | LLVM、protoc，以及 **WDK** 提供的 `Packet.lib`（链接期，见下） |
| CI | 无 GitHub runner，**手动部署** | 出 release 产物 + **真实运行**冒烟测试 | 出 release 产物 + 导入校验（运行期冒烟测试需 Npcap，见下） |

- **目录布局由 `remgr/src/platform.rs` 单点决定**，可用环境变量 `REMGR_HOME` 整体重定位（CI 与冒烟测试就是这么跑的：重定位后配置在根目录，`ssl`/`lib`/`log`/`run` 在其下）。运维上意味着一台机器可以放多套互不干扰的实例。
- **`%ProgramData%\ReMgr` 与 Windows 服务**：以管理员身份运行时该目录可写；若要让服务账户也能写，给该目录授权即可。
- **Windows 上必须安装 Npcap，且这是启动前提（不只是 EasyTier）**：`remgr.exe` 在链接时用了 Npcap 的**导入库** `Packet.lib`，而 Windows 的加载器在 `main()` 之前就解析普通导入，因此**没有 `Packet.dll` 时整个二进制无法启动**——连 `remgr --version` 都会立刻以 `0xC0000135`（STATUS_DLL_NOT_FOUND）退出，与是否使用 EasyTier 无关。依赖链是：EasyTier 的 faketcp netfilter 用 `pnet`（`PnetTun` 是各平台的回退实现，见 `netfilter/mod.rs`），`pnet_sys` → Npcap。请从 <https://npcap.com/#download> 安装（Wireshark 用的也是它）。
  - 这一点在 CI 里是**机器校验**的：Windows job 会扫描 `remgr.exe` 的导入表确认 `Packet.dll` 在其中；若上游某天不再需要它，该步骤会失败并提示可以启用运行期冒烟测试。
  - **免费版 Npcap 没有静默安装**（其文档写明 `/S` 仅 Npcap OEM 可用），所以这是人工步骤；因此 CI 在装有 Npcap 的机器上才能跑 Windows 运行期冒烟测试，否则会明确报告「未运行」并说明原因，**不会假装通过**。
- **Windows 构建期还需要 `Packet.lib`**：它随 **Windows Driver Kit** 提供（`Windows Kits\10\Lib\<版本>\km\x64\`，不在默认库搜索路径上），或从 **Npcap SDK**（`Lib\x64\Packet.lib`，约 345 KB）获取。CI 优先用前者、否则下载官方 SDK，并把目录加进链接搜索路径；手工构建遇到 `LNK1181: cannot open input file 'Packet.lib'` 时同样处理（`RUSTFLAGS=-L native=<目录>`）。
- **Linux 不需要额外运行期依赖**：CI 在 Ubuntu 上构建并**真实运行**（启动 → 自签证书 → HTTPS 登录 → 目录布局 → SIGTERM 退出）全绿。
- **除 EasyTier 中心节点外，其余模块（easytier-web 仪表盘、STUN/TURN、RustDesk、frps、frpc）在任何平台都不依赖 TUN**，所以即使没装 wintun，Windows 上仍是一个可用的中继管理器（把配置里的 `[easytier] node_enabled` 关掉即可）。
- **未验证的部分要如实说明**：Linux 上「能构建 + 能真实运行」已由 CI 每次 push 验证；Windows 上验证到「能构建、能链接、导入校验通过、产物可下载」，**运行期**那一环需要 Npcap（免费版无法静默安装），因此由操作者在装了 Npcap 的机器上执行同样步骤 —— CI 会明确报告该步骤未运行。而 EasyTier 的 TUN 组网、RustDesk 客户端的真实连接这类**需要真实客户端参与**的行为，只在 OpenBSD 上实测过。

## 构建（OpenBSD 7.x）

```sh
pkg_add rust llvm19 protobuf    # llvm19 提供 libclang（kcp-sys 的 bindgen 用），protobuf 提供 protoc
sh scripts/openbsd-build.sh     # 需要的环境变量都在这个脚本里
```

产物：`target/release/remgr`（单文件）。

实测可用的组合：rust/cargo **1.94.1**、llvm-**19.1.7p14**、protobuf-**6.34.1**。脚本里的环境变量各有原因，删掉任何一个都会构建失败或产出错误结果：

- `LIBCLANG_PATH=/usr/local/llvm19/lib` —— kcp-sys 经 bindgen 调 libclang，默认搜索路径下没有 libclang.so。
- `RUSTC_BOOTSTRAP=1` —— vendored 的 guarden 补丁用了 `cfg_select!`，rustc 1.94 在稳定通道不接受；ReMgr 自己的代码不需要这个变量。
- `--ignore-rust-version` —— 同一个 vendored crate 的元数据写着 `rust-version = 1.95`，代码实际能在 1.94 上编译。
- `--locked` —— `Cargo.lock` 已入库，构建可复现；清单与锁文件漂移时会直接报错，而不是悄悄换依赖。
- `ulimit -n 1024` —— **编译期**限制（thin LTO 链接要更多 fd），与运行期无关：服务跑在登录类里，不装 `scripts/login.conf.d/remgr` 就只有 128 个 fd，见下。

## 部署

```sh
install -m 755 target/release/remgr /usr/local/bin/remgr
install -m 555 scripts/rc.d/remgr /etc/rc.d/remgr
install -m 644 scripts/login.conf.d/remgr /etc/login.conf.d/remgr   # 运行期的 fd 上限，别漏
rcctl set remgr status on
rcctl start remgr
sh scripts/preflight.sh                                             # 逐项核对，只读
```

控制台默认 **`https://<host>:9443`**：首次启动会自签一张 P-384 证书（SAN 含主机名、`localhost`、回环地址与本机出站 IP），并把 `[console] tls` 打开；自签名证书浏览器会提示不受信任，接受即可，或在控制台「系统」页上传正式证书（生成/上传后路径会自动写入配置）。登录需要**用户名 + 密码**，首次启动安装**默认账户 `admin` / `admin`**（口令写入 syslog 与 `/var/run/remgr/initial_password`，0600），登录后请在「系统」页立即修改——控制台可能暴露在公网。用户名可在「系统」页改（不允许留空）；已设置过的口令永不覆盖（仅当哈希为空时才安装默认值）。

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
  并重启该服务使其生效。生成的私钥以 0600 落盘（先写临时文件再 rename，避免「私钥短暂全局可读」或半截文件）；
  `config.toml` 与 `remgr.log` 同样为 0600 —— 前者含口令哈希、frps token、网络密钥，后者会记录首次启动的口令。

## 安全与运维约束（生产注意）

- **口令哈希：Argon2id，参数 m=64 MiB / t=3 / p=1**（在目标机器上实测单次校验约 240 ms）。
  选 Argon2id 而非 yescrypt 的原因：它是 PHC 竞赛优胜者、OWASP 首选，且属「混合型」——
  第一趟的前半段数据无关（抗侧信道），其余数据相关（抗 GPU/ASIC 暴力搜索），内存硬度可调；
  Rust 生态有 RustCrypto 的成熟实现（已是本项目依赖）。yescrypt 本身也很好（Debian/Ubuntu 的 shadow 在用），
  但**没有同等质量的 Rust 实现**（只有质量不明的移植），而 OpenBSD 生态里根本不使用它，
  引入一个未经审计的密码学依赖换不到安全收益。
  哈希是 PHC 字符串（`$argon2id$v=19$m=65536,t=3,p=1$…`），**校验时从字符串读取参数**，
  所以以后提高参数不会作废旧哈希——旧口令继续可用，直到下次改密码才升级。
  并发校验有上限（信号量 2 个席位）：每次校验要 64 MiB，不设限的话大量并发登录请求会成为
  内存耗尽攻击面；这两条合起来把哈希占用限制在 128 MiB 以内。
- **登录限流**：控制台可被公网访问且默认口令较短，因此登录失败计数：同一 5 分钟窗口内失败 10 次后，
  后续**错误**口令返回 `429`（带 `Retry-After`）。**正确口令任何时候都被接受**并清零计数，所以不会把运维锁在门外。
  计数是全局的（TLS 监听由 axum-server 提供，不向上层传递来源地址；若要按 IP 限流需改这条链路）。
- **登录需要用户名 + 密码**，用户名与密码错误都返回同一条 `401 invalid username or password`；
  密码**始终**会做一次完整哈希校验（用户名错也照做），避免通过响应时间判断是哪一半错了。
- **`PUT /api/config/<服务>` 是整体替换**：未提供的字段会回落到默认值，因此空对象 `{}` 会被拒绝（400），
  避免「curl 打错一次就把 token/凭据/路径清空」。控制台界面总是发送完整配置段。
- **会话 cookie** 带 `HttpOnly`、`SameSite=Lax`，并在真正以 HTTPS 服务时带 `Secure`（明文回退时不会误标）；
  控制台自身的会话 cookie 不会被转发给 `/et` 上游。控制台界面渲染的所有服务端数据都经过 HTML 转义
  （frps 的代理名来自远端 frpc 客户端，属于不可信输入）。
- 证书路径若不在 unveiled 目录内（`/etc/remgr`、`/var/lib/remgr` 等）会在绑定阶段失败，
  此时 `/api/status` 的 `console.tls_active` 为 false（界面提示「HTTPS 未生效」）。
- **终止信号会记录来源（能记多少记多少）**：`SIGTERM`/`SIGINT` 触发优雅停机（逐模块停止后退出），日志写明信号种类与内核给出的原因
  （`si_code`，用来区分「某个进程发了 kill(2)」还是「内核发的」）。**但实测结论：OpenBSD 的 `kill(2)` 不填发送者** ——
  `si_code=SI_USER(0)` 而 `si_pid`/`si_uid` 恒为 0（C 探针在「别的进程发」「shell 发」「自己 raise」三种情况下都验证过），
  OpenBSD 也没有 `sigqueue(3)`。因此这一行在 OpenBSD 上是
  `SIGTERM received with no sender reported by the kernel (sent by a process: kill(2)/raise(3))`，
  在会报告发送者的平台（Linux 等）上则是 `… from pid N (uid M) …`。
  **真正的取证靠内核记账**：收到终止信号时读取 `/var/account/acct` 尾部 12 条，把「信号前刚执行过的命令」写进日志 ——
  命令名、uid、pid、起始时间、结束方式（被信号杀死 / pledge 违规 / core dump …），例如
  `accounting: 2026-09-26T01:53:11Z ksh uid=0 pid=4711 (normal exit)`。前提是开启记账：
  `echo 'accounting=YES' >> /etc/rc.conf.local; accton /var/account/acct`（本机已开启；账本 64 字节/条，
  实测约 2.7 MB/小时）。**注意轮转陷阱**：OpenBSD 的 `daily(8)` 对记账文件是 `cp`（复制）而**不截断**正在写入的文件，所以它既会无限增长、又会每天把当时的大小冻成一份新世代（4 份）——磁盘紧张时这是会填满磁盘的隐患。因此 `scripts/remgr-watchdog.sh` 里加了上限（16 MiB）与规范轮转（`accton` 关 → `mv` 成 `.0` → 再开）；关掉记账用 `accton`（不带参数即停用）。未开启记账时，日志会明确写一行说明，而不是假装有记录。
  处理器另外把一条原始记录（`signal <n> from pid=<pid> uid=<uid> code=<code>`）**直写日志文件描述符**：
  即使紧随其后的第二个终止信号立刻结束进程（第二个终止信号不再等优雅停机，直接 `_exit`），证据也已经落盘。
  **`SIGHUP` 只记录、不退出**：本服务没有需要重新读取的磁盘配置（控制台的改动是写配置文件并自行重绑监听），
  而 `rcctl reload`（rc.subr 默认 reload 信号就是 HUP；`scripts/rc.d/remgr` 已声明 `rc_reload=NO`）
  或终端挂断把中继服务静默杀掉，比"在日志里说一句"糟糕得多。
  实现上用 `SA_SIGINFO` 自装处理器（tokio 的 signal API 拿不到 siginfo），并且**故意不转发**给依赖自己注册的处理器：
  RustDesk 的 hbbs 在 `tokio::select!` 里等 TERM，收到后直接 `process::exit(0)`（`rendezvous_server.rs`），
  转发等于把退出权交给它 —— 实测症状正是停机日志在 EasyTier 的 `I/O error: socket closed` 处断掉、没有收尾行。
  现在退出只由一个地方决定：本处理器 → `main` 里的模块逐个停止 → `exit(0)`。
  顺带：libc crate 给 OpenBSD 的 `siginfo_t` 定义有误（声明 128 字节、`si_pid()` 读偏移 128；实际 136 字节、字段在 16/20），
  所以这里按实测偏移自行读取。
- **日志不会阻塞服务**：作为服务启动时 stdout 是 rc.subr 的 `logger -isp` 管道（`-s` 让 logger 把每行再回显到自己的 stderr，
  而对「从 SSH 会话里 `rcctl start` 的实例」来说后者就是那条会话通道，会话一结束就断）。
  本机实测存在卡死数小时的 `logger` 进程：64 KiB 管道一旦填满，**阻塞式**写日志会把整个守护进程（连控制台一起）冻住。
  因此非终端场景下 stdout 被设为非阻塞，日志写入改为直接 `write(2)`（不经过 Rust 的 `BufWriter`——它会把写不出去的字节
  留在缓冲区里无限增长），管道满或已关闭时丢弃该行而不是报错；服务路径上的 `println!`/`eprintln!` 也换成不会 panic 的写法。
- **进程组由 rc.subr 隔离（实测）**：`rc_bg=YES` 让 rc.subr 用 `set -o monitor` 启动守护进程；从 SSH 会话里
  `rcctl restart remgr` 后实测新实例的 `PGID` 等于它自己的 pid（`PPID=1`），**不会**留在该会话的进程组里。
  这点值得实测而不是假设：同一台机器上别的服务（另一项目的 `ksh -c` 子进程）就留在了早已退出的会话进程组中，
  一旦那个 pgid 被后续会话复用，任何 `killpg` 都会误伤它们。
- 磁盘：根分区曾因写满而被内核杀死进程（本机长期在 90% 以上，目前约 1.4 GiB 空闲）。日志按 8 MB 轮转保留一代，写不进去时服务不会崩、也不会报错（但会在 stderr/日志里报一次）；配置保存是原子的，不会留下半截文件。细节见「磁盘与 fd 压力下的行为」。

## CI（`.github/workflows/ci.yml`）

每次 push / PR 跑三个 job：

1. **frp 协议 crate** —— `remgr-frps` 构建 + 16 个单元测试 + 互通自检程序（`examples/frpc_probe --self-test`）。这个 crate 是刻意保持跨平台的（`scripts/check-repo.sh` 会强制这一点），所以能在 Linux runner 上真跑。
2. **控制台** —— 单文件脚本能解析（`node --check`）、每个 inline 属性引用的处理函数都存在、每种 widget 都有渲染分支、每个证书服务与 API 端点都在 router 里（`scripts/check-console.sh`），外加仓库卫生检查（无凭据/密钥/日志/编译产物）。
3. **release build（矩阵：linux-x86_64 / windows-x86_64）** —— 完整服务编译成 release，各自跑该平台的 `remgr-frps` 测试**和服务本体（`remgr`）的单元测试**（信号来源记录、路径布局），产物以 artifact 形式保留 30 天。随后按平台做力所能及的运行期验证：
   - **Linux：真实运行**（用 scratch `REMGR_HOME` 启动、等控制台起来、校验首次启动写入了文档里的默认登录并生成 P-384 证书、用 HTTPS 登录、确认整棵布局 `config`/`ssl`/`lib`/`log`/`run` 都落在 home 下、再用 SIGTERM 关掉）。
   - **Windows：导入校验**（扫描 `remgr.exe` 的导入表确认 `Packet.dll` 在其中，把「需要 Npcap」变成可测事实）；真正的运行期冒烟测试脚本也写好了，但它**只在机器已装 Npcap 时才执行**，否则明确报告「未运行」及原因——因为免费版 Npcap 无法静默安装（`/S` 仅 OEM），CI 不能替操作者接受许可协议。

两个平台都要装 **LLVM**（`kcp-sys` 与 `machine-uid` 在构建期跑 bindgen）和 **protoc + well-known types**（`easytier-proto` 生成 protobuf 类型）。后者容易踩：Ubuntu 上 `.proto` 文件在 `libprotobuf-dev` 里而不是 `protobuf-compiler`，所以 workflow 从实际文件反推 include 根目录，并在准备阶段用一行 protoc 探针先验证，避免等 20 分钟才在依赖输出里看到同样的报错。

> **CI 绿灯不等于 OpenBSD 编译通过**：GitHub 没有 OpenBSD runner，`remgr`（服务本体）在那个平台上只能手工构建与部署——这也是为什么上面的检查清单和 `scripts/preflight.sh` 存在。做重大改动后请在目标机上跑一次 `sh scripts/preflight.sh`。

## 生产部署检查清单

```sh
install -m 755 target/release/remgr /usr/local/bin/remgr
install -m 555 scripts/rc.d/remgr /etc/rc.d/remgr
install -m 644 scripts/login.conf.d/remgr /etc/login.conf.d/remgr
rcctl enable remgr && rcctl start remgr
sh scripts/preflight.sh        # 只读核对，任何 FAIL 都要处理
```

- **`rc_bg=YES` 不能删**（`scripts/rc.d/remgr` 里已写明原因）：remgr 不 fork，rc.subr 会在前台运行它，没有 `rc_bg` 时 `_rc_wait_for_start` 不会提前跳出轮询，于是 `rcctl start/restart remgr` **空等到 daemon_timeout 结束**，打印 `remgr(timeout)` 并返回 **1** —— 服务其实是好的，但启动序列被拖了两分钟、退出码还告诉调用方失败了。用同一份脚本改指向 scratch 实测量化：修前 `start` 2m00.5s/rc=1、`restart` 2m00.1s/rc=1；加 `rc_bg=YES` 后 `start` 0.54s/rc=0、`restart` 0.61s/rc=0。日志里从 `starting` 到最后一个 `listening` 只有 0.2–0.4 s，所以 `daemon_timeout` 保留 120 s 只是「进程压根没起来」的上界（真触发时 rc.subr 会杀掉启动任务，也就是杀掉服务，别调小）。
- **不需要 `rc_pre`/`rc_post`**：`secure::prepare_dirs` 每次启动都会建 `/etc/remgr`、`/var/lib/remgr`、`/var/db/remgr`、`/var/log/remgr`、`/var/run/remgr`，重启后 `/var/run` 被清空也照样起来。
- **fd 上限必须显式给**：rc.subr 通过 `su -fl -c <登录类>` 启动，脚本里写 `ulimit -n` 会被丢弃，因此默认落到系统的 `daemon` 类：`openfiles-cur=128`（`kern.maxfiles=7030`，系统天花板远不是瓶颈）。以同样方式启动真实二进制作压力测试：把 200 条连接**挂着不发请求**，进程涨到 128 个 fd 就停住，此时新的控制台请求**完全无响应**（日志里也没有任何报错），客户端断开后才恢复；换成 `openfiles-cur=1024` 同样 200 条全部服务。装 `scripts/login.conf.d/remgr` 后 rc.subr 会按名字选中 `remgr` 类（`daemon_class=remgr`）。注意 login.conf 取**首个**同名属性，覆盖项必须写在 `:tc=daemon:` **之前**（把两行交换就退回 128，实测过）。
- 装完 `rcctl restart remgr` 应在 1 秒内返回 0；`/etc/rc.d/remgr` 与仓库副本必须逐字节一致（`preflight.sh` 用 md5 核对，这个文件曾经漂移过）。
- **没有任何东西会自动拉起重挂的服务**（OpenBSD 的 rc.subr 不托管前台守护进程）。实测过：2026-09-26 remgr 三次收到外部 SIGTERM 后都按设计干净退出（日志里模块逐个停止），此后前两次分别**停了 4 小时 31 分、1 小时 43 分**才被人工拉起，第三次（看门狗装好后）49 秒就被拉回——前两次的停机期间没有任何通知。
  若要它自愈，用仓库里的 `scripts/remgr-watchdog.sh`（默认**不安装**：看门狗和运维主动停机是冲突的）。它的动作写进 `/var/log/remgr/watchdog.log`（外加 syslog），一行一次，便于回答「多久重启一次、从什么时候开始不对劲」：
  ```sh
  install -m 555 scripts/remgr-watchdog.sh /etc/remgr/remgr-watchdog.sh
  crontab -l > /tmp/ct 2>/dev/null; echo '*/2 * * * * /etc/remgr/remgr-watchdog.sh' >> /tmp/ct; crontab /tmp/ct
  ```
  它只在 `rcctl ls on` 且 `rcctl check` 失败时用 `rcctl -f start` 拉起，并把「不在运行 → 已恢复」或「没起来（附 rcctl 输出）」写进 syslog；实测停掉服务后 6 秒内恢复。**经 `rcctl ls off` 禁用的服务它不会碰**。

## 升级（替换二进制）

```sh
cp -p /etc/remgr/config.toml /etc/remgr/config.toml.bak.$(date +%F)   # 含口令哈希/token，先备份
install -m 755 target/release/remgr /usr/local/bin/remgr.new           # 先写到旁边的临时名
mv -f /usr/local/bin/remgr.new /usr/local/bin/remgr                    # 再 rename 覆盖（见下）
rcctl restart remgr                                                   # 应立刻返回 0
tail -5 /var/log/remgr/remgr.log      # 应看到 "starting" 与 "openbsd sandbox active"
sh scripts/preflight.sh
```

- **不要用 `cp`/`install` 直接覆盖正在运行的二进制**：内核会拒绝写入被作为可执行文件打开的文件，报 `Text file busy`（ETXTBSY）。实测踩过：`cp target/release/remgr /usr/local/bin/remgr` 失败，而当时的部署脚本是「先 `rcctl stop`、再 `cp`」——
  一旦 `cp` 失败（`set -e`）脚本就在 `start` 之前中止，**服务留在停止状态，日志里只有一次干净的停机、没有任何启动记录**，正是本仓库里三次「不明原因死亡」的记录特征。
  正确做法是 `mv`（rename）覆盖：运行中的进程继续持有旧 inode，重启后自然用上新二进制。若确实要先停后装，请在 `start` 之前显式校验二进制（大小/`--version`），失败就立刻拉起旧的。

- **配置兼容性（实测）**：
  - 旧配置缺字段能加载：所有结构体都是 `#[serde(default)]`；没有 `[frpc]` 段、没有 `console.username` 的文件照样起，缺的字段取默认值并在下次保存时补写进文件。
  - 新配置带未知字段也能加载：旧二进制忽略它 —— **但下一次保存就把未知字段丢掉了**，所以**回滚前必须先备份配置**，并确认要回滚到的版本认识里面的字段。
  - 解析失败**不会**静默退回默认值：进程以退出码 1 结束，stderr 给出带行列号的 TOML 错误（`remgr: fatal: TOML parse error at line 2, column 8 … invalid type: string "not-a-number", expected u16`）。
  - `--config <相对路径>` 可用：启动时按当时的工作目录解析成绝对路径，之后 chdir 到 `/var/lib/remgr` 也不会读错；但配置**必须落在 unveiled 目录内**（见下）。
- 回滚：放回旧二进制 + `rcctl restart remgr`。日志时间戳是 **UTC**（本机时区是 UTC+8），`grep starting /var/log/remgr/remgr.log | tail -1` 就是新进程的起点。
- 升级后重点看：`/api/status` 里 `console.tls_active` 是否为 true、五个模块是否 `running`、日志里有没有新的 `EPERM`/`unveil`/`ENOENT`。

## 磁盘与 fd 压力下的行为（实测）

- **fd 耗尽（EMFILE）**：症状是「连接挂着、请求无响应、日志无异常」，不会崩溃，客户端断开后自愈。监控 `fstat -p $(pgrep -x remgr) | wc -l`（空闲时约 55 行，含 `text`/`wd` 两行非 fd）。连接抖动本身不泄漏：200 次「连接-请求-断开」循环前后 fd 数量完全不变；1024 上限下 200 条并发全部服务、用完即还。
- **磁盘写满**：
  - 日志：`remgr.log` 的写入是尽力而为，写失败**不中断服务也不报错**（只有进程**首次打不开**日志文件时会在 stderr 说一次 `file logging disabled`）。所以磁盘满时控制台仍可用、内存环形缓冲（1000 行）与 WebSocket 实时日志仍正常，但**落盘历史会静默停止** —— 这是目前最需要盯的一条。
  - 配置：`Config::save` 先写 `config.toml.tmp`、fsync、再 rename，因此**不可能**留下被截断的 `config.toml`；保存失败时内存里的配置也不提交（不会出现内存与文件不一致），API 报错、原文件 md5 不变。代价是磁盘满期间会残留半截 `config.toml.tmp`（`.gitignore` 里有这个模式，恢复后下次保存会覆盖它）。
  - 证书：`write_service_cert` 同样先写 `.new` 再 rename，失败不破坏正在使用的那对，只留下 `.new` 垃圾文件。
  - **首次启动**若 `password_hash` 为空，`cfg.save()?` 失败会让进程直接退出（exit 1）——这个取舍是对的：此时还没有任何生效的口令，带着默认口令继续对外服务比退出更糟。而服务**已经在跑**时（控制台保存配置失败）只让那一次请求失败、服务不退出，同样是对的。
- **unveil 的硬约束**：配置文件与证书路径必须落在 unveiled 目录里（`/etc/remgr`、`/var/lib/remgr`、`/var/db/remgr`、`/var/log/remgr`、`/var/run/remgr`、`/etc/ssl`）。实测把控制台证书指到 `/tmp`：证书会被生成、`tls = true` 会被写进配置，但沙箱生效后读不到 → 日志报 `console settings unusable: … No such file or directory` 并**回落到明文 HTTP**（`/api/status` 的 `console.tls_active=false`，界面提示 HTTPS 未生效）。同理 `--config /tmp/x.toml` 能启动，但之后每次保存都返回 `400 {"error":"No such file or directory"}`。
- **TUN 数量**：EasyTier 每个用 tun 的实例占一个 `/dev/tunN`（当前节点用 `tun0`）。`unveil` 放开 `tun0-15`，但真正能用的数量是机器上**存在的设备节点**数（本机只有 `tun0-3`）；要多跑网络实例先 `MAKEDEV tun4 …`。

## License

- ReMgr：AGPL-3.0
- 第三方源码随各自许可证（见 `third_party/` 内相应 LICENSE）。
