# MSFile Go NAS 服务运行手册（V1 硬切换版）

> 本手册描述 20260825-2 硬切换之后的正式形态。旧的 objects 对象仓库、SQLite 白名单表和
> Web 文件上传/删除能力已全部删除，不再存在兼容模式。

## 1. 能力与数据模型

正式入口位于 `labs/webrtc-go/cmd/msfile-nas`，只接收 `--config` 一个配置来源：

```bash
msfile-nas --config /etc/msfile-nas.yaml            # 启动服务
msfile-nas --config /etc/msfile-nas.yaml --check-config  # 仅校验配置
```

服务提供三类接口：

1. `/msfile/1.0.0`：运行在已认证 libp2p stream 上的 MSFile Proxy V1（Stat/Read）；
2. WebRTC Direct、WS、WSS：libp2p transport；WS/WSS 与普通 Web 共用同一个 TCP 入口；
3. Web 公共内容索引：平面 Hash 索引、文件详情与按文件名下载。

### 两个数据区

```text
nas_data/                     # 用户原文件唯一真值；服务只读，绝不改变布局
├── 电影/movie-a.mkv
└── 文档/report.pdf

seed_data/                    # 全部派生数据；删除后可从 nas_data 完整重建
├── seeds/ab/cd/<seed_hash>.seed   # MasterSeed 原始二进制（两级 Hash 前缀分散）
├── staging/                       # 尚未原子发布的临时 Seed
├── trash/                         # 已解除索引、等待安全清理的 Seed
├── index.sqlite                   # 平面 Hash 索引（contents/file_locations/seed_blocks/scan_runs）
└── service.lock                   # 防止两个服务进程同时管理同一 seed_data
```

读取路径冻结如下：

```text
Read(seed_hash)  -> 从 seed_data 的 .seed 文件返回（要求至少一个 valid 原文件位置）
Read(block_hash) -> 查询一个 valid 原文件位置 -> 对 nas_data ReadAt(offset,length)
                 -> SHA-256 校验通过后才返回；失败 fail closed 并标脏重索引
```

## 2. SQLite 并发模型

`internal/indexdb` 是唯一数据库入口：

```text
watcher / scanner / hash worker / MSFile / Web
        │
        ▼
 有界异步请求队列（满载背压）
        │
        ▼
 单个 SQLite executor goroutine
        │
        ▼
 唯一 *sql.DB（MaxOpenConns = 1，WAL + foreign_keys + busy_timeout）
```

业务包拿不到底层 `*sql.DB`；慢磁盘 Hash 与网络读写都不在执行器内进行。
检测到旧版 schema（`files`/`objects`/`clients` 等表）时会中文报错并拒绝启动，
绝不自动迁移或删除：

```text
检测到不兼容的旧版数据库：该 SQLite 包含旧对象仓库或 clients 白名单表。
V1 硬切换不支持自动迁移；请备份后改用空的 seed_data 目录重新建立索引
```

## 3. 同步模型

- **文件事件**（fsnotify 递归 watch）负责快速发现；创建/修改/删除/重命名都会调度到协调器；
- **周期全量扫描**（默认 10 分钟）负责最终一致性：generation 批次号防误删，
  失败子树整体转 invalid 而不是删除；
- **稳定性检测** stat A/B/C 阻止把正在复制的文件发布成半成品；
- 同一路径的 revision 计数保证旧 Hash 任务不能覆盖新结果；
- 文件不可见立即停止对外提供；DB/Seed 保留 24 小时，期内同指纹恢复不重算，
  超期由 GC 只清理派生数据（Seed 先移入 trash 再异步删除）。

## 4. 访问控制

- `github.com/bsv8/bitcoin-libp2p@v0.1.0` 是 libp2p 身份与连接认证上游真值：
  统一校验 secp256k1 私钥范围、压缩公钥、PeerId 推导和连接公钥绑定；
- `access_mode: private`：仅允许配置文件 `public_key_whitelist` 中的压缩公钥；
  列表为空等价拒绝全部，不存在 allow-all 回退；
- `access_mode: public`：任何 libp2p Noise 已认证的 secp256k1 客户端可用；
  服务端实施全局并发 Read 上限（默认 16），换公钥无法绕过；
- 授权判断只使用 connection 层认证出的远端公钥，报文自报身份不参与；
- WSS 的 TLS 不替代 Noise 与 PeerId 校验。

MSFile 不复制上游身份协议，也不增加私有握手字段。`/msfile/1.0.0` 只运行在
标准 Noise/Yamux 已认证连接之上。WebRTC Direct、WS/WSS transport 仍由 NAS 显式装配；
这是因为上游 V1 的不可提取身份 host 不承诺需要 `PrivKey.Raw()` 的 WebRTC 构造路径，
不代表 MSFile 可以自行定义另一套公钥或 PeerId 规则。

## 5. 网络入口与 Web 公共内容索引

### 5.1 同端口 Web/WS 分流

`listen` 是 NAS 进程在本机真正绑定的 transport 地址，至少要有一条 `/ws` 或 `/tls/ws`
入口。普通 Web 与 libp2p WebSocket transport 使用同一个 TCP listener：

```text
HTTP request（没有 Upgrade）       -> Web Handler（页面与 HTTP API）
HTTP/1.1 WebSocket Upgrade        -> libp2p WebSocket transport
                                      -> Noise -> Yamux -> /msfile/1.0.0
```

施工后不会再由 `admin_listen` 创建第二个 `net.Listen`。`admin_listen` 仍作为旧配置兼容字段
接受，但实际绑定、端口和安全校验都以 `listen` 为准；新配置可删除该字段。若旧配置仍保留，
启动时会输出一次中文弃用提示。
长下载只受 HTTP header 读取和空闲连接限制，不会被 WebSocket handshake timeout 截断。

推荐反向代理终止 TLS 的配置形态：

```yaml
# WebRTC Direct 公网 UDP 基础地址：只写 IP/DNS、UDP 端口和 /webrtc-direct。
# certhash 与 /p2p/<PeerId> 由运行中的 host 自动补齐。
webrtc_direct_public_addresses:
  - "/dns4/direct-nas.example.com/udp/4001/webrtc-direct"

# 本机实际 listener；普通 Web 和 WS 共用下面的 TCP 入口。
listen:
  - "/ip4/0.0.0.0/udp/4001/webrtc-direct"
  - "/ip4/127.0.0.1/tcp/4002/ws"

# 非 loopback 共享入口必须配置，保护 /api/status 与 /api/scans。
admin_token: "替换为随机长 token"
```

上例对应“同机反向代理终止 TLS”：Nginx/Caddy 监听公网 443，并把 HTTPS/Upgrade 透明转发到
`127.0.0.1:4002`。代理已经占用 443 时，NAS 不得再次绑定 `0.0.0.0:443/ws`。

如果 NAS 直接终止源站 TLS，使用下面的独立形态（不要与上例的 4002 源站同时配置）：

```yaml
listen:
  - "/ip4/0.0.0.0/udp/4001/webrtc-direct"
  - "/ip4/0.0.0.0/tcp/443/tls/ws"
tls_cert_file: "/etc/msfile-nas/tls.crt"
tls_key_file: "/etc/msfile-nas/tls.key"
admin_token: "替换为随机长 token"
```

Cloudflare 使用 Full (Strict) 时，源站证书必须合法、未过期且覆盖访问域名；`/tls/ws` 与
证书/私钥的错配会在 `--check-config` 阶段拒绝。
反向代理必须透明透传 WebSocket Upgrade 和二进制字节，不得缓存或解析 MSFile Frame。

### 5.2 WebRTC Direct 公网地址

`webrtc_direct_public_addresses` 是客户端从公网拨号的地址，不是本机 listener 的替代品。
每项只允许以下形态：

```text
/ip4/<公网 IP>/udp/<端口>/webrtc-direct
/ip6/<公网 IP>/udp/<端口>/webrtc-direct
/dns4/<域名>/udp/<端口>/webrtc-direct
/dns6/<域名>/udp/<端口>/webrtc-direct
```

地址必须使用 `1..65535` 的 UDP 端口；禁止 `/certhash`、`/p2p`、`/ws`、`/tls` 和其他协议
段；IP 不能是 unspecified、loopback、multicast、link-local 或明确的私网地址；重复项按
首次出现顺序去重。监听 WebRTC Direct 却不配置公网基础地址，或未监听却配置该字段，都会在
创建 listener 前失败。DNS 不在启动时解析，也不由服务判断 Cloudflare 橙云状态。

服务从运行中 WebRTC Direct listener 取得 `certhash`，再加上当前 host 的 PeerId，形成页面中
可复制的完整地址。服务不会从本机地址、STUN、UPnP、NAT-PMP 或 Cloudflare Header 推测公网地址。

### 5.3 公共页面与 API

公共页面不需要 Bearer Token，展示“网络接入地址”与内容索引。`GET /api/network-info` 是
拨号方需要的最小公开接口，响应字段如下：

| 字段 | 中文含义 |
|---|---|
| `peer_id` | NAS 业务私钥派生的 libp2p PeerId |
| `supplier_public_key` | NAS 的 33 字节压缩 secp256k1 公钥 hex |
| `webrtc_direct_addresses` | 已补齐 `certhash` 和 PeerId 的公网 WebRTC Direct multiaddr |

该接口只允许 `GET`、不要求 token，响应使用 JSON、安全响应 Header 和 `Cache-Control: no-store`。
listener 已开始接收请求但运行时 `certhash`/PeerId 地址快照尚未完成时，返回 `503` 和中文错误码
`network_info_not_ready`；页面会短暂退避后重试，不把空地址列表当作“已就绪”。
它不会返回 WSS multiaddr、本机 `listen_addresses`、私钥、白名单、admin token、数据路径或
Cloudflare 凭据。WSS 地址由页面使用当前浏览器的 `window.location.hostname` 与有效端口生成：

```text
HTTPS 页面 -> /ip4|ip6|dns4/<当前域名>/tcp/<端口>/tls/ws/p2p/<peer_id>
loopback HTTP 开发页 -> /ip4|ip6|dns4/<当前主机>/tcp/<端口>/ws/p2p/<peer_id>
公网 HTTP 页面 -> 显示“公网浏览器必须使用 HTTPS/WSS”，不生成生产 WSS 地址
```

页面不会修改或保存地址，也不把“显示地址”当作“已从外网验证可达”。WSS 与 WebRTC Direct
即使使用相同 hostname，也分别是 TCP/TLS 和公网 UDP 两条独立路径；普通 Cloudflare 橙云
记录通常不能把 UDP 直接导向 NAS。

列表只返回 `ready` 且至少有一个 `valid` 文件位置的内容；公共详情不暴露 NAS 内部路径。
其余方法返回中文 `405`；不存在白名单 CRUD 或原文件写路由。

为兼容已有脚本，`GET /api/status`、`GET /api/scans`、`POST /api/scans` 仍保留，
但不出现在公共页面，且继续要求 `admin_token`（Bearer）。`admin_token` 为空时表示运维 API
禁用，受保护接口始终返回 401；`access_mode=public`
不会改变这些兼容运维接口的认证要求。`/api/status` 中：

| 字段 | 中文含义 |
|---|---|
| `listen_addresses` | 本机实际绑定/运行的 transport 地址 |
| `webrtc_direct_public_addresses` | YAML 配置的 WebRTC Direct 公网基础地址 |

`/api/status` 不生成 WSS 公网地址。

## 6. 一次性切换与回滚

切换步骤见施工单 §7。要点：

1. 停止旧 binary，备份旧配置、旧 SQLite 和旧 `data/objects`（服务绝不自动删除）；
2. 准备显式指定 `nas_data`/`seed_data`/`access_mode` 的新 YAML；
3. 若目标 `seed_data` 含不兼容旧库，改用空目录或人工备份后重建；
4. 启动新 binary，首次全量扫描完成后才对外公布新地址。

回滚单位是整个 release：停新进程 → 保留失败现场 seed_data → 恢复旧 binary/配置/数据库。
`nas_data` 从未被新服务写入，无需恢复。

## 7. 常见运维操作

```bash
# 校验配置
msfile-nas --config /etc/msfile-nas.yaml --check-config

# 查看日志事件（JSON，中文 reason_zh）
journalctl -u msfile-nas -f | jq 'select(.event|test("scan|gc|watcher"))'

# 共享 Web/WS 入口上的兼容运维接口：手动触发全量扫描（公共页面不提供此按钮）
curl -s -X POST -H "Authorization: Bearer $TOKEN" https://nas.example.com/api/scans

# 公开网络信息（不带 token；只返回 PeerId、公钥和已补齐的 WebRTC Direct 地址）
curl -s https://nas.example.com/api/network-info | jq

# 读取受保护状态（实际地址以 listen 中的共享入口为准）
curl -s -H "Authorization: Bearer $TOKEN" https://nas.example.com/api/status | jq \
  '{peer_id, listen_addresses, webrtc_direct_public_addresses, counts, scan_running}'

# 从零重建索引（确认 nas_data 无需变更后）
systemctl stop msfile-nas
mv /var/lib/msfile-nas /var/lib/msfile-nas.bak-$(date +%F)
systemctl start msfile-nas   # 新空 seed_data 自动重建
```
