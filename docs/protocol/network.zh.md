# MSFile Proxy Network Protocol v1

> 状态：V1 网络设计真值。
>
> 本文定义 MSFile 的供应商身份、libp2p transport、连接认证、双 stream 模型和多供应商调度。
> CBOR Header、raw attachment、请求覆盖和错误报文见
> [MSFile Proxy Wire Messages v1](./wire-messages.zh.md)。

---

## 1. 设计结论

MSFile V1 网络层统一规定：

1. Keymaster/客户端和供应商都运行兼容的 libp2p 实现；
2. 只支持 WebRTC Direct 与 WebSocket/WSS 两种 libp2p transport；
3. MSFile 不直接运行在裸 RTCDataChannel 或裸 WebSocket 上；
4. WebRTC Direct 适合供应商具有客户端可达 UDP 地址的场景；
5. WSS 是浏览器到服务器/NAS 的生产环境 TCP/TLS 直连路径；
6. WS 只用于本机开发或受控可信网络；
7. 不使用 relay-signaled WebRTC、Circuit Relay 或文件数据中转；
8. 节点 identity 使用业务身份同一把 secp256k1 私钥；
9. 供应商 ID 是 libp2p 已认证出的 33 字节压缩公钥；
10. PeerId 从该公钥按 libp2p 规则派生，不是另一套供应商 ID；
11. libp2p 已完成连接握手、密钥证明和协议协商，MSFile 不增加应用层握手；
12. 每个供应商 connection 使用一条 Stat stream 和至多一条 Read stream；
13. Stat 对所有已启用供应商并发发送，Read 按供应商公钥定向发送；
14. connection、stream 和业务 Frame 是三个不同生命周期，不能相互代替。

---

## 2. 分层模型

### 2.1 WebRTC Direct

```text
Keymaster / Client
  └── MSFile Stat stream + Read stream
       └── libp2p authenticated connection
            └── WebRTC Direct transport
                 └── reliable RTCDataChannel streams
                      └── UDP/IP
```

WebRTC Direct transport 使用 WebRTC DataChannel 自带的 stream multiplexing。每条 libp2p stream
对应独立 DataChannel；MSFile 不自行管理 DataChannel ID。

### 2.2 WSS

```text
Keymaster / Browser
  └── MSFile Stat stream + Read stream
       └── libp2p authenticated connection
            └── Noise + Yamux
                 └── WebSocket
                      └── TLS/TCP/IP
```

WSS 的 TLS 证书认证域名并保护 WebSocket 接入，但不替代 libp2p 节点身份认证。V1 的 WSS
实现使用 Noise 认证远端 PeerId，并使用 Yamux 在一个 connection 上复用 stream。

### 2.3 应用边界

Connect App 不直接取得 libp2p host、私钥、RTCDataChannel 或 WebSocket。App 只调用 Keymaster
提供的 MSFile service；Keymaster 负责：

- 节点身份与私钥隔离；
- 供应商公钥 pin；
- 地址选择和连接复用；
- Stat 广播与结果聚合；
- Read 定向调度；
- Frame、哈希、尺寸和价格授权校验。

---

## 3. 节点身份与认证

### 3.1 密钥口径

客户端和供应商必须使用：

```text
key_type          = secp256k1
private_key_bytes = 32 bytes
public_key_bytes  = 33-byte SEC1 compressed public key
```

压缩公钥首字节必须是 `0x02` 或 `0x03`。配置与展示可以使用 66 个小写 hex 字符；wire、授权和
密码学内部使用原始 33 字节。

节点把业务私钥作为 libp2p identity private key：

```text
business_private_key
  ├── supplier/client public key
  └── libp2p PeerId
```

不得另建一把与业务身份无关的临时 libp2p 私钥，也不得在 MSFile Frame 内自报另一把公钥。

### 3.2 `supplier_id`

MSFile 的供应商身份定义为：

```text
supplier_id = authenticated_remote_secp256k1_public_key
```

- 二进制形态是 33 字节压缩公钥；
- UI、日志和配置可以显示为 66 字符小写 hex；
- PeerId 是它的 libp2p 派生标识，用于 multiaddr 与连接层；
- 响应属于哪个供应商，由承载响应的 authenticated connection 决定；
- StatResponse、ReadResponse 和 ErrorResponse 不携带 `supplier_id` 字段。

客户端不能信任报文、文件名、Seed 或 URL 中声明的供应商身份。

### 3.3 libp2p 握手已经足够

WebRTC Direct 规范在专用 DataChannel 上执行绑定 DTLS fingerprint 的 Noise XX 身份认证，
认证成功后才使用普通 DataChannel 承载 protocol stream。WSS 路径在 transport upgrade 中执行
Noise，并在其后使用 Yamux。

因此 MSFile 不再定义 `Hello`、challenge、重复公钥交换、应用签名或 session token。开始处理
`/msfile/1.0.0` Frame 前，实现只需确认：

1. libp2p connection 已完成身份认证；
2. remote PeerId 与认证出的 remote public key 一致；
3. remote public key 满足本地白名单或授权策略；
4. connection 使用本文允许的 transport。

### 3.4 双向 pin 与白名单

客户端必须 pin 供应商公钥：

1. 从 `supplier_public_key` 派生期望 PeerId；
2. 配置地址尾部 `/p2p/<peer-id>` 必须与期望 PeerId 一致；
3. libp2p 握手认证出的远端身份必须再次一致；
4. 任一不一致都关闭 connection，不提供“仍然继续”选项。

供应商按 authenticated client public key 授权至少以下能力：

- 是否允许 Stat；
- 是否允许 Read Seed；
- 是否允许 Read 文件块；
- 单次与累计预算策略；
- 请求频率、并发、带宽和缓存上限。

报文没有 API Key、Bearer Token、Cookie 或客户端公钥字段。

### 3.5 Keymaster Vault 边界

“使用同一把私钥”不表示 Connect App 可以读取 raw private key：

- libp2p identity 只由 Keymaster 受信任核心或 Vault 运行时持有；
- Vault 锁定时停止 libp2p host 并关闭全部供应商 connection；
- active key 切换时关闭旧 host，以新密钥重建，PeerId 随之变化；
- 私钥不得写入 localStorage、日志、错误、配置或跨 App 消息。

---

## 4. 供应商配置与地址

每个供应商至少配置：

```text
name                 // 本地显示名称，不进入 wire
supplier_public_key  // 33 字节压缩 secp256k1 公钥
addresses[]          // 一个或多个可拨号 libp2p multiaddr
enabled              // 是否参加 Stat 并发查询
```

WebRTC Direct 示例：

```text
/dns4/nas.example.com/udp/4001/webrtc-direct/certhash/<multihash>/p2p/<supplier-peer-id>
```

WSS 推荐规范形态：

```text
/dns4/proxy.example.com/tcp/443/tls/ws/p2p/<supplier-peer-id>
```

实现可以接受 libp2p 库规范化后的 `/wss` 别名，但持久化和文档输出应优先使用
`/tls/ws` 形态。开发环境 WS 示例：

```text
/ip4/127.0.0.1/tcp/8080/ws/p2p/<supplier-peer-id>
```

规范性规则：

- `supplier_public_key` 必须能派生地址中的最终 PeerId；
- address 只能是 `webrtc-direct`、`ws` 或 `tls/ws`；
- 生产浏览器不得通过不安全公网 WS 发送 MSFile 数据；
- 一个供应商可以同时发布 WebRTC Direct 和 WSS 地址；
- 地址优先级是本地策略，不是 wire 字段；
- DNS、DDNS、二维码和配对流程不进入 MSFile wire，最终只产生公钥与 multiaddr。

### 4.1 NAS Web 与 WSS 的部署地址来源

NAS 的普通 Web 页面/API 与 libp2p WS/WSS 共用同一个源站 TCP listener：没有 HTTP Upgrade 的
请求进入 Web Handler，WebSocket Upgrade 进入 libp2p WebSocket transport，随后仍执行 Noise、
Yamux 和 `/msfile/1.0.0`。这只是部署分流，不增加裸 WebSocket 业务协议，也不改变 wire 语义。

WSS 公网 multiaddr 不写入 NAS YAML，也不从 `listen`、`Host.Addrs()`、`Host` Header 或代理
Header 推导。NAS Web 页面读取公开网络信息接口取得 PeerId，再用当前浏览器的
`window.location.hostname` 和 HTTPS 有效端口生成：

```text
/ip4|ip6|dns4/<当前页面主机>/tcp/<HTTPS端口>/tls/ws/p2p/<PeerId>
```

WebRTC Direct 的公网 IP/DNS 与 UDP 端口则必须由 NAS YAML 的
`webrtc_direct_public_addresses` 显式提供；服务运行时只补齐 listener 产生的 `certhash` 和
PeerId。两种地址都不是“显示出来即已验证公网可达”。

---

## 5. Transport 行为

### 5.1 WebRTC Direct

WebRTC Direct 用于供应商具有客户端可达 UDP listener 的场景，例如公网 IPv6、公网 IPv4 或
稳定 UDP 端口映射。

拨号前必须：

- 校验 multiaddr 的 PeerId 与供应商公钥一致；
- 校验 `/certhash` 格式；
- 限制拨号超时和并发；
- 禁止在身份认证完成前发送 MSFile Frame。

WebRTC Direct 的 DTLS 负责 DataChannel 机密性和完整性；绑定 fingerprint 的 libp2p Noise
握手负责远端 PeerId 身份认证。两者都不能替代内容 SHA-256 校验。

供应商没有可达 UDP 地址时，客户端直接把该地址报告为不可达，并尝试同一供应商配置的 WSS
地址或其他供应商。

### 5.2 WebSocket/WSS

WSS 用于供应商通过 HTTPS 基础设施、反向代理或标准 443/TCP 对浏览器提供服务的场景。

- 浏览器通常只能作为 WebSocket dialer，供应商负责监听；
- TLS 证书必须由浏览器/运行环境信任，域名必须匹配；
- 反向代理必须把二进制 WebSocket 字节透明转发给 libp2p listener；
- 反向代理不得解析、重写或缓存 MSFile Frame；
- WSS 建连成功后仍必须完成 libp2p Noise 与 PeerId pin；
- WSS connection 使用 Yamux 提供独立 libp2p stream。

WS 没有 TLS，只允许 loopback、本机集成测试或明确受控的可信网络。即使使用 WS，libp2p Noise
仍然必须开启。

### 5.3 地址选择

客户端按供应商分别维护地址健康状态，可以基于历史成功率、RTT 和本地网络选择地址：

```text
configured
  -> dialing
  -> authenticating
  -> msfile_ready
  -> disconnected

任意中间状态 -> failed
```

只有 `msfile_ready` connection 可以打开 `/msfile/1.0.0` stream。一个地址失败可以尝试同一
供应商的另一允许 transport；这只是地址切换，不改变供应商身份。

如果同一供应商同时存在多个可用 connection，客户端应选择一个作为 active connection，避免
同一身份下 request ID、Read 覆盖和预算状态被分散到多个 connection。

---

## 6. MSFile stream 生命周期

### 6.1 建立

客户端在 active connection 上：

1. 打开第一条 `/msfile/1.0.0` stream；
2. 以 StatRequest 作为首个 Frame，将它锁定为 Stat stream；
3. 第一次需要内容时打开第二条 `/msfile/1.0.0` stream；
4. 以 ReadRequest 作为首个 Frame，将它锁定为 Read stream；
5. 后续请求复用相应 stream。

供应商对同一 connection 上重复打开的同角色 stream 应拒绝或 Reset，避免产生多个序号作用域。
stream 重建时必须先确认旧 stream 已终止，并延续当前 connection 的 request ID 计数。

### 6.2 为什么使用两条 stream

| 方案 | 优点 | 问题 | V1 结论 |
|---|---|---|---|
| 每个请求一条 stream | 天然关联和独立取消 | 高频 Stat 和 Read 会反复支付 stream 协商与状态开销 | 不采用 |
| Stat/Read 混合一条 stream | stream 数最少 | Seed/块 attachment、背压和 Reset 会阻塞或影响 Stat | 不采用 |
| 一条 Stat + 一条 Read | 控制面与数据面隔离，stream 数固定 | Read 内仍需 request ID 和串行 writer | **采用** |

WebRTC transport 通常把 libp2p stream 映射为 RTCDataChannel；WSS 则通过 Yamux 维护 stream
状态。具体内存和时延由实现版本决定，但两条长期复用 stream 避免了每次请求的协议协商和
stream churn。正式实现仍需用目标浏览器、js-libp2p 和 go-libp2p 版本做基准测试。

### 6.3 全双工与写入纪律

- 请求读取循环、业务执行器和响应写队列应相互独立；
- 供应商可以并发执行多个 Stat 或 Read；
- 响应可以按完成顺序乱序返回；
- 每个方向必须只有一个 Frame writer；
- attachment 不得与其他响应交错；
- Read stream Reset 不影响 Stat stream，但两者共享 connection 的带宽与关闭事件；
- connection 关闭会同时终止两条 stream。

---

## 7. 多供应商调度

### 7.1 Stat：对所有供应商并发

查询某个 `seed_hash` 时，客户端必须对所有已启用供应商并发发送 Stat：

```text
for supplier in enabled_suppliers concurrently:
  connection = get_or_dial(supplier)
  send StatRequest on supplier.stat_stream
```

聚合键是：

```text
(supplier_id, seed_hash, stat_request_id)
```

规则：

- 每个响应的 `supplier_id` 来自承载它的 authenticated connection；
- 不在 StatRequest 中携带供应商 ID；
- 每个供应商独立维护状态与超时；
- 某个供应商连接失败不阻塞其他供应商结果；
- 网络失败不能转换为 `absent`；
- App 频繁刷新 Stat 时复用既有 Stat stream；
- 同一供应商、同一 SeedHash 只展示最大 `stat_request_id` 的响应。

### 7.2 Read：按供应商公钥定向

客户端根据 Stat 结果、价格、延迟和本地策略选定供应商，然后只在该供应商 authenticated
connection 的 Read stream 上发送 Read：

```text
read(supplier_id, content_hash, max_price_satoshis)
```

`supplier_id` 是客户端 service API 的路由参数，不进入 ReadRequest。不同供应商之间的相同
`content_hash` 和 request ID 不共享授权状态。

Read 既用于取得 Seed，也用于取得 Seed 中列出的文件块。客户端不需要先发送 Acquire。

### 7.3 播放与预读

顺序播放可以维持一个有限的后台 Read 窗口。用户 seek 时：

1. 停止继续扩展旧位置的预读窗口；
2. 优先发送目标位置所需块的 Read；
3. 必要时用同一 hash 的更大 `read_request_id` 更新价格上限；
4. 内容到达后再按新位置恢复后台窗口。

调度优先级由客户端发送策略表达，不增加 wire `priority` 字段。

---

## 8. 背压与资源限制

两种 transport 都提供可靠字节传输，但都必须显式执行背压：

- 不把 16 MiB Seed、256 KiB 块或完整文件一次性复制到 transport buffer；
- encoder 增量写入，decoder 增量读取并计算 SHA-256；
- WSS 使用 Yamux/stream 的背压，不直接绕过 libp2p 调用 WebSocket `send()`；
- WebRTC Direct 不直接绕过 libp2p 调用 RTCDataChannel `send()`；
- 限制每公钥、每 connection 和全局未完成 Read 数；
- 限制 response writer 队列总字节数；
- 限制 Stat 频率，但允许 App 高频轮询复用同一 stream；
- 资源不足时返回 `rate_limited`、Reset stream 或关闭 connection，不得静默丢包。

建议分别观测：

```text
connections_by_transport
open_stat_streams
open_read_streams
pending_stat_requests
pending_read_requests
response_queue_bytes
content_bytes_sent
stream_resets
```

---

## 9. 安全边界

### 9.1 三层校验

```text
transport encryption  -> 防窃听和链路篡改
libp2p identity       -> 认证客户端/供应商公钥
content SHA-256       -> 验证 Seed 与文件块真值
```

任何一层都不能替代另一层。特别是 WSS TLS 证书不能替代 supplier public key pin，WebRTC DTLS
也不能替代内容哈希。

### 9.2 白名单与预算

白名单公钥仍可能来自被盗设备或有 bug 的客户端。供应商必须保留：

- connection、stream 和请求频率限制；
- Read 单次价格上限检查；
- 每公钥累计支出与速率策略；
- Frame、attachment、内存和带宽上限；
- 超时、异常序号和违规行为处理。

### 9.3 日志

允许记录 PeerId、供应商 ID 的截断展示、transport、request ID、content hash 和尺寸用于审计。
禁止记录：

- 私钥；
- 完整内容 attachment；
- 完整客户端白名单；
- WebSocket/TLS credential；
- 交易原文或钱包秘密；
- 非必要的长期内网地址历史。

---

## 10. 失败语义与恢复

网络层至少区分：

```text
supplier_unreachable
transport_not_supported
webrtc_direct_dial_failed
wss_dial_failed
tls_validation_failed
peer_id_mismatch
public_key_not_allowed
connection_closed
stream_open_failed
stream_reset
timeout
```

这些错误发生在合法业务响应之外，不能转换成：

```text
absent
discovering
content_not_found
```

恢复规则：

- Stat stream 失败：重建 stream，继续 connection 级 Stat 序号；
- Read stream 失败：所有未终结 Read 进入传输不确定状态，重建后由客户端重新决策；
- connection 失败：关闭两条 stream，按供应商地址策略重拨；
- 重拨到同一公钥的另一 transport 仍是同一供应商，但形成新的 request ID 作用域；
- 供应商不得因客户端断线开始新的付款；已经不可逆的付款按 Wire Protocol 边界处理；
- 对其他供应商的 Stat 和 Read 不受单个供应商故障影响。

---

## 11. 兼容性与版本

MSFile protocol ID 固定为：

```text
/msfile/1.0.0
```

libp2p、Noise、Yamux、WebRTC Direct、WebSocket 和浏览器都有独立版本。依赖升级后，只要以下
可观察结果不变，就不提升 MSFile wire 版本：

- 同一业务公钥仍认证为同一供应商身份；
- 两种允许 transport 都提供可靠、双向 libp2p stream；
- Stat/Read 双 stream 角色和生命周期不变；
- `/msfile/1.0.0` Frame 字节与命令语义不变。

新增 transport 不等于自动获得 MSFile 兼容性；必须先完成安全、互操作和性能验收。改变 Frame、
Kind、数组字段或请求覆盖规则必须提升 MSFile 版本。

---

## 12. 验收范围

### 12.1 身份

- JS 与 Go 从同一 secp256k1 私钥派生一致公钥和 PeerId；
- 两端从 authenticated connection 取得正确远端公钥；
- 错误 PeerId、公钥 pin 或白名单连接失败；
- 伪造 Frame 字段不能改变供应商或客户端身份；
- Vault 锁定和 active key 切换关闭旧身份 connection。

### 12.2 WebRTC Direct

- Chrome、Firefox、Safari 拨入兼容供应商；
- 公网 IPv6、IPv4 和稳定 UDP 映射场景；
- 正确与错误 certhash；
- 认证后打开 Stat/Read stream；
- 大 Seed、顺序块和随机块传输哈希一致；
- 连接中断后可以重新拨号恢复。

### 12.3 WSS

- Chrome、Firefox、Safari 通过受信 TLS 域名拨入供应商；
- WSS 反向代理透明承载 libp2p；
- Noise 认证和供应商公钥 pin 成功；
- TLS 域名错误、证书错误和 PeerId 错误均失败关闭；
- Yamux 下双 stream、乱序响应、背压和大 attachment 正常；
- 本机 WS 仅在开发策略启用时可用。

### 12.4 Stream 与调度

- 每个 active connection 只有一条 Stat 和一条 Read stream；
- Stat 向所有已启用供应商并发发送；
- Read 只发送给选定供应商公钥；
- 高频 Stat 不创建等量 stream；
- Read attachment 不阻塞 StatResponse；
- Read 内并发执行、乱序响应和覆盖取消符合 Wire Protocol；
- 4/8 个并发内容请求时 Frame 不串线、内存有明确上限。

---

## 13. 明确不属于 V1 的网络能力

V1 不定义：

- relay-signaled WebRTC、Circuit Relay 或 TURN 数据路径；
- HTTP/HTTPS 文件 API 或裸 WebSocket 协议；
- WebTransport、QUIC、TCP 等其他 MSFile transport；
- API Key、Cookie、Bearer Token 或匿名访问；
- MSFile 应用层重复握手和逐报文签名；
- DHT、mDNS、Rendezvous、二维码或配对码的具体发现协议；
- 自动修改家庭路由器或保证所有 NAT 环境可达；
- 向 Connect App 暴露 raw libp2p host、RTCDataChannel 或 WebSocket。

---

## 参考规范与实现

- [libp2p WebRTC Transport](https://github.com/libp2p/js-libp2p/tree/main/packages/transport-webrtc)
- [libp2p WebRTC Direct Protocol](https://github.com/libp2p/specs/blob/master/webrtc/webrtc-direct.md)
- [libp2p WebSockets Transport](https://github.com/libp2p/js-libp2p/tree/main/packages/transport-websockets)
- [libp2p Noise](https://github.com/libp2p/specs/tree/master/noise)
- [libp2p Yamux](https://github.com/libp2p/specs/tree/master/yamux)
- [libp2p Connections and Streams](https://github.com/libp2p/specs/blob/master/connections/README.md)
