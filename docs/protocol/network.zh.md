# MSFile Proxy Network Protocol v1

> 状态：V1 网络设计真值。
>
> 本文只定义 MSFile 节点身份、Proxy 设置、libp2p over WebRTC 建连、两种直连模式、
> Circuit Relay 信令边界、直连验证、连接状态和网络验收。具体命令、CBOR Header、raw
> attachment 和错误报文见
> [MSFile Proxy Wire Messages v1](./wire-messages.zh.md)。

---

## 1. 设计结论

MSFile V1 网络层统一规定：

1. Keymaster Browser 运行 js-libp2p，NAS/BitFSProxy 运行兼容的 libp2p 实现；
2. 业务数据只通过 WebRTC DataChannel 上的 libp2p stream 传输；
3. 同时支持 `webRTCDirect` 和 `webRTC` 两种 transport；
4. `webRTCDirect` 用于浏览器直接拨入具有可达 UDP 地址的 Proxy；
5. `webRTC` 用于两个 NAT 后节点借助 Circuit Relay 交换 SDP/ICE 后建立 WebRTC 直连；
6. Circuit Relay 只允许承载 reservation、SDP 和 ICE 信令，严禁承载 MSFile stream；
7. TURN、`turn:`、`turns:` 和任何文件数据 Relay 回退均不属于 V1；
8. ICE 打洞失败时 Proxy 不可达，不能降级为经 Relay 读取；
9. libp2p identity 使用业务身份同一把 secp256k1 私钥；
10. Proxy 从已认证 connection 取得远端压缩公钥并执行白名单授权；
11. MSFile 只在通过 `direct_ready` 验证的具体 connection 上打开 stream；
12. Proxy 可以同时发布两类地址，客户端优先尝试 WebRTC Direct，再尝试 Relay-signaled
    WebRTC；
13. libp2p/WebRTC 内部版本可以升级，但不得改变本文可观察的直连、安全和报文边界。

---

## 2. 分层模型

```text
Keymaster / Connect App
  └── msfile.service
       └── /msfile/1.0.0 stream
            └── libp2p authenticated connection
                 └── WebRTC DataChannel
                      └── selected ICE candidate pair
```

Connect App 不直接取得 libp2p host、私钥、RTCPeerConnection 或 Proxy 白名单。App 只调用
Keymaster 暴露的 `msfile.service`；Keymaster 负责节点身份、连接验证、请求调度和内容校验。

传输关系不能写成“WebRTC 上再启动一个可能回退 Relay 的文件服务”。MSFile stream 的唯一
合法底层是已经形成的 WebRTC connection。

---

## 3. 节点身份

### 3.1 密钥口径

Keymaster 和 Proxy 都必须使用：

```text
key_type          = secp256k1
private_key_bytes = 32 bytes
public_key_bytes  = 33-byte SEC1 compressed public key
```

压缩公钥首字节必须是 `0x02` 或 `0x03`。配置和日志展示使用 66 个小写 hex 字符；连接和
密码学内部使用原始字节。

节点把该业务私钥作为 libp2p identity private key。PeerId 从对应公钥按 libp2p 标准派生：

```text
business_private_key
  ├── business_public_key
  └── libp2p PeerId
```

不得再生成一把与业务身份无关的临时 libp2p 私钥，也不得在报文中自报另一把业务公钥。

### 3.2 Keymaster Vault 边界

“使用同一把私钥”不表示插件或 Connect App可以读取 raw private key。

Keymaster 实现必须满足：

- libp2p identity 由 Keymaster 受信任核心或 Vault 控制的运行时持有；
- 普通插件和 Connect App 只能取得 `msfile.service` capability；
- Vault 锁定时立即停止 libp2p host 并关闭全部 MSFile connection；
- active key 切换时关闭旧 host，以新业务密钥重建 host；
- key 切换后 PeerId 同步变化；
- 不得把 raw private key 写入 localStorage、日志、错误、配置或跨 App 消息。

如果 js-libp2p 的当前 PrivateKey 接口要求长期持有 raw key，实现必须把这项能力限制在受信任
运行时中，不能为方便接入而扩散 Vault 解密结果。

### 3.3 Proxy 白名单

Proxy 白名单保存允许访问服务的 33 字节压缩公钥，并可以为每个公钥配置：

- 是否允许 `stat(discover=false)`；
- 是否允许 `stat(discover=true)`；
- 是否允许本地 `read`；
- 是否允许 `acquire` 和 acquisition read；
- 并发 stream、带宽和预算上限。

授权真值必须来自 libp2p 握手认证后的 remote public key。Proxy 禁止信任：

- 报文字段中的公钥；
- 调用方声明的 PeerId；
- 推荐文件名、Seed 或 quote 中的身份字段；
- WebRTC DTLS certhash 作为业务身份。

Proxy 可以把白名单公钥预先派生成 PeerId，在 secure connection gater 阶段尽早拒绝；最终
MSFile stream handler 仍必须使用 connection 上的远端身份执行授权。

### 3.4 双向认证

客户端也必须确认连接的是目标 Proxy：

1. Proxy 设置包含期望压缩公钥；
2. 从该公钥派生期望 PeerId；
3. 每个配置 multiaddr 的 `/p2p/<peer-id>` 必须与其一致；
4. libp2p secure handshake 认证出的 remote PeerId 必须再次一致；
5. 任一不一致都关闭 connection，不能提示用户忽略。

libp2p Noise 负责证明对端持有 PeerId 对应私钥并保护连接；公钥白名单负责业务授权；
MasterSeed 负责文件内容完整性。这三个边界不得混为一层。

---

## 4. Proxy 设置

Keymaster 的一条配置型 Proxy 至少包含：

```text
name
proxy_public_key
addresses[]
```

例如：

```text
name = home-nas
proxy_public_key = 02...

addresses = [
  /dns4/nas.example.com/udp/4001/webrtc-direct/certhash/<hash>/p2p/<nas-peer-id>,
  /dns4/relay.example.com/tcp/443/wss/p2p/<relay-peer-id>/p2p-circuit/webrtc/p2p/<nas-peer-id>
]
```

规范性规则：

- `proxy_public_key` 必须是合法的压缩 secp256k1 公钥；
- 每个 address 必须是合法 libp2p multiaddr；
- 最终目标 `/p2p/` 必须等于该公钥派生的 PeerId；
- address 只能属于本文定义的 `webrtc-direct` 或 relay-signaled `webrtc`；
- 配置不包含 API Key、HTTP URL、Bearer Token 或用户名密码；
- Relay 地址中的 Relay PeerId 与 Proxy PeerId 是两个不同身份；
- 用户可以为同一 Proxy 配置多个网络地址；
- Keymaster 内部 Proxy ID 可以由配置记录生成，但不是 wire 字段；
- 内置静态文件源可以直接实现 `msfile.service` Adapter，不要求绕行 WebRTC。

地址发现、二维码、配对码和 DDNS 更新机制不进入 V1 wire；它们最终必须产生上述公钥和
multiaddr 真值。

---

## 5. 模式 A：WebRTC Direct

### 5.1 用途

WebRTC Direct 用于 Proxy 具有浏览器可达 UDP listener 的场景：

- 公网 IPv6；
- 公网 IPv4；
- 路由器静态 UDP 端口映射；
- UPnP、NAT-PMP 或 PCP 建立的稳定 UDP 映射。

```text
Browser/js-libp2p
        ═════ WebRTC Direct ═════>
Proxy/go-libp2p UDP listener
```

浏览器只能拨号，不能作为 WebRTC Direct listener。Proxy 发布的 multiaddr 必须包含：

```text
network address
udp port
/webrtc-direct
/certhash/<certificate-hash>
/p2p/<proxy-peer-id>
```

### 5.2 Certhash

`certhash` 是 WebRTC DTLS 证书指纹，不是 PeerId，也不是业务公钥哈希。

Proxy 应持久化 WebRTC certificate/key，使重启后 certhash 稳定。若证书轮换导致 certhash
变化，旧 multiaddr 必须失效并通过配置/发现机制发布新地址。

客户端必须同时验证 certhash 和 PeerId，不能用其中一个代替另一个。

### 5.3 不可达边界

WebRTC Direct 不通过第三方交换 SDP。普通 NAT 后且没有可达端口映射的 Proxy 不能仅靠
STUN 变成 Direct listener。

以下情况 Direct 可以失败：

- CGNAT 且无公网 IPv6；
- UDP 入站映射不存在或过期；
- 防火墙阻断；
- DDNS 或 certhash 已过期。

失败后客户端可以尝试模式 B，但不得经 Circuit Relay 直接打开 MSFile stream。

---

## 6. 模式 B：Relay-signaled WebRTC

### 6.1 用途

该模式用于 Browser 和 Proxy 都位于 NAT 后，但 NAT/防火墙仍允许 WebRTC ICE 打洞的
场景。

```text
阶段 1：信令

Browser ── Circuit Relay ── Proxy
          SDP + ICE only

阶段 2：业务数据

Browser ═══ selected ICE pair / WebRTC DataChannel ═══ Proxy
          Circuit Relay 不在数据路径中
```

Proxy 先在 Circuit Relay v2 建立 reservation，并发布形如：

```text
<relay-address>/p2p/<relay-peer-id>/p2p-circuit/webrtc/p2p/<proxy-peer-id>
```

客户端通过 relay circuit 打开 libp2p WebRTC signaling protocol，交换 SDP 和 ICE
candidate。`RTCPeerConnection` 进入 connected 后：

- signaling stream 必须关闭；
- 新的 WebRTC connection 成为 MSFile 候选 connection；
- Relay reservation/control connection 可以继续存在以服务未来拨号；
- MSFile 不得在 signaling circuit connection 上打开。

### 6.2 STUN 与 TURN

V1 允许 STUN，因为 STUN 只帮助发现地址和执行连通性检查，不转发文件数据。

配置加载时必须：

- 允许 `stun:` URL；
- 拒绝 `turn:` URL；
- 拒绝 `turns:` URL；
- 拒绝 TURN username、credential 和 relay-only ICE policy；
- 不提供“打洞失败后使用 TURN”的开关。

ICE 打洞可能在普通家庭 NAT 下成功，也可能在对称 NAT、部分 CGNAT、多层 NAT、企业网络
或 UDP 受限网络下失败。V1 接受“不能直连就不可达”，不追求所有网络可用。

### 6.3 Circuit Relay 的允许流量

Relay connection 只允许：

- libp2p connection 建立与 identify 所需最小控制流量；
- Circuit Relay v2 reservation/control；
- libp2p WebRTC signaling protocol；
- SDP offer/answer；
- ICE candidates 和连通状态。

明确禁止：

- `/msfile/1.0.0` stream；
- Seed attachment；
- 文件块 attachment；
- Stat、Acquire、Read Header；
- 把 Relay 当作 ICE 失败后的文件传输回退。

“Relay connection 仍保持在线”不表示 Relay 仍参与已经形成的 WebRTC DataChannel。保留
reservation 是为了后续连接；是否参与某一 MSFile 传输必须由第 8 节的验证规则判断。

---

## 7. 地址选择与建连策略

同一 Proxy 可以同时发布两类地址。建议顺序：

1. 尝试已知可用的 `webrtc-direct` 地址；
2. Direct 超时或不可达时尝试 relay-signaled `webrtc` 地址；
3. 等待 ICE selected candidate pair；
4. 执行完整 `direct_ready` 验证；
5. 验证通过后才允许 MSFile 请求；
6. 两种方式均失败则报告 Proxy 网络不可达。

客户端可以根据近期成功记录调整地址尝试顺序，但不能降低验证条件。

禁止只使用：

```text
dialProtocol(peer_id, "/msfile/1.0.0")
```

让 connection manager 任意复用现存连接，因为同一 PeerId 可能同时存在：

- signaling Circuit Relay connection；
- relay-signaled WebRTC connection；
- WebRTC Direct connection。

正确做法是：

1. 对明确的 WebRTC multiaddr 建连；
2. 取得建连返回的具体 libp2p Connection；
3. 对该对象执行第 8 节检查；
4. 在这个具体 Connection 上 `newStream("/msfile/1.0.0")`。

连接断开后可以重新执行上述流程；绝不能把待重试 Read 自动切到 indirect connection。

---

## 8. `direct_ready` 强制检查

每次 connection 建立后，MSFile 网络层必须完成以下全部检查。

### 8.1 libp2p Connection 检查

```text
connection.status == open
connection.direct == true
connection.limits == nil
connection.remote_peer == expected_proxy_peer_id
transport matches webrtc or webrtc-direct
```

说明：

- `direct == false` 表示间接连接，不得用于 MSFile；
- `limits != nil` 通常表示 Relay 施加字节或时间限制，不得用于 MSFile；
- relay-signaled WebRTC 的 remote multiaddr 可能仍包含建立路径信息，不能仅凭字符串中出现
  `p2p-circuit` 就判断文件仍经 Relay；必须结合 connection 类型和真实 ICE pair；
- transport 必须明确是 WebRTC，TCP、WebSocket、WebTransport 和裸 Circuit Relay 均不
  自动成为 MSFile V1 transport。

### 8.2 身份检查

```text
remote_public_key.type == secp256k1
remote_public_key == configured/whitelisted public key
PeerId(remote_public_key) == connection.remote_peer
```

客户端检查 Proxy 身份；Proxy 对入站 connection 执行同样逻辑并检查客户端白名单。

### 8.3 ICE selected candidate pair 检查

实现必须从底层 `RTCPeerConnection` 或等价 Go/Pion ICE transport 取得当前 selected candidate
pair。允许的 candidate type：

```text
host
srflx
prflx
```

以下任一条件均必须拒绝或立即关闭 MSFile connection：

```text
local_candidate_type  == relay
remote_candidate_type == relay
selected pair 不存在
selected pair state 不是 succeeded/selected
```

Circuit Relay 和 ICE `relay` candidate 是两个不同概念：前者可以交换信令；后者通常表示
TURN 数据中转，V1 禁止。

如果 ICE restart 或网络切换改变 selected candidate pair，必须重新执行本节检查。在检查
完成前暂停新 MSFile stream；新 pair 不合格时关闭现有 MSFile connection。

### 8.4 js-libp2p 观测接口

当前 js-libp2p 公共 `Connection` 可以提供 `direct`、`limits` 和 `remoteAddr`，但底层
`RTCPeerConnection` 可能被 transport 封装为私有字段。实现必须通过以下一种受控方式取得
ICE 观测值：

- 上游公开的 transport event/hook；
- 项目维护的最小 transport adapter；
- 对固定依赖版本维护的最小补丁，输出只读 selected-pair snapshot。

观测接口只能暴露候选类型、协议、必要的脱敏地址和统计，不得暴露私钥或允许插件操作
RTCPeerConnection。不能因为库没有公开 `getStats()` 就跳过检查。

### 8.5 MSFile stream gate

出站和入站都必须执行：

```text
if connection is not direct_ready:
    reject/reset /msfile/1.0.0 stream
```

MSFile 协议注册和开流禁止设置 `runOnLimitedConnection=true`。只有 libp2p 自己的 WebRTC
signaling handler 可以在 limited connection 上显式运行。

---

## 9. 可确认的 Relay 退出机制

“Relay 不再参与数据传输”必须由以下四类证据共同确认。

### 9.1 建连状态证据

- signaling stream 已关闭；
- `RTCPeerConnection.connectionState == connected`；
- libp2p 已创建独立 WebRTC Connection；
- MSFile 使用该具体 Connection 开流。

### 9.2 路径证据

- `connection.direct == true`；
- `connection.limits == nil`；
- selected candidate pair 不含 `relay`；
- WebRTC candidate-pair `bytesSent/bytesReceived` 随 MSFile 传输增长。

### 9.3 Relay 流量证据

受控 Relay 应提供按 reservation/connection 的字节和存续统计。建立 WebRTC 后：

- Relay 可以有 reservation keepalive 和小量控制流量；
- Relay 字节不得随 Seed 或文件块体积同比增长；
- 两端的 protocol metrics 不得显示在 Relay connection 上打开 MSFile stream；
- Relay 本身看不到 Noise 内部协议明文，只能通过连接字节增量与端点侧 protocol metrics
  交叉验证。

### 9.4 断 Relay 证据

集成测试必须在 WebRTC `direct_ready` 后停止或防火墙阻断 Relay，然后继续传输大量随机块。
已经建立的 MSFile 读取必须继续成功。Relay 消失后不能建立新的 relay-signaled connection
是正常结果，不影响当前直连证明。

只看“文件还能下载”或只看 multiaddr 都不足以作为完整证据；运行时 gate 和断 Relay 测试
必须同时存在。

---

## 10. 连接状态机

```text
idle
  -> dialing
  -> signaling             # 仅模式 B
  -> ice_connecting
  -> direct_verifying
  -> direct_ready
  -> disconnected

任意中间状态 -> failed
```

只有 `direct_ready` 允许打开 `/msfile/1.0.0`。

建议暴露给 Keymaster 诊断层的只读快照：

```text
proxy_peer_id
transport = webrtc | webrtc-direct
state
direct
limited
local_candidate_type
remote_candidate_type
candidate_protocol
relay_peer_id              # 仅模式 B，说明其角色是 signaling_only
rtt_ms
connected_at
last_error_code
```

不得向普通 Connect App 暴露完整内网地址、STUN 映射地址或 Relay 管理细节。App 只需要知道
Proxy 是否可用以及 MSFile 命令结果。

---

## 11. 多 Proxy 调度

Keymaster 可以配置多个 Proxy，并对每个 Proxy 独立维护 connection 和状态。

当系统需要某个 SeedHash 时：

1. 对所有配置 Proxy 并发或按本地策略建立/复用 `direct_ready` connection；
2. 在每个可用 connection 的独立 stream 上发送 StatRequest；
3. 连接失败与业务 `absent` 严格区分；
4. 聚合 `available/quoted/discovering/absent`；
5. 根据本地、报价、延迟、策略和用户选择决定使用哪个 Proxy；
6. 后续 Acquire 和 Read 必须发送到产生该 quote/acquisition 的同一 Proxy 身份。

一个 Proxy 不可达不能伪装成 `absent`，也不应阻塞其他 Proxy 的 Stat 结果。

---

## 12. 背压与资源控制

WebRTC DataChannel 是可靠二进制传输，但仍必须执行背压和并发限制：

- 使用 libp2p stream 写入 raw attachment；
- 不直接把 16 MiB Seed、256 KiB 块或整个文件作为单个 `RTCDataChannel.send()` 消息；
- MSFile encoder 按 WebRTC transport 的 `maxMessageSize` 主动拆成小块 write，V1 建议每片
  不超过 16 KiB；
- 为每个客户端公钥限制并发 Read stream；
- 为每个 connection 限制未完成 attachment 总字节；
- 为 Proxy 设置总带宽、内存和打开 stream 上限；
- 浏览器 tab 暂停、网络切换和 ICE restart 后允许按块恢复；
- 资源耗尽只能限流、拒绝或断开，不能回退 Relay。

Relay-signaled 模式下 signaling connection 和 WebRTC data connection 必须分别计量，避免把
控制流量误计为文件带宽。

---

## 13. 安全边界

### 13.1 网络机密性

WebRTC DTLS 保护 DataChannel；libp2p secure handshake 认证 PeerId。实现不得因为 WebRTC
已经加密而关闭 libp2p 身份认证。

### 13.2 内容完整性

网络加密不替代 MasterSeed 校验。客户端仍必须：

- 验证 SeedHash；
- 验证 Seed 与文件尺寸；
- 验证每个块 SHA-256；
- 校验成功后才交给上层。

### 13.3 白名单不替代限流

白名单公钥也可能对应被盗设备或有 bug 的客户端。Proxy 必须保留：

- connection 和 stream 数量上限；
- Stat/Read 频率限制；
- Acquire 预算限制；
- Frame 和 attachment 尺寸限制；
- 超时、取消和异常行为封禁策略。

### 13.4 日志

允许记录 PeerId 和截断/脱敏公钥用于审计。禁止记录：

- 私钥；
- 完整 Seed attachment；
- 文件块内容；
- acquisition identifier；
- 用户内网地址的非必要长期历史；
- SDP 全文和 ICE credential。

---

## 14. 失败语义

网络层至少区分：

```text
proxy_unreachable
direct_dial_failed
signaling_failed
ice_failed
direct_verification_failed
unexpected_relay_path
peer_id_mismatch
public_key_not_allowed
connection_closed
stream_reset
timeout
```

这些错误不是 Wire ErrorResponse，因为失败时可能尚未形成合法 MSFile stream。它们也不能
转换成：

```text
absent
discovering
unavailable
```

客户端可以对另一个地址或另一个 Proxy 重试；对同一 Proxy 的 Acquire 不确定结果必须遵守
Wire Protocol 的 `idempotency_key` 规则。

---

## 15. 兼容性与版本

MSFile protocol ID 固定为：

```text
/msfile/1.0.0
```

libp2p、js-libp2p、go-libp2p、Pion、WebRTC Direct 内部规范和浏览器实现具有独立版本。实现
必须维护经过测试的兼容矩阵，尤其覆盖 WebRTC Direct V1/V2 演进和浏览器 ICE 行为变化。

升级依赖后，只要以下可观察结果不变，就不提升 MSFile wire 版本：

- 相同业务私钥派生并认证相同 PeerId；
- 两种 WebRTC 模式语义不变；
- Relay 仍只承担信令；
- `direct_ready` 检查仍成立；
- `/msfile/1.0.0` Frame 字节和命令语义不变。

任何让 MSFile 可以运行在 Relay、TURN 或其他 transport 上的变化都不是兼容实现优化，必须
重新设计并提升协议版本。

---

## 16. 验收范围

### 16.1 身份

- Go 与 Browser 使用同一 32 字节 secp256k1 私钥得到一致业务公钥和 PeerId；
- Proxy 从 connection 取得的远端公钥与客户端业务公钥一致；
- 非白名单公钥无法打开 MSFile stream；
- 伪造报文字段无法替代连接身份；
- Vault 锁定和 active key 切换立即关闭旧身份连接。

### 16.2 WebRTC Direct

- Chrome、Firefox、Safari 拨入 Go Proxy；
- 公网 IPv6、IPv4 和路由端口映射；
- certhash 持久化与轮换；
- 错误 PeerId、错误 certhash 和过期地址失败关闭；
- 不启动 Circuit Relay 时仍能完成大文件随机块读取。

### 16.3 Relay-signaled WebRTC

- 常见家庭 NAT 下通过 STUN/ICE 形成直连；
- signaling 完成后关闭 signaling stream；
- `connection.direct == true` 且 `limits == nil`；
- selected candidate pair 是 host/srflx/prflx；
- ICE 失败时不产生 MSFile Relay fallback；
- TURN URL 和 relay candidate 被拒绝；
- 网络切换或 ICE restart 后重新验证 candidate pair。

### 16.4 Relay 退出证明

- `direct_ready` 后停止 Relay，持续读取至少 1 GiB 随机块；
- Relay 字节不随文件体积增长；
- WebRTC candidate-pair bytes 与文件传输量同步增长；
- 人为尝试在 limited/indirect connection 打开 `/msfile/1.0.0` 被拒绝；
- 同一 PeerId 同时存在 Relay 与 WebRTC connection 时，MSFile 只选择具体 WebRTC
  connection。

### 16.5 性能与恢复

- 256 KiB 块顺序读取和随机 seek；
- 多 stream 并发与背压；
- 16 MiB Seed 不发生 Base64 膨胀；
- tab 暂停、connection 断开和按块恢复；
- 大文件传输期间内存有明确上限；
- Relay 不承担视频或文件带宽。

---

## 17. 明确不属于 V1 的网络能力

V1 不定义：

- TURN 数据中转；
- Circuit Relay 文件回退；
- HTTP/HTTPS、WebSocket/WSS 或 WebTransport 文件 API；
- API Key、Bearer Token 或 Cookie 认证；
- 匿名访问；
- 浏览器作为 WebRTC Direct listener；
- DHT、mDNS、Rendezvous、二维码或配对码的具体发现协议；
- 自动修改家庭路由器的标准实现；
- 对所有 CGNAT/企业网络保证可达；
- 向 Connect App 暴露 raw libp2p host 或 RTCPeerConnection。

---

## 参考规范与实现

- [libp2p WebRTC Transport](https://github.com/libp2p/js-libp2p/tree/main/packages/transport-webrtc)
- [libp2p WebRTC Protocol](https://github.com/libp2p/specs/blob/master/webrtc/webrtc.md)
- [libp2p WebRTC Direct Protocol](https://github.com/libp2p/specs/blob/master/webrtc/webrtc-direct.md)
- [libp2p Circuit Relay v2](https://github.com/libp2p/specs/tree/master/relay/circuit-v2)
- [libp2p Connection Interface](https://github.com/libp2p/js-libp2p/blob/main/packages/interface/src/connection.ts)
- [W3C WebRTC](https://www.w3.org/TR/webrtc/)
- [W3C WebRTC Stats](https://www.w3.org/TR/webrtc-stats/)
