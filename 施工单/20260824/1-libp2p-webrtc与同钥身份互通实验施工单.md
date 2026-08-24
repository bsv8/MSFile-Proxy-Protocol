# 20260824-1 libp2p WebRTC 与同钥身份互通实验施工单

## 1. 本次目标

本次迭代在 `MSFile-Proxy-Protocol` 仓库内建立两个彼此独立、可以分别构建和运行的实验
subproject：

```text
labs/webrtc-web/    TypeScript + js-libp2p 的 HTTPS 静态网站
labs/webrtc-go/     Go + go-libp2p 的 NAS/Relay 实验服务
```

本次只验证两个基础假设：

1. libp2p 在浏览器 WebRTC 环境下的 `webRTCDirect` 与 relay-signaled `webRTC` 互联边界；
2. 一个节点能否把自己的业务 secp256k1 私钥直接作为 libp2p identity 私钥，并让对端从
   已认证 connection 中恢复相同业务公钥，用公钥白名单完成授权。

本次必须产出可复现的实验结果，不预设所有组合一定成功。成功、失败和上游暂不支持都属于
有效结果，但每个结果必须有版本、日志、连接路径和字节统计证据。

本次不实现正式 MSFile `stat/acquire/read` wire，不接 Keymaster Vault，不做购买、报价和
文件缓存。实验通过后再决定正式实现施工单。

---

## 2. 先明确“同一把私钥”的准确含义

每个节点复用自己的业务私钥作为自己的 libp2p identity：

```text
Browser 业务私钥 KB
  -> Browser 业务公钥 Pub(KB)
  -> Browser libp2p private key KB
  -> Browser PeerId

NAS 业务私钥 KN
  -> NAS 业务公钥 Pub(KN)
  -> NAS libp2p private key KN
  -> NAS PeerId
```

Browser 与 NAS 运行时必须使用不同私钥。不能让两个在线节点共用同一把私钥，否则二者会
得到相同 PeerId，libp2p 会把拨号识别成连接自己，身份和路由都不成立。

本次需要使用同一份固定测试私钥做跨语言 identity vector，证明 Go 与 TypeScript 对同一
输入派生出完全相同的：

```text
33-byte compressed secp256k1 public key
libp2p PeerId
```

这只是离线向量测试，不表示两个运行时 peer 共用该测试私钥。

---

## 3. 当前上游能力边界与 Gate 0

### 3.1 已知能力

当前 js-libp2p `@libp2p/webrtc` 暴露两种 transport：

- `webRTCDirect()`：浏览器直接拨具有可达 UDP listener 的 native peer；
- `webRTC()`：两个 private peer 通过 Circuit Relay 交换 SDP/ICE，再建立直接 WebRTC
  connection。

当前 go-libp2p 的 `p2p/transport/webrtc` 明确包含 WebRTC Direct listener/dialer。官方
`universal-connectivity` 能力矩阵当前把 Go peer 标记为：

```text
WebRTC Direct = supported
WebRTC        = not supported
```

因此不能在施工单里把“Browser `webRTC()` 一定可以连 Go NAS”写成既定能力。

参考：

- [js-libp2p WebRTC transport](https://github.com/libp2p/js-libp2p/tree/main/packages/transport-webrtc)
- [go-libp2p WebRTC transport](https://github.com/libp2p/go-libp2p/tree/master/p2p/transport/webrtc)
- [libp2p universal-connectivity matrix](https://github.com/libp2p/universal-connectivity)

### 3.2 Gate 0：锁版本并重新确认

开始编码前必须记录当日正式 release，不能直接依赖 `main`：

```text
Node.js version
pnpm version
libp2p version
@libp2p/webrtc version
@libp2p/crypto version
@libp2p/circuit-relay-v2 version
Go version
go-libp2p version
Pion/WebRTC version（由 go.mod 最终解析）
Chrome / Firefox / Safari version
```

然后用 release 源码和最小编译探针确认：

1. js-libp2p 是否仍支持 `webRTC()` 和 `webRTCDirect()`；
2. Go WebRTC transport 是否仍只实现 WebRTC Direct；
3. Go host 是否能监听 relay-signaled `/webrtc`；
4. WebRTC Direct V2 的 Browser -> Go 组合是否已经进入正式 release；
5. js-libp2p 是否公开底层 selected ICE candidate pair 观测接口。

Gate 0 结果写入最终实验报告。若 Go 仍不支持 relay-signaled WebRTC：

- 不自行实现一套 Go private-to-private WebRTC transport；
- 不修改上游源码来伪造“已支持”；
- 不把 Circuit Relay connection 当作 MSFile 数据连接；
- 继续完成 Browser <-> Browser 的 `webRTC()` 控制组；
- Browser <-> Go relay-signaled 记录为 `UNSUPPORTED_UPSTREAM`；
- Browser <-> Go WebRTC Direct 仍然必须完成。

只有用户另开施工单，才评估补齐 Go transport 的成本。

---

## 4. 本次硬裁决

### 4.1 只有两个 subproject

```text
labs/webrtc-web/
labs/webrtc-go/
```

不新增第三个 Relay 项目。Go subproject 的同一个 binary 提供两个运行角色：

```text
msfile-webrtc-lab nas
msfile-webrtc-lab relay
```

`relay` 是实验基础设施角色；`nas` 是正式被 Browser 拨号的模拟 NAS 角色。两者在实验中以
不同进程运行，使用不同私钥和 PeerId。

### 4.2 不实现完整 MSFile Wire

本轮只注册实验协议：

```text
/msfile-lab/identity/1.0.0
/msfile-lab/echo/1.0.0
/msfile-lab/bytes/1.0.0
```

它们只用于验证 connection identity、双向字节和大块传输。禁止在这里提前复制正式
`/msfile/1.0.0` 的 CBOR、Stat、Acquire、Read 状态机。

### 4.3 Relay 只做信令

relay-signaled `webRTC()` 实验中：

- Circuit Relay 可以承载 reservation、SDP 和 ICE；
- WebRTC connected 后，实验协议只能开在新的 direct WebRTC connection；
- 禁止 `runOnLimitedConnection=true`；
- 禁止在 Circuit Relay connection 上运行三个 lab protocol；
- 禁止 TURN；
- ICE 失败就失败，不做数据面回退。

### 4.4 不使用真实业务资产私钥

实验只使用没有资金、没有生产权限的测试私钥：

- 自动化测试可以提交显式标记为 test-only 的固定向量；
- 页面运行时默认生成临时身份；
- 可以手工导入 32 字节 test private key hex；
- 不允许导入或复制 Keymaster 生产 Vault 私钥；
- private key 不进入 URL、日志、截图、localStorage 或实验报告。

---

## 5. 目录与交付外形

施工完成后的最小目录：

```text
MSFile-Proxy-Protocol/
  labs/
    webrtc-web/
      README.md
      package.json
      pnpm-lock.yaml
      tsconfig.json
      vite.config.ts
      index.html
      src/
        main.ts
        identity.ts
        node.ts
        direct.ts
        private.ts
        protocols.ts
        stats.ts
        ui.ts
      test/
        identity-vector.test.ts
        framing.test.ts
      testdata/
        identity-vector.json

    webrtc-go/
      README.md
      go.mod
      go.sum
      cmd/
        msfile-webrtc-lab/
          main.go
      internal/
        identity/
        nas/
        relay/
        labproto/
        metrics/
      testdata/
        identity-vector.json
      identity_vector_test.go
      labproto_test.go

  docs/
    labs/
      webrtc-interop-report.zh.md
```

文件可以根据实现语言的合理边界做小幅调整，但不能把两个 subproject 合成一个混合构建，
也不能再拆出第三套重复 identity/protocol 实现。

---

## 6. Subproject A：HTTPS Browser Lab

### 6.1 技术选型

```text
TypeScript
Vite
pnpm
js-libp2p
@libp2p/webrtc
@libp2p/crypto
@libp2p/peer-id
@libp2p/circuit-relay-v2
```

网站是纯静态产物，不增加 Node API backend。生产实验由用户部署到 HTTPS；本地开发允许
Vite 的 loopback dev server。

页面必须在 secure context 下显示明确诊断：

```text
window.isSecureContext
browser user agent/version
WebRTC API availability
configured STUN list
TURN rejection status
```

### 6.2 页面运行角色

同一个网站支持三种显式角色，不自动猜测：

```text
direct-dialer      拨 Go NAS 的 WebRTC Direct multiaddr
private-listener   在 Circuit Relay reservation 上等待另一个 Browser
private-dialer     经 Relay 向 private-listener 发起 WebRTC
```

用户可以开两个独立 Browser profile 或两个不会共享 session state 的页面实例，分别运行
`private-listener` 和 `private-dialer`。

### 6.3 Identity 页面

页面提供：

- 生成 test secp256k1 private key；
- 导入 64 个 hex 字符的 test private key；
- 派生并展示 33 字节压缩公钥；
- 派生并展示 PeerId；
- 明确显示 `business key == libp2p identity key`；
- 将同一个 js-libp2p PrivateKey 对象传给 `createLibp2p({ privateKey })`；
- 页面刷新、停止节点或身份切换时销毁旧 host。

私钥输入框默认使用 password 类型，不提供复制到日志按钮。页面只允许复制公钥与 PeerId。

### 6.4 Direct 页面

输入：

```text
Go NAS WebRTC Direct multiaddr
NAS expected compressed public key
传输总字节数
并发 stream 数
逻辑块大小（默认 262144）
```

建连后显示：

```text
remote PeerId
expected PeerId
connection.direct
connection.limits
connection.remoteAddr
transport kind
selected ICE candidate pair
local/remote candidate type
bytesSent/bytesReceived
RTT
```

只有远端身份和 direct gate 全部通过后才开放 lab protocol 按钮。

### 6.5 Private WebRTC 页面

`private-listener`：

1. 使用自己的业务私钥启动 js-libp2p；
2. 连接指定 Relay；
3. 建立 Circuit Relay v2 reservation；
4. 监听 `/webrtc`；
5. 展示可以复制给 dialer 的完整 relay-signaled WebRTC multiaddr。

`private-dialer`：

1. 导入目标 listener 公钥与完整 multiaddr；
2. 经 Relay 打开 signaling connection；
3. 等待 direct WebRTC connection；
4. 执行 direct gate；
5. 在具体 WebRTC connection 上运行 lab protocol。

两端不得用同一把私钥。

### 6.6 ICE 观测

Browser Lab 必须能取得 selected candidate pair，而不只显示 `connection.direct`。

优先顺序：

1. 使用固定 release 已公开的只读 event/hook；
2. 若没有公开接口，给固定版本的 `@libp2p/webrtc` 加最小只读 observer patch；
3. patch 只暴露 `getStats()` snapshot，不改变拨号、ICE 或 DataChannel 行为；
4. patch 必须随 lockfile 提交并有单独说明；
5. 浏览器 `chrome://webrtc-internals` 只作为人工交叉检查，不能是程序唯一证据。

selected pair 只允许：

```text
host
srflx
prflx
```

出现 `relay` candidate 必须标红并阻止大字节实验。

### 6.7 TURN 硬拒绝

Browser 配置 parser 必须拒绝：

```text
turn:
turns:
iceTransportPolicy = relay
TURN username/credential
```

本轮只允许 `stun:`。

---

## 7. Subproject B：Go NAS/Relay Lab

### 7.1 技术选型

```text
Go
go-libp2p
go-libp2p/core/crypto
go-libp2p/p2p/transport/webrtc
go-libp2p Circuit Relay v2 service
```

依赖使用 Gate 0 确认的正式 release。禁止引用已经归档的独立
`go-libp2p-webrtc-direct` 仓库。

### 7.2 `nas` 角色

启动示意：

```text
msfile-webrtc-lab nas \
  --identity-key-file <test-key-file> \
  --listen /ip4/0.0.0.0/udp/4001/webrtc-direct \
  --allow-public-key <browser-compressed-public-key>
```

职责：

- 从 test key file 加载 32 字节 secp256k1 业务私钥；
- 用 `crypto.UnmarshalSecp256k1PrivateKey` 构造 libp2p private key；
- 将同一个 private key 传给 `libp2p.Identity(...)`；
- 监听 WebRTC Direct；
- 输出自己的压缩公钥、PeerId 和包含 certhash 的 multiaddr；
- 注册三个 lab protocol；
- 从 `stream.Conn().RemotePublicKey()` 读取真实远端公钥；
- 只允许白名单压缩公钥；
- 拒绝非 secp256k1 peer；
- 记录 connection direct/limited、remote PeerId 和脱敏统计；
- 不记录 private key。

WebRTC certificate/key 必须支持持久化，使同一 test identity 重启后能验证 certhash 是否稳定。

### 7.3 `relay` 角色

启动示意：

```text
msfile-webrtc-lab relay \
  --identity-key-file <relay-test-key-file> \
  --listen <public-browser-dialable-wss-multiaddr>
```

职责：

- 启动 Circuit Relay v2 service；
- 提供 Browser 可以从 HTTPS 页面拨号的 WSS 地址；
- 接受 reservation 和 signaling circuit；
- 记录每条 reservation/connection 的总入站、出站字节与存续时间；
- 不注册三个 lab protocol；
- 不承担 TURN；
- 支持收到信号后优雅停止，用于断 Relay 实验。

公网 WSS 的 TLS 证书和反向代理属于部署前置条件，可以由用户现有 HTTPS 基础设施提供；
subproject README 必须给出 multiaddr 与反向代理要求，不能把 `ws://` 地址交给 HTTPS 页面。

### 7.4 Go relay-signaled WebRTC 支持探针

`nas` 启动时打印 capability：

```text
webrtc_direct_listener = supported|unsupported
webrtc_private_listener = supported|unsupported
```

如果固定 go-libp2p release 提供 private WebRTC listener，则增加显式参数：

```text
--relay-listen <relay-multiaddr>
```

并执行 Browser -> Go relay-signaled 互联。

如果不支持，只输出稳定的 `UNSUPPORTED_UPSTREAM`，不使用裸 Relay connection 伪装成功，
不引入自研 transport。

---

## 8. Lab Protocol

### 8.1 `/msfile-lab/identity/1.0.0`

目标：确认业务身份与 libp2p connection identity 相同。

Go NAS 收到 stream 后，从 connection 取得：

```text
remote PeerId
remote secp256k1 public key bytes
local PeerId
local secp256k1 public key bytes
connection direction
connection direct/limited
```

响应只返回这些公开诊断字段。Browser 验证：

- NAS 观察到的 Browser 公钥等于 Browser 业务公钥；
- `PeerId(Browser业务公钥)` 等于 NAS 观察到的 remote PeerId；
- Browser 观察到的 remote PeerId 等于 `PeerId(NAS业务公钥)`；
- connection 通过 direct gate。

响应字段只是诊断证据，授权本身仍必须在响应前使用 connection 真值完成。

### 8.2 `/msfile-lab/echo/1.0.0`

目标：确认双向 stream、二进制不经 JSON/Base64。

- 客户端发送随机 raw bytes；
- 服务端原样回送；
- 默认覆盖 0、1、16384、262144 字节；
- 发送端按 transport `maxMessageSize` 切成不超过 16 KiB 的 write；
- 客户端比较 exact bytes 和 SHA-256。

### 8.3 `/msfile-lab/bytes/1.0.0`

目标：模拟 NAS 向 Browser 传输大文件块。

请求只包含固定长度二进制参数：

```text
total_bytes
logical_block_bytes = 262144
deterministic_data_seed
```

NAS 按 seed 确定性生成 raw bytes，按不超过 16 KiB 的 write 连续发送。Browser：

- 以 stream 方式消费，不把全部响应一次性复制到内存；
- 统计总字节；
- 增量计算 SHA-256；
- 与 Go 端预期摘要比较；
- 记录吞吐、TTFB、RTT、峰值内存和 selected candidate pair bytes。

该 framing 只属于 lab，不进入 `/msfile/1.0.0` 正式规范。

---

## 9. 测试身份与白名单

### 9.1 固定跨语言向量

`identity-vector.json` 至少包含：

```text
name
private_key_hex       # test-only，明确声明无资金无权限
public_key_hex
peer_id
```

Go 与 TypeScript 单测必须独立从 `private_key_hex` 派生后比对后两个期望值。不能让一个语言
执行后把结果动态喂给另一个语言，否则无法发现双方编码口径同时漂移。

### 9.2 运行时身份

实际 E2E 使用四把不同 test key：

```text
K_browser_dialer
K_browser_listener
K_go_nas
K_go_relay
```

NAS 白名单配置 Browser 公钥；Browser 配置并固定 NAS 公钥。Browser-to-Browser 控制组双方
也必须互相配置期望公钥。

### 9.3 负向身份测试

必须覆盖：

- 白名单公钥成功；
- 非白名单公钥连接后无法打开 lab protocol；
- multiaddr PeerId 与期望 NAS 公钥不一致；
- 报文自报白名单公钥但 connection 使用另一私钥；
- 同一私钥启动两个 peer 时被明确诊断为 PeerId collision/自连接，不能记作成功。

---

## 10. 实验矩阵

| ID | 场景 | 必须结果 |
|---|---|---|
| T01 | JS/Go 固定私钥派生公钥与 PeerId | 两边 exact 相同 |
| T02 | Browser -> Go NAS WebRTC Direct identity | 必须 PASS |
| T03 | Browser -> Go NAS WebRTC Direct echo | 必须 PASS |
| T04 | Browser <- Go NAS WebRTC Direct 1 GiB bytes | 必须 PASS |
| T05 | Browser A -> Browser B relay-signaled WebRTC | 必须 PASS |
| T06 | T05 连接后 Relay 保持在线，传 256 MiB | Relay 字节不随 payload 增长 |
| T07 | T05 连接后停止 Relay，再传 1 GiB | 当前传输必须 PASS |
| T08 | Browser -> Go NAS relay-signaled WebRTC | `PASS` 或有证据的 `UNSUPPORTED_UPSTREAM` |
| T09 | ICE 打洞失败 | 不得退回 Relay 数据传输 |
| T10 | 配置 TURN URL | 必须在启动前拒绝 |
| T11 | selected pair 出现 relay candidate | 必须阻止 lab bytes |
| T12 | 非白名单 Browser -> Go NAS | lab protocol 必须拒绝 |
| T13 | 错误 NAS PeerId/公钥 pin | 建连或 direct gate 必须失败 |
| T14 | 4/8 条并发 bytes stream | 不串流、摘要全部正确、内存有界 |

T08 如果是 `UNSUPPORTED_UPSTREAM`，本次研究施工可以完成，但正式 MSFile “Go NAS 支持
relay-signaled WebRTC”的产品目标仍处于阻塞状态，实验报告必须醒目标记。

---

## 11. Relay 退出的可控证明

本实验不能只引用官方文档说“Relay 已退出”。T05–T07 必须同时采集：

### 11.1 端点证据

```text
connection.direct == true
connection.limits == nil
transport == webrtc
selected candidate pair 存在
local candidate type != relay
remote candidate type != relay
WebRTC candidate-pair bytes 随 payload 增长
```

### 11.2 Relay 证据

在大字节传输前后记录：

```text
relay reservation id / peer id
relay bytes in
relay bytes out
relay connection duration
snapshot timestamp
```

允许 keepalive 和少量控制字节，不允许 Relay 增量与 256 MiB payload 同量级。

### 11.3 断 Relay 证据

流程必须严格是：

```text
1. 形成 direct WebRTC connection
2. identity protocol PASS
3. 先传一小段 bytes，确认 connection 可用
4. 停止 Relay 进程或从网络层阻断 Relay
5. 不重拨、不重建 connection
6. 在同一 WebRTC connection 新开 bytes stream
7. 完成 1 GiB、摘要正确
```

如果停止 Relay 导致当前 WebRTC connection 断开，T07 失败。不能重启 Relay 后重测并覆盖
失败证据。

---

## 12. HTTPS 与部署前置条件

### 12.1 Browser 网站

- 正式实验必须部署在 `https://`；
- 页面必须确认 `window.isSecureContext == true`；
- 静态资源不得从 HTTP mixed content 加载；
- private key 只存在页面内存；
- 页面部署不需要访问 Go NAS 的 HTTP API。

### 12.2 WebRTC Direct NAS

- 公网 IPv6，或公网 IPv4/UDP 端口映射；
- UDP 端口对 Browser 可达；
- multiaddr 带 certhash 和 NAS PeerId；
- 不要求 NAS 提供 HTTPS/WSS。

### 12.3 Circuit Relay

- Relay 必须有 Browser 可拨的公开 WSS multiaddr；
- TLS 证书由公共信任链签发；
- Relay 可以部署在现有 HTTPS 反向代理后；
- Relay 不提供 TURN；
- Relay 端口、PeerId 和完整 multiaddr 进入实验记录。

---

## 13. 可观测性与结果格式

两个 subproject 统一输出结构化 JSON line，字段至少包含：

```text
time
side = browser|nas|relay
event
local_peer_id
remote_peer_id
transport
direct
limited
local_candidate_type
remote_candidate_type
bytes_sent
bytes_received
elapsed_ms
error_code
```

日志中禁止出现 private key、SDP 全文、ICE credential 和 payload 内容。

最终报告 `docs/labs/webrtc-interop-report.zh.md` 必须记录：

1. 精确依赖与浏览器版本；
2. 网络拓扑和 NAT 类型；
3. 每个 T01–T14 的 PASS/FAIL/UNSUPPORTED；
4. Browser/Go 公钥与 PeerId 派生是否一致；
5. WebRTC Direct multiaddr 和脱敏连接结果；
6. relay-signaled selected candidate pair；
7. Relay 前后字节统计；
8. 断 Relay 传输结果；
9. Go relay-signaled WebRTC 上游能力结论；
10. 是否足以进入正式 MSFile 实现的最终裁决。

---

## 14. 必须怎么做

### 14.1 阶段 A：Gate 0 与 identity vector

1. 查询并固定正式依赖版本；
2. 写版本审计记录；
3. 建立固定 test-only secp256k1 vector；
4. Go 与 TypeScript 分别实现派生测试；
5. 两边公钥或 PeerId 任一不一致时停止后续网络实验。

### 14.2 阶段 B：Go NAS WebRTC Direct

1. 完成 Go `nas` identity 加载和白名单；
2. 启动 WebRTC Direct listener；
3. 完成 Browser `direct-dialer`；
4. 跑 identity、echo、bytes；
5. 完成错误 identity 和非白名单测试；
6. T02–T04 全部通过后进入 private WebRTC。

### 14.3 阶段 C：Relay 与 Browser private WebRTC

1. 完成 Go `relay` 角色与 WSS 部署；
2. Browser listener 建 reservation；
3. Browser dialer 经 Relay 建 WebRTC；
4. 验证 direct gate 和 selected pair；
5. 保持 Relay 在线跑 payload 与 Relay bytes 对照；
6. 停止 Relay 后跑同一 connection 的 1 GiB；
7. T05–T07 全部形成证据。

### 14.4 阶段 D：Browser -> Go private WebRTC 探针

1. 按 Gate 0 结论使用官方现有能力；
2. 支持则执行完整 identity/echo/bytes；
3. 不支持则保存编译/API/能力矩阵证据；
4. 不写自研 transport；
5. 在报告中给出产品影响。

### 14.5 阶段 E：报告与清理

1. 跑完测试矩阵；
2. 删除临时 private key、SDP 和未脱敏日志；
3. 固化可公开实验日志；
4. 完成互联报告；
5. README 写清运行命令和部署前置；
6. 两个 subproject 分别完成 clean build/test。

---

## 15. 测试与构建要求

### 15.1 Browser subproject

至少提供：

```text
pnpm install --frozen-lockfile
pnpm test
pnpm build
```

单元测试覆盖：

- fixed identity vector；
- private key 格式与范围；
- PeerId/public key pin；
- TURN 配置拒绝；
- lab framing 和分片；
- selected candidate type gate；
- 增量 SHA-256 和长度校验。

### 15.2 Go subproject

至少提供：

```text
go test ./...
go build ./cmd/msfile-webrtc-lab
```

单元测试覆盖：

- fixed identity vector；
- 非 secp256k1 拒绝；
- 白名单匹配；
- 从 connection public key 得到规范压缩字节；
- lab framing；
- 确定性 payload 和摘要；
- Relay 计数器；
- 私钥不进入日志。

### 15.3 网络 E2E

网络 E2E 不进入默认单元测试，必须由显式命令运行并记录环境。测试不能花钱，也不访问
Keymaster 生产 Vault。

---

## 16. 完成标准

本施工单只有满足以下条件才算完成：

1. `labs/webrtc-web` 可以独立安装、测试、构建并部署到 HTTPS；
2. `labs/webrtc-go` 可以独立测试、构建，并以 `nas`、`relay` 两个角色运行；
3. JS/Go fixed identity vector 完全一致；
4. Browser 业务私钥成功成为 js-libp2p identity；
5. Go NAS 业务私钥成功成为 go-libp2p identity；
6. Go NAS 从 connection 取得的 Browser 公钥与白名单业务公钥一致；
7. Browser -> Go WebRTC Direct 完成 1 GiB、摘要正确；
8. Browser -> Browser relay-signaled WebRTC 完成 direct gate；
9. Relay 在线时文件字节不经过 Relay；
10. Relay 停止后同一 WebRTC connection 仍完成 1 GiB；
11. TURN 和 relay ICE candidate 被硬拒绝；
12. Browser -> Go relay-signaled 产生明确 PASS 或 `UNSUPPORTED_UPSTREAM` 结论；
13. 最终报告包含全部版本、矩阵和失败证据；
14. 没有新增正式 MSFile wire、没有自研 Go WebRTC transport、没有提交真实私钥。

---

## 17. 明确不属于本次施工

本次不做：

- 正式 `/msfile/1.0.0`；
- Stat、Acquire、Read；
- MasterSeed 和块哈希业务验证；
- Keymaster plugin 或 `msfile.service` 接线；
- Keymaster Vault 适配；
- Connect SDK API；
- BitFSProxy 发现、报价、购买和缓存；
- DHT、Rendezvous、二维码或配对码；
- TURN；
- Circuit Relay 数据回退；
- 自研 Go private-to-private WebRTC transport；
- 自动路由器端口映射；
- 生产部署和长期运维。

本次结论只回答“transport 和同钥 identity 是否跑得通”。正式功能必须等实验报告通过后另开
施工单。
