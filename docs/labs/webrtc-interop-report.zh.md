# libp2p WebRTC Direct / WSS 与同钥身份互通实验报告

> 协议范围裁决日期：2026-08-25。
>
> 本报告记录实验事实和后续验收矩阵。MSFile V1 已锁定为 libp2p WebRTC Direct 与
> WebSocket/WSS 两种直连 transport；早期 relay-signaled WebRTC、Circuit Relay 和相关
> candidate gate 实验不再是 V1 交付条件。

施工单：[20260824-1](../../施工单/20260824/1-libp2p-webrtc与同钥身份互通实验施工单.md)

---

## 1. 当前裁决

实验与协议讨论已经确认：

1. 保留 libp2p，不在裸 RTCDataChannel 或裸 WebSocket 上重新实现认证与 stream；
2. 支持 `webRTCDirect()` 和 `webSockets()`；
3. 生产浏览器 WebSocket 路径使用 WSS，WS 仅用于本机或受控开发环境；
4. 删除 relay-signaled `webRTC()`、Circuit Relay 和 TURN 相关产品路径；
5. 业务 identity 使用同一把 secp256k1 私钥；
6. 供应商 ID 是 libp2p connection 已认证出的 33 字节压缩公钥；
7. libp2p 已负责 Noise 身份认证，MSFile 不增加应用层握手；
8. 每个供应商 connection 使用一条长驻 Stat stream 和一条按需长驻 Read stream；
9. Stat 向所有启用供应商并发，Read 按供应商公钥定向；
10. 一条 stream 内允许多个并发请求和乱序响应，Frame 写入仍必须串行。

协议真值见：

- [MSFile Proxy Network Protocol v1](../protocol/network.zh.md)
- [MSFile Proxy Wire Messages v1](../protocol/wire-messages.zh.md)

---

## 2. 版本审计基线（2026-08-24）

| 组件 | 实验锁定版本 | 与当前 V1 的关系 |
|---|---:|---|
| Node.js | v22.13.1 | JS 实验运行时 |
| pnpm | 11.5.1 | JS 包管理器 |
| libp2p (js) | 3.3.9 | 显式装配 transport、Noise、Yamux 和服务 |
| `@libp2p/webrtc` | 6.0.30 | V1 只使用 `webRTCDirect()` |
| `@libp2p/websockets` | 10.1.20 | V1 使用 `webSockets()`；生产地址为 WSS |
| `@libp2p/crypto` | 5.1.23 | 从 32 字节 secp256k1 私钥派生 identity |
| `@libp2p/peer-id` | 6.0.15 | 公钥与 PeerId 互相校验 |
| `@noble/hashes` | 2.x | 增量 SHA-256 |
| Go | go1.26.0 | Go 实验运行时；`go.mod` 声明 >= 1.25 |
| go-libp2p | v0.49.0 | WebRTC Direct 与 Go identity 基线 |
| Pion/WebRTC | 由 `go.sum` 锁定 | Go WebRTC Direct 底层实现 |

版本号是本次实验的可复现基线，不是 MSFile wire 的组成部分。依赖升级必须重新执行本文矩阵，
但只要可观察身份、stream 和 Frame 语义不变，就不改变 `/msfile/1.0.0`。

### 2.1 上游能力结论

- js-libp2p 同时提供 WebRTC 与 WebRTC Direct；当前 V1 只选择 WebRTC Direct；
- WebRTC Direct 使用可靠 DataChannel 承载 libp2p protocol stream；
- WebRTC Direct 在身份认证成功后使用 WebRTC 自带的 DataChannel multiplexing；
- WebSocket transport 可以与 Noise、Yamux 组合，浏览器可以作为 WSS dialer；
- go-libp2p v0.49.0 的 WebRTC transport 支持 WebRTC Direct；
- go-libp2p 是否由目标部署程序直接提供 WSS listener，仍需在新的 WSS 实验中验收，不能用
  “JS 已安装 `@libp2p/websockets`”代替跨语言证据。

---

## 3. 固定跨语言 identity vector

两侧共享测试向量位于 `labs/*/testdata/identity-vector.json`：

```text
private_key_hex : 278d5bed18a82b66619e026c2efb2a907e35310829d9658fb967180636afaa6a
public_key_hex  : 02e940822d4e7a09ce013bed4fa812e92f22b0ed1fa2d1ad06ae0406680da1cc46
peer_id         : 16Uiu2HAmB8C2R7pBJu1z2u1gno7aXcbtkoUzrknTFN2EBLjRavKP
```

该私钥只用于测试，无资金和生产权限。

已验证：

- Go 与 TypeScript 分别从相同 32 字节私钥派生相同 33 字节压缩公钥；
- 两侧派生相同 PeerId；
- 固定 payload 的跨语言 SHA-256 fixture 一致；
- 这证明 `supplier_id = authenticated public key` 与 PeerId 派生可以跨语言稳定实现。

对应测试：

- `labs/webrtc-go/identity_vector_test.go#TestFixedIdentityVectorDerivation`
- `labs/webrtc-web/test/identity-vector.test.ts`

---

## 4. 当前原型与新协议的差距

现有 `labs/webrtc-*` 是协议裁决前的研究原型。它已经包含 WebRTC Direct、WebSocket transport
依赖、identity、字节流 framing、白名单和大流量测试基础，但源码仍保留：

- `webRTC()` relay-signaled transport；
- Circuit Relay client/server；
- Relay 流量计数与退出证明；
- TURN/candidate 类型 gate；
- 旧的“一次实验一条 stream”协议 handler。

这些代码没有在本次文档任务中删除，因为当前任务只落地协议文档。它们不能再作为 MSFile V1
运行路径或验收要求。进入正式实现前应另开代码任务：

1. 从默认节点装配和 UI 删除 relay-signaled 路径；
2. 增加真实 WSS listener/反向代理实验；
3. 把 lab protocol 改为长驻 Stat/Read 双 stream；
4. 增加 request ID、乱序响应、ReadCancelled 和 raw attachment 测试。

---

## 5. 已有实验结果

截至 2026-08-24 的本地记录：

```text
labs/webrtc-web:
  pnpm install --frozen-lockfile     PASS
  pnpm test                          57 passed
  pnpm build                         PASS

labs/webrtc-go:
  go vet ./...                       PASS
  gofmt                              no diff
  go test ./...                      PASS
  go test -race -count=1 ./...       PASS
  go build ./cmd/msfile-webrtc-lab   PASS
```

这些结果证明实验基础代码在当时版本下可构建，并不等于新的 MSFile wire 已实现。现有专项测试中
仍有一部分只服务于已经退出 V1 的 Relay/candidate 研究，后续不纳入回归门槛。

### 5.1 可以保留的工程结论

- `crypto.getRandomValues` 单次 64 KiB 上限需要分段处理；
- 大内容必须边生成、边哈希、边发送，不能预先分配完整 1 GiB payload；
- 浏览器主线程上的重计算应移入 Worker，并使用 credit/transferable 控制背压；
- Frame 解析必须支持任意碎片化，不能假设一次 read 得到完整 Header；
- 大流量测试必须采样传输期间峰值内存，不能只比较开始和结束快照；
- listener 必须在 protocol handler 内再次检查 authenticated connection 的远端公钥；
- 每条 stream 的 sink 必须由单一 writer 驱动，避免 Frame 字节交错。

---

## 6. 新互操作验收矩阵

以下矩阵替代旧 T01–T14，结果必须附浏览器/依赖版本、JSONL 日志、multiaddr、远端公钥、
transport、摘要和资源快照。

| ID | 场景 | 当前状态 | 通过条件 |
|---|---|---|---|
| I01 | JS/Go 固定 identity vector | **PASS** | 私钥派生公钥与 PeerId 完全一致 |
| I02 | Browser -> Go WebRTC Direct 身份认证 | 待执行 | 两端取得预期 authenticated remote public key |
| I03 | WebRTC Direct 双向 protocol stream | 待执行 | 同一 stream 同时收发，half-close/Reset 行为明确 |
| I04 | WebRTC Direct 大内容 | 待执行 | 16 MiB Seed、1 GiB 流摘要正确且内存有界 |
| I05 | Browser -> Supplier WSS 身份认证 | 待执行 | 公共信任 TLS + Noise + supplier public key pin 全部通过 |
| I06 | WSS/Yamux 双向 protocol stream | 待执行 | Stat/Read 两条 stream 独立、双向收发正常 |
| I07 | WSS 大内容与背压 | 待执行 | 16 MiB Seed、1 GiB 流摘要正确且队列/内存有界 |
| I08 | 同一供应商双 transport | 待执行 | WebRTC Direct/WSS 认证为同一公钥，地址切换不改变 supplier_id |
| I09 | 长驻 Stat stream | 待实现 | 高频、多 hash、乱序响应，不重复建 stream |
| I10 | 长驻 Read stream | 待实现 | 多 hash 并发，ReadResponse 按 request ID 正确关联 |
| I11 | Read 授权覆盖 | 待实现 | 更大 ID 覆盖旧上限，旧请求收到 ReadCancelled |
| I12 | ReadResponse 发送竞态 | 待实现 | 已开始 attachment 不截断，新请求不重复购买 |
| I13 | Stat/Read 隔离 | 待实现 | Read 大 attachment 期间 StatResponse 仍可及时返回 |
| I14 | 4/8 并发与恢复 | 待实现 | Frame 不串线、哈希正确、stream Reset 后可重建 |
| I15 | 非白名单与错误 pin | 部分 PASS | 两种 transport 都必须拒绝，不能只覆盖 loopback |

### 6.1 WebRTC Direct 实验环境

- 公网可达 UDP 或稳定端口映射；
- Chrome、Firefox、Safari 当前稳定版；
- 固定供应商 identity、公钥与 `/certhash`；
- 错误 PeerId、错误 certhash、连接中断和重拨反向用例。

### 6.2 WSS 实验环境

- 公共信任链 TLS 证书和匹配域名；
- 443/TCP 反向代理或供应商直接 TLS listener；
- 透明二进制 WebSocket 转发；
- Noise 与 Yamux 明确启用；
- 错误域名、过期证书、错误 PeerId 和错误公钥 pin 反向用例；
- WS 只在 loopback 测试，不把结果当作生产 WSS 证据。

---

## 7. Stream 性能基准

V1 选择固定两条长驻 stream，而不是每个请求新建 stream。需要分别在 WebRTC Direct 与 WSS
测量：

```text
connection_setup_ms
stream_open_ms
first_frame_ms
stat_rtt_ms
read_ttfb_ms
read_throughput_bytes_per_second
open_stream_memory_bytes
pending_request_memory_bytes
response_queue_peak_bytes
```

基准场景：

1. 每请求新建 stream，作为开销对照；
2. 一条长驻 Stat stream，连续 10,000 次查询；
3. 一条长驻 Read stream，4/8 个并发 hash；
4. 同一 hash 连续提高和降低 `max_price_satoshis`；
5. 16 MiB Seed attachment 发送期间并发 Stat；
6. stream Reset 后在原 connection 上重建；
7. connection 断开后从 WebRTC Direct 切换到同供应商 WSS。

验收重点不是追求固定常数，而是证明：两条长驻 stream 的内存稳定、没有随请求次数增长，且
控制面不会被数据 attachment 阻塞。

---

## 8. 已退出的旧实验项

以下旧项目只保留在 Git 历史或原型代码中，不再进入 MSFile V1 验收矩阵：

- Browser A/B relay-signaled WebRTC；
- Go relay-signaled WebRTC listener 探针；
- Circuit Relay reservation 和流量计数；
- 停止 Relay 后继续传输的证明；
- TURN URL 与 relay ICE candidate gate；
- “Relay 只做信令、不承载文件”的运行时检查。

退出原因不是实验失败，而是产品网络模型已经改为 WebRTC Direct + WSS 两种显式直连 transport。
因此不再需要维护第三种建连、信令退出或 Relay 数据边界。

---

## 9. 下一步

1. 先补 WSS 的 JS/Go 或 JS/目标供应商跨语言 echo 与 identity 实验；
2. 按新的 Wire Messages 实现最小 Stat/Read 双 stream lab handler；
3. 完成 I02–I15，并回填真实版本、网络环境、耗时、哈希与内存数据；
4. 对 WebRTC Direct 与 WSS 分别生成性能基线；
5. 实验通过后再进入正式 MSFile 实现。

在 I02–I15 完成前，只能裁决“协议方向已锁定、identity vector 已互通”，不能声称完整的
WebRTC Direct/WSS MSFile 协议已经跨语言通过。

---

## 参考资料

- [js-libp2p WebRTC transport](https://github.com/libp2p/js-libp2p/tree/main/packages/transport-webrtc)
- [libp2p WebRTC Direct specification](https://github.com/libp2p/specs/blob/master/webrtc/webrtc-direct.md)
- [js-libp2p WebSockets transport](https://github.com/libp2p/js-libp2p/tree/main/packages/transport-websockets)
- [libp2p connection and stream specification](https://github.com/libp2p/specs/blob/master/connections/README.md)
