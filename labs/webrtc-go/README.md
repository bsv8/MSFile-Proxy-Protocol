# labs/webrtc-go — Go NAS / Relay 实验服务

`MSFile` WebRTC 与同钥身份实验的 Go subproject（施工单
[20260824-1](../../施工单/20260824/1-libp2p-webrtc与同钥身份互通实验施工单.md) 的 Subproject B）。
同一个 binary 提供两个运行角色：

```text
msfile-webrtc-lab nas     正式被 Browser 拨号的模拟 NAS（WebRTC Direct）
msfile-webrtc-lab relay   Circuit Relay v2 信令基础设施（只承载 reservation/SDP/ICE）
```

## 版本（Gate 0 锁定，2026-08-24）

| 依赖 | 版本 |
|---|---|
| Go | 1.26.0（go.mod 要求 >= 1.25） |
| go-libp2p | v0.49.0 |
| pion/webrtc 等 | 由 `go.sum` 最终解析 |
| multiaddr (Go) | v0.16.1 |

上游能力结论（已用编译探针 + 运行时探针双重确认，见
`internal/nas.ProbePrivateWebRTCListener`）：

- `webrtc_direct_listener = supported`
  （`p2p/transport/webrtc` 注册 `P_WEBRTC_DIRECT`；v0.49.0 起支持 webrtc-direct v2，
  `/certhash` 由 identity 私钥经 HKDF 确定性派生，重启后稳定）
- `webrtc_private_listener = unsupported` → **`UNSUPPORTED_UPSTREAM`**
  （上游未实现 relay-signaled `/webrtc` listener；本仓库不自行补齐 transport）

## 构建

```bash
go test ./...
go build ./cmd/msfile-webrtc-lab
```

网络 E2E 不在默认单测内；单元测试使用 loopback TCP host 验证协议与白名单。

## 测试身份

只允许 test-only 私钥（无资金、无生产权限）。生成：

```bash
msfile-webrtc-lab genkey > nas-test.key
```

固定跨语言向量位于 `testdata/identity-vector.json`（`private_key_hex` 明确标记
test-only）。Go 与 TypeScript 各自从 `private_key_hex` 独立派生并比对
`public_key_hex` / `peer_id`，任何一侧不一致即停止后续网络实验。
私钥不得进入日志、URL、截图或实验报告（logger 有脱敏黑名单兜底）。

## 运行 nas 角色

```bash
go build -o msfile-webrtc-lab ./cmd/msfile-webrtc-lab

msfile-webrtc-lab nas \
  --identity-key-file nas-test.key \
  --listen /ip4/0.0.0.0/udp/4001/webrtc-direct \
  --allow-public-key <browser-compressed-public-key-66-hex>
# 可重复 --listen 与 --allow-public-key

# 上游能力探针（当前恒为 UNSUPPORTED_UPSTREAM）：
msfile-webrtc-lab nas ... --relay-listen /ip4/0.0.0.0/udp/4002/webrtc
```

启动后 stderr 打印压缩公钥、PeerId 和带 certhash 的 WebRTC Direct multiaddr；
stdout 输出结构化 JSONL 事件（字段规范见施工单 §13）。

职责边界：

- 从 connection 层 `RemotePublicKey()` 取真实远端公钥做白名单授权；
- 拒绝非 secp256k1 peer；
- 只注册三个 lab protocol：
  `/msfile-lab/identity/1.0.0`、`/msfile-lab/echo/1.0.0`、`/msfile-lab/bytes/1.0.0`；
- 不实现正式 MSFile wire，不接 Keymaster Vault；
- 不记录 private key。

WebRTC DTLS 证书自 v0.49.0 起由 identity 私钥确定性派生，同一 test identity 重启后
certhash 保持稳定（上游 PR #3512），满足施工单 §7.2 的持久化要求。

## 运行 relay 角色

```bash
msfile-webrtc-lab relay \
  --identity-key-file relay-test.key \
  --ws-listen /ip4/127.0.0.1/tcp/9443/ws \
  --edge-listen 127.0.0.1:8443 \
  [--infinite-limits]
```

- 提供 Browser 可拨的 ws/wss 地址。生产实验必须由 HTTPS 基础设施提供 TLS 终结
  （公共信任链证书），把反向代理的 TCP upstream 指到 `--edge-listen` 端口；
  本 binary 自身不提供 wss/TLS。**不得把 `ws://` 地址交给 HTTPS 页面**。
- `--edge-listen` 启动进程内置的裸 TCP 计数代理（`atomic` 实时逐字节累计，转发给
  ws listener），用于采集施工单 §11.2 要求的 Relay 字节证据。计数器每 5 秒输出
  `relay_counter_snapshot` 事件，SIGUSR1 可触发即时快照，因此支持“传输前后对比”
  而不必等连接关闭；停止时会跟踪并关闭活动连接、等待双向拷贝退出后再落最终计数。
- 只做 reservation 与信令 circuit；不注册 lab protocol；不承担 TURN。
- SIGINT/SIGTERM 优雅停止（T07 断 Relay 实验）。

Browser 拼接目标地址模板（stderr 会打印）：

```text
<relay-wss-multiaddr>/p2p/<relay-peer-id>/p2p-circuit/webrtc/p2p/<browser-listener-peer-id>
```

## Lab 协议 framing（仅实验用，不属于正式 `/msfile/1.0.0`）

- echo：`u64 BE 长度 + payload` 单帧；服务端原样回送同构帧；payload ≤ 64 MiB。
- bytes 请求：固定 20 字节 `u64 total_bytes | u32 logical_block_bytes | u64 seed`；
  total 上限 8 GiB，服务端每流 2h deadline、全局最多 8 条并发 bytes 流。
- bytes 响应：**8B 头（u64 total）→ 原始数据流 → 末尾 32B SHA-256 trailer**；
  服务端边生成边哈希边发送，无需预先生成完整摘要。
- 确定性数据：`chunk_i = SHA256(seed_be_u64 || i_be_u64)`（32B/块），顺序拼接截断到
  total_bytes；所有 write ≤ 16 KiB。
- identity：服务端返回一行 JSON 诊断（remote/local 公钥与 PeerId、direction、
  direct/limited、transport），数据取自 connection 真值而非报文自报。

跨语言 digest fixture（TS 与 Go 测试同时断言）：

| total | seed | sha256 |
|---|---|---|
| 0 | 1 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| 1000 | 77 | 5a7ceb5425bc2beba3e82801f7b63d7527914ae64d927933cc4709dfbbaf6187 |
| 65537 | 42 | a942a93d550c97b5182fd5f5bb4b240e5fb88264c8b899170a1dad0f41d55282 |
| 262144 | 7 | 601c25f63b6d90ef44c94b747b60bed311c788e7dcd285966de4532b8c5fbc6e |

## 部署前置条件

- 公网可达 UDP 端口（NAS WebRTC Direct）；multiaddr 含 certhash + NAS PeerId。
- Relay 需要公共信任链 TLS 的反代 + 一个可从公网访问的 WSS 对外地址。
- 无 TURN；无 DHT/Rendezvous；无自动端口映射。
