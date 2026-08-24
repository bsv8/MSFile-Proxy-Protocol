# libp2p WebRTC 与同钥身份互通实验报告

施工单：[20260824-1](../../施工单/20260824/1-libp2p-webrtc与同钥身份互通实验施工单.md)
状态：**本地原型基本完成，四轮评审的代码级问题已全部落地修复并复验：
Private approval 时序竞态、Go 全量 race 稳定性、ICE 歧义检测窗口、
live-counter 测试假通过窗口均已按评审建议修正并通过专项验证（待复核确认）。
真实网络 E2E（T02–T07、T09、T14）、Git 版本跟踪与 Go 普通 NAT NAS 能力仍未完成**
——NAS 能力需产品侧按 §3 三选一决策；E2E 需部署 HTTPS/WSS/公网 UDP 环境；
交付需将 `labs/`、`docs/labs/` 加入版本控制。

---

## 1. Gate 0：版本审计（2026-08-24）

| 组件 | 锁定版本 | 备注 |
|---|---|---|
| Node.js | v22.13.1 | |
| pnpm | 11.5.1 | |
| libp2p (js) | **3.3.9** | npm latest；v3 起完全模块化，noise/yamux/identify/ping 显式装配 |
| @libp2p/webrtc | **6.0.30** | 同时导出 `webRTC()` 与 `webRTCDirect()` ✓ |
| @libp2p/crypto | **5.1.23** | `privateKeyFromRaw(32B)` → secp256k1 |
| @libp2p/circuit-relay-v2 | **4.2.12** | `circuitRelayTransport` / `circuitRelayServer` |
| @libp2p/peer-id | **6.0.15** | `peerIdFromPrivateKey` / `peerIdFromPublicKey` |
| @noble/hashes | 2.x | `@noble/hashes/sha2.js` 增量 SHA-256 |
| Go | go1.26.0 | go.mod 声明 >= 1.25 |
| go-libp2p | **v0.49.0**（2026-07-28 release） | 非 main 分支依赖 ✓ |
| Pion/WebRTC | 由 go.sum 解析（v0.49.0 内已升级） | |
| Chrome/Firefox/Safari | 待实验执行时填写 | |

### Gate 0 五项确认结论

1. **js-libp2p 是否仍支持 `webRTC()` 和 `webRTCDirect()`**：是。`@libp2p/webrtc@6.0.30`
   同时导出两个 transport；官方 README 示例给出 Browser↔Browser relay-signaled 全流程。
2. **Go WebRTC transport 是否仍只实现 WebRTC Direct**：是。
   `p2p/transport/webrtc.Transport.Protocols()` 仅返回 `[P_WEBRTC_DIRECT]`
   （v0.49.0 源码确认）。上游能力矩阵维持 `WebRTC Direct = supported / WebRTC = not supported`。
3. **Go host 能否监听 relay-signaled `/webrtc`**：不能。运行时探针
   （`internal/nas.ProbePrivateWebRTCListener`，对 `/ip4/127.0.0.1/udp/0/webrtc` 发起
   Listen）稳定失败 → nas 启动时输出
   `webrtc_private_listener = unsupported` + `UNSUPPORTED_UPSTREAM`。
   按施工单 §3.2：不自行实现 Go private WebRTC transport、不改上游源码、不把 Circuit Relay
   connection 当数据连接。
4. **WebRTC Direct V2 Browser -> Go 是否进入正式 release**：是。go-libp2p v0.49.0 包含
   `feat(webrtc): support webrtc-direct v2`（PR #3520）。
5. **js-libp2p 是否公开 selected ICE candidate pair 观测接口**：否。
   `@libp2p/webrtc@6.0.30` 未暴露底层 RTCPeerConnection/getStats。
   处置（§6.6 允许的最小只读 observer）：页面在创建节点前包装
   `window.RTCPeerConnection` 构造器，仅登记实例并周期采样 `getStats()` 提取 selected pair，
   不改变拨号/ICE/DataChannel 行为；实现位于
   `labs/webrtc-web/src/stats.ts#installPeerConnectionObserver`，随源码提交并有本节说明。

### 附加上游发现

- v0.49.0 起 Go WebRTC Direct 的 DTLS 证书由 identity 私钥 HKDF 确定性派生
  （`feat(webrtc): stable /certhash across restarts`, PR #3512）→ 同一 test identity 重启后
  certhash 稳定，满足 §7.2 证书持久化要求，无需额外持久化层。

## 2. 固定跨语言 identity vector（T01）

`labs/*/testdata/identity-vector.json`：

```text
private_key_hex : 278d5bed18a82b66619e026c2efb2a907e35310829d9658fb967180636afaa6a   # test-only，无资金无权限
public_key_hex  : 02e940822d4e7a09ce013bed4fa812e92f22b0ed1fa2d1ad06ae0406680da1cc46 # 33B compressed
peer_id         : 16Uiu2HAmB8C2R7pBJu1z2u1gno7aXcbtkoUzrknTFN2EBLjRavKP              # secp256k1 前缀
```

- Go（go-libp2p v0.49.0）与 TypeScript（@libp2p/crypto 5.1.23）各自独立从
  `private_key_hex` 派生并比对期望值，两侧单测均 PASS：
  - `labs/webrtc-go/identity_vector_test.go#TestFixedIdentityVectorDerivation`
  - `labs/webrtc-web/test/identity-vector.test.ts` "fixed identity vector (T01)"
- 确定性 payload 的跨语言 digest fixture（total=1000/seed=77、65537/42、262144/7）
  在两侧测试中同时断言相等。

## 3. 实验矩阵 T01–T14

> 执行环境要求：NAS 公网可达 UDP、Relay WSS 反代（公共信任链 TLS）、双浏览器 profile。
> 每项必须附版本、JSONL 日志、连接路径与字节统计证据后方可标记 PASS。

| ID | 场景 | 结果 | 证据（待回填） |
|---|---|---|---|
| T01 | JS/Go 固定私钥派生公钥与 PeerId 一致 | **PASS**（单元级） | 上文 §2 测试名 |
| T02 | Browser -> Go NAS WebRTC Direct identity | 待执行 | |
| T03 | Browser -> Go NAS WebRTC Direct echo | 待执行 | |
| T04 | Browser <- Go NAS WebRTC Direct 1 GiB bytes | 待执行 | |
| T05 | Browser A -> Browser B relay-signaled WebRTC | 待执行 | |
| T06 | T05 后 Relay 在线传 256 MiB，Relay 字节不随 payload 增长 | 待执行 | relay edge proxy 计数 + candidate-pair bytes 快照 |
| T07 | T05 后停止 Relay，同一 connection 再传 1 GiB | 待执行 | SIGTERM 时间戳 + 传输成功摘要 |
| T08 | Browser -> Go NAS relay-signaled WebRTC | **UNSUPPORTED_UPSTREAM**（Gate 0 探针证据） | §1 结论 3；nas `--relay-listen` 输出 |
| T09 | ICE 打洞失败不得退回 Relay 数据传输 | 待执行 | |
| T10 | 配置 TURN URL 必须启动前拒绝 | **PASS**（单元级） | `test/gates.test.ts` TURN hard rejection |
| T11 | selected pair 出现 relay candidate 必须阻止 lab bytes | **PASS**（单元级） | `test/gates.test.ts` candidate type gate |
| T12 | 非白名单 Browser -> Go NAS lab protocol 拒绝 | **PASS**（loopback 单元级） | `labproto_test.go#TestNonWhitelistedClientIsDenied` |
| T13 | 错误 NAS PeerId/公钥 pin 建连或 gate 失败 | **PASS**（单元级） | `test/gates.test.ts` direct gate |
| T14 | 4/8 并发 bytes stream 不串流、摘要正确、内存有界 | 待执行 | |

T08 为 UNSUPPORTED_UPSTREAM 时本次研究施工可完成，但“Go NAS 支持 relay-signaled
WebRTC”的产品目标保持阻塞状态——**对“普通个人 NAS”是硬阻断**：普通 NAT 后、没有公网
UDP/端口映射的 Go NAS 无法用当前方案对外提供服务。Browser ↔ Browser `webRTC()` 只能证明
js-libp2p 路径，不能证明 Go NAS 路径。产品侧必须三选一：

1. v1 明确要求 Go NAS 具备公网 IPv6 或 IPv4/UDP 端口映射（WebRTC Direct 可用）；
2. 另开项目补齐/向上游贡献 Go relay-signaled WebRTC transport；
3. 引入支持该能力的 sidecar/runtime 承载 NAS 角色。

## 4. 构建与测试现状（2026-08-24，首轮评审修复后）

```text
labs/webrtc-web: pnpm install --frozen-lockfile ✓ / pnpm test 57 passed ✓ / pnpm build ✓
labs/webrtc-go : go vet ./... ✓ / gofmt 无 diff ✓
                 go test ./... 全部通过（含 loopback 真实连接 E2E、relay 计数、SIGUSR1 行为）
                 go test -race -count=1 ./... 通过 ✓
                 go test -race -count=50 -run '^TestEdgeProxyCountersAreLiveDuringTransfer$' 通过 ✓
                 go build ./cmd/msfile-webrtc-lab ✓
```

### 第二轮评审阻断修复记录（2026-08-24）

| # | 阻断问题 | 修复 |
|---|---|---|
| 1 | listener 流程把 66 位压缩公钥传给 `deriveIdentity()`（仅接受 64 位私钥）导致等待连接前必报错 | 改用 `peerIdFromCompressedPublicKeyHex()`；新增 `test/listener-flow.test.ts` 覆盖 UI 公钥 → PeerId 派生 → `waitForApprovedInboundConnection` 的成功/无关 peer 超时/pre-check 失败路径 |
| 2 | gate 在等待 ICE 采样之前执行（dial 函数内部提前 gate），连接过快时误报 `no selected ICE candidate pair` | 拆分拨号与 gate：记录 generation → 仅 dial → 等待本次新建 PC 的 selected pair → 只执行一次 `evaluateDirectGate`；日志与 UI 均使用最终 gate 结果 |
| 3 | bytes 前 re-gate 未 await 采样、从全局最新 PC 取结果、按输入框猜测期望公钥 | 引入 `activeContext{connection, expectedPublicKeyHex, pcGeneration}`；`reGateActiveConn()` 异步等待指定 generation 的采样后用存储的上下文重新 gate |
| SIG | SIGUSR1 被放进终止 Context，实测直接导致 relay_stopping/stopped | SIGINT/SIGTERM 单独负责终止；SIGUSR1 独立 channel，主循环只触发 `relay_counter_snapshot(trigger=SIGUSR1)`；新增 helper-process 测试断言“SIGUSR1 后进程仍在运行、SIGTERM 才退出” |

ICE 证据加强：gate 直接复用 `isPairAllowedForTransfer()`，candidate type 仅接受
host/srflx/prflx，`unknown` 一律失败；`samplePair` 优先读取浏览器
`transport.selectedCandidatePairId`，缺失时才回退 succeeded/nominated 评分。
峰值内存改为传输期间 250ms 间隔采样的 `PeakHeapSampler`（peak − baseline），
替代起止差值。

### 第三轮评审阻断修复记录（2026-08-24）

| # | 问题 | 修复 |
|---|---|---|
| 1 | Dialer 在 Listener 完成审批前就发 identity，未批准流被立即 abort | `serveIfApproved` 对“预期 dialer 公钥对应的连接”引入有界等待（默认 30s，可配）：先发 `lab_protocol_pending_approval`，轮询 approved set，超时才 abort；无关 peer 仍立即拒绝。listener 流程在等待前通过 `approvals.setExpectedPeerId()` 注册预期。新增 `test/approval-race.test.ts` 覆盖“identity 先到、approval 后到”及超时/立即拒绝路径 |
| 2 | Relay 计数测试在首次读取后立即断言，`-race -count=20` 失败 2/20 | 第四轮重构为严格形式：独立 goroutine 持续读取（atomic readTotal），主测试 10ms ticker 轮询计数，仅在 `0 < readTotal < totalBytes` 时接受 `out>0`（并断言 in==0、active==1）；若 reader 完成前从未观察到实时计数则 Fatal——消除完整读取后的假通过路径。首次观察到 partial read 后启动 500ms 有界等待窗口，窗口内 out==0 继续轮询、超时才 Fatal；readerDone 先于任何中途计数仍 Fatal。并发 shutdown 测试 `TestEdgeProxyShutdownWaitsForActiveConnsAndCountsRaceSafe` 已恢复（4 连接并发 + 并发 snapshot 轮询 + `waitForCounter` 同步 + stop 后 active==0）。验证：live-counter 与 shutdown 各自 `-race -count=100` 专项通过；`-race -count=20 ./...` 通过 |
| 3 | ICE 歧义检测只统计“已产生 pair”的新 PC：第二个 PC 已创建但尚未采样时仍会误绑 | `waitForSelectedPair()` 改为统计 marker 后**所有未关闭**新 PeerConnection，数量 >1 即抛出 `ambiguous ICE evidence`（标注各有无 pair）；新增 `test/ice-binding.test.ts` 覆盖“两个新 PC 只有一个已有 pair”“单 PC 正常解析”“closed PC 不计入”三个用例。connection.id→PC 精确映射留作长期改进 |

其他：`ApprovalRegistry.clear()` 现同时重置 expectedPeerId，避免节点重启或角色切换后保留旧预期白名单。

### Git 交付状态

`labs/`、`docs/labs/` 尚未加入 Git 跟踪（本地实验不受影响）。正式提交与交付前
需要用户确认后执行 `git add` 与提交操作。

### 首轮评审阻断修复记录（2026-08-24）

| # | 阻断问题 | 修复 |
|---|---|---|
| 1 | 256 KiB echo 因 `crypto.getRandomValues` 64 KiB 单次上限失败 | `identity.ts#fillRandom` 分段填充；单测覆盖 >64 KiB 尺寸 |
| 2 | 1 GiB 传输：32B/次异步 send + 发送前全量预计算摘要 | 生成聚合为 ≤16 KiB 批次；framing 改为“8B 头 + payload + 32B SHA-256 trailer”，边生成边哈希边发送，无预遍历；浏览器侧重活移入 Web Worker（credit 背压 + transferable）；数据仍为 SHA256(seed‖counter) 确定性流，跨语言 fixture 不变 |
| 3 | ICE candidate 证据未绑定具体连接、采样延迟误判 | observer 引入 generation；拨号前记录 generation，拨号后 `waitForSelectedPair()` 只接受新建 PC 的即时采样结果；bytes 开始前强制 `sampleNow()` 并重跑 gate |
| 4 | Relay 计数仅在连接关闭时落账，无法做传输前后快照；存在竞态 | 计数改为 `atomic.Uint64` 实时逐字节累计；每 5s 输出 `relay_counter_snapshot` + SIGUSR1 即时快照；停止时关闭活动连接并等待双向拷贝退出；新增 relay 计数/停止竞态测试（`go test -race` 通过） |
| 5 | Browser listener 未认证 dialer、无 server-side gate | listener 必填预期 dialer 公钥；入站连接过 inbound gate 后进入 approved set（connection.id）；三个协议 handler 先查 approved set，明确拒绝 limited/relay 连接 |
| 6 | bytes 响应头假设一次读到 ≥40 字节 | 改为增量状态机解析：累计 ≥8B 解析 total、尾部保留 32B 作 trailer、中间全部进 hasher；单测覆盖 1/7/39 字节碎片化及截断/超发场景 |

其他建议落实：Go 侧 bytes 增加 8 GiB 上限、每流 2h deadline、全局并发 ≤8；
NAS multiaddr 追加 `/p2p/<PeerId>` 直接可复制；TTFB/heap delta 进入 `bytes_result`
事件；`gofmt -l` 清零；vitest 超时放宽至 30s 消除首跑波动。

## 5. 待办（进入阶段 B–E）

1. 准备公网 NAS（IPv6 或 IPv4/UDP 端口映射）+ HTTPS/WSS Relay 部署；
2. 按 §14 阶段 B–C 顺序执行 T02–T07、T09、T14 并回填证据；
3. 回填浏览器版本、NAT 类型、selected candidate pair、Relay 前后字节对照；
4. 清理临时私钥与未脱敏日志后给出最终裁决。

## 6. 最终裁决（占位）

待矩阵全部形成证据后填写：
“transport 与同钥身份是否跑得通、是否足以进入正式 MSFile 实现”。
