# labs/webrtc-web — HTTPS Browser Lab

`MSFile` WebRTC 与同钥身份实验的浏览器 subproject（施工单
[20260824-1](../../施工单/20260824/1-libp2p-webrtc与同钥身份互通实验施工单.md) 的
Subproject A）。TypeScript + Vite + js-libp2p 的纯静态网站，无 Node backend。

## 版本（Gate 0 锁定，2026-08-24）

| 依赖 | 版本 |
|---|---|
| Node.js | v22.13.1 |
| pnpm | 11.5.1 |
| libp2p | 3.3.9 |
| @libp2p/webrtc | 6.0.30（官方未修改发行版；同时导出 `webRTC()` 与 `webRTCDirect()`） |
| @libp2p/crypto | 5.1.23 |
| @libp2p/circuit-relay-v2 | 4.2.12 |
| @libp2p/peer-id | 6.0.15 |
| @chainsafe/libp2p-noise / yamux | 17.0.0 / 8.0.1 |
| @noble/hashes | 2.x |
| Playwright | 1.62.1（真实 Chromium 全链路 E2E） |

js-libp2p v3 为完全模块化：noise/yamux/identify/ping/websockets/circuit-relay 均需显式装配，
见 `src/node.ts`。

## ICE 观测说明（施工单 §6.6）

固定 release `@libp2p/webrtc@6.0.30` **没有**公开 selected ICE candidate pair 观测接口
（源码确认未暴露底层 `RTCPeerConnection` 或 getStats）。因此本仓库采用最小只读 observer：
在创建任何 libp2p 节点之前包装 `window.RTCPeerConnection` 构造器
（`src/stats.ts#installPeerConnectionObserver`），只登记实例并周期性采样 `getStats()` 快照，
提取 selected candidate pair 与 candidate type；不改变拨号、ICE 或 DataChannel 行为。

candidate pair 证据与具体拨号绑定：每次拨号前记录 observer generation，拨号完成后
`waitForSelectedPair()` 立即重采样并只接受该次新建 PeerConnection 的结果，
传输开始前还会重新采样并再跑一次 gate；旧连接的快照不会被套用到新连接。
`chrome://webrtc-internals` 仅作人工交叉检查。

## 开发与构建

```bash
pnpm install --frozen-lockfile
pnpm test     # vitest：identity vector / framing / TURN 与 gate 单测
pnpm build    # tsc --noEmit + vite build -> dist/
pnpm dev      # 本地 loopback dev server（正式实验必须 HTTPS 部署）
pnpm test:e2e:direct # 自动启动 Go NAS，用真实 Chromium 逐端口验证完整直连流程
```

部署 `dist/` 到任意 HTTPS 静态托管即可；页面启动时校验 `window.isSecureContext`。

`test:e2e:direct` 默认测试公网 `23.254.242.181` 的 `4001/3478/8443` UDP 端口，
依次验证 WebRTC Direct、Noise 身份、identity 协议和 0/1/16384/262144 字节 echo。
可通过 `MSFILE_E2E_PAGE_URL`、`MSFILE_E2E_NAS_PUBLIC_IP`、`MSFILE_E2E_PORTS`
覆盖页面、IP 与端口；更换 NAS 身份时同步设置 `MSFILE_E2E_NAS_PUBLIC_KEY`、
`MSFILE_E2E_NAS_PEER_ID`、`MSFILE_E2E_NAS_CERTHASH`。若 NAS 已在另一台机器运行，
设置 `MSFILE_E2E_SKIP_GO=true`，脚本只负责浏览器侧并将结果标记为 external NAS。

## 页面角色

同一页面三种显式角色（不自动猜测）：

- `direct-dialer`：输入 Go NAS WebRTC Direct multiaddr（含 certhash）+ NAS 压缩公钥 pin，
  通过 direct gate 后开放 identity / echo / bytes 按钮；
- `private-listener`：连接 Relay 建 reservation，展示可复制的 relay-signaled WebRTC multiaddr；
- `private-dialer`：导入目标 listener 公钥与完整 multiaddr，经 Relay 完成 SDP/ICE 后等待
  direct WebRTC connection 并执行 direct gate。

两端不得使用同一把私钥；刷新、停止或切换身份时销毁旧 host。

## 身份规则

- 业务私钥 == libp2p identity 私钥（同一个 secp256k1 scalar）；
- 页面运行时默认生成临时 test 身份；可手工导入 64 hex 字符 test-only 私钥；
- 私钥输入框为 password 类型，无复制按钮；仅公钥与 PeerId 可复制；
- private key 只存在页面内存，不进 URL、日志、localStorage 或实验报告；
- 固定跨语言向量：`testdata/identity-vector.json`，与 Go 侧各自独立派生比对。

## 配置硬约束

- ICE 只允许 `stun:`；解析器拒绝 `turn:`、`turns:`、`iceTransportPolicy=relay`
  及 TURN username/credential（T10）；
- selected pair 仅允许 `host`/`srflx`/`prflx`；出现 `relay` candidate 标红并阻止
  大字节实验（T11）；
- direct gate 要求：远端 PeerId 等于 pin 公钥派生值 + `connection.direct === true` +
  `connection.limits == null` + 非 relay candidate pair。

## Lab 协议与 framing

三个 lab protocol（不属于正式 `/msfile/1.0.0`）：

- `/msfile-lab/identity/1.0.0`：服务端回一行 JSON 连接诊断；
- `/msfile-lab/echo/1.0.0`：`u64 BE 长度 + payload`，原样回送，覆盖 0/1/16384/262144 字节
  （随机填充按 ≤65536 字节分段调用 `crypto.getRandomValues`）；
- `/msfile-lab/bytes/1.0.0`：20B 请求 → **8B 头（total）→ 原始流 → 末尾 32B SHA-256
  trailer**；客户端增量状态机解析（容忍任意 read 分片，单测覆盖 1/7/39 字节碎片），
  边收边算摘要，不整包驻留内存；所有 write ≤ 16 KiB。

浏览器侧 1 GiB 级生成的重活放在 Web Worker（`src/datasource.worker.ts`，
credit-based 背压 + transferable buffer）；Node/测试环境自动回退内联生成器。
确定性数据与跨语言 digest fixture 见 `labs/webrtc-go/README.md`，两侧测试同时断言。

## Listener 入站认证

private-listener 必须填写预期 dialer 的压缩公钥；入站 WebRTC connection 通过
inbound gate（PeerId/公钥/`direct===true`/`limits==null`/transport/candidate pair）
后才进入 approved set，三个 lab protocol handler 首先检查 approved set，
明确拒绝 limited/relay 连接。

## 结构化 JSONL 日志

所有事件经 `src/ui.ts#EventLog` 输出（含私钥/SDP/credential 键名黑名单脱敏），
字段遵循施工单 §13。日志面板内容可全选复制存档。
