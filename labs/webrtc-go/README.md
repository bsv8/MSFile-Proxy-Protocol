# labs/webrtc-go — Go MSFile NAS 与互通实验

本模块包含正式 NAS 服务 `cmd/msfile-nas` 与保留的互通实验 binary `cmd/msfile-webrtc-lab`。
完整运行说明见 [Go NAS 服务运行手册](../../docs/nas-service.zh.md)。

## 正式服务：msfile-nas

```bash
msfile-nas --config /etc/msfile-nas.yaml
```

- 数据模型：`nas_data`（用户原文件，只读真值）+ `seed_data`（Seed/SQLite/staging/trash，可重建）；
- 协议：仅注册 `/msfile/1.0.0`；WebRTC Direct + WS/WSS 承载；
- 授权：`access_mode: private` 配置文件公钥白名单 / `public` 任意已认证 secp256k1；
  空白名单拒绝全部，没有 allow-all 回退；
- 同步：fsnotify 文件事件快速发现 + 周期全量扫描最终收敛 + stat A/B/C 稳定性检测；
- 存储：SQLite 单执行器串行队列；Seed staging+fsync+原子 rename 发布；
- Web：中文平面 Hash 运维台，只读 API + 触发扫描，无目录树、无上传删除、无白名单管理。

配置示例见 [config/msfile-nas.example.yaml](config/msfile-nas.example.yaml)（全字段中文注释）。

## 实验工具：msfile-webrtc-lab

`MSFile` WebRTC 与同钥身份实验（施工单
[20260824-1](../../施工单/20260824/1-libp2p-webrtc与同钥身份互通实验施工单.md)）。
**仅供互通诊断，不是文件服务**：不打开正式 `seed_data/index.sqlite`，不扫描 `nas_data`。

```text
msfile-webrtc-lab genkey    生成测试用 secp256k1 私钥 hex
msfile-webrtc-lab labnas    只注册 /msfile-lab/* 实验协议；必须显式给 --allow-public-key
msfile-webrtc-lab relay     Circuit Relay v2 信令基础设施（只承载 reservation/SDP/ICE）
```

## 版本锁定

| 依赖 | 版本 |
|---|---|
| Go | 1.25.x（go.mod 要求 >= 1.25） |
| go-libp2p | v0.49.0 |
| modernc.org/sqlite | v1.57.0（纯 Go 驱动） |
| fsnotify | v1.9.0 |
| gopkg.in/yaml.v3 | v3.0.1 |
| benbjohnson/clock | v1.3.5（测试注入时钟） |

版本均锁定在 `go.mod`；交付不允许使用未锁定的分支或本地 replace。

## 进程级冒烟与人工验收

`internal/nas/process_e2e_test.go`（TestProcessLevelSmokeOnLocalDirectory）
用真实二进制 + YAML 在本地目录跑通“启动→首次扫描→WS 读取逐块校验→SIGTERM→nas_data 零写入”。
目标 NAS 挂载类型的人工验证按
[docs/施工单/20260825-3-NAS挂载人工验收清单.md](../../docs/施工单/20260825-3-NAS挂载人工验收清单.md) 执行并留存证据。

## 开发与验收

```bash
cd labs/webrtc-go
go test ./...          # 自动化测试矩阵（见下）
go test -race ./...    # 并发与竞争检查
go vet ./...
go build ./cmd/msfile-nas
go build ./cmd/msfile-webrtc-lab
```

### 自动化覆盖对照（施工单 T01–T28）

| 编号 | 状态 | 位置 |
|---|---|---|
| T01–T02 | ✅ | internal/config、internal/auth |
| T03–T04 | ✅ | internal/seed |
| T05–T15、T28 | ✅ | internal/library（fake clock / 事件注入 / GC 守卫） |
| T14、T16–T17 | ✅ | internal/content（多副本回退与完整性 fail closed） |
| T18 | ✅ | internal/indexdb（并发串行化 + `-race`） |
| T19–T21、T22、T23 | ✅ | internal/msfile（CBOR 严格性 / 双 stream / WS、WSS、WebRTC Direct E2E） |
| T24 | ✅ | internal/admin |
| T25–T26 | ✅ | internal/nas（第二实例锁、旧 schema fail closed、端口冲突回滚） |
| T27 | ✅ 自动化部分：在途请求双层硬上限、全局/单连接带宽令牌桶（三场景）、多连接并发冲击断言峰值不超限；真实磁盘吞吐压测归入部署人工验证 |

目标 NAS 挂载的人工验证仍按施工单 §10 在真实部署环境执行。
