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
2. WebRTC Direct、WS、WSS：libp2p transport；
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

## 5. Web 公共内容索引

默认监听 loopback。公共页面只使用以下接口，接口不要求 Bearer Token：

```text
GET  /api/files                              当前有效内容列表（支持前缀 Hash/文件名搜索）
GET  /api/files/{seed_hash}                  文件详情与下载地址
GET  /api/files/{seed_hash}/download         按索引 filename 下载原文件
```

列表只返回 `ready` 且至少有一个 `valid` 文件位置的内容；公共详情不暴露 NAS 内部路径。
其余方法返回中文 `405`；不存在白名单 CRUD 或原文件写路由。

为兼容已有脚本，`GET /api/status`、`GET /api/scans`、`POST /api/scans` 仍保留，
但不出现在公共页面，且继续要求 `admin_token`（Bearer）。`access_mode=public`
不会改变这些兼容运维接口的认证要求。

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

# 兼容运维接口：手动触发全量扫描（公共页面不提供此按钮）
curl -s -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/scans

# 从零重建索引（确认 nas_data 无需变更后）
systemctl stop msfile-nas
mv /var/lib/msfile-nas /var/lib/msfile-nas.bak-$(date +%F)
systemctl start msfile-nas   # 新空 seed_data 自动重建
```
