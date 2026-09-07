# MSFile Proxy Protocol

MSFile Proxy Protocol 是 Keymaster、Keymaster Connect App 与内容寻址文件代理之间的
公开文件服务协议。

文件使用 MasterSeed V1 `seed_hash` 寻址。一个 Proxy 可以是 Keymaster 内置静态文件源、
只读个人 NAS，也可以是能够发现报价、远程取得文件并缓存文件块的 BitFSProxy。所有实现
向调用方提供 `stat`、`read` 两个命令（V1 已删除 `acquire`）。

网络采用 libp2p，同时支持 WebRTC Direct、WS 和 WSS。Circuit Relay 不得承载 MSFile
报文或文件块。节点使用与业务身份相同的 secp256k1 私钥建立 libp2p 身份，
授权判断只使用连接层认证出的压缩公钥。

控制报文使用 deterministic CBOR；Seed 和文件块作为原始二进制 attachment 传输，不使用
JSON、Base64 或十六进制包装。

## 协议文档

- [MSFile Proxy Network Protocol v1](./docs/protocol/network.zh.md)
- [MSFile Proxy Wire Messages v1](./docs/protocol/wire-messages.zh.md)

## Go NAS 服务（V1 正式形态）

`labs/webrtc-go/cmd/msfile-nas` 是按 [MSFile NAS V1 需求冻结](./docs/施工单/20260825-1-MSFile-NAS-V1需求冻结.md)
一次性硬切换实现的正式 NAS 服务：

- **双数据区**：`nas_data` 是用户原文件的唯一真值，服务只读、绝不改变目录布局；
  `seed_data` 保存 Seed、SQLite 索引与临时状态，整库删除后可从 `nas_data` 完全重建；
- **同步**：fsnotify 文件事件快速发现 + 周期全量扫描最终收敛 + stat A/B/C 稳定性检测；
  文件不可见保留 24 小时，期内同指纹恢复不重算；
- **读取**：Seed 从 `.seed` 文件返回；块按偏移直接读原文件并逐块 SHA-256 校验，
  完整性失败 fail closed；
- **授权**：`access_mode: private` 使用配置文件公钥白名单（空白名单拒绝全部），
  `public` 放行任意已认证 secp256k1 客户端并实施全局资源限额；
- **传输**：libp2p WebRTC Direct + WS/WSS 承载正式 `/msfile/1.0.0`；普通 Web 与 WS/WSS 共用同一
  TCP 入口，公网 WSS multiaddr 由 NAS Web 页面使用当前浏览器 URL 生成；
- **公网地址**：`webrtc_direct_public_addresses` 只配置公网 UDP 基础地址，服务运行时补齐
  `certhash` 与 PeerId；不配置 WSS 公网地址字段；
- **存储**：SQLite 由单个异步执行器独占（MaxOpenConns=1），业务代码无法绕过；
- **Web**：仅 `access_mode: public` 开放中文平面 Hash 公共内容索引，支持按文件名/Hash 搜索、详情查看与按文件名下载；`private`/`public_key_whitelist` 白名单模式隐藏并拒绝这些 Web 内容接口；不提供原文件写操作。

配置示例（全字段中文注释）：[labs/webrtc-go/config/msfile-nas.example.yaml](./labs/webrtc-go/config/msfile-nas.example.yaml)。
构建、启动、切换与回滚见 [Go NAS 服务运行手册](./docs/nas-service.zh.md)。

## 需求与施工文档

- [MSFile NAS V1 需求冻结](./docs/施工单/20260825-1-MSFile-NAS-V1需求冻结.md) — 产品需求真值
- [MSFile NAS V1 硬切换施工单](./docs/施工单/20260825-2-MSFile-NAS-V1硬切换施工单.md) — 施工范围与验收矩阵
- [libp2p WebRTC 与同钥身份互通实验](./施工单/20260824/1-libp2p-webrtc与同钥身份互通实验施工单.md)

## 实验代码

- [labs/webrtc-web](./labs/webrtc-web/) — TypeScript + js-libp2p HTTPS 静态网站
  （direct-dialer / private-listener / private-dialer）
- [labs/webrtc-go](./labs/webrtc-go/) — Go 正式 NAS 与互通实验
  （`msfile-nas --config ...` / `msfile-webrtc-lab genkey|labnas|relay`）
- [WebRTC 互联实验报告](./docs/labs/webrtc-interop-report.zh.md) — Gate 0 版本审计与
  T01–T14 矩阵证据
