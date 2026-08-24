# MSFile Proxy Protocol

MSFile Proxy Protocol 是 Keymaster、Keymaster Connect App 与内容寻址文件代理之间的
公开文件服务协议。

文件使用 MasterSeed V1 `seed_hash` 寻址。一个 Proxy 可以是 Keymaster 内置静态文件源、
只读个人 NAS，也可以是能够发现报价、远程取得文件并缓存文件块的 BitFSProxy。所有实现
向调用方提供 `stat`、`acquire`、`read` 三个命令。

网络采用 libp2p over WebRTC，支持 WebRTC Direct 和借助 Circuit Relay 交换 SDP/ICE 后的
WebRTC 直连。Circuit Relay 不得承载 MSFile 报文或文件块。节点使用与业务身份相同的
secp256k1 私钥建立 libp2p 身份，Proxy 按连接层认证出的压缩公钥执行白名单授权。

控制报文使用 deterministic CBOR；Seed 和文件块作为原始二进制 attachment 传输，不使用
JSON、Base64 或十六进制包装。

## 协议文档

- [MSFile Proxy Network Protocol v1](./docs/protocol/network.zh.md)
- [MSFile Proxy Wire Messages v1](./docs/protocol/wire-messages.zh.md)

## 实验施工单

- [libp2p WebRTC 与同钥身份互通实验](./施工单/20260824/1-libp2p-webrtc与同钥身份互通实验施工单.md)

## 实验代码

- [labs/webrtc-web](./labs/webrtc-web/) — TypeScript + js-libp2p HTTPS 静态网站
  （direct-dialer / private-listener / private-dialer）
- [labs/webrtc-go](./labs/webrtc-go/) — Go NAS / Relay 实验服务
  （`msfile-webrtc-lab nas|relay`）
- [WebRTC 互联实验报告](./docs/labs/webrtc-interop-report.zh.md) — Gate 0 版本审计与
  T01–T14 矩阵证据
