# MSFile Proxy Wire Messages v1

> 状态：V1 报文设计真值。
>
> 本文只定义 MSFile 的 stream 模型、二进制 framing、deterministic CBOR 报文、
> `stat`、`acquire`、`read` 三个命令、状态、幂等和内容验证。节点发现、WebRTC 建连、
> Relay 边界、私钥身份和公钥白名单见
> [MSFile Proxy Network Protocol v1](./network.zh.md)。

---

## 1. 设计结论

MSFile V1 统一规定：

1. libp2p protocol ID 是 `/msfile/1.0.0`；
2. 一条 libp2p stream 恰好承载一个请求和一个响应，响应完成后关闭 stream；
3. 物理 WebRTC connection 可以同时复用多条 MSFile stream；
4. `stat` 和 `read` 没有 `request_id`，stream 本身就是请求—响应关联标识；
5. `acquire` 携带 16 字节 `idempotency_key`，它是业务幂等键，不是传输 request ID；
6. 控制 Header 使用 RFC 8949 deterministic CBOR fixed array；
7. Seed 和文件块使用 raw attachment，不进入 CBOR，不使用 JSON、Base64 或 hex；
8. decoder 不依赖 RTCDataChannel 消息边界，必须按本文长度字段从 stream 读取；
9. 文件唯一内容地址是 MasterSeed V1 `seed_hash`；
10. `stat(discover=false)` 只返回 `available` 或 `absent`；
11. `available` 和 `quoted` 必须携带完整且已验证的 Seed；
12. `absent` 和 `discovering` 不携带文件详情或 Seed；
13. `read` 按 256 KiB 块编号随机读取，支持跳跃播放；
14. BitFSProxy 的发现、报价请求、购买和缓存频率由 Proxy 自主管理，不由 Stat 轮询驱动；
15. 连接身份来自 libp2p 已认证公钥，报文不重复携带公钥或 API Key。

MSFile 是 Keymaster 到已配置 Proxy 的文件服务协议，不是 BitFS 买卖双方 wire 的替代品。

---

## 2. 为什么 V1 不需要通用 Request ID

WebRTC DataChannel 支持多路 libp2p stream。V1 使用如下模型：

```text
WebRTC Connection
  ├── Stream A: StatRequest    -> StatResponse
  ├── Stream B: ReadRequest 12 -> ReadResponse 12
  ├── Stream C: ReadRequest 13 -> ReadResponse 13
  └── Stream D: AcquireRequest -> AcquireResponse
```

每条 stream 只有一个请求者和一个响应者，响应不能跑到另一条 stream，因此：

- 同时读取多个块时，每个块使用独立 stream；
- 某条 stream 超时、Reset 或关闭，不影响其他请求的关联；
- 不需要在报文中再维护一套 `request_id -> waiter` 映射；
- 不存在同一 stream 内响应乱序问题。

只有未来允许“一条 stream 内流水化多个并发请求且响应可以乱序”时，才需要引入通用
`request_id`。该变化属于新的 wire 版本，V1 实现不得自行扩展。

`idempotency_key` 解决的是另一件事：Acquire 可能产生购买副作用。如果连接在 Proxy 已经
接受请求后断开，调用方必须用相同幂等键在新 stream 上重试，避免重复购买。

---

## 3. Stream 生命周期

请求方按以下顺序操作：

1. 在已经通过 Network Protocol `direct_ready` 检查的具体 connection 上打开
   `/msfile/1.0.0` stream；
2. 写入一个完整 Request Frame；
3. 不再向该 stream 写入第二个请求；
4. 读取一个完整 Response Frame；
5. 验证 Header、attachment 和业务内容；
6. 正常关闭 stream。

响应方按以下顺序操作：

1. 读取一个完整 Request Frame；
2. 严格解码并执行身份、权限、尺寸和业务检查；
3. 写入对应的成功 Response 或 ErrorResponse；
4. 不再写入第二个响应；
5. 正常关闭 stream。

如果一方在完整 Frame 后继续发送额外字节，接收方必须 Reset stream。连接可以保留，除非
实现的滥用策略决定关闭整个 connection。

以下事件只作用于当前请求：

- stream Reset；
- stream EOF 早于声明长度；
- Header 超长；
- attachment 长度不符；
- CBOR 或业务校验失败。

不得把上述事件映射成业务 `absent`。

---

## 4. Frame 外形

每个请求和响应都是一个 Frame：

```text
frame = header_length_uvarint || header_cbor || attachment
```

### 4.1 `header_length_uvarint`

- 使用 unsigned LEB128 / protobuf-style uvarint；
- 必须使用最短编码；
- 最大 3 字节；
- 值必须在 `1..65536`；
- 超长、溢出、非最短编码或值为 0 均为 framing error。

### 4.2 `header_cbor`

- 必须是 RFC 8949 deterministic CBOR；
- 顶层必须是 definite-length array；
- 禁止 indefinite-length item；
- 整数必须使用最短编码；
- map 不用于 V1 wire；
- text string 必须是合法 UTF-8；
- 未声明字段、额外数组元素和错误分支长度一律拒绝。

### 4.3 `attachment`

- attachment 是紧跟 Header 的原始字节；
- 其长度由对应 Header 的 `attachment_length` 字段唯一确定；
- 没有 attachment 的消息其长度隐含为 0，不增加占位字段；
- decoder 必须先校验 Header 和声明长度上限，再分配或读取 attachment；
- decoder 不得依赖一次 stream read、一次 RTCDataChannel message 或一个 JS event 对应一个
  Frame。

### 4.4 固定上限

```text
MAX_HEADER_BYTES       = 65536
MAX_SEED_BYTES         = 16777216
MAX_BLOCK_BYTES        = 262144
MAX_ERROR_MESSAGE_BYTES = 1024
```

V1 不允许压缩 Header、Seed 或块。传输层可以执行自己的拥塞控制，但不能改变 wire 字节。

---

## 5. MasterSeed 文件模型

### 5.1 常量

```text
MASTERSEED_FORMAT     = keymaster-seed-v1
BLOCK_SIZE_BYTES      = 262144
DIGEST_SIZE_BYTES     = 32
HASH_ALGORITHM        = SHA-256
MAX_SEED_BYTES        = 16777216
MAX_SOURCE_FILE_BYTES = 137438953472
```

### 5.2 SeedHash

wire 中的 `seed_hash` 是固定 32 字节 CBOR bstr：

```text
seed_hash = SHA-256(seed_bytes)
```

它不是源文件完整字节的 SHA-256。展示层可以转成 64 个小写 hex 字符，但 hex 不是 wire
格式。

### 5.3 Seed 内容

```text
seed_bytes =
  block_hash[0] || block_hash[1] || ... || block_hash[n-1]

block_hash[i] = SHA-256(source_block[i])
```

每个块哈希是 32 字节原始 SHA-256。Seed 通过 Stat 成功响应的 raw attachment 传输。

### 5.4 文件尺寸与块数量

```text
file_size_bytes = 0:
  block_count = 0

file_size_bytes > 0:
  block_count = floor((file_size_bytes - 1) / 262144) + 1

len(seed_bytes) = block_count * 32
```

空文件合法，对应零字节 Seed 和 SHA-256 空输入的 SeedHash。

---

## 6. Wire Kind 注册表

所有 Header 前两个元素固定为：

```text
[wire_version, wire_kind, ...]
```

V1 的 `wire_version` 固定为 `1`。

| Kind | 名称 | 方向 | Attachment |
|---:|---|---|---|
| 1 | `StatRequest` | Client -> Proxy | 无 |
| 2 | `StatResponse` | Proxy -> Client | `available/quoted` 为 Seed |
| 3 | `AcquireRequest` | Client -> Proxy | 无 |
| 4 | `AcquireResponse` | Proxy -> Client | 无 |
| 5 | `ReadRequest` | Client -> Proxy | 无 |
| 6 | `ReadResponse` | Proxy -> Client | `available` 为文件块 |
| 255 | `ErrorResponse` | Proxy -> Client | 无 |

请求 Kind 决定本 stream 的唯一合法成功响应：

```text
1 -> 2
3 -> 4
5 -> 6
any request -> 255
```

收到其他 Kind、收到 Response 作为首帧、或收到第二个 Frame 都必须 Reset stream。

---

## 7. 通用字段类型

### 7.1 整数

- 所有金额、时间、尺寸和索引都是 CBOR unsigned integer；
- V1 最大值是 `2^64 - 1`，具体字段可以有更小上限；
- 禁止负数、浮点数、tagged bignum 和 text number。

### 7.2 标识符

```text
idempotency_key : 16-byte bstr
quote_id        : 32-byte bstr
acquisition_id  : 32-byte bstr
```

- `idempotency_key` 由调用方用密码学安全随机数生成；
- `quote_id` 和 `acquisition_id` 由 Proxy 生成；
- 三者在展示或配置中可以编码为小写 hex，但 wire 上只允许 bstr；
- ID 只在签发它的 Proxy 和已经认证的客户端公钥之间有意义；
- ID 不得用作 libp2p PeerId、公钥、SeedHash 或文件块哈希。

### 7.3 文件名

`recommended_filename` 是 UTF-8 text string，可以为空。非空时必须：

- 是单个 basename；
- 不含 `/`、`\\`、NUL 和控制字符；
- 不是 `.` 或 `..`；
- UTF-8 编码不超过 255 字节；
- 不包含 Proxy 本机路径。

调用方不能直接把建议文件名拼接成本地路径。

### 7.4 Media Type

`media_type` 是 UTF-8 text string，可以为空。非空时必须是不含控制字符、长度不超过
255 字节的 ASCII MIME media type。它只用于展示和播放提示。

### 7.5 Retry After

`retry_after_ms` 是 `0..3600000` 的 unsigned integer。它只是建议调用方下一次轮询的
最短等待时间，不控制 Proxy 的远端发现或购买频率。

---

## 8. Stat

### 8.1 StatRequest（Kind 1）

```text
[1, 1,
  seed_hash,
  discover
]
```

字段：

| Index | 字段 | 类型 | 约束 |
|---:|---|---|---|
| 0 | `wire_version` | uint | 固定 `1` |
| 1 | `wire_kind` | uint | 固定 `1` |
| 2 | `seed_hash` | bstr | 固定 32 字节 |
| 3 | `discover` | bool | 是否允许建立发现意图 |

StatRequest 没有 attachment，也没有 `request_id`。

### 8.2 状态值

```text
1 = available
2 = absent
3 = discovering
4 = quoted
```

### 8.3 Available StatResponse

```text
[1, 2,
  1,
  recommended_filename,
  file_size_bytes,
  media_type,
  seed_length
]
|| seed_bytes
```

`seed_length` 必须等于 attachment 长度，且不得超过 16 MiB。

`available` 的唯一含义是 Proxy 当前拥有全部文件块，并已经验证：

```text
SHA-256(seed_bytes) == request.seed_hash
```

以及 Seed 中所有块哈希与本地完整文件一致。

### 8.4 Absent StatResponse

```text
[1, 2,
  2
]
```

没有 attachment。`absent` 不携带文件名、尺寸、类型、Seed、报价或占位信息。

### 8.5 Discovering StatResponse

```text
[1, 2,
  3,
  retry_after_ms
]
```

没有 attachment。`discovering` 不携带文件详情。

### 8.6 Quoted StatResponse

```text
[1, 2,
  4,
  recommended_filename,
  file_size_bytes,
  media_type,
  seed_length,
  quote_id,
  seed_price_satoshis,
  full_block_price_satoshis,
  expires_at_unix_seconds
]
|| seed_bytes
```

Proxy 只有取得并验证完整 Seed 后才能进入 `quoted`。`quote_id` 必须在服务端不可变地
绑定到：

- 已认证客户端压缩公钥；
- SeedHash；
- 文件详情和完整 Seed；
- Seed 价格与完整块价格；
- 过期时间。

客户端不解析 `quote_id`，也不接触 BitFSProxy 内部 Seller 报价对象。

### 8.7 `discover=false`

只允许返回：

- `available`：Proxy 当前拥有完整且验证过的文件；
- `absent`：Proxy 当前没有完整文件。

即使 Proxy 内部已经发现中、有报价、正在购买或缓存部分文件块，只要完整文件没有就绪，
本请求一律返回 `absent`。

`stat(false)` 不建立、刷新、重试、取消或暴露任何发现和购买任务。

### 8.8 `discover=true`

Proxy 按以下优先级返回：

```text
available > quoted > discovering > absent
```

第一次请求可以建立按 `client_public_key + seed_hash` 去重的发现意图。重复请求：

- 复用已有发现意图；
- 不一对一发布远端请求；
- 不改变 BitFSProxy 自己的广播、退避和重试频率；
- 不刷新发现任务 TTL；
- 只返回当前状态投影。

---

## 9. Acquire

### 9.1 AcquireRequest（Kind 3）

```text
[1, 3,
  idempotency_key,
  seed_hash,
  quote_id,
  max_seed_price_satoshis,
  max_full_block_price_satoshis,
  max_total_price_satoshis
]
```

AcquireRequest 没有 attachment。

Proxy 必须在接受前验证：

1. 当前连接公钥在允许 Acquire 的白名单策略中；
2. 报价由本 Proxy 发出并绑定当前连接公钥；
3. 报价 SeedHash 与请求一致；
4. 报价尚未过期；
5. Seed 和块价格不超过对应上限；
6. acquisition 累计支出不得超过总预算；
7. 同一客户端公钥下该幂等键未绑定另一份不同请求。

`max_total_price_satoshis = 0` 表示不授权任何付费动作，不表示无限预算。免费报价仍可接受。

### 9.2 AcquireResponse（Kind 4）

```text
[1, 4,
  acquisition_id
]
```

没有 attachment。`acquisition_id` 必须绑定：

- 当前客户端压缩公钥；
- SeedHash；
- 已接受报价；
- 三个预算上限。

Acquire 成功只表示 Proxy 已经接受报价和预算，不表示完整文件或任意块已经就绪，也不表示
已经发生付款。

### 9.3 幂等规则

同一已认证客户端公钥使用相同 `idempotency_key`：

- exact 请求重试：返回第一次持久化的相同成功或 ErrorResponse；
- 请求字段不同：返回 `idempotency_conflict`；
- stream Reset、连接断开或超时时：调用方必须使用原键重试；
- 调用方不得因为没有收到响应就生成新键；
- Proxy 必须在执行任何可能付款的动作前持久化幂等状态。

V1 不要求 AcquireRequest 再做一层业务签名。当前连接已经通过同一业务 secp256k1 私钥的
libp2p Noise 身份认证。需要离线不可否认证据的购买系统可以在未来版本增加签名文档，但不
得作为 V1 的隐式可选字段。

---

## 10. Read

### 10.1 Read Mode

```text
0 = local_only
1 = acquisition
```

### 10.2 本地 ReadRequest（Kind 5）

```text
[1, 5,
  seed_hash,
  block_index,
  0
]
```

只读取 Proxy 当前已经验证的块，绝不建立发现、接受报价或触发远程购买。

### 10.3 Acquisition ReadRequest（Kind 5）

```text
[1, 5,
  seed_hash,
  block_index,
  1,
  acquisition_id
]
```

Proxy 必须验证 acquisition 绑定当前连接公钥和 SeedHash。未缓存时可以把目标块提升为
远程取得优先级，但相同 acquisition、SeedHash、块编号的并发请求必须合并，不能重复购买。

ReadRequest 没有 attachment，也没有 `request_id`。每个并发块请求使用独立 stream。

### 10.4 Read 状态值

```text
1 = available
2 = pending
3 = unavailable
```

### 10.5 块已就绪

```text
[1, 6,
  1,
  block_index,
  block_length
]
|| block_bytes
```

`block_length` 必须等于 attachment 长度且不得超过 262144。响应中的 `block_index` 必须与
请求相同。

调用方必须已经保存并验证对应 Seed，然后计算：

```text
expected_block_hash =
  seed_bytes[block_index * 32 : block_index * 32 + 32]

SHA-256(block_bytes) == expected_block_hash
```

除最后一块外，块长度必须恰为 262144。最后一块长度由文件尺寸计算。校验成功前，调用方
不得把字节交给播放器、插件或 Connect App。

### 10.6 块正在获取

```text
[1, 6,
  2,
  block_index,
  retry_after_ms
]
```

没有 attachment。调用方等待建议时间后，在新 stream 上重复同一个 ReadRequest。重复读取
不得重复购买。

### 10.7 块不可用

```text
[1, 6,
  3,
  block_index
]
```

没有 attachment。`local_only` 下没有当前块时返回该状态。它是正常业务结果，不是
ErrorResponse。

### 10.8 块编号与随机读取

`block_index` 从 0 开始。空文件没有合法块编号。需求方可以任意顺序和并发读取：

```text
0, 1, 2, 836, 837, 400, 401
```

媒体播放器把文件偏移换算为：

```text
block_index     = floor(file_offset / 262144)
offset_in_block = file_offset mod 262144
```

Proxy 不得要求从文件开头顺序读取到目标位置。

---

## 11. ErrorResponse（Kind 255）

任何请求都可以返回：

```text
[1, 255,
  error_code,
  error_message,
  retry_after_ms
]
```

字段：

- `error_code`：本文注册的小写 ASCII text string，最多 64 字节；
- `error_message`：诊断用 UTF-8 text string，最多 1024 字节，可以为空；
- `retry_after_ms`：`0` 表示没有重试建议。

调用方只能依赖 `error_code`。`error_message` 不得包含私钥、完整公钥白名单、本机路径、
BitFS Seller 私密信息、交易原文或内部堆栈。

| Error Code | 含义 |
|---|---|
| `bad_request` | CBOR、字段、类型或范围错误 |
| `invalid_seed_hash` | SeedHash 长度或值不合法 |
| `unauthorized_peer` | 连接公钥不在白名单或没有当前命令权限 |
| `direct_connection_required` | MSFile 被错误地尝试运行在间接或受限连接上 |
| `quote_not_found` | 本 Proxy 找不到报价 |
| `quote_expired` | 报价已经过期 |
| `price_limit_exceeded` | 报价或累计支出超过上限 |
| `idempotency_conflict` | 同一幂等键绑定了不同 AcquireRequest |
| `acquisition_not_found` | acquisition 不存在或不属于当前连接公钥 |
| `acquisition_expired` | acquisition 已失效 |
| `block_out_of_range` | 块编号超出可信 Seed 范围 |
| `integrity_error` | Seed、块哈希或长度验证失败 |
| `rate_limited` | 超过 Proxy 调用或并发策略 |
| `unsupported_version` | 不支持 wire version |
| `internal_error` | Proxy 内部错误 |

连接建立失败、ICE 失败、stream Reset 和超时属于 Transport 错误，不编码为 ErrorResponse，
也不能映射成 `absent` 或 `unavailable`。

---

## 12. Stat 状态矩阵

| 请求 | 完整文件 | 部分缓存 | 发现中 | 有有效报价 | 完全没有 |
|---|---|---|---|---|---|
| `discover=false` | `available` + Seed | `absent` | `absent` | `absent` | `absent` |
| `discover=true` | `available` + Seed | 按发现真值 | `discovering` | `quoted` + Seed + quote | `discovering` 或 `absent` |

最后一格取决于 Proxy 能力和策略：只读 NAS 返回 `absent`；能够并愿意发现的 BitFSProxy
建立去重发现意图并返回 `discovering`。

---

## 13. 端到端验证

### 13.1 Available / Quoted

客户端必须按固定顺序：

1. 验证 Frame 长度和 Header CBOR；
2. 验证响应 Kind 与当前请求匹配；
3. 验证状态分支的固定数组长度；
4. 按 `seed_length` 读取 exact attachment；
5. 验证 Seed 长度是 32 的整数倍且不超过 16 MiB；
6. 验证 `SHA-256(seed_bytes) == request.seed_hash`；
7. 根据文件尺寸计算块数量并与 Seed 哈希数量比较；
8. `quoted` 再验证报价、价格和过期时间；
9. 全部成功后才保存文件详情与 Seed。

任何失败都拒绝整个响应，不能降级为 `absent`。

### 13.2 Read

客户端必须：

1. 已经保存同一 SeedHash 的已验证 Seed 和文件尺寸；
2. 在发送前检查块编号范围；
3. 验证响应块编号与请求一致；
4. 验证声明长度、实际长度及最后块长度；
5. 自己计算块 SHA-256；
6. 与 Seed 中对应摘要比较；
7. 成功后才交付给上层。

知道 SeedHash 但没有可信 Seed 时，无法验证随机文件块，不能执行 Read。

---

## 14. 背压、并发与取消

- 实现必须尊重 libp2p stream 和 RTCDataChannel 的背压；
- 逻辑块是 256 KiB，不表示可以一次 `send()` 256 KiB；
- encoder 必须按当前 transport 的安全 `maxMessageSize` 主动把连续 Frame 字节切成多个
  stream write，V1 建议每片不超过 16 KiB；
- 实现不能假定 libp2p 或 RTCDataChannel 会自动把超大 `send()` 安全分片；
- attachment 在 wire 上仍是连续 exact bytes，分片对 decoder 不可见；
- 调用方可以并发打开多条 Read stream，但 Proxy 可以设置每公钥、每 connection 和全局上限；
- 超过上限返回 `rate_limited`，不得静默转到 Relay；
- 取消单个 Read 通过 Reset 对应 stream 实现；
- 一个等待者取消不得取消其他客户端或其他 stream 共享的底层块获取任务；
- 连接断开后，上层可以在重新形成 `direct_ready` connection 后按块重试。

---

## 15. 标准流程

### 15.1 静态文件或 NAS

```text
Stream A:
  StatRequest(seed_hash, false)
  -> available Header + raw seed attachment

客户端验证 Seed

Stream B:
  ReadRequest(seed_hash, block=0, local_only)
  -> available Header + raw block attachment

客户端验证块
```

### 15.2 BitFSProxy 发现报价

```text
Stream A: StatRequest(seed_hash, true) -> discovering

// Proxy 按自己的频率发现；Stat 轮询不驱动远端请求

Stream B: StatRequest(seed_hash, true) -> quoted + Seed + quote
```

### 15.3 报价后跳跃播放

```text
Stream A: AcquireRequest(idempotency_key, quote...) -> acquisition_id
Stream B: ReadRequest(block=0, acquisition_id)      -> available + block 0
Stream C: ReadRequest(block=836, acquisition_id)    -> pending
Stream D: ReadRequest(block=836, acquisition_id)    -> available + block 836
```

播放器不需要先下载块 `1..835`。

---

## 16. 明确不属于 V1 的能力

V1 不定义：

- 同一 stream 内多个请求或乱序响应；
- 通用 `request_id`；
- JSON、Base64、HTTP endpoint 或 API Key；
- TURN 或通过 Circuit Relay 承载业务报文；
- 每个 Stat/Read 的业务签名；
- list、put、delete、rename 和目录操作；
- 文件上传、NAS 导入和价格设置；
- 任意 Byte Range；调用方在 256 KiB 块内自行切片；
- BitFS Seller、费用池、付款、仲裁和交易报文；
- 缓存目录、淘汰算法和后台补全顺序；
- Connect SDK 的 App 权限和用户确认 UI；
- 压缩、批量 Read 或一条 stream 连续推送视频。

上述能力如需进入 wire，必须提升协议版本，不能通过额外数组元素或猜测 optional 字段兼容。

---

## 17. 验收范围

实现至少覆盖：

- 多条并发 stream 的响应不串线；
- 一条 stream 第二个请求或响应被拒绝；
- uvarint 非最短、溢出、Header 超限和 attachment 截断；
- 非 deterministic CBOR、indefinite item、额外数组元素和错误分支；
- `stat(false)` 屏蔽 discovering、quoted、部分缓存和购买状态；
- 重复 `stat(true)` 不产生等量远端请求且不刷新任务 TTL；
- `absent/discovering` 携带 attachment 被拒绝；
- `available/quoted` 缺 Seed、SeedHash 错误和尺寸不匹配被拒绝；
- Acquire stream 断开后同幂等键重试不重复购买；
- 同幂等键不同请求返回冲突；
- Read 随机跳块、pending、并发同块合并；
- 越界块、错误块、错误响应块编号和最后块长度被拒绝；
- stream/connection 错误与业务 `absent/unavailable` 严格区分；
- 大块发送遵守背压且内存使用不随并发无限增长。

---

## 参考规范

- [MasterSeed / Keymaster Seed V1](https://github.com/bsv8/MasterSeed)
- [RFC 8949 · CBOR](https://www.rfc-editor.org/rfc/rfc8949)
- [Protocol Buffers · Base 128 Varints](https://protobuf.dev/programming-guides/encoding/#varints)
- [libp2p Streams](https://docs.libp2p.io/concepts/multiplex/overview/)
