# MSFile Proxy Wire Messages v1

> 状态：V1 报文设计真值。
>
> 本文定义 MSFile 的 libp2p stream 使用方式、二进制 Frame、deterministic CBOR 报文、
> `stat`、`read`、请求覆盖、取消和内容校验。节点身份、transport、供应商调度和连接生命周期见
> [MSFile Proxy Network Protocol v1](./network.zh.md)。

---

## 1. 设计结论

MSFile V1 统一规定：

1. libp2p protocol ID 是 `/msfile/1.0.0`；
2. 每个已认证供应商 connection 最多保留一条 Stat stream 和一条 Read stream；
3. 一条 stream 可以连续承载多个请求和响应，且两个方向可以同时读写；
4. 同一方向的 Frame 必须完整串行写入，不允许交叉写入两个 Frame；
5. Stat 与 Read 使用不同 stream，避免大块内容阻塞频繁状态查询；
6. StatResponse 和 ReadResponse 可以不按请求顺序返回，使用递增的 request ID 关联；
7. `stat` 可以反复查询同一 `seed_hash`，不传输 Seed 内容；
8. `read` 按内容哈希读取 Seed 或文件块，同时表达本次内容购买的最高价格授权；
9. 不再定义 `Acquire`、`quote_id`、`acquisition_id`、`priority` 或额外幂等键；
10. Header 使用 RFC 8949 deterministic CBOR fixed array；
11. 内容使用 raw attachment，不进入 CBOR，不使用 JSON、Base64 或 hex；
12. 客户端以 `SHA-256(content_bytes) == content_hash` 验证所有返回内容；
13. 连接身份来自 libp2p 已认证远端公钥，报文不重复携带客户端或供应商身份。

MSFile 是 Keymaster 到已配置供应商的文件服务协议，不是供应商内部发现、付款和结算协议。

---

## 2. Stream 模型

### 2.1 两条长驻 stream

每个供应商 connection 使用：

```text
Authenticated libp2p Connection
  ├── Stat stream: StatRequest* -> StatResponse* / ErrorResponse*
  └── Read stream: ReadRequest* -> ReadResponse* / ReadCancelled* / ErrorResponse*
```

- Stat stream 在连接可用后建立并长期复用；
- Read stream 可以延迟到第一次 Read 时建立并长期复用；
- 两条 stream 都协商 `/msfile/1.0.0`；
- 客户端打开 stream，供应商只接受，不反向创建 MSFile stream；
- stream 收到的第一个 Request Kind 锁定其角色：Kind 1 为 Stat，Kind 3 为 Read；
- 角色锁定后出现另一类 Request Kind 属于 `wrong_stream_role`；
- 正常空闲不关闭 stream；连接关闭、stream Reset 或协议错误后按需重建。

V1 不为每次 Stat 或 Read 新建 stream，也不把 Stat 和 Read 混入同一条 stream。

### 2.2 全双工与乱序

libp2p stream 是可靠、有序、双向的字节流。客户端可以继续发送请求，同时供应商发送之前请求
的响应。供应商可以并发执行多个请求，并按完成顺序把完整响应 Frame 加入单一写队列：

```text
Client -> Supplier: Read(101, hash_A), Read(102, hash_B), Read(103, hash_A)
Supplier -> Client: ReadResponse(103), ReadCancelled(101, replaced_by=103), ReadResponse(102)
```

“响应可以乱序”不表示字节可以乱序。每个方向只能有一个 Frame writer；一个带 attachment 的
ReadResponse 开始写入后，必须写完该 Header 和全部 `content_bytes`，才能写下一个 Frame。

### 2.3 request ID 作用域

```text
stat_request_id : uint64
read_request_id : uint64
```

- 两个计数器彼此独立；
- 客户端在当前已认证 libp2p connection 内分别单调递增；
- stream 重建但 connection 未变时不得倒退；
- 新 connection 可以重新从 `1` 开始；
- `0` 不作为客户端生成的 request ID；
- 达到 `2^64 - 1` 后必须重建 connection，禁止回绕；
- request ID 只关联请求，不是公钥、内容 ID 或付款凭证。

同一 stream 的请求字节本身有序，因此供应商可以在解码入口检查序号。重复或倒退且不属于本文
定义的“已被新请求覆盖”的报文返回 `stale_request_id`。

---

## 3. Frame 外形

每条消息都是一个 Frame：

```text
frame = header_length_uvarint || header_cbor || attachment
```

### 3.1 `header_length_uvarint`

- 使用 unsigned LEB128 / protobuf-style uvarint；
- 必须使用最短编码；
- 最大 3 字节；
- 值必须在 `1..65536`；
- 超长、溢出、非最短编码或值为 0 均为 framing error。

### 3.2 `header_cbor`

- 必须是 RFC 8949 deterministic CBOR；
- 顶层必须是 definite-length array；
- 禁止 indefinite-length item；
- 整数必须使用最短编码；
- V1 Header 不使用 map；
- text string 必须是合法 UTF-8；
- 未声明字段、额外数组元素和错误分支长度一律拒绝。

所有 Header 前两个元素固定为：

```text
[wire_version, wire_kind, ...]
```

V1 的 `wire_version` 固定为 `1`。

### 3.3 `attachment`

- attachment 是紧跟 Header 的原始字节，不在 CBOR 内；
- V1 只有成功的 ReadResponse 携带 attachment；
- `content_length` 唯一确定 attachment 的字节数和下一个 Frame 的起点；
- decoder 必须先验证 Header 与长度上限，再读取或分配 attachment；
- decoder 必须读取 exact `content_length`，不得依赖一次 stream read 或一次
  RTCDataChannel/WebSocket 消息对应一个 Frame；
- attachment 读取不足是截断错误；多出的字节属于下一 Frame，不能吞并。

### 3.4 固定上限

```text
MAX_HEADER_BYTES        = 65536
MAX_SEED_BYTES          = 16777216
MAX_BLOCK_BYTES         = 262144
MAX_CONTENT_BYTES       = 16777216
MAX_ERROR_MESSAGE_BYTES = 1024
```

V1 不压缩 Header、Seed 或文件块。transport 可以自行分片，但不能改变 Frame 字节。

---

## 4. 内容模型

### 4.1 哈希与块

```text
BLOCK_SIZE_BYTES      = 262144
DIGEST_SIZE_BYTES     = 32
HASH_ALGORITHM        = SHA-256
MAX_SOURCE_FILE_BYTES = 137438953472
```

wire 中的 `seed_hash` 和 `content_hash` 都是固定 32 字节 CBOR bstr。展示层可以编码成 64 个
小写 hex 字符，但 wire 上不得发送 hex text。

本文在数组定义中使用 `content_hash`，它就是需求讨论中的 `hash` 字段：

```text
content_hash = SHA-256(content_bytes)
```

它可以指向两类内容：

- `seed_hash`：MasterSeed 内容的哈希；
- `block_hash`：单个源文件块的哈希。

请求中不再发送 `block_index` 或内容类型。客户端根据调用上下文知道当前哈希是 Seed 还是块。

### 4.2 MasterSeed

```text
seed_hash  = SHA-256(seed_bytes)

seed_bytes =
  block_hash[0] || block_hash[1] || ... || block_hash[n-1]

block_hash[i] = SHA-256(source_block[i])
```

每个块哈希是 32 字节原始 SHA-256。Seed 不再通过 StatResponse 返回，而是通过
`Read(seed_hash, max_price_satoshis)` 获取。

```text
file_size_bytes = 0:
  block_count = 0

file_size_bytes > 0:
  block_count = floor((file_size_bytes - 1) / 262144) + 1

len(seed_bytes) = block_count * 32
```

空文件合法，对应零字节 Seed；其 SeedHash 是 SHA-256 空输入。

### 4.3 验证责任

客户端读取 Seed 时必须验证：

```text
content_hash == requested_seed_hash
SHA-256(content_bytes) == requested_seed_hash
content_length <= MAX_SEED_BYTES
content_length % 32 == 0
content_length == block_count(file_size_bytes) * 32
```

读取文件块时必须验证：

```text
content_hash == requested_block_hash
SHA-256(content_bytes) == requested_block_hash
content_length <= MAX_BLOCK_BYTES
```

如果客户端掌握可信文件尺寸，还必须检查最后一块的精确长度。所有检查通过后才能把内容交给
播放器、文件系统或缓存。

---

## 5. Wire Kind 注册表

| Kind | 名称 | 方向 | Attachment |
|---:|---|---|---|
| 1 | `StatRequest` | Client -> Supplier | 无 |
| 2 | `StatResponse` | Supplier -> Client | 无 |
| 3 | `ReadRequest` | Client -> Supplier | 无 |
| 4 | `ReadResponse` | Supplier -> Client | `content_bytes` |
| 5 | `ReadCancelled` | Supplier -> Client | 无 |
| 255 | `ErrorResponse` | Supplier -> Client | 无 |

`AcquireRequest` 和 `AcquireResponse` 已删除。Kind 3、4 直接用于 Read；本协议尚未部署，不保留
旧草案 Kind 的兼容占位。

合法响应关系：

```text
StatRequest -> StatResponse | ErrorResponse
ReadRequest -> ReadResponse | ReadCancelled | ErrorResponse
```

---

## 6. 通用字段

### 6.1 整数

- request ID、金额、时间和尺寸都是 CBOR unsigned integer；
- 最大值是 `2^64 - 1`，具体字段可以有更小上限；
- 禁止负数、浮点数、tagged bignum 和 text number。

### 6.2 建议文件名

`recommended_filename` 是 UTF-8 text string，可以为空。非空时必须：

- 是单个 basename；
- 不含 `/`、`\\`、NUL 和控制字符；
- 不是 `.` 或 `..`；
- UTF-8 编码不超过 255 字节；
- 不包含供应商本机路径。

客户端不能直接把建议文件名拼接成本地路径。

### 6.3 Media Type

`media_type` 是 UTF-8 text string，可以为空。非空时必须是不含控制字符、长度不超过
255 字节的 ASCII MIME media type。它只用于展示和播放提示，不参与内容校验。

### 6.4 价格

所有 `*_price_satoshis` 都以聪为单位，是单个内容对象的价格，不是累计预算。

StatResponse 中的最小值和最大值是供应商当前观察到的价格范围，只用于展示和决策，不构成
不可变报价。最终购买授权只由 ReadRequest 的 `max_price_satoshis` 决定。

---

## 7. Stat

### 7.1 StatRequest（Kind 1）

```text
[1, 1,
  stat_request_id,
  seed_hash
]
```

| Index | 字段 | 类型 | 中文含义与约束 |
|---:|---|---|---|
| 0 | `wire_version` | uint | 固定为 `1` |
| 1 | `wire_kind` | uint | 固定为 `1` |
| 2 | `stat_request_id` | uint64 | 当前 connection 内单调递增的 Stat 请求序号 |
| 3 | `seed_hash` | 32-byte bstr | 要查询的 MasterSeed 哈希 |

StatRequest 没有 attachment。

客户端可以频繁、重复查询同一 `seed_hash`。供应商必须为每个合法 StatRequest 返回终态响应；
客户端收到乱序响应时，对同一供应商和同一 `seed_hash` 只采用最大 `stat_request_id` 对应的状态。

Stat 轮询只观察状态。供应商可以在第一次查询时按自身策略建立去重的发现任务，但重复 Stat：

- 不得一对一产生远端广播；
- 不得一对一产生购买；
- 不得绕过供应商自身的退避、TTL 和资源限制。

### 7.2 状态值

```text
1 = available    // 内容已在当前供应商本地就绪
2 = absent       // 当前没有内容，也没有可报告的发现状态
3 = discovering  // 正在发现内容或价格
4 = quoted       // 已发现元数据和当前价格范围
```

### 7.3 Available StatResponse

```text
[1, 2,
  stat_request_id,
  1,
  recommended_filename,
  file_size_bytes,
  media_type
]
```

`available` 表示供应商已经验证完整 Seed 和所有文件块，Read 可以直接从本地内容存储返回。
StatResponse 本身不携带 Seed 或其他 attachment。

### 7.4 Absent StatResponse

```text
[1, 2,
  stat_request_id,
  2
]
```

`absent` 只表示该供应商当前没有可报告结果；它不能代表供应商网络不可达。

### 7.5 Discovering StatResponse

```text
[1, 2,
  stat_request_id,
  3,
  retry_after_ms
]
```

`retry_after_ms` 是 `0..3600000` 的建议最短轮询间隔，不控制供应商内部发现频率。

### 7.6 Quoted StatResponse

```text
[1, 2,
  stat_request_id,
  4,
  recommended_filename,
  file_size_bytes,
  media_type,
  min_seed_price_satoshis,
  max_seed_price_satoshis,
  min_full_block_price_satoshis,
  max_full_block_price_satoshis
]
```

| 字段 | 中文含义 |
|---|---|
| `min_seed_price_satoshis` | 当前观察到的 Seed 最低价格 |
| `max_seed_price_satoshis` | 当前观察到的 Seed 最高价格 |
| `min_full_block_price_satoshis` | 当前观察到的一个完整 256 KiB 文件块最低价格 |
| `max_full_block_price_satoshis` | 当前观察到的一个完整 256 KiB 文件块最高价格 |

每组最小值必须小于或等于对应最大值。价格范围不携带 `quote_id`、过期时间或付款凭证。

---

## 8. Read

### 8.1 ReadRequest（Kind 3）

```text
[1, 3,
  read_request_id,
  content_hash,
  max_price_satoshis
]
```

| Index | 字段 | 类型 | 中文含义与约束 |
|---:|---|---|---|
| 0 | `wire_version` | uint | 固定为 `1` |
| 1 | `wire_kind` | uint | 固定为 `3` |
| 2 | `read_request_id` | uint64 | 当前 connection 内单调递增的 Read 请求序号 |
| 3 | `content_hash` | 32-byte bstr | Seed 或文件块的 SHA-256 |
| 4 | `max_price_satoshis` | uint64 | 本次内容允许的最高价格；`0` 表示不限制 |

ReadRequest 没有 attachment。

`max_price_satoshis` 是一次内容购买授权：

- 正整数表示供应商只能在实际价格不超过该值时购买；
- `0` 明确表示客户端接受任意价格；
- `0` 不是“仅免费”，也不是字段缺省值；
- SDK、UI 和配置层必须要求调用方显式选择“不限制”，不得因未初始化而自动发送 `0`；
- 供应商不得把一个 Read 的上限当成整个文件或整个会话的累计预算。

供应商的价格判断必须等价于：

```text
price_authorized =
  max_price_satoshis == 0 || actual_price_satoshis <= max_price_satoshis
```

### 8.2 同一内容的授权覆盖

供应商按以下键维护当前 connection 上尚未终结的读取状态：

```text
(authenticated_client_public_key, content_hash)
```

对同一个 `content_hash` 重复 Read 的目的，是修改当前有效的 `max_price_satoshis`：

1. 更大的 `read_request_id` 完成格式、权限和金额校验后，成为最新请求；
2. 尚未开始发送终态响应的较小请求被覆盖；
3. 每个被覆盖请求返回一个 ReadCancelled；
4. 获取任务、已下载字节和缓存应尽量复用，不得因为更新授权而重复购买同一内容；
5. 成功内容通过最新有效的 `read_request_id` 返回；
6. 不同 `content_hash` 之间互不覆盖，可以并发执行。

只有通过完整校验的新请求才能覆盖旧请求。畸形、未授权或价格非法的新请求不得取消仍有效的
旧请求。

### 8.3 不可逆价格边界

新请求可以提高或降低尚未承诺的价格上限，但不能撤销已经发生的付款承诺：

- 尚未承诺付款：立即采用新上限并取消旧请求；
- 已承诺价格不超过新上限：复用结果，把成功内容关联到新请求；
- 已承诺价格超过新上限：新请求返回 `price_already_committed`，旧请求继续按原授权终结；
- connection 关闭后禁止开始新的付款，但已经不可逆的付款不能由传输断开撤销。

供应商内部必须为同一客户端与同一内容去重购买；request ID 不能作为购买去重键。

### 8.4 ReadResponse（Kind 4）

```text
[1, 4,
  read_request_id,
  content_hash,
  content_length
]
|| content_bytes
```

| Index | 字段 | 类型 | 中文含义与约束 |
|---:|---|---|---|
| 0 | `wire_version` | uint | 固定为 `1` |
| 1 | `wire_kind` | uint | 固定为 `4` |
| 2 | `read_request_id` | uint64 | 成功请求的序号 |
| 3 | `content_hash` | 32-byte bstr | 必须等于该请求的目标哈希 |
| 4 | `content_length` | uint64 | 后续 raw attachment 的精确字节数 |

`content_bytes` 可以是 Seed，也可以是一个文件块，所以统一称为内容字节，不称为
`block_bytes`。成功响应同时承诺供应商遵守了该请求的 `max_price_satoshis`。

V1 ReadResponse 不回传实际成交价格；实际扣款记录和可审计结算属于供应商/钱包账务层。如果
未来要求在 MSFile wire 内核对实付金额，必须提升协议版本，不能向该数组追加可选字段。

### 8.5 ReadCancelled（Kind 5）

```text
[1, 5,
  read_request_id,
  content_hash,
  replaced_by_request_id
]
```

| 字段 | 中文含义 |
|---|---|
| `read_request_id` | 被取消的旧请求序号 |
| `content_hash` | 被覆盖请求的内容哈希 |
| `replaced_by_request_id` | 替代旧请求的新请求序号，必须更大 |

ReadCancelled 是正常终态，不是协议故障。它没有 attachment。客户端收到后必须结束旧请求的
等待状态，但不得取消替代它的新请求。

### 8.6 响应开始后的竞态

ReadResponse Header 一旦进入 stream 写队列并开始发送，就不能再被后来的请求截断，否则接收方
无法定位 attachment 和下一 Frame。因此：

- 新请求在旧 ReadResponse 开始发送前到达：旧请求返回 ReadCancelled，新请求返回内容；
- 新请求在旧 ReadResponse 开始发送后到达：旧响应必须完整发送；新请求仍必须获得自己的终态，
  供应商复用缓存结果再次返回 ReadResponse，不得重复购买；
- 客户端可以忽略已被本地更大序号覆盖的旧成功响应，但仍必须把整个 Frame 读完并校验边界。

这是全双工并发下不可消除的边界。实现不得通过截断 attachment 来强行保证“较小序号总是取消”。

---

## 9. ErrorResponse（Kind 255）

StatRequest 或 ReadRequest 都可以返回：

```text
[1, 255,
  request_kind,
  request_id,
  error_code,
  error_message,
  retry_after_ms
]
```

| 字段 | 中文含义与约束 |
|---|---|
| `request_kind` | 失败请求的 Kind，只能是 `1` 或 `3` |
| `request_id` | 失败请求的 `stat_request_id` 或 `read_request_id` |
| `error_code` | 小写 ASCII 稳定错误码，最多 64 字节 |
| `error_message` | 诊断文本，UTF-8，最多 1024 字节，可以为空 |
| `retry_after_ms` | `0..3600000`；`0` 表示没有重试建议 |

客户端只能依赖 `error_code`，不得解析 `error_message`。诊断文本不得包含私钥、完整白名单、
本机路径、交易原文、内部堆栈或内容字节。

| Error Code | 中文含义 |
|---|---|
| `bad_request` | CBOR、字段、类型或范围错误 |
| `unsupported_version` | 不支持 wire version |
| `wrong_stream_role` | 在已锁定角色的 stream 上发送了另一类命令 |
| `stale_request_id` | request ID 重复、倒退或已经失效 |
| `invalid_content_hash` | SeedHash 或内容哈希长度/值非法 |
| `unauthorized_peer` | 已认证公钥没有当前命令权限 |
| `content_not_found` | 当前无法找到指定哈希的内容 |
| `price_limit_exceeded` | 当前价格超过 Read 授权上限 |
| `price_already_committed` | 已承诺价格高于后来降低的新上限 |
| `acquisition_failed` | 供应商获取内容失败 |
| `integrity_error` | 供应商或客户端检测到内容长度/哈希错误 |
| `rate_limited` | 超过频率、并发、带宽或预算策略 |
| `internal_error` | 供应商内部错误 |

连接建立失败、stream Reset、EOF 和超时属于 Transport 错误，不能编码成业务 `absent`。

---

## 10. 标准流程

### 10.1 多供应商状态查询

```text
Supplier A Stat stream: Stat(41, seed_hash) -> Quoted(41, ...)
Supplier B Stat stream: Stat(18, seed_hash) -> Absent(18)
Supplier C: connection timeout
```

客户端把 A、B 的结果分别绑定到各 connection 已认证的供应商公钥。C 是网络错误，不是
`absent`。

### 10.2 获取 Seed 后随机读取

```text
Read(100, seed_hash, max_seed_price)
  -> ReadResponse(100, seed_hash, seed_length) || seed_bytes

客户端验证 SeedHash，并从 Seed 取得 block_hash[836]

Read(101, block_hash[836], max_block_price)
  -> ReadResponse(101, block_hash[836], block_length) || block_bytes
```

播放器不需要读取块 `0..835`。

### 10.3 更新价格授权

```text
Read(200, block_hash, 50)
Read(201, block_hash, 80)

-> ReadCancelled(200, block_hash, 201)
-> ReadResponse(201, block_hash, content_length) || content_bytes
```

客户端通过控制 Read 发送顺序实现调度：跳转播放时暂停或缩小后台预读窗口，优先发送目标块，
不需要 wire `priority` 字段。

---

## 11. 背压与资源控制

- encoder 和 decoder 必须尊重 libp2p stream 背压；
- WebRTC transport 上不得假设一次写入等于一个 RTCDataChannel message；
- WSS transport 上不得假设一次写入等于一个 WebSocket message；
- 实现建议以不超过 16 KiB 的片段推进 Frame 字节，但该分片不是 wire 边界；
- Read stream 可以并发执行多个请求，但 response writer 必须逐 Frame 串行；
- 单个 16 MiB Seed 响应会阻塞同一 Read stream 后续响应，这是 V1 接受的队头阻塞；
- Stat 使用独立 stream，因此不会被 Seed 或文件块 attachment 阻塞；
- 供应商应限制每公钥、每 connection 和全局的未完成 Read 数、缓存、内存与带宽；
- 达到资源上限返回 `rate_limited` 或关闭连接，不得静默丢弃请求；
- stream 关闭时所有尚未终结的请求进入传输失败，上层可在重连后重新发送。

---

## 12. 明确不属于 V1 的能力

V1 不定义：

- Acquire 命令和独立 acquisition 生命周期；
- `quote_id`、`acquisition_id`、`priority`、`block_index` 或随机幂等键；
- StatResponse 携带 Seed；
- JSON、Base64、HTTP endpoint 或 API Key；
- 每个 Stat/Read 的额外业务签名或应用层握手；
- 任意 Byte Range；调用方在 256 KiB 块内自行切片；
- 文件上传、目录、删除、重命名和价格设置；
- 供应商内部 Seller、付款、仲裁、费用池和交易报文；
- 在 ReadResponse 内报告实际成交价格；
- 压缩、批量 Read 或跨 Frame 交错 attachment。

新增字段、改变数组长度或改变 Kind 含义都必须提升 protocol/wire 版本。

---

## 13. 验收范围

实现至少覆盖：

- Stat 与 Read 各自长驻 stream，重复请求无需新建 stream；
- 请求和响应全双工，多个响应可乱序但 Frame 字节不交错；
- request ID 单调性、关联、过期响应淘汰和 `uint64` 边界；
- 同一 hash 的更大 Read 覆盖旧授权，并为旧请求返回 ReadCancelled；
- 新请求校验失败不取消旧请求；
- ReadResponse 已开始发送时不被截断，竞态分支不重复购买；
- uvarint 非最短、溢出、Header 超限和 attachment 截断；
- deterministic CBOR、固定数组长度、UTF-8 和字段范围；
- Stat 四种状态无 attachment，频繁轮询不一对一驱动远端购买；
- Seed 与块均通过 `content_hash` 读取和验证；
- `max_price_satoshis = 0` 只在客户端显式授权时产生；
- 价格超过上限、已承诺价格和内容获取失败的终态；
- 连接/stream 错误与业务 `absent` 严格区分；
- 大 attachment 遵守背压且内存不随并发无限增长。

---

## 参考规范

- [MasterSeed / Keymaster Seed V1](https://github.com/bsv8/MasterSeed)
- [RFC 8949 · CBOR](https://www.rfc-editor.org/rfc/rfc8949)
- [Protocol Buffers · Base 128 Varints](https://protobuf.dev/programming-guides/encoding/#varints)
- [libp2p Connections and Streams](https://github.com/libp2p/specs/blob/master/connections/README.md)
