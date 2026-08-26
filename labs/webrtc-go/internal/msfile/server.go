// Package msfile 实现正式 libp2p /msfile/1.0.0 服务端（协议真值见 docs/protocol/wire-messages.zh.md）。
//
// 关键规则：
//
//	request ID 作用域是 connection：stream 重建后不得倒退（wire §2.3）；
//	每条 connection 最多一条 Stat stream 和一条 Read stream，第一个请求锁定角色；
//	同一 hash 的更大 Read 覆盖旧请求并返回 ReadCancelled；
//	响应 Frame 由唯一 writer 串行写出，attachment 不交错；
//	授权只依据 connection 层认证出的远端压缩公钥（auth.Policy）；
//	public 模式实施全局并发 Read 与在途请求上限，超限返回 rate_limited。
package msfile

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"

	"msfile.dev/labs/webrtc-go/internal/auth"
	"msfile.dev/labs/webrtc-go/internal/content"
	"msfile.dev/labs/webrtc-go/internal/identity"
	"msfile.dev/labs/webrtc-go/internal/metrics"
)

// ContentSource 抽象内容读取，便于资源限制与取消的确定性测试。
type ContentSource interface {
	Stat(ctx context.Context, seedHashHex string) (content.StatInfo, bool, error)
	Resolve(ctx context.Context, hashHex string) ([]byte, error)
}

// 编译期确认 *content.Reader 满足接口。
var _ ContentSource = (*content.Reader)(nil)

// Limits 是资源上限。public 模式下攻击者可不断生成新公钥，
// 因此限额必须是跨连接的全局值，不能按公钥或连接划分。
type Limits struct {
	MaxConcurrentReads     int           // 全局同时执行的 Read 任务上限
	MaxInflightRequests    int           // 全局在途请求 goroutine 硬上限（含 Stat）
	MaxInflightPerConn     int           // 单 connection 在途请求上限
	ReadQueueTimeout       time.Duration // 等待读取槽位的最长时间；超时返回 rate_limited
	RequestReadTimeout     time.Duration // 单个请求 Frame 的读取 deadline（防半包挂死）
	GlobalWriteBytesPerSec int64         // 全局响应带宽上限（字节/秒）；0 = 不限
	ConnWriteBytesPerSec   int64         // 单 connection 响应带宽上限（字节/秒）；0 = 不限
}

// DefaultLimits 返回保守默认值：
// 16 个并发 Read × 最大 16 MiB 内容 = 内容缓冲上界有界可控；
// 在途请求总量 256、单连接 64，杜绝无界 goroutine 增长。
func DefaultLimits() Limits {
	return Limits{
		MaxConcurrentReads:     16,
		MaxInflightRequests:    256,
		MaxInflightPerConn:     64,
		ReadQueueTimeout:       10 * time.Second,
		RequestReadTimeout:     5 * time.Minute,
		GlobalWriteBytesPerSec: 256 << 20, // 256 MiB/s：功能上强制限流存在，吞吐对内网足够
		ConnWriteBytesPerSec:   32 << 20,  // 32 MiB/s
	}
}

// connState 保存单条 connection 的协议状态：
// LastID 跨 stream 重建延续，Active 只表示当前占用。
type connState struct {
	mu         sync.Mutex
	statLastID uint64
	readLastID uint64
	statActive bool
	readActive bool
	inflight   int
}

// advance 推进某类请求的序号；id 必须严格递增（wire §2.3）。
// 序号在 connection 作用域内跨 stream 重建延续。
func (cs *connState) advance(kind uint64, id uint64) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if kind == KindStatRequest {
		if id <= cs.statLastID {
			return false
		}
		cs.statLastID = id
		return true
	}
	if id <= cs.readLastID {
		return false
	}
	cs.readLastID = id
	return true
}

// claimRole 占用同角色的唯一 stream 槽位。
func (cs *connState) claimRole(kind uint64) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if kind == KindStatRequest {
		if cs.statActive {
			return false
		}
		cs.statActive = true
		return true
	}
	if cs.readActive {
		return false
	}
	cs.readActive = true
	return true
}

func (cs *connState) releaseRole(kind uint64) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if kind == KindStatRequest {
		cs.statActive = false
	} else {
		cs.readActive = false
	}
}

// Server 是正式 MSFile 文件服务端。
type Server struct {
	host         host.Host
	reader       ContentSource
	policy       *auth.Policy
	log          *metrics.Logger
	limits       Limits
	readSem      chan struct{}
	inflight     atomic.Int32
	globalBucket *rateBucket

	connMu sync.Mutex
	conns  map[string]*connState

	closeOnce sync.Once
	stopCh    chan struct{}
}

type response struct {
	fields []any
	data   []byte
	done   func()
}

type pendingRead struct {
	id    uint64
	stage atomic.Int32 // 0=进行中 1=已承诺发送终态 3=已被覆盖取消
}

// NewServer 创建服务端并注册 /msfile/1.0.0 handler；同时挂接连接断开清理。
func NewServer(h host.Host, reader ContentSource, policy *auth.Policy, log *metrics.Logger) *Server {
	return NewServerWithLimits(h, reader, policy, log, DefaultLimits())
}

// NewServerWithLimits 允许测试注入更小的资源上限。
func NewServerWithLimits(h host.Host, reader ContentSource, policy *auth.Policy, log *metrics.Logger, limits Limits) *Server {
	s := &Server{
		host:    h,
		reader:  reader,
		policy:  policy,
		log:     log,
		limits:  limits,
		readSem: make(chan struct{}, maxInt(limits.MaxConcurrentReads, 1)),
		conns:   make(map[string]*connState),
		stopCh:  make(chan struct{}),
	}
	h.Network().Notify(&network.NotifyBundle{
		DisconnectedF: func(_ network.Network, conn network.Conn) {
			s.dropConnState(conn.ID())
		},
	})
	s.Register()
	return s
}

// Register 注册协议 handler（NewServer 已自动调用；保留给需要显式控制的调用方）。
func (s *Server) Register() {
	s.host.SetStreamHandler(protocol.ID(ProtocolID), s.handleStream)
}

func (s *Server) connState(connID string) *connState {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	cs := s.conns[connID]
	if cs == nil {
		cs = &connState{}
		s.conns[connID] = cs
	}
	return cs
}

func (s *Server) dropConnState(connID string) {
	s.connMu.Lock()
	delete(s.conns, connID)
	s.connMu.Unlock()
}

func (s *Server) handleStream(stream network.Stream) {
	conn := stream.Conn()
	if conn == nil {
		_ = stream.Reset()
		return
	}
	remoteKey, err := identity.RemoteCompressedPubKeyHex(conn.RemotePublicKey())
	if err != nil {
		s.log.Emit("msfile_stream_denied", map[string]any{"reason_zh": "远端身份不是 secp256k1 公钥"})
		_ = stream.Reset()
		return
	}
	cs := s.connState(conn.ID())
	reader := bufio.NewReaderSize(stream, 64*1024)

	// 读 deadline：半包或长期不发送完整请求的客户端在此超时。
	_ = stream.SetReadDeadline(time.Now().Add(s.limits.RequestReadTimeout))
	first, err := ReadRequest(reader)
	if err != nil {
		_ = stream.Reset()
		return
	}

	// 授权判断只使用 connection 认证出的远端公钥；
	// private 空白名单在这里拒绝全部客户端，不存在 allow-all 回退。
	if allowErr := s.policy.Allow(remoteKey); allowErr != nil {
		s.log.Emit("msfile_stream_denied", map[string]any{
			"remote_public_key": remoteKey,
			"mode":              s.policy.Mode(),
			"reason_zh":         allowErr.Error(),
		})
		_ = WriteFrame(stream, Error(first.Kind, first.ID, "unauthorized_peer", "该公钥未被授权访问此服务", 0), nil, 0)
		_ = stream.Close()
		return
	}

	// stream 生命周期 ctx：读循环结束或 writer 失败时取消全部在途任务。
	// 角色占用先于序号推进（阻断 4）：认证 → claimRole → advance → 业务。
	// 重复 stream 用更大 ID 无法烧掉合法 stream 的序号空间，
	// 第一帧过期的 ID 也无法绕过“每 connection 一条同角色 stream”约束。
	if !cs.claimRole(first.Kind) {
		responses := make(chan response, 1)
		writerDone := make(chan error, 1)
		go s.writeResponses(stream, responses, writerDone, func() {}, nil)
		responses <- response{fields: Error(first.Kind, first.ID, "wrong_stream_role", "当前连接已经存在同角色 stream", 0)}
		close(responses)
		if err := <-writerDone; err != nil {
			_ = stream.Reset()
		} else {
			s.gracefulClose(stream)
		}
		return
	}
	defer cs.releaseRole(first.Kind)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	responses := make(chan response, 32)
	writerDone := make(chan error, 1)
	connBucket := newRateBucket(s.limits.ConnWriteBytesPerSec)
	go s.writeResponses(stream, responses, writerDone, cancel, connBucket)
	var workers sync.WaitGroup
	var pendingMu sync.Mutex
	pending := make(map[string]*pendingRead)

	handle := func(request Request) bool {
		if request.Kind != first.Kind {
			responses <- response{fields: Error(request.Kind, request.ID, "wrong_stream_role", "Stat 与 Read 必须使用不同 stream", 0)}
			return false
		}
		// 角色已在外部占用（认证 → claimRole → defer release）。
		// 序号推进失败是逐请求错误（stale_request_id），流继续服务后续请求。
		if !cs.advance(request.Kind, request.ID) {
			responses <- response{fields: Error(request.Kind, request.ID, "stale_request_id", "request ID 必须在当前 connection 内递增，重建 stream 也不得倒退", 0)}
			return true
		}

		// 在途请求硬上限：全局 CAS + 单连接同临界区检查并自增（阻断 4）。
		globalOK := s.tryAddInflight()
		if !globalOK {
			responses <- response{fields: Error(request.Kind, request.ID, "rate_limited", "在途请求达到上限，请稍后重试", retryAfterMs())}
			return true
		}
		if !cs.tryInflightAdd(s.limits.MaxInflightPerConn) {
			s.inflight.Add(-1)
			responses <- response{fields: Error(request.Kind, request.ID, "rate_limited", "当前连接在途请求达到上限，请稍后重试", retryAfterMs())}
			return true
		}

		if request.Kind == KindStatRequest {
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { s.inflight.Add(-1); cs.inflightDone() }()
				s.handleStat(ctx, request, responses)
			}()
			return true
		}
		hash := hex.EncodeToString(request.Hash[:])
		current := &pendingRead{id: request.ID}
		pendingMu.Lock()
		previous := pending[hash]
		pending[hash] = current
		cancelled := previous != nil && previous.stage.CompareAndSwap(0, 3)
		pendingMu.Unlock()
		if cancelled {
			responses <- response{fields: ReadCancelled(previous.id, request.Hash, request.ID)}
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { s.inflight.Add(-1); cs.inflightDone() }()
			s.handleRead(request, current, responses, func() {
				pendingMu.Lock()
				if pending[hash] == current {
					delete(pending, hash)
				}
				pendingMu.Unlock()
			}, ctx)
		}()
		return true
	}

	keepReading := handle(first)
	for keepReading {
		_ = stream.SetReadDeadline(time.Now().Add(s.limits.RequestReadTimeout))
		request, readErr := ReadRequest(reader)
		if readErr != nil {
			// 读循环退出：不再接受新请求；在途任务先行收尾（受上限约束，有界），
			// 全部完成后由 defer cancel 统一释放。
			break
		}
		keepReading = handle(request)
	}
	workers.Wait()
	cancel()
	close(responses)
	if werr := <-writerDone; werr != nil {
		_ = stream.Reset()
	} else {
		// 优雅关闭：半关 + 等待对端读完（有界），避免丢最后一帧。
		s.gracefulClose(stream)
	}
}

func (c *connState) inflightExceeds(limit int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inflight >= limit
}

func (c *connState) inflightAdd(delta int) {
	c.mu.Lock()
	c.inflight += delta
	c.mu.Unlock()
}

func (s *Server) handleStat(ctx context.Context, request Request, out chan<- response) {
	info, ok, err := s.reader.Stat(ctx, hex.EncodeToString(request.Hash[:]))
	if err != nil {
		send(ctx, out, response{fields: Error(request.Kind, request.ID, "internal_error", "查询内容状态失败", 0)})
		return
	}
	if !ok {
		send(ctx, out, response{fields: StatAbsent(request.ID)})
		return
	}
	send(ctx, out, response{fields: StatAvailable(request.ID, info.Filename, info.SizeBytes, info.MediaType)})
}

func (s *Server) handleRead(request Request, pending *pendingRead, out chan<- response, done func(), ctx context.Context) {
	queueCtx, cancel := context.WithTimeout(ctx, s.limits.ReadQueueTimeout+30*time.Second)
	defer cancel()
	// 全局并发槽位：public 模式换 key 不能绕过全局上限。
	select {
	case s.readSem <- struct{}{}:
		defer func() { <-s.readSem }()
	case <-time.After(s.limits.ReadQueueTimeout):
		if pending.stage.CompareAndSwap(0, 1) {
			send(queueCtx, out, response{fields: Error(request.Kind, request.ID, "rate_limited", "服务繁忙，请稍后重试", retryAfterMs()), done: done})
		} else {
			done()
		}
		return
	case <-queueCtx.Done():
		done()
		return
	}
	if queueCtx.Err() != nil {
		done()
		return
	}
	data, err := s.reader.Resolve(queueCtx, hex.EncodeToString(request.Hash[:]))
	if err != nil {
		if pending.stage.CompareAndSwap(0, 1) {
			code, message := readErrorCode(err)
			send(queueCtx, out, response{fields: Error(request.Kind, request.ID, code, message, 0), done: done})
		} else {
			done()
		}
		return
	}
	if int64(len(data)) > MaxContentBytes {
		if pending.stage.CompareAndSwap(0, 1) {
			send(queueCtx, out, response{fields: Error(request.Kind, request.ID, "integrity_error", "内容尺寸超过协议上限", 0), done: done})
		} else {
			done()
		}
		return
	}
	if !pending.stage.CompareAndSwap(0, 1) {
		done()
		return
	}
	send(queueCtx, out, response{fields: ReadSuccess(request.ID, request.Hash, int64(len(data))), data: data, done: done})
}

// tryAddInflight 以 CAS 循环原子地占用一个全局在途槽位（阻断 4）。
func (s *Server) tryAddInflight() bool {
	for {
		current := s.inflight.Load()
		if current >= int32(s.limits.MaxInflightRequests) {
			return false
		}
		if s.inflight.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

// tryInflightAdd 在同一临界区内完成检查与自增；满则返回 false 且无任何变更。
func (c *connState) tryInflightAdd(limit int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inflight >= limit {
		return false
	}
	c.inflight++
	return true
}

func (c *connState) inflightDone() {
	c.mu.Lock()
	c.inflight--
	c.mu.Unlock()
}

// gracefulClose 半关写方向、等待对端读完或有界超时后全关。
func (s *Server) gracefulClose(stream network.Stream) {
	_ = stream.CloseWrite()
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buf := make([]byte, 512)
		for {
			if _, err := stream.Read(buf); err != nil {
				return
			}
		}
	}()
	select {
	case <-drained:
	case <-time.After(3 * time.Second):
	case <-s.stopCh:
	}
	_ = stream.Close()
}

// readErrorCode 把 content.Reader 的错误映射为协议稳定错误码；消息保持中文诊断。
func readErrorCode(err error) (string, string) {
	switch {
	case errors.Is(err, content.ErrIntegrity):
		return "integrity_error", "内容完整性校验失败，已拒绝返回未验证字节"
	case errors.Is(err, content.ErrUnavailable):
		return "content_not_found", "内容当前没有任何可用副本"
	case errors.Is(err, content.ErrContentNotFound):
		return "content_not_found", "没有找到指定哈希的内容"
	default:
		return "internal_error", "读取内容失败"
	}
}

func retryAfterMs() uint64 { return 1000 }

func send(ctx context.Context, out chan<- response, value response) {
	select {
	case out <- value:
	case <-ctx.Done():
		if value.done != nil {
			value.done()
		}
	}
}

// writeResponses 是该 stream 唯一的 Frame writer：串行写完整 Header + attachment。
// 写失败即触发 cancel，终止该 stream 上所有在途任务，避免半写 Frame 后继续消耗资源。
func (s *Server) writeResponses(stream network.Stream, responses <-chan response,
	done chan<- error, cancel context.CancelFunc, connBucket *rateBucket) {

	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	go func() {
		select {
		case <-s.stopCh:
			cancel()
			stop()
		case <-ctx.Done():
		}
	}()
	for value := range responses {
		if err := stream.SetWriteDeadline(time.Now().Add(5 * time.Minute)); err != nil {
			finishResponse(&value)
			cancel()
			done <- err
			return
		}
		var attachment io.Reader
		if value.data != nil && len(value.data) > 0 {
			attachment = &throttledReader{
				r:      &byteSliceReader{data: value.data},
				global: s.globalBucket,
				conn:   connBucket,
				ctx:    ctx,
			}
		}
		err := WriteFrame(stream, value.fields, attachment, int64(len(value.data)))
		finishResponse(&value)
		if err != nil {
			cancel()
			done <- err
			return
		}
	}
	done <- stream.CloseWrite()
}

func finishResponse(value *response) {
	if value.done != nil {
		value.done()
	}
	value.data = nil // 尽早释放大缓冲引用
}

type byteSliceReader struct {
	data []byte
	pos  int
}

func (r *byteSliceReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ---------- 带宽令牌桶（需求 §9/§10：public 必须有带宽上限） ----------

// rateBucket 是惰性补充的令牌桶；rate<=0 表示不限速。
type rateBucket struct {
	mu     sync.Mutex
	rate   float64 // 字节/秒
	tokens float64
	last   time.Time
}

func newRateBucket(bytesPerSec int64) *rateBucket {
	if bytesPerSec <= 0 {
		return nil
	}
	return &rateBucket{rate: float64(bytesPerSec), tokens: float64(bytesPerSec), last: time.Now()}
}

// take 阻塞直到获取 n 个字节的配额；ctx 取消时提前返回。
func (b *rateBucket) take(ctx context.Context, n int) error {
	if b == nil {
		return nil
	}
	for n > 0 {
		b.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(b.last).Seconds()
		b.last = now
		b.tokens += elapsed * b.rate
		if max := b.rate; b.tokens > max {
			b.tokens = max // 桶容量 = 1 秒突发
		}
		grant := b.tokens
		if grant > float64(n) {
			grant = float64(n)
		}
		if grant >= 1 {
			b.tokens -= grant
			b.mu.Unlock()
			n -= int(grant)
			continue
		}
		// 计算补足剩余字节需要的等待时间后让出。
		need := float64(n) - b.tokens
		wait := time.Duration(need / b.rate * float64(time.Second))
		b.mu.Unlock()
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// throttledReader 在读取 attachment 字节流时同步消耗全局与单连接配额。
type throttledReader struct {
	r      io.Reader
	global *rateBucket
	conn   *rateBucket
	ctx    context.Context
}

func (t *throttledReader) Read(p []byte) (int, error) {
	if len(p) > 16<<10 {
		p = p[:16<<10] // 与协议建议一致的分片粒度，防止单次长阻塞
	}
	if err := t.global.take(t.ctx, len(p)); err != nil {
		return 0, err
	}
	if err := t.conn.take(t.ctx, len(p)); err != nil {
		return 0, err
	}
	return t.r.Read(p)
}
