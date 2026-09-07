// Package nas 是 MSFile NAS V1 的组合根：
//
//	解析并完整验证配置
//	  -> 创建/检查 seed_data
//	  -> 取得 service.lock
//	  -> 打开并验证 SQLite schema
//	  -> 创建只读 auth policy
//	  -> 恢复未完成 scan/staging
//	  -> 构造 coordinator、Reader 和 Web Handler（此时尚未启动扫描）
//	  -> 注册 /msfile/1.0.0
//	  -> 启动 WebRTC Direct + WS/WSS listener（Web Handler 作为 HTTP fallback）
//	  -> 启动 coordinator（安排首次全量扫描）
//
// 本包只做装配与生命周期编排；SQL、扫描、Hash、协议编解码都在各自的 internal 包内。
package nas

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	yamux "github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	webrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	websocket "github.com/libp2p/go-libp2p/p2p/transport/websocket"
	ma "github.com/multiformats/go-multiaddr"

	"msfile.dev/labs/webrtc-go/internal/admin"
	"msfile.dev/labs/webrtc-go/internal/auth"
	"msfile.dev/labs/webrtc-go/internal/config"
	"msfile.dev/labs/webrtc-go/internal/content"
	"msfile.dev/labs/webrtc-go/internal/identity"
	"msfile.dev/labs/webrtc-go/internal/indexdb"
	"msfile.dev/labs/webrtc-go/internal/library"
	"msfile.dev/labs/webrtc-go/internal/metrics"
	"msfile.dev/labs/webrtc-go/internal/msfile"
	"msfile.dev/labs/webrtc-go/internal/safefs"
	"msfile.dev/labs/webrtc-go/internal/seed"
)

// shutdownTimeout 是有界优雅停止的总时限。
const shutdownTimeout = 15 * time.Second

// App 是一个完整装配的 NAS 服务实例。
type App struct {
	cfg     *config.Config
	log     *metrics.Logger
	root    *safefs.Root
	store   *seed.Store
	db      *indexdb.DB
	policy  *auth.Policy
	coord   *library.Coordinator
	reader  *content.Reader
	msfileS *msfile.Server
	host    host.Host
	lock    *os.File

	done        chan struct{}
	stopOnce    sync.Once
	shutdownErr error
}

// New 按冻结顺序完成全部启动装配。
// 使用逆序 cleanup 栈：任何一步失败都会关闭此前创建的全部资源（host/DB/锁等），
// 不留下仍在运行的后台组件。所有可能失败的 listener 都在 coordinator 启动前创建。
func New(cfg *config.Config) (*App, error) {
	if cfg == nil {
		return nil, errors.New("配置错误：Config 不能为空")
	}
	// Load 已经完成完整配置校验；这里再次校验 transport 关系，覆盖测试或
	// 嵌入调用方直接构造 Config 的路径，避免绕过公网地址与 listener 约束。
	if err := cfg.ValidateNetwork(); err != nil {
		return nil, err
	}
	log := metrics.New("nas")
	if strings.TrimSpace(cfg.AdminListen) != "" {
		log.Emit("deprecated_config", map[string]any{
			"field":     "admin_listen",
			"field_zh":  "旧版独立 Web 管理监听地址",
			"reason_zh": "admin_listen 已弃用且被忽略；Web/API 与 WS/WSS 统一使用 listen 中的共享入口",
		})
	}
	app := &App{cfg: cfg, log: log, done: make(chan struct{})}

	// 逆序回滚栈：后创建的先关闭。
	var cleanups []func()
	fail := func(err error) (*App, error) {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
		return nil, err
	}

	// 1. 创建/检查 seed_data 目录结构，并清理上次进程遗留的 staging 临时文件。
	store, err := seed.Open(cfg.SeedData)
	if err != nil {
		return fail(err)
	}
	app.store = store

	// 1b. 安全文件入口（支持挂载延迟就绪的惰性 Root）。
	root, err := safefs.Open(cfg.NASData)
	if err != nil {
		return fail(err)
	}
	app.root = root
	cleanups = append(cleanups, func() { _ = root.Close() })

	// 2. 取得 service.lock：第二个实例必须被拒绝。
	lock, err := acquireServiceLock(filepath.Join(cfg.SeedData, "service.lock"))
	if err != nil {
		return fail(err)
	}
	app.lock = lock
	cleanups = append(cleanups, func() { app.release() })

	// 3. 打开并校验 SQLite schema；旧 schema 在此 fail closed（中文报错，不自动迁移）。
	db, err := indexdb.Open(filepath.Join(cfg.SeedData, "index.sqlite"))
	if err != nil {
		return fail(err)
	}
	app.db = db
	cleanups = append(cleanups, func() { _ = db.Close() })

	// 4. 恢复运行状态：把上次中断遗留的 running 扫描改为 failed，
	//    并把遗留的 indexing 位置转 invalid（下一轮扫描按指纹确认或重建）。
	if err := db.ResetRunningScans(context.Background(), cfg.Clock.Now()); err != nil {
		return fail(fmt.Errorf("恢复扫描状态失败: %w", err))
	}
	if err := db.RecoverStaleIndexing(context.Background(), cfg.Clock.Now()); err != nil {
		return fail(fmt.Errorf("恢复索引任务状态失败: %w", err))
	}

	// 5. 只读 auth policy：白名单只在配置文件中。
	policy, err := auth.NewPolicy(cfg.AccessMode, cfg.PublicKeyWhitelist)
	if err != nil {
		return fail(err)
	}
	app.policy = policy

	// 6. 加载供应商身份。host 先以 NoListenAddrs 构造，避免 listener 在正式
	// /msfile/1.0.0 handler 注册前对外接受请求。
	priv, err := identity.LoadPrivateKeyHexFile(cfg.IdentityKeyFile)
	if err != nil {
		return fail(err)
	}
	pubHex, err := identity.CompressedPublicKeyHex(priv)
	if err != nil {
		return fail(err)
	}
	selfID, err := identity.PeerID(priv)
	if err != nil {
		return fail(err)
	}
	// 7. 协调器先构造（New 不启动任何 goroutine）；内容读取器带标脏联动。
	coord, err := library.New(cfg, db, store, log, root)
	if err != nil {
		return fail(err)
	}
	app.coord = coord
	app.reader = content.New(root, db, store, coord)

	// Web Handler 必须在共享 WebSocket transport 创建前构造；transport 只把
	// 非 Upgrade 请求交给它，Upgrade 请求仍由 libp2p WebSocket transport 接管。
	networkInfo := &admin.NetworkInfo{
		PeerID:                      selfID.String(),
		SupplierPublicKey:           pubHex,
		WebRTCDirectPublicAddresses: cfg.WebRTCDirectPublicAddrs(),
	}
	adminHandler := admin.New(db, coord, admin.Options{
		Reader:                      app.reader,
		AdminToken:                  cfg.AdminToken,
		PeerID:                      selfID.String(),
		PublicKey:                   pubHex,
		WebRTCDirectPublicAddresses: cfg.WebRTCDirectPublicAddrs(),
		NetworkInfo:                 networkInfo,
		AccessMode:                  cfg.AccessMode,
		WhitelistSize:               len(cfg.PublicKeyWhitelist),
		Retention:                   cfg.InvalidRetention.Standard(),
		ReadMetrics: func() map[string]uint64 {
			if app.msfileS == nil {
				return map[string]uint64{}
			}
			readMetrics := app.msfileS.ReadMetrics()
			return map[string]uint64{
				"started":   readMetrics.Started,
				"completed": readMetrics.Completed,
				"cancelled": readMetrics.Cancelled,
				"aborted":   readMetrics.Aborted,
			}
		},
	})

	h, err := buildHost(priv, cfg, adminHandler)
	if err != nil {
		return fail(err)
	}
	app.host = h
	cleanups = append(cleanups, func() { _ = h.Close() })

	// 8. 注册正式 /msfile/1.0.0 文件服务（不注册实验协议；仅此一次）。
	// 此时 host 尚未 Listen，因此不会出现“已可连接但协议 handler 尚未注册”的窗口。
	msfileLimits := msfile.DefaultLimits()
	msfileLimits.ReadDelay = cfg.ReadDelay.Standard()
	app.msfileS = msfile.NewServerWithLimits(h, app.reader, policy, log, msfileLimits) // 仅注册一次（阻断 5 清理项）
	// 9. 由 libp2p transport 建立唯一共享入口：普通 HTTP 由 fallback handler
	// 处理，HTTP/1.1 WebSocket Upgrade 由 libp2p WebSocket transport 处理。
	if err := listenHost(h, cfg); err != nil {
		return fail(err)
	}
	completeDirectAddresses, err := runtimeWebRTCDirectAddresses(h, cfg)
	if err != nil {
		return fail(err)
	}
	networkInfo.SetRuntime(runtimeListenAddresses(h), cfg.WebRTCDirectPublicAddrs(), completeDirectAddresses)

	// 10. 全部 listener 已建立且正式协议已注册；此刻才启动协调器（首次全量扫描）。
	coord.Start(context.Background())

	log.Emit("nas_started", map[string]any{
		"local_peer_id":  selfID.String(),
		"public_key_hex": pubHex,
		"access_mode":    cfg.AccessMode,
	})
	fmt.Fprintf(os.Stderr, "NAS PeerId: %s\n", selfID.String())
	if cfg.AccessMode == config.AccessModePublic {
		fmt.Fprintln(os.Stderr, "Web 公共内容索引: 由共享 Web/WS 入口提供（地址请在页面“网络接入地址”区域查看）")
	} else {
		fmt.Fprintln(os.Stderr, "Web 内容索引: public_key_whitelist 白名单模式已关闭")
	}
	return app, nil
}

// Run 阻塞等待 SIGINT/SIGTERM 或外部触发的 Shutdown，然后执行有界优雅停止并返回。
func (a *App) Run(ctx context.Context) error {
	signalCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case <-signalCtx.Done():
	case <-ctx.Done():
	case <-a.done: // Shutdown 已被直接调用（测试或管理编排场景）
	}
	return a.shutdown(shutdownTimeout)
}

// Shutdown 触发有界优雅停止；幂等。与 Run 并发调用安全。
// 内部 shutdown 自身受 timeout 约束必然返回（超时路径会保留 service.lock
// 并启动延迟清理），因此这里直接等待其结果，不与外部 ctx 竞争。
func (a *App) Shutdown(ctx context.Context) error {
	timeout := shutdownTimeout
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	return a.shutdown(timeout)
}

// shutdown 执行一次真正的有序停止；由 stopOnce 保证只执行一遍。
// 全程受 timeout 约束：超时后保留 DB、Root 与 service.lock，避免后台任务仍在访问时释放资源；
// 若强制关闭时后台任务仍未退出则保留锁文件供运维诊断（阻断 4）。
func (a *App) shutdown(timeout time.Duration) error {
	a.stopOnce.Do(func() {
		close(a.done)
		a.log.Emit("nas_stopping", map[string]any{})
		var firstErr error
		record := func(err error) {
			if err != nil && firstErr == nil && !errors.Is(err, http.ErrServerClosed) {
				firstErr = err
			}
		}
		stopCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// 1) host 同时拥有共享 HTTP/WS listener 与 libp2p connection；关闭它
		// 会先停止新的 HTTP/Upgrade 入站，再断开已建立的 libp2p connection。
		if a.host != nil {
			record(a.host.Close())
		}
		// 2) 停止 watcher、周期扫描、Hash worker；未 drain 时不得释放
		//    其仍可能访问的 DB / safefs.Root / service.lock（阻断 5）。
		if !a.coord.Stop(stopCtx) {
			// 启动最终清理 goroutine：任务真正退出后按 Root → DB → lock 顺序释放。
			go func() {
				a.coord.WaitDrained()
				_ = a.db.Close()
				if a.root != nil {
					_ = a.root.Close()
				}
				a.release()
				a.log.Emit("nas_stopped_deferred", map[string]any{
					"reason_zh": "超时后后台任务已全部退出，延迟完成最终清理并释放 service.lock",
				})
			}()
			firstErr = errors.New("停止超时：后台任务未完全退出，service.lock 暂时保留以阻止第二实例")
			a.shutdownErr = firstErr
			return
		}
		// 3) drain SQLite executor 后关闭数据库与安全根。
		record(a.db.Close())
		if a.root != nil {
			record(a.root.Close())
		}
		// 4) 释放 service.lock。
		a.release()
		a.log.Emit("nas_stopped", map[string]any{})
		a.shutdownErr = firstErr
	})
	return a.shutdownErr
}

// release 关闭锁文件句柄并释放 flock；幂等。
func (a *App) release() {
	if a.lock != nil {
		_ = a.lock.Close()
		a.lock = nil
	}
}

// Host 暴露 libp2p host 给测试做端到端连接；业务代码不应使用。
func (a *App) Host() host.Host { return a.host }

// Coordinator 暴露协调器给测试与运维扩展；业务代码不应使用。
func (a *App) Coordinator() *library.Coordinator { return a.coord }

// acquireServiceLock 用文件锁保证同一 seed_data 只有一个服务实例。
func acquireServiceLock(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		return nil, fmt.Errorf("创建 service.lock 失败: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, errors.New("seed_data 已被另一个 msfile-nas 进程持有（service.lock 占用中）；请先停止旧进程，若确认无残留进程再删除该锁文件")
	}
	return file, nil
}

// buildHost 构建带 WebRTC Direct 与 WS/WSS transport 的 libp2p host。
// 不在此阶段 Listen；调用方必须先注册正式协议，再调用 listenHost。
func buildHost(priv crypto.PrivKey, cfg *config.Config, httpHandler http.Handler) (host.Host, error) {
	wsOptions := make([]any, 0, 3)
	wsOptions = append(wsOptions,
		websocket.WithHTTPHandler(httpHandler),
		websocket.WithHTTPServerConfig(func(server *http.Server) {
			// 只限制请求头读取和 keep-alive 空闲时间；不设置 ReadTimeout/
			// WriteTimeout，避免长下载被按请求时限截断。
			server.ReadHeaderTimeout = 10 * time.Second
			server.IdleTimeout = 2 * time.Minute
		}),
	)
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		certificate, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("加载 WSS TLS 证书失败: %w", err)
		}
		wsOptions = append(wsOptions, websocket.WithTLSConfig(&tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		}))
		// WSS 必须显式声明：transport 是否启用 TLS 由 multiaddr 决定，
		// 提供证书不会隐式把 /ws 升级为 /tls/ws（阻断 3）。
		for _, text := range cfg.ListenAddrs {
			text = strings.TrimSpace(text)
			if strings.HasSuffix(text, "/ws") && !strings.HasSuffix(text, "/tls/ws") {
				return nil, fmt.Errorf("配置错误：已配置 TLS 证书时禁止裸 /ws 监听 %q；请显式改为 /tls/ws", text)
			}
		}
	}
	// 全局 connection/stream/内存硬限额：public 模式下攻击者可无限生成新公钥，
	// 资源上限必须由 libp2p ResourceManager 在传输层强制执行。
	rcmgrLimits := rcmgr.DefaultLimits
	rcmgrLimits.SystemBaseLimit.Conns = 256
	rcmgrLimits.SystemBaseLimit.ConnsInbound = 192
	rcmgrLimits.SystemBaseLimit.Streams = 2048
	rcmgrLimits.SystemBaseLimit.StreamsInbound = 1024
	resourceMgr, err := rcmgr.NewResourceManager(rcmgr.NewFixedLimiter(rcmgrLimits.AutoScale()))
	if err != nil {
		return nil, fmt.Errorf("初始化资源管理器失败: %w", err)
	}
	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.NoListenAddrs,
		// MSFile Network V1 明确冻结为 Noise + Yamux。这里必须显式装配，
		// 避免 go-libp2p 默认值未来变化或同时开放 libp2p TLS 等额外协商面。
		libp2p.Security(noise.ID, noise.New),
		libp2p.Muxer(yamux.ID, yamux.DefaultTransport),
		libp2p.Transport(webrtc.New),
		libp2p.Transport(websocket.New, wsOptions...),
		libp2p.ResourceManager(resourceMgr),
	)
	if err != nil {
		return nil, fmt.Errorf("启动 libp2p host 失败: %w", err)
	}
	return h, nil
}

// listenHost 使用已装配完成的 libp2p host 建立全部 listener。
// 共享 Web/WS 入口只由 websocket transport 持有，不再创建独立 net.Listen。
func listenHost(h host.Host, cfg *config.Config) error {
	maddrs := make([]ma.Multiaddr, 0, len(cfg.ListenAddrs))
	for _, text := range cfg.ListenAddrs {
		parsed, err := ma.NewMultiaddr(strings.TrimSpace(text))
		if err != nil {
			return fmt.Errorf("配置错误：listen 中的 multiaddr %q 不合法: %w", text, err)
		}
		maddrs = append(maddrs, parsed)
	}
	if err := h.Network().Listen(maddrs...); err != nil {
		return fmt.Errorf("NAS transport listener 建立失败: %w", err)
	}
	// go-libp2p 的 Swarm.Listen 在“至少一个地址成功”时会返回 nil；
	// NAS 必须保证配置中的每个入口都真实建立，否则会出现 Web 有效而
	// WebSocket 失败（或反过来）的半配置状态。
	actual := h.Network().ListenAddresses()
	if len(actual) != len(maddrs) {
		return fmt.Errorf("NAS transport 监听失败：配置 %d 个 listener，实际运行 %d 个；请检查端口占用和地址配置", len(maddrs), len(actual))
	}
	warnPlainWS(h)
	return nil
}

func runtimeListenAddresses(h host.Host) []string {
	addresses := h.Addrs()
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, address.String())
	}
	return result
}

// runtimeWebRTCDirectAddresses 从运行中的 WebRTC listener 提取唯一 certhash，
// 再把它与 YAML 公网基础地址和 host PeerId 组合。公网基础地址永不从本机地址推导。
func runtimeWebRTCDirectAddresses(h host.Host, cfg *config.Config) ([]string, error) {
	publicBases := cfg.WebRTCDirectPublicAddrs()
	if len(publicBases) == 0 {
		return []string{}, nil
	}
	var certhash string
	for _, address := range h.Addrs() {
		hasDirect := false
		for _, protocol := range address.Protocols() {
			if protocol.Code == ma.P_WEBRTC_DIRECT {
				hasDirect = true
				break
			}
		}
		if !hasDirect {
			continue
		}
		value, err := address.ValueForProtocol(ma.P_CERTHASH)
		if err != nil || strings.TrimSpace(value) == "" {
			return nil, errors.New("WebRTC Direct listener 未提供运行时 certhash，无法生成公网接入地址")
		}
		if certhash == "" {
			certhash = value
		} else if certhash != value {
			return nil, errors.New("多个 WebRTC Direct listener 产生了不一致的 certhash，拒绝公布不确定地址")
		}
	}
	if certhash == "" {
		return nil, errors.New("配置了 webrtc_direct_public_addresses，但运行中没有 WebRTC Direct listener")
	}
	addresses, err := config.CompleteWebRTCDirectAddresses(publicBases, certhash, h.ID().String())
	if err != nil {
		return nil, fmt.Errorf("生成 WebRTC Direct 公网接入地址失败: %w", err)
	}
	return addresses, nil
}

// warnPlainWS 对非 loopback 的裸 WS 监听输出中文提醒：生产公网必须 WSS。
// 与是否配置 TLS 证书无关——证书不会隐式升级监听。
func warnPlainWS(h host.Host) {
	for _, addr := range h.Addrs() {
		hasWS := false
		hasTLS := false
		loopbackOnly := true
		for _, protocol := range addr.Protocols() {
			switch protocol.Code {
			case ma.P_WS:
				hasWS = true
			case ma.P_TLS, ma.P_WSS:
				hasTLS = true
			case ma.P_IP4, ma.P_IP6:
				value, valueErr := addr.ValueForProtocol(protocol.Code)
				if valueErr != nil {
					continue
				}
				if ip := net.ParseIP(value); ip != nil && !ip.IsLoopback() {
					loopbackOnly = false
				}
			case ma.P_DNS, ma.P_DNS4, ma.P_DNS6:
				// DNS listener 的最终绑定范围不能在这里静态证明是 loopback。
				loopbackOnly = false
			}
		}
		if hasWS && !hasTLS && !loopbackOnly {
			logger := metrics.New("nas")
			logger.Emit("ws_non_loopback", map[string]any{
				"reason_zh": "检测到非 loopback 的裸 WS 监听；生产公网部署必须使用 tls/ws（WSS），请确认当前是可信内网",
			})
			return
		}
	}
}

// ServiceMultiaddrs 返回附带 PeerId 的对外服务地址列表（仅 webrtc-direct/ws/wss）。
func ServiceMultiaddrs(h host.Host) []string {
	var out []string
	for _, addr := range h.Addrs() {
		for _, p := range addr.Protocols() {
			if p.Code == ma.P_WEBRTC_DIRECT || p.Code == ma.P_WS {
				out = append(out, fmt.Sprintf("%s/p2p/%s", addr.String(), h.ID().String()))
				break
			}
		}
	}
	return out
}
