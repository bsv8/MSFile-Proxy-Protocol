// Package nas 是 MSFile NAS V1 的组合根：
//
//	解析并完整验证配置
//	  -> 创建/检查 seed_data
//	  -> 取得 service.lock
//	  -> 打开并验证 SQLite schema
//	  -> 创建只读 auth policy
//	  -> 恢复未完成 scan/staging
//	  -> 启动 coordinator（安排首次全量扫描）
//	  -> 注册 /msfile/1.0.0
//	  -> 启动 WebRTC Direct + WS/WSS listener
//	  -> 启动 Web 管理面
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
	cfg      *config.Config
	log      *metrics.Logger
	root     *safefs.Root
	store    *seed.Store
	db       *indexdb.DB
	policy   *auth.Policy
	coord    *library.Coordinator
	reader   *content.Reader
	msfileS  *msfile.Server
	host     host.Host
	adminSv  *http.Server
	adminLn  net.Listener
	serveErr chan error
	lock     *os.File

	done        chan struct{}
	stopOnce    sync.Once
	shutdownErr error
}

// New 按冻结顺序完成全部启动装配。
// 使用逆序 cleanup 栈：任何一步失败都会关闭此前创建的全部资源（host/DB/锁等），
// 不留下仍在运行的后台组件。所有可能失败的 listener 都在 coordinator 启动前创建。
func New(cfg *config.Config) (*App, error) {
	log := metrics.New("nas")
	app := &App{cfg: cfg, log: log, done: make(chan struct{}), serveErr: make(chan error, 1)}

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

	// 6. 加载供应商身份并构建 libp2p host（WebRTC Direct + WS/WSS listener 在此绑定）。
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
	h, err := buildHost(priv, cfg)
	if err != nil {
		return fail(err)
	}
	app.host = h
	cleanups = append(cleanups, func() { _ = h.Close() })

	// 7. 协调器先构造（New 不启动任何 goroutine）；内容读取器带标脏联动。
	coord, err := library.New(cfg, db, store, log, root)
	if err != nil {
		return fail(err)
	}
	app.coord = coord
	app.reader = content.New(root, db, store, coord)

	// 8. 注册正式 /msfile/1.0.0 文件服务（不注册实验协议；仅此一次）。
	app.msfileS = msfile.NewServer(h, app.reader, policy, log) // 仅注册一次（阻断 5 清理项）
	adminHandler := admin.New(db, coord, admin.Options{
		AdminToken:    cfg.AdminToken,
		PeerID:        selfID.String(),
		PublicKey:     pubHex,
		Addresses:     ServiceMultiaddrs(h),
		AccessMode:    cfg.AccessMode,
		WhitelistSize: len(cfg.PublicKeyWhitelist),
		Retention:     cfg.InvalidRetention.Standard(),
	})
	adminListener, err := net.Listen("tcp", cfg.AdminListen)
	if err != nil {
		return fail(fmt.Errorf("Web 管理台监听 %s 失败: %w", cfg.AdminListen, err))
	}
	app.adminLn = adminListener
	app.adminSv = &http.Server{
		Handler:           adminHandler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	// 10. 全部可能失败的步骤已完成；此刻才启动协调器（首次全量扫描）与 Serve。
	coord.Start(context.Background())
	go func() { app.serveErr <- app.adminSv.Serve(adminListener) }()

	log.Emit("nas_started", map[string]any{
		"local_peer_id":  selfID.String(),
		"public_key_hex": pubHex,
		"access_mode":    cfg.AccessMode,
	})
	fmt.Fprintf(os.Stderr, "NAS PeerId: %s\n", selfID.String())
	for _, address := range ServiceMultiaddrs(h) {
		fmt.Fprintf(os.Stderr, "NAS MSFile multiaddr（可复制）: %s\n", address)
	}
	fmt.Fprintf(os.Stderr, "Web 管理台: http://%s\n", cfg.AdminListen)
	return app, nil
}

// adminStubCoordinator 仅在装配早期占位：真实协调器启动后由 New 替换为最终 handler 所用对象。
// 由于 Serve 在协调器启动之后才开始接受请求，该桩不会被实际业务调用触达。
type adminStubCoordinator struct{}

func (a *adminStubCoordinator) QueueDepth() int       { return 0 }
func (a *adminStubCoordinator) Scanning() bool        { return false }
func (a *adminStubCoordinator) TriggerFullScan() bool { return false }

// Run 阻塞等待 SIGINT/SIGTERM 或外部触发的 Shutdown，然后执行有界优雅停止并返回。
func (a *App) Run(ctx context.Context) error {
	signalCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case <-signalCtx.Done():
	case <-ctx.Done():
	case <-a.done: // Shutdown 已被直接调用（测试或管理编排场景）
	case err := <-a.serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			// 管理 Serve 非预期退出：立即有界停止全部资源并把错误上抛。
			a.shutdown(shutdownTimeout)
			return fmt.Errorf("Web 管理服务异常退出: %w", err)
		}
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
// 全程受 timeout 约束：超时后强制关闭管理 listener 并继续释放其余资源；
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

		// 1) 停止接受新管理请求；超时则强制关闭 listener。
		if a.adminSv != nil {
			if serveDone := make(chan struct{}); serveDone != nil {
				go func() {
					record(a.adminSv.Shutdown(stopCtx))
					close(serveDone)
				}()
				select {
				case <-serveDone:
				case <-stopCtx.Done():
					if a.adminLn != nil {
						_ = a.adminLn.Close()
					}
					<-serveDone
					firstErr = errors.New("Web 管理台停止超时，已强制关闭监听")
				}
			}
		}
		// 2) 停止接受新 libp2p stream 并断开连接。
		if a.host != nil {
			record(a.host.Close())
		}
		// 3) 停止 watcher、周期扫描、Hash worker；未 drain 时不得释放
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
		// 4) drain SQLite executor 后关闭数据库与安全根。
		record(a.db.Close())
		if a.root != nil {
			record(a.root.Close())
		}
		// 5) 释放 service.lock。
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

// Coordinator 暴露协调器给测试与管理扩展；业务代码不应使用。
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
func buildHost(priv crypto.PrivKey, cfg *config.Config) (host.Host, error) {
	maddrs := make([]ma.Multiaddr, 0, len(cfg.ListenAddrs))
	for _, text := range cfg.ListenAddrs {
		parsed, err := ma.NewMultiaddr(text)
		if err != nil {
			return nil, fmt.Errorf("listen 中的 multiaddr %q 不合法: %w", text, err)
		}
		maddrs = append(maddrs, parsed)
	}
	wsOptions := make([]any, 0, 1)
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
		libp2p.ListenAddrs(maddrs...),
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
	warnPlainWS(h, cfg)
	return h, nil
}

// warnPlainWS 对非 loopback 的裸 WS 监听输出中文提醒：生产公网必须 WSS。
// 与是否配置 TLS 证书无关——证书不会隐式升级监听。
func warnPlainWS(h host.Host, cfg *config.Config) {
	for _, addr := range h.Addrs() {
		hasWS := false
		loopbackOnly := true
		for _, protocol := range addr.Protocols() {
			value, valueErr := addr.ValueForProtocol(protocol.Code)
			if valueErr != nil {
				continue
			}
			switch protocol.Code {
			case ma.P_WS:
				hasWS = true
			case ma.P_IP4, ma.P_IP6:
				if ip := net.ParseIP(value); ip != nil && !ip.IsLoopback() {
					loopbackOnly = false
				}
			}
		}
		if hasWS && !loopbackOnly {
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
