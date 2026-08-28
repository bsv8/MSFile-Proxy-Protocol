package nas

// 本文件覆盖施工单 T25/T26：
//   T25 第二实例 service.lock 拒绝、有界优雅停止（含锁释放）
//   T26 旧 schema/objects 检测后 fail closed，不自动删除，中文报错
//
// 启动顺序本身由 New 的装配路径保证：锁先于数据库，正式协议注册先于共享 listener。

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"

	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	websocket "github.com/libp2p/go-libp2p/p2p/transport/websocket"
	ma "github.com/multiformats/go-multiaddr"
	_ "modernc.org/sqlite"

	"msfile.dev/labs/webrtc-go/internal/config"
	"msfile.dev/labs/webrtc-go/internal/msfile"
	"msfile.dev/labs/webrtc-go/internal/seed"
)

// writeTestKey 写出一个随机但合法的 32 字节 secp256k1 私钥 hex 文件。
func writeTestKey(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	key := hex.EncodeToString(raw)
	// 保证非零标量（极小概率全零）。
	for i := 0; i < len(key) && key == strings.Repeat("0", 64); i++ {
		key = "01" + key[2:]
	}
	path := filepath.Join(t.TempDir(), "identity.key")
	if err := os.WriteFile(path, []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	nasRoot := filepath.Join(dir, "nas_data")
	seedDir := filepath.Join(dir, "seed_data")
	for _, d := range []string{nasRoot, seedDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	return &config.Config{
		IdentityKeyFile:             writeTestKey(t),
		NASData:                     nasRoot,
		SeedData:                    seedDir,
		AccessMode:                  config.AccessModePrivate,
		PublicKeyWhitelist:          []string{},
		FullScanInterval:            config.Duration(time.Hour),
		FileStableInterval:          config.Duration(10 * time.Millisecond),
		InvalidRetention:            config.Duration(24 * time.Hour),
		HashWorkers:                 1,
		ListenAddrs:                 []string{"/ip4/127.0.0.1/udp/0/webrtc-direct", "/ip4/127.0.0.1/tcp/0/ws"},
		WebRTCDirectPublicAddresses: []string{"/ip4/203.0.113.10/udp/4001/webrtc-direct"},
		AdminListen:                 "127.0.0.1:0",
		Clock:                       clock.New(),
	}
}

// TestSecondInstanceRejectedByServiceLock：第二个实例必须被拒绝，第一个实例不受影响。
func TestSecondInstanceRejectedByServiceLock(t *testing.T) {
	cfg := testConfig(t)
	first, err := New(cfg)
	if err != nil {
		t.Fatalf("第一实例启动失败: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = first.Shutdown(shutdownCtx)
	}()

	second, err := New(testConfigWithSameSeedData(t, cfg))
	if err == nil {
		_ = second.Shutdown(mustTimeoutCtx(t))
		t.Fatal("第二实例应被 service.lock 拒绝")
	}
	if !strings.Contains(err.Error(), "service.lock") && !strings.Contains(err.Error(), "另一个") {
		t.Fatalf("拒绝原因必须是中文锁冲突说明，实际: %v", err)
	}
	// 第一实例仍然健康：协调器可以触发扫描且不 panic。
	if first.Coordinator() == nil || first.Host() == nil {
		t.Fatal("第一实例在第二实例被拒后必须继续正常运行")
	}
}

// TestGracefulShutdownReleasesLock：优雅停止有界完成并释放锁，之后新实例可立即启动。
func TestGracefulShutdownReleasesLock(t *testing.T) {
	cfg := testConfig(t)
	app, err := New(cfg)
	if err != nil {
		t.Fatalf("启动失败: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- app.Run(context.Background()) }()
	// Run 等待信号；直接并发调用 Shutdown 模拟 SIGTERM 后的有界停止路径。
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := app.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("优雅停止失败: %v", err)
	}
	select {
	case runErr := <-done:
		if runErr != nil {
			t.Fatalf("Run 返回错误: %v", runErr)
		}
	case <-time.After(shutdownTimeout + 2*time.Second):
		t.Fatal("优雅停止超时")
	}
	// 锁已释放：同 seed_data 可以再次启动。
	again, err := New(testConfigWithSameSeedData(t, cfg))
	if err != nil {
		t.Fatalf("停止后新实例应能取得锁: %v", err)
	}
	shutdownCtx2, cancel2 := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel2()
	if err := again.Shutdown(shutdownCtx2); err != nil {
		t.Fatalf("第二次停止失败: %v", err)
	}
}

// TestLegacySchemaFailsClosed：旧 objects/clients schema 必须中文报错并拒绝启动，
// 绝不自动删除或原地转换（T26）。
func TestLegacySchemaFailsClosed(t *testing.T) {
	cfg := testConfig(t)
	dbPath := filepath.Join(cfg.SeedData, "index.sqlite")
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`CREATE TABLE clients(public_key TEXT PRIMARY KEY, name TEXT)`)
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	app, err := New(cfg)
	if err == nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = app.Shutdown(shutdownCtx)
		t.Fatal("旧 schema 必须 fail closed 拒绝启动")
	}
	if !strings.Contains(err.Error(), "不兼容") || !strings.Contains(err.Error(), "重新建立") {
		t.Fatalf("必须是中文的不兼容提示并给出重建指引，实际: %v", err)
	}
	// 旧表未被自动删除。
	verify, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer verify.Close()
	var name string
	if err := verify.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='clients'`).Scan(&name); err != nil {
		t.Fatalf("旧表必须原样保留供运维备份，实际: %v", err)
	}
}

func testConfigWithSameSeedData(t *testing.T, base *config.Config) *config.Config {
	t.Helper()
	cloned := *base
	cloned.IdentityKeyFile = writeTestKey(t)
	return &cloned
}

func mustTimeoutCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	t.Cleanup(cancel)
	return ctx
}

// TestAdminPortConflictRollsBackEverything（阻断 4）：
// 共享 Web/WS 端口被占用时 New 必须中文报错，并逆序释放 host/DB/锁——
// 证据是随后同 seed_data 的新实例可以立即取得锁启动。
func TestAdminPortConflictRollsEverythingBack(t *testing.T) {
	// 先占用一个端口。
	squatter, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer squatter.Close()
	port := squatter.Addr().(*net.TCPAddr).Port

	cfg := testConfig(t)
	cfg.ListenAddrs = []string{
		"/ip4/127.0.0.1/udp/0/webrtc-direct",
		fmt.Sprintf("/ip4/127.0.0.1/tcp/%d/ws", port),
	}

	app, err := New(cfg)
	if err == nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = app.Shutdown(shutdownCtx)
		t.Fatal("端口被占用时必须失败")
	}
	if !strings.Contains(err.Error(), "监听") && !strings.Contains(err.Error(), "失败") {
		t.Fatalf("必须是中文的监听失败提示，实际: %v", err)
	}

	// 回滚完整性：锁已释放、DB 已关闭 → 新实例可立即用同一 seed_data 启动
	// （换一个空闲共享入口端口，只验证锁与资源回收）。
	againCfg := testConfigWithSameSeedData(t, cfg)
	againCfg.ListenAddrs = []string{"/ip4/127.0.0.1/udp/0/webrtc-direct", "/ip4/127.0.0.1/tcp/0/ws"}
	again, err := New(againCfg)
	if err != nil {
		t.Fatalf("回滚后新实例应能立即启动（锁与 DB 均已释放），实际: %v", err)
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer stopCancel()
	if err := again.Shutdown(stopCtx); err != nil {
		t.Fatalf("二次实例停止失败: %v", err)
	}
}

// ---------- 阻断 3：正式配置链路的 WSS 装配 ----------

// TestTLSConfigRequiresExplicitWSSListener：配置了证书却仍写裸 /ws 必须拒绝启动，
// 证书不会隐式把 /ws 升级为 /tls/ws。
func TestTLSConfigRequiresExplicitWSSListener(t *testing.T) {
	cfg := testConfig(t)
	certFile, keyFile := writeSelfSignedCert(t)
	cfg.TLSCertFile = certFile
	cfg.TLSKeyFile = keyFile
	cfg.ListenAddrs = []string{"/ip4/127.0.0.1/tcp/0/ws"} // 裸 WS + 证书：非法组合
	cfg.WebRTCDirectPublicAddresses = nil
	if app, err := New(cfg); err == nil {
		_ = app.Shutdown(mustTimeoutCtx(t))
		t.Fatal("证书 + 裸 /ws 的组合必须被拒绝")
	} else if !strings.Contains(err.Error(), "/tls/ws") {
		t.Fatalf("错误信息必须提示显式改写为 /tls/ws，实际: %v", err)
	}
}

// TestFullAssemblyServesStatOverWSS（G08 端到端）：
// 配置 → nas.New → ServiceMultiaddrs 含 /tls/ws → 同一 WSS connection 上分别打开
// Stat/Read 两条 stream，并校验 Seed 与每个文件块的真实 attachment。
func TestFullAssemblyServesStatOverWSS(t *testing.T) {
	cfg := testConfig(t)
	certFile, keyFile := writeSelfSignedCert(t)
	cfg.TLSCertFile = certFile
	cfg.TLSKeyFile = keyFile
	cfg.ListenAddrs = []string{"/ip4/127.0.0.1/udp/0/webrtc-direct", "/ip4/127.0.0.1/tcp/0/tls/ws"}

	// 预置一个可提供的内容，让 Stat 有 available 可断言。
	base := make([]byte, 300000)
	for i := range base {
		base[i] = byte(i * 7)
	}
	if err := os.MkdirAll(filepath.Join(cfg.NASData), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.NASData, "wss-e2e.bin"), base, 0o640); err != nil {
		t.Fatal(err)
	}

	app, err := New(cfg)
	if err != nil {
		t.Fatalf("装配失败: %v", err)
	}
	shutdownOnce := false
	defer func() {
		if !shutdownOnce {
			_ = app.Shutdown(mustTimeoutCtx(t))
		}
	}()

	found := false
	for _, addr := range ServiceMultiaddrs(app.Host()) {
		maddr, merr := ma.NewMultiaddr(addr)
		if merr != nil {
			continue
		}
		hasTLS, hasWS := false, false
		for _, p := range maddr.Protocols() {
			switch p.Code {
			case ma.P_TLS:
				hasTLS = true
			case ma.P_WS:
				hasWS = true
			}
		}
		if hasTLS && hasWS {
			found = true
		}
	}
	if !found {
		t.Fatalf("ServiceMultiaddrs 应包含 /tls/ws 地址: %v", ServiceMultiaddrs(app.Host()))
	}

	// 客户端：InsecureSkipVerify（自签），身份认证只能来自 Noise + PeerId pin。
	clientPriv, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientPubRaw, err := clientPriv.GetPublic().Raw()
	if err != nil {
		t.Fatal(err)
	}
	// 白名单必须包含该客户端；重启服务以加载白名单。
	cfg.PublicKeyWhitelist = []string{hex.EncodeToString(clientPubRaw)}
	_ = app.Shutdown(mustTimeoutCtx(t))
	shutdownOnce = true
	app2, err := New(testConfigWithSameSeedData(t, cfg))
	if err != nil {
		t.Fatalf("带白名单重启失败: %v", err)
	}
	defer func() { _ = app2.Shutdown(mustTimeoutCtx(t)) }()

	clientHost, err := libp2p.New(
		libp2p.Identity(clientPriv),
		libp2p.NoListenAddrs,
		libp2p.Transport(websocket.New, websocket.WithTLSClientConfig(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer clientHost.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := clientHost.Connect(ctx, peer.AddrInfo{ID: app2.Host().ID(), Addrs: app2.Host().Addrs()}); err != nil {
		t.Fatalf("WSS 连接失败: %v", err)
	}
	stream, err := clientHost.NewStream(ctx, app2.Host().ID(), protocol.ID(msfile.ProtocolID))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	res, err := seed.Build(bytes.NewReader(base), "wss-e2e.bin")
	if err != nil {
		t.Fatal(err)
	}
	var hashArr [32]byte
	copy(hashArr[:], res.SeedHash[:])
	// 首次全量扫描异步执行：轮询直到内容 available（或超时）。
	var fields []any
	deadlinePoll := time.Now().Add(8 * time.Second)
	id := uint64(1)
	for {
		if err := msfile.EncodeRequest(stream, []any{uint64(1), uint64(1), id, hashArr[:]}); err != nil {
			t.Fatal(err)
		}
		resp, derr := msfile.DecodeResponseFields(stream)
		if derr != nil {
			t.Fatalf("解码 Stat 响应失败: %v", derr)
		}
		fields = resp
		id++
		if len(fields) == 7 && fields[3] == uint64(1) {
			break
		}
		if time.Now().After(deadlinePoll) {
			t.Fatalf("等待索引完成超时，最后一次响应: %#v", fields)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(fields) != 7 || fields[3] != uint64(1) {
		t.Fatalf("WSS 正式链路 Stat 应回复 available: %#v", fields)
	}

	// Read 使用同一 connection 上的另一条长驻 stream；依次读取 Seed 和全部块，
	// 每个 attachment 都按请求 hash 做 SHA-256 校验，覆盖真实二进制响应而非只测 Header。
	readStream, err := clientHost.NewStream(ctx, app2.Host().ID(), protocol.ID(msfile.ProtocolID))
	if err != nil {
		t.Fatalf("同一 WSS connection 建立独立 Read stream 失败: %v", err)
	}
	if stream.Conn().ID() != readStream.Conn().ID() {
		t.Fatalf("Stat 与 Read 必须复用同一 WSS connection，实际连接不同")
	}
	defer readStream.Close()
	readVerified := func(hash [32]byte, requestID uint64) []byte {
		if err := msfile.EncodeRequest(readStream, []any{uint64(1), uint64(3), requestID, hash[:], uint64(0)}); err != nil {
			t.Fatal(err)
		}
		response, err := msfile.DecodeResponseFields(readStream)
		if err != nil {
			t.Fatalf("解码 WSS Read 响应失败: %v", err)
		}
		if len(response) != 5 || response[1] != uint64(4) {
			t.Fatalf("WSS Read 应回复 ReadResponse，实际 %#v", response)
		}
		responseHash, ok := response[3].([]byte)
		if !ok || !bytes.Equal(responseHash, hash[:]) {
			t.Fatalf("WSS Read 响应 hash 不匹配: %#v", response)
		}
		length, ok := response[4].(uint64)
		if !ok {
			t.Fatalf("WSS Read 响应 content_length 类型错误: %#v", response)
		}
		data := make([]byte, length)
		if _, err := io.ReadFull(readStream, data); err != nil {
			t.Fatalf("读取 WSS Read attachment 失败: %v", err)
		}
		if digest := sha256.Sum256(data); digest != hash {
			t.Fatalf("WSS Read attachment SHA-256 不匹配: len=%d", len(data))
		}
		return data
	}
	if got := readVerified(hashArr, 100); !bytes.Equal(got, res.Seed) {
		t.Fatal("WSS Read 返回的 Seed 与预期不一致")
	}
	for _, block := range res.Blocks {
		var blockHash [32]byte
		copy(blockHash[:], block.Hash[:])
		got := readVerified(blockHash, uint64(200+block.Index))
		if len(got) != block.Length {
			t.Fatalf("WSS Read 块 %d 长度不符: %d != %d", block.Index, len(got), block.Length)
		}
	}
	_ = readStream.CloseWrite()

	// G09：白名单外的真实 secp256k1 客户端不能读取内容。实现允许在 connection
	// 层先完成 Noise，再由 MSFile stream 返回 unauthorized_peer；两种拒绝点都算失败关闭。
	strangerPriv, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	strangerHost, err := libp2p.New(
		libp2p.Identity(strangerPriv),
		libp2p.NoListenAddrs,
		libp2p.Transport(websocket.New, websocket.WithTLSClientConfig(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer strangerHost.Close()
	rejected := false
	if err := strangerHost.Connect(ctx, peer.AddrInfo{ID: app2.Host().ID(), Addrs: app2.Host().Addrs()}); err != nil {
		rejected = true
	} else {
		strangerStream, streamErr := strangerHost.NewStream(ctx, app2.Host().ID(), protocol.ID(msfile.ProtocolID))
		if streamErr != nil {
			rejected = true
		} else {
			if encodeErr := msfile.EncodeRequest(strangerStream, []any{uint64(1), uint64(1), uint64(1), hashArr[:]}); encodeErr != nil {
				rejected = true
			} else {
				_ = strangerStream.CloseWrite()
				denied, decodeErr := msfile.DecodeResponseFields(strangerStream)
				rejected = decodeErr != nil || (len(denied) >= 5 && denied[1] == uint64(255) && denied[4] == "unauthorized_peer")
			}
			_ = strangerStream.Close()
		}
	}
	if !rejected {
		t.Fatal("非白名单 WSS 客户端不应获得 Stat/Read 响应")
	}
}

// writeSelfSignedCert 生成临时自签证书对，返回 (cert, key) 文件路径。
func writeSelfSignedCert(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "msfile-nas-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// ---------- 阻断 5：Stop 超时保留 service.lock，任务退出后才释放 ----------

// TestShutdownTimeoutKeepsServiceLockUntilDrained：
// 用可控阻塞的协调器模拟“NAS IO 永久卡住”：
//  1. Stop 超时 → shutdown 返回错误且 service.lock 未释放（第二实例仍被拒绝）；
//  2. 阻塞解除、后台任务真正退出 → 延迟清理完成，第二实例可以取得锁。
func TestShutdownTimeoutKeepsServiceLockUntilDrained(t *testing.T) {
	cfg := testConfig(t)
	app, err := New(cfg)
	if err != nil {
		t.Fatalf("启动失败: %v", err)
	}

	// 注入一个受控阻塞的伪任务：直接占用协调器的 WaitGroup，
	// 模拟 worker 卡在无法取消的网络 IO 上。
	blocker := make(chan struct{})
	app.coord.InjectBlockedWorkerForTest(blocker)

	// 用极短超时触发 Stop 失败路径。
	stopCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	err = app.Shutdown(stopCtx)
	cancel()
	if err == nil || !strings.Contains(err.Error(), "service.lock") {
		t.Fatalf("超时停止必须报错并提示锁暂保留，实际: %v", err)
	}

	// 第二实例此刻仍必须被锁拒绝。
	if second, serr := New(testConfigWithSameSeedData(t, cfg)); serr == nil {
		_ = second.Shutdown(mustTimeoutCtx(t))
		t.Fatal("未 drain 时第二实例不得取得锁")
	}

	// 解除阻塞：延迟清理完成后锁被释放。
	close(blocker)
	waitDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(waitDeadline) {
		if probe, perr := New(testConfigWithSameSeedData(t, cfg)); perr == nil {
			_ = probe.Shutdown(mustTimeoutCtx(t))
			return // 成功取得锁：延迟清理已生效
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("阻塞解除后迟迟未能重新取得锁，延迟清理未执行")
}
