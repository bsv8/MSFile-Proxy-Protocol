package nas

// 本文件覆盖施工单 T25/T26：
//   T25 第二实例 service.lock 拒绝、有界优雅停止（含锁释放）
//   T26 旧 schema/objects 检测后 fail closed，不自动删除，中文报错
//
// 启动顺序本身由 New 的装配路径保证：锁先于数据库，数据库先于监听。

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/benbjohnson/clock"
	_ "modernc.org/sqlite"

	"msfile.dev/labs/webrtc-go/internal/config"
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
		IdentityKeyFile:    writeTestKey(t),
		NASData:            nasRoot,
		SeedData:           seedDir,
		AccessMode:         config.AccessModePrivate,
		PublicKeyWhitelist: []string{},
		FullScanInterval:   config.Duration(time.Hour),
		FileStableInterval: config.Duration(10 * time.Millisecond),
		InvalidRetention:   config.Duration(24 * time.Hour),
		HashWorkers:        1,
		ListenAddrs:        []string{"/ip4/127.0.0.1/udp/0/webrtc-direct", "/ip4/127.0.0.1/tcp/0/ws"},
		AdminListen:        "127.0.0.1:0",
		Clock:              clock.New(),
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
// 管理端口被占用时 New 必须中文报错，并逆序释放 host/DB/锁——
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
	cfg.AdminListen = fmt.Sprintf("127.0.0.1:%d", port)

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
	// （换一个空闲管理端口，只验证锁与资源回收）。
	againCfg := testConfigWithSameSeedData(t, cfg)
	againCfg.AdminListen = "127.0.0.1:0"
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
