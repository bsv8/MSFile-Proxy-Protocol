package config

// 本文件覆盖施工单 T01：YAML 配置加载与启动前校验的全部静态分支。
// 只使用标准库 testing 与项目内部包，不引入第三方断言库。

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"

	"msfile.dev/labs/webrtc-go/internal/identity"
)

// layout 描述一组默认可用的本地目录布局。
type layout struct {
	root     string // 测试根目录（t.TempDir()）
	nasDir   string // 用户原文件根目录；必须真实存在才能通过校验
	seedDir  string // 派生数据根目录；故意不预建，由 Load 内部的 MkdirAll 创建
	keyFile  string // 私钥文件路径；Validate 仅 stat 要求存在，不读内容
	certFile string // TLS 证书占位空文件；用于测试缺失/非法证书分支
}

// newLayout 在临时目录中准备 nas 根目录、私钥占位文件与证书占位文件。
func newLayout(t *testing.T) layout {
	t.Helper()
	root := t.TempDir()
	nasDir := filepath.Join(root, "nas")
	// nas_data 必须是已存在的目录
	if err := os.MkdirAll(nasDir, 0o750); err != nil {
		t.Fatalf("创建 nas_data 目录失败: %v", err)
	}
	keyFile := filepath.Join(root, "identity.hex")
	// identity_key_file 只需存在即可，Validate 不会读取其内容
	if err := os.WriteFile(keyFile, nil, 0o600); err != nil {
		t.Fatalf("写入私钥占位文件失败: %v", err)
	}
	certFile := filepath.Join(root, "cert.pem")
	if err := os.WriteFile(certFile, nil, 0o600); err != nil {
		t.Fatalf("写入证书占位文件失败: %v", err)
	}
	return layout{
		root:     root,
		nasDir:   nasDir,
		seedDir:  filepath.Join(root, "seed"),
		keyFile:  keyFile,
		certFile: certFile,
	}
}

// baseYAML 中各可替换行的“标准写法”，供测试按行精准替换制造特定场景。
const (
	lineFullScan   = "full_scan_interval: 10m"  // 周期全量扫描间隔
	lineStable     = "file_stable_interval: 3s" // 文件安静判定窗口
	lineRetention  = "invalid_retention: 24h"   // 派生数据保留时间
	lineHashWorker = "hash_workers: 2"          // Seed 计算 worker 数
	lineWatcherOn  = "enable_file_watcher: true"
	lineAdmin      = `admin_listen: "127.0.0.1:8080"` // 已弃用的旧兼容字段
)

// baseYAML 返回一份带中文注释、全部字段显式给出的合法 private 模式配置文本。
// pubKeys 作为白名单条目；传空时输出空列表。
func (l layout) baseYAML(pubKeys []string) string {
	var b strings.Builder
	b.WriteString("# 中文注释：MSFile NAS 启动配置（测试用）\n")
	fmt.Fprintf(&b, "identity_key_file: %q\n", l.keyFile)
	fmt.Fprintf(&b, "nas_data: %q\n", l.nasDir)
	fmt.Fprintf(&b, "seed_data: %q\n", l.seedDir)
	b.WriteString(`access_mode: "private"` + "\n")
	if len(pubKeys) > 0 {
		b.WriteString("public_key_whitelist:\n")
		for _, k := range pubKeys {
			fmt.Fprintf(&b, "  - %q\n", k)
		}
	} else {
		b.WriteString("public_key_whitelist: []\n")
	}
	b.WriteString(lineFullScan + "\n")
	b.WriteString(lineStable + "\n")
	b.WriteString(lineRetention + "\n")
	b.WriteString(lineHashWorker + "\n")
	b.WriteString("# 中文注释：公网发布地址只填写 WebRTC Direct 基础段，运行时补齐 certhash/PeerId\n")
	b.WriteString("webrtc_direct_public_addresses:\n")
	b.WriteString("  - \"/ip4/203.0.113.10/udp/4001/webrtc-direct\"\n")
	b.WriteString("listen:\n")
	b.WriteString("  - \"/ip4/127.0.0.1/udp/4001/webrtc-direct\"\n")
	b.WriteString("  - \"/ip4/127.0.0.1/tcp/8080/ws\"\n")
	b.WriteString(lineAdmin + "\n")
	b.WriteString(lineWatcherOn + "\n")
	return b.String()
}

// minimalYAML 只保留四个必填字段，其余全部走默认值逻辑。
func (l layout) minimalYAML() string {
	return fmt.Sprintf(`
# 中文注释：仅必填字段的极简配置
identity_key_file: %q
nas_data: %q
seed_data: %q
access_mode: private
`, l.keyFile, l.nasDir, l.seedDir)
}

// writeConfig 把 YAML 文本写入临时目录并返回配置文件路径。
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写入配置文件失败: %v", err)
	}
	return path
}

// mustLoad 加载成功并返回配置；任何失败都直接终止测试。
func mustLoad(t *testing.T, content string) *Config {
	t.Helper()
	cfg, err := Load(writeConfig(t, content))
	if err != nil {
		t.Fatalf("合法配置加载失败: %v", err)
	}
	return cfg
}

// wantLoadErr 断言配置加载失败，且错误信息包含指定中文子串。
func wantLoadErr(t *testing.T, content, wantSub string) {
	t.Helper()
	if _, err := Load(writeConfig(t, content)); err == nil {
		t.Fatalf("期望加载失败（应包含 %q），但实际成功了", wantSub)
	} else if !strings.Contains(err.Error(), wantSub) {
		t.Fatalf("错误信息缺少子串 %q，实际为: %v", wantSub, err)
	}
}

// replaceLine 把 base 中第一次出现的 old 行替换为 new；找不到则终止测试。
func replaceLine(t *testing.T, base, old, new string) string {
	t.Helper()
	if !strings.Contains(base, old) {
		t.Fatalf("基准 YAML 中找不到待替换行 %q", old)
	}
	return strings.Replace(base, old, new, 1)
}

// newCompressedPubKeyHex 生成一条合法的 66 位 secp256k1 压缩公钥 hex（小写）。
// 通过随机 32 字节标量构造私钥再导出压缩公钥，保证样本真实可用。
func newCompressedPubKeyHex(t *testing.T) string {
	t.Helper()
	for i := 0; i < 8; i++ {
		scalar := make([]byte, identity.Secp256k1PrivKeyLen)
		if _, err := crand.Read(scalar); err != nil {
			t.Fatalf("读取随机数失败: %v", err)
		}
		priv, err := crypto.UnmarshalSecp256k1PrivateKey(scalar)
		if err != nil {
			continue // 极小概率标量越界，重试即可
		}
		pubHex, err := identity.CompressedPublicKeyHex(priv)
		if err != nil {
			continue
		}
		return pubHex
	}
	t.Fatal("多次尝试仍无法生成合法的 secp256k1 压缩公钥")
	return ""
}

// writeValidTLSFiles 生成一对可被 tls.LoadX509KeyPair 解析的测试证书与私钥。
// 证书只用于 --check-config 的静态解析测试，不代表生产证书配置。
func writeValidTLSFiles(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatalf("生成测试 TLS 私钥失败: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "msfile-config-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(crand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("生成测试 TLS 证书失败: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("编码测试 TLS 私钥失败: %v", err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("写入测试 TLS 证书失败: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("写入测试 TLS 私钥失败: %v", err)
	}
	return certPath, keyPath
}

// --- T01 场景开始 -------------------------------------------------------

// 场景 1：合法 private 配置（含中文注释）加载成功；
// 白名单公钥被规范化为小写并去重。
func TestLoadValidPrivateConfigNormalizesWhitelist(t *testing.T) {
	l := newLayout(t)
	k1 := newCompressedPubKeyHex(t)
	k2 := newCompressedPubKeyHex(t)

	// 故意混入大写、首尾空白与重复项，验证规范化与去重
	entries := []string{
		strings.ToUpper(k1),
		"  " + strings.ToUpper(k1) + "  ", // 大写 + 首尾空白 + 与第一项重复
		k1,
		strings.ToUpper(k2[:6]) + k2[6:], // 部分大写
	}
	cfg := mustLoad(t, l.baseYAML(entries))

	if cfg.AccessMode != AccessModePrivate {
		t.Fatalf("access_mode = %q, 期望 %q", cfg.AccessMode, AccessModePrivate)
	}
	want := []string{k1, k2}
	if len(cfg.PublicKeyWhitelist) != len(want) {
		t.Fatalf("白名单去重后应有 %d 项，实际 %d 项: %q", len(want), len(cfg.PublicKeyWhitelist), cfg.PublicKeyWhitelist)
	}
	for i := range want {
		if cfg.PublicKeyWhitelist[i] != want[i] {
			t.Fatalf("白名单第 %d 项 = %q, 期望规范化后的 %q", i+1, cfg.PublicKeyWhitelist[i], want[i])
		}
	}
	// 路径应已被转为绝对路径
	if !filepath.IsAbs(cfg.NASData) || !filepath.IsAbs(cfg.SeedData) {
		t.Fatalf("nas_data/seed_data 应转换为绝对路径: %q / %q", cfg.NASData, cfg.SeedData)
	}
}

// 场景 2：identity_key_file 缺失或是目录时给出中文报错。
func TestLoadIdentityKeyFileValidation(t *testing.T) {
	l := newLayout(t)

	t.Run("字段缺失", func(t *testing.T) {
		content := strings.Replace(l.baseYAML(nil),
			fmt.Sprintf("identity_key_file: %q\n", l.keyFile), "", 1)
		wantLoadErr(t, content, "identity_key_file 不能为空")
	})

	t.Run("指向目录", func(t *testing.T) {
		content := replaceLine(t, l.baseYAML(nil),
			fmt.Sprintf("identity_key_file: %q", l.keyFile),
			fmt.Sprintf("identity_key_file: %q", l.root))
		wantLoadErr(t, content, "identity_key_file 是目录而不是私钥文件")
	})
}

// 场景 3：nas_data 不存在或只是普通文件时报错。
func TestLoadNASDataValidation(t *testing.T) {
	l := newLayout(t)

	t.Run("目录不存在时允许 degraded 启动", func(t *testing.T) {
		content := replaceLine(t, l.baseYAML(nil),
			fmt.Sprintf("nas_data: %q", l.nasDir),
			fmt.Sprintf("nas_data: %q", filepath.Join(l.root, "no-such-nas")))
		cfg, err := Load(writeConfig(t, content))
		if err != nil {
			t.Fatalf("挂载未就绪应以 degraded 状态放行，实际报错: %v", err)
		}
		if !cfg.Degraded() {
			t.Fatal("nas_data 不存在时应标记 Degraded")
		}
	})

	t.Run("是普通文件", func(t *testing.T) {
		content := replaceLine(t, l.baseYAML(nil),
			fmt.Sprintf("nas_data: %q", l.nasDir),
			fmt.Sprintf("nas_data: %q", l.certFile))
		wantLoadErr(t, content, "nas_data 必须是目录")
	})
}

// 场景 4：seed_data 与 nas_data 互相嵌套都必须报错。
func TestLoadRejectsNestedRoots(t *testing.T) {
	l := newLayout(t)

	t.Run("seed 位于 nas 内部", func(t *testing.T) {
		content := replaceLine(t, l.baseYAML(nil),
			fmt.Sprintf("seed_data: %q", l.seedDir),
			fmt.Sprintf("seed_data: %q", filepath.Join(l.nasDir, "nested-seed")))
		wantLoadErr(t, content, "nas_data 与 seed_data 不能互相嵌套")
	})

	t.Run("nas 位于 seed 内部", func(t *testing.T) {
		// 反向嵌套：seed 是 nas 的父目录；nas_data 已存在，满足前置校验
		outer := filepath.Join(l.root, "outer")
		nasInside := filepath.Join(outer, "nas")
		if err := os.MkdirAll(nasInside, 0o750); err != nil {
			t.Fatalf("创建反向嵌套目录失败: %v", err)
		}
		content := l.baseYAML(nil)
		content = replaceLine(t, content,
			fmt.Sprintf("nas_data: %q", l.nasDir),
			fmt.Sprintf("nas_data: %q", nasInside))
		content = replaceLine(t, content,
			fmt.Sprintf("seed_data: %q", l.seedDir),
			fmt.Sprintf("seed_data: %q", outer))
		wantLoadErr(t, content, "nas_data 与 seed_data 不能互相嵌套")
	})
}

// 场景 5：access_mode 只接受 private/public，大小写与其他值一律拒绝。
func TestLoadRejectsInvalidAccessMode(t *testing.T) {
	l := newLayout(t)
	base := l.baseYAML(nil)

	for _, mode := range []string{"Public", "open", "PRIVATE"} {
		content := replaceLine(t, base, `access_mode: "private"`,
			fmt.Sprintf("access_mode: %q", mode))
		wantLoadErr(t, content, "access_mode 只能是 private 或 public")
	}

	// 完全缺失 access_mode 也属于非法值
	content := strings.Replace(base, `access_mode: "private"`+"\n", "", 1)
	wantLoadErr(t, content, "access_mode 只能是 private 或 public")
}

// 场景 6：白名单坏项导致整体启动失败，绝不跳过坏项继续。
func TestLoadWhitelistBadItemAbortsStartup(t *testing.T) {
	l := newLayout(t)
	good := newCompressedPubKeyHex(t)

	cases := []struct {
		name string // 场景名称
		keys []string
	}{
		{"长度不足66位", []string{good[:65]}},
		{"长度超过66位", []string{good + "aa"}},
		{"非hex字符", []string{strings.Repeat("zz", 33)}},
		{"04开头前缀", []string{"04" + strings.Repeat("ab", 32)}},
		{"好项之后跟坏项", []string{good, strings.Repeat("zz", 33)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := l.baseYAML(tc.keys)
			// 任一坏项都会让整个 Load 失败，服务不允许带着残缺白名单启动
			wantLoadErr(t, content, "不是合法的 66 位压缩 secp256k1 公钥 hex")
		})
	}

	// 明确指出坏项位置（从 1 开始计数）
	content := l.baseYAML([]string{good, strings.Repeat("zz", 33)})
	wantLoadErr(t, content, "public_key_whitelist 第 2 项")
}

// 场景 7：未知 YAML 字段在严格模式下直接解析失败。
func TestLoadRejectsUnknownField(t *testing.T) {
	l := newLayout(t)
	content := l.baseYAML(nil) + "unknown_extra_field: 1\n"
	_, err := Load(writeConfig(t, content))
	if err == nil {
		t.Fatal("未知字段应当导致解析失败，但实际成功了")
	}
	msg := err.Error()
	if !strings.Contains(msg, "解析 YAML 配置失败") {
		t.Fatalf("错误应带有中文解析失败前缀，实际为: %v", err)
	}
	if !strings.Contains(msg, "unknown_extra_field") {
		t.Fatalf("错误应指出未知字段名 unknown_extra_field，实际为: %v", err)
	}
}

// 场景 8：显式非正值的时长被自定义 Unmarshal 拒绝。
func TestDurationRejectsNonPositiveValues(t *testing.T) {
	l := newLayout(t)

	t.Run("full_scan_interval 为 0", func(t *testing.T) {
		content := replaceLine(t, l.baseYAML(nil), lineFullScan, "full_scan_interval: 0")
		wantLoadErr(t, content, "必须大于 0")
	})

	t.Run("invalid_retention 为负值", func(t *testing.T) {
		content := replaceLine(t, l.baseYAML(nil), lineRetention, "invalid_retention: -1h")
		wantLoadErr(t, content, "必须大于 0")
	})
}

// 场景 9：未配置的时长/worker/监听地址均落到文档化默认值；
// enable_file_watcher 未配置时默认开启。
func TestDefaultsAppliedWhenFieldsOmitted(t *testing.T) {
	l := newLayout(t)
	cfg := mustLoad(t, l.minimalYAML())

	if got := cfg.FullScanInterval.Standard(); got != 10*time.Minute {
		t.Fatalf("full_scan_interval 默认应为 10m，实际 %v", got)
	}
	if got := cfg.FileStableInterval.Standard(); got != 3*time.Second {
		t.Fatalf("file_stable_interval 默认应为 3s，实际 %v", got)
	}
	if got := cfg.InvalidRetention.Standard(); got != 24*time.Hour {
		t.Fatalf("invalid_retention 默认应为 24h，实际 %v", got)
	}
	if cfg.HashWorkers != MinHashWorkers {
		t.Fatalf("hash_workers 默认应为 %d，实际 %d", MinHashWorkers, cfg.HashWorkers)
	}
	if cfg.AdminListen != "" {
		t.Fatalf("admin_listen 未配置时应保持为空（已弃用且不参与运行），实际 %q", cfg.AdminListen)
	}
	if len(cfg.ListenAddrs) != 1 || cfg.ListenAddrs[0] != "/ip4/127.0.0.1/tcp/8080/ws" {
		t.Fatalf("listen 默认应提供 loopback 共享 Web/WS 地址，实际 %q", cfg.ListenAddrs)
	}
	if !cfg.WatcherEnabled() {
		t.Fatal("enable_file_watcher 未配置时应默认开启")
	}
}

// 场景 10：hash_workers 超出 1..32 范围报错。
func TestHashWorkersBounds(t *testing.T) {
	l := newLayout(t)
	base := l.baseYAML(nil)

	// 注意不能写 MinHashWorkers-1（等于 0，会被默认值逻辑修正为合法值）
	for _, workers := range []int{MaxHashWorkers + 1, -1} { // 上界外 33 与负值 -1
		content := replaceLine(t, base, lineHashWorker,
			fmt.Sprintf("hash_workers: %d", workers))
		wantLoadErr(t, content, fmt.Sprintf("hash_workers 必须在 %d..%d 之间", MinHashWorkers, MaxHashWorkers))
	}
}

// 场景 11：TLS 文件必须成对出现，且成对内容必须能被解析。
func TestTLSCertKeyPairing(t *testing.T) {
	l := newLayout(t)
	base := l.baseYAML(nil)

	t.Run("只配证书", func(t *testing.T) {
		content := base + fmt.Sprintf("tls_cert_file: %q\n", l.certFile)
		wantLoadErr(t, content, "tls_cert_file 与 tls_key_file 必须同时配置")
	})

	t.Run("只配私钥", func(t *testing.T) {
		content := base + fmt.Sprintf("tls_key_file: %q\n", l.certFile)
		wantLoadErr(t, content, "tls_cert_file 与 tls_key_file 必须同时配置")
	})

	t.Run("成对存在通过校验", func(t *testing.T) {
		certFile, keyFile := writeValidTLSFiles(t)
		// /tls/ws 明确表示由 NAS 终止 TLS；--check-config 必须同时验证证书内容。
		tlsBase := replaceLine(t, base, `  - "/ip4/127.0.0.1/tcp/8080/ws"`, `  - "/ip4/127.0.0.1/tcp/8080/tls/ws"`)
		content := tlsBase +
			fmt.Sprintf("tls_cert_file: %q\n", certFile) +
			fmt.Sprintf("tls_key_file: %q\n", keyFile)
		cfg := mustLoad(t, content)
		if cfg.TLSCertFile != certFile || cfg.TLSKeyFile != keyFile {
			t.Fatalf("成对配置应被完整接受: %q / %q", cfg.TLSCertFile, cfg.TLSKeyFile)
		}
	})
}

// 场景 12：admin_listen 仅作为旧配置兼容字段，不能改变实际 listener 或安全校验。
func TestAdminListenIsDeprecatedAndIgnored(t *testing.T) {
	l := newLayout(t)
	base := l.baseYAML(nil)

	t.Run("格式错误也不参与校验", func(t *testing.T) {
		content := replaceLine(t, base, lineAdmin, `admin_listen: "0.0.0.0:8080"`)
		content = replaceLine(t, content, `admin_listen: "0.0.0.0:8080"`, `admin_listen: "不是 host:port"`)
		cfg := mustLoad(t, content)
		if cfg.AdminListen != "不是 host:port" {
			t.Fatalf("旧字段应原样保留供弃用提示，实际 %q", cfg.AdminListen)
		}
	})

	t.Run("旧字段非 loopback 不会放宽共享入口安全校验", func(t *testing.T) {
		content := replaceLine(t, base, lineAdmin,
			`admin_listen: "0.0.0.0:8080"`)
		content = replaceLine(t, content, `  - "/ip4/127.0.0.1/tcp/8080/ws"`, `  - "/ip4/0.0.0.0/tcp/8080/ws"`)
		wantLoadErr(t, content, "listen 中共享 Web/WS 入口监听非 loopback 地址时必须配置 admin_token")
	})
}

// 场景 13：TLS/listener 错配必须在 Load（即 msfile-nas --check-config 路径）阶段失败，
// 不能等到 nas.New/buildHost 才发现。
func TestCheckConfigRejectsTLSListenerMismatch(t *testing.T) {
	l := newLayout(t)
	base := l.baseYAML(nil)
	tlsBase := replaceLine(t, base, `  - "/ip4/127.0.0.1/tcp/8080/ws"`, `  - "/ip4/127.0.0.1/tcp/8080/tls/ws"`)

	t.Run("tls/ws 缺少证书私钥", func(t *testing.T) {
		wantLoadErr(t, tlsBase, "/tls/ws（WSS）时必须同时配置")
	})

	t.Run("配置证书但仍使用裸 ws", func(t *testing.T) {
		certFile, keyFile := writeValidTLSFiles(t)
		content := base +
			fmt.Sprintf("tls_cert_file: %q\n", certFile) +
			fmt.Sprintf("tls_key_file: %q\n", keyFile)
		wantLoadErr(t, content, "禁止裸 /ws 监听")
	})

	t.Run("tls/ws 的证书内容非法", func(t *testing.T) {
		content := tlsBase +
			fmt.Sprintf("tls_cert_file: %q\n", l.certFile) +
			fmt.Sprintf("tls_key_file: %q\n", l.certFile)
		wantLoadErr(t, content, "TLS 证书与私钥无法解析")
	})
}

// 场景 13：enable_file_watcher 显式关闭后 WatcherEnabled 返回 false。
func TestWatcherEnabledDefaultAndOverride(t *testing.T) {
	l := newLayout(t)

	t.Run("缺省开启", func(t *testing.T) {
		if !mustLoad(t, l.minimalYAML()).WatcherEnabled() {
			t.Fatal("未配置 enable_file_watcher 时应默认开启")
		}
	})

	t.Run("显式 false 关闭", func(t *testing.T) {
		content := replaceLine(t, l.baseYAML(nil), lineWatcherOn, "enable_file_watcher: false")
		if mustLoad(t, content).WatcherEnabled() {
			t.Fatal("显式 enable_file_watcher: false 后应报告关闭")
		}
	})
}

// 场景 14：非法时长字符串给出中文提示。
func TestDurationInvalidTextGivesChineseHint(t *testing.T) {
	l := newLayout(t)
	content := replaceLine(t, l.baseYAML(nil), lineStable, `file_stable_interval: "10x"`)
	wantLoadErr(t, content, "不合法，应写成例如 300ms、10m、24h")
}
