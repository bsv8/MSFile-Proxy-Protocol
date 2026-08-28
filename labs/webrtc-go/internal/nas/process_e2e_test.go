package nas

// 进程级端到端冒烟：用真实二进制 + YAML 配置在本地目录上跑通
// “启动 → 首次扫描 → WS 读取（Seed 与块逐个 SHA-256 校验）→ SIGTERM 优雅停止
// → nas_data 零写入”的完整链路。这是施工单 §10 中可自动化的部分；
// 目标 NAS 挂载类型的人工验证见 docs/施工单/20260825-3-NAS挂载人工验收清单.md。

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	websocket "github.com/libp2p/go-libp2p/p2p/transport/websocket"
	ma "github.com/multiformats/go-multiaddr"

	"msfile.dev/labs/webrtc-go/internal/msfile"
	"msfile.dev/labs/webrtc-go/internal/seed"
)

type smokeCounts struct {
	ReadyContents int64 `json:"ready_contents"`
}

type smokeStatus struct {
	Counts          smokeCounts `json:"counts"`
	ScanRunning     bool        `json:"scan_running"`
	PeerID          string      `json:"peer_id"`
	ListenAddresses []string    `json:"listen_addresses"`
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// treeDigest 记录相对路径 → 模式:尺寸:mtime纳秒:sha256，用于零写入断言。
func treeDigest(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		sum := sha256.Sum256(data)
		out[filepath.ToSlash(rel)] = fmt.Sprintf("%s:%d:%d:%s",
			info.Mode(), info.Size(), info.ModTime().UnixNano(), hex.EncodeToString(sum[:]))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *syncBuffer) recent(n int) string {
	str := s.String()
	if len(str) <= n {
		return str
	}
	return str[len(str)-n:]
}

// TestProcessLevelSmokeOnLocalDirectory 覆盖 §10 可自动化子集。
func TestProcessLevelSmokeOnLocalDirectory(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过进程级冒烟")
	}
	dir := t.TempDir()
	nasRoot := filepath.Join(dir, "nas_data")

	movie := make([]byte, 700*1024) // 跨 3 个块
	for i := range movie {
		movie[i] = byte(i*13 + 5)
	}
	files := map[string][]byte{
		filepath.Join("电影", "movie.mkv"):       movie,
		filepath.Join("音乐", "专辑", "song.flac"): bytes.Repeat([]byte{0x33}, 300*1024),
		filepath.Join("文档", "empty.txt"):       {},
	}
	for rel, data := range files {
		full := filepath.Join(nasRoot, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o640); err != nil {
			t.Fatal(err)
		}
	}

	// 客户端身份先生成，公钥写进白名单。
	clientPriv, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubRaw, err := clientPriv.GetPublic().Raw()
	if err != nil {
		t.Fatal(err)
	}

	// 验收工具使用独立身份：两把公钥都进入白名单。
	toolPriv, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	toolPubRaw, err := toolPriv.GetPublic().Raw()
	if err != nil {
		t.Fatal(err)
	}

	serverKeyPath := filepath.Join(dir, "identity.key")
	sk := make([]byte, 32)
	if _, err := rand.Read(sk); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(serverKeyPath, []byte(hex.EncodeToString(sk)), 0o600); err != nil {
		t.Fatal(err)
	}

	wsPort := freePort(t)
	cfgText := fmt.Sprintf(`# 进程级冒烟配置（自动生成）
identity_key_file: %q

# 用户原目录；服务只读
nas_data: %q

# 派生数据区；可从 nas_data 重建
seed_data: %q

access_mode: private
public_key_whitelist:
  - "%s"
  - "%s"

full_scan_interval: 1h
file_stable_interval: 100ms
invalid_retention: 24h
hash_workers: 1

listen:
  - "/ip4/127.0.0.1/tcp/%d/ws"
admin_listen: "127.0.0.1:%d"
admin_token: "process-test-token"
`,
		serverKeyPath,
		nasRoot,
		filepath.Join(dir, "seed_data"),
		hex.EncodeToString(pubRaw),
		hex.EncodeToString(toolPubRaw),
		wsPort, wsPort)
	cfgPath := filepath.Join(dir, "msfile-nas.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgText), 0o600); err != nil {
		t.Fatal(err)
	}

	binPath := filepath.Join(dir, "msfile-nas")
	build := exec.Command("go", "build", "-o", binPath, "./cmd/msfile-nas")
	build.Dir = "../.."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("构建失败: %v\n%s", err, out)
	}

	before := treeDigest(t, nasRoot)

	cmd := exec.Command(binPath, "--config", cfgPath)
	var stdout syncBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	base := fmt.Sprintf("http://127.0.0.1:%d", wsPort)
	readyDeadline := time.Now().Add(45 * time.Second)
	ready := false
	var serviceStatus smokeStatus
	for time.Now().Before(readyDeadline) {
		req, reqErr := http.NewRequest(http.MethodGet, base+"/api/status", nil)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		req.Header.Set("Authorization", "Bearer process-test-token")
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			var sr smokeStatus
			derr := json.NewDecoder(resp.Body).Decode(&sr)
			resp.Body.Close()
			if derr == nil && !sr.ScanRunning && sr.Counts.ReadyContents == 3 {
				serviceStatus = sr
				ready = true
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("首次扫描未在时限内完成三个内容索引；最近日志:\n%s", stdout.recent(2048))
	}

	if strings.Contains(stdout.String(), "NAS MSFile multiaddr（可复制）") {
		t.Fatal("启动日志不应输出可复制的 multiaddr")
	}

	// 从受保护的 status 读取本机真实 listener，再附加运行中 PeerId。
	addrLine := ""
	for _, address := range serviceStatus.ListenAddresses {
		if strings.HasSuffix(address, "/ws") {
			addrLine = address + "/p2p/" + serviceStatus.PeerID
			break
		}
	}
	if addrLine == "" {
		t.Fatalf("未能从日志解析服务地址:\n%s", stdout.recent(2048))
	}
	maddr, err := ma.NewMultiaddr(addrLine)
	if err != nil {
		t.Fatal(err)
	}
	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		t.Fatal(err)
	}

	clientHost, err := libp2p.New(
		libp2p.Identity(clientPriv),
		libp2p.NoListenAddrs,
		libp2p.Transport(websocket.New),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer clientHost.Close()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer dialCancel()
	if err := clientHost.Connect(dialCtx, *info); err != nil {
		t.Fatalf("WS 连接失败: %v", err)
	}

	newStream := func() network.Stream {
		st, serr := clientHost.NewStream(dialCtx, info.ID, protocol.ID(msfile.ProtocolID))
		if serr != nil {
			t.Fatal(serr)
		}
		return st
	}

	resMovie, err := seed.Build(bytes.NewReader(movie), "movie.mkv")
	if err != nil {
		t.Fatal(err)
	}
	var movieHash [32]byte
	copy(movieHash[:], resMovie.SeedHash[:])

	// Stat：available。
	st := newStream()
	if err := msfile.EncodeRequest(st, []any{uint64(1), uint64(1), uint64(1), movieHash[:]}); err != nil {
		t.Fatal(err)
	}
	_ = st.CloseWrite() // 半关：服务端读完即释放角色，响应仍完整送达
	fields, err := msfile.DecodeResponseFields(st)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 7 || fields[3] != uint64(1) {
		t.Fatalf("Stat 应 available: %#v", fields)
	}
	_ = st.Close()

	// Read：Seed 与每个块都做 SHA-256 校验。
	readVerified := func(hash [32]byte, id uint64) []byte {
		st := newStream()
		defer st.Close()
		if err := msfile.EncodeRequest(st, []any{uint64(1), uint64(3), id, hash[:], uint64(0)}); err != nil {
			t.Fatal(err)
		}
		_ = st.CloseWrite()
		f, derr := msfile.DecodeResponseFields(st)
		if derr != nil {
			t.Fatal(derr)
		}
		if len(f) != 5 || f[1] != uint64(4) {
			t.Fatalf("期望 ReadResponse，实际 %#v", f)
		}
		length := f[4].(uint64)
		data := make([]byte, length)
		if _, err := io.ReadFull(st, data); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if sum != hash {
			t.Fatalf("SHA-256 不匹配请求哈希（len=%d）", length)
		}
		return data
	}
	if got := readVerified(movieHash, 100); !bytes.Equal(got, resMovie.Seed) {
		t.Fatal("Seed 字节与预期不一致")
	}
	for _, block := range resMovie.Blocks {
		var bh [32]byte
		copy(bh[:], block.Hash[:])
		data := readVerified(bh, uint64(200+block.Index))
		if len(data) != block.Length {
			t.Fatalf("块 %d 长度不符: %d != %d", block.Index, len(data), block.Length)
		}
	}

	// 验收客户端子命令冒烟：用 msfile-acceptance 以独立身份完成 stat 与 read --verify。
	accPath := filepath.Join(dir, "msfile-acceptance")
	buildAcc := exec.Command("go", "build", "-o", accPath, "./cmd/msfile-acceptance")
	buildAcc.Dir = "../.."
	if out, err := buildAcc.CombinedOutput(); err != nil {
		t.Fatalf("构建验收客户端失败: %v\n%s", err, out)
	}
	toolKeyPath := filepath.Join(dir, "tool.key")
	toolRaw, err := toolPriv.Raw()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(toolKeyPath, []byte(hex.EncodeToString(toolRaw)), 0o600); err != nil {
		t.Fatal(err)
	}

	runAcc := func(args ...string) string {
		c := exec.Command(accPath, args...)
		c.Env = append(os.Environ(), "GOCACHE="+filepath.Join(dir, "gocache"))
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("验收客户端执行失败 %v:\n%s\n--- 服务端日志 ---\n%s", err, out, stdout.recent(16000))
		}
		return string(out)
	}
	movieHashHex := hex.EncodeToString(movieHash[:])
	_ = runAcc("--addr", addrLine, "--identity-key", toolKeyPath,
		"stat", "--hash", movieHashHex)
	seedOut := filepath.Join(dir, "smoke-seed.bin")
	_ = runAcc("--addr", addrLine, "--identity-key", toolKeyPath,
		"read", "--hash", movieHashHex, "--output", seedOut, "--verify")
	written, err := os.ReadFile(seedOut)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written, resMovie.Seed) {
		t.Fatal("验收客户端写出的 Seed 与预期不一致")
	}

	// keygen 行为冒烟：排他创建 + 0600 + 二次拒绝。
	keygenPath := filepath.Join(dir, "gen.key")
	_ = runAcc("keygen", "--identity-key", keygenPath)
	if info, err := os.Stat(keygenPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("keygen 权限应为 0600，实际 %v / err=%v", info, err)
	}
	accFail := exec.Command(accPath, "keygen", "--identity-key", keygenPath)
	if out, err := accFail.CombinedOutput(); err == nil {
		t.Fatalf("keygen 二次执行应失败:\n%s", out)
	} else if !strings.Contains(string(out), "拒绝覆盖") {
		t.Fatalf("二次 keygen 错误信息缺少拒绝覆盖提示:\n%s", out)
	}

	// verify-file：跨块文件逐块校验并重构原文件（阻断 3）。
	rebuild := filepath.Join(dir, "reconstructed.mkv")
	verifyJSON := runAcc("--addr", addrLine, "--identity-key", toolKeyPath,
		"verify-file", "--seed-hash", movieHashHex, "--output", rebuild)
	var vf struct {
		SeedOK        bool     `json:"seed_ok"`
		BlockTotal    int      `json:"block_total"`
		BlockOK       int      `json:"block_ok"`
		FailedHashes  []string `json:"failed_hashes"`
		OutputFile    string   `json:"output_file"`
		BytesVerified int64    `json:"bytes_verified"`
	}
	jsonPart := verifyJSON[strings.Index(verifyJSON, "{"):] // 剥离 stderr 中文字段说明行
	if err := json.Unmarshal([]byte(jsonPart), &vf); err != nil {
		t.Fatalf("verify-file 输出解析失败: %v\n%s", err, verifyJSON)
	}
	if !vf.SeedOK || vf.BlockTotal != 3 || vf.BlockOK != 3 || len(vf.FailedHashes) != 0 {
		t.Fatalf("verify-file 结果不符: %+v", vf)
	}
	rebuilt, err := os.ReadFile(rebuild)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rebuilt, movie) {
		t.Fatal("verify-file 重构的原文件与 nas_data 原始字节不一致")
	}

	// load 冒烟：单连接长驻 READ stream 循环读取真实块，
	// 断言无 wrong_stream_role、attempted==ok（正常负载）。
	loadJSON := runAcc("--addr", addrLine, "--identity-key", toolKeyPath,
		"load", "--seed-hash", movieHashHex,
		"--connections", "1", "--requests-per-block", "2", "--duration", "20s")
	var lr struct {
		PlannedRequests   int            `json:"planned_requests"`
		AttemptedRequests int            `json:"attempted_requests"`
		OK                int            `json:"ok"`
		ErrorCodes        map[string]int `json:"error_codes"`
		ThroughputMBps    float64        `json:"throughput_mbps"`
	}
	loadPart := loadJSON[strings.Index(loadJSON, "{"):]
	if err := json.Unmarshal([]byte(loadPart), &lr); err != nil {
		t.Fatalf("load 输出解析失败: %v\n%s", err, loadJSON)
	}
	if lr.ErrorCodes["wrong_stream_role"] != 0 {
		t.Fatalf("正常负载不得出现 wrong_stream_role：%+v", lr.ErrorCodes)
	}
	if lr.OK != lr.AttemptedRequests || lr.AttemptedRequests <= 0 {
		t.Fatalf("正常负载下 ok 应等于 attempted：%+v", lr)
	}

	// SIGTERM：有界优雅停止且退出码为 0。
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case werr := <-done:
		if code := exitCodeOf(werr); code != 0 {
			t.Fatalf("优雅停止退出码异常（%d）: %v", code, werr)
		}
	case <-time.After(shutdownTimeout + 10*time.Second):
		t.Fatal("SIGTERM 后超时未退出")
	}

	after := treeDigest(t, nasRoot)
	if !mapsEqual(before, after) {
		t.Fatal("服务运行前后 nas_data 发生变化（违反零写入约束）")
	}
	_ = peer.ID("") // 保持 peer 引用使用
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	type exitcoder interface{ ExitCode() int }
	if ec, ok := err.(exitcoder); ok {
		return ec.ExitCode()
	}
	return -1
}
