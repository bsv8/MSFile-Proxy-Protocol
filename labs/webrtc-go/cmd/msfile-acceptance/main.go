// msfile-acceptance 是 NAS 验收客户端：
//
//	msfile-acceptance keygen --identity-key client.key
//	msfile-acceptance [公共参数] stat        --hash <64位hex>
//	msfile-acceptance [公共参数] read       --hash <64位hex> [--output <文件>] [--verify]
//	msfile-acceptance [公共参数] verify-seed --hash <64位hex>
//	msfile-acceptance [公共参数] verify-file --seed-hash <64位hex> [--output 原文件]
//	msfile-acceptance [公共参数] load       --seed-hash <64位hex>
//	                                        [--connections N] [--requests-per-block M]
//	                                        [--duration 30s]
//
// 公共参数：
//
//	--addr          服务端 multiaddr（须带 /p2p/<PeerId>；支持 ws、tls/ws、webrtc-direct）
//	--identity-key  客户端私钥 hex 文件（keygen 子命令生成；缺省随机生成并打印公钥）
//	--tls-insecure  跳过 WSS 证书校验（自签证书环境；身份仍由 Noise+PeerId 保证）
//
// 说明：
//   - keygen 使用 O_EXCL 排他创建并 chmod 0600，绝不覆盖已有私钥；
//   - verify-file 校验 Seed 后逐块读取全部 block_hash 并校验，
//     可选按顺序重构原文件；
//   - load 的每个“连接”是独立的 libp2p host（独立身份与 TCP 连接），
//     各自维持一条长驻 READ stream 顺序读取真实文件块——
//     因此多连接压测要求服务端 public 模式或已把这些临时公钥加入白名单；
//     private 模式请使用 --connections 1。
//
// 子命令输出 JSON 结果（英文键）；stderr 先输出中文字段说明。
// 退出码：0 成功；2 用法/连接错误；1 校验失败或服务端返回错误响应。
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	webrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	websocket "github.com/libp2p/go-libp2p/p2p/transport/websocket"
	ma "github.com/multiformats/go-multiaddr"

	"msfile.dev/labs/webrtc-go/internal/msfile"
)

const usageDoc = `MSFile NAS 验收客户端（子命令与参数详见源码头注释）`

func fatal(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误：%s: %v\n", msg, err)
	} else {
		fmt.Fprintf(os.Stderr, "错误：%s\n", msg)
	}
	os.Exit(1)
}

func exitOnErr(err error) {
	if err == nil {
		return
	}
	if msg := err.Error(); strings.HasPrefix(msg, "server_error:") {
		fmt.Fprintf(os.Stderr, "服务端错误码：%s\n", strings.TrimPrefix(msg, "server_error:"))
		os.Exit(1)
	}
	fatal("执行失败", err)
}

func emit(v any) {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatal("序列化结果失败", err)
	}
	fmt.Println(string(out))
}

func parseHash(s string) ([32]byte, error) {
	var out [32]byte
	clean := strings.ToLower(strings.TrimSpace(s))
	raw, err := hex.DecodeString(clean)
	if err != nil || len(clean) != 64 {
		return out, errors.New("必须是 64 位小写 hex")
	}
	copy(out[:], raw)
	return out, nil
}

// ---------- 身份 ----------

// generateIdentityFile 以排他方式生成私钥文件（0600，绝不覆盖已有文件），
// 返回对应的压缩公钥 hex。
func generateIdentityFile(path string) (string, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	priv, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		file.Close()
		return "", err
	}
	raw, err := priv.Raw()
	if err != nil {
		file.Close()
		return "", err
	}
	if _, err := file.WriteString(hex.EncodeToString(raw) + "\n"); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	return clientPubHex(priv)
}

// loadIdentityFile 读取私钥 hex 文件（容忍末尾换行）。
func loadIdentityFile(path string) (crypto.PrivKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	bin, herr := hex.DecodeString(strings.TrimSpace(string(raw)))
	if herr != nil || len(bin) != 32 {
		return nil, errors.New("私钥文件必须是 32 字节 hex")
	}
	return crypto.UnmarshalSecp256k1PrivateKey(bin)
}

func clientPubHex(priv crypto.PrivKey) (string, error) {
	raw, err := priv.GetPublic().Raw()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// ---------- host / wire ----------

// buildHost 按 --addr 中出现的 transport 建立 host；
// WSS 拨号侧 TLS 必须用 WithTLSClientConfig（WithTLSConfig 只作用于监听侧）。
func buildHost(priv crypto.PrivKey, addr string, tlsInsecure bool) (host.Host, error) {
	maddr, err := ma.NewMultiaddr(addr)
	if err != nil {
		return nil, fmt.Errorf("解析 multiaddr 失败: %w", err)
	}
	hasTLS, hasWS, hasWebRTC := false, false, false
	for _, p := range maddr.Protocols() {
		switch p.Code {
		case ma.P_TLS:
			hasTLS = true
		case ma.P_WS:
			hasWS = true
		case ma.P_WEBRTC_DIRECT:
			hasWebRTC = true
		}
	}
	opts := []libp2p.Option{libp2p.Identity(priv), libp2p.NoListenAddrs}
	if hasWS {
		wsOptions := make([]any, 0, 1)
		if hasTLS {
			wsOptions = append(wsOptions,
				websocket.WithTLSClientConfig(&tls.Config{
					InsecureSkipVerify: tlsInsecure,
					MinVersion:         tls.VersionTLS12,
				}))
		}
		opts = append(opts, libp2p.Transport(websocket.New, wsOptions...))
	}
	if hasWebRTC {
		opts = append(opts, libp2p.Transport(webrtc.New))
	}
	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, err
	}
	return h, nil
}

type client struct {
	h  host.Host
	p  peer.ID
	mu sync.Mutex
	id uint64
}

func newClient(h host.Host, p peer.ID) *client { return &client{h: h, p: p} }

func (c *client) nextID() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.id++
	return c.id
}

// request 打开一条新 stream 发送请求并读回响应（READ 含完整 attachment）。
func (c *client) request(kind uint64, hash [32]byte) ([]any, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	stream, err := c.h.NewStream(ctx, c.p, protocol.ID(msfile.ProtocolID))
	if err != nil {
		return nil, nil, fmt.Errorf("打开 stream 失败: %w", err)
	}
	defer stream.Close()

	id := c.nextID()
	var payload []any
	if kind == msfile.KindStatRequest {
		payload = []any{uint64(1), msfile.KindStatRequest, id, hash[:]}
	} else {
		payload = []any{uint64(1), msfile.KindReadRequest, id, hash[:], uint64(0)}
	}
	if err := msfile.EncodeRequest(stream, payload); err != nil {
		return nil, nil, err
	}
	_ = stream.CloseWrite()

	buffered := bufio.NewReader(stream)
	fields, err := msfile.DecodeResponseFields(buffered)
	if err != nil {
		return nil, nil, err
	}
	if len(fields) >= 5 && fields[1] == uint64(255) {
		code, _ := fields[4].(string)
		return fields, nil, fmt.Errorf("server_error:%s", code)
	}
	var attachment []byte
	if kind == msfile.KindReadRequest {
		if len(fields) != 5 || fields[1] != uint64(4) {
			return fields, nil, fmt.Errorf("期望 ReadResponse，实际 %#v", fields)
		}
		length, ok := fields[4].(uint64)
		if !ok {
			return nil, nil, errors.New("content_length 类型错误")
		}
		attachment = make([]byte, length)
		if _, err := io.ReadFull(buffered, attachment); err != nil {
			return nil, nil, fmt.Errorf("读取 attachment: %w", err)
		}
	}
	return fields, attachment, nil
}

// connWorker 是一条长驻 READ stream 上的顺序请求器：
// 同一 connection 只有一条活动 READ stream（协议 §2.1），
// 帧之间以请求/应答严格串行，不发送 CloseWrite。
type connWorker struct {
	st network.Stream
	br *bufio.Reader
	c  *client
}

func newConnWorker(c *client, hashHint [32]byte) (*connWorker, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	st, err := c.h.NewStream(ctx, c.p, protocol.ID(msfile.ProtocolID))
	if err != nil {
		return nil, err
	}
	w := &connWorker{st: st, br: bufio.NewReader(st), c: c}
	// 发送一个哑请求建立流协商即可？不行——哑请求会消耗序号并被服务端处理。
	// 这里保持惰性：首帧在第一次 readBlock 时发出。
	_ = hashHint
	return w, nil
}

func (w *connWorker) close() { _ = w.st.Close() }

func (w *connWorker) readBlock(id uint64, hash [32]byte) ([]byte, error) {
	payload := []any{uint64(1), msfile.KindReadRequest, id, hash[:], uint64(0)}
	if err := msfile.EncodeRequest(w.st, payload); err != nil {
		return nil, err
	}
	fields, err := msfile.DecodeResponseFields(w.br)
	if err != nil {
		return nil, err
	}
	if len(fields) >= 5 && fields[1] == uint64(255) {
		code, _ := fields[4].(string)
		return nil, fmt.Errorf("server_error:%s", code)
	}
	if len(fields) != 5 || fields[1] != uint64(4) {
		return nil, fmt.Errorf("期望 ReadResponse，实际 %#v", fields)
	}
	length, ok := fields[4].(uint64)
	if !ok {
		return nil, errors.New("content_length 类型错误")
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(w.br, data); err != nil {
		return nil, fmt.Errorf("读取 attachment: %w", err)
	}
	sum := sha256.Sum256(data)
	if sum != hash {
		return nil, fmt.Errorf("server_error:integrity_error(client)")
	}
	return data, nil
}

// ---------- 子命令结果结构 ----------

type statResult struct {
	Available bool   `json:"available"`  // 是否可提供
	Filename  string `json:"filename"`   // 建议文件名
	SizeBytes uint64 `json:"size_bytes"` // 原文件尺寸
	MediaType string `json:"media_type"` // 媒体类型
}

type readResult struct {
	OutputFile    string `json:"output_file"`    // 写入路径（空表示未写盘）
	Bytes         int    `json:"bytes"`          // 内容字节数
	SHA256        string `json:"sha256"`         // 内容摘要
	VerifiedMatch bool   `json:"verified_match"` // --verify 与请求哈希比对结果
}

type verifySeedResult struct {
	SeedOK     bool `json:"seed_ok"`     // SHA-256(内容)==请求哈希 且 32 字节对齐
	SizeBytes  int  `json:"size_bytes"`  // Seed 字节数
	BlockCount int  `json:"block_count"` // 块数 = 字节/32
}

type verifyFileResult struct {
	SeedOK        bool     `json:"seed_ok"`        // Seed 自身校验
	BlockTotal    int      `json:"block_total"`    // 解析出的块总数
	BlockOK       int      `json:"block_ok"`       // 通过校验的块数
	BytesVerified int64    `json:"bytes_verified"` // 已校验字节总数
	FailedHashes  []string `json:"failed_hashes"`  // 失败的块哈希列表
	OutputFile    string   `json:"output_file"`    // 重构的原文件路径（未指定为空）
}

type loadResult struct {
	Connections       int            `json:"connections"`        // 实际建立的独立连接数
	BlocksPerRequest  int            `json:"blocks_per_request"` // 每个请求循环覆盖的块数
	PlannedRequests   int            `json:"planned_requests"`   // 计划请求数
	AttemptedRequests int            `json:"attempted_requests"` // 实际尝试数
	OK                int            `json:"ok"`                 // 成功数（含本地完整性校验通过）
	Bytes             int64          `json:"bytes"`              // 收到字节总数
	ErrorCodes        map[string]int `json:"error_codes"`        // 错误码 -> 次数
	DurationMs        int64          `json:"duration_ms"`
	ThroughputMBps    float64        `json:"throughput_mbps"`
	NoteZh            string         `json:"note_zh"`
}

// ---------- 主流程 ----------

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "缺少子命令；支持 keygen / stat / read / verify-seed / verify-file / load（详见源码头注释）")
		os.Exit(2)
	}
	knownSubs := map[string]bool{
		"keygen": true, "stat": true, "read": true,
		"verify-seed": true, "verify-file": true, "load": true,
	}
	sub := ""
	var rest []string
	if knownSubs[os.Args[1]] {
		sub = os.Args[1]
		rest = os.Args[2:]
	} else {
		for i := 1; i < len(os.Args); i++ {
			if knownSubs[os.Args[i]] {
				sub = os.Args[i]
				rest = append(append([]string{}, os.Args[1:i]...), os.Args[i+1:]...)
				break
			}
		}
	}
	if sub == "" {
		fmt.Fprintln(os.Stderr, "缺少子命令；支持 keygen / stat / read / verify-seed / verify-file / load")
		os.Exit(2)
	}

	fs := flag.NewFlagSet(sub, flag.ExitOnError)
	addr := fs.String("addr", "", "服务端 multiaddr（含 /p2p/<PeerId>）")
	keyFile := fs.String("identity-key", "", "客户端私钥 hex 文件")
	tlsInsecure := fs.Bool("tls-insecure", false, "跳过 WSS 证书校验")
	hashHex := fs.String("hash", "", "内容 Hash（64 位小写 hex）")
	seedHashHex := fs.String("seed-hash", "", "[verify-file/load] Seed Hash（64 位小写 hex）")
	output := fs.String("output", "", "[read/verify-file] 输出文件路径")
	verify := fs.Bool("verify", false, "[read] 校验 SHA-256(内容)==--hash")
	conns := fs.Int("connections", 8, "[load] 独立连接数（每条独立身份与 TCP 连接）")
	rpb := fs.Int("requests-per-block", 4, "[load] 每个块的重复读取次数")
	duration := fs.Duration("duration", 30*time.Second, "[load] 总时长上限")

	switch sub {
	case "keygen":
		if err := fs.Parse(rest); err != nil {
			os.Exit(2)
		}
		if *keyFile == "" {
			fatal("keygen 必须提供 --identity-key 输出路径", nil)
		}
		pub, err := generateIdentityFile(*keyFile)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				fatal("私钥文件已存在，拒绝覆盖（如需更换请先手工删除）", nil)
			}
			fatal("生成私钥失败", err)
		}
		info, _ := os.Stat(*keyFile)
		fmt.Fprintf(os.Stderr, "identity_key_file=%s\nmode=%s\n", *keyFile, info.Mode())
		emit(map[string]string{"client_public_key_hex": pub})
		return
	case "stat", "read", "verify-seed", "verify-file", "load":
	default:
		fmt.Fprintf(os.Stderr, "未知子命令 %q\n", sub)
		os.Exit(2)
	}
	if err := fs.Parse(rest); err != nil {
		os.Exit(2)
	}

	var hashArr [32]byte
	var seedArr [32]byte
	hasHash := *hashHex != ""
	var perr error
	if sub == "load" {
		if *seedHashHex == "" {
			fmt.Fprintln(os.Stderr, "load 必须提供 --seed-hash（将自动解析全部块并逐块校验）")
			os.Exit(2)
		}
		seedArr, perr = parseHash(*seedHashHex)
		exitOnErr(perr)
	} else if sub == "verify-file" {
		if *seedHashHex == "" {
			fmt.Fprintln(os.Stderr, "verify-file 必须提供 --seed-hash")
			os.Exit(2)
		}
		seedArr, perr = parseHash(*seedHashHex)
		exitOnErr(perr)
		if hasHash {
			fmt.Fprintln(os.Stderr, "提示：verify-file 以 --seed-hash 为准，忽略 --hash")
		}
	} else {
		if !hasHash {
			fmt.Fprintln(os.Stderr, "必须提供 --hash")
			fs.Usage()
			os.Exit(2)
		}
		hashArr, perr = parseHash(*hashHex)
		exitOnErr(perr)
	}

	// 身份：指定文件则加载（必须已由 keygen 生成）；否则随机生成。
	var priv crypto.PrivKey
	if *keyFile != "" {
		loaded, lerr := loadIdentityFile(*keyFile)
		exitOnErr(lerr)
		priv = loaded
	} else {
		generated, _, gerr := crypto.GenerateSecp256k1Key(rand.Reader)
		exitOnErr(gerr)
		priv = generated
	}
	pubHex, pubErr := clientPubHex(priv)
	exitOnErr(pubErr)
	fmt.Fprintf(os.Stderr, "client_public_key_hex=%s\n", pubHex)
	fmt.Fprintln(os.Stderr, "提示：请把上方公钥加入服务端 public_key_whitelist 后重启服务。")

	h, err := buildHost(priv, *addr, *tlsInsecure)
	exitOnErr(err)
	defer h.Close()
	maddr, err := ma.NewMultiaddr(*addr)
	exitOnErr(err)
	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		fatal("--addr 缺少 /p2p/<PeerId> 部分", err)
	}
	dialCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := h.Connect(dialCtx, *info); err != nil {
		fatal("连接服务端失败", err)
	}
	c := newClient(h, info.ID)

	switch sub {
	case "stat":
		runStat(c, hashArr)
	case "read":
		runRead(c, hashArr, *output, *verify)
	case "verify-seed":
		runVerifySeed(c, hashArr)
	case "verify-file":
		runVerifyFile(c, seedArr, *output)
	case "load":
		runLoad(c, priv, seedArr, *conns, *rpb, *duration, *tlsInsecure, *addr)
	}
}

// ---------- 子命令实现 ----------

func runStat(c *client, hash [32]byte) {
	fields, _, err := c.request(msfile.KindStatRequest, hash)
	exitOnErr(err)
	res := statResult{}
	serverErr := ""
	if len(fields) >= 5 && fields[1] == uint64(255) {
		serverErr, _ = fields[4].(string)
	} else if len(fields) >= 4 && fields[3] == uint64(1) {
		res.Available = true
		if len(fields) == 7 {
			res.Filename, _ = fields[4].(string)
			if size, ok := fields[5].(uint64); ok {
				res.SizeBytes = size
			}
			res.MediaType, _ = fields[6].(string)
		}
	}
	fmt.Fprintln(os.Stderr, "字段说明：available=是否可提供；filename=建议文件名；size_bytes=原文件尺寸；media_type=媒体类型")
	emit(res)
	if serverErr != "" {
		exitOnErr(fmt.Errorf("服务端返回 %s", serverErr))
	}
}

func runRead(c *client, hash [32]byte, output string, verify bool) {
	_, data, err := c.request(msfile.KindReadRequest, hash)
	exitOnErr(err)
	sum := sha256.Sum256(data)
	res := readResult{
		OutputFile:    output,
		Bytes:         len(data),
		SHA256:        hex.EncodeToString(sum[:]),
		VerifiedMatch: !verify || sum == hash,
	}
	if output != "" {
		if werr := os.WriteFile(output, data, 0o640); werr != nil {
			fatal("写入输出文件失败", werr)
		}
	}
	fmt.Fprintln(os.Stderr, "字段说明：output_file=写入路径；bytes=字节数；sha256=实际摘要；verified_match=校验结果")
	emit(res)
	if verify && !res.VerifiedMatch {
		exitOnErr(errors.New("--verify 失败：内容摘要与请求哈希不一致"))
	}
}

func runVerifySeed(c *client, hash [32]byte) {
	_, data, err := c.request(msfile.KindReadRequest, hash)
	exitOnErr(err)
	sum := sha256.Sum256(data)
	ok := sum == hash && len(data)%32 == 0
	res := verifySeedResult{SeedOK: ok, SizeBytes: len(data), BlockCount: len(data) / 32}
	fmt.Fprintln(os.Stderr, "字段说明：seed_ok=完整性校验通过；size_bytes=Seed 字节数；block_count=块数（字节/32）")
	emit(res)
	if !ok {
		exitOnErr(errors.New("Seed 校验失败"))
	}
}

// runVerifyFile 校验 Seed 后逐块下载全部 block_hash 并校验，
// 可选按顺序重构原文件（阻断 3）。
func runVerifyFile(c *client, seedHash [32]byte, output string) {
	_, seedData, err := c.request(msfile.KindReadRequest, seedHash)
	exitOnErr(err)
	seedSum := sha256.Sum256(seedData)
	res := verifyFileResult{FailedHashes: []string{}}
	res.SeedOK = seedSum == seedHash
	if !res.SeedOK {
		fmt.Fprintln(os.Stderr, "字段说明：seed_ok/block_total/block_ok/bytes_verified/failed_hashes/output_file")
		emit(res)
		exitOnErr(errors.New("Seed 校验失败，终止块校验"))
	}
	res.BlockTotal = len(seedData) / 32

	var outFile *os.File
	if output != "" {
		outFile, err = os.Create(output)
		if err != nil {
			fatal("创建输出文件失败", err)
		}
		defer outFile.Close()
		res.OutputFile = output
	}

	for i := 0; i < res.BlockTotal; i++ {
		var bh [32]byte
		copy(bh[:], seedData[i*32:(i+1)*32])
		hashHex := hex.EncodeToString(bh[:])
		data, err := func() ([]byte, error) {
			_, data, err := c.request(msfile.KindReadRequest, bh)
			return data, err
		}()
		if err != nil {
			res.FailedHashes = append(res.FailedHashes, hashHex)
			continue
		}
		sum := sha256.Sum256(data)
		if sum != bh {
			res.FailedHashes = append(res.FailedHashes, hashHex)
			continue
		}
		res.BlockOK++
		res.BytesVerified += int64(len(data))
		if outFile != nil {
			if _, err := outFile.Write(data); err != nil {
				fatal("写出重构文件失败", err)
			}
		}
	}
	fmt.Fprintln(os.Stderr, "字段说明：seed_ok=Seed 校验；block_total/block_ok=块总数与通过数；bytes_verified=已校验字节；failed_hashes=失败块哈希；output_file=重构原文件路径")
	emit(res)
	if res.BlockOK != res.BlockTotal {
		exitOnErr(fmt.Errorf("%d/%d 个块校验失败", len(res.FailedHashes), res.BlockTotal))
	}
}

// runLoad 建立 conns 条独立连接（各自 libp2p host 与身份），
// 每条连接维持一条长驻 READ stream，循环读取真实文件块并强制校验（阻断 4）。
func runLoad(base *client, basePriv crypto.PrivKey, seedHash [32]byte, conns, rpb int,
	duration time.Duration, tlsInsecure bool, addr string) {

	// 先取 Seed 并解析全部块哈希（计入 setup，不计入压测统计）。
	_, seedData, err := base.request(msfile.KindReadRequest, seedHash)
	exitOnErr(err)
	if sha256.Sum256(seedData) != seedHash {
		fatal("Seed 校验失败，终止压测", nil)
	}
	blocks := make([][32]byte, 0, len(seedData)/32)
	for i := 0; i+32 <= len(seedData); i += 32 {
		var bh [32]byte
		copy(bh[:], seedData[i:i+32])
		blocks = append(blocks, bh)
	}
	if len(blocks) == 0 {
		fatal("该 Seed 对应空文件，没有可压测的块", nil)
	}
	_ = addr

	planned := conns * rpb * len(blocks)
	res := loadResult{
		Connections:      conns,
		BlocksPerRequest: len(blocks),
		PlannedRequests:  planned,
		ErrorCodes:       map[string]int{},
		NoteZh: "字段说明：connections=独立连接数；blocks_per_request=每轮覆盖的块数；" +
			"planned/attempted_requests=计划/实际尝试请求数；ok=成功（含本地完整性校验）；" +
			"bytes=总字节；error_codes=错误码分布；throughput_mbps=聚合吞吐。" +
			"多连接压测要求 public 模式或把各临时公钥加入白名单；private 模式建议 --connections 1。" +
			"确定性限流结论以自动化测试 TestInflightHardCapReturnsRateLimited 为准。",
	}

	start := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := time.AfterFunc(duration, cancel)

	var mu sync.Mutex
	record := func(code string) {
		mu.Lock()
		defer mu.Unlock()
		res.ErrorCodes[code]++
	}

	var wg sync.WaitGroup
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// 每个连接独立的 libp2p host；
			// 第 0 条复用基础身份（便于 private 白名单），其余为临时身份。
			var priv crypto.PrivKey
			if idx == 0 {
				priv = basePriv
			} else {
				generated, _, gerr := crypto.GenerateSecp256k1Key(rand.Reader)
				if gerr != nil {
					record("host_error")
					return
				}
				priv = generated
			}
			h, err := buildHost(priv, addr, tlsInsecure)
			if err != nil {
				record("host_error")
				return
			}
			defer h.Close()
			maddr, merr := ma.NewMultiaddr(addr)
			if merr != nil {
				record("host_error")
				return
			}
			info, ierr := peer.AddrInfoFromP2pAddr(maddr)
			if ierr != nil {
				record("host_error")
				return
			}
			dctx, dcancel := context.WithTimeout(ctx, 60*time.Second)
			if err := h.Connect(dctx, *info); err != nil {
				dcancel()
				record("connect_error")
				return
			}
			dcancel()

			w, err := newConnWorker(newClient(h, info.ID), blocks[0])
			if err != nil {
				record("stream_error")
				return
			}
			defer w.close()

			localID := uint64(idx)*100000 + 1
			for round := 0; round < rpb; round++ {
				for bi := range blocks {
					select {
					case <-ctx.Done():
						return
					default:
					}
					mu.Lock()
					res.AttemptedRequests++
					mu.Unlock()
					data, err := w.readBlock(localID, blocks[bi])
					localID++
					if err != nil {
						msg := err.Error()
						code := "transport_error"
						for _, candidate := range []string{
							"rate_limited", "content_not_found", "integrity_error",
							"unauthorized_peer", "wrong_stream_role", "stale_request_id",
						} {
							if strings.Contains(msg, candidate) {
								code = candidate
								break
							}
						}
						record(code)
						continue
					}
					mu.Lock()
					res.OK++
					res.Bytes += int64(len(data))
					mu.Unlock()
				}
			}
		}(i)
	}
	wg.Wait()
	timer.Stop()
	cancel()
	res.DurationMs = time.Since(start).Milliseconds()
	if secs := time.Since(start).Seconds(); secs > 0 {
		res.ThroughputMBps = float64(res.Bytes) / 1048576 / secs
	}
	emit(res)
	if res.AttemptedRequests < res.PlannedRequests && len(res.ErrorCodes) == 0 {
		// 提前结束但没有任何错误码：通常是 duration 到期，属预期行为。
		fmt.Fprintln(os.Stderr, "提示：因时长上限提前结束，attempted < planned 属正常。")
	}
}
