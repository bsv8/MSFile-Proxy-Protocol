// msfile-acceptance 是 NAS 验收客户端：
//
//	msfile-acceptance [公共参数] stat        --hash <64位hex>
//	msfile-acceptance [公共参数] read       --hash <64位hex> [--output <文件>] [--verify]
//	msfile-acceptance [公共参数] verify-seed --hash <64位hex>
//	msfile-acceptance [公共参数] load       --hash <64位hex> --connections N --requests M [--duration 30s]
//
// 公共参数：
//
//	--addr          服务端 multiaddr（须带 /p2p/<PeerId>；支持 ws、tls/ws、webrtc-direct）
//	--identity-key  客户端 32 字节 secp256k1 私钥 hex 文件；缺省随机生成并把公钥打印到 stderr
//	--tls-insecure  跳过 WSS 证书校验（自签证书环境；身份仍由 Noise+PeerId 保证）
//
// 子命令输出 JSON 结果（英文键）；stderr 先输出中文字段说明，便于人工验收留档。
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
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	webrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	websocket "github.com/libp2p/go-libp2p/p2p/transport/websocket"
	ma "github.com/multiformats/go-multiaddr"

	"msfile.dev/labs/webrtc-go/internal/msfile"
)

const usageDoc = `MSFile NAS 验收客户端（详见文件头注释）`

func fatal(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误：%s: %v\n", msg, err)
	} else {
		fmt.Fprintf(os.Stderr, "错误：%s\n", msg)
	}
	os.Exit(1)
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

func loadOrCreateIdentity(path string) crypto.PrivKey {
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			fatal("读取私钥文件失败", err)
		}
		bin, herr := hex.DecodeString(strings.TrimSpace(string(raw)))
		if herr != nil || len(bin) != 32 {
			fatal("私钥文件必须是 32 字节 hex", nil)
		}
		priv, perr := crypto.UnmarshalSecp256k1PrivateKey(bin)
		if perr != nil {
			fatal("解析 secp256k1 私钥失败", perr)
		}
		return priv
	}
	priv, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		fatal("生成临时身份失败", err)
	}
	return priv
}

func clientPubHex(priv crypto.PrivKey) (string, error) {
	raw, err := priv.GetPublic().Raw()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

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
		wsTransport := websocket.New
		var wsOptions []any
		if hasTLS {
			wsOptions = append(wsOptions,
				websocket.WithTLSClientConfig(&tls.Config{
					InsecureSkipVerify: tlsInsecure,
					MinVersion:         tls.VersionTLS12,
				}))
		}
		opts = append(opts, libp2p.Transport(wsTransport, wsOptions...))
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

func (c *client) nextID() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.id++
	return c.id
}

// request 发送一个请求并返回响应字段；READ 请求同时读回完整 attachment。
func (c *client) request(kind uint64, hash [32]byte) ([]any, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	stream, err := c.h.NewStream(ctx, c.p, protocol.ID(msfile.ProtocolID))
	if err != nil {
		return nil, nil, fmt.Errorf("打开 stream 失败: %w", err)
	}
	defer stream.Close()

	id := c.nextID()
	// Stat 请求是四元数组；Read 请求带 max_price 是五元（wire §7.1/§8.1）。
	var payload []any
	if kind == msfile.KindStatRequest {
		payload = []any{uint64(1), msfile.KindStatRequest, id, hash[:]}
	} else {
		payload = []any{uint64(1), msfile.KindReadRequest, id, hash[:], uint64(0)}
	}
	if err := msfile.EncodeRequest(stream, payload); err != nil {
		return nil, nil, err
	}
	_ = stream.CloseWrite() // 半关：服务端读完即释放角色，响应仍完整送达

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

// ---------- 子命令 ----------

type statResult struct {
	Available bool   `json:"available"`  // 是否可提供
	Filename  string `json:"filename"`   // 建议文件名
	SizeBytes uint64 `json:"size_bytes"` // 原文件尺寸
	MediaType string `json:"media_type"` // 媒体类型
}

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

type readResult struct {
	OutputFile    string `json:"output_file"`    // 写入的文件路径（空表示未写盘）
	Bytes         int    `json:"bytes"`          // 内容字节数
	SHA256        string `json:"sha256"`         // 内容摘要
	VerifiedMatch bool   `json:"verified_match"` // --verify 时与请求哈希比对结果
}

func runRead(c *client, hash [32]byte, output string, verify bool) {
	fields, data, err := c.request(msfile.KindReadRequest, hash)
	exitOnErr(err)
	_ = fields
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

type verifySeedResult struct {
	SeedOK     bool `json:"seed_ok"`     // SHA-256(内容)==请求哈希 且长度 32 字节对齐
	SizeBytes  int  `json:"size_bytes"`  // Seed 字节数
	BlockCount int  `json:"block_count"` // 块数 = 字节数/32
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

type loadResult struct {
	Connections    int            `json:"connections"`     // 并发连接数
	RequestsEach   int            `json:"requests_each"`   // 每连接请求次数
	DurationMs     int64          `json:"duration_ms"`     // 实际耗时
	TotalRequests  int            `json:"total_requests"`  // 请求总数
	OK             int            `json:"ok"`              // 成功数
	Bytes          int64          `json:"bytes"`           // 收到字节总数
	ErrorCodes     map[string]int `json:"error_codes"`     // 错误码 -> 次数
	ThroughputMBps float64        `json:"throughput_mbps"` // 聚合吞吐
	NoteZh         string         `json:"note_zh"`         // 结果解读提示（中文）
}

func runLoad(c *client, hash [32]byte, conns, requests int, duration time.Duration) {
	if conns <= 0 || requests <= 0 {
		exitOnErr(errors.New("--connections/--requests 必须大于 0"))
	}
	start := time.Now()
	end := start.Add(duration)
	startBarrier := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	res := loadResult{
		Connections:  conns,
		RequestsEach: requests,
		ErrorCodes:   map[string]int{},
	}
	record := func(code string) {
		mu.Lock()
		defer mu.Unlock()
		res.ErrorCodes[code]++
	}

	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startBarrier // 屏障同步：全部连接同时发起
			for j := 0; j < requests; j++ {
				if time.Now().After(end) {
					return
				}
				_, data, err := c.request(msfile.KindReadRequest, hash)
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
		}()
	}
	close(startBarrier)
	wg.Wait()
	res.TotalRequests = conns * requests
	res.DurationMs = time.Since(start).Milliseconds()
	if secs := time.Since(start).Seconds(); secs > 0 {
		res.ThroughputMBps = float64(res.Bytes) / 1048576 / secs
	}
	res.NoteZh = "字段说明见各键名；确定性限流结论以自动化测试 TestInflightHardCapReturnsRateLimited 与 " +
		"TestGlobalInflightCapUnderConcurrentConnections 为准，本输出作为真实负载稳定性证据留存。"
	emit(res)
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

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "缺少子命令；支持 stat / read / verify-seed / load（详见源码头注释）")
		os.Exit(2)
	}
	// 允许公共参数写在子命令之前或之后：
	//   msfile-acceptance --addr X stat --hash H
	//   msfile-acceptance stat --addr X --hash H
	knownSubs := map[string]bool{"stat": true, "read": true, "verify-seed": true, "load": true}
	sub := ""
	var rest []string
	if len(os.Args) >= 2 && knownSubs[os.Args[1]] {
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
		fmt.Fprintln(os.Stderr, "缺少子命令；支持 stat / read / verify-seed / load（详见源码头注释）")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(sub, flag.ExitOnError)
	addr := fs.String("addr", "", "服务端 multiaddr（含 /p2p/<PeerId>）")
	keyFile := fs.String("identity-key", "", "客户端私钥 hex 文件（缺省随机生成）")
	tlsInsecure := fs.Bool("tls-insecure", false, "跳过 WSS 证书校验（自签证书环境）")

	hashHex := fs.String("hash", "", "内容 Hash（64 位小写 hex）")
	output := fs.String("output", "", "[read] 输出文件路径")
	verify := fs.Bool("verify", false, "[read] 校验 SHA-256(内容)==--hash")
	conns := fs.Int("connections", 8, "[load] 并发连接数")
	requests := fs.Int("requests", 10, "[load] 每连接请求次数")
	duration := fs.Duration("duration", 30*time.Second, "[load] 总时长上限")

	if err := fs.Parse(rest); err != nil {
		os.Exit(2)
	}
	if *addr == "" || *hashHex == "" {
		fmt.Fprintln(os.Stderr, "必须提供 --addr 与 --hash")
		fs.Usage()
		os.Exit(2)
	}

	priv := loadOrCreateIdentity(*keyFile)
	pubHex, err := clientPubHex(priv)
	exitOnErr(err)
	fmt.Fprintf(os.Stderr, "client_public_key_hex=%s\n", pubHex)
	fmt.Fprintln(os.Stderr, "提示：请把上方公钥加入服务端 public_key_whitelist 后重启服务。")

	hashArr, err := parseHash(*hashHex)
	exitOnErr(err)

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
	c := &client{h: h, p: info.ID}

	switch sub {
	case "stat":
		runStat(c, hashArr)
	case "read":
		runRead(c, hashArr, *output, *verify)
	case "verify-seed":
		runVerifySeed(c, hashArr)
	case "load":
		runLoad(c, hashArr, *conns, *requests, *duration)
	}
}
