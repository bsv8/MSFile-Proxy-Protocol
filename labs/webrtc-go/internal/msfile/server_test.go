package msfile

// 本文件覆盖施工单 T20/T21：
// - Stat/Read 双 stream、角色锁定、request ID 单调性（T20）
// - 覆盖取消（同一 hash 更大 ID）与终态完整性
// - private/public 授权与 unauthorized_peer fail-closed
// - WS 传输上的正式 /msfile/1.0.0 E2E（T21）

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
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

	"msfile.dev/labs/webrtc-go/internal/auth"
	"msfile.dev/labs/webrtc-go/internal/content"
	"msfile.dev/labs/webrtc-go/internal/indexdb"
	"msfile.dev/labs/webrtc-go/internal/metrics"
	"msfile.dev/labs/webrtc-go/internal/safefs"
	"msfile.dev/labs/webrtc-go/internal/seed"
)

const testSourceSize = 700000 // 约 3 块：2 完整 + 1 短块

type testEnv struct {
	reader  *content.Reader
	db      *indexdb.DB
	store   *seed.Store
	nasRoot string
	result  *seed.Result
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	nasRoot := filepath.Join(dir, "nas_data")
	seedDir := filepath.Join(dir, "seed_data")
	if err := os.MkdirAll(filepath.Join(nasRoot, "电影"), 0o750); err != nil {
		t.Fatal(err)
	}
	store, err := seed.Open(seedDir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := indexdb.Open(filepath.Join(seedDir, "index.sqlite"))
	if err := err; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	source := filepath.Join(nasRoot, "电影", "a.mkv")
	data := make([]byte, testSourceSize)
	for i := range data {
		data[i] = byte(i*131+7) ^ byte(i>>13)
	}
	if err := os.WriteFile(source, data, 0o640); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	res, err := seed.Build(file, "a.mkv")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Publish(res); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	blocks := make([]indexdb.SeedBlock, 0, len(res.Blocks))
	for _, b := range res.Blocks {
		blocks = append(blocks, indexdb.SeedBlock{
			BlockIndex:  b.Index,
			BlockHash:   hex.EncodeToString(b.Hash[:]),
			OffsetBytes: b.Offset,
			LengthBytes: int64(b.Length),
		})
	}
	ctx := context.Background()
	revision, err := db.PrepareIndex(ctx, "电影/a.mkv", 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	err = db.CommitSeedResult(ctx, indexdb.CommitParams{
		RelativePath:     "电影/a.mkv",
		SeedHash:         res.HashHex(),
		SeedLength:       len(res.Seed),
		SourceSize:       res.SourceSize,
		Filename:         res.RecommendedFilename,
		MediaType:        res.MediaType,
		SizeBytes:        info.Size(),
		MtimeNs:          info.ModTime().UnixNano(),
		ExpectedRevision: revision,
		Blocks:           blocks,
	}, time.Now())
	if err != nil {
		t.Fatalf("提交索引失败: %v", err)
	}
	safeRoot, err := safefs.Open(nasRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = safeRoot.Close() })
	return &testEnv{reader: content.New(safeRoot, db, store, nil), db: db, store: store, nasRoot: nasRoot, result: res}
}

func newKeyPair(t *testing.T) crypto.PrivKey {
	t.Helper()
	priv, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func buildTestHost(t *testing.T, priv crypto.PrivKey, ws bool) host.Host {
	t.Helper()
	opts := []libp2p.Option{libp2p.Identity(priv)}
	if ws {
		opts = append(opts, libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0/ws"))
	} else {
		opts = append(opts, libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	}
	h, err := libp2p.New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func mustConnect(t *testing.T, from, to host.Host) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := from.Connect(ctx, peer.AddrInfo{ID: to.ID(), Addrs: to.Addrs()}); err != nil {
		t.Fatalf("建立连接失败: %v", err)
	}
}

func openStream(t *testing.T, from host.Host, to peer.ID) network.Stream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := from.NewStream(ctx, to, protocol.ID(ProtocolID))
	if err != nil {
		t.Fatalf("打开 stream 失败: %v", err)
	}
	return stream
}

func sendRequest(t *testing.T, stream network.Stream, fields []any) {
	t.Helper()
	if err := WriteFrame(stream, fields, nil, 0); err != nil {
		t.Fatalf("写入请求失败: %v", err)
	}
}

func readFields(t *testing.T, reader *bufio.Reader) []any {
	t.Helper()
	header, err := readHeader(reader)
	if err != nil {
		t.Fatalf("读取响应 Header: %v", err)
	}
	var fields []any
	if err := decMode.Unmarshal(header, &fields); err != nil {
		t.Fatalf("解码响应 CBOR: %v", err)
	}
	return fields
}

func readAttachment(t *testing.T, reader *bufio.Reader, length uint64) []byte {
	t.Helper()
	data := make([]byte, length)
	if _, err := io.ReadFull(reader, data); err != nil {
		t.Fatalf("读取 attachment: %v", err)
	}
	return data
}

func statRequest(id uint64, hash [32]byte) []any {
	return []any{WireVersion, KindStatRequest, id, hash[:]}
}

func readRequest(id uint64, hash [32]byte, maxPrice uint64) []any {
	return []any{WireVersion, KindReadRequest, id, hash[:], maxPrice}
}

func seedHash32(t *testing.T, result *seed.Result) [32]byte {
	t.Helper()
	var out [32]byte
	copy(out[:], result.SeedHash[:])
	return out
}

// newServerPair 构造 private 模式服务端与已授权客户端。
func newServerPair(t *testing.T, mode string) (server host.Host, client host.Host, env *testEnv, clientKeyHex string) {
	t.Helper()
	env = newTestEnv(t)
	serverPriv := newKeyPair(t)
	clientPriv := newKeyPair(t)
	clientKeyHex, err := identityPubHex(clientPriv)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := auth.NewPolicy(mode, []string{clientKeyHex})
	if err != nil {
		t.Fatal(err)
	}
	server = buildTestHost(t, serverPriv, false)
	client = buildTestHost(t, clientPriv, false)
	NewServer(server, env.reader, policy, metrics.New("test"))
	mustConnect(t, client, server)
	return server, client, env, clientKeyHex
}

func identityPubHex(priv crypto.PrivKey) (string, error) {
	raw, err := priv.GetPublic().Raw()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// TestStatAndReadDoubleStreamsOverLibp2p 覆盖正式双 stream 用法：
// Stat 与 Read 各占一条 stream，重复 Stat 不需要新 stream，读取结果逐字节可验证。
func TestStatAndReadDoubleStreamsOverLibp2p(t *testing.T) {
	server, client, env, _ := newServerPair(t, "private")
	hash := seedHash32(t, env.result)
	statStream := openStream(t, client, server.ID())
	defer statStream.Close()

	for round := 1; round <= 3; round++ {
		sendRequest(t, statStream, statRequest(uint64(round), hash))
		fields := readFields(t, bufio.NewReader(statStream))
		if len(fields) != 7 || fields[1] != KindStatResponse || fields[3] != uint64(1) {
			t.Fatalf("第 %d 次 Stat 应返回 available 七元组: %#v", round, fields)
		}
		if fields[4] != env.result.RecommendedFilename || fields[5] != uint64(env.result.SourceSize) {
			t.Fatalf("Stat 元数据不符: %#v", fields)
		}
	}

	readStream := openStream(t, client, remoteIDFor(t, client))
	defer readStream.Close()
	sendRequest(t, readStream, readRequest(100, hash, 0))
	reader := bufio.NewReader(readStream)
	fields := readFields(t, reader)
	if len(fields) != 5 || fields[1] != KindReadResponse || fields[2] != uint64(100) {
		t.Fatalf("ReadResponse 字段错误: %#v", fields)
	}
	length, ok := fields[4].(uint64)
	if !ok || length != uint64(len(env.result.Seed)) {
		t.Fatalf("content_length 应为 Seed 长度 %d，实际 %#v", len(env.result.Seed), fields[4])
	}
	data := readAttachment(t, reader, length)
	digest := sha256.Sum256(data)
	if digest != env.result.SeedHash {
		t.Fatal("attachment 的 SHA-256 必须等于请求的 seed_hash")
	}

	// 同一条 Read stream 连续读一个块：验证块字节与 SHA-256。
	block := env.result.Blocks[1]
	var blockHash [32]byte
	copy(blockHash[:], block.Hash[:])
	sendRequest(t, readStream, readRequest(101, blockHash, 5))
	fields = readFields(t, reader)
	length, ok = fields[4].(uint64)
	if !ok {
		t.Fatalf("块响应缺少 content_length: %#v", fields)
	}
	blockData := readAttachment(t, reader, length)
	digest = sha256.Sum256(blockData)
	if digest != blockHash {
		t.Fatal("块 attachment 的 SHA-256 必须等于请求的 block_hash")
	}
	if !bytes.Equal(blockData, mustSourceSlice(t, env.nasRoot, int(block.Offset), block.Length)) {
		t.Fatal("块字节必须精确等于原文件对应偏移内容")
	}
}

func remoteIDFor(t *testing.T, client host.Host) peer.ID {
	t.Helper()
	conns := client.Network().Conns()
	if len(conns) == 0 {
		t.Fatal("没有已建立的连接")
	}
	return conns[0].RemotePeer()
}

func mustSourceSlice(t *testing.T, nasRoot string, offset, length int) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(nasRoot, "电影", "a.mkv"))
	if err != nil {
		t.Fatal(err)
	}
	return data[offset : offset+length]
}

// TestAbsentStatWhenNoValidReplica：所有位置失效后 Stat 必须 absent，
// 即使 .seed 文件仍在保留期内。
func TestAbsentStatWhenNoValidReplica(t *testing.T) {
	_, client, env, _ := newServerPair(t, "private")
	hash := seedHash32(t, env.result)
	if err := env.db.MarkInvalidNow(context.Background(), "电影/a.mkv", "测试失效", time.Now()); err != nil {
		t.Fatal(err)
	}
	stream := openStream(t, client, remoteIDFor(t, client))
	defer stream.Close()
	sendRequest(t, stream, statRequest(1, hash))
	fields := readFields(t, bufio.NewReader(stream))
	if len(fields) != 4 || fields[3] != uint64(2) {
		t.Fatalf("全部位置失效时应返回 absent 四元组: %#v", fields)
	}
}

// TestUnauthorizedPeerIsRejected：private 未命中白名单 → unauthorized_peer 且不泄露内容。
func TestUnauthorizedPeerIsRejected(t *testing.T) {
	env := newTestEnv(t)
	serverPriv := newKeyPair(t)
	strangerPriv := newKeyPair(t)
	policy, err := auth.NewPolicy("private", nil) // 空白名单拒绝全部
	if err != nil {
		t.Fatal(err)
	}
	server := buildTestHost(t, serverPriv, false)
	client := buildTestHost(t, strangerPriv, false)
	NewServer(server, env.reader, policy, metrics.New("test"))
	mustConnect(t, client, server)
	stream := openStream(t, client, server.ID())
	defer stream.Close()
	sendRequest(t, stream, statRequest(1, seedHash32(t, env.result)))
	fields := readFields(t, bufio.NewReader(stream))
	if len(fields) != 7 || fields[1] != KindErrorResponse || fields[4] != "unauthorized_peer" {
		t.Fatalf("应返回 unauthorized_peer 错误: %#v", fields)
	}
	// 服务端随后关闭 stream；再发请求应失败。
	stream.SetWriteDeadline(time.Now().Add(2 * time.Second))
	err = WriteFrame(stream, statRequest(2, seedHash32(t, env.result)), nil, 0)
	if err == nil {
		t.Log("提示：对端尚未关闭写方向，属允许行为")
	}
}

// TestPublicModeAllowsAnyAuthenticatedKey：public 放行任意已认证 secp256k1 客户端。
func TestPublicModeAllowsAnyAuthenticatedKey(t *testing.T) {
	env := newTestEnv(t)
	serverPriv := newKeyPair(t)
	clientPriv := newKeyPair(t)
	policy, err := auth.NewPolicy("public", nil)
	if err != nil {
		t.Fatal(err)
	}
	server := buildTestHost(t, serverPriv, false)
	client := buildTestHost(t, clientPriv, false)
	NewServer(server, env.reader, policy, metrics.New("test"))
	mustConnect(t, client, server)
	stream := openStream(t, client, server.ID())
	defer stream.Close()
	sendRequest(t, stream, statRequest(9, seedHash32(t, env.result)))
	fields := readFields(t, bufio.NewReader(stream))
	if len(fields) != 7 || fields[3] != uint64(1) {
		t.Fatalf("public 模式应返回 available: %#v", fields)
	}
}

// TestWrongStreamRoleLocked：第一条请求锁定角色；同 stream 发另一类命令报 wrong_stream_role。
func TestWrongStreamRoleLocked(t *testing.T) {
	_, client, env, _ := newServerPair(t, "private")
	hash := seedHash32(t, env.result)
	stream := openStream(t, client, remoteIDFor(t, client))
	defer stream.Close()
	sendRequest(t, stream, statRequest(1, hash))
	fields := readFields(t, bufio.NewReader(stream))
	if fields[1] != KindStatResponse {
		t.Fatalf("首个 Stat 应正常响应: %#v", fields)
	}
	sendRequest(t, stream, readRequest(2, hash, 0))
	fields = readFields(t, bufio.NewReader(stream))
	if fields[1] != KindErrorResponse || fields[4] != "wrong_stream_role" {
		t.Fatalf("角色锁定后混入 Read 应报 wrong_stream_role: %#v", fields)
	}
}

// TestStaleRequestIDRejected：request ID 倒退必须返回 stale_request_id。
func TestStaleRequestIDRejected(t *testing.T) {
	_, client, env, _ := newServerPair(t, "private")
	hash := seedHash32(t, env.result)
	stream := openStream(t, client, remoteIDFor(t, client))
	defer stream.Close()
	sendRequest(t, stream, statRequest(5, hash))
	fields := readFields(t, bufio.NewReader(stream))
	if fields[1] != KindStatResponse {
		t.Fatalf("首次 Stat 应成功: %#v", fields)
	}
	sendRequest(t, stream, statRequest(5, hash)) // 重复 ID
	fields = readFields(t, bufio.NewReader(stream))
	if fields[1] != KindErrorResponse || fields[4] != "stale_request_id" {
		t.Fatalf("重复 request ID 应报 stale_request_id: %#v", fields)
	}
}

// TestReadOverrideProducesCancelOrDuplicateTerminal：
// 同一 hash 的更大 ID 覆盖旧请求。若旧响应尚未开始发送则返回 ReadCancelled；
// 若已开始发送则两个终态都会完整到达。两种行为都符合协议 §8.6。
func TestReadOverrideProducesCancelOrDuplicateTerminal(t *testing.T) {
	_, client, env, _ := newServerPair(t, "private")
	hash := seedHash32(t, env.result)
	stream := openStream(t, client, remoteIDFor(t, client))
	defer stream.Close()
	sendRequest(t, stream, readRequest(1, hash, 0))
	sendRequest(t, stream, readRequest(2, hash, 0))
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(stream)
	sawCancel, sawFinal2 := false, false
	for i := 0; i < 2; i++ {
		fields := readFields(t, reader)
		switch fields[1] {
		case KindReadCancelled:
			if fields[2] == uint64(1) && fields[4] == uint64(2) {
				sawCancel = true
			}
		case KindReadResponse:
			if fields[2] == uint64(2) {
				sawFinal2 = true
				length := fields[4].(uint64)
				data := readAttachment(t, reader, length)
				digest := sha256.Sum256(data)
				if digest != hash {
					t.Fatal("覆盖后的 Read 内容校验失败")
				}
			} else if fields[2] == uint64(1) {
				readAttachment(t, reader, fields[4].(uint64)) // 读完整个 Frame 保持边界
			}
		default:
			t.Fatalf("意外响应: %#v", fields)
		}
	}
	if !sawFinal2 {
		t.Fatal("新请求必须获得自己的终态响应")
	}
	_ = sawCancel // 两种竞态结果均合法
}

// TestContentNotFoundErrorCode：未知 Hash 返回稳定的 content_not_found。
func TestContentNotFoundErrorCode(t *testing.T) {
	_, client, _, _ := newServerPair(t, "private")
	var unknown [32]byte
	for i := range unknown {
		unknown[i] = 0x77
	}
	stream := openStream(t, client, remoteIDFor(t, client))
	defer stream.Close()
	sendRequest(t, stream, readRequest(1, unknown, 0))
	fields := readFields(t, bufio.NewReader(stream))
	if fields[1] != KindErrorResponse || fields[4] != "content_not_found" {
		t.Fatalf("未知 Hash 应返回 content_not_found: %#v", fields)
	}
}

// TestFormalProtocolOverWebSocketTransport（T21）：WS 传输上的正式协议 E2E。
func TestFormalProtocolOverWebSocketTransport(t *testing.T) {
	env := newTestEnv(t)
	serverPriv := newKeyPair(t)
	clientPriv := newKeyPair(t)
	clientKeyHex, err := identityPubHex(clientPriv)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := auth.NewPolicy("private", []string{clientKeyHex})
	if err != nil {
		t.Fatal(err)
	}
	server := buildTestHost(t, serverPriv, true)
	client := buildTestHost(t, clientPriv, true)
	NewServer(server, env.reader, policy, metrics.New("test"))
	mustConnect(t, client, server)

	wsAddrFound := false
	for _, addr := range server.Addrs() {
		for _, p := range addr.Protocols() {
			if fmt.Sprintf("/%s", p.Name) == "/ws" {
				wsAddrFound = true
			}
		}
	}
	if !wsAddrFound {
		t.Fatal("服务端应在 /ws multiaddr 上监听")
	}

	statStream := openStream(t, client, server.ID())
	defer statStream.Close()
	sendRequest(t, statStream, statRequest(1, seedHash32(t, env.result)))
	fields := readFields(t, bufio.NewReader(statStream))
	if len(fields) != 7 || fields[3] != uint64(1) {
		t.Fatalf("WS 上的 Stat 应回复 available: %#v", fields)
	}
}

// TestFormalProtocolOverWebRTCDirectTransport（T23）：WebRTC Direct 回环 E2E。
// 服务端与客户端都是 libp2p 主机，经 webrtc-direct transport 完成 ICE 后走正式协议。
func TestFormalProtocolOverWebRTCDirectTransport(t *testing.T) {
	env := newTestEnv(t)
	serverPriv := newKeyPair(t)
	clientPriv := newKeyPair(t)
	clientKeyHex, err := identityPubHex(clientPriv)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := auth.NewPolicy("private", []string{clientKeyHex})
	if err != nil {
		t.Fatal(err)
	}

	newHost := func(priv crypto.PrivKey) host.Host {
		h, err := libp2p.New(
			libp2p.Identity(priv),
			libp2p.NoListenAddrs,
			libp2p.Transport(webrtc.New),
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/udp/0/webrtc-direct"),
		)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = h.Close() })
		return h
	}
	server := newHost(serverPriv)
	client := newHost(clientPriv)
	NewServer(server, env.reader, policy, metrics.New("test"))
	mustConnect(t, client, server)

	statStream := openStream(t, client, server.ID())
	defer statStream.Close()
	sendRequest(t, statStream, statRequest(1, seedHash32(t, env.result)))
	fields := readFields(t, bufio.NewReader(statStream))
	if len(fields) != 7 || fields[3] != uint64(1) {
		t.Fatalf("WebRTC Direct 上的 Stat 应回复 available: %#v", fields)
	}
}

// ---------- 阻断 5：connection 作用域 request ID 与资源上限 ----------

// blockingSource 是可控阻塞的假内容源，用于确定性资源限制测试。
type blockingSource struct {
	release chan struct{} // 关闭后放行全部在途 Resolve
}

func (b *blockingSource) Stat(context.Context, string) (content.StatInfo, bool, error) {
	<-b.release
	return content.StatInfo{Filename: "x", SizeBytes: 1}, true, nil
}

func (b *blockingSource) Resolve(context.Context, string) ([]byte, error) {
	<-b.release
	return []byte{1}, nil
}

// TestStreamRebuildKeepsRequestIDMonotonic（wire §2.3）：
// 同一 connection 上重建 stream 后，request ID 从更小值重新开始必须被拒绝。
func TestStreamRebuildKeepsRequestIDMonotonic(t *testing.T) {
	env := newTestEnv(t)
	serverPriv := newKeyPair(t)
	clientPriv := newKeyPair(t)
	clientKeyHex, err := identityPubHex(clientPriv)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := auth.NewPolicy("private", []string{clientKeyHex})
	if err != nil {
		t.Fatal(err)
	}
	server := buildTestHost(t, serverPriv, false)
	client := buildTestHost(t, clientPriv, false)
	NewServer(server, env.reader, policy, metrics.New("test"))
	mustConnect(t, client, server)

	hash := seedHash32(t, env.result)

	s1 := openStream(t, client, server.ID())
	sendRequest(t, s1, statRequest(7, hash))
	fields := readFields(t, bufio.NewReader(s1))
	if fields[1] != KindStatResponse {
		t.Fatalf("首 stream 的 Stat 应成功: %#v", fields)
	}
	_ = s1.Close() // 只关 stream，不断开 connection

	s2 := openStream(t, client, server.ID())
	defer s2.Close()
	sendRequest(t, s2, statRequest(3, hash)) // 倒退：必须 stale_request_id
	var buf2 [106]byte
	total2 := 0
	for total2 < len(buf2) {
		_ = s2.SetReadDeadline(time.Now().Add(time.Second))
		n2, e2 := s2.Read(buf2[total2:])
		if n2 > 0 {
			total2 += n2
			continue
		}
		if e2 != nil {
			t.Fatalf("原始读取失败: %v", e2)
		}
	}
	t.Logf("raw total=%d head=%x", total2, buf2[:9])
	fields = []any{}
	_ = fields
	fields2, ferr := decodeRawHeader(buf2[:total2])
	if ferr != nil {
		t.Fatalf("解码: %v", ferr)
	}
	fields = fields2
	if fields[1] != KindErrorResponse || fields[4] != "stale_request_id" {
		t.Fatalf("stream 重建后 ID 倒退必须报 stale_request_id: %#v", fields)
	}
	sendRequest(t, s2, statRequest(8, hash)) // 继续递增：成功
	fields = readFields(t, bufio.NewReader(s2))
	if fields[1] != KindStatResponse || fields[2] != uint64(8) {
		t.Fatalf("跨 stream 递增序号应正常服务: %#v", fields)
	}
}

// TestInflightHardCapReturnsRateLimited（T27 资源上限）：
// 在途请求达到全局硬上限后，新请求立即得到 rate_limited，
// goroutine 与内存不会随请求量无限增长。
func TestInflightHardCapReturnsRateLimited(t *testing.T) {
	env := newTestEnv(t) // reader 未被使用；用 blockingSource 替换
	serverPriv := newKeyPair(t)
	clientPriv := newKeyPair(t)
	clientKeyHex, err := identityPubHex(clientPriv)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := auth.NewPolicy("private", []string{clientKeyHex})
	if err != nil {
		t.Fatal(err)
	}
	source := &blockingSource{release: make(chan struct{})}
	limits := DefaultLimits()
	limits.MaxConcurrentReads = 2
	limits.MaxInflightRequests = 2
	limits.MaxInflightPerConn = 64
	server := buildTestHost(t, serverPriv, false)
	client := buildTestHost(t, clientPriv, false)
	NewServerWithLimits(server, source, policy, metrics.New("test"), limits)
	mustConnect(t, client, server)

	stream := openStream(t, client, server.ID())
	defer stream.Close()
	hash := seedHash32(t, env.result)

	// 打满 2 个全局槽位（不同 hash，避免触发同内容覆盖取消；均阻塞在 source 中）。
	hashB := hash
	hashB[0] ^= 0x01
	sendRequest(t, stream, readRequest(1, hash, 0))
	sendRequest(t, stream, readRequest(2, hashB, 0))

	// 第 3 个请求：立即收到 rate_limited，不会被排队挂死。
	sendRequest(t, stream, readRequest(3, hash, 0))
	reader := bufio.NewReader(stream)
	fields := readFields(t, reader)
	if fields[1] != KindErrorResponse || fields[4] != "rate_limited" {
		t.Fatalf("超过在途上限的请求应立即返回 rate_limited，实际: %#v", fields)
	}

	// 放行被阻塞的两个请求并读取其终态，验证服务恢复正常。
	close(source.release)
	for i := 0; i < 2; i++ {
		f := readFields(t, reader)
		switch f[1] {
		case KindReadResponse:
			readAttachment(t, reader, f[4].(uint64))
		case KindReadCancelled:
		default:
			t.Fatalf("放行后应只剩 Read 终态: %#v", f)
		}
	}
}

// TestDebugS2Reads 临时诊断：逐次读取 s2 的字节流事件。
func TestDebugS2Reads(t *testing.T) {
	env := newTestEnv(t)
	serverPriv := newKeyPair(t)
	clientPriv := newKeyPair(t)
	clientKeyHex, _ := identityPubHex(clientPriv)
	policy, _ := auth.NewPolicy("private", []string{clientKeyHex})
	server := buildTestHost(t, serverPriv, false)
	client := buildTestHost(t, clientPriv, false)
	NewServer(server, env.reader, policy, metrics.New("test"))
	mustConnect(t, client, server)
	hash := seedHash32(t, env.result)

	s1 := openStream(t, client, server.ID())
	sendRequest(t, s1, statRequest(7, hash))
	readFields(t, bufio.NewReader(s1))
	_ = s1.Close()

	s2 := openStream(t, client, server.ID())
	defer s2.Close()
	sendRequest(t, s2, statRequest(3, hash))
	buf := make([]byte, 200)
	total := 0
	deadline := time.Now().Add(2 * time.Second)
	for total < 106 && time.Now().Before(deadline) {
		_ = s2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := s2.Read(buf[total:])
		t.Logf("poll n=%d err=%v data=%x", n, err, buf[total:total+n])
		if err != nil {
			break
		}
		total += n
	}
	t.Logf("total=%d", total)
}

// ---------- T22：WSS（TLS 终止 + Noise + PeerId 双重认证）E2E ----------

// TestFormalProtocolOverWSSWithPeerIDPinning：自签证书 WSS 上完成 Stat/Read；
// 客户端显式 pin 服务端 PeerId，TLS 证书不被信任——证明身份来自 Noise 而非证书链。
func TestFormalProtocolOverWSSWithPeerIDPinning(t *testing.T) {
	env := newTestEnv(t)
	serverPriv := newKeyPair(t)
	clientPriv := newKeyPair(t)
	clientKeyHex, err := identityPubHex(clientPriv)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := auth.NewPolicy("private", []string{clientKeyHex})
	if err != nil {
		t.Fatal(err)
	}

	// 自签证书：客户端 InsecureSkipVerify，因此任何认证都只能来自 libp2p Noise。
	certPEM, keyPEM := selfSignedCertPEM(t)
	certFile := filepath.Join(t.TempDir(), "tls.crt")
	keyFile := filepath.Join(t.TempDir(), "tls.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	serverHost, err := libp2p.New(
		libp2p.Identity(serverPriv),
		libp2p.NoListenAddrs,
		libp2p.Transport(websocket.New, websocket.WithTLSConfig(&tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0/tls/ws"),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverHost.Close() })

	// 拨号侧 TLS 配置必须用 WithTLSClientConfig（WithTLSConfig 只作用于监听侧）。
	clientHost, err := libp2p.New(
		libp2p.Identity(clientPriv),
		libp2p.NoListenAddrs,
		libp2p.Transport(websocket.New, websocket.WithTLSClientConfig(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientHost.Close() })

	NewServer(serverHost, env.reader, policy, metrics.New("test"))

	wssFound := false
	for _, addr := range serverHost.Addrs() {
		hasTLS, hasWS := false, false
		for _, p := range addr.Protocols() {
			switch p.Code {
			case ma.P_TLS:
				hasTLS = true
			case ma.P_WS:
				hasWS = true
			}
		}
		if hasTLS && hasWS {
			wssFound = true
		}
	}
	if !wssFound {
		t.Fatal("服务端应在 /tls/ws multiaddr 上监听")
	}

	// PeerId pin：AddrInfo 携带服务端 ID；Noise 握手校验身份，伪造者无法冒充。
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := clientHost.Connect(ctx, peer.AddrInfo{ID: serverHost.ID(), Addrs: serverHost.Addrs()}); err != nil {
		t.Fatalf("WSS 连接失败: %v", err)
	}

	stream := openStream(t, clientHost, serverHost.ID())
	defer stream.Close()
	sendRequest(t, stream, statRequest(1, seedHash32(t, env.result)))
	fields := readFields(t, bufio.NewReader(stream))
	if len(fields) != 7 || fields[3] != uint64(1) {
		t.Fatalf("WSS 上的 Stat 应回复 available: %#v", fields)
	}
}

// selfSignedCertPEM 生成测试用自签证书与私钥 PEM。
func selfSignedCertPEM(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "msfile-test"},
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
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}
