package msfile

// 本文件把 github.com/bsv8/bitcoin-libp2p@v0.1.0 当作身份与连接协议真值，
// 验证其标准 Noise/Yamux host 可以直接访问 MSFile 的 WS 业务 stream。

import (
	"bufio"
	"context"
	"encoding/hex"
	"testing"
	"time"

	bitcoingolibp2p "github.com/bsv8/bitcoin-libp2p/golibp2p"
	bitcoinsigner "github.com/bsv8/bitcoin-libp2p/signer"
	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	websocket "github.com/libp2p/go-libp2p/p2p/transport/websocket"

	"msfile.dev/labs/webrtc-go/internal/auth"
	"msfile.dev/labs/webrtc-go/internal/metrics"
)

func TestBitcoinLibp2pUpstreamClientInteroperatesOverWS(t *testing.T) {
	env := newTestEnv(t)

	// 固定合法测试标量，避免随机数极小概率落到 secp256k1 非法范围造成伪失败。
	rawClientKey := make([]byte, 32)
	rawClientKey[31] = 2
	upstreamSigner, err := bitcoinsigner.NewLocalSigner(rawClientKey)
	if err != nil {
		t.Fatalf("创建 bitcoin-libp2p 测试 signer 失败: %v", err)
	}
	clientPublicKeyHex := hex.EncodeToString(upstreamSigner.PublicKey())
	policy, err := auth.NewPolicy("private", []string{clientPublicKeyHex})
	if err != nil {
		t.Fatal(err)
	}

	serverHost := buildTestHost(t, newKeyPair(t), true)
	NewServer(serverHost, env.reader, policy, metrics.New("bitcoin-libp2p-interop-test"))

	upstreamHost, err := bitcoingolibp2p.NewHost(bitcoingolibp2p.HostConfig{
		Signer: upstreamSigner,
		// 不监听；只作为拨号客户端。WebSocket transport 由 MSFile 场景显式注入。
		MuxerOptions: []libp2p.Option{libp2p.NoListenAddrs},
		TransportOptions: []libp2p.Option{
			libp2p.Transport(websocket.New),
		},
	})
	if err != nil {
		t.Fatalf("创建 bitcoin-libp2p 上游 host 失败: %v", err)
	}
	t.Cleanup(func() { _ = upstreamHost.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := upstreamHost.Connect(ctx, peer.AddrInfo{ID: serverHost.ID(), Addrs: serverHost.Addrs()}); err != nil {
		t.Fatalf("bitcoin-libp2p 上游 host 连接 MSFile WS 失败: %v", err)
	}

	hash := seedHash32(t, env.result)
	stream := openStream(t, upstreamHost, serverHost.ID())
	defer stream.Close()
	sendRequest(t, stream, statRequest(1, hash))
	_ = stream.CloseWrite()
	fields := readFields(t, bufio.NewReader(stream))
	if len(fields) != 7 || fields[1] != KindStatResponse || fields[3] != uint64(1) {
		t.Fatalf("上游 host 的 Stat 应返回 available，实际 %#v", fields)
	}
	if upstreamHost.ID().String() == "" || clientPublicKeyHex == "" {
		t.Fatal("上游身份派生结果不得为空")
	}
}
