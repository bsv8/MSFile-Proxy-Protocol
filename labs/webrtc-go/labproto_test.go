package webrtc_go_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	_ "github.com/libp2p/go-libp2p/p2p/transport/tcp"
	_ "github.com/libp2p/go-libp2p/p2p/transport/webrtc"

	"msfile.dev/labs/webrtc-go/internal/identity"
	"msfile.dev/labs/webrtc-go/internal/labproto"
	"msfile.dev/labs/webrtc-go/internal/metrics"
)

func TestEchoFrameRoundtrip(t *testing.T) {
	for _, size := range []int{0, 1, 16384, 262144} {
		payload := make([]byte, size)
		if _, err := rand.Read(payload); err != nil {
			t.Fatalf("rand: %v", err)
		}
		frame := labproto.EncodeEchoFrame(payload)
		got, err := labproto.ParseEchoFrame(frame)
		if err != nil {
			t.Fatalf("size %d: parse: %v", size, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("size %d: payload mismatch", size)
		}
	}
	frame := labproto.EncodeEchoFrame(make([]byte, 16))
	frame[0] = 0xFF
	if _, err := labproto.ParseEchoFrame(frame); err == nil {
		t.Fatal("expected mismatched length header to fail")
	}
}

func TestBytesRequestRoundtrip(t *testing.T) {
	req := labproto.BytesRequest{TotalBytes: 1073741824, LogicalBlockBytes: 262144, Seed: 42}
	encoded, err := labproto.EncodeBytesRequest(req)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(encoded) != 20 {
		t.Fatalf("request must be 20 bytes, got %d", len(encoded))
	}
	parsed, err := labproto.ParseBytesRequest(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed != req {
		t.Fatalf("roundtrip mismatch: %+v != %+v", parsed, req)
	}
	bad := req
	bad.LogicalBlockBytes = 0
	if _, err := labproto.EncodeBytesRequest(bad); err == nil {
		t.Fatal("expected zero block size to be rejected")
	}
}

func TestDeterministicDataCrossLanguageFixtures(t *testing.T) {
	fixtures := []struct {
		total  uint64
		seed   uint64
		digest string
	}{
		{0, 1, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{1000, 77, "5a7ceb5425bc2beba3e82801f7b63d7527914ae64d927933cc4709dfbbaf6187"},
		{65537, 42, "a942a93d550c97b5182fd5f5bb4b240e5fb88264c8b899170a1dad0f41d55282"},
		{262144, 7, "601c25f63b6d90ef44c94b747b60bed311c788e7dcd285966de4532b8c5fbc6e"},
	}
	for _, fx := range fixtures {
		if got := labproto.ExpectedDigest(fx.total, fx.seed); got != fx.digest {
			t.Fatalf("digest(total=%d, seed=%d):\n got  %s\n want %s", fx.total, fx.seed, got, fx.digest)
		}
	}
}

func TestGenerateDeterministicDataStreamBoundedWrites(t *testing.T) {
	var totalWritten uint64
	maxChunk := 0
	err := labproto.GenerateDeterministicData(100000, 9, func(chunk []byte) error {
		totalWritten += uint64(len(chunk))
		if len(chunk) > maxChunk {
			maxChunk = len(chunk)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if totalWritten != 100000 {
		t.Fatalf("streamed %d bytes, want 100000", totalWritten)
	}
	if maxChunk > labproto.MaxWriteChunkBytes {
		t.Fatalf("write chunk %d exceeds %d byte cap", maxChunk, labproto.MaxWriteChunkBytes)
	}
}

func TestBytesHeaderAndTrailerRoundtrip(t *testing.T) {
	header := labproto.EncodeBytesResponseHeader(4096)
	if len(header) != 8 {
		t.Fatalf("response header must be 8 bytes, got %d", len(header))
	}
	total, err := labproto.ParseBytesResponsePrefix(header)
	if err != nil {
		t.Fatalf("parse header: %v", err)
	}
	if total != 4096 {
		t.Fatalf("header total mismatch: %d", total)
	}
	trailer, terr := labproto.EncodeBytesTrailer(strings.Repeat("ab", 32))
	if terr != nil {
		t.Fatalf("encode trailer: %v", terr)
	}
	if len(trailer) != 32 {
		t.Fatalf("trailer must be 32 bytes, got %d", len(trailer))
	}
	if _, err := labproto.ParseBytesResponsePrefix(make([]byte, 7)); err == nil {
		t.Fatal("expected short prefix to fail")
	}
	if _, err := labproto.EncodeBytesTrailer("zz"); err == nil {
		t.Fatal("expected invalid trailer hex to fail")
	}
}

func randomScalarHex(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	for {
		if _, err := rand.Read(raw); err != nil {
			t.Fatalf("rand: %v", err)
		}
		if raw[0] != 0 || raw[1] >= 0x10 {
			break
		}
	}
	return hex.EncodeToString(raw)
}

func keyFromHex(t *testing.T, hexKey string) crypto.PrivKey {
	t.Helper()
	priv, err := identity.PrivateKeyFromHex(hexKey)
	if err != nil {
		t.Fatalf("key from hex: %v", err)
	}
	return priv
}

func buildHost(t *testing.T, priv crypto.PrivKey) host.Host {
	t.Helper()
	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
	)
	if err != nil {
		t.Fatalf("new host: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func mustConnect(t *testing.T, from, to host.Host) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := from.Connect(ctx, peer.AddrInfo{ID: to.ID(), Addrs: to.Addrs()})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
}

func openStream(t *testing.T, h host.Host, target peer.ID, proto string) network.Stream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stream, err := h.NewStream(ctx, target, protocol.ID(proto))
	if err != nil {
		t.Fatalf("open stream %s: %v", proto, err)
	}
	return stream
}

func silentLogger() *metrics.Logger {
	return metrics.New("test")
}

func registerServer(t *testing.T, nasHost host.Host, whitelist []string) {
	t.Helper()
	wl, err := identity.NewWhitelist(whitelist)
	if err != nil {
		t.Fatalf("whitelist: %v", err)
	}
	srv := labproto.NewServer(nasHost, wl, silentLogger())
	if err := srv.Register(); err != nil {
		t.Fatalf("register handlers: %v", err)
	}
}

func TestIdentityProtocolReportsConnectionTruth(t *testing.T) {
	vector := loadVector(t)
	nasPriv := keyFromHex(t, randomScalarHex(t))
	clientPriv := keyFromHex(t, vector.PrivateKeyHex)

	nasPubHex, err := identity.CompressedPublicKeyHex(nasPriv)
	if err != nil {
		t.Fatalf("nas pub: %v", err)
	}
	clientPubHex, err := identity.CompressedPublicKeyHex(clientPriv)
	if err != nil {
		t.Fatalf("client pub: %v", err)
	}
	clientID, err := identity.PeerID(clientPriv)
	if err != nil {
		t.Fatalf("client id: %v", err)
	}

	nasHost := buildHost(t, nasPriv)
	clientHost := buildHost(t, clientPriv)
	registerServer(t, nasHost, []string{clientPubHex})
	mustConnect(t, clientHost, nasHost)

	stream := openStream(t, clientHost, nasHost.ID(), labproto.ProtocolIdentity)
	defer stream.Close()

	raw, err := io.ReadAll(io.LimitReader(stream, 64*1024))
	if err != nil {
		t.Fatalf("read identity response: %v", err)
	}
	var diag map[string]any
	if err := json.Unmarshal(raw, &diag); err != nil {
		t.Fatalf("identity response not JSON (%q): %v", string(raw), err)
	}
	if diag["remote_peer_id"] != clientID.String() {
		t.Fatalf("NAS observed remote peer %v, want %s (connection identity must equal business identity)", diag["remote_peer_id"], clientID.String())
	}
	if diag["remote_public_key_hex"] != clientPubHex {
		t.Fatalf("NAS observed remote key %v, want %s", diag["remote_public_key_hex"], clientPubHex)
	}
	if diag["local_public_key_hex"] != nasPubHex {
		t.Fatalf("NAS reported local key %v, want %s", diag["local_public_key_hex"], nasPubHex)
	}
	if diag["transport"] != "tcp" {
		t.Logf("note: transport label was %v in this environment", diag["transport"])
	}
}

func TestEchoAndBytesProtocolsOverRealConnections(t *testing.T) {
	nasPriv := keyFromHex(t, randomScalarHex(t))
	clientPriv := keyFromHex(t, randomScalarHex(t))
	clientPubHex, err := identity.CompressedPublicKeyHex(clientPriv)
	if err != nil {
		t.Fatalf("client pub: %v", err)
	}

	nasHost := buildHost(t, nasPriv)
	clientHost := buildHost(t, clientPriv)
	registerServer(t, nasHost, []string{clientPubHex})
	mustConnect(t, clientHost, nasHost)

	for _, size := range []int{0, 1, 16384, 262144} {
		echoOnce(t, clientHost, nasHost.ID(), size)
	}

	runBytesClient(t, clientHost, nasHost.ID(), labproto.BytesRequest{
		TotalBytes:        1000,
		LogicalBlockBytes: labproto.DefaultBlockBytes,
		Seed:              77,
	})
	runBytesClient(t, clientHost, nasHost.ID(), labproto.BytesRequest{
		TotalBytes:        65537,
		LogicalBlockBytes: labproto.DefaultBlockBytes,
		Seed:              42,
	})
}

func echoOnce(t *testing.T, h host.Host, target peer.ID, size int) {
	t.Helper()
	stream := openStream(t, h, target, labproto.ProtocolEcho)
	defer stream.Close()
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	frame := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint64(frame[0:], uint64(size))
	copy(frame[8:], payload)
	if _, err := stream.Write(frame); err != nil {
		t.Fatalf("echo write: %v", err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("echo closewrite: %v", err)
	}
	response := make([]byte, len(frame))
	if _, err := io.ReadFull(stream, response); err != nil {
		t.Fatalf("echo read (size=%d): %v", size, err)
	}
	echoed, err := labproto.ParseEchoFrame(response)
	if err != nil {
		t.Fatalf("echo frame (size=%d): %v", size, err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("echo mismatch at size %d", size)
	}
}

func runBytesClient(t *testing.T, h host.Host, target peer.ID, req labproto.BytesRequest) {
	t.Helper()
	stream := openStream(t, h, target, labproto.ProtocolBytes)
	defer stream.Close()
	reqRaw, err := labproto.EncodeBytesRequest(req)
	if err != nil {
		t.Fatalf("request encode: %v", err)
	}
	if _, err := stream.Write(reqRaw); err != nil {
		t.Fatalf("request write: %v", err)
	}

	var pending []byte
	hasher := sha256.New()
	received := uint64(0)
	headerSeen := false
	buf := make([]byte, 32*1024)
	for {
		n, rerr := stream.Read(buf)
		if n > 0 {
			pending = append(pending, buf[:n]...)
			if !headerSeen && len(pending) >= 8 {
				announcedTotal := binary.BigEndian.Uint64(pending[:8])
				if announcedTotal != req.TotalBytes {
					t.Fatalf("server announced %d, requested %d", announcedTotal, req.TotalBytes)
				}
				headerSeen = true
				pending = pending[8:]
			}
			if headerSeen && len(pending) > 32 {
				take := len(pending) - 32
				hasher.Write(pending[:take])
				received += uint64(take)
				pending = append([]byte{}, pending[take:]...)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			t.Fatalf("payload read: %v", rerr)
		}
	}
	if !headerSeen {
		t.Fatal("no bytes response header received")
	}
	if received != req.TotalBytes {
		t.Fatalf("received %d payload bytes, want %d", received, req.TotalBytes)
	}
	if len(pending) != 32 {
		t.Fatalf("expected 32-byte sha256 trailer at end of stream, got %d tail bytes", len(pending))
	}
	expectedDigestHex := fmt.Sprintf("%x", hasher.Sum(nil))
	gotDigestHex := hex.EncodeToString(pending)
	if gotDigestHex != expectedDigestHex {
		t.Fatalf("digest mismatch:\n got  %s\n want %s", gotDigestHex, expectedDigestHex)
	}
}

func TestNonWhitelistedClientIsDenied(t *testing.T) {
	nasPriv := keyFromHex(t, randomScalarHex(t))
	allowedPriv := keyFromHex(t, randomScalarHex(t))
	strangerPriv := keyFromHex(t, randomScalarHex(t))

	allowedPub, err := identity.CompressedPublicKeyHex(allowedPriv)
	if err != nil {
		t.Fatalf("allowed pub: %v", err)
	}

	nasHost := buildHost(t, nasPriv)
	registerServer(t, nasHost, []string{allowedPub})

	allowedHost := buildHost(t, allowedPriv)
	mustConnect(t, allowedHost, nasHost)
	stream := openStream(t, allowedHost, nasHost.ID(), labproto.ProtocolIdentity)
	raw, err := io.ReadAll(io.LimitReader(stream, 16*1024))
	if err != nil && !strings.Contains(err.Error(), "reset") {
		t.Fatalf("whitelisted identity read failed unexpectedly: %v", err)
	}
	if !strings.Contains(string(raw), "remote_peer_id") {
		t.Fatalf("whitelisted client should receive diagnostics, got %q (err=%v)", string(raw), err)
	}
	stream.Close()

	strangerHost := buildHost(t, strangerPriv)
	mustConnect(t, strangerHost, nasHost)
	s2 := openStream(t, strangerHost, nasHost.ID(), labproto.ProtocolIdentity)
	_, werr := s2.Write([]byte{0x00})
	if werr != nil {
		t.Logf("stranger stream write refused: %v", werr)
	}
	buf := make([]byte, 1024)
	deadlineCtx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	n := readSome(s2, buf, deadlineCtx)
	if n > 0 {
		t.Fatalf("non-whitelisted client must not receive lab protocol data, got %d bytes", n)
	}
}

func readSome(stream network.Stream, buf []byte, ctx context.Context) int {
	done := make(chan int, 1)
	go func() {
		n, _ := stream.Read(buf)
		done <- n
	}()
	select {
	case n := <-done:
		return n
	case <-ctx.Done():
		return 0
	}
}

func TestSamePrivateKeyProducesIdenticalPeerIdCollision(t *testing.T) {
	keyHex := randomScalarHex(t)
	privA := keyFromHex(t, keyHex)
	idA1, err := identity.PeerID(privA)
	if err != nil {
		t.Fatalf("id a1: %v", err)
	}
	idA2, err := identity.PeerID(privA)
	if err != nil {
		t.Fatalf("id a2: %v", err)
	}
	if idA1 != idA2 {
		t.Fatal("same private key must derive identical peer id")
	}
	hostA := buildHost(t, privA)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = hostA.Connect(ctx, peer.AddrInfo{ID: hostA.ID()})
	if err == nil {
		t.Fatal("dialing own peer id must be diagnosed as an error (peer id collision / self connection), never success")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "self") {
		t.Logf("self-dial diagnostic message: %v", err)
	}
}
