package labproto

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
	ma "github.com/multiformats/go-multiaddr"

	"msfile.dev/labs/webrtc-go/internal/identity"
	"msfile.dev/labs/webrtc-go/internal/metrics"
)

type Server struct {
	host      host.Host
	whitelist *identity.Whitelist
	log       *metrics.Logger
}

func NewServer(h host.Host, wl *identity.Whitelist, log *metrics.Logger) *Server {
	return &Server{host: h, whitelist: wl, log: log}
}

func (s *Server) Register() error {
	handlers := map[protocol.ID]network.StreamHandler{
		ProtocolIdentity: s.wrap(ProtocolIdentity, s.serveIdentity),
		ProtocolEcho:     s.wrap(ProtocolEcho, s.serveEcho),
		ProtocolBytes:    s.wrap(ProtocolBytes, s.serveBytes),
	}
	for pid, handler := range handlers {
		s.host.SetStreamHandler(pid, handler)
	}
	return nil
}

func (s *Server) wrap(protocol string, serve func(network.Stream, connFacts) error) network.StreamHandler {
	return func(stream network.Stream) {
		conn := stream.Conn()
		facts, factsErr := s.facts(conn)
		base := map[string]any{
			"protocol":       protocol,
			"local_peer_id":  facts.localPeerID,
			"remote_peer_id": facts.remotePeerID,
			"transport":      facts.transport,
			"direct":         facts.direct,
			"limited":        facts.limited,
		}
		// 即使 demo 处于免白名单模式，也必须成功取得并验证远端
		// secp256k1 公钥；免除的只是业务白名单匹配，不是身份认证。
		if factsErr != nil || !s.whitelist.Contains(facts.remotePubHex) {
			reason := "public key not whitelisted"
			if factsErr != nil {
				reason = "remote key rejected: " + sanitizeErr(factsErr)
			}
			base["error_code"] = reason
			s.log.Emit("lab_protocol_denied", base)
			stream.Reset()
			return
		}
		started := time.Now()
		err := serve(stream, facts)
		if err != nil {
			base["error_code"] = sanitizeErr(err)
			s.log.Emit("lab_protocol_error", base)
			stream.Reset()
			return
		}
		base["elapsed_ms"] = time.Since(started).Milliseconds()
		s.log.Emit("lab_protocol_served", base)
	}
}

type connFacts struct {
	remotePeerID string
	remotePubHex string
	localPeerID  string
	direction    string
	direct       bool
	limited      bool
	transport    string
}

func (s *Server) facts(conn network.Conn) (connFacts, error) {
	f := connFacts{
		remotePeerID: conn.RemotePeer().String(),
		localPeerID:  s.host.ID().String(),
		direction:    directionString(conn.Stat().Direction),
		direct:       !conn.Stat().Limited,
		limited:      conn.Stat().Limited,
		transport:    TransportKind(conn.RemoteMultiaddr()),
	}
	hexKey, err := identity.RemoteCompressedPubKeyHex(conn.RemotePublicKey())
	if err != nil {
		return f, err
	}
	f.remotePubHex = hexKey
	return f, nil
}

func (s *Server) serveIdentity(stream network.Stream, facts connFacts) error {
	diag := IdentityDiagnostics{
		RemotePeerID:       facts.remotePeerID,
		RemotePublicKeyHex: facts.remotePubHex,
		LocalPeerID:        facts.localPeerID,
		LocalPublicKeyHex:  localPublicKeyHex(s.host),
		Direction:          facts.direction,
		Direct:             facts.direct,
		Limited:            facts.limited,
		Transport:          facts.transport,
	}
	payload, err := json.Marshal(diag)
	if err != nil {
		return err
	}
	if _, err := stream.Write(append(payload, '\n')); err != nil {
		return err
	}
	return stream.CloseWrite()
}

type IdentityDiagnostics struct {
	RemotePeerID       string `json:"remote_peer_id"`
	RemotePublicKeyHex string `json:"remote_public_key_hex"`
	LocalPeerID        string `json:"local_peer_id"`
	LocalPublicKeyHex  string `json:"local_public_key_hex"`
	Direction          string `json:"direction"`
	Direct             bool   `json:"direct"`
	Limited            bool   `json:"limited"`
	Transport          string `json:"transport"`
}

func (s *Server) serveEcho(stream network.Stream, _ connFacts) error {
	defer stream.Close()
	frame, err := readAllWithLimit(stream, EchoMaxPayloadBytes+8)
	if err != nil {
		return err
	}
	payload, err := ParseEchoFrame(frame)
	if err != nil {
		return err
	}
	_, err = stream.Write(EncodeEchoFrame(payload))
	return err
}

var bytesStreamSlots = make(chan struct{}, maxConcurrentBytes)

func (s *Server) serveBytes(stream network.Stream, _ connFacts) error {
	select {
	case bytesStreamSlots <- struct{}{}:
		defer func() { <-bytesStreamSlots }()
	default:
		return fmt.Errorf("too many concurrent lab bytes streams (limit %d)", maxConcurrentBytes)
	}
	if err := stream.SetDeadline(time.Now().Add(2 * time.Hour)); err != nil {
		return fmt.Errorf("set stream deadline: %w", err)
	}
	defer stream.Close()
	reqRaw := make([]byte, bytesRequestSize)
	if _, err := io.ReadFull(stream, reqRaw); err != nil {
		return fmt.Errorf("read bytes request: %w", err)
	}
	req, err := ParseBytesRequest(reqRaw)
	if err != nil {
		return err
	}
	digestHasher := sha256.New()
	if _, err := stream.Write(EncodeBytesResponseHeader(req.TotalBytes)); err != nil {
		return err
	}
	err = GenerateDeterministicData(req.TotalBytes, req.Seed, func(chunk []byte) error {
		digestHasher.Write(chunk)
		_, werr := stream.Write(chunk)
		return werr
	})
	if err != nil {
		return err
	}
	trailer, terr := EncodeBytesTrailer(fmt.Sprintf("%x", digestHasher.Sum(nil)))
	if terr != nil {
		return terr
	}
	_, werr := stream.Write(trailer)
	return werr
}

func localPublicKeyHex(h host.Host) string {
	key := h.Peerstore().PrivKey(h.ID())
	if key == nil {
		return ""
	}
	raw, err := key.GetPublic().Raw()
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", raw)
}

func readAllWithLimit(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("stream exceeded %d byte lab limit", limit)
	}
	return data, nil
}

func sanitizeErr(err error) string {
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

func directionString(d network.Direction) string {
	switch d {
	case network.DirInbound:
		return "inbound"
	case network.DirOutbound:
		return "outbound"
	default:
		return "unknown"
	}
}

func TransportKind(addr ma.Multiaddr) string {
	protos := addr.Protocols()
	for _, p := range protos {
		switch p.Code {
		case ma.P_WEBRTC_DIRECT:
			return "webrtc-direct"
		case ma.P_CIRCUIT:
			return "circuit-relay"
		case ma.P_WS, ma.P_WSS:
			return "websocket"
		case ma.P_QUIC_V1:
			return "quic"
		}
	}
	for _, p := range protos {
		switch p.Code {
		case ma.P_TCP:
			return "tcp"
		case ma.P_UDP:
			return "udp"
		}
	}
	if len(protos) > 0 {
		return protos[0].Name
	}
	return "unknown"
}
