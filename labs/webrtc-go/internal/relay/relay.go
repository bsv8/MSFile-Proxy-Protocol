package relay

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	ma "github.com/multiformats/go-multiaddr"

	"msfile.dev/labs/webrtc-go/internal/identity"
	"msfile.dev/labs/webrtc-go/internal/metrics"
)

type Options struct {
	KeyFile     string
	WSListen    string
	EdgeListen  string
	InfiniteLim bool
}

type byteCounter struct {
	totalIn    atomic.Uint64
	totalOut   atomic.Uint64
	activeConn atomic.Int64
}

func (bc *byteCounter) add(in, out uint64) {
	if in > 0 {
		bc.totalIn.Add(in)
	}
	if out > 0 {
		bc.totalOut.Add(out)
	}
}

func (bc *byteCounter) snapshot() (uint64, uint64, int64) {
	return bc.totalIn.Load(), bc.totalOut.Load(), bc.activeConn.Load()
}

type aclLogger struct {
	log *metrics.Logger
}

func (a *aclLogger) AllowReserve(p peer.ID, addr ma.Multiaddr) bool {
	a.log.Emit("relay_reservation_allowed", map[string]any{
		"remote_peer_id": p.String(),
		"remote_addr":    anonymizeAddr(addr),
	})
	return true
}

func (a *aclLogger) AllowConnect(src peer.ID, srcAddr ma.Multiaddr, dest peer.ID) bool {
	a.log.Emit("relay_circuit_requested", map[string]any{
		"remote_peer_id": src.String(),
		"dest_peer_id":   dest.String(),
		"remote_addr":    anonymizeAddr(srcAddr),
	})
	return true
}

func anonymizeAddr(addr ma.Multiaddr) string {
	s := addr.String()
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

type edgeProxy struct {
	listener net.Listener
	counter  *byteCounter
	log      *metrics.Logger

	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	upstreams map[net.Conn]struct{}
	wg        sync.WaitGroup
	closed    bool
}

func (ep *edgeProxy) track(conn net.Conn) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.conns[conn] = struct{}{}
	ep.counter.activeConn.Add(1)
}

func (ep *edgeProxy) untrack(conn net.Conn) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if _, ok := ep.conns[conn]; ok {
		delete(ep.conns, conn)
		ep.counter.activeConn.Add(-1)
	}
}

func (ep *edgeProxy) registerUpstream(conn net.Conn) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.upstreams[conn] = struct{}{}
}

func (ep *edgeProxy) unregisterUpstream(conn net.Conn) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	delete(ep.upstreams, conn)
}

func (ep *edgeProxy) closeAllConns() {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	for conn := range ep.conns {
		_ = conn.Close()
	}
	for conn := range ep.upstreams {
		_ = conn.Close()
	}
}

func (ep *edgeProxy) snapshotEvent(event string) {
	in, out, active := ep.counter.snapshot()
	ep.log.Emit(event, map[string]any{
		"bytes_received": in,
		"bytes_sent":     out,
		"active_conns":   active,
		"note":           "edge TCP proxy live counters; payload between browsers must NOT move these numbers once the direct WebRTC connection is formed",
	})
}

func Run(opts Options) error {
	log := metrics.New("relay")

	priv, err := identity.LoadPrivateKeyHexFile(opts.KeyFile)
	if err != nil {
		return err
	}
	pubHex, err := identity.CompressedPublicKeyHex(priv)
	if err != nil {
		return err
	}
	selfID, err := identity.PeerID(priv)
	if err != nil {
		return err
	}
	log.Emit("identity_loaded", map[string]any{
		"local_peer_id":  selfID.String(),
		"public_key_hex": pubHex,
	})

	wsListen := opts.WSListen
	if wsListen == "" {
		wsListen = "/ip4/127.0.0.1/tcp/9443/ws"
	}
	wsAddr, err := ma.NewMultiaddr(wsListen)
	if err != nil {
		return fmt.Errorf("parse ws listen addr: %w", err)
	}

	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrs(wsAddr),
	)
	if err != nil {
		return fmt.Errorf("start relay host: %w", err)
	}
	defer h.Close()

	var relayOpts []relay.Option
	if opts.InfiniteLim {
		relayOpts = append(relayOpts, relay.WithInfiniteLimits())
	}
	relayOpts = append(relayOpts, relay.WithACL(&aclLogger{log: log}))
	r, err := relay.New(h, relayOpts...)
	if err != nil {
		return fmt.Errorf("start circuit relay v2 service: %w", err)
	}
	defer r.Close()

	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(n network.Network, conn network.Conn) {
			log.Emit("relay_conn_opened", map[string]any{
				"local_peer_id":  h.ID().String(),
				"remote_peer_id": conn.RemotePeer().String(),
				"transport":      transportLabel(conn.RemoteMultiaddr()),
			})
		},
		DisconnectedF: func(n network.Network, conn network.Conn) {
			log.Emit("relay_conn_closed", map[string]any{
				"local_peer_id":  h.ID().String(),
				"remote_peer_id": conn.RemotePeer().String(),
				"transport":      transportLabel(conn.RemoteMultiaddr()),
				"elapsed_ms":     time.Since(conn.Stat().Opened).Milliseconds(),
			})
		},
	})

	wssPublicAddrs := make([]string, 0)
	for _, a := range h.Addrs() {
		wssPublicAddrs = append(wssPublicAddrs, a.String())
	}
	log.Emit("relay_started", map[string]any{
		"local_peer_id": h.ID().String(),
		"multiaddrs":    wssPublicAddrs,
	})
	fmt.Fprintf(os.Stderr, "Relay PeerId: %s\n", h.ID().String())
	for _, a := range wssPublicAddrs {
		fmt.Fprintf(os.Stderr, "Relay listen: %s\n", a)
	}
	fmt.Fprintf(os.Stderr, "Browser-dialable circuit multiaddr template: %s/p2p/%s/p2p-circuit/webrtc/p2p/<browser-listener-peer-id>\n",
		publicDialablePrefix(wssPublicAddrs), h.ID().String())

	var edgeClose func()
	var edge *edgeProxy
	if opts.EdgeListen != "" {
		edge = startEdgeProxy(log, opts.EdgeListen, resolvedWSAddr(h, wsAddr))
		if edge != nil {
			edge.snapshotEvent("edge_proxy_listening_with_counters")
			edgeClose = edge.stop
			defer edgeClose()
		}
	}

	runCtx, stopRun := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopRun()
	sigusr1 := make(chan os.Signal, 1)
	signal.Notify(sigusr1, syscall.SIGUSR1)
	defer signal.Stop(sigusr1)

	snapshotTicker := time.NewTicker(5 * time.Second)
	defer snapshotTicker.Stop()

loop:
	for {
		select {
		case <-runCtx.Done():
			break loop
		case <-sigusr1:
			if edge != nil {
				_, out, active := edge.counter.snapshot()
				in, _, _ := edge.counter.snapshot()
				log.Emit("relay_counter_snapshot", map[string]any{
					"bytes_received": in,
					"bytes_sent":     out,
					"active_conns":   active,
					"trigger":        "SIGUSR1",
				})
			} else {
				log.Emit("relay_counter_snapshot", map[string]any{"trigger": "SIGUSR1", "note": "no edge proxy configured"})
			}
		case <-snapshotTicker.C:
			if edge != nil {
				edge.snapshotEvent("relay_counter_snapshot")
			}
		}
	}

	in, out, active := uint64(0), uint64(0), int64(0)
	if edge != nil {
		edge.snapshotEvent("relay_stopping")
		if edgeClose != nil {
			edgeClose()
			edgeClose = nil
		}
		in, out, active = edge.counter.snapshot()
	}
	log.Emit("relay_stopping", map[string]any{
		"bytes_received": in,
		"bytes_sent":     out,
		"active_conns":   active,
	})
	if err := r.Close(); err != nil {
		log.Emit("relay_service_close_error", map[string]any{"error_code": err.Error()})
	}
	if err := h.Close(); err != nil {
		return err
	}
	if edge != nil {
		in, out, _ = edge.counter.snapshot()
	}
	log.Emit("relay_stopped", map[string]any{
		"local_peer_id":  h.ID().String(),
		"bytes_received": in,
		"bytes_sent":     out,
	})
	return nil
}

func resolvedWSAddr(h hostLike, fallback ma.Multiaddr) ma.Multiaddr {
	for _, a := range h.Addrs() {
		for _, p := range a.Protocols() {
			if p.Code == ma.P_WS || p.Code == ma.P_WSS {
				return a
			}
		}
	}
	return fallback
}

type hostLike interface {
	Addrs() []ma.Multiaddr
}

func publicDialablePrefix(addrs []string) string {
	if len(addrs) > 0 {
		return addrs[0]
	}
	return "<relay-multiaddr>"
}

func transportLabel(addr ma.Multiaddr) string {
	for _, p := range addr.Protocols() {
		switch p.Code {
		case ma.P_WSS, ma.P_WS:
			return "wss/ws"
		case ma.P_QUIC_V1:
			return "quic"
		case ma.P_TCP:
			return "tcp"
		}
	}
	return "unknown"
}

func startEdgeProxy(log *metrics.Logger, edgeListen string, target ma.Multiaddr) *edgeProxy {
	tcpTarget, err := tcpTargetOf(target)
	if err != nil {
		log.Emit("edge_proxy_disabled", map[string]any{"error_code": err.Error()})
		return nil
	}
	listener, err := net.Listen("tcp", edgeListen)
	if err != nil {
		log.Emit("edge_proxy_failed", map[string]any{"error_code": err.Error()})
		return nil
	}
	ep := &edgeProxy{
		listener:  listener,
		counter:   &byteCounter{},
		log:       log,
		conns:     make(map[net.Conn]struct{}),
		upstreams: make(map[net.Conn]struct{}),
	}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			ep.track(conn)
			ep.wg.Add(1)
			go func() {
				defer ep.wg.Done()
				handleEdgeConn(log, ep, conn, tcpTarget)
				ep.untrack(conn)
			}()
		}
	}()
	log.Emit("edge_proxy_listening", map[string]any{
		"edge":            listener.Addr().String(),
		"upstream_target": tcpTarget,
	})
	return ep
}

func (ep *edgeProxy) stop() {
	ep.mu.Lock()
	if ep.closed {
		ep.mu.Unlock()
		return
	}
	ep.closed = true
	ep.mu.Unlock()
	_ = ep.listener.Close()
	ep.closeAllConns()
	waitDone := make(chan struct{})
	go func() {
		ep.wg.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
	case <-time.After(10 * time.Second):
		ep.log.Emit("edge_proxy_stop_timeout", map[string]any{})
	}
}

type countingReader struct {
	r       io.Reader
	n       atomic.Uint64
	onBytes func(delta uint64)
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.n.Add(uint64(n))
		if c.onBytes != nil {
			c.onBytes(uint64(n))
		}
	}
	return n, err
}

type countingWriter struct {
	w       io.Writer
	n       atomic.Uint64
	onBytes func(delta uint64)
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		c.n.Add(uint64(n))
		if c.onBytes != nil {
			c.onBytes(uint64(n))
		}
	}
	return n, err
}

func handleEdgeConn(log *metrics.Logger, ep *edgeProxy, client net.Conn, target string) {
	defer client.Close()
	upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		log.Emit("edge_proxy_dial_failed", map[string]any{"error_code": err.Error()})
		return
	}
	defer upstream.Close()
	defer ep.unregisterUpstream(upstream)
	ep.registerUpstream(upstream)

	started := time.Now()
	if tcp, ok := upstream.(*net.TCPConn); ok {
		_ = tcp.SetReadDeadline(time.Now().Add(2 * time.Hour))
	}
	var clientToUpstream, upstreamToClient atomic.Uint64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		cr := &countingReader{r: client, onBytes: func(delta uint64) { ep.counter.add(delta, 0) }}
		_, _ = io.Copy(upstream, cr)
		clientToUpstream.Store(cr.n.Load())
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	cw := &countingWriter{w: client, onBytes: func(delta uint64) { ep.counter.add(0, delta) }}
	_, _ = io.Copy(cw, upstream)
	upstreamToClient.Store(cw.n.Load())
	if tcp, ok := client.(*net.TCPConn); ok {
		_ = tcp.CloseRead()
	}
	wgWait := make(chan struct{})
	go func() {
		wg.Wait()
		close(wgWait)
	}()
	select {
	case <-wgWait:
	case <-time.After(10 * time.Second):
	}
	in := clientToUpstream.Load()
	out := upstreamToClient.Load()
	log.Emit("edge_conn_closed", map[string]any{
		"bytes_received": in,
		"bytes_sent":     out,
		"elapsed_ms":     time.Since(started).Milliseconds(),
	})
}

func tcpTargetOf(addr ma.Multiaddr) (string, error) {
	hasTCP := false
	for _, p := range addr.Protocols() {
		if p.Code == ma.P_TCP {
			hasTCP = true
		}
	}
	if !hasTCP {
		return "", fmt.Errorf("ws listen addr has no tcp component")
	}
	var ip, port string
	for _, comp := range ma.Split(addr) {
		switch comp.Protocol().Code {
		case ma.P_IP4, ma.P_IP6:
			ip = comp.Value()
		case ma.P_TCP:
			port = comp.Value()
		}
	}
	if ip == "" || port == "" {
		return "", fmt.Errorf("could not derive ip:port from ws listen addr")
	}
	if _, err := strconv.Atoi(port); err != nil {
		return "", fmt.Errorf("bad port %q", port)
	}
	return net.JoinHostPort(ip, port), nil
}
