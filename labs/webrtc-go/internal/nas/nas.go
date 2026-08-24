package nas

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	webrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	ma "github.com/multiformats/go-multiaddr"

	"msfile.dev/labs/webrtc-go/internal/identity"
	"msfile.dev/labs/webrtc-go/internal/labproto"
	"msfile.dev/labs/webrtc-go/internal/metrics"
)

type Options struct {
	KeyFile         string
	ListenAddrs     []string
	AllowPublicKeys []string
	RelayListenAddr string
}

func Run(opts Options) error {
	log := metrics.New("nas")

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

	wl, err := identity.NewWhitelist(opts.AllowPublicKeys)
	if err != nil {
		return err
	}
	log.Emit("whitelist_loaded", map[string]any{
		"entries":   wl.Size(),
		"allow_all": wl.AllowsAll(),
		"note_zh":   "未配置白名单时允许任意已通过 Noise 身份认证的 secp256k1 客户端；仅限 demo",
	})
	if wl.AllowsAll() {
		fmt.Fprintln(os.Stderr, "警告：demo 免白名单模式已启用；允许任意已认证的 secp256k1 客户端访问实验协议")
	}

	listenAddrs := opts.ListenAddrs
	if len(listenAddrs) == 0 {
		listenAddrs = []string{"/ip4/0.0.0.0/udp/4001/webrtc-direct"}
	}
	maddrs := make([]ma.Multiaddr, 0, len(listenAddrs))
	for _, a := range listenAddrs {
		parsed, perr := ma.NewMultiaddr(a)
		if perr != nil {
			return fmt.Errorf("parse listen addr %q: %w", a, perr)
		}
		maddrs = append(maddrs, parsed)
	}

	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrs(maddrs...),
		libp2p.Transport(webrtc.New),
	)
	if err != nil {
		return fmt.Errorf("start nas host: %w", err)
	}
	defer h.Close()
	log.Emit("nas_started", map[string]any{
		"local_peer_id": h.ID().String(),
	})

	directAddrs := filterWebRTCDirect(h)
	withSelf := make([]string, 0, len(directAddrs))
	for _, a := range directAddrs {
		fullStr := fmt.Sprintf("%s/p2p/%s", a, h.ID().String())
		if _, perr := ma.NewMultiaddr(fullStr); perr != nil {
			continue
		}
		withSelf = append(withSelf, fullStr)
	}
	log.Emit("webrtc_direct_addrs", map[string]any{
		"multiaddrs": withSelf,
		"note":       "certhash is deterministic from the identity key and stays stable across restarts (go-libp2p v0.49.0)",
	})
	fmt.Fprintf(os.Stderr, "NAS PeerId: %s\n", h.ID().String())
	for _, a := range withSelf {
		fmt.Fprintf(os.Stderr, "NAS webrtc-direct multiaddr (copy-ready): %s\n", a)
	}

	srv := labproto.NewServer(h, wl, log)
	if err := srv.Register(); err != nil {
		return err
	}
	log.Emit("lab_protocols_registered", map[string]any{})

	if opts.RelayListenAddr != "" {
		if ProbePrivateWebRTCListener() {
			log.Emit("webrtc_private_listener_probe", map[string]any{
				"result":     "supported",
				"capability": "webrtc_private_listener = supported",
			})
			fmt.Fprintln(os.Stderr, "webrtc_private_listener = supported")
		} else {
			log.Emit("webrtc_private_listener_probe", map[string]any{
				"result":       "UNSUPPORTED_UPSTREAM",
				"capability":   "webrtc_private_listener = unsupported",
				"upstream_ref": "go-libp2p v0.49.0 p2p/transport/webrtc registers only P_WEBRTC_DIRECT; relay-signaled /webrtc is not implemented upstream",
			})
			fmt.Fprintln(os.Stderr, "UNSUPPORTED_UPSTREAM: go-libp2p v0.49.0 does not implement the relay-signaled /webrtc listener; --relay-listen ignored")
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	return gracefulStop(log, h)
}

func gracefulStop(log *metrics.Logger, h host.Host) error {
	log.Emit("nas_stopping", map[string]any{})
	if err := h.Close(); err != nil {
		return err
	}
	log.Emit("nas_stopped", map[string]any{"local_peer_id": h.ID().String()})
	return nil
}

func filterWebRTCDirect(h host.Host) []string {
	var out []string
	for _, addr := range h.Addrs() {
		for _, p := range addr.Protocols() {
			if p.Code == ma.P_WEBRTC_DIRECT {
				out = append(out, addr.String())
				break
			}
		}
	}
	return out
}

func ProbePrivateWebRTCListener() bool {
	h, err := libp2p.New(libp2p.NoListenAddrs, libp2p.Transport(webrtc.New))
	if err != nil {
		return false
	}
	defer h.Close()
	addr, err := ma.NewMultiaddr("/ip4/127.0.0.1/udp/0/webrtc")
	if err != nil {
		return false
	}
	if listenErr := h.Network().Listen(addr); listenErr != nil {
		return false
	}
	return true
}
