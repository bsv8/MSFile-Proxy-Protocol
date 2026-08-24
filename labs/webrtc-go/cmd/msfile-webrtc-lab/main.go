package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"msfile.dev/labs/webrtc-go/internal/identity"
	"msfile.dev/labs/webrtc-go/internal/nas"
	"msfile.dev/labs/webrtc-go/internal/relay"
)

type repeatedString []string

func (r *repeatedString) String() string {
	return strings.Join(*r, ",")
}

func (r *repeatedString) Set(v string) error {
	*r = append(*r, v)
	return nil
}

const usage = `msfile-webrtc-lab - MSFile libp2p WebRTC / same-key identity lab (test-only keys)

Usage:
  msfile-webrtc-lab genkey
  msfile-webrtc-lab nas --identity-key-file <file> [--listen <multiaddr>]... [--allow-public-key <hex>]... [--relay-listen <multiaddr>]
  msfile-webrtc-lab relay --identity-key-file <file> [--ws-listen <multiaddr>] [--edge-listen <ip:port>] [--infinite-limits]

Roles:
  nas     WebRTC Direct listener serving the three lab protocols with public key whitelist auth.
  relay   Circuit Relay v2 signaling infrastructure (reservation + SDP/ICE only, never MSFile payload).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "genkey":
		err = runGenkey()
	case "nas":
		err = runNas(os.Args[2:])
	case "relay":
		err = runRelay(os.Args[2:])
	case "help", "-h", "--help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runGenkey() error {
	raw := make([]byte, identity.Secp256k1PrivKeyLen)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("read crypto/rand: %w", err)
	}
	fmt.Println(strings.ToLower(hex.EncodeToString(raw)))
	return nil
}

func runNas(args []string) error {
	fs := flag.NewFlagSet("nas", flag.ExitOnError)
	keyFile := fs.String("identity-key-file", "", "path to file containing the 32-byte test-only secp256k1 private key hex")
	var listenAddrs repeatedString
	fs.Var(&listenAddrs, "listen", "WebRTC Direct listen multiaddr (repeatable)")
	var allowKeys repeatedString
	fs.Var(&allowKeys, "allow-public-key", "浏览器压缩公钥 hex（66 字符，可重复）；不传时 demo 允许所有已认证 secp256k1 客户端")
	relayListen := fs.String("relay-listen", "", "optional relay-signaled /webrtc listen multiaddr (probe only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" {
		return fmt.Errorf("--identity-key-file is required")
	}
	return nas.Run(nas.Options{
		KeyFile:         *keyFile,
		ListenAddrs:     listenAddrs,
		AllowPublicKeys: allowKeys,
		RelayListenAddr: *relayListen,
	})
}

func runRelay(args []string) error {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	keyFile := fs.String("identity-key-file", "", "path to file containing the test-only secp256k1 private key hex")
	wsListen := fs.String("ws-listen", "/ip4/127.0.0.1/tcp/9443/ws", "libp2p websocket listen multiaddr")
	edgeListen := fs.String("edge-listen", "", "optional raw TCP edge proxy ip:port for byte accounting behind a TLS terminator")
	infinite := fs.Bool("infinite-limits", false, "disable circuit v2 bandwidth/duration limits (lab only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" {
		return fmt.Errorf("--identity-key-file is required")
	}
	return relay.Run(relay.Options{
		KeyFile:     *keyFile,
		WSListen:    *wsListen,
		EdgeListen:  *edgeListen,
		InfiniteLim: *infinite,
	})
}
