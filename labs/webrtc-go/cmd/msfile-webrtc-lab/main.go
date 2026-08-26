// msfile-webrtc-lab 是互通实验 binary，与正式 msfile-nas 完全无关：
//
//	genkey  生成测试用 secp256k1 私钥 hex
//	labnas  只注册 /msfile-lab/* 实验协议，供浏览器 WebRTC 互通诊断；
//	        不打开正式 seed_data/index.sqlite，不扫描 nas_data，不提供文件服务
//	relay   Circuit Relay v2 信令基础设施（只转发预留与 SDP/ICE）
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/libp2p/go-libp2p"
	webrtc "github.com/libp2p/go-libp2p/p2p/transport/webrtc"
	websocket "github.com/libp2p/go-libp2p/p2p/transport/websocket"

	"msfile.dev/labs/webrtc-go/internal/identity"
	"msfile.dev/labs/webrtc-go/internal/labproto"
	"msfile.dev/labs/webrtc-go/internal/metrics"
	"msfile.dev/labs/webrtc-go/internal/relay"
)

type repeatedString []string

func (r *repeatedString) String() string { return strings.Join(*r, ",") }
func (r *repeatedString) Set(v string) error {
	*r = append(*r, v)
	return nil
}

const usage = `msfile-webrtc-lab - MSFile libp2p WebRTC / same-key identity lab (test-only)

Usage:
  msfile-webrtc-lab genkey
  msfile-webrtc-lab labnas --identity-key-file <file> --allow-public-key <hex>... [--listen <multiaddr>]...
  msfile-webrtc-lab relay --identity-key-file <file> [--ws-listen <multiaddr>] [--edge-listen <ip:port>] [--infinite-limits]

Roles:
  labnas  WebRTC/WS listener serving ONLY the experimental /msfile-lab/* protocols.
          It never opens the formal seed_data/index.sqlite and never scans nas_data.
  relay   Circuit Relay v2 signaling infrastructure (reservation + SDP/ICE only).

注意：labnas 的白名单必须显式给出；空白名单拒绝全部客户端，没有 allow-all 回退。
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
	case "labnas":
		err = runLabNas(os.Args[2:])
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
		fmt.Fprintf(os.Stderr, "错误：%v\n", err)
		os.Exit(1)
	}
}

func runGenkey() error {
	raw := make([]byte, identity.Secp256k1PrivKeyLen)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("读取 crypto/rand: %w", err)
	}
	fmt.Println(strings.ToLower(hex.EncodeToString(raw)))
	return nil
}

// runLabNas 启动纯实验协议服务；绝不触碰正式数据区。
func runLabNas(args []string) error {
	flags := flag.NewFlagSet("labnas", flag.ExitOnError)
	keyFile := flags.String("identity-key-file", "", "测试用 32 字节 secp256k1 私钥 hex 文件路径")
	var listenAddrs repeatedString
	flags.Var(&listenAddrs, "listen", "监听 multiaddr（可重复；webrtc-direct、ws）")
	var allowKeys repeatedString
	flags.Var(&allowKeys, "allow-public-key", "浏览器压缩公钥 hex（66 位，可重复；必须显式提供）")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" {
		return errors.New("--identity-key-file 不能为空")
	}
	if len(allowKeys) == 0 {
		return errors.New("labnas 必须显式提供 --allow-public-key；空白名单拒绝全部客户端")
	}
	priv, err := identity.LoadPrivateKeyHexFile(*keyFile)
	if err != nil {
		return err
	}
	whitelist, err := identity.NewWhitelist(allowKeys)
	if err != nil {
		return fmt.Errorf("解析 --allow-public-key: %w", err)
	}
	addrs := listenAddrs
	if len(addrs) == 0 {
		addrs = []string{"/ip4/127.0.0.1/udp/4001/webrtc-direct", "/ip4/127.0.0.1/tcp/4002/ws"}
	}
	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings(addrs...),
		libp2p.Transport(webrtc.New),
		libp2p.Transport(websocket.New),
	)
	if err != nil {
		return fmt.Errorf("启动 libp2p host 失败: %w", err)
	}
	defer h.Close()
	log := metrics.New("labnas")
	if err := labproto.NewServer(h, whitelist, log).Register(); err != nil {
		return err
	}
	selfID := h.ID().String()
	log.Emit("labnas_started", map[string]any{
		"local_peer_id": selfID,
		"whitelist":     whitelist.Size(),
		"note_zh":       "实验协议仅供互通诊断，不是正式文件服务",
	})
	fmt.Fprintf(os.Stderr, "LabNAS PeerId: %s\n", selfID)
	for _, addr := range h.Addrs() {
		fmt.Fprintf(os.Stderr, "LabNAS multiaddr: %s/p2p/%s\n", addr, selfID)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	log.Emit("labnas_stopping", map[string]any{})
	return h.Close()
}

func runRelay(args []string) error {
	flags := flag.NewFlagSet("relay", flag.ExitOnError)
	keyFile := flags.String("identity-key-file", "", "测试用 secp256k1 私钥 hex 文件路径")
	wsListen := flags.String("ws-listen", "/ip4/127.0.0.1/tcp/9443/ws", "libp2p websocket 监听 multiaddr")
	edgeListen := flags.String("edge-listen", "", "可选的裸 TCP 边缘代理 ip:port，用于 TLS 终止方字节统计")
	infinite := flags.Bool("infinite-limits", false, "禁用 Circuit v2 带宽/时长限额（仅限实验环境）")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" {
		return errors.New("--identity-key-file 不能为空")
	}
	return relay.Run(relay.Options{
		KeyFile:     *keyFile,
		WSListen:    *wsListen,
		EdgeListen:  *edgeListen,
		InfiniteLim: *infinite,
	})
}
