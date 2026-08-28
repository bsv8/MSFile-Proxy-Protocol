package config

// 本文件覆盖施工单 G01-G04：
// WebRTC Direct 公网基础地址的形态校验、重复地址顺序、listener 约束与运行时补齐。

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	ma "github.com/multiformats/go-multiaddr"

	"msfile.dev/labs/webrtc-go/internal/identity"
)

func TestNormalizeWebRTCDirectPublicAddresses(t *testing.T) {
	got, err := NormalizeWebRTCDirectPublicAddresses([]string{
		"  /ip4/203.0.113.10/udp/4001/webrtc-direct ",
		"/dns4/direct.example.com/udp/4002/webrtc-direct",
		"/ip4/203.0.113.10/udp/4001/webrtc-direct",
		"/ip6/2001:4860:4860::8888/udp/4003/webrtc-direct",
	})
	if err != nil {
		t.Fatalf("合法公网基础地址不应报错: %v", err)
	}
	want := []string{
		"/ip4/203.0.113.10/udp/4001/webrtc-direct",
		"/dns4/direct.example.com/udp/4002/webrtc-direct",
		"/ip6/2001:4860:4860::8888/udp/4003/webrtc-direct",
	}
	if len(got) != len(want) {
		t.Fatalf("地址应按首次出现顺序去重，实际 %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("第 %d 条规范化地址 = %q，期望 %q", i+1, got[i], want[i])
		}
	}
}

func TestRejectInvalidWebRTCDirectPublicAddresses(t *testing.T) {
	cases := []struct {
		name string
		addr string
		want string
	}{
		{"空地址", "", "不能为空"},
		{"unspecified IPv4", "/ip4/0.0.0.0/udp/4001/webrtc-direct", "unspecified"},
		{"loopback IPv4", "/ip4/127.0.0.1/udp/4001/webrtc-direct", "loopback"},
		{"multicast IPv4", "/ip4/224.0.0.1/udp/4001/webrtc-direct", "multicast"},
		{"link-local IPv4", "/ip4/169.254.1.1/udp/4001/webrtc-direct", "link-local"},
		{"private IPv4", "/ip4/192.168.1.10/udp/4001/webrtc-direct", "私网"},
		{"TCP instead of UDP", "/ip4/203.0.113.10/tcp/4001/webrtc-direct", "形态"},
		{"zero UDP port", "/ip4/203.0.113.10/udp/0/webrtc-direct", "1..65535"},
		{"extra certhash", "/ip4/203.0.113.10/udp/4001/webrtc-direct/certhash/uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g", "不能携带"},
		{"DNS with extra p2p", "/dns4/direct.example.com/udp/4001/webrtc-direct/p2p/QmYwAPJzv5CZsnAzt8auVZRn4w2dR4wGxD9sJbTj6YdQ8S", "不能携带"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NormalizeWebRTCDirectPublicAddress(tc.addr)
			if err == nil {
				t.Fatal("非法公网基础地址不应通过校验")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("错误信息应包含 %q，实际: %v", tc.want, err)
			}
		})
	}
}

func TestValidateNetworkListenerPublicationConstraint(t *testing.T) {
	const direct = "/ip4/0.0.0.0/udp/4001/webrtc-direct"
	const ws = "/ip4/127.0.0.1/tcp/8080/ws"
	const publicBase = "/ip4/203.0.113.10/udp/4001/webrtc-direct"

	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "监听 Direct 但没有公网发布地址",
			cfg:  Config{ListenAddrs: []string{direct, ws}},
			want: "至少配置一项",
		},
		{
			name: "没有 Direct listener 却配置公网发布地址",
			cfg:  Config{ListenAddrs: []string{ws}, WebRTCDirectPublicAddresses: []string{publicBase}},
			want: "未监听 WebRTC Direct",
		},
		{
			name: "共享入口缺失",
			cfg:  Config{ListenAddrs: []string{direct}, WebRTCDirectPublicAddresses: []string{publicBase}},
			want: "共享 Web/WS 入口",
		},
		{
			name: "非 loopback 共享入口没有 token",
			cfg:  Config{ListenAddrs: []string{"/ip4/0.0.0.0/tcp/443/ws"}},
			want: "admin_token",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.ValidateNetwork(); err == nil {
				t.Fatal("应拒绝不完整或不安全的网络配置")
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("错误信息应包含 %q，实际: %v", tc.want, err)
			}
		})
	}

	valid := Config{
		ListenAddrs:                 []string{direct, ws},
		WebRTCDirectPublicAddresses: []string{publicBase},
		AdminToken:                  "test-token",
	}
	if err := valid.ValidateNetwork(); err != nil {
		t.Fatalf("完整网络配置不应报错: %v", err)
	}
}

func TestCompleteWebRTCDirectAddressesUsesRuntimeIdentity(t *testing.T) {
	priv, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		t.Fatalf("生成测试身份失败: %v", err)
	}
	peerID, err := identity.PeerID(priv)
	if err != nil {
		t.Fatalf("派生测试 PeerId 失败: %v", err)
	}
	const publicBase = "/dns4/direct.example.com/udp/4001/webrtc-direct"
	const certHash = "uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g"

	addresses, err := CompleteWebRTCDirectAddresses(
		[]string{publicBase, publicBase}, certHash, peerID.String())
	if err != nil {
		t.Fatalf("补齐运行时 certhash/PeerId 失败: %v", err)
	}
	if len(addresses) != 1 {
		t.Fatalf("补齐结果应保留去重后的 1 条地址，实际 %q", addresses)
	}

	parsed, err := ma.NewMultiaddr(addresses[0])
	if err != nil {
		t.Fatalf("补齐结果不是合法 multiaddr: %v", err)
	}
	if got, _ := parsed.ValueForProtocol(ma.P_CERTHASH); got != certHash {
		t.Fatalf("certhash = %q，期望 %q", got, certHash)
	}
	if got, _ := parsed.ValueForProtocol(ma.P_P2P); got != peerID.String() {
		t.Fatalf("PeerId = %q，期望 %q", got, peerID)
	}
	if strings.Count(addresses[0], "/certhash/") != 1 || strings.Count(addresses[0], "/p2p/") != 1 {
		t.Fatalf("完整地址应各包含一个 certhash 与 PeerId: %q", addresses[0])
	}
}
