package config

// 本文件只处理 WebRTC Direct 公网地址的静态模型。
// 公网基础地址来自 YAML；certhash 与 PeerId 由运行中的 libp2p host 补齐。

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	ma "github.com/multiformats/go-multiaddr"
)

// NormalizeWebRTCDirectPublicAddress 校验并规范化一条 WebRTC Direct 公网基础地址。
// 允许的最终形态只有：ip4/ip6/dns4/dns6 + udp + webrtc-direct。
// 返回值不包含 certhash 或 p2p，这两个字段必须由运行时身份补齐。
func NormalizeWebRTCDirectPublicAddress(raw string) (string, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return "", errors.New("公网基础地址不能为空")
	}
	addr, err := ma.NewMultiaddr(text)
	if err != nil {
		return "", fmt.Errorf("不是合法的 multiaddr: %w", err)
	}
	protocols := addr.Protocols()
	if len(protocols) != 3 {
		return "", errors.New("只允许 ip4/ip6/dns4/dns6、udp、webrtc-direct 三段，不能携带 certhash、p2p、ws、tls 或其他协议")
	}
	if !isAllowedPublicHostProtocol(protocols[0].Code) || protocols[1].Code != ma.P_UDP || protocols[2].Code != ma.P_WEBRTC_DIRECT {
		return "", errors.New("形态必须是 /ip4/<公网IP>/udp/<端口>/webrtc-direct、/ip6/...、/dns4/... 或 /dns6/...")
	}

	portText, err := addr.ValueForProtocol(ma.P_UDP)
	if err != nil {
		return "", errors.New("缺少 UDP 端口")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("UDP 端口 %q 不合法，必须在 1..65535 之间", portText)
	}

	switch protocols[0].Code {
	case ma.P_IP4, ma.P_IP6:
		value, valueErr := addr.ValueForProtocol(protocols[0].Code)
		if valueErr != nil {
			return "", fmt.Errorf("读取公网 IP 失败: %w", valueErr)
		}
		ip := net.ParseIP(value)
		if ip == nil {
			return "", fmt.Errorf("公网 IP %q 不合法", value)
		}
		if isForbiddenPublicIP(ip) {
			return "", fmt.Errorf("公网 IP %q 不能是 unspecified、loopback、multicast、link-local 或私网地址", value)
		}
	}

	return addr.String(), nil
}

// NormalizeWebRTCDirectPublicAddresses 校验、规范化并按首次出现顺序去重地址。
func NormalizeWebRTCDirectPublicAddresses(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(raw))
	normalized := make([]string, 0, len(raw))
	for i, address := range raw {
		canonical, err := NormalizeWebRTCDirectPublicAddress(address)
		if err != nil {
			return nil, fmt.Errorf("配置错误：webrtc_direct_public_addresses 第 %d 项不合法：%w", i+1, err)
		}
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}
	return normalized, nil
}

// CompleteWebRTCDirectAddress 把一个已校验的公网基础地址补齐为可拨号地址。
// 这是纯函数：不解析 DNS、不读取本机 listener，也不修改传入配置。
func CompleteWebRTCDirectAddress(publicBase, certhash, peerID string) (string, error) {
	base, err := NormalizeWebRTCDirectPublicAddress(publicBase)
	if err != nil {
		return "", fmt.Errorf("公网基础地址不合法: %w", err)
	}
	if strings.TrimSpace(certhash) == "" {
		return "", errors.New("运行时 certhash 不能为空")
	}
	if strings.TrimSpace(peerID) == "" {
		return "", errors.New("运行时 PeerId 不能为空")
	}
	certAddr, err := ma.NewMultiaddr("/certhash/" + strings.TrimSpace(certhash))
	if err != nil {
		return "", fmt.Errorf("运行时 certhash 不合法: %w", err)
	}
	peerAddr, err := ma.NewMultiaddr("/p2p/" + strings.TrimSpace(peerID))
	if err != nil {
		return "", fmt.Errorf("运行时 PeerId 不合法: %w", err)
	}
	return ma.StringCast(base).Encapsulate(certAddr).Encapsulate(peerAddr).String(), nil
}

// CompleteWebRTCDirectAddresses 为多条公网基础地址补齐相同运行时身份。
func CompleteWebRTCDirectAddresses(publicBases []string, certhash, peerID string) ([]string, error) {
	normalized, err := NormalizeWebRTCDirectPublicAddresses(publicBases)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(normalized))
	for _, base := range normalized {
		address, completeErr := CompleteWebRTCDirectAddress(base, certhash, peerID)
		if completeErr != nil {
			return nil, completeErr
		}
		out = append(out, address)
	}
	return out, nil
}

func isAllowedPublicHostProtocol(code int) bool {
	return code == ma.P_IP4 || code == ma.P_IP6 || code == ma.P_DNS4 || code == ma.P_DNS6
}

func isForbiddenPublicIP(ip net.IP) bool {
	return ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsPrivate()
}
