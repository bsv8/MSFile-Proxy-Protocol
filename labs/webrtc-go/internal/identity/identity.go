package identity

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	bitcoingolibp2p "github.com/bsv8/bitcoin-libp2p/golibp2p"
	bitcoinidentity "github.com/bsv8/bitcoin-libp2p/identity"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	CompressedSecp256k1PubKeyLen = 33
	Secp256k1PrivKeyLen          = 32
)

var ErrNotSecp256k1 = errors.New("peer public key is not secp256k1")

func LoadPrivateKeyHexFile(path string) (crypto.PrivKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取身份私钥文件失败: %w", err)
	}
	return PrivateKeyFromHex(strings.TrimSpace(string(raw)))
}

func PrivateKeyFromHex(s string) (crypto.PrivKey, error) {
	// bitcoin-libp2p 是身份规则真值：这里不再自行实现 secp256k1
	// 标量范围判断，统一接受且只接受 1..n-1 的 32 字节私钥。
	bin, err := bitcoinidentity.ParsePrivateKeyHex(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("私钥必须是 32 字节 secp256k1 标量（范围 1..n-1）: %w", err)
	}
	priv, err := crypto.UnmarshalSecp256k1PrivateKey(bin)
	if err != nil {
		return nil, fmt.Errorf("转换为 libp2p secp256k1 私钥失败: %w", err)
	}
	return priv, nil
}

func CompressedPublicKeyHex(priv crypto.PrivKey) (string, error) {
	pub := priv.GetPublic()
	raw, err := pub.Raw()
	if err != nil {
		return "", fmt.Errorf("读取压缩公钥失败: %w", err)
	}
	return bitcoinidentity.PublicKeyHex(raw)
}

func PeerID(priv crypto.PrivKey) (peer.ID, error) {
	raw, err := priv.GetPublic().Raw()
	if err != nil {
		return "", fmt.Errorf("读取 PeerId 公钥失败: %w", err)
	}
	return bitcoinidentity.PeerIDFromPublicKey(raw)
}

func ValidateCompressedSecp256k1(raw []byte) error {
	if _, err := bitcoinidentity.PublicKeyBytes(raw); err != nil {
		return fmt.Errorf("%w: %v", ErrNotSecp256k1, err)
	}
	return nil
}

type Whitelist struct {
	keys map[string]struct{}
}

func NewWhitelist(compressedPubKeysHex []string) (*Whitelist, error) {
	w := &Whitelist{keys: make(map[string]struct{}, len(compressedPubKeysHex))}
	for _, k := range compressedPubKeysHex {
		norm, err := NormalizeCompressedPubKeyHex(k)
		if err != nil {
			return nil, fmt.Errorf("白名单公钥不合法: %w", err)
		}
		w.keys[norm] = struct{}{}
	}
	return w, nil
}

func NormalizeCompressedPubKeyHex(k string) (string, error) {
	clean := strings.ToLower(strings.TrimSpace(k))
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return "", fmt.Errorf("公钥必须是压缩 secp256k1 hex: %w", err)
	}
	normalized, err := bitcoinidentity.PublicKeyHex(raw)
	if err != nil {
		return "", err
	}
	return normalized, nil
}

func (w *Whitelist) Contains(hexKey string) bool {
	if w == nil {
		return false // 空白名单拒绝全部客户端；不存在 allow-all 回退
	}
	_, ok := w.keys[strings.ToLower(strings.TrimSpace(hexKey))]
	return ok
}

func (w *Whitelist) Size() int {
	if w == nil {
		return 0
	}
	return len(w.keys)
}

// AuthenticatedRemoteCompressedPubKeyHex 从 Noise 完成安全升级后的 connection
// 提取身份，并由 bitcoin-libp2p 同时验证：公钥是规范 secp256k1、PeerId 由该
// 公钥推导且与 connection.RemotePeer 一致。业务报文中的自报身份不参与判断。
func AuthenticatedRemoteCompressedPubKeyHex(conn network.Conn) (string, error) {
	authenticated, err := bitcoingolibp2p.AuthenticatedPeerFromConn(conn, nil)
	if err != nil {
		return "", fmt.Errorf("bitcoin-libp2p 远端身份认证失败: %w", err)
	}
	return bitcoinidentity.PublicKeyHex(authenticated.PublicKey)
}
