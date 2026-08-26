package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/libp2p/go-libp2p/core/crypto"
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
		return nil, fmt.Errorf("read identity key file: %w", err)
	}
	return PrivateKeyFromHex(strings.TrimSpace(string(raw)))
}

func PrivateKeyFromHex(s string) (crypto.PrivKey, error) {
	clean := strings.ToLower(strings.TrimSpace(s))
	if len(clean) != Secp256k1PrivKeyLen*2 {
		return nil, fmt.Errorf("private key hex must be exactly %d characters, got %d", Secp256k1PrivKeyLen*2, len(clean))
	}
	if _, err := hex.DecodeString(clean); err != nil {
		return nil, fmt.Errorf("private key hex is not valid hexadecimal: %w", err)
	}
	bin, _ := hex.DecodeString(clean)
	var scalar [sha256.Size]byte
	copy(scalar[:], bin)
	if isZeroScalar(scalar[:]) {
		return nil, errors.New("private key scalar must not be zero")
	}
	priv, err := crypto.UnmarshalSecp256k1PrivateKey(bin)
	if err != nil {
		return nil, fmt.Errorf("unmarshal secp256k1 private key: %w", err)
	}
	return priv, nil
}

func isZeroScalar(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func CompressedPublicKeyHex(priv crypto.PrivKey) (string, error) {
	pub := priv.GetPublic()
	raw, err := pub.Raw()
	if err != nil {
		return "", fmt.Errorf("raw public key: %w", err)
	}
	if err := ValidateCompressedSecp256k1(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func PeerID(priv crypto.PrivKey) (peer.ID, error) {
	return peer.IDFromPrivateKey(priv)
}

func ValidateCompressedSecp256k1(raw []byte) error {
	if len(raw) != CompressedSecp256k1PubKeyLen {
		return fmt.Errorf("%w: raw key length %d, want 33-byte compressed point", ErrNotSecp256k1, len(raw))
	}
	if raw[0] != 0x02 && raw[0] != 0x03 {
		return fmt.Errorf("%w: unexpected point prefix 0x%02x", ErrNotSecp256k1, raw[0])
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
			return nil, fmt.Errorf("whitelist entry: %w", err)
		}
		w.keys[norm] = struct{}{}
	}
	return w, nil
}

func NormalizeCompressedPubKeyHex(k string) (string, error) {
	clean := strings.ToLower(strings.TrimSpace(k))
	raw, err := hex.DecodeString(clean)
	if err != nil || len(clean) != CompressedSecp256k1PubKeyLen*2 {
		return "", fmt.Errorf("expected 33-byte compressed secp256k1 public key hex")
	}
	if err := ValidateCompressedSecp256k1(raw); err != nil {
		return "", err
	}
	return clean, nil
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

func RemoteCompressedPubKeyHex(pub crypto.PubKey) (string, error) {
	raw, err := pub.Raw()
	if err != nil {
		return "", fmt.Errorf("raw remote public key: %w", err)
	}
	if err := ValidateCompressedSecp256k1(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
