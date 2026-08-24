package webrtc_go_test

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"

	"msfile.dev/labs/webrtc-go/internal/identity"
)

type identityVector struct {
	Name          string `json:"name"`
	PrivateKeyHex string `json:"private_key_hex"`
	PublicKeyHex  string `json:"public_key_hex"`
	PeerID        string `json:"peer_id"`
}

func loadVector(t *testing.T) identityVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "identity-vector.json"))
	if err != nil {
		t.Fatalf("read identity vector: %v", err)
	}
	var v identityVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshal identity vector: %v", err)
	}
	return v
}

func TestFixedIdentityVectorDerivation(t *testing.T) {
	v := loadVector(t)
	priv, err := identity.PrivateKeyFromHex(v.PrivateKeyHex)
	if err != nil {
		t.Fatalf("derive private key: %v", err)
	}
	pubHex, err := identity.CompressedPublicKeyHex(priv)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	if pubHex != v.PublicKeyHex {
		t.Fatalf("public key mismatch:\n got  %s\n want %s", pubHex, v.PublicKeyHex)
	}
	id, err := identity.PeerID(priv)
	if err != nil {
		t.Fatalf("derive peer id: %v", err)
	}
	if id.String() != v.PeerID {
		t.Fatalf("peer id mismatch:\n got  %s\n want %s", id.String(), v.PeerID)
	}
}

func TestPrivateKeyFormatAndRangeGuards(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid 32 bytes", "278d5bed18a82b66619e026c2efb2a907e35310829d9658fb967180636afaa6a", false},
		{"uppercase accepted", strings.ToUpper("278d5bed18a82b66619e026c2efb2a907e35310829d9658fb967180636afaa6a"), false},
		{"too short", "abcd", true},
		{"not hex", strings.Repeat("zz", 32), true},
		{"zero scalar", strings.Repeat("00", 32), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := identity.PrivateKeyFromHex(tc.input)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %q", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCompressedPublicKeyCanonicalBytesFromConnectionKey(t *testing.T) {
	v := loadVector(t)
	priv, err := identity.PrivateKeyFromHex(v.PrivateKeyHex)
	if err != nil {
		t.Fatalf("vector key: %v", err)
	}
	hexKey, err := identity.RemoteCompressedPubKeyHex(priv.GetPublic())
	if err != nil {
		t.Fatalf("secp256k1 public key rejected: %v", err)
	}
	raw, _ := hex.DecodeString(hexKey)
	if len(raw) != 33 || (raw[0] != 0x02 && raw[0] != 0x03) {
		t.Fatalf("expected canonical 33-byte compressed point, got %d bytes", len(raw))
	}

	_, ed25519Pub, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	if _, err := identity.RemoteCompressedPubKeyHex(ed25519Pub); err == nil {
		t.Fatal("expected non-secp256k1 public key to be rejected")
	}
}

func TestWhitelistMatching(t *testing.T) {
	v := loadVector(t)
	wl, err := identity.NewWhitelist([]string{strings.ToUpper(v.PublicKeyHex)})
	if err != nil {
		t.Fatalf("build whitelist: %v", err)
	}
	if !wl.Contains(v.PublicKeyHex) {
		t.Fatal("whitelist must contain the committed public key regardless of case")
	}
	if wl.Contains(strings.Repeat("ab", 33)) {
		t.Fatal("whitelist must not contain an unrelated key")
	}
	empty, err := identity.NewWhitelist(nil)
	if err != nil {
		t.Fatalf("empty whitelist: %v", err)
	}
	if !empty.AllowsAll() {
		t.Fatal("empty whitelist must enable demo allow-all mode")
	}
	if !empty.Contains(v.PublicKeyHex) {
		t.Fatal("empty whitelist must allow an authenticated secp256k1 key in demo mode")
	}
	if wl.AllowsAll() {
		t.Fatal("non-empty whitelist must not enable demo allow-all mode")
	}
	if _, err := identity.NewWhitelist([]string{"nothex"}); err == nil {
		t.Fatal("expected malformed whitelist entry to fail")
	}
}
