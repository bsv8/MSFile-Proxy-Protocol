package auth

// 本文件覆盖施工单 T02：访问策略的构造与判定逻辑。
// 只使用标准库 testing，不引入第三方断言库。

import (
	crand "crypto/rand"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"

	"msfile.dev/labs/webrtc-go/internal/config"
	"msfile.dev/labs/webrtc-go/internal/identity"
)

// newCompressedPubKeyHex 生成一条合法的 66 位 secp256k1 压缩公钥 hex（小写）。
func newCompressedPubKeyHex(t *testing.T) string {
	t.Helper()
	for i := 0; i < 8; i++ {
		scalar := make([]byte, identity.Secp256k1PrivKeyLen)
		if _, err := crand.Read(scalar); err != nil {
			t.Fatalf("读取随机数失败: %v", err)
		}
		priv, err := crypto.UnmarshalSecp256k1PrivateKey(scalar)
		if err != nil {
			continue // 极小概率标量越界，重试即可
		}
		pubHex, err := identity.CompressedPublicKeyHex(priv)
		if err != nil {
			continue
		}
		return pubHex
	}
	t.Fatal("多次尝试仍无法生成合法的 secp256k1 压缩公钥")
	return ""
}

// private 模式：命中白名单放行；未命中拒绝。
func TestPrivatePolicyEnforcesWhitelist(t *testing.T) {
	k1 := newCompressedPubKeyHex(t)
	k2 := newCompressedPubKeyHex(t)
	k3 := newCompressedPubKeyHex(t) // 不在任何列表中的第三方公钥

	p, err := NewPolicy(config.AccessModePrivate, []string{k1, k2})
	if err != nil {
		t.Fatalf("构造 private 策略失败: %v", err)
	}

	if err := p.Allow(k1); err != nil {
		t.Fatalf("白名单内公钥应被允许，实际被拒: %v", err)
	}
	if err := p.Allow(k2); err != nil {
		t.Fatalf("白名单内公钥应被允许，实际被拒: %v", err)
	}
	if err := p.Allow(k3); err == nil {
		t.Fatal("白名单外公钥应被拒绝，实际却放行了")
	}
}

// private 且空白名单必须拒绝一切公钥——重点验证不存在 allow-all 回退。
func TestPrivateEmptyWhitelistDeniesEverything(t *testing.T) {
	kAny := newCompressedPubKeyHex(t)

	for name, whitelist := range map[string][]string{
		"nil 列表": nil,
		"空切片":    {},
		"显式空切片":  []string{},
	} {
		p, err := NewPolicy(config.AccessModePrivate, whitelist)
		if err != nil {
			t.Fatalf("%s：构造 private 策略失败: %v", name, err)
		}
		if err := p.Allow(kAny); err == nil {
			t.Fatalf("%s：空白名单却放行了任意公钥，出现危险的 allow-all 回退", name)
		}
	}
}

// public 模式：任意已认证的合法格式公钥都放行，包括不在任何列表中的随机公钥。
func TestPublicPolicyAllowsAnyAuthenticatedKey(t *testing.T) {
	k1 := newCompressedPubKeyHex(t)

	// 即使传入非空列表，public 模式也完全忽略它
	p, err := NewPolicy(config.AccessModePublic, []string{k1})
	if err != nil {
		t.Fatalf("构造 public 策略失败: %v", err)
	}

	for i := 0; i < 4; i++ {
		random := newCompressedPubKeyHex(t)
		if random == k1 {
			t.Fatal("随机生成的公钥不应恰好等于列表项，测试样本无效")
		}
		if err := p.Allow(random); err != nil {
			t.Fatalf("public 模式下随机合法公钥应被允许，实际被拒: %v", err)
		}
	}
	if err := p.Allow(k1); err != nil {
		t.Fatalf("public 模式下列表内公钥自然也应被允许: %v", err)
	}
}

// NewPolicy 对未知模式必须报错并返回 nil 策略。
func TestNewPolicyRejectsUnknownMode(t *testing.T) {
	for _, mode := range []string{"Public", "", "readonly", "private "} { // 含大小写错误与尾部空白
		p, err := NewPolicy(mode, nil)
		if err == nil {
			t.Fatalf("未知访问模式 %q 应当报错，实际成功了", mode)
		}
		if p != nil {
			t.Fatalf("构造失败时应返回 nil 策略，实际为 %#v", p)
		}
	}
}

// Mode 与 WhitelistSize 返回正确值；public 模式 WhitelistSize 恒为 0；
// private 白名单在构造时按集合去重。
func TestPolicyAccessorsReportModeAndSize(t *testing.T) {
	k1 := newCompressedPubKeyHex(t)
	k2 := newCompressedPubKeyHex(t)

	private, err := NewPolicy(config.AccessModePrivate, []string{k1, k1, k2})
	if err != nil {
		t.Fatalf("构造 private 策略失败: %v", err)
	}
	if got := private.Mode(); got != config.AccessModePrivate {
		t.Fatalf("Mode() = %q, 期望 %q", got, config.AccessModePrivate)
	}
	if got := private.WhitelistSize(); got != 2 {
		t.Fatalf("重复项去重后 WhitelistSize() = %d, 期望 2", got)
	}

	public, err := NewPolicy(config.AccessModePublic, []string{k1})
	if err != nil {
		t.Fatalf("构造 public 策略失败: %v", err)
	}
	if got := public.Mode(); got != config.AccessModePublic {
		t.Fatalf("Mode() = %q, 期望 %q", got, config.AccessModePublic)
	}
	if got := public.WhitelistSize(); got != 0 {
		t.Fatalf("public 模式 WhitelistSize() 应恒为 0，实际 %d", got)
	}
}

// Allow/Mode/WhitelistSize 在并发调用下结果稳定；
// 数据竞争由 go test -race 负责捕捉。
func TestAllowConcurrentCallsAreSafe(t *testing.T) {
	const (
		goroutines = 16 // 并发 goroutine 数
		iterations = 200
	)
	allowed := newCompressedPubKeyHex(t)
	denied := newCompressedPubKeyHex(t)

	p, err := NewPolicy(config.AccessModePrivate, []string{allowed})
	if err != nil {
		t.Fatalf("构造 private 策略失败: %v", err)
	}

	// 统计“意外结果”：白名单内被拒、白名单外被放行
	var unexpectedAllow atomic.Int64
	var unexpectedDeny atomic.Int64

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if err := p.Allow(allowed); err != nil {
					unexpectedDeny.Add(1)
				}
				if err := p.Allow(denied); err == nil {
					unexpectedAllow.Add(1)
				}
				_ = p.Mode()
				_ = p.WhitelistSize()
			}
		}()
	}
	wg.Wait()

	if n := unexpectedDeny.Load(); n != 0 {
		t.Fatalf("白名单内公钥在并发下被误拒 %d 次", n)
	}
	if n := unexpectedAllow.Load(); n != 0 {
		t.Fatalf("白名单外公钥在并发下被误放行 %d 次", n)
	}
}
