// Package auth 提供 MSFile NAS V1 的访问策略。
//
// 策略在启动时由配置构造为不可变对象：
//
//	private -> 仅允许配置文件白名单中的客户端公钥执行 Stat 与 Read
//	public  -> 任意通过 libp2p Noise 认证的 secp256k1 客户端都允许
//
// 白名单只存在于配置文件，不查询 SQLite clients 表，
// 也绝不信任报文内自报的公钥；判断输入必须来自 connection 层认证出的远端公钥。
package auth

import (
	"errors"
	"fmt"

	"msfile.dev/labs/webrtc-go/internal/config"
)

// Policy 是不可变的访问策略；所有方法并发安全。
type Policy struct {
	mode      string
	whitelist map[string]struct{}
}

// NewPolicy 按配置构造策略。private 模式把白名单规范化为去重只读集合；
// public 模式忽略列表内容（列表不参与判断）。
func NewPolicy(mode string, whitelist []string) (*Policy, error) {
	switch mode {
	case config.AccessModePrivate:
		set := make(map[string]struct{}, len(whitelist))
		for _, key := range whitelist {
			set[key] = struct{}{}
		}
		return &Policy{mode: mode, whitelist: set}, nil
	case config.AccessModePublic:
		return &Policy{mode: mode}, nil
	default:
		return nil, fmt.Errorf("auth：未知的访问模式 %q", mode)
	}
}

// Allow 判断已认证远端公钥是否可以执行 Stat/Read。
// 返回非 nil 时调用方应向客户端回 unauthorized_peer。
func (p *Policy) Allow(authenticatedPublicKeyHex string) error {
	if p.mode == config.AccessModePublic {
		// 公共模式仍然要求调用方先完成 libp2p Noise 身份认证；
		// 这里只负责业务放行，身份校验由连接层完成。
		return nil
	}
	// private 且白名单为空等价于拒绝全部客户端，不存在 allow-all 回退。
	if _, ok := p.whitelist[authenticatedPublicKeyHex]; !ok {
		return errors.New("该公钥不在 private 白名单中")
	}
	return nil
}

// Mode 返回当前访问模式字符串（private / public），用于诊断展示。
func (p *Policy) Mode() string { return p.mode }

// WhitelistSize 返回 private 白名单条数；public 模式恒为 0。
// 用于状态页展示数量，不暴露公钥本身。
func (p *Policy) WhitelistSize() int { return len(p.whitelist) }
