package main

// 覆盖 keygen 子命令的核心安全属性（阻断 2）：
// 排他创建、0600 权限、公钥稳定、已有文件拒绝覆盖且内容不变。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeygenExclusiveCreateAndStablePubkey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "client.key")

	pub1, err := generateIdentityFile(keyPath)
	if err != nil {
		t.Fatalf("首次 keygen 失败: %v", err)
	}
	if len(pub1) != 66 || (pub1[:2] != "02" && pub1[:2] != "03") {
		t.Fatalf("公钥应为 66 位压缩 hex，实际 %q", pub1)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("私钥文件权限应为 0600，实际 %v", info.Mode().Perm())
	}
	content, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// 第二次必须失败且原文件内容不变。
	if _, err := generateIdentityFile(keyPath); err == nil {
		t.Fatal("已存在的私钥文件必须拒绝覆盖")
	}
	content2, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != string(content2) {
		t.Fatal("拒绝覆盖时原文件内容不得被改动")
	}

	// 重复加载：公钥稳定。
	priv, err := loadIdentityFile(keyPath)
	if err != nil {
		t.Fatalf("加载私钥失败: %v", err)
	}
	pub2, err := clientPubHex(priv)
	if err != nil {
		t.Fatal(err)
	}
	if pub1 != pub2 {
		t.Fatalf("同一私钥的公钥必须稳定：%s vs %s", pub1, pub2)
	}
}

func TestLoadIdentityToleratesTrailingNewlineAndRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k.key")
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	if err := os.WriteFile(p, append([]byte(encodeHex(raw)), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	priv, err := loadIdentityFile(p)
	if err != nil {
		t.Fatalf("容忍末尾换行: %v", err)
	}
	pub, err := clientPubHex(priv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pub, "02") && !strings.HasPrefix(pub, "03") {
		t.Fatalf("公钥格式错误: %s", pub)
	}

	if err := os.WriteFile(p, []byte("nothex"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentityFile(p); err == nil {
		t.Fatal("非法 hex 必须报错")
	}
}

func encodeHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		out = append(out, digits[v>>4], digits[v&0x0f])
	}
	return string(out)
}
