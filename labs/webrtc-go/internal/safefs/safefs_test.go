package safefs

// 覆盖阻断 3：路径逃逸、中间/最终符号链接、打开期替换与挂载自愈。

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func mustOpen(t *testing.T, dir string) *Root {
	t.Helper()
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func TestEscapeAttemptsRejected(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("机密"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := mustOpen(t, dir)
	for _, bad := range []string{"../secret.txt", "..", "", "/etc/passwd", `a\..\evil`} {
		if _, _, err := r.OpenFile(bad); err == nil {
			t.Fatalf("路径 %q 必须被拒绝", bad)
		} else if !errors.Is(err, ErrEscape) && !errors.Is(err, os.ErrNotExist) {
			t.Logf("路径 %q 错误类型: %v", bad, err)
		}
	}
}

func TestAncestorSymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "a"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "leak.txt"), []byte("外部内容"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := mustOpen(t, dir)

	// 正常路径先可读。
	if err := os.WriteFile(filepath.Join(dir, "a", "f.bin"), []byte("内部"), 0o640); err != nil {
		t.Fatal(err)
	}
	f, _, err := r.OpenFile("a/f.bin")
	if err != nil {
		t.Fatalf("正常路径应可打开: %v", err)
	}
	_ = f.Close()

	// 扫描之后把祖先目录替换为指向根外的符号链接。
	if err := os.RemoveAll(filepath.Join(dir, "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "a")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.OpenFile("a/f.bin"); !errors.Is(err, ErrSymlinkAncestor) {
		t.Fatalf("中间目录 symlink 必须被拒绝，实际: %v", err)
	}
}

func TestFinalSymlinkAndReplacementRejected(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "target.txt"), []byte("外部目标"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "d"), 0o750); err != nil {
		t.Fatal(err)
	}
	r := mustOpen(t, dir)

	link := filepath.Join(dir, "d", "link.bin")
	if err := os.Symlink(filepath.Join(outside, "target.txt"), link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.OpenFile("d/link.bin"); !errors.Is(err, ErrSymlinkFinal) {
		t.Fatalf("最终组件 symlink 必须被拒绝，实际: %v", err)
	}
}

func TestReopenAfterDirectoryReplaced(t *testing.T) {
	dir := t.TempDir()
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if err := os.WriteFile(filepath.Join(dir, "x.bin"), []byte("v1"), 0o640); err != nil {
		t.Fatal(err)
	}
	f, _, err := r.OpenFile("x.bin")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	// 模拟卸载后重新挂载：目录 inode 变化。
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x.bin"), []byte("v2"), 0o640); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 2)
	fd, info, err := r.OpenFile("x.bin")
	if err != nil {
		t.Fatalf("挂载恢复后应自动重开安全根: %v", err)
	}
	if _, err := fd.Read(data); err != nil {
		t.Fatal(err)
	}
	_ = info
	_ = fd.Close()
	if string(data) != "v2" {
		t.Fatalf("重开后应读到新内容，实际 %q", data)
	}
}

// ---------- 阻断 4：惰性 Root 与关闭态严格区分 ----------

// TestLazyRootBecomesUsableWithoutReopen：
// Open 时目录不存在 → 之后创建目录和文件 → 同一 Root 实例无需重建即可读取。
func TestLazyRootBecomesUsableWithoutReopen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-yet-mounted")
	r, err := Open(dir)
	if err != nil {
		t.Fatalf("目录不存在时 Open 应成功（惰性）: %v", err)
	}
	defer r.Close()
	if _, _, err := r.OpenFile("a.bin"); err == nil {
		t.Fatal("挂载前读取应失败")
	}
	// “挂载出现”：创建目录与文件。
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.bin"), []byte("lazy"), 0o640); err != nil {
		t.Fatal(err)
	}
	f, info, err := r.OpenFile("a.bin")
	if err != nil {
		t.Fatalf("同一 Root 实例应自动就绪: %v", err)
	}
	defer f.Close()
	if info.Size() != 4 {
		t.Fatalf("读到错误内容尺寸 %d", info.Size())
	}
}

// TestClosedRootStaysClosed：Close 后即使目录存在也必须永久拒绝，
// 与“惰性等待挂载”状态严格区分。
func TestClosedRootStaysClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x"), []byte("v"), 0o640); err != nil {
		t.Fatal(err)
	}
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close 必须幂等: %v", err)
	}
	if _, _, err := r.OpenFile("x"); !errors.Is(err, ErrRootClosed) {
		t.Fatalf("关闭后访问必须返回 ErrRootClosed，实际: %v", err)
	}
	if _, err := r.LstatFile("x"); !errors.Is(err, ErrRootClosed) {
		t.Fatalf("关闭后 Lstat 必须返回 ErrRootClosed，实际: %v", err)
	}
}

// TestInodeChangeReopensAndDoesNotKeepClosedHandle：inode 变化重开后旧句柄不残留。
func TestInodeChangeReopensAndDoesNotKeepClosedHandle(t *testing.T) {
	dir := t.TempDir()
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("one"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "g"), []byte("two"), 0o640); err != nil {
		t.Fatal(err)
	}
	f, _, err := r.OpenFile("g")
	if err != nil {
		t.Fatalf("inode 变化后应自动重开: %v", err)
	}
	_ = f.Close()
	if _, _, err := r.OpenFile("f"); err == nil {
		t.Fatal("旧文件不应在重开后的根里可见")
	}
}
