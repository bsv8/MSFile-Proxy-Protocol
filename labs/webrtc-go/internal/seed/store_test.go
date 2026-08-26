package seed

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestStore 在临时目录里打开一个 Store，返回 Store 与目录路径。
func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open(%s) 失败: %v", dir, err)
	}
	return s, dir
}

// buildSmallResult 用确定性伪随机数据构建一个小文件的 Result，
// 避免依赖真实磁盘文件，也让每个用例可重复。
func buildSmallResult(t *testing.T, size int, filename string) *Result {
	t.Helper()
	res, err := Build(bytes.NewReader(lcgBytes(size)), filename)
	if err != nil {
		t.Fatalf("Build 小文件失败: %v", err)
	}
	return res
}

// publishedPath 复刻 Store 的落盘布局：
// seeds/<h[0:2]>/<h[2:4]>/<完整 hash>.seed。
func publishedPath(dir string, res *Result) string {
	h := res.HashHex()
	return filepath.Join(dir, "seeds", h[:2], h[2:4], h+".seed")
}

// TestOpenCreatesDirectoryLayout 校验 Open 会建立 seeds/staging/trash 三个目录。
func TestOpenCreatesDirectoryLayout(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir); err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	for _, name := range []string{"seeds", "staging", "trash"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("目录 %s 未被创建: %v", name, err)
		}
		if !info.IsDir() {
			t.Errorf("%s 存在但不是目录", name)
		}
	}
}

// TestCleanupStagingRemovesJunk 校验 staging 残留清理：
// 先塞入垃圾文件，CleanupStaging 与重新 Open 都应把它们清空。
func TestCleanupStagingRemovesJunk(t *testing.T) {
	s, dir := newTestStore(t)
	staging := filepath.Join(dir, "staging")
	junk1 := filepath.Join(staging, ".publish-leftover-1")
	junk2 := filepath.Join(staging, "orphan.tmp")
	for _, p := range []string{junk1, junk2} {
		if err := os.WriteFile(p, []byte("垃圾残留"), 0o600); err != nil {
			t.Fatalf("预置垃圾文件失败: %v", err)
		}
	}

	if err := s.CleanupStaging(); err != nil {
		t.Fatalf("CleanupStaging 失败: %v", err)
	}
	entries, err := os.ReadDir(staging)
	if err != nil {
		t.Fatalf("读取 staging 失败: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("CleanupStaging 后 staging 仍有 %d 个残留", len(entries))
	}

	// 再验证 Open 自身也会顺带清一次 staging（模拟上次进程崩溃遗留）。
	if err := os.WriteFile(junk1, []byte("再次遗留"), 0o600); err != nil {
		t.Fatalf("预置垃圾文件失败: %v", err)
	}
	if _, err := Open(dir); err != nil {
		t.Fatalf("二次 Open 失败: %v", err)
	}
	entries, err = os.ReadDir(staging)
	if err != nil {
		t.Fatalf("读取 staging 失败: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("重新 Open 后 staging 仍有 %d 个残留", len(entries))
	}
}

// TestPublishWritesCanonicalPathAndReuses 校验发布主流程：
// 目标路径按两级哈希前缀分散；内容与 result.Seed 逐字节一致；
// 重复发布同一 Result 视为复用成功且不改变既有文件。
func TestPublishWritesCanonicalPathAndReuses(t *testing.T) {
	s, dir := newTestStore(t)
	res := buildSmallResult(t, 700, "hello.bin")
	target := publishedPath(dir, res)

	if err := s.Publish(res); err != nil {
		t.Fatalf("Publish 失败: %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("目标文件不存在: %v (期望路径 %s)", err, target)
	}
	if !bytes.Equal(data, res.Seed) {
		t.Error("落盘内容与 result.Seed 不逐字节一致")
	}

	// 发布成功的副产品：staging 不应有任何临时文件残留。
	entries, err := os.ReadDir(filepath.Join(dir, "staging"))
	if err != nil {
		t.Fatalf("读取 staging 失败: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("发布后 staging 残留 %d 个临时文件", len(entries))
	}

	// 记录首次发布的 inode/修改时间信息，用于确认复用时未被重写。
	firstInfo, err := os.Stat(target)
	if err != nil {
		t.Fatalf("Stat 失败: %v", err)
	}
	if err := s.Publish(res); err != nil {
		t.Fatalf("重复 Publish 同一 Result 应复用成功, 实际报错: %v", err)
	}
	secondInfo, err := os.Stat(target)
	if err != nil {
		t.Fatalf("Stat 失败: %v", err)
	}
	if !firstInfo.ModTime().Equal(secondInfo.ModTime()) || firstInfo.Size() != secondInfo.Size() {
		t.Error("重复 Publish 改写了已存在的 Seed 文件，应当原样复用")
	}
	data, _ = os.ReadFile(target)
	if !bytes.Equal(data, res.Seed) {
		t.Error("复用后文件内容发生变化")
	}
}

// TestPublishRejectsCorruptedExistingFile 校验碰撞/损坏保护：
// 目标位置已有一个长度不一致的垃圾文件时，Publish 必须报错且绝不覆盖。
func TestPublishRejectsCorruptedExistingFile(t *testing.T) {
	s, dir := newTestStore(t)
	res := buildSmallResult(t, 1024, "victim.dat") // Seed 为 32 字节
	target := publishedPath(dir, res)

	junk := []byte("人为破坏的垃圾数据，长度故意不同") // 明显不等于 len(res.Seed)=32
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		t.Fatalf("建目录失败: %v", err)
	}
	if err := os.WriteFile(target, junk, 0o640); err != nil {
		t.Fatalf("预写垃圾文件失败: %v", err)
	}

	// 新语义（评审修复）：损坏的既有 Seed 必须被原子重建，而不是错误复用。
	if err := s.Publish(res); err != nil {
		t.Fatalf("损坏 Seed 应通过 staging 原子重建，实际报错: %v", err)
	}
	onDisk, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("读取重建后的目标文件失败: %v", readErr)
	}
	if !bytes.Equal(onDisk, res.Seed) {
		t.Errorf("重建后的内容必须与计算结果逐字节一致，实际 %d 字节", len(onDisk))
	}

	// 同尺寸但内容不同的损坏同样必须自愈。
	res2 := buildSmallResult(t, 4096, "same-size.dat")
	target2 := publishedPath(dir, res2)
	badSameSize := make([]byte, len(res2.Seed))
	for i := range badSameSize {
		badSameSize[i] = 0xAB
	}
	if err := os.MkdirAll(filepath.Dir(target2), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target2, badSameSize, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(res2); err != nil {
		t.Fatalf("同尺寸损坏 Seed 应重建: %v", err)
	}
	onDisk2, _ := os.ReadFile(target2)
	if !bytes.Equal(onDisk2, res2.Seed) {
		t.Error("同尺寸损坏文件未被重建为正确内容")
	}
}

// TestReadSeedHappyPath 校验已发布 Seed 可读回且内容一致，
// 同时确认大写形式的 Hash 会被归一化接受。
func TestReadSeedHappyPath(t *testing.T) {
	s, _ := newTestStore(t)
	res := buildSmallResult(t, 300000, "readme.txt")
	if err := s.Publish(res); err != nil {
		t.Fatalf("Publish 失败: %v", err)
	}
	hashHex := res.HashHex()

	got, err := s.ReadSeed(hashHex)
	if err != nil {
		t.Fatalf("ReadSeed 失败: %v", err)
	}
	if !bytes.Equal(got, res.Seed) {
		t.Error("ReadSeed 内容与 result.Seed 不一致")
	}

	// 大写 hex 属于合法输入（内部会转小写）。
	gotUpper, err := s.ReadSeed(strings.ToUpper(hashHex))
	if err != nil {
		t.Fatalf("大写 Hash 的 ReadSeed 应当成功: %v", err)
	}
	if !bytes.Equal(gotUpper, res.Seed) {
		t.Error("大写 Hash 读回的内容不一致")
	}
}

// TestReadSeedTamperedReturnsErrIntegrity 校验文件被篡改后 fail closed：
// 哈希对不上必须返回 ErrIntegrity。
func TestReadSeedTamperedReturnsErrIntegrity(t *testing.T) {
	s, dir := newTestStore(t)
	res := buildSmallResult(t, 64, "tamper.bin")
	if err := s.Publish(res); err != nil {
		t.Fatalf("Publish 失败: %v", err)
	}
	hashHex := res.HashHex()
	path := publishedPath(dir, res)

	// 篡改第一个字节（保持长度不变），使内容与声明 Hash 不匹配。
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取已发布文件失败: %v", err)
	}
	raw[0] ^= 0xFF
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatalf("篡改文件失败: %v", err)
	}

	if _, err := s.ReadSeed(hashHex); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("篡改后期望 ErrIntegrity, 实际: %v", err)
	}
}

// TestReadSeedNotFoundAndInvalidHash 校验两类失败路径：
// 不存在的 Hash -> ErrNotFound；非法 Hash -> ErrHashInvalid。
func TestReadSeedNotFoundAndInvalidHash(t *testing.T) {
	s, _ := newTestStore(t)

	// 合法格式但不存在的 64 位小写 hex。
	fresh := strings.Repeat("ab", 32)
	if _, err := s.ReadSeed(fresh); !errors.Is(err, ErrNotFound) {
		t.Fatalf("期望 ErrNotFound, 实际: %v", err)
	}

	cases := []struct {
		name string
		in   string
	}{
		{"长度不对", "abcd"},
		{"空串", ""},
		{"含非法字符g", strings.Repeat("g", 64)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.ReadSeed(tc.in); !errors.Is(err, ErrHashInvalid) {
				t.Fatalf("期望 ErrHashInvalid, 实际: %v", err)
			}
		})
	}
}

// TestMoveToTrashLifecycle 校验回收全流程：
// 发布后移动到 trash、原路径消失、重复移动静默成功、EmptyTrash 清空。
func TestMoveToTrashLifecycle(t *testing.T) {
	s, dir := newTestStore(t)
	res := buildSmallResult(t, 50000, "gone.dat")
	if err := s.Publish(res); err != nil {
		t.Fatalf("Publish 失败: %v", err)
	}
	hashHex := res.HashHex()
	origin := publishedPath(dir, res)
	inTrash := filepath.Join(dir, "trash", hashHex+".seed")

	if err := s.MoveToTrash(hashHex); err != nil {
		t.Fatalf("MoveToTrash 失败: %v", err)
	}
	if _, err := os.Stat(origin); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("原路径仍存在或报错异常: %v", err)
	}
	moved, err := os.ReadFile(inTrash)
	if err != nil {
		t.Fatalf("trash 中未找到文件: %v", err)
	}
	if !bytes.Equal(moved, res.Seed) {
		t.Error("trash 文件内容与 result.Seed 不一致")
	}
	if s.HasSeedFile(hashHex) {
		t.Error("移入 trash 后 HasSeedFile 仍报告存在")
	}

	// 对已不存在的 Hash 再次 MoveToTrash 应静默成功（可能已被更早的 GC 清理）。
	if err := s.MoveToTrash(hashHex); err != nil {
		t.Errorf("对不存在 Hash 的 MoveToTrash 应静默成功, 实际: %v", err)
	}

	// EmptyTrash 之后 trash 目录应为空；顺带塞个垃圾文件一并验证。
	if err := os.WriteFile(filepath.Join(dir, "trash", "junk.log"), []byte("x"), 0o600); err != nil {
		t.Fatalf("预置垃圾失败: %v", err)
	}
	if err := s.EmptyTrash(); err != nil {
		t.Fatalf("EmptyTrash 失败: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "trash"))
	if err != nil {
		t.Fatalf("读取 trash 失败: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("EmptyTrash 后 trash 仍有 %d 个条目", len(entries))
	}

	// 附带校验：非法 Hash 走 MoveToTrash 也应得到 ErrHashInvalid。
	if err := s.MoveToTrash("nothex"); !errors.Is(err, ErrHashInvalid) {
		t.Errorf("期望 ErrHashInvalid, 实际: %v", err)
	}
}

// TestHasSeedFileStates 校验诊断接口在生命周期各阶段的状态翻转。
func TestHasSeedFileStates(t *testing.T) {
	s, _ := newTestStore(t)
	res := buildSmallResult(t, 128, "state.bin")
	hashHex := res.HashHex()

	if s.HasSeedFile(hashHex) {
		t.Fatal("发布前 HasSeedFile 应为 false")
	}
	if err := s.Publish(res); err != nil {
		t.Fatalf("Publish 失败: %v", err)
	}
	if !s.HasSeedFile(hashHex) {
		t.Fatal("发布后 HasSeedFile 应为 true")
	}
	if s.HasSeedFile(strings.ToUpper(hashHex)) {
		// 大写形式也应能定位（实现内部做了 ToLower）。
	} else {
		t.Error("大写 Hash 形式的 HasSeedFile 应为 true")
	}
	if err := s.MoveToTrash(hashHex); err != nil {
		t.Fatalf("MoveToTrash 失败: %v", err)
	}
	if s.HasSeedFile(hashHex) {
		t.Fatal("移入 trash 后 HasSeedFile 应为 false")
	}
}
