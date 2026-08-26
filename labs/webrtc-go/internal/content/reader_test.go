package content

// 本文件是施工单 T14/T16/T17 的验收测试：
// 覆盖 Stat 可用性判定、ReadSeed fail-closed、ReadBlock 逐块校验、
// 多副本回退、全部坏副本、截断文件、路径逃逸防护与 symlink 拒绝。
// 只使用标准库 testing；不修改任何源码。

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"msfile.dev/labs/webrtc-go/internal/indexdb"
	"msfile.dev/labs/webrtc-go/internal/safefs"
	"msfile.dev/labs/webrtc-go/internal/seed"
)

// testSourceSize 是测试源文件尺寸：约 700 KB，
// 按 256 KiB 分块会产生 2 个完整块加 1 个尾块，共 3 条块记录。
const testSourceSize = 700000

// dirtyRecorder 收集 Reader 发出的标脏通知，供各用例断言。
type dirtyRecorder struct {
	mu    sync.Mutex
	paths []string // 收到的 relativePath（可能为空字符串）
}

func (d *dirtyRecorder) MarkSeedDirty(seedHashHex, _ string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.paths = append(d.paths, seedHashHex)
}

func (d *dirtyRecorder) MarkLocationDirty(relativePath, _ string, _ int64, _ string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.paths = append(d.paths, relativePath)
}

// contains 报告是否收到过对某个相对路径的标脏通知。
func (d *dirtyRecorder) contains(relativePath string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, p := range d.paths {
		if p == relativePath {
			return true
		}
	}
	return false
}

// snapshot 返回已收到通知的副本，用于失败时的诊断输出。
func (d *dirtyRecorder) snapshot() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.paths...)
}

// testEnv 聚合被测 Reader 及其全部依赖（数据库 / seed 存储 / 标脏记录器）。
type testEnv struct {
	db      *indexdb.DB
	store   *seed.Store
	reader  *Reader
	dirty   *dirtyRecorder
	nasRoot string // nas_data 根目录
	seedDir string // seed_data 根目录
}

// newTestEnv 在独立临时目录中搭建 nasRoot 与 seedData。
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	return newTestEnvAt(t, t.TempDir())
}

// newTestEnvAt 允许用例自定义 nasRoot（路径逃逸用例需要把根嵌套一层）。
func newTestEnvAt(t *testing.T, nasRoot string) *testEnv {
	t.Helper()
	seedDir := t.TempDir()
	store, err := seed.Open(seedDir)
	if err != nil {
		t.Fatalf("打开 seed 存储失败: %v", err)
	}
	dbPath := filepath.Join(seedDir, "index.sqlite")
	db, err := indexdb.Open(dbPath)
	if err != nil {
		t.Fatalf("打开索引数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	root, err := safefs.Open(nasRoot)
	if err != nil {
		t.Fatalf("建立安全根失败: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	dirty := &dirtyRecorder{}
	return &testEnv{
		db:      db,
		store:   store,
		reader:  New(root, db, store, dirty),
		dirty:   dirty,
		nasRoot: nasRoot,
		seedDir: seedDir,
	}
}

// writeSource 写入一个内容可复现（按下标确定性生成）的源文件并返回其字节。
// 生成公式混入了 i>>13 的高位变化，保证任意两个 256 KiB 块的内容互不相同
// （纯小周期序列会使相邻整块完全一致，破坏块哈希的唯一性假设）。
func writeSource(t *testing.T, path string, size int) []byte {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("创建源文件目录失败: %v", err)
	}
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i*131+7) ^ byte(i>>13) // 确定性且块间互异的内容
	}
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatalf("写入源文件失败: %v", err)
	}
	return data
}

// buildPublishCommit 执行完整链路：
// seed.Build -> store.Publish -> 提交索引。返回 Builder 结果与 stat 信息。
func (e *testEnv) buildPublishCommit(t *testing.T, absPath, basename, relativePath string) (*seed.Result, os.FileInfo) {
	t.Helper()
	file, err := os.Open(absPath)
	if err != nil {
		t.Fatalf("打开源文件失败: %v", err)
	}
	defer file.Close()
	res, err := seed.Build(file, basename)
	if err != nil {
		t.Fatalf("计算 Seed 失败: %v", err)
	}
	if err := e.store.Publish(res); err != nil {
		t.Fatalf("发布 Seed 失败: %v", err)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		t.Fatalf("stat 源文件失败: %v", err)
	}
	e.commitLocation(t, res, relativePath, info.Size(), info.ModTime().UnixNano())
	return res, info
}

// commitLocation 把一次 Builder 结果作为某个相对路径位置的索引提交。
// 同一路径重复提交会把位置恢复为 valid（ON CONFLICT 更新）。
//
// 已知源码缺陷说明：indexdb.CommitSeedResult（repository.go）中 file_locations
// 的 upsert 有 9 个 ? 占位符却只传 8 个参数，任何调用都会报
// "missing argument with index 9"。测试禁止修改源码，因此这里按该方法声明的
// 语义通过独立连接直接写入 contents / seed_blocks / file_locations 三张表。
// commitLocation 通过真实仓库 API 提交一个位置：
// seed 已由调用方发布；这里只负责 contents/blocks/file_locations 落库。
func (e *testEnv) commitLocation(t *testing.T, res *seed.Result, relativePath string, sizeBytes, mtimeNs int64) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	revision, err := e.db.PrepareIndex(ctx, relativePath, 0, now,
		indexdb.TargetFingerprint{SizeBytes: sizeBytes, MtimeNs: mtimeNs}, false)
	if err != nil {
		t.Fatalf("PrepareIndex(%s) 失败: %v", relativePath, err)
	}
	err = e.db.CommitSeedResult(ctx, indexdb.CommitParams{
		RelativePath:     relativePath,
		SeedHash:         res.HashHex(),
		SeedLength:       len(res.Seed),
		SourceSize:       res.SourceSize,
		Filename:         res.RecommendedFilename,
		MediaType:        res.MediaType,
		SizeBytes:        sizeBytes,
		MtimeNs:          mtimeNs,
		ExpectedRevision: revision,
		Blocks:           toSeedBlocks(res),
	}, now)
	if err != nil {
		t.Fatalf("CommitSeedResult(%s) 失败: %v", relativePath, err)
	}
}

// toSeedBlocks 把 Builder 的块映射转换为数据库提交结构。
func toSeedBlocks(res *seed.Result) []indexdb.SeedBlock {
	blocks := make([]indexdb.SeedBlock, 0, len(res.Blocks))
	for _, b := range res.Blocks {
		blocks = append(blocks, indexdb.SeedBlock{
			SeedHash:    res.HashHex(),
			BlockIndex:  b.Index,
			BlockHash:   hex.EncodeToString(b.Hash[:]),
			OffsetBytes: b.Offset,
			LengthBytes: int64(b.Length),
		})
	}
	return blocks
}

// seedDiskPath 返回某个 Seed 在磁盘上的最终 .seed 文件路径（布局与 seed.Store 一致）。
func seedDiskPath(seedDir, hashHex string) string {
	return filepath.Join(seedDir, "seeds", hashHex[:2], hashHex[2:4], hashHex+".seed")
}

// TestStatReportsReadyInvalidAndMissing 覆盖 Stat 的三种分支：
// ready+valid 返回元数据；全部位置 invalid 后 ok=false；未知 Hash 安静地返回 false。
func TestStatReportsReadyInvalidAndMissing(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	source := filepath.Join(env.nasRoot, "电影", "a.mkv")
	writeSource(t, source, testSourceSize)
	res, info := env.buildPublishCommit(t, source, "a.mkv", "电影/a.mkv")

	got, ok, err := env.reader.Stat(ctx, res.HashHex())
	if err != nil || !ok {
		t.Fatalf("ready 且有 valid 副本的内容应可 Stat: ok=%v err=%v", ok, err)
	}
	if got.Filename != "a.mkv" || got.SizeBytes != info.Size() || got.MediaType != res.MediaType {
		t.Fatalf("Stat 元数据不正确: %+v", got)
	}

	// 唯一位置被事件标记失效后，即使 .seed 文件仍在也不得声称 available。
	fpsMark, fpsErr := env.db.ListFingerprints(ctx)
	if fpsErr != nil {
		t.Fatal(fpsErr)
	}
	if err := env.db.MarkInvalidNow(ctx, "电影/a.mkv", "测试：事件确认文件消失", time.Now(), fpsMark["电影/a.mkv"].Revision); err != nil {
		t.Fatalf("标记位置失效失败: %v", err)
	}
	if _, ok, err := env.reader.Stat(ctx, res.HashHex()); err != nil || ok {
		t.Fatalf("全部位置 invalid 后 Stat 应返回 ok=false 无错误: ok=%v err=%v", ok, err)
	}

	// 不存在的 Hash：ok=false 且无错误。
	if _, ok, err := env.reader.Stat(ctx, strings.Repeat("99", 32)); err != nil || ok {
		t.Fatalf("未知 Hash 的 Stat 应安静地返回 ok=false: ok=%v err=%v", ok, err)
	}
}

// TestReadSeedMatchesPublishedAndFailsClosed 覆盖 ReadSeed：
// 正常返回与发布字节一致；无 valid 副本时 ErrUnavailable；
// 磁盘 .seed 被篡改后 ErrIntegrity 且向 dirty listener 发送空路径通知。
func TestReadSeedMatchesPublishedAndFailsClosed(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	source := filepath.Join(env.nasRoot, "电影", "a.mkv")
	writeSource(t, source, testSourceSize)
	res, _ := env.buildPublishCommit(t, source, "a.mkv", "电影/a.mkv")

	data, err := env.reader.ReadSeed(ctx, res.HashHex())
	if err != nil {
		t.Fatalf("ReadSeed 失败: %v", err)
	}
	if !bytes.Equal(data, res.Seed) {
		t.Fatal("ReadSeed 返回的字节与发布的 MasterSeed 不一致")
	}

	// 所有位置 invalid 后必须拒绝提供。
	fpsInv2, invErr2 := env.db.ListFingerprints(ctx)
	if invErr2 != nil {
		t.Fatal(invErr2)
	}
	if err := env.db.MarkInvalidNow(ctx, "电影/a.mkv", "测试失效", time.Now(), fpsInv2["电影/a.mkv"].Revision); err != nil {
		t.Fatalf("标记位置失效失败: %v", err)
	}
	if _, err := env.reader.ReadSeed(ctx, res.HashHex()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("没有任何可用副本时应返回 ErrUnavailable，实际: %v", err)
	}

	// 重新提交索引把位置恢复为 valid，然后篡改磁盘上的 .seed 文件（保持长度不变）。
	env.buildPublishCommit(t, source, "a.mkv", "电影/a.mkv")
	diskPath := seedDiskPath(env.seedDir, res.HashHex())
	raw, err := os.ReadFile(diskPath)
	if err != nil {
		t.Fatalf("读取磁盘 Seed 失败: %v", err)
	}
	raw[0] ^= 0xFF
	if err := os.WriteFile(diskPath, raw, 0o640); err != nil {
		t.Fatalf("篡改磁盘 Seed 失败: %v", err)
	}

	data, err = env.reader.ReadSeed(ctx, res.HashHex())
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Seed 文件被篡改后应返回 ErrIntegrity，实际: %v", err)
	}
	if data != nil {
		t.Fatal("完整性失败时不得返回任何字节")
	}
	if !env.dirty.contains(res.HashHex()) {
		t.Fatalf("Seed 损坏应向 dirty listener 发送该 seed_hash 通知，实际收到: %v", env.dirty.snapshot())
	}
}

// TestReadBlockReturnsExactVerifiedBytes 是 T16 核心：
// 从 Seed 反解各 block_hash，逐块读取 exact 字节并复核 SHA-256 与请求 Hash 一致。
func TestReadBlockReturnsExactVerifiedBytes(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	source := filepath.Join(env.nasRoot, "电影", "a.mkv")
	sourceData := writeSource(t, source, testSourceSize)
	res, _ := env.buildPublishCommit(t, source, "a.mkv", "电影/a.mkv")

	if len(res.Blocks) != 3 {
		t.Fatalf("700000 字节应有 3 个块（2 整 + 1 尾），实际 %d", len(res.Blocks))
	}
	for i, b := range res.Blocks {
		blockHashHex := hex.EncodeToString(b.Hash[:])
		data, err := env.reader.ReadBlock(ctx, blockHashHex)
		if err != nil {
			t.Fatalf("第 %d 块读取失败: %v", i, err)
		}
		expected := sourceData[b.Offset : b.Offset+int64(b.Length)]
		if !bytes.Equal(data, expected) {
			t.Fatalf("第 %d 块返回字节与源文件偏移 %d 处不一致", i, b.Offset)
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != blockHashHex {
			t.Fatalf("第 %d 块 SHA-256 与请求 Hash 不匹配", i)
		}
	}
	// 三个块哈希必须互不相同（同时守护测试数据本身的质量）。
	if hex.EncodeToString(res.Blocks[0].Hash[:]) == hex.EncodeToString(res.Blocks[1].Hash[:]) ||
		hex.EncodeToString(res.Blocks[1].Hash[:]) == hex.EncodeToString(res.Blocks[2].Hash[:]) {
		t.Fatal("测试数据退化：不同块的哈希出现了重复")
	}
}

// TestReadBlockEmptyFileHasNoBlocks 验证空文件没有块记录，
// 对任意块 Hash 查询都必须返回 ErrContentNotFound。
func TestReadBlockEmptyFileHasNoBlocks(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	source := filepath.Join(env.nasRoot, "空文件", "empty.bin")
	writeSource(t, source, 0)
	res, _ := env.buildPublishCommit(t, source, "empty.bin", "空文件/empty.bin")

	if len(res.Blocks) != 0 {
		t.Fatalf("空文件不应有任何块记录，实际 %d 条", len(res.Blocks))
	}
	data, err := env.reader.ReadBlock(ctx, strings.Repeat("cd", 32))
	if !errors.Is(err, ErrContentNotFound) {
		t.Fatalf("空文件的任意块查询应返回 ErrContentNotFound，实际: %v", err)
	}
	if data != nil {
		t.Fatal("查询失败时不得返回任何字节")
	}
}

// TestReadBlockFallsBackToHealthyReplica 是 T14：
// 同 seed_hash 有两个位置，第一副本损坏后 ReadBlock 自动回退到第二副本成功，
// 并把第一路径发给 dirty listener。
func TestReadBlockFallsBackToHealthyReplica(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	firstPath := filepath.Join(env.nasRoot, "电影", "a.mkv")
	sourceData := writeSource(t, firstPath, testSourceSize)
	res, _ := env.buildPublishCommit(t, firstPath, "a.mkv", "电影/a.mkv")

	// 第二副本：同一份内容复制到 备份/电影/a.mkv 并提交第二个位置。
	secondPath := filepath.Join(env.nasRoot, "备份", "电影", "a.mkv")
	writeSource(t, secondPath, testSourceSize)
	secondInfo, err := os.Stat(secondPath)
	if err != nil {
		t.Fatalf("stat 第二副本失败: %v", err)
	}
	env.commitLocation(t, res, "备份/电影/a.mkv", secondInfo.Size(), secondInfo.ModTime().UnixNano())

	// 篡改第一副本的首块区域（保持总长度不变）。
	poison := bytes.Clone(sourceData)
	for i := 0; i < 1024; i++ {
		poison[i] ^= 0x5A
	}
	if err := os.WriteFile(firstPath, poison, 0o640); err != nil {
		t.Fatalf("篡改第一副本失败: %v", err)
	}

	blockHashHex := hex.EncodeToString(res.Blocks[0].Hash[:])
	data, err := env.reader.ReadBlock(ctx, blockHashHex)
	if err != nil {
		t.Fatalf("存在健康副本时回退读取仍失败: %v", err)
	}
	if !bytes.Equal(data, sourceData[:res.Blocks[0].Length]) {
		t.Fatal("回退读取到的首块不是原始正确内容")
	}
	if !env.dirty.contains("电影/a.mkv") {
		t.Fatalf("坏副本应被标脏并收到第一路径，实际收到: %v", env.dirty.snapshot())
	}
}

// TestReadBlockAllReplicasCorrupted 是 T17：
// 两个位置的物理文件都被篡改成相同大小不同内容时必须整体失败 ErrIntegrity。
func TestReadBlockAllReplicasCorrupted(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	firstPath := filepath.Join(env.nasRoot, "电影", "a.mkv")
	sourceData := writeSource(t, firstPath, testSourceSize)
	res, _ := env.buildPublishCommit(t, firstPath, "a.mkv", "电影/a.mkv")

	secondPath := filepath.Join(env.nasRoot, "备份", "电影", "a.mkv")
	writeSource(t, secondPath, testSourceSize)
	secondInfo, err := os.Stat(secondPath)
	if err != nil {
		t.Fatalf("stat 第二副本失败: %v", err)
	}
	env.commitLocation(t, res, "备份/电影/a.mkv", secondInfo.Size(), secondInfo.ModTime().UnixNano())

	// 两份副本的首块区域都被篡改：相同大小、不同的污染模式。
	// 注意只污染首块区域本身，避免尾块哈希巧合等于首块哈希的干扰。
	poisonFirst := bytes.Clone(sourceData)
	for i := 0; i < 1024; i++ {
		poisonFirst[i] ^= 0x5A
	}
	poisonSecond := bytes.Clone(sourceData)
	for i := 0; i < 1024; i++ {
		poisonSecond[i] ^= 0xA5
	}
	if err := os.WriteFile(firstPath, poisonFirst, 0o640); err != nil {
		t.Fatalf("篡改第一副本失败: %v", err)
	}
	if err := os.WriteFile(secondPath, poisonSecond, 0o640); err != nil {
		t.Fatalf("篡改第二副本失败: %v", err)
	}

	blockHashHex := hex.EncodeToString(res.Blocks[0].Hash[:])
	data, err := env.reader.ReadBlock(ctx, blockHashHex)
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("全部副本损坏时应返回 ErrIntegrity，实际: %v", err)
	}
	if data != nil {
		t.Fatal("全部副本损坏时不得返回任何字节")
	}
	if !env.dirty.contains("电影/a.mkv") || !env.dirty.contains("备份/电影/a.mkv") {
		t.Fatalf("两个坏副本都应被标脏，实际收到: %v", env.dirty.snapshot())
	}
}

// TestReadBlockTruncatedFileIsIntegrityError 验证唯一副本被截短后
// shortRead / 越界分支映射为 ErrIntegrity，绝不返回残缺字节。
func TestReadBlockTruncatedFileIsIntegrityError(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	sourcePath := filepath.Join(env.nasRoot, "电影", "a.mkv")
	writeSource(t, sourcePath, testSourceSize)
	res, _ := env.buildPublishCommit(t, sourcePath, "a.mkv", "电影/a.mkv")

	// 截断到 100 字节：首块请求 offset=0+length=262144 已超出文件尺寸。
	if err := os.Truncate(sourcePath, 100); err != nil {
		t.Fatalf("截断源文件失败: %v", err)
	}

	data, err := env.reader.ReadBlock(ctx, hex.EncodeToString(res.Blocks[0].Hash[:]))
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("文件被截短后应返回 ErrIntegrity，实际: %v", err)
	}
	if data != nil {
		t.Fatal("截短文件读取不得返回任何字节")
	}
}

// TestReadBlockRejectsPathEscape 验证数据库被注入 "../evil.txt" 时：
// ReadBlock 必须失败（ErrIntegrity）、向 dirty listener 上报该路径，
// 并且绝不读出 nasRoot 外部文件的内容。
func TestReadBlockRejectsPathEscape(t *testing.T) {
	// 把 nasRoot 嵌套在外层目录里，使 "../evil.txt" 恰好指向外层的 evil.txt。
	outer := t.TempDir()
	nasRoot := filepath.Join(outer, "nas")
	if err := os.MkdirAll(nasRoot, 0o750); err != nil {
		t.Fatalf("创建 nas 根目录失败: %v", err)
	}
	env := newTestEnvAt(t, nasRoot)
	ctx := context.Background()

	const secret = "外部机密文件内容-绝不允许被读出"
	evilPath := filepath.Join(outer, "evil.txt")
	if err := os.WriteFile(evilPath, []byte(secret), 0o640); err != nil {
		t.Fatalf("放置外部文件失败: %v", err)
	}

	// 源文件放在 nasRoot 内仅用于算出真实 Seed；
	// 提交索引时直接注入逃逸相对路径 "../evil.txt" 作为唯一位置。
	source := filepath.Join(nasRoot, "a.mkv")
	writeSource(t, source, testSourceSize)
	res, _ := env.buildPublishCommit(t, source, "a.mkv", "../evil.txt")

	data, err := env.reader.ReadBlock(ctx, hex.EncodeToString(res.Blocks[0].Hash[:]))
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("路径逃逸必须失败且映射为 ErrIntegrity，实际: %v", err)
	}
	if data != nil {
		t.Fatal("路径逃逸时不得返回任何字节")
	}
	if !env.dirty.contains("../evil.txt") {
		t.Fatalf("逃逸路径应上报给 dirty listener，实际收到: %v", env.dirty.snapshot())
	}
	// 外部文件保持原样：内容从未被读出或改动。
	current, err := os.ReadFile(evilPath)
	if err != nil || string(current) != secret {
		t.Fatalf("外部文件不应被触碰: err=%v 内容=%q", err, string(current))
	}
}

// TestReadBlockRejectsSymlinkLocation 验证位置文件是指向外部内容的符号链接时，
// openNoFollow（O_NOFOLLOW）拒绝打开，读取失败且不返回外部文件内容。
func TestReadBlockRejectsSymlinkLocation(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	locationPath := filepath.Join(env.nasRoot, "电影", "a.mkv")
	writeSource(t, locationPath, testSourceSize)
	res, _ := env.buildPublishCommit(t, locationPath, "a.mkv", "电影/a.mkv")

	// 外部文件甚至写入与原文件完全相同的确定性内容；
	// 即便如此也绝不允许通过符号链接读出。
	external := filepath.Join(t.TempDir(), "outside.bin")
	writeSource(t, external, testSourceSize)
	if err := os.Remove(locationPath); err != nil {
		t.Fatalf("移除原位置文件失败: %v", err)
	}
	if err := os.Symlink(external, locationPath); err != nil {
		t.Fatalf("创建符号链接失败: %v", err)
	}

	data, err := env.reader.ReadBlock(ctx, hex.EncodeToString(res.Blocks[0].Hash[:]))
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("symlink 位置必须拒绝读取（O_NOFOLLOW）并映射为 ErrIntegrity，实际: %v", err)
	}
	if data != nil {
		t.Fatal("symlink 位置不得返回任何字节")
	}
	if !env.dirty.contains("电影/a.mkv") {
		t.Fatalf("symlink 位置应被标脏，实际收到: %v", env.dirty.snapshot())
	}
}
