package indexdb

// 仓库层单元测试：全部通过公开 API 驱动，仅两处例外使用同包白盒能力——
//  1. 把 contents.state 直接改成非 ready，验证 BlockCandidates 的 ready 过滤；
//  2. 统计 seed_blocks 行数，验证 DeleteContents 的外键级联。
//
// 时间参数一律显式传固定时间（time.Unix），保证断言精确可复现。

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------- 测试基建 ----------

// testDB 组合公开的 *DB 与数据库文件路径；路径仅供白盒断言直连底层文件时使用。
type testDB struct {
	*DB
	path string
}

// newTestDB 在 t.TempDir() 下打开一个全新的索引库，并在测试结束时自动关闭。
func newTestDB(t *testing.T) *testDB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "index.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open 测试数据库 %s 失败: %v", path, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &testDB{DB: db, path: path}
}

// hexHash 生成确定性的 64 位小写十六进制 Hash：
// 首字节是组标识，序号左移 44 位占据高位，剩余位补零；
// 不同组首字节不同、同组不同序号前缀不同，便于构造互不碰撞的测试数据。
func hexHash(group byte, serial int64) string {
	return fmt.Sprintf("%02x%015x%s", group, serial<<44, strings.Repeat("0", 47))
}

// singleBlock 构造单个满块（256 KiB）的块列表。
func singleBlock(seedHash, blockHash string) []SeedBlock {
	return []SeedBlock{{
		SeedHash:    seedHash,
		BlockIndex:  0,
		BlockHash:   blockHash,
		OffsetBytes: 0,
		LengthBytes: 262144,
	}}
}

// mustCommit 以固定参数提交一次索引结果；任何失败直接终止测试。
func mustCommit(t *testing.T, db *DB, relativePath, seedHash string, now time.Time, generation int64, blocks []SeedBlock) {
	t.Helper()
	var totalSize int64
	for _, block := range blocks {
		totalSize += block.LengthBytes
	}
	revision, err := db.PrepareIndex(context.Background(), relativePath, generation, now,
		TargetFingerprint{SizeBytes: totalSize, MtimeNs: now.UnixNano()}, false)
	if err != nil {
		t.Fatalf("PrepareIndex(%s) 失败: %v", relativePath, err)
	}
	err = db.CommitSeedResult(context.Background(), CommitParams{
		RelativePath:     relativePath,
		SeedHash:         seedHash,
		SeedLength:       32,
		SourceSize:       totalSize,
		Filename:         filepath.Base(relativePath),
		MediaType:        "application/octet-stream",
		SizeBytes:        totalSize,
		MtimeNs:          now.UnixNano(),
		Generation:       generation,
		ExpectedRevision: revision,
		Blocks:           blocks,
	}, now)
	if err != nil {
		t.Fatalf("CommitSeedResult(%s -> %s) 失败: %v", relativePath, seedHash, err)
	}
}

// findScan 按 generation 查找扫描记录，找不到返回 nil。
func findScan(scans []ScanRun, generation int64) *ScanRun {
	for i := range scans {
		if scans[i].Generation == generation {
			return &scans[i]
		}
	}
	return nil
}

// getLocation 通过公开 API GetContentDetail 取某个位置的状态明细，找不到直接终止测试。
func getLocation(t *testing.T, db *DB, ctx context.Context, seedHash, relativePath string, at time.Time) LocationDetail {
	t.Helper()
	_, locations, err := db.GetContentDetail(ctx, seedHash, time.Hour, at)
	if err != nil {
		t.Fatalf("GetContentDetail(%s) 失败: %v", seedHash, err)
	}
	for _, loc := range locations {
		if loc.RelativePath == relativePath {
			return loc
		}
	}
	t.Fatalf("内容 %s 下不存在位置 %s", seedHash, relativePath)
	return LocationDetail{}
}

// execDirect 用独立的裸连接对同一数据库文件执行一条 SQL（白盒辅助）。
func execDirect(t *testing.T, dbPath, statement string, args ...any) {
	t.Helper()
	raw, err := openSQLDB(dbPath)
	if err != nil {
		t.Fatalf("白盒打开 %s 失败: %v", dbPath, err)
	}
	defer func() { _ = raw.Close() }()
	if _, err := raw.Exec(statement, args...); err != nil {
		t.Fatalf("白盒执行 %q 失败: %v", statement, err)
	}
}

// countRows 用独立的裸连接统计查询行数/标量值（白盒辅助）。
func countRows(t *testing.T, dbPath, query string, args ...any) int64 {
	t.Helper()
	raw, err := openSQLDB(dbPath)
	if err != nil {
		t.Fatalf("白盒打开 %s 失败: %v", dbPath, err)
	}
	defer func() { _ = raw.Close() }()
	var n int64
	if err := raw.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("白盒查询 %q 失败: %v", query, err)
	}
	return n
}

// ---------- 扫描批次 ----------

// TestScanLifecycleGenerationsAndResetRunning 覆盖：
// BeginScan 单调递增、FinishScan 写入终态、RecentScans 新记录在前、
// ResetRunningScans 把遗留 running 批次改为 failed。
func TestScanLifecycleGenerationsAndResetRunning(t *testing.T) {
	tdb := newTestDB(t)
	bg := context.Background()

	t0 := time.Unix(10000, 0)
	g1, err := tdb.BeginScan(bg, t0)
	if err != nil {
		t.Fatalf("第一次 BeginScan 失败: %v", err)
	}
	g2, err := tdb.BeginScan(bg, t0.Add(time.Second))
	if err != nil {
		t.Fatalf("第二次 BeginScan 失败: %v", err)
	}
	if g2 <= g1 {
		t.Errorf("generation 应单调递增：g1=%d g2=%d", g1, g2)
	}

	scans, err := tdb.RecentScans(bg, 10)
	if err != nil {
		t.Fatalf("RecentScans 失败: %v", err)
	}
	if len(scans) != 2 {
		t.Fatalf("应有 2 条扫描记录，实际 %d 条", len(scans))
	}
	if scans[0].Generation != g2 || scans[1].Generation != g1 {
		t.Errorf("RecentScans 应新记录在前：得到 [%d, %d]，期望 [%d, %d]",
			scans[0].Generation, scans[1].Generation, g2, g1)
	}
	for _, s := range scans {
		if s.Status != ScanRunning || s.FinishedAt != nil {
			t.Errorf("批次 %d 初始应为 running 且 finished_at 为空，实际 status=%s",
				s.Generation, s.Status)
		}
		if !s.StartedAt.Equal(time.Unix(0, s.StartedAt.UnixNano())) {
			t.Errorf("批次 %d 的 started_at 时间戳往返应一致", s.Generation)
		}
	}

	finishAt := t0.Add(2 * time.Second)
	if err := tdb.FinishScan(bg, g1, ScanSucceeded, "", finishAt); err != nil {
		t.Fatalf("FinishScan 失败: %v", err)
	}
	scans, err = tdb.RecentScans(bg, 10)
	if err != nil {
		t.Fatalf("RecentScans 复查失败: %v", err)
	}
	done := findScan(scans, g1)
	if done == nil || done.Status != ScanSucceeded || done.FinishedAt == nil || !done.FinishedAt.Equal(finishAt) {
		t.Errorf("批次 %d 应为 succeeded 且 finished_at=%v，实际 %+v", g1, finishAt, done)
	}

	// ResetRunningScans 只处理 running 批次，已完成的 succeeded 不受影响。
	resetAt := t0.Add(3 * time.Second)
	if err := tdb.ResetRunningScans(bg, resetAt); err != nil {
		t.Fatalf("ResetRunningScans 失败: %v", err)
	}
	scans, err = tdb.RecentScans(bg, 10)
	if err != nil {
		t.Fatalf("RecentScans 三查失败: %v", err)
	}
	reset := findScan(scans, g2)
	if reset == nil || reset.Status != ScanFailed {
		t.Errorf("遗留批次 %d 应被重置为 failed，实际 %+v", g2, reset)
	} else {
		if reset.FinishedAt == nil || !reset.FinishedAt.Equal(resetAt) {
			t.Errorf("重置后 finished_at 应为 %v，实际 %v", resetAt, reset.FinishedAt)
		}
		if reset.ErrorZh != "进程中断，扫描未完成" {
			t.Errorf("重置后 error_zh 应为中文诊断，实际 %q", reset.ErrorZh)
		}
	}
	if ok := findScan(scans, g1); ok == nil || ok.Status != ScanSucceeded {
		t.Errorf("已完成批次 %d 不应被 ResetRunningScans 改动", g1)
	}

	g3, err := tdb.BeginScan(bg, t0.Add(4*time.Second))
	if err != nil {
		t.Fatalf("重置后的第三次 BeginScan 失败: %v", err)
	}
	if g3 <= g2 {
		t.Errorf("重置不应影响 generation 单调性：g2=%d g3=%d", g2, g3)
	}
}

// ---------- 索引提交 ----------

// TestCommitSeedResultInsertAndResubmit 覆盖：
// 首次提交写入 contents + seed_blocks + file_locations 并可查询可用性；
// 同一路径重复提交不同 seed_hash 后位置指向新 hash 且 revision 递增。
func TestCommitSeedResultInsertAndResubmit(t *testing.T) {
	tdb := newTestDB(t)
	bg := context.Background()

	now := time.Unix(20000, 0)
	path := "movies/big.mkv"
	seed1 := hexHash('a', 11)
	blocks := []SeedBlock{
		{SeedHash: seed1, BlockIndex: 0, BlockHash: hexHash('b', 101), OffsetBytes: 0, LengthBytes: 262144},
		{SeedHash: seed1, BlockIndex: 1, BlockHash: hexHash('b', 102), OffsetBytes: 262144, LengthBytes: 1024},
	}
	mustCommit(t, tdb.DB, path, seed1, now, 1, blocks)

	avail, err := tdb.GetAvailability(bg, seed1)
	if err != nil {
		t.Fatalf("GetAvailability 失败: %v", err)
	}
	if avail.Content.State != StateReady {
		t.Errorf("内容状态应为 ready，实际 %q", avail.Content.State)
	}
	if avail.ValidReplicas != 1 {
		t.Errorf("valid 副本数应为 1，实际 %d", avail.ValidReplicas)
	}
	if avail.Content.SizeBytes != 263168 {
		t.Errorf("contents.size_bytes 应等于 SourceSize，实际 %d", avail.Content.SizeBytes)
	}

	fingerprints, err := tdb.ListFingerprints(bg)
	if err != nil {
		t.Fatalf("ListFingerprints 失败: %v", err)
	}
	fp, ok := fingerprints[path]
	if !ok {
		t.Fatalf("提交后位置 %s 应存在", path)
	}
	if fp.SeedHash != seed1 || fp.State != LocationValid || fp.Revision != 2 {
		t.Errorf("首次提交后位置状态不符（revision=PrepareIndex+提交）： %+v", fp)
	}

	// 同一路径、不同 seed_hash 的重新提交：location 改指新 hash，revision 自增。
	now2 := now.Add(time.Second)
	seed2 := hexHash('a', 12)
	mustCommit(t, tdb.DB, path, seed2, now2, 7, blocks)

	fingerprints, err = tdb.ListFingerprints(bg)
	if err != nil {
		t.Fatalf("ListFingerprints 二查失败: %v", err)
	}
	fp = fingerprints[path]
	if fp.SeedHash != seed2 {
		t.Errorf("重复提交后位置应指向新 hash %s，实际 %s", seed2, fp.SeedHash)
	}
	if fp.Revision != 4 {
		t.Errorf("重复提交后 revision 应为 4（两次 PrepareIndex+两次提交），实际 %d", fp.Revision)
	}

	avail2, err := tdb.GetAvailability(bg, seed2)
	if err != nil {
		t.Fatalf("GetAvailability(seed2) 失败: %v", err)
	}
	if avail2.ValidReplicas != 1 {
		t.Errorf("新 hash 的 valid 副本数应为 1，实际 %d", avail2.ValidReplicas)
	}
	// 旧 hash 内容仍存在（孤儿 Seed 留给 GC），但不再有 valid 位置。
	old, err := tdb.GetAvailability(bg, seed1)
	if err != nil {
		t.Fatalf("旧 hash 应仍在 contents 中: %v", err)
	}
	if old.ValidReplicas != 0 {
		t.Errorf("旧 hash 的 valid 副本数应为 0，实际 %d", old.ValidReplicas)
	}
}

// TestCommitSeedResultAtomicOnConstraintViolation 覆盖 CommitSeedResult 的事务性：
// 某个块的 length_bytes=0 触发 CHECK 约束失败时整体回滚，
// contents 中不允许留下半提交的 seed_hash 记录，file_locations 也不允许出现该路径。
func TestCommitSeedResultAtomicOnConstraintViolation(t *testing.T) {
	tdb := newTestDB(t)
	bg := context.Background()

	now := time.Unix(21000, 0)
	path := "broken/file.bin"
	seed := hexHash('a', 21)
	badBlocks := []SeedBlock{{
		SeedHash:    seed,
		BlockIndex:  0,
		BlockHash:   hexHash('b', 201),
		OffsetBytes: 0,
		LengthBytes: 0, // 违反 CHECK(length_bytes BETWEEN 1 AND 262144)
	}}

	err := tdb.CommitSeedResult(bg, CommitParams{
		RelativePath: path,
		SeedHash:     seed,
		SeedLength:   32,
		SourceSize:   262144,
		Filename:     "file.bin",
		MediaType:    "application/octet-stream",
		SizeBytes:    262144,
		MtimeNs:      now.UnixNano(),
		Generation:   1,
		Blocks:       badBlocks,
	}, now)
	if err == nil {
		t.Fatal("CHECK 约束失败时 CommitSeedResult 必须报错")
	}

	if _, err := tdb.GetAvailability(bg, seed); !errors.Is(err, ErrNotFound) {
		t.Errorf("事务应整体回滚：seed_hash=%s 不应出现在 contents 中，实际错误: %v", seed, err)
	}

	fingerprints, err := tdb.ListFingerprints(bg)
	if err != nil {
		t.Fatalf("ListFingerprints 失败: %v", err)
	}
	if _, exists := fingerprints[path]; exists {
		t.Errorf("事务回滚后位置 %s 不应存在", path)
	}
}

// ---------- 失效与恢复 ----------

// TestInvalidatePathsCoalesceAndRevisionGuard 覆盖：
// 第一次失效写入 invalid_since；重复失效不刷新 invalid_since（COALESCE 语义）；
// KnownRevision 守卫在 revision 变化后让过期任务的整体失效动作落空。
func TestInvalidatePathsCoalesceAndRevisionGuard(t *testing.T) {
	tdb := newTestDB(t)
	bg := context.Background()

	now := time.Unix(30000, 0)
	path := "docs/report.pdf"
	seed := hexHash('a', 31)
	mustCommit(t, tdb.DB, path, seed, now, 5, singleBlock(seed, hexHash('b', 301)))

	t1 := now.Add(time.Minute)
	fpsVar369, snapErr369 := tdb.ListFingerprints(bg)
	if snapErr369 != nil {
		t.Fatal(snapErr369)
	}
	err := tdb.InvalidatePaths(bg, []InvalidateTarget{{RelativePath: path, KnownRevision: fpsVar369[path].Revision, ErrorZh: "扫描未见该文件"}}, t1, 6)
	if err != nil {
		t.Fatalf("第一次 InvalidatePaths 失败: %v", err)
	}
	fps, err := tdb.ListFingerprints(bg)
	if err != nil {
		t.Fatalf("ListFingerprints 失败: %v", err)
	}
	fp := fps[path]
	if fp.State != LocationInvalid {
		t.Errorf("首次失效后状态应为 invalid，实际 %+v", fp)
	}
	if fp.Revision != 2 {
		t.Errorf("首次失效后 revision 应为 2（PrepareIndex+提交各一），实际 %d", fp.Revision)
	}
	loc := getLocation(t, tdb.DB, bg, seed, path, t1)
	if loc.InvalidSince == nil || !loc.InvalidSince.Equal(t1) {
		t.Errorf("首次失效后 invalid_since 应为 %v，实际 %+v", t1, loc.InvalidSince)
	}
	if loc.LastSeenGeneration != 6 {
		t.Errorf("首次失效后 last_seen_generation 应为 6，实际 %d", loc.LastSeenGeneration)
	}

	// 第二次失效：时间已推进，但 invalid_since 不得被刷新。
	t2 := t1.Add(time.Hour)
	fpsVar391, snapErr391 := tdb.ListFingerprints(bg)
	if snapErr391 != nil {
		t.Fatal(snapErr391)
	}
	err = tdb.InvalidatePaths(bg, []InvalidateTarget{{RelativePath: path, KnownRevision: fpsVar391[path].Revision, ErrorZh: "第二轮仍未看到"}}, t2, 7)
	if err != nil {
		t.Fatalf("第二次 InvalidatePaths 失败: %v", err)
	}
	loc = getLocation(t, tdb.DB, bg, seed, path, t2)
	if loc.InvalidSince == nil || !loc.InvalidSince.Equal(t1) {
		t.Errorf("重复失效不得刷新 invalid_since：期望 %v，实际 %v", t1, loc.InvalidSince)
	}
	if loc.LastSeenGeneration != 7 {
		t.Errorf("第二次失效应生效（last_seen_generation=7），实际 %d", loc.LastSeenGeneration)
	}
	if loc.LastErrorZh != "第二轮仍未看到" {
		t.Errorf("last_error_zh 应更新为最新诊断，实际 %q", loc.LastErrorZh)
	}

	// KnownRevision 守卫：PrepareIndex（生产入口）之后旧快照的失效动作必须整体跳过。
	newRev, err := tdb.PrepareIndex(bg, path, 8, t2.Add(time.Second), TargetFingerprint{}, true)
	if err != nil {
		t.Fatalf("PrepareIndex 失败: %v", err)
	}
	if newRev != 3 {
		t.Fatalf("PrepareIndex 后 revision 应为 3（前两轮各 +1），实际 %d", newRev)
	}
	t3 := t2.Add(time.Hour)
	// 故意使用过期快照 revision=1（早于两轮变更），守卫必须让本次失效整体落空。
	err = tdb.InvalidatePaths(bg, []InvalidateTarget{{RelativePath: path, KnownRevision: 1, ErrorZh: "过期任务试图失效"}}, t3, 8)
	if err != nil {
		t.Fatalf("带守卫的 InvalidatePaths 失败: %v", err)
	}
	fps, err = tdb.ListFingerprints(bg)
	if err != nil {
		t.Fatalf("ListFingerprints 三查失败: %v", err)
	}
	fp = fps[path]
	if fp.Revision != 3 {
		t.Errorf("守卫生效时 revision 不得变化，实际 %d", fp.Revision)
	}
	loc = getLocation(t, tdb.DB, bg, seed, path, t3)
	if loc.LastSeenGeneration != 7 {
		t.Errorf("revision 守卫应使过期失效落空（last_seen_generation 保持 7），实际 %d", loc.LastSeenGeneration)
	}
	if loc.InvalidSince == nil || !loc.InvalidSince.Equal(t1) {
		t.Errorf("revision 守卫下 invalid_since 不得变化，实际 %v", loc.InvalidSince)
	}
	if loc.LastErrorZh != "第二轮仍未看到" {
	}
}

// TestConfirmSeenPathsRestoresLocation 覆盖 ConfirmSeenPaths：
// invalid 行恢复 valid、invalid_since 清空、last_seen_generation 更新为新批次号。
func TestConfirmSeenPathsRestoresLocation(t *testing.T) {
	tdb := newTestDB(t)
	bg := context.Background()

	now := time.Unix(31000, 0)
	path := "photos/img.jpg"
	seed := hexHash('a', 32)
	mustCommit(t, tdb.DB, path, seed, now, 1, singleBlock(seed, hexHash('b', 302)))

	t1 := now.Add(time.Minute)
	fpsVar450, snapErr450 := tdb.ListFingerprints(bg)
	if snapErr450 != nil {
		t.Fatal(snapErr450)
	}
	if err := tdb.InvalidatePaths(bg, []InvalidateTarget{{RelativePath: path, KnownRevision: fpsVar450[path].Revision, ErrorZh: "扫描未见"}}, t1, 2); err != nil {
		t.Fatalf("InvalidatePaths 失败: %v", err)
	}

	seenAt := t1.Add(time.Minute)
	err := tdb.ConfirmSeenPaths(bg, []TouchAction{{
		RelativePath:  path,
		KnownRevision: fpsVar450[path].Revision,
		SizeBytes:     555,
		MtimeNs:       777,
	}}, 42, seenAt)
	if err != nil {
		t.Fatalf("ConfirmSeenPaths 失败: %v", err)
	}

	fps, err := tdb.ListFingerprints(bg)
	if err != nil {
		t.Fatalf("ListFingerprints 失败: %v", err)
	}
	fp := fps[path]
	if fp.State != LocationValid {
		t.Errorf("确认后应恢复 valid，实际 %+v", fp)
	}
	loc := getLocation(t, tdb.DB, bg, seed, path, seenAt)
	if loc.InvalidSince != nil {
		t.Errorf("确认后 invalid_since 应被清空，实际 %v", loc.InvalidSince)
	}
	if loc.LastSeenGeneration != 42 {
		t.Errorf("确认后 last_seen_generation 应为 42，实际 %d", loc.LastSeenGeneration)
	}
	if fp.SizeBytes != 555 || fp.MtimeNs != 777 {
		t.Errorf("确认后指纹应刷新为 (555,777)，实际 (%d,%d)", fp.SizeBytes, fp.MtimeNs)
	}

	avail, err := tdb.GetAvailability(bg, seed)
	if err != nil {
		t.Fatalf("GetAvailability 失败: %v", err)
	}
	if avail.ValidReplicas != 1 {
		t.Errorf("恢复后 valid 副本数应为 1，实际 %d", avail.ValidReplicas)
	}
}

// TestMarkInvalidNowAndLocationFailure 覆盖 MarkInvalidNow / SetLocationFailed / MarkLocationError：
//   - MarkInvalidNow 置 invalid 且 invalid_since 只写第一次（COALESCE，重复标记不刷新）；
//   - SetLocationFailed 对不存在的路径创建无 seed_hash 的 error 占位行，重复调用按 upsert 更新；
//   - MarkLocationError 置 error 时保留既有 invalid_since。
func TestMarkInvalidNowAndLocationFailure(t *testing.T) {
	tdb := newTestDB(t)
	bg := context.Background()

	now := time.Unix(32000, 0)
	path := "videos/live.mkv"
	seed := hexHash('a', 33)
	mustCommit(t, tdb.DB, path, seed, now, 1, singleBlock(seed, hexHash('b', 303)))

	revSnap0, snapErr0 := tdb.ListFingerprints(bg)
	if snapErr0 != nil {
		t.Fatal(snapErr0)
	}
	if err := tdb.MarkInvalidNow(bg, path, "inotify 确认文件消失", time.Now(), revSnap0[path].Revision); err != nil {
		t.Fatalf("MarkInvalidNow 失败: %v", err)
	}
	fps, err := tdb.ListFingerprints(bg)
	if err != nil {
		t.Fatalf("ListFingerprints 失败: %v", err)
	}
	first := fps[path]
	if first.State != LocationInvalid {
		t.Fatalf("MarkInvalidNow 后状态应为 invalid，实际 %+v", first)
	}
	loc := getLocation(t, tdb.DB, bg, seed, path, now.Add(time.Minute))
	if loc.InvalidSince == nil {
		t.Fatalf("MarkInvalidNow 后 invalid_since 应非空")
	}
	firstSince := *loc.InvalidSince

	time.Sleep(5 * time.Millisecond) // 让 time.Now() 明确推进，证明 COALESCE 生效
	if err := tdb.MarkInvalidNow(bg, path, "第二次标记", time.Now().Add(time.Second), revSnap0[path].Revision); err != nil {
		t.Fatalf("第二次 MarkInvalidNow 失败: %v", err)
	}
	loc = getLocation(t, tdb.DB, bg, seed, path, now.Add(2*time.Minute))
	if loc.InvalidSince == nil || !loc.InvalidSince.Equal(firstSince) {
		t.Errorf("重复 MarkInvalidNow 不得刷新 invalid_since：期望 %v，实际 %v", firstSince, loc.InvalidSince)
	}

	// SetLocationFailed：路径不存在时创建占位行（插入分支不受 CAS 约束），且不带 seed_hash。
	failPath := "oversize/raw.iso"
	if err := tdb.SetLocationFailed(bg, failPath, 9_000_000_000, 1234567890, "超过协议最大源文件尺寸", 0); err != nil {
		t.Fatalf("SetLocationFailed 失败: %v", err)
	}
	fps, err = tdb.ListFingerprints(bg)
	if err != nil {
		t.Fatalf("ListFingerprints 三查失败: %v", err)
	}
	placeholder, ok := fps[failPath]
	if !ok {
		t.Fatalf("占位位置 %s 应存在", failPath)
	}
	if placeholder.SeedHash != "" {
		t.Errorf("占位行不应携带 seed_hash，实际 %q", placeholder.SeedHash)
	}
	if placeholder.State != LocationError || placeholder.SizeBytes != 9_000_000_000 || placeholder.MtimeNs != 1234567890 {
		t.Errorf("占位行字段不符：%+v", placeholder)
	}

	// 再次调用按 CAS 语义更新同一行而不是插入新行。
	fpsNow, fpsErr := tdb.ListFingerprints(bg)
	if fpsErr != nil {
		t.Fatal(fpsErr)
	}
	if err := tdb.SetLocationFailed(bg, failPath, 1, 2, "尺寸信息修正", fpsNow[failPath].Revision); err != nil {
		t.Fatalf("SetLocationFailed 更新失败: %v", err)
	}
	fps, err = tdb.ListFingerprints(bg)
	if err != nil {
		t.Fatalf("ListFingerprints 四查失败: %v", err)
	}
	placeholder = fps[failPath]
	if placeholder.State != LocationError || placeholder.SizeBytes != 1 || placeholder.MtimeNs != 2 {
		t.Errorf("upsert 后占位行应被更新，实际 %+v", placeholder)
	}

	// MarkLocationError：置 error 但保留 invalid_since。
	errPath := "videos/live.mkv"
	if err := tdb.MarkLocationError(bg, errPath, "读取完整性校验失败"); err != nil {
		t.Fatalf("MarkLocationError 失败: %v", err)
	}
	marked := getLocation(t, tdb.DB, bg, seed, errPath, now.Add(3*time.Minute))
	if marked.State != LocationError {
		t.Errorf("MarkLocationError 后状态应为 error，实际 %q", marked.State)
	}
	if marked.InvalidSince == nil || !marked.InvalidSince.Equal(firstSince) {
		t.Errorf("MarkLocationError 应保留 invalid_since=%v，实际 %v", firstSince, marked.InvalidSince)
	}
}

// ---------- Stat / Read 支撑 ----------

// TestBlockCandidatesOnlyValidAndReady 覆盖 BlockCandidates 过滤规则：
// 同一 seed_hash 有 valid 与 invalid 两个位置时只返回 valid 的；
// contents.state 不是 ready 时一律返回空。
func TestBlockCandidatesOnlyValidAndReady(t *testing.T) {
	tdb := newTestDB(t)
	bg := context.Background()

	now := time.Unix(33000, 0)
	seed := hexHash('a', 41)
	blockHash := hexHash('b', 401)

	// 同一 seed 提交到两个位置。
	mustCommit(t, tdb.DB, "replicas/good.bin", seed, now, 1, singleBlock(seed, blockHash))
	mustCommit(t, tdb.DB, "replicas/bad.bin", seed, now, 1, singleBlock(seed, blockHash))

	t1 := now.Add(time.Minute)
	fpsSnap592, snapErr592 := tdb.ListFingerprints(bg)
	if snapErr592 != nil {
		t.Fatal(snapErr592)
	}
	if err := tdb.InvalidatePaths(bg, []InvalidateTarget{{RelativePath: "replicas/bad.bin", KnownRevision: fpsSnap592["replicas/bad.bin"].Revision, ErrorZh: "副本丢失"}}, t1, 2); err != nil {
		t.Fatalf("InvalidatePaths 失败: %v", err)
	}

	candidates, err := tdb.BlockCandidates(bg, blockHash, 10)
	if err != nil {
		t.Fatalf("BlockCandidates 失败: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("只应返回 1 个 valid 候选，实际 %d 个：%+v", len(candidates), candidates)
	}
	if candidates[0].RelativePath != "replicas/good.bin" ||
		candidates[0].OffsetBytes != 0 || candidates[0].LengthBytes != 262144 {
		t.Errorf("候选位置字段不符：%+v", candidates[0])
	}

	// 白盒：把 contents.state 改成非 ready，候选必须清空。
	execDirect(t, tdb.path, `UPDATE contents SET state = 'invalid' WHERE seed_hash = ?`, seed)
	candidates, err = tdb.BlockCandidates(bg, blockHash, 10)
	if err != nil {
		t.Fatalf("非 ready 状态下 BlockCandidates 失败: %v", err)
	}
	if len(candidates) != 0 {
		t.Errorf("内容非 ready 时应返回空候选，实际 %+v", candidates)
	}
}

// ---------- 管理台查询 ----------

// TestListContentsFilterPagingAndRetention 覆盖 ListContents：
// 文本过滤（Hash 前缀）、状态过滤、分页 total、以及 invalid_since 到期的保留毫秒计算。
func TestListContentsFilterPagingAndRetention(t *testing.T) {
	tdb := newTestDB(t)
	bg := context.Background()

	base := time.Unix(40000, 0)
	retention := time.Hour

	seedA := hexHash('a', 51)
	mustCommit(t, tdb.DB, "list/a.bin", seedA, base, 1, singleBlock(seedA, hexHash('b', 501)))

	seedB := hexHash('a', 52)
	mustCommit(t, tdb.DB, "list/b1.bin", seedB, base.Add(time.Second), 2, singleBlock(seedB, hexHash('b', 502)))
	mustCommit(t, tdb.DB, "list/b2.bin", seedB, base.Add(time.Second), 2, singleBlock(seedB, hexHash('b', 502)))
	tInv := base.Add(2 * time.Second)
	fpsSnap, snapErr := tdb.ListFingerprints(bg)
	if snapErr != nil {
		t.Fatal(snapErr)
	}
	err := tdb.InvalidatePaths(bg, []InvalidateTarget{
		{RelativePath: "list/b1.bin", KnownRevision: fpsSnap["list/b1.bin"].Revision, ErrorZh: "副本消失"},
		{RelativePath: "list/b2.bin", KnownRevision: fpsSnap["list/b2.bin"].Revision, ErrorZh: "副本消失"},
	}, tInv, 3)
	if err != nil {
		t.Fatalf("InvalidatePaths 失败: %v", err)
	}

	seedC := hexHash('a', 53)
	mustCommit(t, tdb.DB, "list/c.bin", seedC, base.Add(3*time.Second), 4, singleBlock(seedC, hexHash('b', 503)))

	listTime := base.Add(4 * time.Second)

	// 文本过滤：粘贴 Hash 前缀即可命中唯一内容。
	page, err := tdb.ListContents(bg, ListQuery{Text: seedA[:16]}, retention, listTime)
	if err != nil {
		t.Fatalf("ListContents 文本过滤失败: %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].SeedHash != seedA {
		t.Errorf("前缀 %q 应命中 seedA 一条，实际 Total=%d Items=%+v", seedA[:16], page.Total, page.Items)
	}

	// 状态过滤：ready 只有 A 与 C（B 已全部失效）。
	page, err = tdb.ListContents(bg, ListQuery{State: StateReady}, retention, listTime)
	if err != nil {
		t.Fatalf("ListContents 状态过滤失败: %v", err)
	}
	if page.Total != 2 {
		t.Errorf("ready 内容应共 2 条，实际 %d", page.Total)
	}
	states := map[string]bool{}
	for _, item := range page.Items {
		states[item.SeedHash] = true
	}
	if !states[seedA] || !states[seedC] || states[seedB] {
		t.Errorf("状态过滤结果不符：%v", states)
	}

	// 分页：Total 反映过滤条件下的总数，与 Limit/Offset 无关；created_at DESC 排序。
	page, err = tdb.ListContents(bg, ListQuery{Limit: 2}, retention, listTime)
	if err != nil {
		t.Fatalf("ListContents 第一页失败: %v", err)
	}
	if page.Total != 3 || len(page.Items) != 2 {
		t.Errorf("第一页应 Total=3 取 2 行，实际 Total=%d 行数=%d", page.Total, len(page.Items))
	}
	if page.Items[0].SeedHash != seedC || page.Items[1].SeedHash != seedB {
		t.Errorf("第一页应按 created_at 倒序为 [C,B]，实际 [%s,%s]",
			page.Items[0].SeedHash, page.Items[1].SeedHash)
	}
	page, err = tdb.ListContents(bg, ListQuery{Limit: 2, Offset: 2}, retention, listTime)
	if err != nil {
		t.Fatalf("ListContents 第二页失败: %v", err)
	}
	if page.Total != 3 || len(page.Items) != 1 || page.Items[0].SeedHash != seedA {
		t.Errorf("第二页应只剩 seedA，实际 Total=%d Items=%+v", page.Total, page.Items)
	}

	// RetentionLeftMs：全失效内容的剩余保留毫秒 = retention - (now - invalid_since)。
	page, err = tdb.ListContents(bg, ListQuery{Text: seedB[:16]}, retention, tInv.Add(20*time.Minute))
	if err != nil {
		t.Fatalf("ListContents 保留期查询失败: %v", err)
	}
	if page.Total != 1 {
		t.Fatalf("seedB 应命中 1 条，实际 %d", page.Total)
	}
	item := page.Items[0]
	if item.ValidReplicas != 0 || item.InvalidReplicas != 2 {
		t.Errorf("seedB 副本计数应为 0 valid / 2 invalid，实际 %d/%d", item.ValidReplicas, item.InvalidReplicas)
	}
	if item.InvalidSince == nil || !item.InvalidSince.Equal(tInv) {
		t.Errorf("invalid_since 应为 %v，实际 %v", tInv, item.InvalidSince)
	}
	if left := (retention - 20*time.Minute).Milliseconds(); item.RetentionLeftMs != left {
		t.Errorf("RetentionLeftMs 应为 %d，实际 %d", left, item.RetentionLeftMs)
	}

	// 已过保留期：剩余毫秒钳制为 0。
	page, err = tdb.ListContents(bg, ListQuery{Text: seedB[:16]}, retention, tInv.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("ListContents 到期查询失败: %v", err)
	}
	if page.Items[0].RetentionLeftMs != 0 {
		t.Errorf("超过保留期后 RetentionLeftMs 应为 0，实际 %d", page.Items[0].RetentionLeftMs)
	}

	// 有效内容不参与保留期计算。
	page, err = tdb.ListContents(bg, ListQuery{Text: seedA[:16]}, retention, listTime)
	if err != nil {
		t.Fatalf("ListContents 复查失败: %v", err)
	}
	if page.Items[0].RetentionLeftMs != 0 {
		t.Errorf("valid 内容的 RetentionLeftMs 应为 0，实际 %d", page.Items[0].RetentionLeftMs)
	}
}

// TestGetContentDetailAndNotFound 覆盖 GetContentDetail：
// 返回 summary + 全部位置明细（相对路径与中文诊断按相对路径排序）；未知 hash 返回 ErrNotFound。
func TestGetContentDetailAndNotFound(t *testing.T) {
	tdb := newTestDB(t)
	bg := context.Background()

	now := time.Unix(41000, 0)
	seed := hexHash('a', 61)
	blockHash := hexHash('b', 601)

	mustCommit(t, tdb.DB, "detail/zeta.bin", seed, now, 1, singleBlock(seed, blockHash))
	mustCommit(t, tdb.DB, "detail/alpha.bin", seed, now, 1, singleBlock(seed, blockHash))

	tInv := now.Add(time.Minute)
	fpsSnap747, snapErr747 := tdb.ListFingerprints(bg)
	if snapErr747 != nil {
		t.Fatal(snapErr747)
	}
	err := tdb.InvalidatePaths(bg, []InvalidateTarget{{RelativePath: "detail/zeta.bin", KnownRevision: fpsSnap747["detail/zeta.bin"].Revision, ErrorZh: "扫描未发现该文件"}}, tInv, 2)
	if err != nil {
		t.Fatalf("InvalidatePaths 失败: %v", err)
	}

	summary, locations, err := tdb.GetContentDetail(bg, seed, time.Hour, tInv.Add(time.Minute))
	if err != nil {
		t.Fatalf("GetContentDetail 失败: %v", err)
	}
	if summary.SeedHash != seed || summary.State != StateReady {
		t.Errorf("summary 主键/状态不符：%+v", summary.Content)
	}
	if summary.ValidReplicas != 1 || summary.InvalidReplicas != 1 {
		t.Errorf("summary 副本计数应为 1/1，实际 %d/%d", summary.ValidReplicas, summary.InvalidReplicas)
	}
	if len(locations) != 2 {
		t.Fatalf("应返回 2 个位置明细，实际 %d 个：%+v", len(locations), locations)
	}
	// ORDER BY relative_path：alpha 在前。
	validLoc := locations[0]
	if validLoc.RelativePath != "detail/alpha.bin" || validLoc.State != LocationValid || validLoc.InvalidSince != nil {
		t.Errorf("valid 位置明细不符：%+v", validLoc)
	}
	invalidLoc := locations[1]
	if invalidLoc.RelativePath != "detail/zeta.bin" || invalidLoc.State != LocationInvalid {
		t.Errorf("invalid 位置明细不符：%+v", invalidLoc)
	}
	if invalidLoc.LastErrorZh != "扫描未发现该文件" {
		t.Errorf("位置中文诊断不符：%q", invalidLoc.LastErrorZh)
	}
	if invalidLoc.InvalidSince == nil || !invalidLoc.InvalidSince.Equal(tInv) {
		t.Errorf("位置 invalid_since 应为 %v，实际 %v", tInv, invalidLoc.InvalidSince)
	}

	// 不存在的 hash：errors.Is 判定为 ErrNotFound。
	missing := hexHash('f', 999)
	if _, _, err := tdb.GetContentDetail(bg, missing, time.Hour, tInv); !errors.Is(err, ErrNotFound) {
		t.Errorf("未知 hash 应返回 ErrNotFound，实际: %v", err)
	}
}

// ---------- GC ----------

// TestExpiredInvalidLocationsCutoff 覆盖 ExpiredInvalidLocations：
// 只返回 invalid_since <= cutoff 的 invalid 位置；valid 位置与新近失效的位置不出现。
func TestExpiredInvalidLocationsCutoff(t *testing.T) {
	tdb := newTestDB(t)
	bg := context.Background()

	base := time.Unix(42000, 0)
	seedOld := hexHash('a', 71)
	seedFresh := hexHash('a', 72)
	seedKeep := hexHash('a', 73)

	mustCommit(t, tdb.DB, "gc/old.bin", seedOld, base, 1, singleBlock(seedOld, hexHash('b', 701)))
	mustCommit(t, tdb.DB, "gc/fresh.bin", seedFresh, base, 1, singleBlock(seedFresh, hexHash('b', 702)))
	mustCommit(t, tdb.DB, "gc/keep.bin", seedKeep, base, 1, singleBlock(seedKeep, hexHash('b', 703)))

	tOld := base.Add(time.Second)
	tFresh := base.Add(time.Hour)
	fps0, err := tdb.ListFingerprints(bg)
	if err != nil {
		t.Fatal(err)
	}
	if err := tdb.InvalidatePaths(bg, []InvalidateTarget{{RelativePath: "gc/old.bin", KnownRevision: fps0["gc/old.bin"].Revision, ErrorZh: "早退"}}, tOld, 2); err != nil {
		t.Fatalf("失效 old 失败: %v", err)
	}
	if err := tdb.InvalidatePaths(bg, []InvalidateTarget{{RelativePath: "gc/fresh.bin", KnownRevision: fps0["gc/fresh.bin"].Revision, ErrorZh: "晚退"}}, tFresh, 2); err != nil {
		t.Fatalf("失效 fresh 失败: %v", err)
	}

	// cutoff 在两者之间：只命中 old。
	expired, err := tdb.ExpiredInvalidLocations(bg, base.Add(30*time.Minute), 100)
	if err != nil {
		t.Fatalf("ExpiredInvalidLocations 失败: %v", err)
	}
	if len(expired) != 1 || expired[0].RelativePath != "gc/old.bin" {
		t.Errorf("cutoff 之前应只有 gc/old.bin，实际 %+v", expired)
	}
	// cutoff 早于所有失效时间：空结果。
	expired, err = tdb.ExpiredInvalidLocations(bg, base, 100)
	if err != nil {
		t.Fatalf("ExpiredInvalidLocations 二查失败: %v", err)
	}
	if len(expired) != 0 {
		t.Errorf("cutoff 早于一切失效时间时应返回空，实际 %+v", expired)
	}
	// cutoff 晚于两者：两个都返回，valid 的 keep 永远不出现。
	expired, err = tdb.ExpiredInvalidLocations(bg, base.Add(2*time.Hour), 100)
	if err != nil {
		t.Fatalf("ExpiredInvalidLocations 三查失败: %v", err)
	}
	if len(expired) != 2 {
		t.Errorf("cutoff 之后应有 2 个过期位置，实际 %+v", expired)
	}
}

// TestDeleteLocationsGuarded 覆盖守卫式过期位置删除（阻断 2）：
// 只删除 state=invalid 且 invalid_since<=cutoff 且 revision 与快照一致的位置；
// 快照后恢复为 valid 或被新任务取代（revision 变化）的位置一律跳过。
func TestDeleteLocationsGuarded(t *testing.T) {
	tdb := newTestDB(t)
	bg := context.Background()

	now := time.Unix(43000, 0)
	seedShared := hexHash('a', 81)
	seedSolo := hexHash('a', 82)

	mustCommit(t, tdb.DB, "del/shared1.bin", seedShared, now, 1, singleBlock(seedShared, hexHash('b', 801)))
	mustCommit(t, tdb.DB, "del/shared2.bin", seedShared, now, 1, singleBlock(seedShared, hexHash('b', 801)))
	mustCommit(t, tdb.DB, "del/solo.bin", seedSolo, now, 1, singleBlock(seedSolo, hexHash('b', 802)))

	tInv := now.Add(time.Minute)
	fps, err := tdb.ListFingerprints(bg)
	if err != nil {
		t.Fatal(err)
	}
	targets := []InvalidateTarget{}
	for _, path := range []string{"del/shared1.bin", "del/shared2.bin", "del/solo.bin"} {
		targets = append(targets, InvalidateTarget{RelativePath: path, KnownRevision: fps[path].Revision})
	}
	if err := tdb.InvalidatePaths(bg, targets, tInv, 9); err != nil {
		t.Fatal(err)
	}

	// GC 快照：此时三个位置都是过期 invalid。
	cutoff := tInv.Add(time.Minute)
	expired, err := tdb.ExpiredInvalidLocations(bg, cutoff, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 3 {
		t.Fatalf("快照应包含 3 个过期位置，实际 %d", len(expired))
	}

	// 快照之后：shared1 恢复为 valid（模拟挂载恢复），shared2 被 PrepareIndex 取代（revision 变化）。
	fpsRec, snapErr := tdb.ListFingerprints(bg)
	if snapErr != nil {
		t.Fatal(snapErr)
	}
	if err := tdb.ConfirmSeenPaths(bg, []TouchAction{{RelativePath: "del/shared1.bin", KnownRevision: fpsRec["del/shared1.bin"].Revision}}, 10, cutoff.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	newRev, err := tdb.PrepareIndex(bg, "del/shared2.bin", 11, cutoff.Add(time.Second), TargetFingerprint{}, true)
	if err != nil {
		t.Fatal(err)
	}

	delTargets := make([]LocationDeleteTarget, 0, len(expired))
	for _, loc := range expired {
		delTargets = append(delTargets, LocationDeleteTarget{RelativePath: loc.RelativePath, Revision: loc.Revision})
	}
	delTargets = append(delTargets, LocationDeleteTarget{RelativePath: "del/ghost.bin", Revision: 1})

	orphanCtx, cancel := context.WithTimeout(bg, time.Second)
	defer cancel()
	orphans, err := tdb.DeleteLocations(bg, delTargets, cutoff)
	if err != nil {
		t.Fatalf("DeleteLocations 失败: %v", err)
	}
	_ = orphanCtx
	if len(orphans) != 1 || orphans[0] != seedSolo {
		t.Errorf("孤儿 Seed 应恰为 [%s]（shared1 恢复仍引用；shared2 引用未变），实际 %v", seedSolo, orphans)
	}
	fpList, err := tdb.ListFingerprints(bg)
	if err != nil {
		t.Fatal(err)
	}
	if fp, ok := fpList["del/shared1.bin"]; !ok || fp.State != LocationValid {
		t.Errorf("快照后恢复的位置不得被 GC 删除，实际 %+v 存在=%v", fp, ok)
	}
	if _, ok := fpList["del/solo.bin"]; ok {
		t.Error("del/solo.bin 应已被删除")
	}
	if _, ok := fpList["del/ghost.bin"]; ok {
		t.Error("不存在的路径应被静默跳过")
	}
	_ = newRev

	// SetLocationFailed 创建的无 seed 占位行：invalid 后可删，但不产生孤儿。
	if err := tdb.SetLocationFailed(bg, "del/failed.tmp", 1, 1, "超过协议最大源文件尺寸", 1); err != nil {
		t.Fatal(err)
	}
	if err := tdb.MarkInvalidNow(bg, "del/failed.tmp", "测试失效", cutoff, 1); err != nil {
		t.Fatal(err)
	}
	orphans, err = tdb.DeleteLocations(bg, []LocationDeleteTarget{{RelativePath: "del/failed.tmp", Revision: 1}}, cutoff)
	if err != nil {
		t.Fatalf("删除占位行失败: %v", err)
	}
	if len(orphans) != 0 {
		t.Errorf("无 seed 占位行不应产生孤儿 Seed，实际 %v", orphans)
	}
}

// TestOrphanContentsAndDeleteContentsCascade 覆盖孤儿清理闭环：
// OrphanContents 只挑出无引用且 updated_at 早于阈值的内容；
// DeleteContents 删除 contents 并级联清掉 seed_blocks。
func TestOrphanContentsAndDeleteContentsCascade(t *testing.T) {
	tdb := newTestDB(t)
	bg := context.Background()

	tO := time.Unix(50000, 0)
	seedOrphan := hexHash('a', 91)
	mustCommit(t, tdb.DB, "orphan/o.bin", seedOrphan, tO, 1, singleBlock(seedOrphan, hexHash('b', 901)))

	fps, err := tdb.ListFingerprints(bg)
	if err != nil {
		t.Fatal(err)
	}
	if err := tdb.MarkInvalidNow(bg, "orphan/o.bin", "测试失效", tO.Add(time.Second), fps["orphan/o.bin"].Revision); err != nil {
		t.Fatal(err)
	}
	orphans, err := tdb.DeleteLocations(bg,
		[]LocationDeleteTarget{{RelativePath: "orphan/o.bin", Revision: fps["orphan/o.bin"].Revision}},
		tO.Add(time.Minute))
	if err != nil || len(orphans) != 1 {
		t.Fatalf("删除唯一位置后应产生孤儿 %s，实际 orphans=%v err=%v", seedOrphan, orphans, err)
	}

	// updated_at=tO：阈值在其之后才计入孤儿。
	orphaned, err := tdb.OrphanContents(bg, tO.Add(time.Second), 100)
	if err != nil {
		t.Fatalf("OrphanContents 失败: %v", err)
	}
	if len(orphaned) != 1 || orphaned[0] != seedOrphan {
		t.Errorf("阈值之后应恰好返回孤儿 %s，实际 %v", seedOrphan, orphaned)
	}
	// 阈值早于 updated_at：不返回。
	orphaned, err = tdb.OrphanContents(bg, tO.Add(-time.Second), 100)
	if err != nil {
		t.Fatalf("OrphanContents 二查失败: %v", err)
	}
	if len(orphaned) != 0 {
		t.Errorf("阈值之前不应有孤儿，实际 %v", orphaned)
	}

	// DeleteContents：外键 ON DELETE CASCADE 清掉 seed_blocks。
	seedKeep := hexHash('a', 92)
	blocks := []SeedBlock{
		{SeedHash: seedKeep, BlockIndex: 0, BlockHash: hexHash('b', 902), OffsetBytes: 0, LengthBytes: 262144},
		{SeedHash: seedKeep, BlockIndex: 1, BlockHash: hexHash('b', 903), OffsetBytes: 262144, LengthBytes: 1000},
	}
	mustCommit(t, tdb.DB, "keep/k.bin", seedKeep, tO, 1, blocks)

	if got := countRows(t, tdb.path, `SELECT count(*) FROM seed_blocks WHERE seed_hash = ?`, seedKeep); got != 2 {
		t.Fatalf("删除前 seed_blocks 应有 2 行，实际 %d", got)
	}
	// 新守卫语义：仍被位置引用的内容必须拒绝删除。
	if err := tdb.DeleteContents(bg, []string{seedKeep}); err != nil {
		t.Fatalf("DeleteContents 不应报错: %v", err)
	}
	if _, err := tdb.GetAvailability(bg, seedKeep); errors.Is(err, ErrNotFound) {
		t.Fatal("仍被位置引用的内容不得被 DeleteContents 删除")
	}
	// 解除唯一位置的引用后再删：级联清空块映射。
	fpsKeep, err := tdb.ListFingerprints(bg)
	if err != nil {
		t.Fatal(err)
	}
	if err := tdb.MarkInvalidNow(bg, "keep/k.bin", "测试失效", tO.Add(time.Minute), fpsKeep["keep/k.bin"].Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := tdb.DeleteLocations(bg,
		[]LocationDeleteTarget{{RelativePath: "keep/k.bin", Revision: fpsKeep["keep/k.bin"].Revision}},
		tO.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := tdb.DeleteContents(bg, []string{seedKeep}); err != nil {
		t.Fatalf("DeleteContents 失败: %v", err)
	}
	if _, err := tdb.GetAvailability(bg, seedKeep); !errors.Is(err, ErrNotFound) {
		t.Errorf("删除后 GetAvailability 应返回 ErrNotFound，实际: %v", err)
	}
	if got := countRows(t, tdb.path, `SELECT count(*) FROM seed_blocks WHERE seed_hash = ?`, seedKeep); got != 0 {
		t.Errorf("级联删除后 seed_blocks 应清空，实际剩 %d 行", got)
	}

	// 孤儿 Seed 本体也可以被 DeleteContents 回收。
	if err := tdb.DeleteContents(bg, []string{seedOrphan}); err != nil {
		t.Fatalf("回收孤儿 Seed 失败: %v", err)
	}
	orphaned, err = tdb.OrphanContents(bg, tO.Add(time.Second), 100)
	if err != nil {
		t.Fatalf("OrphanContents 三查失败: %v", err)
	}
	if len(orphaned) != 0 {
		t.Errorf("回收后不应再有孤儿，实际 %v", orphaned)
	}
}

// ---------- schema fail closed ----------

// TestOpenFailsClosedOnLegacyTables 是最重要的 fail closed 用例：
// 数据库里预先存在旧方向遗留表（clients）时，indexdb.Open 必须以 ErrIncompatibleSchema 拒绝启动，
// 且绝不自动删除或改写旧表。
func TestOpenFailsClosedOnLegacyTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	// 用 database/sql 直连手工布置旧 schema。
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("打开裸连接失败: %v", err)
	}
	if _, err := raw.Exec(`CREATE TABLE clients (
		id INTEGER PRIMARY KEY,
		token TEXT NOT NULL,
		quota_bytes INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		t.Fatalf("创建旧表 clients 失败: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("关闭裸连接失败: %v", err)
	}

	_, err = Open(path)
	if !errors.Is(err, ErrIncompatibleSchema) {
		t.Fatalf("含旧表的库应以 ErrIncompatibleSchema 拒绝启动，实际错误: %v", err)
	}
	if !strings.Contains(err.Error(), "clients") {
		t.Errorf("错误信息应指出具体旧表名，实际: %v", err)
	}

	// 旧表必须原样保留：fail closed 不做任何破坏性操作。
	raw, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("复查裸连接失败: %v", err)
	}
	defer func() { _ = raw.Close() }()
	var name string
	if err := raw.QueryRow(
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'clients'`).Scan(&name); err != nil {
		t.Fatalf("旧表 clients 应原样保留，查询失败: %v", err)
	}
	if name != "clients" {
		t.Errorf("旧表名应为 clients，实际 %q", name)
	}
}

// TestOpenRejectsUnknownSchemaVersion 覆盖版本守卫：
// meta.schema_version 被写成未来版本 "99" 时，Open 必须返回中文版本错误并拒绝启动。
func TestOpenRejectsUnknownSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.db")

	// 先用正常流程建立当前版本的库。
	db, err := Open(path)
	if err != nil {
		t.Fatalf("建立基线数据库失败: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("关闭基线数据库失败: %v", err)
	}

	// 直连把 schema_version 篡改为 "99"，模拟来自未来的不兼容库。
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("打开篡改连接失败: %v", err)
	}
	if _, err := raw.Exec(`UPDATE meta SET value = '99' WHERE key = 'schema_version'`); err != nil {
		t.Fatalf("篡改 schema_version 失败: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("关闭篡改连接失败: %v", err)
	}

	_, err = Open(path)
	if err == nil {
		t.Fatal("schema_version=99 的库应拒绝启动")
	}
	if !strings.Contains(err.Error(), "检测到未知 schema 版本") {
		t.Errorf("应返回中文版本错误，实际: %v", err)
	}
	if !strings.Contains(err.Error(), `"99"`) {
		t.Errorf("错误信息应包含检测到的版本号 \"99\"，实际: %v", err)
	}
}

// TestPrepareIndexMakesContentUnavailableImmediately（阻断 1）：
// PrepareIndex 把位置转为 indexing 并让旧内容立即不可用；
// 重算完成前旧 Seed Hash 不再被 Stat 报告为 available。
func TestPrepareIndexMakesContentUnavailableImmediately(t *testing.T) {
	tdb := newTestDB(t)
	bg := context.Background()

	now := time.Unix(60000, 0)
	seedOld := hexHash('a', 61)
	mustCommit(t, tdb.DB, "cas/file.bin", seedOld, now, 1, singleBlock(seedOld, hexHash('b', 601)))

	avail, err := tdb.GetAvailability(bg, seedOld)
	if err != nil || avail.ValidReplicas != 1 {
		t.Fatalf("提交后应有 1 个 valid 副本: %+v err=%v", avail, err)
	}

	if _, err := tdb.PrepareIndex(bg, "cas/file.bin", 2, now.Add(time.Second),
		TargetFingerprint{SizeBytes: 263168, MtimeNs: now.Add(time.Second).UnixNano()}, true); err != nil {
		t.Fatalf("PrepareIndex 失败: %v", err)
	}
	avail, err = tdb.GetAvailability(bg, seedOld)
	if err != nil {
		t.Fatal(err)
	}
	if avail.Content.State == StateReady && avail.ValidReplicas > 0 {
		t.Fatal("进入重算后旧内容必须立即不可用，不得继续报告 available")
	}
	fps, err := tdb.ListFingerprints(bg)
	if err != nil {
		t.Fatal(err)
	}
	if fp := fps["cas/file.bin"]; fp.State != LocationIndexing {
		t.Fatalf("位置状态应为 indexing，实际 %q", fp.State)
	}
}

// TestCommitSeedResultRevisionCAS（阻断 1 核心竞态）：
// Publish 与 DB commit 之间注入新事件（revision 前进）时，
// 旧任务的提交必须以 ErrRevisionStale 整体失败，绝不覆盖新索引。
func TestCommitSeedResultRevisionCAS(t *testing.T) {
	tdb := newTestDB(t)
	bg := context.Background()

	now := time.Unix(61000, 0)
	path := "cas/race.bin"
	seedA := hexHash('a', 62)

	rev1, err := tdb.PrepareIndex(bg, path, 1, now, TargetFingerprint{SizeBytes: 262144, MtimeNs: now.UnixNano()}, false)
	if err != nil {
		t.Fatal(err)
	}
	blocksA := singleBlock(seedA, hexHash('b', 611))
	err = tdb.CommitSeedResult(bg, CommitParams{
		RelativePath: path, SeedHash: seedA, SeedLength: 32,
		SourceSize: 262144, Filename: "race.bin", MediaType: "application/octet-stream",
		SizeBytes: 262144, MtimeNs: now.UnixNano(), Generation: 1,
		ExpectedRevision: rev1, Blocks: blocksA,
	}, now)
	if err != nil {
		t.Fatalf("首次提交失败: %v", err)
	}

	// 模拟“Publish 之后、Commit 之前”来了新事件：revision 前进。
	rev2, err := tdb.PrepareIndex(bg, path, 2, now.Add(time.Second),
		TargetFingerprint{SizeBytes: 524288, MtimeNs: now.Add(time.Second).UnixNano()}, false)
	if err != nil {
		t.Fatal(err)
	}
	if rev2 <= rev1 {
		t.Fatalf("revision 必须前进：rev2=%d rev1=%d", rev2, rev1)
	}

	seedB := hexHash('a', 63)
	err = tdb.CommitSeedResult(bg, CommitParams{
		RelativePath: path, SeedHash: seedB, SeedLength: 32,
		SourceSize: 524288, Filename: "race.bin", MediaType: "application/octet-stream",
		SizeBytes: 524288, MtimeNs: now.Add(time.Second).UnixNano(), Generation: 0,
		ExpectedRevision: rev1, Blocks: blocksA, // 旧任务拿着旧 revision 提交
	}, now.Add(time.Second))
	if !errors.Is(err, ErrRevisionStale) {
		t.Fatalf("旧 revision 提交必须返回 ErrRevisionStale，实际: %v", err)
	}

	// 整体回滚：contents 中不得出现 seedB 半提交。
	if _, err := tdb.GetAvailability(bg, seedB); !errors.Is(err, ErrNotFound) {
		t.Errorf("CAS 失败的提交不得留下 contents 行，实际查询错误: %v", err)
	}

	// 新任务以 rev2 提交成功。
	err = tdb.CommitSeedResult(bg, CommitParams{
		RelativePath: path, SeedHash: seedB, SeedLength: 32,
		SourceSize: 524288, Filename: "race.bin", MediaType: "application/octet-stream",
		SizeBytes: 524288, MtimeNs: now.Add(time.Second).UnixNano(), Generation: 2,
		ExpectedRevision: rev2,
		Blocks:           singleBlock(seedB, hexHash('b', 612)),
	}, now.Add(time.Second))
	if err != nil {
		t.Fatalf("新任务提交失败: %v", err)
	}
	fpList, _ := tdb.ListFingerprints(bg)
	if fp := fpList[path]; fp.SeedHash != seedB || fp.State != LocationValid {
		t.Fatalf("新任务结果应生效：%+v", fp)
	}
}

// TestFilterUnreferenced：FilterUnreferenced 只返回当前无任何位置引用的 hash。
func TestFilterUnreferenced(t *testing.T) {
	tdb := newTestDB(t)
	bg := context.Background()
	now := time.Unix(62000, 0)
	seedRef := hexHash('a', 64)
	seedFree := hexHash('a', 65)
	mustCommit(t, tdb.DB, "f/keep.bin", seedRef, now, 1, singleBlock(seedRef, hexHash('b', 621)))

	out, err := tdb.FilterUnreferenced(bg, []string{seedRef, seedFree})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0] != seedFree {
		t.Fatalf("应只返回无引用的 %s，实际 %v", seedFree, out)
	}
}
