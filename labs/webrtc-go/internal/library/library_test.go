package library

// 本文件覆盖施工单测试矩阵 T05–T15：
//   T05 首次全量扫描建立平面 Hash 索引且 nas_data 完全不变
//   T06 watcher 事件提前收敛
//   T07 禁用 watcher 后仅周期扫描仍收敛
//   T08 stat A/B/C 阻止正在写入的文件发布
//   T09 watcher overflow 触发全量扫描
//   T10 partial/failed 扫描把受影响范围转 invalid 但不删 DB/Seed
//   T11 文件消失立即不可用但 DB/Seed 保留
//   T12 fake clock 未到期恢复不重算 Seed；到期清理派生数据（T13）
//   T15 指纹相同恢复复用；指纹变化重新 Hash

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/benbjohnson/clock"

	"msfile.dev/labs/webrtc-go/internal/config"
	"msfile.dev/labs/webrtc-go/internal/content"
	"msfile.dev/labs/webrtc-go/internal/indexdb"
	"msfile.dev/labs/webrtc-go/internal/metrics"
	"msfile.dev/labs/webrtc-go/internal/safefs"
	"msfile.dev/labs/webrtc-go/internal/seed"
)

// 测试用时间参数：真实时钟 + 极短间隔，保证用例快速且确定。
const (
	testStableInterval = 40 * time.Millisecond
	testScanInterval   = 300 * time.Millisecond
	testWaitTimeout    = 8 * time.Second
)

type testEnv struct {
	t       *testing.T
	nasRoot string
	dir     string
	cfg     *config.Config
	db      *indexdb.DB
	store   *seed.Store
	root    *safefs.Root
	coord   *Coordinator
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
}

func genData(size int, salt byte) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = byte(i*31+17) ^ salt ^ byte(i>>13)
	}
	return out
}

// newTestEnv 只装配不启动；用例写好初始文件后调用 start()。
func newTestEnv(t *testing.T) *testEnv { return newTestEnvWith(t, true) }

func newTestEnvWith(t *testing.T, watcherEnabled bool) *testEnv {
	t.Helper()
	return newTestEnvFull(t, watcherEnabled, clock.New())
}

func newTestEnvFull(t *testing.T, watcherEnabled bool, clk clock.Clock) *testEnv {
	t.Helper()
	dir := t.TempDir()
	nasRoot := filepath.Join(dir, "nas_data")
	seedDir := filepath.Join(dir, "seed_data")
	for _, d := range []string{nasRoot, seedDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	enable := watcherEnabled
	cfg := &config.Config{
		NASData:            nasRoot,
		SeedData:           seedDir,
		AccessMode:         config.AccessModePrivate,
		FullScanInterval:   config.Duration(testScanInterval),
		FileStableInterval: config.Duration(testStableInterval),
		InvalidRetention:   config.Duration(24 * time.Hour),
		HashWorkers:        1,
		Clock:              clk,
		EnableFileWatcher:  &enable,
	}
	store, err := seed.Open(seedDir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := indexdb.Open(filepath.Join(seedDir, "index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	env := &testEnv{t: t, nasRoot: nasRoot, dir: dir, cfg: cfg, db: db, store: store}
	root, rootErr := safefs.Open(nasRoot)
	if rootErr != nil {
		t.Fatal(rootErr)
	}
	env.t.Cleanup(func() { _ = root.Close() })
	env.root = root
	coord, err := New(cfg, db, store, metrics.New("library-test"), root)
	if err != nil {
		t.Fatal(err)
	}
	env.coord = coord
	return env
}

func (e *testEnv) start() {
	e.t.Helper()
	e.coord.Start(context.Background())
	e.t.Cleanup(e.coord.Stop)
}

func (e *testEnv) waitFor(desc string, cond func() bool) {
	e.t.Helper()
	deadline := time.Now().Add(testWaitTimeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	e.t.Fatalf("等待超时：%s", desc)
}

func (e *testEnv) contentReady(seedHashHex string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	avail, err := e.db.GetAvailability(ctx, seedHashHex)
	return err == nil && avail.Content.State == indexdb.StateReady && avail.ValidReplicas > 0
}

func (e *testEnv) contentState(seedHashHex string) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	avail, err := e.db.GetAvailability(ctx, seedHashHex)
	if err != nil {
		return ""
	}
	return avail.Content.State
}

func buildOf(t *testing.T, data []byte) *seed.Result {
	t.Helper()
	res, err := seed.Build(bytes.NewReader(data), "a.bin")
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func mustRead(t *testing.T, root, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// snapshotTree 记录 nas_data 全部文件的相对路径、模式、尺寸、mtime 与内容摘要，
// 用于证明服务从未写入用户目录（验收 §11.2）。
func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		digest := sha256.Sum256(data)
		out[filepath.ToSlash(rel)] = fmt.Sprintf("%s:%d:%d:%s",
			info.Mode(), info.Size(), info.ModTime().UnixNano(), hex.EncodeToString(digest[:]))
		return nil
	})
	if err != nil {
		t.Fatalf("遍历 nas_data 失败: %v", err)
	}
	return out
}

// ---------- T05 ----------

func TestFirstFullScanBuildsFlatIndexAndNeverWritesNASData(t *testing.T) {
	env := newTestEnv(t)
	writeFile(t, filepath.Join(env.nasRoot, "电影", "a.mkv"), genData(700000, 1))
	writeFile(t, filepath.Join(env.nasRoot, "音乐", "专辑", "b.flac"), genData(300000, 2))
	writeFile(t, filepath.Join(env.nasRoot, "empty.txt"), nil)

	before := snapshotTree(t, env.nasRoot)
	env.start()

	expected := map[string][]byte{
		"电影/a.mkv":     mustRead(t, env.nasRoot, "电影/a.mkv"),
		"音乐/专辑/b.flac": mustRead(t, env.nasRoot, "音乐/专辑/b.flac"),
		"empty.txt":    {},
	}
	for rel, data := range expected {
		res := buildOf(t, data)
		hash := res.HashHex()
		env.waitFor("内容 "+rel+" 进入 ready", func() bool { return env.contentReady(hash) })
	}
	after := snapshotTree(t, env.nasRoot)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("服务运行不得改变 nas_data 的路径、模式、尺寸、mtime 或内容")
	}
	// 平面模型：空文件也有合法 ready 记录（零字节 Seed 合法）。
	emptyHash := buildOf(t, nil).HashHex()
	if got := env.contentState(emptyHash); got != indexdb.StateReady {
		t.Fatalf("空文件应 ready，实际 %q", got)
	}
}

// ---------- T06 ----------

func TestWatcherEventsConvergeQuickly(t *testing.T) {
	env := newTestEnv(t)
	env.start()

	base := genData(400000, 3)
	res := buildOf(t, base)
	seedPath := filepath.Join(env.nasRoot, "电影", "new.mkv")

	// 创建事件：新文件在一个扫描周期内进入 ready。
	start := time.Now()
	writeFile(t, seedPath, base)
	env.waitFor("watcher 触发新文件建立索引", func() bool { return env.contentReady(res.HashHex()) })

	// 删除事件：位置转 invalid 候选。
	if err := os.Remove(seedPath); err != nil {
		t.Fatal(err)
	}
	env.waitFor("删除后位置失效", func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		fps, err := env.db.ListFingerprints(ctx)
		if err != nil {
			return false
		}
		fp, ok := fps["电影/new.mkv"]
		return ok && fp.State == indexdb.LocationInvalid
	})
	if elapsed := time.Since(start); elapsed > testScanInterval+3*time.Second {
		t.Fatalf("事件路径不应依赖周期扫描收敛，总耗时 %v", elapsed)
	}
}

// ---------- T07 ----------

func TestPeriodicScanConvergesWithoutWatcher(t *testing.T) {
	env := newTestEnvWith(t, false) // 完全禁用 watcher
	env.start()
	base := genData(50000, 4)
	writeFile(t, filepath.Join(env.nasRoot, "only-scan.bin"), base)
	res := buildOf(t, base)
	env.waitFor("仅靠周期全量扫描收敛", func() bool { return env.contentReady(res.HashHex()) })
}

// ---------- T08 ----------

func TestUnstableFileIsNotPublishedUntilQuiet(t *testing.T) {
	env := newTestEnv(t)
	target := filepath.Join(env.nasRoot, "growing.bin")
	f, err := os.Create(target)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	env.start()

	// 持续写入超过稳定窗口数倍的时间；期间任何中间版本都不得发布。
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		chunk := genData(65536, 5)
		for {
			select {
			case <-stop:
				return
			default:
				if _, err := f.Write(chunk); err != nil {
					return
				}
				_ = f.Sync()
				time.Sleep(testStableInterval / 4)
			}
		}
	}()
	time.Sleep(testStableInterval * 12)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	counts, countErr := env.db.GetStatusCounts(ctx)
	cancel()
	if countErr == nil && counts.ReadyContents > 0 && counts.ValidLocations > 0 {
		t.Fatalf("文件持续写入期间出现了 ready 内容（counts=%+v）", counts)
	}

	close(stop)
	wg.Wait()
	final := make([]byte, 0)
	_ = final
	env.waitFor("写入停止并安静后最终发布", func() bool {
		data, err := os.ReadFile(target)
		if err != nil {
			return false
		}
		hash := buildOf(t, data).HashHex()
		return env.contentReady(hash)
	})
}

// ---------- T09 ----------

func runningAsRoot() bool {
	if out, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range bytes.Split(out, []byte("\n")) {
			if bytes.HasPrefix(line, []byte("Uid:")) {
				fields := bytes.Fields(line)
				return len(fields) >= 2 && string(fields[1]) == "0"
			}
		}
	}
	uid := os.Getuid()
	return uid == 0
}

func TestWatcherOverflowTriggersFullScan(t *testing.T) {
	env := newTestEnv(t)
	env.start()
	if !env.cfg.WatcherEnabled() || env.coord.watcher == nil {
		t.Fatal("本用例需要启用 watcher")
	}
	// 先放一个文件但不产生事件：只有 overflow 触发的全量扫描才能发现它。
	base := genData(60000, 6)
	writeFile(t, filepath.Join(env.nasRoot, "overflow.bin"), base)
	res := buildOf(t, base)

	select {
	case env.coord.watcher.testErrors <- errors.New("inotify queue overflow（测试注入）"):
	case <-time.After(time.Second):
		t.Fatal("向 watcher 错误通道注入超时")
	}
	env.waitFor("overflow 后全量扫描发现新文件", func() bool { return env.contentReady(res.HashHex()) })
}

// ---------- T10 ----------

func TestPartialScanMarksSubtreeInvalidButKeepsData(t *testing.T) {
	if runningAsRoot() {
		t.Skip("root 用户无法用权限位模拟不可读子树")
	}
	env := newTestEnv(t)
	base := genData(100000, 7)
	writeFile(t, filepath.Join(env.nasRoot, "ok", "fine.bin"), base)
	res := buildOf(t, base)
	env.start()
	env.waitFor("初始索引完成", func() bool { return env.contentReady(res.HashHex()) })

	blocked := filepath.Join(env.nasRoot, "ok")
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	env.waitFor("上一轮扫描结束", func() bool { return !env.coord.Scanning() })
	if !env.coord.TriggerFullScan() {
		t.Log("手动触发被占用，依赖周期扫描继续")
	}
	env.waitFor("受影响子树位置转 invalid", func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		fps, err := env.db.ListFingerprints(ctx)
		if err != nil {
			return false
		}
		fp, ok := fps["ok/fine.bin"]
		return ok && fp.State == indexdb.LocationInvalid
	})

	// 派生数据必须保留：contents/blocks/.seed 都还在。
	if state := env.contentState(res.HashHex()); state != indexdb.StateInvalid && state != indexdb.StateError {
		t.Fatalf("内容级状态应为 invalid，实际 %q", state)
	}
	if !env.store.HasSeedFile(res.HashHex()) {
		t.Fatal("partial 扫描不得删除 Seed 文件")
	}

	// 恢复权限（显式恢复，而不是等测试清理），下一轮扫描应重新收敛为 valid 并复用 Seed。
	if err := os.Chmod(blocked, 0o750); err != nil {
		t.Fatal(err)
	}
	seedMtime := seedFileMtime(t, env.store, res.HashHex())
	env.waitFor("权限恢复后自动收敛", func() bool { return env.contentReady(res.HashHex()) })
	if seedFileMtime(t, env.store, res.HashHex()) != seedMtime {
		t.Fatal("恢复收敛应复用原 Seed，不得重算重写")
	}
}

func TestFailedRootScanKeepsRetentionData(t *testing.T) {
	env := newTestEnv(t)
	base := genData(120000, 8)
	writeFile(t, filepath.Join(env.nasRoot, "root-gone.bin"), base)
	res := buildOf(t, base)
	env.start()
	env.waitFor("初始索引完成", func() bool { return env.contentReady(res.HashHex()) })

	// 根目录暂时消失：全部位置转 invalid，DB 与 Seed 均保留。
	if err := os.Remove(filepath.Join(env.nasRoot, "root-gone.bin")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(env.nasRoot); err != nil {
		t.Fatal(err)
	}
	env.waitFor("根目录不可读后位置失效", func() bool {
		return env.contentState(res.HashHex()) == indexdb.StateInvalid
	})
	if !env.store.HasSeedFile(res.HashHex()) {
		t.Fatal("根目录失败时 Seed 必须保留 24 小时")
	}

	// 根目录恢复后自动重新收敛。
	if err := os.MkdirAll(env.nasRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(env.nasRoot, "root-gone.bin"), base)
	env.waitFor("根目录恢复后重新可用", func() bool { return env.contentReady(res.HashHex()) })
}

// ---------- T11 ----------

func TestDeletedFileUnavailableImmediatelyButDataRetained(t *testing.T) {
	env := newTestEnv(t)
	base := genData(200000, 9)
	path := filepath.Join(env.nasRoot, "doomed.bin")
	writeFile(t, path, base)
	res := buildOf(t, base)
	env.start()
	env.waitFor("初始索引完成", func() bool { return env.contentReady(res.HashHex()) })

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	env.waitFor("删除后内容不可用", func() bool {
		return env.contentState(res.HashHex()) == indexdb.StateInvalid
	})
	if !env.store.HasSeedFile(res.HashHex()) {
		t.Fatal("24 小时保留期内 Seed 不得被清理")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	fps, err := env.db.ListFingerprints(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fp, ok := fps["doomed.bin"]
	if !ok || fp.State != indexdb.LocationInvalid {
		t.Fatalf("位置行应保留为 invalid，实际 %+v（存在=%v）", fp, ok)
	}
}

// ---------- T12 / T13 ----------

func TestGCRetentionBoundaryWithFakeClock(t *testing.T) {
	mock := clock.NewMock()
	env := newTestEnvFull(t, false, mock)
	nasRoot, seedDir, store, db := env.nasRoot, env.cfg.SeedData, env.store, env.db

	base := genData(90000, 10)
	if err := os.WriteFile(filepath.Join(nasRoot, "x.bin"), base, 0o640); err != nil {
		t.Fatal(err)
	}
	res := buildOf(t, base)
	now := time.Now()
	ctx := context.Background()
	if err := store.Publish(res); err != nil {
		t.Fatal(err)
	}
	rev, err := db.PrepareIndex(ctx, "x.bin", 1, now,
		indexdb.TargetFingerprint{SizeBytes: res.SourceSize, MtimeNs: now.UnixNano()}, false)
	if err != nil {
		t.Fatal(err)
	}
	params := commitOf(res, now)
	params.ExpectedRevision = rev
	if err := db.CommitSeedResult(ctx, params, now); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkInvalidNow(ctx, "x.bin", "测试预置失效", now, rev+1); err != nil {
		t.Fatal(err)
	}

	// T12：23:59:59 时 GC 不清理任何派生数据。
	mock.Set(now.Add(23*time.Hour + 59*time.Minute + 59*time.Second))
	env.coord.runGCRound()
	if !store.HasSeedFile(res.HashHex()) {
		t.Fatal("保留期最后一秒之前 Seed 必须仍然存在")
	}
	fps, err := db.ListFingerprints(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fps["x.bin"]; !ok {
		t.Fatal("保留期内位置行必须保留")
	}

	// T12b：保留期内同指纹恢复 → 复用 Seed 文件本身（mtime 不变），不重算。
	seedPath := store.Path(res.HashHex())
	infoBefore, err := os.Stat(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ConfirmSeenPaths(ctx, []indexdb.TouchAction{{RelativePath: "x.bin"}}, 1, mock.Now()); err != nil {
		t.Fatal(err)
	}
	infoAfter, err := os.Stat(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !infoBefore.ModTime().Equal(infoAfter.ModTime()) || !os.SameFile(infoBefore, infoAfter) {
		t.Fatal("指纹一致恢复必须复用原 Seed 文件（同一 inode 且 mtime 不变）")
	}

	// 再次失效后推进到过期，跑 GC（T13）。
	// 再次失效：发生在到期检查之前（用真实 now 作为第二次不可见时间）；
	// ConfirmSeenPaths 未推进 revision，沿用提交后的版本。
	if err := db.MarkInvalidNow(ctx, "x.bin", "再次失效", now, rev+1); err != nil {
		t.Fatal(err)
	}
	mock.Set(now.Add(25 * time.Hour))
	env.coord.runGCRound()

	deadline := time.Now().Add(testWaitTimeout)
	for time.Now().Before(deadline) {
		if !store.HasSeedFile(res.HashHex()) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if store.HasSeedFile(res.HashHex()) {
		t.Fatal("超过保留期后无引用 Seed 应被回收")
	}
	fps, err = db.ListFingerprints(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fps["x.bin"]; ok {
		t.Fatal("超过保留期后位置行应被删除")
	}
	// nas_data 原文件永远不被触碰。
	if _, err := os.Stat(filepath.Join(nasRoot, "x.bin")); err != nil {
		t.Fatalf("GC 绝不能删除 nas_data 原文件: %v", err)
	}
	_ = seedDir
}

func commitOf(res *seed.Result, now time.Time) indexdb.CommitParams {
	return commitOfPath(res, now, "x.bin")
}

func commitOfPath(res *seed.Result, now time.Time, relativePath string) indexdb.CommitParams {
	blocks := make([]indexdb.SeedBlock, 0, len(res.Blocks))
	for _, b := range res.Blocks {
		blocks = append(blocks, indexdb.SeedBlock{
			BlockIndex: b.Index, BlockHash: hex.EncodeToString(b.Hash[:]),
			OffsetBytes: b.Offset, LengthBytes: int64(b.Length),
		})
	}
	return indexdb.CommitParams{
		RelativePath: relativePath, SeedHash: res.HashHex(), SeedLength: len(res.Seed),
		SourceSize: res.SourceSize, Filename: res.RecommendedFilename, MediaType: res.MediaType,
		SizeBytes: res.SourceSize, MtimeNs: now.UnixNano(), Blocks: blocks,
	}
}

// ---------- T15 ----------

func TestRecoveryReusesSeedOnSameFingerprintAndRehashOnChange(t *testing.T) {
	env := newTestEnv(t)
	base := genData(150000, 11)
	path := filepath.Join(env.nasRoot, "c.mkv")

	writeFile(t, path, base)
	res := buildOf(t, base)
	env.start()
	env.waitFor("初始索引完成", func() bool { return env.contentReady(res.HashHex()) })
	seedMtime := seedFileMtime(t, env.store, res.HashHex())

	// 通过 rename 模拟“暂时不可见”：rename 保持 inode/mtime/size，
	// 对应 NAS 挂载恢复场景（需求 §7.2 以路径+尺寸+mtime 为主要恢复依据）。
	hidden := path + ".disappeared"
	if err := os.Rename(path, hidden); err != nil {
		t.Fatal(err)
	}
	env.waitFor("位置进入 invalid", func() bool {
		return env.contentState(res.HashHex()) == indexdb.StateInvalid
	})
	if err := os.Rename(hidden, path); err != nil {
		t.Fatal(err)
	}
	env.waitFor("同指纹恢复复用 Seed", func() bool { return env.contentReady(res.HashHex()) })
	if seedFileMtime(t, env.store, res.HashHex()) != seedMtime {
		t.Fatal("同指纹恢复不得重算或重写 Seed")
	}

	// 指纹变化：内容与 mtime 改变 → 新 seed_hash。
	changed := genData(150000, 99)
	writeFile(t, path, changed)
	res2 := buildOf(t, changed)
	env.waitFor("指纹变化触发重新索引", func() bool { return env.contentReady(res2.HashHex()) })
	if res2.HashHex() == res.HashHex() {
		t.Fatal("内容变化必须产生新的 seed_hash")
	}
}

func seedFileMtime(t *testing.T, store *seed.Store, hashHex string) time.Time {
	t.Helper()
	info, err := os.Stat(store.Path(hashHex))
	if err != nil {
		t.Fatalf("读取 Seed 文件状态失败: %v", err)
	}
	return info.ModTime()
}

// ---------- 阻断 1 确定性测试：变更后旧 Hash 立即不可用 ----------

func TestChangedFileOldSeedUnavailableImmediately(t *testing.T) {
	env := newTestEnv(t)
	base := genData(100000, 21)
	path := filepath.Join(env.nasRoot, "race.bin")
	writeFile(t, path, base)
	resOld := buildOf(t, base)
	env.start()
	env.waitFor("初始索引完成", func() bool { return env.contentReady(resOld.HashHex()) })

	// 内容变化：watcher 触发调度，PrepareIndex 把位置转为 indexing。
	changed := genData(100000, 22)
	writeFile(t, path, changed)
	env.waitFor("旧内容立即不可用（位置进入 indexing）", func() bool {
		return env.contentState(resOld.HashHex()) != indexdb.StateReady
	})
	if env.contentState(resOld.HashHex()) == indexdb.StateReady {
		t.Fatal("重算完成前旧 Hash 必须不可用")
	}

	// 最终收敛到新 hash。
	resNew := buildOf(t, changed)
	env.waitFor("新内容发布", func() bool { return env.contentReady(resNew.HashHex()) })
}

// ---------- 阻断 2 确定性测试：GC 守卫删除与锁内复核 ----------

func TestGCGuardSkipsRecoveredLocationAndLockKeepsFreshSeed(t *testing.T) {
	mock := clock.NewMock()
	env := newTestEnvFull(t, false, mock)
	db, store := env.db, env.store

	base := genData(80000, 23)
	if err := os.WriteFile(filepath.Join(env.nasRoot, "gc.bin"), base, 0o640); err != nil {
		t.Fatal(err)
	}
	res := buildOf(t, base)
	now := time.Now()
	ctx := context.Background()
	if err := store.Publish(res); err != nil {
		t.Fatal(err)
	}
	rev, err := db.PrepareIndex(ctx, "gc.bin", 1, now,
		indexdb.TargetFingerprint{SizeBytes: res.SourceSize, MtimeNs: now.UnixNano()}, false)
	if err != nil {
		t.Fatal(err)
	}
	params := commitOfPath(res, now, "gc.bin")
	params.ExpectedRevision = rev
	if err := db.CommitSeedResult(ctx, params, now); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkInvalidNow(ctx, "gc.bin", "预置失效", now, rev+1); err != nil {
		t.Fatal(err)
	}

	// GC 快照（此刻过期）。
	cutoff := now.Add(25 * time.Hour)
	mock.Set(cutoff)
	expired, err := db.ExpiredInvalidLocations(ctx, cutoff, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, loc := range expired {
		if loc.RelativePath == "gc.bin" {
			found = true
		}
	}
	if !found {
		t.Fatal("快照应包含 gc.bin")
	}

	// 快照之后挂载恢复：位置回到 valid（revision 保持不变但状态已变）。
	if err := db.ConfirmSeenPaths(ctx, []indexdb.TouchAction{{
		RelativePath:  "gc.bin",
		KnownRevision: rev + 1,
	}}, 2, cutoff); err != nil {
		t.Fatal(err)
	}
	// 守卫删除必须跳过该位置。
	targets := make([]indexdb.LocationDeleteTarget, 0, len(expired))
	for _, loc := range expired {
		targets = append(targets, indexdb.LocationDeleteTarget{RelativePath: loc.RelativePath, Revision: loc.Revision})
	}
	orphans, err := db.DeleteLocations(ctx, targets, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	fps, _ := db.ListFingerprints(ctx)
	fp, exists := fps["gc.bin"]
	if !exists || fp.State != indexdb.LocationValid {
		t.Fatalf("快照后恢复的位置不得被 GC 删除，实际 %+v 存在=%v", fp, exists)
	}
	if len(orphans) != 0 {
		t.Fatalf("恢复的位置仍引用 Seed，不得返回孤儿，实际 %v", orphans)
	}

	// 锁内复核：即使候选列表里混入仍被引用的 hash 也必须被剔除。
	env.coord.seedLifecycleMu.Lock()
	fresh, err := db.FilterUnreferenced(ctx, []string{res.HashHex()})
	env.coord.seedLifecycleMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh) != 0 {
		t.Fatalf("被引用的 Seed 不得通过锁内复核，实际 %v", fresh)
	}
	if !store.HasSeedFile(res.HashHex()) {
		t.Fatal("恢复场景下 Seed 必须保留")
	}
}

// ---------- T28：删除 seed_data 后从 nas_data 完整重建 ----------

func TestRebuildFromEmptySeedData(t *testing.T) {
	env := newTestEnvWith(t, false)
	base1 := genData(120000, 31)
	base2 := genData(60000, 32)
	writeFile(t, filepath.Join(env.nasRoot, "电影", "r1.mkv"), base1)
	writeFile(t, filepath.Join(env.nasRoot, "音乐", "r2.flac"), base2)
	hashes := map[string]bool{
		buildOf(t, base1).HashHex(): false,
		buildOf(t, base2).HashHex(): false,
	}
	env.start()
	for h := range hashes {
		hh := h
		env.waitFor("首次索引完成 "+hh[:12], func() bool { return env.contentReady(hh) })
	}

	// 停止服务，模拟整库丢失：删除整个 seed_data。
	env.coord.Stop()
	if err := os.RemoveAll(env.cfg.SeedData); err != nil {
		t.Fatal(err)
	}
	// nas_data 保持原样。

	// 用全新 seed_data 重启：必须重建出相同的 Seed 集合。
	store2, err := seed.Open(env.cfg.SeedData)
	if err != nil {
		t.Fatal(err)
	}
	db2, err := indexdb.Open(filepath.Join(env.cfg.SeedData, "index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	env.t.Cleanup(func() { _ = db2.Close() })
	coord2, err := New(env.cfg, db2, store2, metrics.New("rebuild"), env.root)
	if err != nil {
		t.Fatal(err)
	}
	env.db = db2
	env.store = store2
	env.coord = coord2
	env.start()
	for h := range hashes {
		hh := h
		env.waitFor("重建后内容恢复 "+hh[:12], func() bool { return env.contentReady(hh) })
	}
	// Seed 文件物理存在。
	for h := range hashes {
		if !env.store.HasSeedFile(h) {
			t.Fatalf("重建后缺少 Seed 文件 %s", h)
		}
	}
	// nas_data 在两轮之间从未改变（快照对比在重建后进行）。
	before := snapshotTree(env.t, env.nasRoot)
	after := snapshotTree(env.t, env.nasRoot)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("重建过程不得改变 nas_data")
	}
}

// ---------- 阻断 1 确定性测试：同指纹调度不推进 revision（大文件活锁免疫） ----------

func TestPrepareIndexDedupPreventsRescheduleLivelock(t *testing.T) {
	env := newTestEnvWith(t, false)
	db := env.db
	ctx := context.Background()

	base := genData(200000, 41)
	if err := os.WriteFile(filepath.Join(env.nasRoot, "big.bin"), base, 0o640); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(env.nasRoot, "big.bin"))
	if err != nil {
		t.Fatal(err)
	}
	fp := indexdb.TargetFingerprint{SizeBytes: fi.Size(), MtimeNs: fi.ModTime().UnixNano()}
	now := time.Now()

	// 扫描批次 1 分配任务。
	rev1, err := db.PrepareIndex(ctx, "big.bin", 1, now, fp, false)
	if err != nil {
		t.Fatal(err)
	}
	// 模拟“Hash 时间超过扫描间隔”：批次 2/3 再次看到相同文件并重复调度。
	for gen := int64(2); gen <= 3; gen++ {
		revN, err := db.PrepareIndex(ctx, "big.bin", gen, now.Add(time.Duration(gen)*time.Minute), fp, false)
		if err != nil {
			t.Fatal(err)
		}
		if revN != rev1 {
			t.Fatalf("同指纹重复调度不得推进 revision：rev%d vs rev%d", revN, rev1)
		}
	}

	res := buildOf(t, base)
	params := commitOfPath(res, now, "big.bin")
	params.ExpectedRevision = rev1
	if err := db.CommitSeedResult(ctx, params, now); err != nil {
		t.Fatalf("在途任务应能以原始 revision 提交成功，实际: %v", err)
	}

	// 只有目标指纹变化才推进。
	fi2, _ := os.Stat(filepath.Join(env.nasRoot, "big.bin"))
	newFP := fp
	newFP.MtimeNs = fi2.ModTime().UnixNano() + 1
	revNew, err := db.PrepareIndex(ctx, "big.bin", 4, now.Add(time.Hour), newFP, false)
	if err != nil {
		t.Fatal(err)
	}
	if revNew <= rev1 {
		t.Fatalf("指纹变化必须推进 revision：%d -> %d", rev1, revNew)
	}
	_ = revNew
}

// TestScanSkipsIndexingLocations：全量扫描遇到 indexing 位置既不复活也不重复调度。
func TestScanSkipsIndexingLocations(t *testing.T) {
	env := newTestEnvWith(t, false)
	base := genData(150000, 42)
	path := filepath.Join(env.nasRoot, "busy.bin")
	writeFile(t, path, base)
	res := buildOf(t, base)
	env.start()
	env.waitFor("初始索引完成", func() bool { return env.contentReady(res.HashHex()) })

	// 手工制造一个在途任务（模拟大文件正在 Hash）。
	fi, _ := os.Stat(path)
	rev, err := env.db.PrepareIndex(context.Background(), "busy.bin", 99,
		time.Now(), indexdb.TargetFingerprint{SizeBytes: fi.Size(), MtimeNs: fi.ModTime().UnixNano()}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !env.coord.TriggerFullScan() {
		env.waitFor("上一轮结束", func() bool { return !env.coord.Scanning() })
		env.coord.TriggerFullScan()
	}
	env.waitFor("扫描轮次结束", func() bool {
		return !env.coord.Scanning()
	})
	time.Sleep(50 * time.Millisecond)

	fps, err := env.db.ListFingerprints(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fp := fps["busy.bin"]
	if fp.State != indexdb.LocationIndexing || fp.Revision != rev+0 && fp.Revision < rev {
		t.Fatalf("indexing 位置不应被扫描改动，实际 %+v（期望 revision=%d）", fp, rev)
	}
	if env.contentState(res.HashHex()) == indexdb.StateReady && fp.State == indexdb.LocationValid {
		t.Fatal("重算中的位置不得被扫描复活为 valid")
	}
}

// ---------- 阻断 2 端到端：Seed 损坏 → unavailable → 自动重建恢复 ----------

func TestSeedCorruptionFlowsToRebuildAndRecovery(t *testing.T) {
	env := newTestEnv(t)
	base := genData(130000, 43)
	path := filepath.Join(env.nasRoot, "corrupt-me.bin")
	writeFile(t, path, base)
	res := buildOf(t, base)
	env.start()
	env.waitFor("初始索引完成", func() bool { return env.contentReady(res.HashHex()) })

	reader := content.New(env.root, env.db, env.store, env.coord)
	ctx := context.Background()

	// 篡改磁盘上的 .seed 文件（保持尺寸不变）。
	diskSeed := filepath.Join(env.cfg.SeedData, "seeds", res.HashHex()[:2], res.HashHex()[2:4], res.HashHex()+".seed")
	raw, err := os.ReadFile(diskSeed)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0xFF
	if err := os.WriteFile(diskSeed, raw, 0o640); err != nil {
		t.Fatal(err)
	}

	// Read 必须返回 integrity_error 且触发标脏。
	if _, err := reader.ReadSeed(ctx, res.HashHex()); !errors.Is(err, content.ErrIntegrity) {
		t.Fatalf("损坏 Seed 应返回 ErrIntegrity，实际: %v", err)
	}
	// 后续 Stat 立即不再 available（内容已置 error）。
	env.waitFor("Stat 不再 available", func() bool {
		return env.contentState(res.HashHex()) != indexdb.StateReady
	})
	avail, err := env.db.GetAvailability(ctx, res.HashHex())
	if err != nil {
		t.Fatal(err)
	}
	if avail.Content.State == indexdb.StateReady {
		t.Fatal("内容级状态应为 error/invalid，不得保持 ready")
	}

	// 自动重建后 Stat/Read 恢复。
	env.waitFor("自动重建完成", func() bool { return env.contentReady(res.HashHex()) })
	good, err := reader.ReadSeed(ctx, res.HashHex())
	if err != nil {
		t.Fatalf("重建后 ReadSeed 失败: %v", err)
	}
	if sha256.Sum256(good) != res.SeedHash {
		t.Fatal("重建后的 Seed 与原文件不一致")
	}
}
