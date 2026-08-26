// Package library 实现冻结需求 §6 的文件同步模型：
//
//	文件事件用于快速发现
//	周期性全量扫描负责最终一致性
//	nas_data 是真值
//	SQLite 和 Seed 都是派生索引
//
// Coordinator 是唯一入口：统一 path revision、Hash 队列、提交与生命周期。
// watcher 与 scanner 都只通过 SchedulePath 提交任务，绝不各自写索引，避免竞态。
package library

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/benbjohnson/clock"

	"msfile.dev/labs/webrtc-go/internal/config"
	"msfile.dev/labs/webrtc-go/internal/indexdb"
	"msfile.dev/labs/webrtc-go/internal/metrics"
	"msfile.dev/labs/webrtc-go/internal/safefs"
	"msfile.dev/labs/webrtc-go/internal/seed"
)

// maxAttempts 是同一路径连续失败的重试上限；
// 达到后保留 error 状态，等待下一次文件事件或全量扫描再重置。
const maxAttempts = 5

// maxPendingPaths 是待处理路径队列上限；满载时不再排队并触发全量扫描兜底（背压）。
const maxPendingPaths = 10000

var (
	// ErrScanInProgress 表示已有一轮全量扫描在执行。
	ErrScanInProgress = errors.New("全量扫描正在进行中")
)

// atomicBool 是基于 sync/atomic 的布尔标志；scanning 标志会被多个 goroutine 并发读写。
type atomicBool struct{ v atomic.Int32 }

func (a *atomicBool) Store(v bool) {
	if v {
		a.v.Store(1)
	} else {
		a.v.Store(0)
	}
}

func (a *atomicBool) Load() bool { return a.v.Load() == 1 }

func (a *atomicBool) CompareAndSwap(old, newV bool) bool {
	var want, replace int32 = 0, 1
	if old {
		want = 1
	}
	if newV {
		replace = 1
	}
	return a.v.CompareAndSwap(want, replace)
}

// IndexJob 是一次带版本的任务：revision 由 SQLite PrepareIndex 分配，
// 是提交时 CAS 的唯一凭据；generation 记录触发扫描批次（事件任务为 0）。
type IndexJob struct {
	RelativePath string
	Revision     int64
	Generation   int64
}

// queuedTask 是去重队列里的待处理项：fp/force 在出队时传给 PrepareIndex。
// 同路径重复入队时 generation 取最大、force 取或。
type queuedTask struct {
	path  string
	gen   int64
	fp    indexdb.TargetFingerprint
	force bool
}

// Coordinator 统一管理扫描、事件、稳定性检测、Hash worker、提交与 GC 生命周期。
// revision 的唯一真值在 SQLite；内存只保留去重队列与重试计数。
type Coordinator struct {
	cfg   *config.Config
	db    *indexdb.DB
	store *seed.Store
	log   *metrics.Logger
	clk   clock.Clock

	nasRoot string
	root    *safefs.Root // nas_data 安全打开入口：Hash/stat 全部经由它

	mu       sync.Mutex
	pending  []queuedTask        // 有界 FIFO 去重队列
	pendingG map[string]int64    // 路径 -> 触发 generation（同路径取最大）
	inQueue  map[string]struct{} // 去重集合
	attempts map[string]int      // 连续失败计数（运维诊断，不参与正确性）

	notifyCh chan struct{}
	jobs     chan IndexJob // 已完成 PrepareIndex 的任务

	scanning atomicBool
	manual   chan struct{}

	// seedLifecycleMu 串行化 worker 的 Publish->Commit 与 GC 的
	// FilterUnreferenced->MoveToTrash->DeleteContents，防止刚发布的 Seed 被 GC 回收。
	seedLifecycleMu sync.Mutex

	watcher      *fileWatcher
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	fullyStopped chan struct{}
	stopOnce     sync.Once
}

// New 创建协调器；调用 Start 前不会启动任何 goroutine。
// New 创建协调器；失败时返回中文错误，调用方无需回滚。
// New 创建协调器；root 由组合根创建并共享给内容读取器，停止时统一关闭。
func New(cfg *config.Config, db *indexdb.DB, store *seed.Store, log *metrics.Logger,
	root *safefs.Root) (*Coordinator, error) {

	return &Coordinator{
		cfg:          cfg,
		db:           db,
		store:        store,
		log:          log,
		clk:          cfg.Clock,
		nasRoot:      cfg.NASData,
		root:         root,
		pendingG:     make(map[string]int64),
		inQueue:      make(map[string]struct{}),
		attempts:     make(map[string]int),
		notifyCh:     make(chan struct{}, 1),
		jobs:         make(chan IndexJob, cfg.HashWorkers*8),
		manual:       make(chan struct{}, 1),
		fullyStopped: make(chan struct{}),
	}, nil
}

// Start 启动 dispatcher、Hash worker、扫描循环与 GC 循环，
// 并安排首次全量扫描（需求 §6.2：取得锁并打开数据库后必须启动一次全量扫描）。
func (c *Coordinator) Start(parent context.Context) {
	c.ctx, c.cancel = context.WithCancel(parent)
	for i := 0; i < c.cfg.HashWorkers; i++ {
		c.wg.Add(1)
		go func(id int) {
			defer c.wg.Done()
			c.workerLoop(c.ctx)
		}(i)
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.dispatchLoop(c.ctx)
	}()
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.scanLoop(c.ctx)
	}()
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.gcLoop(c.ctx)
	}()
	if c.cfg.WatcherEnabled() {
		w, err := startFileWatcher(c.ctx, c)
		if err != nil {
			// watcher 启动失败不阻止服务运行：记录中文诊断，最终一致性由周期全量扫描保证。
			c.log.Emit("library_watcher_start_failed", map[string]any{
				"error":     err.Error(),
				"reason_zh": "文件事件监视器未启用，同步完全依赖周期全量扫描",
			})
		} else {
			c.watcher = w
		}
	}
}

// Stop 按冻结顺序停止，并返回是否已完全 drain：
// 先停 watcher（不再产生新调度）→ 取消扫描/Hash 任务 → 有界等待退出。
// 返回 false 表示超时仍有后台任务未退出（例如网络挂载 IO 永久阻塞）；
// 调用方此时不得释放该协调器仍可能访问的 DB / safefs.Root / service.lock，
// 应等待 WaitDrained 后再执行最终清理（阻断 5）。
func (c *Coordinator) Stop(ctx context.Context) bool {
	c.stopOnce.Do(func() {
		if c.watcher != nil {
			c.watcher.Stop()
			c.watcher = nil
		}
		if c.cancel != nil {
			c.cancel()
		}
		// 独立 goroutine 等待全部任务退出；WaitDrained 依赖其完成信号。
		go func() {
			c.wg.Wait()
			close(c.fullyStopped)
		}()
	})
	select {
	case <-c.fullyStopped:
		return true
	case <-ctx.Done():
		c.log.Emit("library_stop_timeout", map[string]any{
			"reason_zh": "停止等待超时（可能有阻塞中的文件 IO），service.lock 将保留至任务真正退出",
		})
		return false
	}
}

// WaitDrained 阻塞直到全部后台任务真正退出（须在 Stop 之后调用）。
func (c *Coordinator) WaitDrained() { <-c.fullyStopped }

// QueueDepth 返回当前排队路径数，供管理台展示。
func (c *Coordinator) QueueDepth() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}

// Scanning 返回是否正在执行全量扫描。
func (c *Coordinator) Scanning() bool { return c.scanning.Load() }

// SchedulePath 把一个 nas_data 相对路径以强制模式加入处理队列：
// watcher 事件、标脏重建等“内容可能已变化”的来源使用本入口，
// 出队后 PrepareIndex 必定推进 revision。
func (c *Coordinator) SchedulePath(reasonZh string, generation int64, relativePaths ...string) {
	c.enqueue(reasonZh, generation, indexdb.TargetFingerprint{}, true, relativePaths...)
}

// ScheduleFromScan 是全量扫描专用入口：携带扫描时观察到的指纹。
// 同指纹的在途任务不会被重复推进 revision（阻断 1 活锁修复）。
func (c *Coordinator) ScheduleFromScan(reasonZh string, generation int64,
	relativePath string, fp indexdb.TargetFingerprint) {

	c.enqueue(reasonZh, generation, fp, false, relativePath)
}

// enqueue 去重入队；同路径合并 generation（取最大）与 force（取或）。
func (c *Coordinator) enqueue(reasonZh string, generation int64,
	fp indexdb.TargetFingerprint, force bool, relativePaths ...string) {

	overflow := false
	c.mu.Lock()
	for _, path := range relativePaths {
		path = filepath.ToSlash(filepath.Clean(path))
		if path == "." || path == "" || strings.HasPrefix(path, "..") {
			continue
		}
		if gen, ok := c.pendingG[path]; !ok || generation > gen {
			c.pendingG[path] = generation
		}
		if _, ok := c.inQueue[path]; ok {
			for i := range c.pending {
				if c.pending[i].path == path {
					c.pending[i].force = c.pending[i].force || force
					break
				}
			}
			continue
		}
		if len(c.pending) >= maxPendingPaths {
			overflow = true
			break
		}
		c.inQueue[path] = struct{}{}
		c.pending = append(c.pending, queuedTask{path: path, gen: generation, fp: fp, force: force})
	}
	c.mu.Unlock()
	select {
	case c.notifyCh <- struct{}{}:
	default:
	}
	if overflow {
		c.log.Emit("library_queue_overflow", map[string]any{
			"reason_zh": "任务队列超过上限，改为触发全量扫描收敛",
		})
		c.TriggerFullScan()
	}
}

// TriggerFullScan 请求执行一轮全量扫描；已有扫描进行中时返回 false。
func (c *Coordinator) TriggerFullScan() bool {
	select {
	case c.manual <- struct{}{}:
		return true
	default:
		return false
	}
}

// MarkSeedDirty 实现 content.DirtyListener（阻断 2）：
// Seed 缺失或损坏时，事务内立即把内容置为 error——后续 Stat 必须返回 absent；
// 随后以强制模式调度该 Seed 的全部原文件位置重建。
func (c *Coordinator) MarkSeedDirty(seedHashHex, reasonZh string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.db.MarkContentError(ctx, seedHashHex, reasonZh, c.clk.Now()); err != nil {
		c.log.Emit("library_seed_mark_error_failed", map[string]any{"seed_hash": seedHashHex, "error": err.Error()})
	}
	locations, err := c.db.LocationsOfSeed(ctx, seedHashHex)
	if err != nil {
		c.log.Emit("library_seed_relocate_failed", map[string]any{"seed_hash": seedHashHex, "error": err.Error()})
		return
	}
	if len(locations) == 0 {
		c.TriggerFullScan()
		return
	}
	c.log.Emit("library_seed_dirty", map[string]any{
		"seed_hash":   seedHashHex,
		"reason_zh":   reasonZh,
		"rebuild_cnt": len(locations),
	})
	c.SchedulePath("Seed 损坏，从原文件强制重建", 0, locations...)
}

// MarkLocationDirty 实现 content.DirtyListener（阻断 2）：
// 携带候选时刻的 seed_hash 与 revision 做 CAS 标脏。
// CAS 未命中说明该位置已被新索引提交取代：不得改动状态、不得触发重建，
// 否则旧 Read 会造成可用性抖动与无谓重算。
func (c *Coordinator) MarkLocationDirty(relativePath, seedHashHex string, revision int64, reasonZh string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := c.db.MarkLocationDirty(ctx, relativePath, seedHashHex, revision, reasonZh, c.clk.Now())
	switch {
	case err == nil:
		c.SchedulePath("读取完整性失败，标脏重索引", 0, relativePath)
	case errors.Is(err, indexdb.ErrRevisionStale):
		c.log.Emit("library_dirty_stale_skip", map[string]any{
			"path_zh":   relativePath,
			"reason_zh": "读取失败的位置已被新索引提交取代，跳过标脏",
		})
	default:
		c.log.Emit("library_mark_dirty_failed", map[string]any{"error": err.Error()})
	}
}

func (c *Coordinator) dispatchLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.notifyCh:
		}
		for {
			task, ok := c.popPending()
			if !ok {
				break
			}
			// PrepareIndex：分配本次任务的 revision（CAS 凭据）并把位置置为 indexing；
			// 同指纹的非强制重复调度不会推进 revision（阻断 1 活锁修复）。
			prepCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			revision, err := c.db.PrepareIndex(prepCtx, task.path, task.gen,
				c.clk.Now(), task.fp, task.force)
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					c.log.Emit("library_prepare_failed", map[string]any{
						"path_zh":   task.path,
						"error":     err.Error(),
						"reason_zh": "任务准备失败，等待下一次事件或全量扫描重试",
					})
				}
				continue
			}
			job := IndexJob{RelativePath: task.path, Revision: revision, Generation: task.gen}
			select {
			case c.jobs <- job:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (c *Coordinator) popPending() (queuedTask, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.pending) > 0 {
		task := c.pending[0]
		c.pending = c.pending[1:]
		delete(c.inQueue, task.path)
		delete(c.pendingG, task.path)
		if task.path == "" || task.path == "." {
			continue
		}
		return task, true
	}
	return queuedTask{}, false
}

func (c *Coordinator) workerLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-c.jobs:
			c.processPath(ctx, job)
		}
	}
}

// processPath 对单个任务执行完整流水线：
// 稳定性检测(stat A/B) -> 流式建 Seed -> 发布 -> stat C -> 带 CAS 的短事务提交。
// job.Revision 是 SQLite 分配的任务版本；提交时任何更新调度都会使 CAS 落空。
func (c *Coordinator) processPath(ctx context.Context, job IndexJob) {
	relativePath := job.RelativePath

	before, ok, err := stableStatBefore(ctx, c.clk, c.root, relativePath, c.cfg.FileStableInterval.Standard())
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		c.retryOrFailWith(ctx, job, fmt.Sprintf("稳定性检测失败：%v", err))
		return
	}
	if !ok {
		// 文件消失：进入 invalid（24 小时保留），不删除任何派生数据。
		c.handleMissing(ctx, relativePath, job.Revision)
		return
	}
	if !before.Mode.IsRegular() {
		// 设备文件、socket、FIFO 或符号链接一律跳过。
		c.log.Emit("library_skip_non_regular", map[string]any{
			"path_zh":   relativePath,
			"reason_zh": "不是普通文件（可能是符号链接、设备、socket 或 FIFO），已跳过",
		})
		return
	}

	result, buildErr := c.buildSeed(relativePath)
	if buildErr != nil {
		c.retryOrFailWith(ctx, job, buildErr.Error())
		return
	}

	// stat C：Hash 期间文件发生变化则本次结果无效。
	stillSame, err := stableStatAfter(ctx, c.root, relativePath, before)
	if ctx.Err() != nil {
		return
	}
	if err != nil || !stillSame {
		c.log.Emit("library_unstable_file", map[string]any{
			"path_zh":   relativePath,
			"reason_zh": "Hash 期间文件继续变化，丢弃本次结果并重新排队",
		})
		c.retryOrFailWith(ctx, job, "文件持续写入，等待稳定后重试")
		return
	}

	// Seed 生命周期锁：Publish->Commit 与 GC 的回收段互斥（阻断 2）。
	now := c.clk.Now()
	dev, inode := deviceInode(before)
	c.seedLifecycleMu.Lock()
	if err := c.store.Publish(result); err != nil {
		c.seedLifecycleMu.Unlock()
		c.retryOrFailWith(ctx, job, "Seed 发布失败："+err.Error())
		return
	}
	err = c.db.CommitSeedResult(ctx, indexdb.CommitParams{
		RelativePath:     relativePath,
		SeedHash:         result.HashHex(),
		SeedLength:       len(result.Seed),
		SourceSize:       result.SourceSize,
		Filename:         result.RecommendedFilename,
		MediaType:        result.MediaType,
		SizeBytes:        before.SizeBytes,
		MtimeNs:          before.MtimeNs,
		DeviceID:         dev,
		Inode:            inode,
		Generation:       job.Generation,
		ExpectedRevision: job.Revision,
		Blocks:           toBlockRows(result.Blocks),
	}, now)
	c.seedLifecycleMu.Unlock()
	switch {
	case err == nil:
		c.mu.Lock()
		delete(c.attempts, relativePath)
		c.mu.Unlock()
	case errors.Is(err, indexdb.ErrRevisionStale):
		// 已被更新的调度取代：丢弃本次结果；孤儿 Seed 由 GC 磁盘扫描延迟回收。
		c.log.Emit("library_revision_stale", map[string]any{
			"path_zh":   relativePath,
			"reason_zh": "提交时任务已被更新的调度取代，丢弃本次计算结果",
		})
	default:
		c.retryOrFailWith(ctx, job, "SQLite 提交失败："+err.Error())
	}
}

// handleMissing 处理确认消失的文件：位置进入 invalid（第一次进入时记录 invalid_since，
// 之后重复标记不得刷新），不删除任何派生数据。同时 bump revision 使同路径在途任务失效。
func (c *Coordinator) handleMissing(ctx context.Context, relativePath string, revision int64) {
	err := c.db.MarkInvalidNow(ctx, relativePath, "文件或目录当前不可见", c.clk.Now(), revision)
	if err != nil && !errors.Is(err, indexdb.ErrRevisionStale) {
		c.log.Emit("library_invalidate_failed", map[string]any{"path_zh": relativePath, "error": err.Error()})
	}
}

// retryOrFailWith 记录一次失败：未达上限立即重新排队（防抖由稳定性检测承担）；
// 达到上限后保留 error 状态并停止重试，等待下一次事件或全量扫描。
func (c *Coordinator) retryOrFailWith(ctx context.Context, job IndexJob, reasonZh string) {
	c.mu.Lock()
	attempt := c.attempts[job.RelativePath] + 1
	giveUp := attempt >= maxAttempts
	if giveUp {
		delete(c.attempts, job.RelativePath)
	} else {
		c.attempts[job.RelativePath] = attempt
	}
	c.mu.Unlock()

	if giveUp {
		var size, mtime int64
		if fi, err := c.root.LstatFile(job.RelativePath); err == nil {
			size = fi.Size()
			mtime = fi.ModTime().UnixNano()
		}
		dbCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := c.db.SetLocationFailed(dbCtx, job.RelativePath, size, mtime, reasonZh, job.Revision); err != nil {
			c.log.Emit("library_record_error_failed", map[string]any{"path_zh": job.RelativePath, "error": err.Error()})
		}
		c.log.Emit("library_path_gave_up", map[string]any{
			"path_zh":   job.RelativePath,
			"attempts":  maxAttempts,
			"reason_zh": reasonZh,
		})
		return
	}
	c.log.Emit("library_retry_scheduled", map[string]any{
		"path_zh":   job.RelativePath,
		"attempt":   attempt,
		"reason_zh": reasonZh,
	})
	// 重试属于“内容可能已变化”的强制调度。
	c.SchedulePath(reasonZh, job.Generation, job.RelativePath)
}

// buildSeed 通过安全入口打开原文件并流式计算 Seed；不做任何数据库写入。
// 中间目录符号链接、最终符号链接与任何路径逃逸都在此处 fail closed。
func (c *Coordinator) buildSeed(relativePath string) (*seed.Result, error) {
	file, _, err := c.root.OpenFile(relativePath)
	if err != nil {
		if errors.Is(err, safefs.ErrSymlinkAncestor) || errors.Is(err, safefs.ErrSymlinkFinal) {
			return nil, fmt.Errorf("路径包含符号链接，已跳过：%w", err)
		}
		return nil, fmt.Errorf("打开原文件失败: %w", err)
	}
	defer file.Close()
	return seed.Build(file, relativeBase(relativePath))
}

func relativeBase(relativePath string) string {
	return strings.TrimPrefix(relativePath, "./")
}

// deviceInode 提取可靠的 device_id / inode；文件系统不提供时返回 nil，
// 恢复判定以路径+尺寸+mtime 为主要依据，不得因 inode 缺失强制失败。
func deviceInode(fp fingerprint) (*int64, *int64) {
	if fp.sys == nil {
		return nil, nil
	}
	if st, ok := fp.sys.(*syscall.Stat_t); ok {
		dev := int64(st.Dev)
		ino := int64(st.Ino)
		return &dev, &ino
	}
	return nil, nil
}

// openNoFollow 打开文件且拒绝最终组件是符号链接（默认不跟随 symlink）。
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

func toBlockRows(blocks []seed.Block) []indexdb.SeedBlock {
	rows := make([]indexdb.SeedBlock, 0, len(blocks))
	buf := make([]byte, 64)
	for _, b := range blocks {
		hex.Encode(buf, b.Hash[:])
		rows = append(rows, indexdb.SeedBlock{
			BlockIndex:  b.Index,
			BlockHash:   string(buf),
			OffsetBytes: b.Offset,
			LengthBytes: int64(b.Length),
		})
	}
	return rows
}

// InjectBlockedWorkerForTest 注册一个受控阻塞的后台任务，
// 仅供 nas 包验证“停止超时保留 service.lock”语义（跨包测试钩子）。
func (c *Coordinator) InjectBlockedWorkerForTest(done <-chan struct{}) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		<-done
	}()
}
