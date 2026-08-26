package library

import (
	"context"
	"time"

	"msfile.dev/labs/webrtc-go/internal/indexdb"
)

// 本文件实现冻结需求 §7.4 的派生数据回收：
//
//	位置连续不可见达到保留期（默认 24 小时）后：
//	  1. 以守卫方式删除该 file_locations 行（state/invalid_since/revision 三重校验）；
//	  2. 在 Seed 生命周期锁内重新过滤无引用内容，先移 Seed 入 trash，再删 contents/blocks；
//	  3. 异步清空 trash。
//	  4. 磁盘孤儿扫描：提交失败遗留、从未入索引的 .seed 文件在保留期后回收。
//
// 铁律：GC 只触碰 seed_data 派生数据，绝不删除、移动或创建 nas_data 原文件。

// gcInterval 是 GC 巡检周期；与 24 小时保留期无关，只影响清理延迟上限。
const gcInterval = time.Hour

// gcBatchSize 是单轮 GC 处理的最大行数，避免一次事务过大阻塞 SQLite executor。
const gcBatchSize = 500

func (c *Coordinator) gcLoop(ctx context.Context) {
	timer := c.clk.Timer(gcInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			timer.Reset(gcInterval)
			c.runGCRound()
		}
	}
}

// runGCRound 执行一轮完整回收。
func (c *Coordinator) runGCRound() {
	now := c.clk.Now()
	cutoff := now.Add(-c.cfg.InvalidRetention.Standard())

	collectCtx, collectCancel := context.WithTimeout(context.Background(), time.Minute)
	defer collectCancel()

	// 第一部分：过期 invalid 位置。删除语句带 state/invalid_since/revision 守卫，
	// 快照之后恢复或被新任务取代的位置自动跳过（阻断 2）。
	expired, err := c.db.ExpiredInvalidLocations(collectCtx, cutoff, gcBatchSize)
	if err != nil {
		c.log.Emit("library_gc_failed", map[string]any{"stage_zh": "查询过期失效位置", "error": err.Error()})
		return
	}
	var orphans []string
	if len(expired) > 0 {
		targets := make([]indexdb.LocationDeleteTarget, 0, len(expired))
		for _, loc := range expired {
			targets = append(targets, indexdb.LocationDeleteTarget{
				RelativePath: loc.RelativePath,
				Revision:     loc.Revision,
			})
		}
		orphans, err = c.db.DeleteLocations(collectCtx, targets, cutoff)
		if err != nil {
			c.log.Emit("library_gc_failed", map[string]any{"stage_zh": "守卫删除过期位置", "error": err.Error()})
		} else {
			c.log.Emit("library_gc_locations_expired", map[string]any{
				"count":      len(targets),
				"orphan_cnt": len(orphans),
				"note_zh":    "仅删除派生索引与 Seed，nas_data 原文件不受影响",
			})
		}
	}

	// 第二部分：SQLite 提交失败遗留的无引用孤儿内容（延迟一个保留期再清理，
	// 给并发中的发布流程留出完成窗口）。
	dbOrphans, err := c.db.OrphanContents(collectCtx, cutoff, gcBatchSize)
	if err != nil {
		c.log.Emit("library_gc_failed", map[string]any{"stage_zh": "查询孤儿内容", "error": err.Error()})
		return
	}

	// 第三部分：磁盘孤儿扫描——Publish 成功但 Commit 失败/CAS 落空的 .seed 文件
	// 从未进入数据库，按文件 mtime 超过保留期回收。
	diskOrphans := c.diskOrphanSeeds(collectCtx, cutoff)

	// 第四部分（Seed 生命周期锁内）：重新过滤 + trash + 删行。
	// 锁保证与 worker 的 Publish->Commit 串行；过滤在锁内执行才是删除前的最终真值。
	candidates := dedupeSeeds(append(append(orphans, dbOrphans...), diskOrphans...))
	if len(candidates) > 0 {
		c.recycleSeeds(collectCtx, candidates, cutoff)
	}

	// 第五部分：异步清空 trash。此时相关行已解除数据库引用；
	// 物理删除失败只影响磁盘占用，下轮 GC 会再次尝试。
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		trashCtx, trashCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer trashCancel()
		select {
		case <-trashCtx.Done():
			return
		default:
		}
		if err := c.store.EmptyTrash(); err != nil {
			c.log.Emit("library_gc_trash_failed", map[string]any{"error": err.Error()})
		}
	}()
}

// recycleSeeds 必须持有的语义：锁内重新过滤 -> MoveToTrash -> DeleteContents。
func (c *Coordinator) recycleSeeds(dbCtx context.Context, candidates []string, cutoff time.Time) {
	c.seedLifecycleMu.Lock()
	defer c.seedLifecycleMu.Unlock()

	// 锁内的最终真值：快照后已被 worker 重新引用的候选在此被剔除。
	fresh, err := c.db.FilterUnreferenced(dbCtx, candidates)
	if err != nil {
		c.log.Emit("library_gc_failed", map[string]any{"stage_zh": "锁内复核无引用", "error": err.Error()})
		return
	}
	if len(fresh) == 0 {
		return
	}
	moved := make([]string, 0, len(fresh))
	for _, hash := range fresh {
		if err := c.store.MoveToTrash(hash); err != nil {
			c.log.Emit("library_gc_seed_move_failed", map[string]any{"seed_hash": hash, "error": err.Error()})
			continue
		}
		moved = append(moved, hash)
	}
	if len(moved) == 0 {
		return
	}
	if err := c.db.DeleteContents(dbCtx, moved); err != nil {
		// DB 行未删除时 Seed 已在 trash：内容不可见且下轮 GC 会重试删除行。
		c.log.Emit("library_gc_contents_delete_failed", map[string]any{"count": len(moved), "error": err.Error()})
		return
	}
	c.log.Emit("library_gc_seeds_recycled", map[string]any{"count": len(moved)})
}

// diskOrphanSeeds 扫描 seeds 目录，返回 mtime 早于 cutoff 且不在数据库 contents 表中的 hash。
func (c *Coordinator) diskOrphanSeeds(ctx context.Context, cutoff time.Time) []string {
	referenced, err := c.db.AllContentHashes(ctx)
	if err != nil {
		c.log.Emit("library_gc_failed", map[string]any{"stage_zh": "查询已知内容 Hash", "error": err.Error()})
		return nil
	}
	var out []string
	err = c.store.WalkSeeds(func(hashHex string, modTime time.Time) error {
		if _, ok := referenced[hashHex]; ok {
			return nil
		}
		if modTime.After(cutoff) {
			return nil // 新鲜孤儿：给发布事务留时间窗口
		}
		out = append(out, hashHex)
		return nil
	})
	if err != nil {
		c.log.Emit("library_gc_failed", map[string]any{"stage_zh": "扫描磁盘孤儿 Seed", "error": err.Error()})
	}
	return out
}

func dedupeSeeds(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
