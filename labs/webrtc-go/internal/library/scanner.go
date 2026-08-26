package library

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"msfile.dev/labs/webrtc-go/internal/indexdb"
	"msfile.dev/labs/webrtc-go/internal/seed"
)

// scanLoop 周期性执行全量扫描，并响应管理台的手动触发。
// 启动后立即安排首次全量扫描（需求 §6.2）。
func (c *Coordinator) scanLoop(ctx context.Context) {
	interval := c.cfg.FullScanInterval.Standard()
	timer := c.clk.Timer(interval)
	defer timer.Stop()
	c.startScan(ctx, "startup") // 首次全量扫描
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			timer.Reset(interval)
			c.startScan(ctx, "periodic")
		case <-c.manual:
			timer.Reset(interval)
			c.startScan(ctx, "manual")
		}
	}
}

// startScan 异步执行一轮扫描；同一时刻只允许一轮。
func (c *Coordinator) startScan(ctx context.Context, trigger string) {
	if !c.scanning.CompareAndSwap(false, true) {
		return // 已有扫描在执行；本轮跳过，周期会再来
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer c.scanning.Store(false)
		scanCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		started := c.clk.Now()
		generation, status, errorZh := c.executeScan(scanCtx, started)
		c.log.Emit("library_scan_finished", map[string]any{
			"trigger":    trigger,
			"generation": generation,
			"status":     status,
			"error_zh":   errorZh,
		})
	}()
}

// executeScan 执行一轮完整扫描并落库：
//
//  1. 分配 generation；
//  2. 递归遍历 nas_data（不跟随符号链接，只接受普通文件）；
//  3. 与 relative_path + size + mtime 指纹比较：一致的恢复/确认（复用 Seed），
//     不一致或新增的进入 Hash 队列；
//  4. 本轮未见的位置（含读取失败的子树）批量转 invalid；
//  5. 写入 succeeded / partial / failed 终态。
func (c *Coordinator) executeScan(ctx context.Context, startedAt time.Time) (int64, string, string) {
	dbCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	generation, err := c.db.BeginScan(dbCtx, startedAt)
	if err != nil {
		return 0, indexdb.ScanFailed, "分配扫描批次失败：" + err.Error()
	}

	fingerprints, err := c.db.ListFingerprints(dbCtx)
	if err != nil {
		c.finishScan(generation, indexdb.ScanFailed, "读取位置指纹失败："+err.Error())
		return generation, indexdb.ScanFailed, "读取位置指纹失败：" + err.Error()
	}

	var (
		pendingVerify = map[string][]indexdb.TouchAction{} // seedHash -> 确认候选
		seen          = make(map[string]struct{}, len(fingerprints))
		walkErrs      = make([]string, 0, 8)
		scheduled     = 0
		confirm       []indexdb.TouchAction
	)

	err = filepath.WalkDir(c.nasRoot, func(path string, d fs.DirEntry, walkError error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel, relErr := filepath.Rel(c.nasRoot, path)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if walkError != nil {
			// 目录或文件不可读：该范围本轮按不可见处理，绝不删除记录或 Seed。
			walkErrs = append(walkErrs, fmt.Sprintf("%s：%v", rel, walkError))
			if d != nil && d.IsDir() && !errors.Is(walkError, fs.ErrNotExist) {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			walkErrs = append(walkErrs, fmt.Sprintf("%s：无法读取文件信息：%v", rel, infoErr))
			return nil
		}
		if info.Mode()&fs.ModeSymlink != 0 || d.Type()&fs.ModeSymlink != 0 {
			c.log.Emit("library_scan_skip_symlink", map[string]any{
				"path_zh":   rel,
				"reason_zh": "符号链接默认跳过，避免越出 nas_data 根目录或形成循环",
			})
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil // 设备、socket、FIFO 一律跳过
		}
		seen[rel] = struct{}{}
		fp, known := fingerprints[rel]

		// 已有在途索引任务的位置：本轮不确认也不重复调度，
		// 交给 PrepareIndex 的指纹去重决定是否推进（阻断 1）。
		if known && fp.State == indexdb.LocationIndexing {
			return nil
		}
		dev, ino := deviceInode(fingerprint{sys: info.Sys()})
		scanFP := indexdb.TargetFingerprint{
			SizeBytes: info.Size(), MtimeNs: info.ModTime().UnixNano(),
			DeviceID: dev, Inode: ino,
		}

		if info.Size() > seed.MaxSourceBytes {
			failCtx, failCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer failCancel()
			reason := fmt.Sprintf("文件尺寸 %d 超过 MSFile V1 最大源文件尺寸 %d 字节", info.Size(), seed.MaxSourceBytes)
			if err := c.db.SetLocationFailed(failCtx, rel, info.Size(), info.ModTime().UnixNano(), reason, fp.Revision); err != nil {
				walkErrs = append(walkErrs, rel+"："+reason)
			} else {
				c.log.Emit("library_scan_unsupported_size", map[string]any{"path_zh": rel, "reason_zh": reason})
			}
			return nil
		}

		if known && fp.SeedHash != "" &&
			fp.SizeBytes == info.Size() && fp.MtimeNs == info.ModTime().UnixNano() &&
			!deviceInodeContradicts(fp, dev, ino) { // 指纹一致：valid 直接确认；invalid/error 在保留期内恢复为 valid，
			// 复用 SQLite 块映射和原 Seed，不重新计算（需求 §7.2）。
			pendingVerify[fp.SeedHash] = append(pendingVerify[fp.SeedHash], indexdb.TouchAction{
				RelativePath:  rel,
				KnownRevision: fp.Revision,
				SizeBytes:     info.Size(),
				MtimeNs:       info.ModTime().UnixNano(),
				DeviceID:      dev,
				Inode:         ino,
			})
			return nil
		}
		// 新增、变化或身份无法确认：进入稳定性检测与 Hash 队列（携带扫描指纹）。
		c.ScheduleFromScan("全量扫描发现新增或变化文件", generation, rel, scanFP)
		scheduled++
		return nil
	})

	rootFailed := false
	if err != nil && !errors.Is(err, fs.SkipDir) {
		if ctx.Err() != nil {
			c.finishScan(generation, indexdb.ScanFailed, "扫描被停止")
			return generation, indexdb.ScanFailed, "扫描被停止"
		}
		// 根目录本身不可读时 WalkDir 立即返回错误。
		if _, statErr := os.Stat(c.nasRoot); statErr != nil {
			rootFailed = true
			walkErrs = append([]string{fmt.Sprintf("nas_data 根目录不可读：%v", statErr)}, walkErrs...)
		} else {
			walkErrs = append(walkErrs, fmt.Sprintf("遍历中断：%v", err))
		}
	}

	// 未见位置批量失效：包含成功范围内消失的文件与不可读子树中的已知位置。
	targets := make([]indexdb.InvalidateTarget, 0, len(fingerprints))
	for path, fp := range fingerprints {
		if _, ok := seen[path]; ok {
			continue
		}
		reasonZh := "全量扫描未见该路径"
		if rootFailed {
			reasonZh = "nas_data 根目录当前不可读"
		}
		targets = append(targets, indexdb.InvalidateTarget{
			RelativePath:  path,
			KnownRevision: fp.Revision,
			ErrorZh:       reasonZh,
		})
	}

	// 阻断 2：复用前校验 .seed 存在且 SHA-256 正确；每个唯一 Hash 只读一次。
	confirm = make([]indexdb.TouchAction, 0, len(pendingVerify))
	for seedHash, actions := range pendingVerify {
		if err := c.store.VerifySeed(seedHash); err != nil {
			c.log.Emit("library_scan_seed_corrupt", map[string]any{
				"seed_hash": seedHash,
				"reason_zh": "复用前完整性校验失败，强制重建：" + err.Error(),
			})
			for _, action := range actions {
				c.SchedulePath("Seed 文件损坏，强制重建", generation, action.RelativePath)
				scheduled++
			}
			continue
		}
		confirm = append(confirm, actions...)
	}

	now := c.clk.Now()
	status := indexdb.ScanSucceeded
	errorZh := ""
	switch {
	case rootFailed:
		status = indexdb.ScanFailed
		errorZh = strings.Join(walkErrs, "; ")
	case len(walkErrs) > 0:
		status = indexdb.ScanPartial
		errorZh = truncateZh(strings.Join(walkErrs, "; "), 900)
	}

	confirmCtx, confirmCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer confirmCancel()
	if cerr := c.db.ConfirmSeenPaths(confirmCtx, confirm, generation, now); cerr != nil {
		status = indexdb.ScanPartial
		errorZh = joinZh(errorZh, "确认已见位置失败："+cerr.Error())
	}
	if ierr := c.db.InvalidatePaths(confirmCtx, targets, now, generation); ierr != nil {
		status = indexdb.ScanPartial
		errorZh = joinZh(errorZh, "标记失效位置失败："+ierr.Error())
	}
	c.finishScan(generation, status, errorZh)
	c.log.Emit("library_scan_summary", map[string]any{
		"generation":     generation,
		"status":         status,
		"confirmed":      len(confirm),
		"scheduled":      scheduled,
		"invalidated":    len(targets),
		"walk_error_cnt": len(walkErrs),
	})
	return generation, status, errorZh
}

// deviceInodeContradicts 判断可靠的 device_id/inode 是否与记录矛盾。
// 任一方缺失（NAS 文件系统未提供）不算矛盾；只有双方都有且不同才算，
// 此时按“指纹变化”重新确认，不能仅因 inode 缺失强制失败。
func deviceInodeContradicts(fp indexdb.Fingerprint, dev, ino *int64) bool {
	if dev == nil || ino == nil || fp.DeviceID == nil || fp.Inode == nil {
		return false
	}
	return *fp.DeviceID != *dev || *fp.Inode != *ino
}

func (c *Coordinator) finishScan(generation int64, status, errorZh string) {
	finCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.db.FinishScan(finCtx, generation, status, errorZh, c.clk.Now()); err != nil {
		c.log.Emit("library_scan_finish_failed", map[string]any{"error": err.Error()})
	}
}

func joinZh(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

func truncateZh(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := s[:max]
	// 防止截断出半个 UTF-8 字符
	for len(cut) > 0 && !utf8ValidLast(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut + "…"
}

func utf8ValidLast(s string) bool {
	// 简单检查最后一个字节是否是 UTF-8 序列起点
	b := s[len(s)-1]
	return b&0xC0 != 0x80
}
