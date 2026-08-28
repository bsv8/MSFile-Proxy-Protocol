package indexdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNotFound 表示请求的 Hash 或路径没有索引记录。
var ErrNotFound = errors.New("索引中没有该记录")

// ErrRevisionStale 表示提交结果时同一路径已被更新的任务取代，旧结果必须丢弃。
var ErrRevisionStale = errors.New("任务 revision 已过期，丢弃本次提交")

// DB 是业务侧唯一可见的数据库对象；底层 *sql.DB 永不外泄。
type DB struct {
	exec *Executor
}

// Open 打开（必要时创建）索引数据库并完成 schema 校验。
// 检测到旧 schema 时返回 ErrIncompatibleSchema，由组合根中文报错并拒绝启动。
func Open(path string) (*DB, error) {
	raw, err := openRaw(path)
	if err != nil {
		return nil, err
	}
	return &DB{exec: start(raw, DefaultQueueDepth)}, nil
}

// Close 排空队列并关闭数据库；幂等。
func (d *DB) Close() error { return d.exec.Close() }

// QueueDepth 返回当前排队请求数。
func (d *DB) QueueDepth() int { return d.exec.QueueDepth() }

func nullInt64(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}

func scanTime(value any) time.Time {
	switch t := value.(type) {
	case time.Time:
		return t
	case int64:
		return time.Unix(0, t)
	default:
		return time.Time{}
	}
}

func nullableTime(row sql.NullInt64) *time.Time {
	if !row.Valid {
		return nil
	}
	t := time.Unix(0, row.Int64)
	return &t
}

// ---------- 扫描批次 ----------

// BeginScan 分配一个新的单调递增 generation 并写入 running 记录。
func (d *DB) BeginScan(ctx context.Context, startedAt time.Time) (int64, error) {
	return call(ctx, d.exec, func(ctx context.Context, db *sql.DB) (int64, error) {
		var generation int64
		err := db.QueryRowContext(ctx,
			`INSERT INTO scan_runs(generation, started_at, status)
			 VALUES ((SELECT coalesce(max(generation), 0) + 1 FROM scan_runs), ?, ?)
			 RETURNING generation`, startedAt.UnixNano(), ScanRunning).Scan(&generation)
		if err != nil {
			return 0, fmt.Errorf("分配扫描批次失败: %w", err)
		}
		return generation, nil
	})
}

// FinishScan 写入扫描终态。
func (d *DB) FinishScan(ctx context.Context, generation int64, status string, errorZh string, finishedAt time.Time) error {
	_, err := call(ctx, d.exec, func(ctx context.Context, db *sql.DB) (struct{}, error) {
		_, err := db.ExecContext(ctx,
			`UPDATE scan_runs SET finished_at = ?, status = ?, error_zh = ? WHERE generation = ?`,
			finishedAt.UnixNano(), status, errorZh, generation)
		return struct{}{}, err
	})
	return err
}

// ResetRunningScans 把上次进程中断遗留的 running 扫描改为 failed。
func (d *DB) ResetRunningScans(ctx context.Context, now time.Time) error {
	_, err := call(ctx, d.exec, func(ctx context.Context, db *sql.DB) (struct{}, error) {
		_, err := db.ExecContext(ctx,
			`UPDATE scan_runs SET status = ?, finished_at = ?, error_zh = '进程中断，扫描未完成' WHERE status = ?`,
			ScanFailed, now.UnixNano(), ScanRunning)
		return struct{}{}, err
	})
	return err
}

// RecentScans 返回最近 limit 次扫描记录（新在前）。
func (d *DB) RecentScans(ctx context.Context, limit int) ([]ScanRun, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	return call(ctx, d.exec, func(ctx context.Context, db *sql.DB) ([]ScanRun, error) {
		rows, err := db.QueryContext(ctx,
			`SELECT generation, started_at, finished_at, status, error_zh
			 FROM scan_runs ORDER BY generation DESC LIMIT ?`, limit)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		scans := make([]ScanRun, 0, limit)
		for rows.Next() {
			var run ScanRun
			var startedAt int64
			var finishedAt sql.NullInt64
			if err := rows.Scan(&run.Generation, &startedAt, &finishedAt, &run.Status, &run.ErrorZh); err != nil {
				return nil, err
			}
			run.StartedAt = time.Unix(0, startedAt)
			run.FinishedAt = nullableTime(finishedAt)
			scans = append(scans, run)
		}
		return scans, rows.Err()
	})
}

// ---------- 位置指纹与批量确认 ----------

// ListFingerprints 返回全部位置指纹，供全量扫描在内存中比对。
func (d *DB) ListFingerprints(ctx context.Context) (map[string]Fingerprint, error) {
	return call(ctx, d.exec, func(ctx context.Context, db *sql.DB) (map[string]Fingerprint, error) {
		rows, err := db.QueryContext(ctx,
			`SELECT relative_path, coalesce(seed_hash,''), size_bytes, mtime_ns, state, revision, device_id, inode
			 FROM file_locations`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		result := make(map[string]Fingerprint)
		for rows.Next() {
			var fp Fingerprint
			var deviceID, inode sql.NullInt64
			if err := rows.Scan(&fp.RelativePath, &fp.SeedHash, &fp.SizeBytes, &fp.MtimeNs, &fp.State, &fp.Revision, &deviceID, &inode); err != nil {
				return nil, err
			}
			if deviceID.Valid {
				v := deviceID.Int64
				fp.DeviceID = &v
			}
			if inode.Valid {
				v := inode.Int64
				fp.Inode = &v
			}
			result[fp.RelativePath] = fp
		}
		return result, rows.Err()
	})
}

// TouchAction 是一次扫描确认后的批量动作。
// KnownRevision 是扫描快照中的版本：位置在快照后进入 indexing（新任务）
// 或被再次失效时，确认会被跳过，绝不把重算中的位置复活为 valid。
type TouchAction struct {
	RelativePath  string
	KnownRevision int64
	SizeBytes     int64
	MtimeNs       int64
	DeviceID      *int64
	Inode         *int64
}

// ConfirmSeenPaths 在一个短事务内确认本轮扫描看到的文件：
// 指纹一致的恢复为 valid（复用既有 Seed，不重算），并刷新 last_seen_generation。
func (d *DB) ConfirmSeenPaths(ctx context.Context, actions []TouchAction, generation int64, now time.Time) error {
	if len(actions) == 0 {
		return nil
	}
	_, err := call(ctx, d.exec, func(ctx context.Context, db *sql.DB) (struct{}, error) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return struct{}{}, err
		}
		defer tx.Rollback()
		statement, err := tx.PrepareContext(ctx,
			`UPDATE file_locations SET state = 'valid', invalid_since = NULL, last_error_zh = '',
			    size_bytes = ?, mtime_ns = ?, device_id = ?, inode = ?, last_seen_generation = ?
			 WHERE relative_path = ? AND revision = ? AND seed_hash IS NOT NULL AND seed_hash <> ''`)
		if err != nil {
			return struct{}{}, err
		}
		defer statement.Close()
		for _, action := range actions {
			if _, err := statement.ExecContext(ctx, action.SizeBytes, action.MtimeNs,
				nullInt64(action.DeviceID), nullInt64(action.Inode), generation,
				action.RelativePath, action.KnownRevision); err != nil {
				return struct{}{}, fmt.Errorf("确认位置 %s 失败: %w", action.RelativePath, err)
			}
		}
		// 恢复的内容重新升级为 ready（指纹一致恢复复用 Seed，需求 §7.2）。
		if _, err := tx.ExecContext(ctx,
			`UPDATE contents SET state = 'ready', updated_at = ?
			 WHERE state <> 'ready'
			   AND EXISTS (SELECT 1 FROM file_locations f
			               WHERE f.seed_hash = contents.seed_hash AND f.state = 'valid')`,
			now.UnixNano()); err != nil {
			return struct{}{}, fmt.Errorf("恢复有有效副本的内容失败: %w", err)
		}
		return struct{}{}, tx.Commit()
	})
	return err
}

// InvalidateTarget 是一次失效动作：revision 用于防止覆盖并发提交的新结果。
type InvalidateTarget struct {
	RelativePath  string
	KnownRevision int64
	ErrorZh       string
}

// InvalidatePaths 在一个短事务内把未见位置转为 invalid。
// invalid_since 只在第一次从 valid 进入 invalid 时写入（COALESCE），重复扫描不得刷新。
// 带 revision 守卫：扫描快照之后若 worker 已提交新索引，则跳过该路径，交给下一轮收敛。
func (d *DB) InvalidatePaths(ctx context.Context, targets []InvalidateTarget, now time.Time, generation int64) error {
	if len(targets) == 0 {
		return nil
	}
	_, err := call(ctx, d.exec, func(ctx context.Context, db *sql.DB) (struct{}, error) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return struct{}{}, err
		}
		defer tx.Rollback()
		statement, err := tx.PrepareContext(ctx,
			`UPDATE file_locations SET state = 'invalid',
			    invalid_since = coalesce(invalid_since, ?),
			    last_error_zh = ?, last_seen_generation = ?
			 WHERE relative_path = ? AND revision = ?`)
		if err != nil {
			return struct{}{}, err
		}
		defer statement.Close()
		for _, target := range targets {
			if _, err := statement.ExecContext(ctx, now.UnixNano(), target.ErrorZh, generation,
				target.RelativePath, target.KnownRevision); err != nil {
				return struct{}{}, fmt.Errorf("标记位置 %s 失效失败: %w", target.RelativePath, err)
			}
			// 该路径的未完成索引任务一并作废。
			if _, err := tx.ExecContext(ctx,
				`DELETE FROM index_jobs WHERE relative_path = ?`, target.RelativePath); err != nil {
				return struct{}{}, err
			}
		}
		// 内容级状态联动（需求 §7.2）：不再拥有任何 valid 位置的 ready 内容降级为 invalid，
		// 保证管理台与可用性判断一致；仍有一个 valid 副本的内容不受影响。
		if _, err := tx.ExecContext(ctx,
			`UPDATE contents SET state = 'invalid', updated_at = ?
			 WHERE state = 'ready'
			   AND NOT EXISTS (SELECT 1 FROM file_locations f
			                   WHERE f.seed_hash = contents.seed_hash AND f.state = 'valid')`,
			now.UnixNano()); err != nil {
			return struct{}{}, fmt.Errorf("降级无有效副本的内容失败: %w", err)
		}
		return struct{}{}, tx.Commit()
	})
	return err
}

// MarkLocationDirty 把读取失败的候选位置标脏为 error。
// 三重 CAS（路径 + 当时候选的 seed_hash + revision）：任一不匹配说明位置已被
// 新索引提交取代，返回 ErrRevisionStale 且绝不改动状态、不再触发重建调度，
// 防止旧 Read 打脏新索引或造成可用性抖动（阻断 2）。
func (d *DB) MarkLocationDirty(ctx context.Context, relativePath, expectedSeedHash string,
	expectedRevision int64, reasonZh string, now time.Time) error {

	_, err := call(ctx, d.exec, func(ctx context.Context, db *sql.DB) (struct{}, error) {
		result, err := db.ExecContext(ctx,
			`UPDATE file_locations SET state = 'error', last_error_zh = ?
			 WHERE relative_path = ? AND seed_hash = ? AND revision = ?`,
			reasonZh, relativePath, expectedSeedHash, expectedRevision)
		if err != nil {
			return struct{}{}, err
		}
		if affected, affectedErr := result.RowsAffected(); affectedErr != nil {
			return struct{}{}, affectedErr
		} else if affected == 0 {
			return struct{}{}, ErrRevisionStale
		}
		return struct{}{}, nil
	})
	return err
}

// MarkInvalidNow 立即把一个位置标记为 invalid（事件确认文件消失）。
// invalid_since 用 COALESCE 保证只在第一次进入 invalid 时写入，重复标记不刷新；
// now 由调用方注入（协调器时钟），保证 24 小时边界测试确定。
// MarkInvalidNow 立即把一个位置标记为 invalid（事件确认文件消失）。
// invalid_since 用 COALESCE 保证只在第一次进入 invalid 时写入；
// ExpectedRevision 是调用方任务持有的版本，CAS 不命中返回 ErrRevisionStale，
// 防止旧 worker 覆盖新任务已提交的状态（阻断 1）。
// now 由调用方注入（协调器时钟），保证 24 小时边界测试确定。
func (d *DB) MarkInvalidNow(ctx context.Context, relativePath, errorZh string,
	now time.Time, expectedRevision int64) error {

	_, err := call(ctx, d.exec, func(ctx context.Context, db *sql.DB) (struct{}, error) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return struct{}{}, err
		}
		defer tx.Rollback()
		result, err := tx.ExecContext(ctx,
			`UPDATE file_locations SET state = 'invalid',
			    invalid_since = coalesce(invalid_since, ?),
			    last_error_zh = ?
			 WHERE relative_path = ? AND revision = ?`,
			now.UnixNano(), errorZh, relativePath, expectedRevision)
		if err != nil {
			return struct{}{}, err
		}
		if affected, affectedErr := result.RowsAffected(); affectedErr != nil {
			return struct{}{}, affectedErr
		} else if affected == 0 {
			return struct{}{}, ErrRevisionStale
		}
		// 同步内容级状态：失去最后一个 valid 副本时降级为 invalid。
		if _, err := tx.ExecContext(ctx,
			`UPDATE contents SET state = 'invalid', updated_at = ?
			 WHERE state = 'ready'
			   AND NOT EXISTS (SELECT 1 FROM file_locations f
			                   WHERE f.seed_hash = contents.seed_hash AND f.state = 'valid')`,
			now.UnixNano()); err != nil {
			return struct{}{}, err
		}
		// 文件确认消失：其未完成的索引任务一并作废。
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM index_jobs WHERE relative_path = ?`, relativePath); err != nil {
			return struct{}{}, err
		}
		return struct{}{}, tx.Commit()
	})
	return err
}

// TargetFingerprint 是调度任务时观察到的目标文件指纹；
// PrepareIndex 用它判断“是否是同一个未完成任务的重复调度”。
type TargetFingerprint struct {
	SizeBytes int64
	MtimeNs   int64
	DeviceID  *int64
	Inode     *int64
}

// nullAsInt64 把 SQL NULL 视作 0，参与指纹比较。
func nullAsInt64(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	default:
		return 0
	}
}

func (f TargetFingerprint) equal(size, mtime int64, dev, ino any) bool {
	if f.SizeBytes != size || f.MtimeNs != mtime {
		return false
	}
	return nullAsInt64(nullInt64(f.DeviceID)) == nullAsInt64(dev) &&
		nullAsInt64(nullInt64(f.Inode)) == nullAsInt64(ino)
}

// PrepareIndex 在任务进入 Hash 队列时调用，返回本次任务的 revision（CAS 凭据）。
//
// 去重规则（阻断 1 活锁修复）：同一文件、同一目标指纹、非强制的重复调度只刷新
// index_jobs 时间戳并沿用现有 revision——大文件 Hash 超过扫描间隔时，
// 周期扫描不会再推进 revision 打掉在途任务。
// 只有以下情况才推进 revision 并把位置置为 indexing：
//   - force=true（watcher 事件 / 标脏重建：内容可能已变化）；
//   - 目标指纹与在途任务不同（文件确实变了）；
//   - 该路径尚无任务或位置行。
//
// 同时让失去最后一个 valid 副本的内容立即降级——变更文件在重算完成前必须不可用。
func (d *DB) PrepareIndex(ctx context.Context, relativePath string, generation int64,
	now time.Time, fp TargetFingerprint, force bool) (int64, error) {

	forceFlag := 0
	if force {
		forceFlag = 1
	}
	return call(ctx, d.exec, func(ctx context.Context, db *sql.DB) (int64, error) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return 0, err
		}
		defer tx.Rollback()

		var currentRevision int64
		var hasLocation bool
		err = tx.QueryRowContext(ctx,
			`SELECT revision FROM file_locations WHERE relative_path = ?`, relativePath).Scan(&currentRevision)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			hasLocation = false
		case err != nil:
			return 0, fmt.Errorf("查询位置 %s 失败: %w", relativePath, err)
		default:
			hasLocation = true
		}

		// 已有同指纹的非强制任务：只刷新时间戳，revision 不变。
		if !force {
			var size, mtime int64
			var dev, ino sql.NullInt64
			jobErr := tx.QueryRowContext(ctx,
				`SELECT size_bytes, mtime_ns, device_id, inode FROM index_jobs WHERE relative_path = ?`,
				relativePath).Scan(&size, &mtime, &dev, &ino)
			hasJob := jobErr == nil
			if jobErr != nil && !errors.Is(jobErr, sql.ErrNoRows) {
				return 0, jobErr
			}
			if hasJob && fp.equal(size, mtime, dev.Int64, ino.Int64) {
				if _, err := tx.ExecContext(ctx,
					`UPDATE index_jobs SET updated_at = ? WHERE relative_path = ?`,
					now.UnixNano(), relativePath); err != nil {
					return 0, err
				}
				return currentRevision, tx.Commit()
			}
		}

		// 记录/更新任务目标指纹。
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO index_jobs(relative_path, size_bytes, mtime_ns, device_id, inode, forced, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(relative_path) DO UPDATE SET
			   size_bytes = excluded.size_bytes,
			   mtime_ns = excluded.mtime_ns,
			   device_id = excluded.device_id,
			   inode = excluded.inode,
			   forced = excluded.forced,
			   updated_at = excluded.updated_at`,
			relativePath, fp.SizeBytes, fp.MtimeNs, nullInt64(fp.DeviceID), nullInt64(fp.Inode),
			forceFlag, now.UnixNano()); err != nil {
			return 0, fmt.Errorf("记录索引任务 %s 失败: %w", relativePath, err)
		}

		var newRevision int64
		if hasLocation {
			if err := tx.QueryRowContext(ctx,
				`UPDATE file_locations SET state = 'indexing', revision = revision + 1
				 WHERE relative_path = ? RETURNING revision`, relativePath).Scan(&newRevision); err != nil {
				return 0, fmt.Errorf("准备索引任务 %s 失败: %w", relativePath, err)
			}
		} else {
			// 新文件：创建 indexing 占位行（无 seed_hash，不会对 MSFile 可见）。
			newRevision = 1
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO file_locations(relative_path, seed_hash, size_bytes, mtime_ns, state,
				    invalid_since, last_seen_generation, revision, last_error_zh)
				 VALUES (?, NULL, 0, 0, 'indexing', NULL, 0, 1, '')`, relativePath); err != nil {
				return 0, fmt.Errorf("创建索引占位 %s 失败: %w", relativePath, err)
			}
		}

		// 旧内容立即不可用：该位置不再是 valid 副本。
		if _, err := tx.ExecContext(ctx,
			`UPDATE contents SET state = 'invalid', updated_at = ?
			 WHERE state = 'ready'
			   AND NOT EXISTS (SELECT 1 FROM file_locations f
			                   WHERE f.seed_hash = contents.seed_hash AND f.state = 'valid')`,
			now.UnixNano()); err != nil {
			return 0, err
		}
		_ = generation
		return newRevision, tx.Commit()
	})
}

// SetLocationFailed 记录一个位置的处理失败状态；位置行不存在时创建占位行，
// 用于“超过协议最大源文件尺寸”等需要在管理台中文展示的情况。
// 该行没有 seed_hash，不会对 MSFile 可见。
// SetLocationFailed 记录一个位置的处理失败状态；位置行不存在时创建占位行，
// 用于“超过协议最大源文件尺寸”等需要在管理台中文展示的情况。
// 该行没有 seed_hash，不会对 MSFile 可见。ExpectedRevision CAS 与 MarkInvalidNow 一致。
func (d *DB) SetLocationFailed(ctx context.Context, relativePath string, sizeBytes, mtimeNs int64,
	errorZh string, expectedRevision int64) error {

	_, err := call(ctx, d.exec, func(ctx context.Context, db *sql.DB) (struct{}, error) {
		result, err := db.ExecContext(ctx,
			`INSERT INTO file_locations(relative_path, seed_hash, size_bytes, mtime_ns, state, revision, last_error_zh)
			 VALUES (?, NULL, ?, ?, 'error', 1, ?)
			 ON CONFLICT(relative_path) DO UPDATE SET
			   size_bytes = excluded.size_bytes,
			   mtime_ns = excluded.mtime_ns,
			   state = 'error',
			   last_error_zh = excluded.last_error_zh
			 WHERE file_locations.revision = ?`,
			relativePath, sizeBytes, mtimeNs, errorZh, expectedRevision)
		if err != nil {
			return struct{}{}, err
		}
		if affected, affectedErr := result.RowsAffected(); affectedErr != nil {
			return struct{}{}, affectedErr
		} else if affected == 0 {
			return struct{}{}, ErrRevisionStale
		}
		return struct{}{}, nil
	})
	return err
}

// ---------- 索引提交 ----------

// CommitParams 是 hash worker 完成磁盘计算后的一次性短事务提交。
type CommitParams struct {
	RelativePath     string // nas_data 内部相对路径
	SeedHash         string // 新计算的 seed_hash（64 位小写 hex）
	SeedLength       int    // MasterSeed 字节数
	SourceSize       int64  // 原文件尺寸
	Filename         string // 建议文件名
	MediaType        string // MIME 类型
	SizeBytes        int64  // stat C 确认的尺寸
	MtimeNs          int64  // stat C 确认的修改时间
	DeviceID         *int64
	Inode            *int64
	Generation       int64 // 触发本次任务的扫描批次（事件任务为 0）
	ExpectedRevision int64 // PrepareIndex 返回的任务版本；提交时 CAS 校验，不匹配返回 ErrRevisionStale
	Blocks           []SeedBlock
}

// CommitSeedResult 提交 contents + seed_blocks + file_locations。
// 全部在一个事务内；file_locations 更新带 ExpectedRevision CAS，
// 任务被更新调度取代时整体回滚并返回 ErrRevisionStale。
func (d *DB) CommitSeedResult(ctx context.Context, p CommitParams, now time.Time) error {
	_, err := call(ctx, d.exec, func(ctx context.Context, db *sql.DB) (struct{}, error) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return struct{}{}, err
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO contents(seed_hash, size_bytes, recommended_filename, media_type, state, created_at, updated_at)
			 VALUES (?, ?, ?, ?, 'ready', ?, ?)
			 ON CONFLICT(seed_hash) DO UPDATE SET
			   recommended_filename = excluded.recommended_filename,
			   media_type = excluded.media_type,
			   size_bytes = excluded.size_bytes,
			   state = 'ready',
			   updated_at = excluded.updated_at`,
			p.SeedHash, p.SourceSize, p.Filename, p.MediaType, now.UnixNano(), now.UnixNano()); err != nil {
			return struct{}{}, fmt.Errorf("写入 contents 失败: %w", err)
		}
		blockStatement, err := tx.PrepareContext(ctx,
			`INSERT INTO seed_blocks(seed_hash, block_index, block_hash, offset_bytes, length_bytes)
			 VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(seed_hash, block_index) DO UPDATE SET
			   block_hash = excluded.block_hash,
			   offset_bytes = excluded.offset_bytes,
			   length_bytes = excluded.length_bytes`)
		if err != nil {
			return struct{}{}, err
		}
		for _, block := range p.Blocks {
			if _, err := blockStatement.ExecContext(ctx, p.SeedHash, block.BlockIndex, block.BlockHash, block.OffsetBytes, block.LengthBytes); err != nil {
				blockStatement.Close()
				return struct{}{}, fmt.Errorf("写入 seed_blocks 失败: %w", err)
			}
		}
		if err := blockStatement.Close(); err != nil {
			return struct{}{}, err
		}
		result, err := tx.ExecContext(ctx,
			`INSERT INTO file_locations(relative_path, seed_hash, size_bytes, mtime_ns, device_id, inode,
			    state, invalid_since, last_seen_generation, revision, last_error_zh)
			 VALUES (?, ?, ?, ?, ?, ?, 'valid', NULL, CASE WHEN ? > 0 THEN ? ELSE 0 END, ?, '')
			 ON CONFLICT(relative_path) DO UPDATE SET
			   seed_hash = excluded.seed_hash,
			   size_bytes = excluded.size_bytes,
			   mtime_ns = excluded.mtime_ns,
			   device_id = excluded.device_id,
			   inode = excluded.inode,
			   state = 'valid',
			   invalid_since = NULL,
			   last_error_zh = '',
			   revision = file_locations.revision + 1,
			   last_seen_generation = CASE WHEN ? > 0 THEN ? ELSE last_seen_generation END
			 WHERE file_locations.revision = ?`,
			p.RelativePath, p.SeedHash, p.SizeBytes, p.MtimeNs, nullInt64(p.DeviceID), nullInt64(p.Inode),
			p.Generation, p.Generation, p.ExpectedRevision,
			p.Generation, p.Generation, p.ExpectedRevision)
		if err != nil {
			return struct{}{}, fmt.Errorf("更新 file_locations 失败: %w", err)
		}
		if affected, affectedErr := result.RowsAffected(); affectedErr != nil {
			return struct{}{}, affectedErr
		} else if affected == 0 {
			// CAS 失败：任务已被更新的调度取代，整体回滚，绝不覆盖新索引。
			return struct{}{}, ErrRevisionStale
		}
		// 提交事务内同步降级：位置改指新 Seed 后，旧内容可能不再有任何 valid 副本，
		// 否则 Web 统计与可用性判断会失真（次要问题一并修复）。
		if _, err := tx.ExecContext(ctx,
			`UPDATE contents SET state = 'invalid', updated_at = ?
			 WHERE state = 'ready'
			   AND NOT EXISTS (SELECT 1 FROM file_locations f
			                   WHERE f.seed_hash = contents.seed_hash AND f.state = 'valid')`,
			now.UnixNano()); err != nil {
			return struct{}{}, err
		}

		// 任务完成：清除目标指纹记录。
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM index_jobs WHERE relative_path = ?`, p.RelativePath); err != nil {
			return struct{}{}, err
		}
		return struct{}{}, tx.Commit()
	})
	return err
}

// ---------- Stat / Read 支撑 ----------

// ContentAvailability 描述一个 seed_hash 是否可以对外提供。
type ContentAvailability struct {
	Content       Content
	ValidReplicas int64
}

// GetAvailability 返回 ready 内容及其 valid 副本数；
// Stat 只有在 valid_replicas > 0 时才允许返回 available。
func (d *DB) GetAvailability(ctx context.Context, seedHash string) (ContentAvailability, error) {
	return call(ctx, d.exec, func(ctx context.Context, db *sql.DB) (ContentAvailability, error) {
		var out ContentAvailability
		var createdAt, updatedAt int64
		err := db.QueryRowContext(ctx,
			`SELECT c.seed_hash, c.size_bytes, c.recommended_filename, c.media_type, c.state, c.created_at, c.updated_at,
			        (SELECT count(*) FROM file_locations f WHERE f.seed_hash = c.seed_hash AND f.state = 'valid')
			 FROM contents c WHERE c.seed_hash = ?`, seedHash).
			Scan(&out.Content.SeedHash, &out.Content.SizeBytes, &out.Content.RecommendedFilename,
				&out.Content.MediaType, &out.Content.State, &createdAt, &updatedAt,
				&out.ValidReplicas)
		if errors.Is(err, sql.ErrNoRows) {
			return ContentAvailability{}, ErrNotFound
		}
		if err != nil {
			return ContentAvailability{}, err
		}
		out.Content.CreatedAt = scanTime(createdAt)
		out.Content.UpdatedAt = scanTime(updatedAt)
		return out, nil
	})
}

// BlockCandidates 返回一个块哈希的全部可用读取位置（最多 limit 个），
// 按 valid 副本优先排序，供 Reader 在坏副本之间回退。
func (d *DB) BlockCandidates(ctx context.Context, blockHash string, limit int) ([]BlockLocation, error) {
	if limit <= 0 {
		limit = 4
	}
	return call(ctx, d.exec, func(ctx context.Context, db *sql.DB) ([]BlockLocation, error) {
		rows, err := db.QueryContext(ctx,
			`SELECT f.relative_path, f.seed_hash, f.revision, b.offset_bytes, b.length_bytes
			 FROM seed_blocks b
			 JOIN contents c ON c.seed_hash = b.seed_hash AND c.state = 'ready'
			 JOIN file_locations f ON f.seed_hash = b.seed_hash AND f.state = 'valid'
			 WHERE b.block_hash = ?
			 ORDER BY f.invalid_since NULLS FIRST
			 LIMIT ?`, blockHash, limit)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		locations := make([]BlockLocation, 0, limit)
		for rows.Next() {
			var loc BlockLocation
			if err := rows.Scan(&loc.RelativePath, &loc.SeedHash, &loc.Revision,
				&loc.OffsetBytes, &loc.LengthBytes); err != nil {
				return nil, err
			}
			locations = append(locations, loc)
		}
		return locations, rows.Err()
	})
}

// ---------- 公共内容索引查询 ----------

// ListQuery 是内容索引列表过滤条件。
type ListQuery struct {
	Text          string // 匹配完整/前缀 Hash 或建议文件名
	State         string // 空 = 全部
	AvailableOnly bool   // 只返回至少有一个 valid 文件位置的 ready 内容
	Limit         int
	Offset        int
}

// ContentPage 是一次列表查询结果：行加总数。
type ContentPage struct {
	Items []ContentSummary // 当前行
	Total int64            // 过滤条件下的总行数
}

// ListContents 返回平面 Hash 列表；绝不包含绝对路径或内部相对路径。
func (d *DB) ListContents(ctx context.Context, q ListQuery, retention time.Duration, now time.Time) (ContentPage, error) {
	if q.Limit <= 0 || q.Limit > 200 {
		q.Limit = 50
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	return call(ctx, d.exec, func(ctx context.Context, db *sql.DB) (ContentPage, error) {
		text := "%" + strings.TrimSpace(q.Text) + "%"
		where := `WHERE (c.seed_hash LIKE ? OR c.recommended_filename LIKE ?)`
		args := []any{text, text}
		if q.State != "" {
			where += ` AND c.state = ?`
			args = append(args, q.State)
		}
		if q.AvailableOnly {
			where += ` AND c.state = ?
				AND EXISTS (SELECT 1 FROM file_locations f_available
				            WHERE f_available.seed_hash = c.seed_hash
				              AND f_available.state = 'valid')`
			args = append(args, StateReady)
		}
		var total int64
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM contents c `+where, args...).Scan(&total); err != nil {
			return ContentPage{}, err
		}
		query := `SELECT c.seed_hash, c.size_bytes, c.recommended_filename, c.media_type, c.state,
		        c.created_at, c.updated_at,
		        (SELECT count(*) FROM file_locations f WHERE f.seed_hash = c.seed_hash AND f.state = 'valid'),
		        (SELECT count(*) FROM file_locations f WHERE f.seed_hash = c.seed_hash AND f.state <> 'valid'),
		        (SELECT min(f.invalid_since) FROM file_locations f WHERE f.seed_hash = c.seed_hash)
		 FROM contents c ` + where + `
		 ORDER BY c.created_at DESC LIMIT ? OFFSET ?`
		rows, err := db.QueryContext(ctx, query, append(args, q.Limit, q.Offset)...)
		if err != nil {
			return ContentPage{}, err
		}
		defer rows.Close()
		items := make([]ContentSummary, 0, q.Limit)
		for rows.Next() {
			var item ContentSummary
			var createdAt, updatedAt int64
			var invalidSince sql.NullInt64
			if err := rows.Scan(&item.SeedHash, &item.SizeBytes, &item.RecommendedFilename, &item.MediaType,
				&item.State, &createdAt, &updatedAt, &item.ValidReplicas, &item.InvalidReplicas, &invalidSince); err != nil {
				return ContentPage{}, err
			}
			item.CreatedAt = time.Unix(0, createdAt)
			item.UpdatedAt = time.Unix(0, updatedAt)
			item.InvalidSince = nullableTime(invalidSince)
			if item.InvalidSince != nil && item.ValidReplicas == 0 {
				left := retention - now.Sub(*item.InvalidSince)
				if left < 0 {
					left = 0
				}
				item.RetentionLeftMs = left.Milliseconds()
			}
			items = append(items, item)
		}
		if err := rows.Err(); err != nil {
			return ContentPage{}, err
		}
		return ContentPage{Items: items, Total: total}, nil
	})
}

// ValidLocationPaths 返回某个内容当前全部 valid 文件位置的内部相对路径。
// 仅供公共下载在服务端选择副本使用，绝不直接写入 HTTP 响应。
func (d *DB) ValidLocationPaths(ctx context.Context, seedHash string) ([]string, error) {
	return call(ctx, d.exec, func(ctx context.Context, db *sql.DB) ([]string, error) {
		rows, err := db.QueryContext(ctx,
			`SELECT relative_path FROM file_locations
			 WHERE seed_hash = ? AND state = 'valid'
			 ORDER BY relative_path`, seedHash)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		paths := make([]string, 0, 2)
		for rows.Next() {
			var path string
			if err := rows.Scan(&path); err != nil {
				return nil, err
			}
			paths = append(paths, path)
		}
		return paths, rows.Err()
	})
}

// LocationDetail 是管理台单 Hash 详情中的一个位置行。
// 只包含内部相对路径（非绝对路径）与同步诊断信息。
type LocationDetail struct {
	RelativePath       string     `json:"relative_path"`           // nas_data 内部相对路径
	State              string     `json:"state"`                   // valid / invalid / indexing / error
	SizeBytes          int64      `json:"size_bytes"`              // 上次确认尺寸
	MtimeNs            int64      `json:"mtime_ns"`                // 上次确认修改时间
	InvalidSince       *time.Time `json:"invalid_since,omitempty"` // 第一次失效时间；valid 时为空
	LastSeenGeneration int64      `json:"last_seen_generation"`    // 最近一次成功扫描批次号
	LastErrorZh        string     `json:"last_error_zh"`           // 中文同步诊断
}

// contentDetail 聚合单 Hash 详情的内部返回结构。
type contentDetail struct {
	Summary   ContentSummary
	Locations []LocationDetail
}

// GetContentDetail 返回单 Hash 的内容摘要与其全部位置明细；
// 供 GET /api/files/{seed_hash} 使用，绝不返回绝对路径。
func (d *DB) GetContentDetail(ctx context.Context, seedHash string, retention time.Duration, now time.Time) (ContentSummary, []LocationDetail, error) {
	detail, err := call(ctx, d.exec, func(ctx context.Context, db *sql.DB) (contentDetail, error) {
		var summary ContentSummary
		var createdAt, updatedAt int64
		var invalidSince sql.NullInt64
		err := db.QueryRowContext(ctx, `SELECT c.seed_hash, c.size_bytes, c.recommended_filename, c.media_type, c.state,
		        c.created_at, c.updated_at,
		        (SELECT count(*) FROM file_locations f WHERE f.seed_hash = c.seed_hash AND f.state = 'valid'),
		        (SELECT count(*) FROM file_locations f WHERE f.seed_hash = c.seed_hash AND f.state <> 'valid'),
		        (SELECT min(f.invalid_since) FROM file_locations f WHERE f.seed_hash = c.seed_hash)
		 FROM contents c WHERE c.seed_hash = ?`, seedHash).
			Scan(&summary.SeedHash, &summary.SizeBytes, &summary.RecommendedFilename, &summary.MediaType,
				&summary.State, &createdAt, &updatedAt, &summary.ValidReplicas, &summary.InvalidReplicas, &invalidSince)
		if errors.Is(err, sql.ErrNoRows) {
			return contentDetail{}, ErrNotFound
		}
		if err != nil {
			return contentDetail{}, err
		}
		summary.CreatedAt = time.Unix(0, createdAt)
		summary.UpdatedAt = time.Unix(0, updatedAt)
		summary.InvalidSince = nullableTime(invalidSince)
		if summary.InvalidSince != nil && summary.ValidReplicas == 0 {
			left := retention - now.Sub(*summary.InvalidSince)
			if left < 0 {
				left = 0
			}
			summary.RetentionLeftMs = left.Milliseconds()
		}
		rows, err := db.QueryContext(ctx, `SELECT relative_path, state, size_bytes, mtime_ns,
		       invalid_since, last_seen_generation, last_error_zh
		 FROM file_locations WHERE seed_hash = ? ORDER BY relative_path`, seedHash)
		if err != nil {
			return contentDetail{}, err
		}
		defer rows.Close()
		locations := make([]LocationDetail, 0, 8)
		for rows.Next() {
			var loc LocationDetail
			var locInvalidSince sql.NullInt64
			if err := rows.Scan(&loc.RelativePath, &loc.State, &loc.SizeBytes, &loc.MtimeNs,
				&locInvalidSince, &loc.LastSeenGeneration, &loc.LastErrorZh); err != nil {
				return contentDetail{}, err
			}
			loc.InvalidSince = nullableTime(locInvalidSince)
			locations = append(locations, loc)
		}
		if err := rows.Err(); err != nil {
			return contentDetail{}, err
		}
		return contentDetail{Summary: summary, Locations: locations}, nil
	})
	if err != nil {
		return ContentSummary{}, nil, err
	}
	return detail.Summary, detail.Locations, nil
}

// StatusCounts 是管理台状态汇总。
type StatusCounts struct {
	TotalContents    int64 `json:"total_contents"`    // 内容总数
	ReadyContents    int64 `json:"ready_contents"`    // 可提供内容数
	InvalidContents  int64 `json:"invalid_contents"`  // 全部副本失效的内容数
	IndexingCount    int64 `json:"indexing_count"`    // 索引中数量
	ErrorCount       int64 `json:"error_count"`       // 错误数量
	ValidLocations   int64 `json:"valid_locations"`   // valid 位置数
	InvalidLocations int64 `json:"invalid_locations"` // invalid/error/indexing 位置数
}

// GetStatusCounts 返回管理台汇总数字。
func (d *DB) GetStatusCounts(ctx context.Context) (StatusCounts, error) {
	return call(ctx, d.exec, func(ctx context.Context, db *sql.DB) (StatusCounts, error) {
		var counts StatusCounts
		err := db.QueryRowContext(ctx, `SELECT
				count(*),
				coalesce(sum(state = 'ready'), 0),
				coalesce(sum(state IN ('invalid','indexing','error')), 0),
				coalesce(sum(state = 'indexing'), 0),
				coalesce(sum(state = 'error'), 0)
			FROM contents`).Scan(&counts.TotalContents, &counts.ReadyContents, &counts.InvalidContents,
			&counts.IndexingCount, &counts.ErrorCount)
		if err != nil {
			return counts, err
		}
		err = db.QueryRowContext(ctx, `SELECT
				coalesce(sum(state = 'valid'), 0),
				coalesce(sum(state <> 'valid'), 0)
			FROM file_locations`).Scan(&counts.ValidLocations, &counts.InvalidLocations)
		return counts, err
	})
}

// ---------- GC ----------

// ExpiredInvalidTargets 返回超过保留期仍 invalid 的位置（分批）。
func (d *DB) ExpiredInvalidLocations(ctx context.Context, cutoff time.Time, limit int) ([]FileLocation, error) {
	if limit <= 0 {
		limit = 200
	}
	return call(ctx, d.exec, func(ctx context.Context, db *sql.DB) ([]FileLocation, error) {
		rows, err := db.QueryContext(ctx,
			`SELECT relative_path, coalesce(seed_hash,''), size_bytes, mtime_ns, state, revision, last_error_zh
			 FROM file_locations
			 WHERE state = 'invalid' AND invalid_since IS NOT NULL AND invalid_since <= ?
			 LIMIT ?`, cutoff.UnixNano(), limit)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		locations := make([]FileLocation, 0, limit)
		for rows.Next() {
			var loc FileLocation
			if err := rows.Scan(&loc.RelativePath, &loc.SeedHash, &loc.SizeBytes, &loc.MtimeNs,
				&loc.State, &loc.Revision, &loc.LastErrorZh); err != nil {
				return nil, err
			}
			locations = append(locations, loc)
		}
		return locations, rows.Err()
	})
}

// LocationDeleteTarget 是一次受守卫的过期位置删除：
// revision 必须与快照一致，防止 GC 误删快照之后已恢复或被重新索引的位置。
type LocationDeleteTarget struct {
	RelativePath string
	Revision     int64
}

// DeleteLocations 在一个事务内删除过期 invalid 位置。
// 删除条件同时校验 relative_path、state='invalid'、invalid_since<=cutoff、revision=expected，
// 快照之后恢复为 valid 或被新任务取代（revision 变化）的位置一律跳过。
// 返回因此不再被任何位置引用的 seed_hash 列表；只清理派生数据，绝不触碰 nas_data 原文件。
func (d *DB) DeleteLocations(ctx context.Context, targets []LocationDeleteTarget, cutoff time.Time) ([]string, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	return call(ctx, d.exec, func(ctx context.Context, db *sql.DB) ([]string, error) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		orphanSeeds := make([]string, 0, len(targets))
		deleteStatement, err := tx.PrepareContext(ctx,
			`DELETE FROM file_locations
			 WHERE relative_path = ? AND state = 'invalid'
			   AND invalid_since IS NOT NULL AND invalid_since <= ? AND revision = ?
			 RETURNING seed_hash`)
		if err != nil {
			return nil, err
		}
		defer deleteStatement.Close()
		orphanStatement, err := tx.PrepareContext(ctx,
			`SELECT c.seed_hash FROM contents c
			 WHERE c.seed_hash = ? AND NOT EXISTS (SELECT 1 FROM file_locations f WHERE f.seed_hash = c.seed_hash)`)
		if err != nil {
			return nil, err
		}
		defer orphanStatement.Close()
		for _, target := range targets {
			var seedHash sql.NullString
			if err := deleteStatement.QueryRowContext(ctx, target.RelativePath, cutoff.UnixNano(), target.Revision).Scan(&seedHash); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					continue // 守卫未命中：快照后状态已变化，交给下一轮收敛
				}
				return nil, fmt.Errorf("删除位置 %s 失败: %w", target.RelativePath, err)
			}
			if !seedHash.Valid || seedHash.String == "" {
				continue // 占位失败行没有关联内容
			}
			var orphan string
			scanErr := orphanStatement.QueryRowContext(ctx, seedHash.String).Scan(&orphan)
			if errors.Is(scanErr, sql.ErrNoRows) {
				continue
			}
			if scanErr != nil {
				return nil, scanErr
			}
			orphanSeeds = append(orphanSeeds, orphan)
		}
		return orphanSeeds, tx.Commit()
	})
}

// FilterUnreferenced 返回输入中当前不被任何位置引用的 seed_hash。
// 必须在 Seed 生命周期锁内调用：保证与 worker 的 Publish->Commit 串行，
// 过滤结果才是删除前的最终真值。
func (d *DB) FilterUnreferenced(ctx context.Context, seedHashes []string) ([]string, error) {
	if len(seedHashes) == 0 {
		return nil, nil
	}
	return call(ctx, d.exec, func(ctx context.Context, db *sql.DB) ([]string, error) {
		statement, err := db.PrepareContext(ctx,
			// 保守判定：任何状态（含 indexing）的位置行引用都阻止删除；
			// 该查询必须在 Seed 生命周期锁内执行，与提交串行后结果才可靠。
			`SELECT count(*) FROM file_locations f WHERE f.seed_hash = ?`)
		if err != nil {
			return nil, err
		}
		defer statement.Close()
		out := make([]string, 0, len(seedHashes))
		for _, hash := range seedHashes {
			var refs int64
			if err := statement.QueryRowContext(ctx, hash).Scan(&refs); err != nil {
				return nil, err
			}
			if refs == 0 {
				out = append(out, hash)
			}
		}
		return out, nil
	})
}

func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// OrphanContents 返回没有任何位置引用、且超过 grace 未更新的内容（延迟清理孤儿 Seed）。
func (d *DB) OrphanContents(ctx context.Context, olderThan time.Time, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 200
	}
	return call(ctx, d.exec, func(ctx context.Context, db *sql.DB) ([]string, error) {
		rows, err := db.QueryContext(ctx,
			`SELECT c.seed_hash FROM contents c
			 WHERE NOT EXISTS (SELECT 1 FROM file_locations f WHERE f.seed_hash = c.seed_hash)
			   AND c.updated_at <= ?
			 LIMIT ?`, olderThan.UnixNano(), limit)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		hashes := make([]string, 0, limit)
		for rows.Next() {
			var h string
			if err := rows.Scan(&h); err != nil {
				return nil, err
			}
			hashes = append(hashes, h)
		}
		return hashes, rows.Err()
	})
}

// DeleteContents 删除内容与其块映射（seed_blocks 由外键级联删除）。
// 调用方负责先把 .seed 文件移入 trash。
func (d *DB) DeleteContents(ctx context.Context, seedHashes []string) error {
	if len(seedHashes) == 0 {
		return nil
	}
	_, err := call(ctx, d.exec, func(ctx context.Context, db *sql.DB) (struct{}, error) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return struct{}{}, err
		}
		defer tx.Rollback()
		statement, err := tx.PrepareContext(ctx,
			// 删除前再次校验无位置引用，绝不按旧快照无条件删除（阻断 2 防线之二）。
			`DELETE FROM contents
			 WHERE seed_hash = ?
			   AND NOT EXISTS (SELECT 1 FROM file_locations f WHERE f.seed_hash = contents.seed_hash)`)
		if err != nil {
			return struct{}{}, err
		}
		defer statement.Close()
		for _, hash := range seedHashes {
			if _, err := statement.ExecContext(ctx, hash); err != nil {
				return struct{}{}, fmt.Errorf("删除内容 %s 失败: %w", hash, err)
			}
		}
		return struct{}{}, tx.Commit()
	})
	return err
}

// AllContentHashes 返回 contents 表中的全部 seed_hash 集合，
// 供 GC 磁盘孤儿扫描比对；V1 内容量级下一次性载入内存可接受。
func (d *DB) AllContentHashes(ctx context.Context) (map[string]struct{}, error) {
	return call(ctx, d.exec, func(ctx context.Context, db *sql.DB) (map[string]struct{}, error) {
		rows, err := db.QueryContext(ctx, `SELECT seed_hash FROM contents`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := make(map[string]struct{}, 1024)
		for rows.Next() {
			var h string
			if err := rows.Scan(&h); err != nil {
				return nil, err
			}
			out[h] = struct{}{}
		}
		return out, rows.Err()
	})
}

// MarkContentError 在 Seed 文件缺失或完整性失败时调用：
// 事务内把内容置为 error，后续 Stat 立即返回 absent（阻断 2）。
func (d *DB) MarkContentError(ctx context.Context, seedHash, reasonZh string, now time.Time) error {
	_, err := call(ctx, d.exec, func(ctx context.Context, db *sql.DB) (struct{}, error) {
		_, err := db.ExecContext(ctx,
			`UPDATE contents SET state = 'error', updated_at = ? WHERE seed_hash = ?`,
			now.UnixNano(), seedHash)
		return struct{}{}, err
	})
	return err
}

// LocationsOfSeed 返回该 Seed 当前全部非 indexing 位置的相对路径，
// 供 Seed 损坏后调度重建使用。
func (d *DB) LocationsOfSeed(ctx context.Context, seedHash string) ([]string, error) {
	return call(ctx, d.exec, func(ctx context.Context, db *sql.DB) ([]string, error) {
		rows, err := db.QueryContext(ctx,
			`SELECT relative_path FROM file_locations
			 WHERE seed_hash = ? AND state IN ('valid','invalid','error')`, seedHash)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var p string
			if err := rows.Scan(&p); err != nil {
				return nil, err
			}
			out = append(out, p)
		}
		return out, rows.Err()
	})
}

// RecoverStaleIndexing 在服务启动时调用（阻断 1 配套）：
// 上次进程中断可能把位置留在 indexing 且其 index_jobs 目标已不可信。
// 处理方式：清空全部任务记录，把 indexing 位置转为 invalid——
// 下一轮全量扫描中指纹一致者自动确认复用，变化者重新计算。
func (d *DB) RecoverStaleIndexing(ctx context.Context, now time.Time) error {
	_, err := call(ctx, d.exec, func(ctx context.Context, db *sql.DB) (struct{}, error) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return struct{}{}, err
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, `DELETE FROM index_jobs`); err != nil {
			return struct{}{}, err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE file_locations SET state = 'invalid', last_error_zh = ?
			 WHERE state = 'indexing'`, "进程中断，上次索引任务作废"); err != nil {
			return struct{}{}, err
		}
		return struct{}{}, tx.Commit()
	})
	return err
}
