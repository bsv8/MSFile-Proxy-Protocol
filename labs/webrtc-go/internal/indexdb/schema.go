package indexdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SchemaVersion 是当前唯一支持的 schema 版本。
// 硬切换不允许原地改写不兼容旧 schema；检测到旧表时必须中文报错并拒绝启动。
// v2：新增 index_jobs 表（任务目标指纹去重，阻断 1 活锁修复），纯增量迁移。
const SchemaVersion = 2

// ErrIncompatibleSchema 表示数据库里存在旧版（objects 仓库 / clients 白名单）schema。
var ErrIncompatibleSchema = errors.New("检测到不兼容的旧版数据库：该 SQLite 包含旧对象仓库或 clients 白名单表。" +
	"V1 硬切换不支持自动迁移；请备份后改用空的 seed_data 目录重新建立索引")

const schemaStatements = `
CREATE TABLE IF NOT EXISTS meta (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS contents (
	seed_hash TEXT PRIMARY KEY CHECK(length(seed_hash) = 64),
	size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
	recommended_filename TEXT NOT NULL DEFAULT '',
	media_type TEXT NOT NULL DEFAULT '',
	state TEXT NOT NULL CHECK(state IN ('ready','invalid','indexing','error')),
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS file_locations (
	relative_path TEXT PRIMARY KEY,
	seed_hash TEXT REFERENCES contents(seed_hash) ON DELETE SET NULL,
	size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
	mtime_ns INTEGER NOT NULL CHECK(mtime_ns >= 0),
	device_id INTEGER,
	inode INTEGER,
	state TEXT NOT NULL CHECK(state IN ('valid','invalid','indexing','error')),
	invalid_since INTEGER,
	last_seen_generation INTEGER NOT NULL DEFAULT 0 CHECK(last_seen_generation >= 0),
	revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0),
	last_error_zh TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX IF NOT EXISTS file_locations_seed_state_idx ON file_locations(seed_hash, state);
CREATE INDEX IF NOT EXISTS file_locations_generation_idx ON file_locations(last_seen_generation);
CREATE INDEX IF NOT EXISTS file_locations_invalid_since_idx ON file_locations(invalid_since);

CREATE TABLE IF NOT EXISTS seed_blocks (
	seed_hash TEXT NOT NULL REFERENCES contents(seed_hash) ON DELETE CASCADE,
	block_index INTEGER NOT NULL CHECK(block_index >= 0),
	block_hash TEXT NOT NULL CHECK(length(block_hash) = 64),
	offset_bytes INTEGER NOT NULL CHECK(offset_bytes >= 0),
	length_bytes INTEGER NOT NULL CHECK(length_bytes BETWEEN 1 AND 262144),
	PRIMARY KEY (seed_hash, block_index)
) STRICT;

CREATE INDEX IF NOT EXISTS seed_blocks_block_hash_idx ON seed_blocks(block_hash);

CREATE TABLE IF NOT EXISTS scan_runs (
	generation INTEGER PRIMARY KEY,
	started_at INTEGER NOT NULL,
	finished_at INTEGER,
	status TEXT NOT NULL CHECK(status IN ('running','succeeded','partial','failed')),
	error_zh TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE TABLE IF NOT EXISTS index_jobs (
	relative_path TEXT PRIMARY KEY,
	size_bytes INTEGER NOT NULL DEFAULT 0 CHECK(size_bytes >= 0),
	mtime_ns INTEGER NOT NULL DEFAULT 0 CHECK(mtime_ns >= 0),
	device_id INTEGER,
	inode INTEGER,
	forced INTEGER NOT NULL DEFAULT 0 CHECK(forced IN (0,1)),
	updated_at INTEGER NOT NULL
) STRICT;
`

// openRaw 打开底层连接、校验 schema 并应用 PRAGMA；只允许在启动阶段调用一次。
// 对瞬时 SQLITE_BUSY（前一个进程尚未完全释放文件锁）做有界重试，
// 但不兼容 schema 等永久性错误立即返回。
func openRaw(path string) (*sql.DB, error) {
	var lastErr error
	for attempt := 0; attempt < 8; attempt++ {
		raw, err := openSQLDB(path)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		migrateErr := configureAndMigrate(ctx, raw)
		cancel()
		if migrateErr == nil {
			return raw, nil
		}
		_ = raw.Close()
		lastErr = migrateErr
		busy := strings.Contains(migrateErr.Error(), "locked") ||
			strings.Contains(migrateErr.Error(), "busy") ||
			strings.Contains(migrateErr.Error(), "SQLITE_BUSY")
		if !busy {
			return nil, migrateErr
		}
		time.Sleep(time.Duration(attempt+1) * 150 * time.Millisecond)
	}
	return nil, fmt.Errorf("数据库持续被占用（可能有旧进程未退出）: %w", lastErr)
}

func configureAndMigrate(ctx context.Context, raw *sql.DB) error {
	for _, pragma := range []string{
		`PRAGMA journal_mode = WAL`,   // WAL 提升并发读
		`PRAGMA synchronous = NORMAL`, // 配合 WAL 的持久化级别
		`PRAGMA foreign_keys = ON`,    // 强制外键约束
		`PRAGMA busy_timeout = 5000`,  // 5 秒锁等待
	} {
		if _, err := raw.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("初始化 SQLite PRAGMA 失败: %w", err)
		}
	}
	if err := detectLegacySchema(ctx, raw); err != nil {
		return err
	}
	var version string
	err := raw.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'schema_version'`).Scan(&version)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if err := createSchema(ctx, raw); err != nil {
			return err
		}
	case err != nil:
		// meta 表不存在也视为全新数据库
		if !strings.Contains(err.Error(), "no such table") {
			return fmt.Errorf("读取 schema 版本失败: %w", err)
		}
		if err := createSchema(ctx, raw); err != nil {
			return err
		}
	default:
		if version == fmt.Sprintf("%d", SchemaVersion-1) {
			// 相邻版本的纯增量迁移：只允许 CREATE TABLE IF NOT EXISTS 类语句。
			if err := createSchema(ctx, raw); err != nil {
				return err
			}
		} else if version != fmt.Sprintf("%d", SchemaVersion) {
			return fmt.Errorf("检测到未知 schema 版本 %q（期望 %d）；请备份后使用空 seed_data 重建索引", version, SchemaVersion)
		}
	}
	return nil
}

// detectLegacySchema 在建新表之前检查旧方向遗留的表；
// 命中即 fail closed，绝不自动删除或原地转换。
func detectLegacySchema(ctx context.Context, raw *sql.DB) error {
	rows, err := raw.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		return fmt.Errorf("检查数据库 schema 失败: %w", err)
	}
	defer rows.Close()
	legacy := make([]string, 0, 3)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		switch name {
		case "files", "objects", "file_objects", "clients":
			legacy = append(legacy, name)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(legacy) > 0 {
		return fmt.Errorf("%w（发现旧表：%s）", ErrIncompatibleSchema, strings.Join(legacy, ", "))
	}
	return nil
}

func createSchema(ctx context.Context, raw *sql.DB) error {
	for _, statement := range strings.Split(schemaStatements, ";") {
		trimmed := strings.TrimSpace(statement)
		if trimmed == "" {
			continue
		}
		if _, err := raw.ExecContext(ctx, trimmed); err != nil {
			return fmt.Errorf("初始化 SQLite schema 失败: %w", err)
		}
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO meta(key, value) VALUES ('schema_version', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, fmt.Sprintf("%d", SchemaVersion)); err != nil {
		return fmt.Errorf("写入 schema 版本失败: %w", err)
	}
	return nil
}
