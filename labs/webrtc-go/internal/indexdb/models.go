package indexdb

// 本文件定义平面 Hash 模型的全部行结构与中文说明。
// 不存在目录节点、父子目录表或目录树对象；
// relative_path 只是 nas_data 内部相对路径，不是内容身份，也不进入 MSFile wire。

import "time"

// 内容状态（contents.state）。
const (
	StateReady    = "ready"    // Seed 与块索引有效
	StateInvalid  = "invalid"  // 没有任何可用副本
	StateIndexing = "indexing" // 正在计算或等待稳定性确认
	StateError    = "error"    // 最近一次处理失败
)

// 位置状态（file_locations.state）。
const (
	LocationValid    = "valid"    // 路径当前可见且指纹一致
	LocationInvalid  = "invalid"  // 扫描或事件确认路径不可见；进入 24 小时保留期
	LocationIndexing = "indexing" // 该位置正在重新计算
	LocationError    = "error"    // 该位置最近一次读取或索引失败
)

// 扫描状态（scan_runs.status）。
const (
	ScanRunning   = "running"
	ScanSucceeded = "succeeded"
	ScanPartial   = "partial"
	ScanFailed    = "failed"
)

// Content 是 contents 表的一行：内容真值以 seed_hash 为主键的平面记录。
type Content struct {
	SeedHash            string    `json:"seed_hash"`            // 内容唯一标识，64 位小写 hex
	SizeBytes           int64     `json:"size_bytes"`           // 原文件尺寸
	RecommendedFilename string    `json:"recommended_filename"` // Stat 建议文件名，取一个可用位置的 basename
	MediaType           string    `json:"media_type"`           // MIME 类型
	State               string    `json:"state"`                // ready / invalid / indexing / error
	CreatedAt           time.Time `json:"created_at"`           // 首次索引时间
	UpdatedAt           time.Time `json:"updated_at"`           // 最近状态更新时间
}

// FileLocation 是 file_locations 表的一行：nas_data 内部相对路径到内容的映射。
type FileLocation struct {
	RelativePath       string     `json:"relative_path"`           // nas_data 内部相对路径（不是 Web 目录模型）
	SeedHash           string     `json:"seed_hash"`               // 指向 contents；尚未提交时为空
	SizeBytes          int64      `json:"size_bytes"`              // 上次确认尺寸
	MtimeNs            int64      `json:"mtime_ns"`                // 上次确认修改时间（UnixNano）
	DeviceID           *int64     `json:"device_id,omitempty"`     // 文件系统提供时记录
	Inode              *int64     `json:"inode,omitempty"`         // 文件系统提供且稳定时记录
	State              string     `json:"state"`                   // valid / invalid / indexing / error
	InvalidSince       *time.Time `json:"invalid_since,omitempty"` // 第一次确认不可见的时间；valid 时为空
	LastSeenGeneration int64      `json:"last_seen_generation"`    // 最近一次成功扫描批次号
	Revision           int64      `json:"revision"`                // 同一路径任务淘汰计数
	LastErrorZh        string     `json:"last_error_zh"`           // 中文同步诊断
}

// Fingerprint 是扫描比对用的位置指纹。
type Fingerprint struct {
	RelativePath string
	SeedHash     string
	SizeBytes    int64
	MtimeNs      int64
	State        string
	Revision     int64
	DeviceID     *int64 // 文件系统提供时记录；用于“恢复且指纹一致”判定
	Inode        *int64 // 文件系统提供且稳定时记录；NAS 上可能为空
}

// SeedBlock 是 seed_blocks 表的一行。
type SeedBlock struct {
	SeedHash    string `json:"seed_hash"`    // 所属 Seed
	BlockIndex  int64  `json:"block_index"`  // 从 0 开始的块序号
	BlockHash   string `json:"block_hash"`   // 64 位小写 hex
	OffsetBytes int64  `json:"offset_bytes"` // block_index * 262144
	LengthBytes int64  `json:"length_bytes"` // 1..262144；空文件没有记录
}

// ScanRun 是 scan_runs 表的一行。
type ScanRun struct {
	Generation int64      `json:"generation"`            // 单调递增扫描批次号
	StartedAt  time.Time  `json:"started_at"`            // 扫描开始时间
	FinishedAt *time.Time `json:"finished_at,omitempty"` // 扫描完成时间
	Status     string     `json:"status"`                // running / succeeded / partial / failed
	ErrorZh    string     `json:"error_zh"`              // 中文诊断
}

// BlockLocation 是块读取的一个候选位置：从哪个原文件的哪个偏移读取该块。
// SeedHash 与 Revision 用于读取失败时的标脏 CAS（阻断 2）。
type BlockLocation struct {
	RelativePath string `json:"relative_path"` // nas_data 内部相对路径
	SeedHash     string `json:"-"`             // 候选时刻该位置指向的内容
	Revision     int64  `json:"-"`             // 候选时刻的位置版本
	OffsetBytes  int64  `json:"offset_bytes"`  // block_index * 262144
	LengthBytes  int64  `json:"length_bytes"`  // 1..262144
}

// ContentSummary 是内容索引列表行：contents 加上可用副本数。
type ContentSummary struct {
	Content
	ValidReplicas   int        `json:"valid_replicas"`          // valid 状态的位置数量
	InvalidReplicas int        `json:"invalid_replicas"`        // invalid/error/indexing 位置数量
	InvalidSince    *time.Time `json:"invalid_since,omitempty"` // 全部失效时的第一次失效时间
	RetentionLeftMs int64      `json:"retention_left_ms"`       // 剩余保留毫秒数；非负
}
