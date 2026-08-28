// Package content 实现冻结需求 §3/§7.3 的原文件读取路径：
//
//	Read(seed_hash)  -> 从 seed_data 的 .seed 文件返回（要求至少一个 valid 位置）
//	Read(block_hash) -> SQLite 查询一个 valid 原文件位置、块偏移和长度
//	                    -> 对 nas_data 原文件执行 ReadAt(offset, length)
//	                    -> 校验 SHA-256(bytes) == requested block_hash
//
// 禁止：为每个块永久生成对象文件；未校验 Hash 就返回字节；
// 把内部相对路径或 .seed 路径放进 MSFile wire。
package content

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"msfile.dev/labs/webrtc-go/internal/indexdb"
	"msfile.dev/labs/webrtc-go/internal/safefs"
	"msfile.dev/labs/webrtc-go/internal/seed"
)

// readBlockAt 打开一个记录位置，ReadAt 精确长度并校验 Hash。
// 打开动作全部经 safefs.Root 完成：拒绝中间/最终符号链接与任何路径逃逸，
// 并校验打开前后 inode 一致；Hash 不符时调用方必须标脏该位置。
func (r *Reader) readBlockAt(relativePath string, offset, length int64, blockHashHex string) ([]byte, error) {
	file, info, err := r.root.OpenFile(relativePath)
	if err != nil {
		return nil, fmt.Errorf("安全打开原文件失败: %w", err)
	}
	defer file.Close()
	if offset < 0 || length <= 0 || offset+length > info.Size() {
		return nil, fmt.Errorf("块偏移 %d+%d 超出当前文件尺寸 %d", offset, length, info.Size())
	}
	buf := make([]byte, length)
	read, err := file.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("ReadAt 失败: %w", err)
	}
	if int64(read) != length {
		return nil, fmt.Errorf("%w：%d/%d 字节", errShortRead, read, length)
	}
	digest := sha256.Sum256(buf[:read])
	if hex.EncodeToString(digest[:]) != blockHashHex {
		return nil, errMismatchedHash
	}
	return buf[:read], nil
}

var (
	// ErrContentNotFound 表示当前无法找到指定哈希的内容。
	ErrContentNotFound = errors.New("没有找到指定哈希的内容")
	// ErrUnavailable 表示内容已索引但所有位置都不可用；不得返回损坏字节。
	ErrUnavailable = errors.New("内容当前没有任何可用副本")
	// ErrIntegrity 表示读到的字节与请求 Hash 不一致，必须 fail closed。
	ErrIntegrity = errors.New("内容完整性校验失败")
)

// StatInfo 是 Stat available 响应需要的元数据。
type StatInfo struct {
	Filename  string // 建议文件名
	SizeBytes int64  // 原文件尺寸
	MediaType string // MIME 类型
}

// DirtyListener 接收读取过程中的标脏事件（阻断 2）：
//   - MarkSeedDirty：Seed 文件缺失或完整性失败——协调器必须立即把内容置为
//     error（Stat 转为 absent）并调度全部原文件位置强制重建；
//   - MarkLocationDirty：单个原文件位置读取或校验失败——标脏该位置并重索引。
//
// 不再使用“空路径表示 Seed 损坏”的隐式约定。
type DirtyListener interface {
	MarkSeedDirty(seedHashHex, reasonZh string)
	// MarkLocationDirty 携带候选时刻的 seed_hash 与 revision：
	// 协调器据此做 CAS 标脏，旧 Read 无法打脏已被新索引提交取代的位置。
	MarkLocationDirty(relativePath, seedHashHex string, revision int64, reasonZh string)
}

// Reader 是 MSFile 服务端的内容真值入口。
type Reader struct {
	db    *indexdb.DB
	root  *safefs.Root
	store *seed.Store
	dirty DirtyListener
}

// New 创建 Reader。root 必须是绑定到已校验 nas_data 的安全打开入口；
// 所有原文件读取都经由它完成，杜绝中间目录符号链接逃逸。
func New(root *safefs.Root, db *indexdb.DB, store *seed.Store, dirty DirtyListener) *Reader {
	return &Reader{db: db, root: root, store: store, dirty: dirty}
}

// Stat 返回 ready 且至少有一个 valid 位置的内容元数据。
// 所有位置 invalid/indexing/error 时返回 false——
// 即使 .seed 文件仍在 24 小时保留期，也不得对外声称 available。
func (r *Reader) Stat(ctx context.Context, seedHashHex string) (StatInfo, bool, error) {
	availability, err := r.db.GetAvailability(ctx, strings.ToLower(seedHashHex))
	if errors.Is(err, indexdb.ErrNotFound) {
		return StatInfo{}, false, nil
	}
	if err != nil {
		return StatInfo{}, false, err
	}
	if availability.Content.State != indexdb.StateReady || availability.ValidReplicas == 0 {
		return StatInfo{}, false, nil
	}
	return StatInfo{
		Filename:  availability.Content.RecommendedFilename,
		SizeBytes: availability.Content.SizeBytes,
		MediaType: availability.Content.MediaType,
	}, true, nil
}

// ReadSeed 返回 MasterSeed 字节。
// 内容必须 ready 且至少一个位置 valid；.seed 文件逐字节校验 SHA-256。
func (r *Reader) ReadSeed(ctx context.Context, seedHashHex string) ([]byte, error) {
	availability, err := r.db.GetAvailability(ctx, strings.ToLower(seedHashHex))
	if errors.Is(err, indexdb.ErrNotFound) {
		return nil, ErrContentNotFound
	}
	if err != nil {
		return nil, err
	}
	if availability.Content.State != indexdb.StateReady || availability.ValidReplicas == 0 {
		return nil, fmt.Errorf("%w：%s", ErrUnavailable, seedHashHex)
	}
	data, err := r.store.ReadSeed(strings.ToLower(seedHashHex))
	if err != nil {
		switch {
		case errors.Is(err, seed.ErrIntegrity), errors.Is(err, seed.ErrNotFound):
			// Seed 缺失或损坏：通知协调器把内容置为 error 并强制重建；
			// 绝不返回坏字节，也绝不让 Stat 继续声称 available。
			r.markSeedDirty(strings.ToLower(seedHashHex), "Seed 文件缺失或完整性校验失败")
			if errors.Is(err, seed.ErrNotFound) {
				return nil, ErrContentNotFound
			}
			return nil, ErrIntegrity
		default:
			return nil, err
		}
	}
	return data, nil
}

// OpenFileForDownload 打开一个当前可用内容的原文件副本。
//
// 只允许 ready 且至少有一个 valid 位置的内容；候选路径来自 SQLite，
// 实际打开仍然必须经过 safefs.Root，避免下载接口绕过路径安全检查。
// 返回的文件句柄由调用方负责关闭。
func (r *Reader) OpenFileForDownload(ctx context.Context, seedHashHex string) (*os.File, StatInfo, error) {
	seedHashHex = strings.ToLower(strings.TrimSpace(seedHashHex))
	availability, err := r.db.GetAvailability(ctx, seedHashHex)
	if errors.Is(err, indexdb.ErrNotFound) {
		return nil, StatInfo{}, ErrContentNotFound
	}
	if err != nil {
		return nil, StatInfo{}, err
	}
	if availability.Content.State != indexdb.StateReady || availability.ValidReplicas == 0 {
		return nil, StatInfo{}, fmt.Errorf("%w：%s", ErrUnavailable, seedHashHex)
	}

	paths, err := r.db.ValidLocationPaths(ctx, seedHashHex)
	if err != nil {
		return nil, StatInfo{}, err
	}
	var lastErr error
	for _, path := range paths {
		file, info, openErr := r.root.OpenFile(path)
		if openErr != nil {
			lastErr = openErr
			continue
		}
		// 索引尺寸与当前打开文件不一致时，拒绝下载这份可能已变化的内容。
		if info.Size() != availability.Content.SizeBytes {
			_ = file.Close()
			lastErr = fmt.Errorf("文件尺寸已变化：索引 %d，当前 %d",
				availability.Content.SizeBytes, info.Size())
			continue
		}
		return file, StatInfo{
			Filename:  availability.Content.RecommendedFilename,
			SizeBytes: info.Size(),
			MediaType: availability.Content.MediaType,
		}, nil
	}

	if lastErr != nil {
		return nil, StatInfo{}, fmt.Errorf("%w：有效副本无法读取：%v", ErrUnavailable, lastErr)
	}
	return nil, StatInfo{}, fmt.Errorf("%w：没有可读取副本", ErrUnavailable)
}

// ReadBlock 按块 Hash 从一个 valid 原文位置读取 exact 字节并校验 SHA-256。
// 当前副本失败时自动回退到下一个 valid 副本；全部失败返回 integrity_error。
func (r *Reader) ReadBlock(ctx context.Context, blockHashHex string) ([]byte, error) {
	blockHashHex = strings.ToLower(blockHashHex)
	candidates, err := r.db.BlockCandidates(ctx, blockHashHex, 4)
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, ErrContentNotFound
	}
	var lastErr error
	for _, candidate := range candidates {
		data, readErr := r.readBlockAt(candidate.RelativePath, candidate.OffsetBytes, candidate.LengthBytes, blockHashHex)
		if readErr == nil {
			return data, nil
		}
		lastErr = readErr
		r.markLocationDirty(candidate.RelativePath, candidate.SeedHash,
			candidate.Revision, "块读取或校验失败："+readErr.Error())
	}
	if errors.Is(lastErr, ErrIntegrity) || isIntegrityCause(lastErr) {
		return nil, ErrIntegrity
	}
	return nil, fmt.Errorf("%w：%v", ErrIntegrity, lastErr)
}

// Resolve 统一处理 Read 请求：先按 Seed 查，再按块查。
func (r *Reader) Resolve(ctx context.Context, hashHex string) ([]byte, error) {
	hashHex = strings.ToLower(hashHex)
	if _, ok, err := r.Stat(ctx, hashHex); err != nil {
		return nil, err
	} else if ok {
		return r.ReadSeed(ctx, hashHex)
	}
	return r.ReadBlock(ctx, hashHex)
}

func (r *Reader) markSeedDirty(seedHashHex, reasonZh string) {
	if r.dirty != nil {
		r.dirty.MarkSeedDirty(seedHashHex, reasonZh)
	}
}

func (r *Reader) markLocationDirty(relativePath, seedHashHex string, revision int64, reasonZh string) {
	if r.dirty != nil {
		r.dirty.MarkLocationDirty(relativePath, seedHashHex, revision, reasonZh)
	}
}

func isIntegrityCause(err error) bool {
	for _, cause := range []error{errMismatchedHash, errShortRead} {
		if errors.Is(err, cause) {
			return true
		}
	}
	return false
}

var (
	errMismatchedHash = errors.New("块内容 SHA-256 与请求 Hash 不一致")
	errShortRead      = errors.New("原文件读取字节数不足")
)
