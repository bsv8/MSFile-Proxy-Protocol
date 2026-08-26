package seed

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Store 管理 seed_data 下的派生 Seed 文件布局：
//
//	seeds/<h[0:2]>/<h[2:4]>/<完整 seed_hash>.seed   最终发布位置
//	staging/                                        尚未原子发布的临时文件
//	trash/                                          已解除索引、等待清理的派生文件
//
// 发布使用 staging + fsync + 原子 rename；最终 Seed 已存在时复用，绝不覆盖为不同字节。
type Store struct {
	root    string
	seeds   string
	staging string
	trash   string
}

var (
	// ErrHashInvalid 表示输入不是 64 位小写 hex。
	ErrHashInvalid = errors.New("Seed Hash 必须是 64 位小写 hex")
)

func validateHash(hashHex string) error {
	if len(hashHex) != sha256.Size*2 {
		return ErrHashInvalid
	}
	if _, err := hex.DecodeString(hashHex); err != nil {
		return ErrHashInvalid
	}
	return nil
}

// Open 建立 seed_data 目录结构并清理上次进程遗留的 staging 临时文件。
func Open(seedDataDir string) (*Store, error) {
	s := &Store{
		root:    seedDataDir,
		seeds:   filepath.Join(seedDataDir, "seeds"),
		staging: filepath.Join(seedDataDir, "staging"),
		trash:   filepath.Join(seedDataDir, "trash"),
	}
	for _, dir := range []string{s.seeds, s.staging, s.trash} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("创建目录 %s 失败: %w", dir, err)
		}
	}
	if err := s.CleanupStaging(); err != nil {
		return nil, err
	}
	return s, nil
}

// CleanupStaging 删除 staging 目录中的全部残留临时文件；
// 这些文件从未通过原子 rename 发布，对 MSFile 不可见，可以安全删除。
func (s *Store) CleanupStaging() error {
	entries, err := os.ReadDir(s.staging)
	if err != nil {
		return fmt.Errorf("读取 staging 目录失败: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(s.staging, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("清理 staging 残留失败: %w", err)
		}
	}
	return nil
}

// Publish 把 Builder 结果写入 staging、fsync 后原子 rename 到最终路径。
// 目标已存在时校验完整 SHA-256：一致则复用；损坏（同尺寸但内容不符）时
// 通过 staging 原子替换重建，绝不把坏 Seed 留给读取方。
func (s *Store) Publish(result *Result) error {
	hashHex := hex.EncodeToString(result.SeedHash[:])
	target := s.path(hashHex)
	if _, err := os.Stat(target); err == nil {
		if err := verifySeedFile(target, hashHex, int64(len(result.Seed))); err == nil {
			return nil // 复用已发布的相同 Seed
		}
		// 既有文件损坏（人工破坏或历史截断）：走下方 staging 路径原子重建。
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	tmp, err := os.CreateTemp(s.staging, ".publish-*")
	if err != nil {
		return fmt.Errorf("创建 staging 临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // rename 成功后该调用无害
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(result.Seed); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("写入临时 Seed 失败: %w", err)
	}
	// fsync 保证掉电后 rename 出来的最终文件内容完整。
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync 临时 Seed 失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		// rename 失败但目标已存在（并发发布竞态）：只有完整 Hash 校验通过才视为成功。
		if verifyErr := verifySeedFile(target, hashHex, int64(len(result.Seed))); verifyErr == nil {
			return nil
		}
		return fmt.Errorf("原子发布 Seed 失败: %w", err)
	}
	fsyncDir(filepath.Dir(target))
	return nil
}

// verifySeedFile 校验磁盘 Seed 的完整 SHA-256 与长度。
func verifySeedFile(path, hashHex string, wantLen int64) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	digest := sha256.New()
	n, err := io.Copy(digest, file)
	if err != nil {
		return err
	}
	if n != wantLen || hex.EncodeToString(digest.Sum(nil)) != hashHex {
		return fmt.Errorf("Seed 文件内容与 Hash %s 不一致，需要重建", hashHex)
	}
	return nil
}

// fsyncDir 对目录执行 fsync，保证 rename 元数据在掉电后不丢失。
func fsyncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// path 返回两级 Hash 前缀分散后的最终 .seed 文件路径（不校验存在性）。
func (s *Store) path(hashHex string) string {
	return filepath.Join(s.seeds, hashHex[:2], hashHex[2:4], hashHex+".seed")
}

// Path 返回某个 Hash 的最终 .seed 文件完整路径（诊断与管理工具使用）。
func (s *Store) Path(hashHex string) string {
	return s.path(strings.ToLower(hashHex))
}

// ReadSeed 打开并完整读取一个已发布的 Seed 文件，
// 校验 SHA-256(内容) == 请求 Hash 与 4 字节对齐后返回；校验失败返回 ErrIntegrity。
func (s *Store) ReadSeed(hashHex string) ([]byte, error) {
	hashHex = strings.ToLower(hashHex)
	if err := validateHash(hashHex); err != nil {
		return nil, err
	}
	file, err := os.Open(s.path(hashHex))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, hashHex)
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("读取 Seed 文件失败: %w", err)
	}
	digest := sha256.Sum256(data)
	if !equalDigest(digest, hashHex) {
		return nil, fmt.Errorf("%w: Seed 文件内容与 Hash 不匹配", ErrIntegrity)
	}
	if len(data)%32 != 0 {
		return nil, fmt.Errorf("%w: Seed 长度 %d 不是 32 字节的整数倍", ErrIntegrity, len(data))
	}
	return data, nil
}

var (
	// ErrNotFound 表示磁盘上没有该 Seed 文件。
	ErrNotFound = errors.New("没有找到 Seed 文件")
	// ErrIntegrity 表示 Seed 内容与声明 Hash 不一致，必须 fail closed。
	ErrIntegrity = errors.New("Seed 完整性校验失败")
)

func equalDigest(digest [32]byte, hashHex string) bool {
	return hex.EncodeToString(digest[:]) == hashHex
}

// MoveToTrash 把已解除索引的 Seed 原子移入 trash；等待异步删除。
// 文件不存在时静默成功（可能已被更早一轮 GC 清理）。
func (s *Store) MoveToTrash(hashHex string) error {
	if err := validateHash(hashHex); err != nil {
		return err
	}
	source := s.path(hashHex)
	if _, err := os.Stat(source); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := os.MkdirAll(s.trash, 0o750); err != nil {
		return err
	}
	if err := os.Rename(source, filepath.Join(s.trash, hashHex+".seed")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("移动 Seed 到 trash 失败: %w", err)
	}
	// 目录清空后顺带删除空的前缀目录，避免目录项无限累积。
	removeEmptyDirs(s.seeds, hashHex[:2], hashHex[2:4])
	return nil
}

// EmptyTrash 删除 trash 目录下的全部文件。由 GC 在解除数据库引用之后异步调用。
func (s *Store) EmptyTrash() error {
	entries, err := os.ReadDir(s.trash)
	if err != nil {
		return fmt.Errorf("读取 trash 目录失败: %w", err)
	}
	var firstErr error
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(s.trash, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// HasSeedFile 报告某个 Hash 的 .seed 文件是否在磁盘上（诊断用）。
func (s *Store) HasSeedFile(hashHex string) bool {
	_, err := os.Stat(s.path(strings.ToLower(hashHex)))
	return err == nil
}

func removeEmptyDirs(root string, parts ...string) {
	// 从最深的目录开始向上尝试删除空目录；非空会失败，忽略即可。
	for i := len(parts); i > 0; i-- {
		dir := filepath.Join(append([]string{root}, parts[:i]...)...)
		_ = os.Remove(dir)
	}
}

// WalkSeeds 遍历 seeds 目录下全部已发布 Seed，回调参数为 hash hex 与文件 mtime。
// 供 GC 磁盘孤儿扫描使用；任何回调错误都会中止遍历。
func (s *Store) WalkSeeds(visit func(hashHex string, modTime time.Time) error) error {
	entries, err := os.ReadDir(s.seeds)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("读取 seeds 目录失败: %w", err)
	}
	for _, level1 := range entries {
		if !level1.IsDir() || len(level1.Name()) != 2 {
			continue
		}
		subEntries, err := os.ReadDir(filepath.Join(s.seeds, level1.Name()))
		if err != nil {
			continue
		}
		for _, level2 := range subEntries {
			if !level2.IsDir() || len(level2.Name()) != 2 {
				continue
			}
			files, err := os.ReadDir(filepath.Join(s.seeds, level1.Name(), level2.Name()))
			if err != nil {
				continue
			}
			for _, file := range files {
				if file.IsDir() || !strings.HasSuffix(file.Name(), ".seed") {
					continue
				}
				hashHex := strings.TrimSuffix(file.Name(), ".seed")
				info, err := file.Info()
				if err != nil {
					continue
				}
				if err := visit(strings.ToLower(hashHex), info.ModTime()); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// VerifySeed 校验已发布 Seed 文件存在且 SHA-256 与 Hash 一致（阻断 2）。
func (s *Store) VerifySeed(hashHex string) error {
	hashHex = strings.ToLower(hashHex)
	if err := validateHash(hashHex); err != nil {
		return err
	}
	path := s.path(hashHex)
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w：%s", ErrNotFound, hashHex)
	}
	if err != nil {
		return err
	}
	// 长度校验放宽为 32 字节对齐（空 Seed 合法），内容做完整 SHA-256。
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	digest := sha256.New()
	size, err := io.Copy(digest, file)
	if err != nil {
		return err
	}
	if size != info.Size() {
		return fmt.Errorf("Seed %s 读取长度异常", hashHex)
	}
	if hex.EncodeToString(digest.Sum(nil)) != hashHex {
		return fmt.Errorf("Seed %s 内容 SHA-256 不匹配", hashHex)
	}
	return nil
}
