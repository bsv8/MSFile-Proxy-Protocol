// Package safefs 提供 nas_data 内的安全文件打开入口：
//
//	拒绝绝对路径、.. 回溯与空路径；
//	拒绝任何中间目录是符号链接（Lstat 逐级检查）；
//	拒绝最终组件是符号链接（打开前后 inode 双重校验）；
//	底层使用 os.Root（Linux openat2 RESOLVE_BENEATH）兜底，
//	即使存在竞态替换，也绝不可能打开 nas_data 根之外的文件。
//
// Hash 计算、stat 与块 ReadAt 必须共用同一入口，防止绕过。
package safefs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

var (
	// ErrEscape 表示路径试图越出根目录。
	ErrEscape = errors.New("路径越出根目录")
	// ErrSymlinkAncestor 表示中间目录包含符号链接。
	ErrSymlinkAncestor = errors.New("路径的中间目录包含符号链接")
	// ErrSymlinkFinal 表示最终组件是符号链接。
	ErrSymlinkFinal = errors.New("路径最终组件是符号链接")
	// ErrReplaced 表示打开期间文件被替换（inode 变化）。
	ErrReplaced = errors.New("文件在打开期间被替换")
	// ErrNotRegular 表示目标不是普通文件。
	ErrNotRegular = errors.New("目标不是普通文件")
)

// Root 是绑定到某个目录的安全打开器；并发安全。
// 目录被卸载后重新挂载（inode 变化）时自动重开底层句柄，
// 保证“挂载恢复”场景不需要重启服务。
type Root struct {
	mu    sync.Mutex
	dir   string
	inner *os.Root
	dev   uint64
	ino   uint64
}

// Open 建立绑定 dir 的安全根。目录暂时不存在（挂载未就绪，degraded 启动）时
// 返回可用的惰性 Root：目录出现后的首次访问会自动建立底层句柄。
func Open(dir string) (*Root, error) {
	r := &Root{dir: dir}
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return r, nil // 惰性：inner 为空，ensure 时再建
	}
	if err := r.reopen(); err != nil {
		return nil, err
	}
	return r, nil
}

// reopen 重开底层 os.Root 并记录当前目录 inode；调用方必须持有 mu。
func (r *Root) reopen() error {
	if _, err := os.Stat(r.dir); err != nil {
		return err // 目录仍不可见：保持惰性
	}
	inner, err := os.OpenRoot(r.dir)
	if err != nil {
		return fmt.Errorf("建立安全根 %s 失败: %w", r.dir, err)
	}
	fi, err := os.Stat(r.dir)
	if err != nil {
		_ = inner.Close()
		return fmt.Errorf("stat 安全根失败: %w", err)
	}
	r.inner = inner
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		r.dev = uint64(st.Dev)
		r.ino = uint64(st.Ino)
	}
	return nil
}

// ensure 检测目录可见性与 inode 变化（卸载重挂、删除重建、延迟挂载）；
// 需要时重开或惰性建立底层句柄。调用方必须持有 mu。
func (r *Root) ensure() error {
	fi, err := os.Stat(r.dir)
	if err != nil {
		return err // 当前不可见：调用方按文件不可见路径处理
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	curDev, curIno := uint64(st.Dev), uint64(st.Ino)
	switch {
	case r.inner == nil:
		return r.reopen()
	case curDev != r.dev || curIno != r.ino:
		_ = r.inner.Close()
		return r.reopen()
	}
	return nil
}

// Dir 返回根目录绝对路径。
func (r *Root) Dir() string { return r.dir }

// Close 释放底层句柄；幂等。
func (r *Root) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inner == nil {
		return nil
	}
	err := r.inner.Close()
	r.inner = nil
	return err
}

// OpenFile 以不跟随任何符号链接的方式打开 rel 指向的普通文件。
// 返回的句柄保证位于根目录之内且内容与校验时的 inode 一致。
func (r *Root) OpenFile(rel string) (*os.File, fs.FileInfo, error) {
	cleaned, err := normalize(rel)
	if err != nil {
		return nil, nil, err
	}
	if r == nil || r.inner == nil {
		return nil, nil, errors.New("安全根已关闭")
	}
	// 第一道防线：逐级 Lstat，拒绝中间符号链接与最终符号链接。
	parts := strings.Split(cleaned, "/")
	for i := 1; i < len(parts); i++ {
		fi, err := os.Lstat(filepath.Join(r.dir, strings.Join(parts[:i], "/")))
		if err != nil {
			return nil, nil, fmt.Errorf("检查父目录失败: %w", err)
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return nil, nil, fmt.Errorf("%w：%s", ErrSymlinkAncestor, strings.Join(parts[:i], "/"))
		}
	}
	before, err := os.Lstat(filepath.Join(r.dir, cleaned))
	if err != nil {
		return nil, nil, err
	}
	if before.Mode()&fs.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("%w：%s", ErrSymlinkFinal, cleaned)
	}
	if !before.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%w：%s", ErrNotRegular, cleaned)
	}
	// 第二道防线：os.Root 在 Linux 上使用 openat2(RESOLVE_BENEATH|NO_MAGICLINKS)，
	// 即使祖先在校验后被竞态替换为指向根外的链接，也无法逃出根目录。
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ensure(); err != nil {
		return nil, nil, err
	}
	if r.inner == nil {
		return nil, nil, fmt.Errorf("nas_data 尚未就绪：%w", fs.ErrNotExist)
	}
	file, err := r.inner.Open(cleaned)
	if err != nil {
		return nil, nil, err
	}
	after, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	// 第三道防线：打开前后 inode 一致，防止最终组件被并发替换成另一个文件或符号链接。
	if !os.SameFile(before, after) {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%w：%s", ErrReplaced, cleaned)
	}
	return file, after, nil
}

// LstatFile 返回 rel 的 Lstat 信息但不打开文件；供协调器的稳定性检测复用同一套校验。
func (r *Root) LstatFile(rel string) (fs.FileInfo, error) {
	cleaned, err := normalize(rel)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ensure(); err != nil {
		return nil, err
	}
	if r.inner == nil {
		return nil, fmt.Errorf("nas_data 尚未就绪：%w", fs.ErrNotExist)
	}
	for i := 1; i < len(parts(cleaned)); i++ {
		fi, err := os.Lstat(filepath.Join(r.dir, strings.Join(parts(cleaned)[:i], "/")))
		if err != nil {
			return nil, err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w：%s", ErrSymlinkAncestor, strings.Join(parts(cleaned)[:i], "/"))
		}
	}
	return os.Lstat(filepath.Join(r.dir, cleaned))
}

func parts(cleaned string) []string { return strings.Split(cleaned, "/") }

func normalize(rel string) (string, error) {
	if rel == "" {
		return "", errors.New("空的相对路径")
	}
	if filepath.IsAbs(rel) || strings.ContainsRune(rel, '\\') {
		return "", fmt.Errorf("非法的相对路径 %q：%w", rel, ErrEscape)
	}
	cleaned := filepath.ToSlash(filepath.Clean(rel))
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("相对路径 %q 越出根目录：%w", rel, ErrEscape)
	}
	return cleaned, nil
}
