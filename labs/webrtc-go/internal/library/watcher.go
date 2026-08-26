package library

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// 本文件实现冻结需求 §6.3 的文件事件快速发现：
//
//	创建/写入 -> 调度路径（稳定性检测负责防抖，重复事件由队列去重合并）
//	删除/重命名旧路径 -> 调度路径（协调器 stat 确认后进入 invalid 候选）
//	新目录 -> 注册递归 watcher
//	目录删除 -> 目录下旧位置经全量扫描收敛为 invalid
//	watcher overflow / watch limit / 后端错误 -> 中文诊断并立即触发全量扫描
//
// 事件绝不直接发布 Seed；网络挂载（SMB/NFS/FUSE/WebDAV）可能丢失事件，
// 最终一致性始终由周期全量扫描兜底。

const (
	// addWatchRetry 是目录 watch 注册失败后的重试等待。
	addWatchRetry = 200 * time.Millisecond
)

type fileWatcher struct {
	c   *Coordinator
	fsw *fsnotify.Watcher
	wg  sync.WaitGroup

	// testErrors 仅供测试注入溢出/后端错误；生产环境恒为 nil。
	testErrors chan error
}

// startFileWatcher 建立 watcher、注册 nas_data 根下全部目录并启动事件循环。
// 返回的 watcher 由调用方在 ctx 取消后 Stop。
func startFileWatcher(ctx context.Context, c *Coordinator) (*fileWatcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	w := &fileWatcher{c: c, fsw: fsw}
	// testErrors 是容量 1 的注入通道：生产环境永远无人写入，仅供测试模拟溢出。
	w.testErrors = make(chan error, 1)
	if err := w.addWatchRecursive(c.nasRoot); err != nil {
		_ = fsw.Close()
		return nil, err
	}
	w.wg.Add(2)
	go func() {
		defer w.wg.Done()
		w.runEvents(ctx)
	}()
	go func() {
		defer w.wg.Done()
		w.runErrors(ctx)
	}()
	c.log.Emit("library_watcher_started", map[string]any{
		"root_zh": "nas_data",
		"note_zh": "文件事件只用于快速发现；网络挂载可能丢事件，最终一致性由周期全量扫描保证",
	})
	return w, nil
}

// addWatchRecursive 注册 root 及其全部子目录。
func (w *fileWatcher) addWatchRecursive(root string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// 单个子树不可读不阻止启动；后续扫描会按 invalid 收敛。
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil // 不跟随符号链接
		}
		return w.fsw.Add(path)
	})
}

// runEvents 消费文件系统事件并转换为调度请求。
func (w *fileWatcher) runEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-w.fsw.Events:
			if !ok {
				return
			}
			w.handleEvent(event)
		}
	}
}

// runErrors 把 watcher 后端错误（含 inotify 队列溢出、watch 数量上限）转为中文诊断和全量扫描。
func (w *fileWatcher) runErrors(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case err, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
			w.reportError(err)
		case err := <-w.testErrors:
			if err == nil {
				return
			}
			w.reportError(err)
		}
	}
}

func (w *fileWatcher) reportError(err error) {
	w.c.log.Emit("library_watcher_error", map[string]any{
		"error":     err.Error(),
		"reason_zh": "文件事件通道异常或溢出，立即安排全量扫描以保证最终一致",
	})
	w.c.TriggerFullScan()
}

func (w *fileWatcher) handleEvent(event fsnotify.Event) {
	rel := w.relativePath(event.Name)
	if rel == "" || rel == "." {
		return
	}
	if event.Has(fsnotify.Create) {
		if info, err := os.Lstat(event.Name); err == nil && info.IsDir() {
			// 新目录：注册递归 watcher；目录内已有文件的发现交给本轮触发的调度与周期扫描。
			if err := w.addWatchRecursive(event.Name); err != nil {
				w.c.log.Emit("library_watcher_add_failed", map[string]any{
					"path_zh":   rel,
					"reason_zh": "新目录注册监视失败，将依赖全量扫描收敛",
				})
				w.c.TriggerFullScan()
				return
			}
			// 网络挂载上新目录可能在注册完成前就已写入子项；
			// 递归调度该目录下全部普通文件，嵌套内容不必等下一次周期扫描。
			var children []string
			walkErr := filepath.WalkDir(event.Name, func(p string, d os.DirEntry, err error) error {
				if err != nil {
					return nil // 单个子树不可读交给全量扫描收敛
				}
				if d.IsDir() || !d.Type().IsRegular() {
					return nil
				}
				if relChild := w.relativePath(p); relChild != "" {
					children = append(children, relChild)
				}
				return nil
			})
			if walkErr == nil && len(children) > 0 {
				w.c.SchedulePath("watcher 发现新目录", 0, children...)
			}
			return
		}
	}
	if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) ||
		event.Has(fsnotify.Create) || event.Has(fsnotify.Write) {
		// 删除/重命名：调度后由协调器 stat 确认消失并进入 invalid 候选；
		// 创建/写入：调度后进入稳定性检测。重复事件被队列去重合并。
		w.c.SchedulePath("watcher 文件事件", 0, rel)
	}
	if event.Has(fsnotify.Chmod) {
		// 权限位变化不影响内容身份；忽略以避免无意义重算。
	}
}

// relativePath 把绝对路径转换为 nas_data 内部 slash 相对路径；根外路径返回空。
func (w *fileWatcher) relativePath(absolute string) string {
	rel, err := filepath.Rel(w.c.nasRoot, absolute)
	if err != nil {
		return ""
	}
	rel = filepath.ToSlash(filepath.Clean(rel))
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return ""
	}
	return rel
}

// Stop 关闭底层 watcher 并等待事件循环退出。
func (w *fileWatcher) Stop() {
	_ = w.fsw.Close()
	w.wg.Wait()
}
