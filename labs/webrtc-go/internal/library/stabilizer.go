package library

import (
	"context"
	"errors"
	"io/fs"
	"syscall"
	"time"

	"github.com/benbjohnson/clock"

	"msfile.dev/labs/webrtc-go/internal/safefs"
)

// 本文件实现冻结需求 §6.4 的稳定性检测（stat A/B/C）：
//
//	stat A
//	等待安静期
//	stat B —— A 与 B 的 size/mtime 相同才开始 Hash
//	完成 Hash
//	stat C —— B 与 C 的 size/mtime 相同才允许提交
//
// 任一比较失败：丢弃临时 Seed、不覆盖旧索引、重新防抖排队。

type fingerprint struct {
	SizeBytes int64
	MtimeNs   int64
	Mode      fs.FileMode
	sys       any // 平台相关 stat 信息，用于提取 device_id/inode
}

// sameAs 语义化比较两次采集的指纹：
// 只比较尺寸、修改时间、模式与可靠的 device/inode 值；
// 绝不比较 sys 指针本身——每次 Lstat 都会返回新的指针。
func (f fingerprint) sameAs(other fingerprint) bool {
	if f.SizeBytes != other.SizeBytes || f.MtimeNs != other.MtimeNs || f.Mode != other.Mode {
		return false
	}
	sf, okF := f.sys.(*syscall.Stat_t)
	so, okO := other.sys.(*syscall.Stat_t)
	if !okF || !okO || sf == nil || so == nil {
		// 非 Unix 或无法取得底层信息时，以路径+尺寸+mtime 为准。
		return true
	}
	return sf.Dev == so.Dev && sf.Ino == so.Ino
}

// statFile 通过安全入口采集指纹：拒绝中间目录符号链接与路径逃逸；
// 文件消失返回 false。与 Hash、ReadAt 共用同一套校验。
func statFile(root *safefs.Root, relativePath string) (fingerprint, bool, error) {
	info, err := root.LstatFile(relativePath)
	if errors.Is(err, fs.ErrNotExist) {
		return fingerprint{}, false, nil
	}
	if err != nil {
		return fingerprint{}, false, err
	}
	return fingerprint{
		SizeBytes: info.Size(),
		MtimeNs:   info.ModTime().UnixNano(),
		Mode:      info.Mode(),
		sys:       info.Sys(),
	}, true, nil
}

// stableStatBefore 执行 stat A -> 安静期 -> stat B；
// 返回 ok=false 表示两次不一致或文件消失，调用方应放弃本轮并重新排队。
func stableStatBefore(ctx context.Context, clk clock.Clock, root *safefs.Root, relativePath string, quiet time.Duration) (fingerprint, bool, error) {
	a, exists, err := statFile(root, relativePath)
	if err != nil || !exists {
		return fingerprint{}, false, err
	}
	if err := sleepContext(ctx, clk, quiet); err != nil {
		return fingerprint{}, false, err
	}
	b, exists, err := statFile(root, relativePath)
	if err != nil {
		return fingerprint{}, false, err
	}
	if !exists || !a.sameAs(b) {
		return fingerprint{}, false, nil
	}
	return b, true, nil
}

// stableStatAfter 在 Hash 完成后执行 stat C 并与 stat B 比较；
// 只有完全一致才允许提交索引结果。
func stableStatAfter(ctx context.Context, root *safefs.Root, relativePath string, before fingerprint) (bool, error) {
	c, exists, err := statFile(root, relativePath)
	if err != nil {
		return false, err
	}
	return exists && c.sameAs(before), nil
}

// sleepContext 用注入时钟睡眠，ctx 取消时立即返回。
// 生产使用真实时钟，测试注入 fake clock 避免真实等待。
func sleepContext(ctx context.Context, clk clock.Clock, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := clk.Timer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
