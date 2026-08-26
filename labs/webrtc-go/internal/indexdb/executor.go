// Package indexdb 是 NAS V1 唯一的 SQLite 数据层入口。
//
// 并发模型（需求 §5）：
//
//	watcher / scanner / hash worker / MSFile / Web
//	        │
//	        ▼
//	 有界异步请求队列
//	        │
//	        ▼
//	 单个 SQLite executor goroutine
//	        │
//	        ▼
//	 唯一 *sql.DB，MaxOpenConns = 1
//
// 业务包只能拿到 *indexdb.DB 与仓库方法，不能取得底层 *sql.DB，
// 因此无法绕过队列制造读写竞争。队列有界，满载时调用方阻塞等待或因 ctx 取消退出，
// 不会无限占用内存。
package indexdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

// DefaultQueueDepth 是请求队列容量；超过后提交方产生背压。
const DefaultQueueDepth = 256

// Executor 把全部 SQLite 操作串行化到同一个后台 goroutine。
type Executor struct {
	requests  chan dbRequest
	done      chan struct{}
	closeOnce sync.Once
}

type dbRequest struct {
	ctx    context.Context
	run    func(context.Context, *sql.DB) (any, error)
	result chan dbResult
	close  bool
}

type dbResult struct {
	value any
	err   error
}

func openSQLDB(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("创建数据库目录失败: %w", err)
	}
	// modernc.org/sqlite 纯 Go 驱动；文件不存在时自动创建。
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("打开 SQLite 失败: %w", err)
	}
	// 队列已保证串行；MaxOpenConns=1 同时防止 database/sql 私自开第二条连接。
	raw.SetMaxOpenConns(1)
	raw.SetMaxIdleConns(1)
	raw.SetConnMaxLifetime(0)
	return raw, nil
}

// start 启动执行器循环。schema 由调用方（Open）先行校验。
func start(raw *sql.DB, queueDepth int) *Executor {
	e := &Executor{requests: make(chan dbRequest, queueDepth), done: make(chan struct{})}
	go e.loop(raw)
	return e
}

func (e *Executor) loop(raw *sql.DB) {
	defer close(e.done)
	for request := range e.requests {
		if request.close {
			request.result <- dbResult{err: raw.Close()}
			return
		}
		if err := request.ctx.Err(); err != nil {
			request.result <- dbResult{err: err}
			continue
		}
		value, err := request.run(request.ctx, raw)
		request.result <- dbResult{value: value, err: err}
	}
}

// call 是业务侧唯一入口：把闭包送入队列等待结果。
// 队列只做调度，闭包内禁止目录遍历、文件 Hash、网络写入和大附件读取。
func call[T any](ctx context.Context, e *Executor, fn func(context.Context, *sql.DB) (T, error)) (T, error) {
	var zero T
	result := make(chan dbResult, 1)
	request := dbRequest{ctx: ctx, result: result, run: func(ctx context.Context, raw *sql.DB) (any, error) {
		return fn(ctx, raw)
	}}
	select {
	case e.requests <- request:
	case <-ctx.Done():
		return zero, ctx.Err()
	case <-e.done:
		return zero, errors.New("SQLite 执行器已关闭")
	}
	select {
	case response := <-result:
		if response.err != nil {
			return zero, response.err
		}
		value, ok := response.value.(T)
		if !ok {
			return zero, errors.New("SQLite 执行器返回了错误的内部类型")
		}
		return value, nil
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}

// Close 排空队列后关闭底层连接；幂等。
func (e *Executor) Close() error {
	var closeErr error
	e.closeOnce.Do(func() {
		result := make(chan dbResult, 1)
		select {
		case e.requests <- dbRequest{close: true, result: result}:
			closeErr = (<-result).err
			<-e.done
		case <-e.done:
		}
	})
	return closeErr
}

// QueueDepth 返回当前排队中的请求数，供管理台展示队列压力。
func (e *Executor) QueueDepth() int { return len(e.requests) }
