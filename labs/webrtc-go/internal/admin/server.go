// Package admin 提供 V1 Web 运维面：
// 只读的平面 Hash 索引查询、同步状态展示和手动触发全量扫描。
//
// 明确禁止（冻结需求 §11）：
//
//	上传/删除/移动/重命名 nas_data 原文件；
//	白名单 CRUD 或任何 clients 路由；
//	返回绝对路径、私钥或完整白名单；
//	把 Web 管理 token 当成 MSFile 客户端凭据。
package admin

import (
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"msfile.dev/labs/webrtc-go/internal/indexdb"
)

//go:embed web/*
var webFiles embed.FS

// Coordinator 是管理台需要的协调器只读能力（由 library.Coordinator 实现）。
type Coordinator interface {
	QueueDepth() int       // 当前待处理路径队列深度
	Scanning() bool        // 是否正在执行全量扫描
	TriggerFullScan() bool // 请求触发一轮全量扫描；已有扫描进行中时返回 false
}

// Options 是管理台构造参数。
type Options struct {
	AdminToken    string        // Bearer Token；为空时仅限 loopback 使用（config 已校验）
	PeerID        string        // 供应商 PeerId
	PublicKey     string        // 供应商压缩公钥 hex
	Addresses     []string      // 对外 MSFile multiaddr 列表
	AccessMode    string        // private / public；只用于展示，不影响管理面认证
	WhitelistSize int           // private 白名单条数；只展示数量，不返回公钥本身
	Retention     time.Duration // invalid 派生数据保留期，用于剩余倒计时
}

// New 创建管理台 http.Handler。
func New(db *indexdb.DB, coord Coordinator, options Options) http.Handler {
	server := &Server{db: db, coord: coord, options: options}
	mux := http.NewServeMux()
	assets, _ := fs.Sub(webFiles, "web")
	fileServer := http.FileServer(http.FS(assets))
	// 无方法根模式同时服务 GET/HEAD 静态资源；API 前缀与具体方法路由都比它更specific，
	// 不会产生 ServeMux 模式冲突。
	mux.Handle("/", securityHeaders(fileServer))

	// 允许的 V1 API 最小集合；每个路径同时注册无方法兜底路由，
	// 其他写方法一律返回中文 405，而不是默认纯文本响应。
	mux.HandleFunc("GET /api/status", server.protect(server.status))
	mux.HandleFunc("/api/status", server.methodNotAllowed)
	mux.HandleFunc("GET /api/files", server.protect(server.listFiles))
	mux.HandleFunc("/api/files", server.methodNotAllowed)
	mux.HandleFunc("GET /api/files/{seed_hash}", server.protect(server.fileDetail))
	mux.HandleFunc("/api/files/{seed_hash}", server.methodNotAllowed)
	mux.HandleFunc("GET /api/scans", server.protect(server.listScans))
	mux.HandleFunc("POST /api/scans", server.protect(server.triggerScan))
	mux.HandleFunc("/api/scans", server.methodNotAllowed)
	mux.HandleFunc("/api/", server.notFound)
	return securityHeaders(mux)
}

// Server 持有管理台依赖。
type Server struct {
	db      *indexdb.DB
	coord   Coordinator
	options Options
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

// protect 校验管理 Bearer Token。access_mode=public 不改变管理面的认证要求。
func (s *Server) protect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.options.AdminToken != "" {
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(token), []byte(s.options.AdminToken)) != 1 {
				writeError(w, http.StatusUnauthorized, "admin_token_invalid", "管理令牌无效或缺失")
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", s.allowHeader(r.URL.Path))
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed",
		"该路径不支持此 HTTP 方法；V1 管理台只提供只读查询与触发全量扫描")
}

func (s *Server) allowHeader(path string) string {
	switch {
	case strings.HasPrefix(path, "/api/scans"):
		return "GET, POST"
	default:
		return "GET"
	}
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "not_found",
		"接口不存在；V1 只有 status/files/scans 三组只读 API")
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	counts, err := s.db.GetStatusCounts(r.Context())
	if err != nil {
		writeError(w, 500, "database_error", "读取索引统计失败")
		return
	}
	scans, err := s.db.RecentScans(r.Context(), 1)
	var lastScan *indexdb.ScanRun
	if err == nil && len(scans) > 0 {
		lastScan = &scans[0]
	}
	writeJSON(w, 200, map[string]any{
		"service_status":      "running",
		"service_status_zh":   "运行中",
		"time":                time.Now().UTC().Format(time.RFC3339),
		"peer_id":             s.options.PeerID,                         // 供应商 PeerId
		"supplier_public_key": s.options.PublicKey,                      // 供应商压缩公钥
		"listen_addresses":    s.options.Addresses,                      // 对外 multiaddr
		"access_mode":         s.options.AccessMode,                     // private / public
		"whitelist_size":      s.options.WhitelistSize,                  // 白名单条数（不含内容）
		"counts":              counts,                                   // 内容与位置统计
		"scan_running":        s.coord.Scanning(),                       // 是否正在全量扫描
		"queue_depth":         s.coord.QueueDepth(),                     // 待处理路径队列深度
		"last_scan":           lastScan,                                 // 最近一次扫描记录
		"retention_seconds":   int64(s.options.Retention / time.Second), // 失效保留期
	})
}

func (s *Server) listFiles(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	limit, _ := strconv.Atoi(query.Get("limit"))
	offset, _ := strconv.Atoi(query.Get("offset"))
	state := strings.TrimSpace(query.Get("state"))
	if !isValidStateFilter(state) {
		writeError(w, 400, "bad_state_filter", "状态过滤只能是 ready、invalid、indexing、error 或留空")
		return
	}
	page, err := s.db.ListContents(r.Context(), indexdb.ListQuery{
		Text:   strings.TrimSpace(query.Get("q")), // 匹配完整/前缀 Hash 或建议文件名
		State:  state,
		Limit:  limit,
		Offset: offset,
	}, s.options.Retention, time.Now())
	if err != nil {
		writeError(w, 500, "database_error", "查询平面 Hash 列表失败")
		return
	}
	writeJSON(w, 200, map[string]any{
		"items":  page.Items,
		"total":  page.Total,
		"limit":  clampLimit(limit),
		"offset": maxInt(offset, 0),
	})
}

func (s *Server) fileDetail(w http.ResponseWriter, r *http.Request) {
	hashHex := strings.ToLower(strings.TrimSpace(r.PathValue("seed_hash")))
	if _, err := hex.DecodeString(hashHex); err != nil || len(hashHex) != 64 {
		writeError(w, 400, "invalid_seed_hash", "Seed Hash 必须是 64 位小写 hex")
		return
	}
	summary, locations, err := s.db.GetContentDetail(r.Context(), hashHex, s.options.Retention, time.Now())
	if errors.Is(err, indexdb.ErrNotFound) {
		writeError(w, 404, "content_not_found", "索引中没有该 Seed Hash")
		return
	}
	if err != nil {
		writeError(w, 500, "database_error", "查询单 Hash 详情失败")
		return
	}
	writeJSON(w, 200, map[string]any{
		"content":   summary,   // 内容摘要（含可用副本数与保留倒计时）
		"locations": locations, // 内部相对路径位置明细（非绝对路径）
	})
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.db.RecentScans(r.Context(), 20)
	if err != nil {
		writeError(w, 500, "database_error", "读取扫描历史失败")
		return
	}
	writeJSON(w, 200, map[string]any{"items": scans})
}

func (s *Server) triggerScan(w http.ResponseWriter, r *http.Request) {
	if s.coord.Scanning() {
		writeError(w, http.StatusConflict, "scan_in_progress", "已有一轮全量扫描正在进行，请稍后再试")
		return
	}
	if !s.coord.TriggerFullScan() {
		writeError(w, http.StatusConflict, "scan_in_progress", "扫描触发失败：可能刚有扫描完成，请稍后重试")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":    "accepted",
		"status_zh": "已接受，全量扫描开始执行",
	})
}

func isValidStateFilter(state string) bool {
	switch state {
	case "", indexdb.StateReady, indexdb.StateInvalid, indexdb.StateIndexing, indexdb.StateError:
		return true
	}
	return false
}

func clampLimit(limit int) int {
	if limit <= 0 || limit > 200 {
		return 50
	}
	return limit
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, messageZh string) {
	writeJSON(w, status, map[string]any{
		"error_code":       code,
		"error_message_zh": messageZh,
		"timestamp":        time.Now().UTC().Format(time.RFC3339),
	})
}
