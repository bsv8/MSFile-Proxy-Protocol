// Package admin 提供 V1 Web 内容服务：
// 面向公共访问者展示可用的平面 Hash 索引，并提供文件详情与下载。
// status/scans API 仍保留给已有运维脚本兼容使用，但不再出现在公共页面。
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
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"msfile.dev/labs/webrtc-go/internal/content"
	"msfile.dev/labs/webrtc-go/internal/indexdb"
)

//go:embed web/*
var webFiles embed.FS

// Coordinator 是兼容运维 API 所需的协调器只读能力（由 library.Coordinator 实现）。
type Coordinator interface {
	QueueDepth() int       // 当前待处理路径队列深度
	Scanning() bool        // 是否正在执行全量扫描
	TriggerFullScan() bool // 请求触发一轮全量扫描；已有扫描进行中时返回 false
}

// NetworkInfo 保存公开网络信息与运维 listener 信息。
//
// PeerId、公钥和 WebRTC Direct 地址会出现在公开接口；ListenAddresses
// 只用于受保护的 /api/status。字段全部附中文含义，避免把两种地址口径混用。
type NetworkInfo struct {
	PeerID                      string   // NAS 业务私钥派生的 libp2p PeerId
	SupplierPublicKey           string   // NAS 的 33 字节压缩 secp256k1 公钥 hex
	ListenAddresses             []string // 本机实际绑定/运行的 transport 地址（/api/status）
	WebRTCDirectPublicAddresses []string // YAML 配置的 WebRTC Direct 公网基础地址（/api/status）
	WebRTCDirectAddresses       []string // 已补齐 certhash 与 PeerId 的公网 WebRTC Direct 地址
	ready                       bool     // 运行时地址是否已完成初始化；未就绪时公开接口返回 503

	mu sync.RWMutex
}

// SetRuntime 写入运行中 host 产生的地址快照；切片会被复制，调用方可安全复用原切片。
func (n *NetworkInfo) SetRuntime(listenAddresses, publicBases, directAddresses []string) {
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ListenAddresses = cloneStrings(listenAddresses)
	n.WebRTCDirectPublicAddresses = cloneStrings(publicBases)
	n.WebRTCDirectAddresses = cloneStrings(directAddresses)
	n.ready = true
}

type networkSnapshot struct {
	peerID                      string
	supplierPublicKey           string
	listenAddresses             []string
	webRTCDirectPublicAddresses []string
	webRTCDirectAddresses       []string
	ready                       bool
}

func (n *NetworkInfo) snapshot() networkSnapshot {
	if n == nil {
		return networkSnapshot{}
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	return networkSnapshot{
		peerID:                      n.PeerID,
		supplierPublicKey:           n.SupplierPublicKey,
		listenAddresses:             cloneStrings(n.ListenAddresses),
		webRTCDirectPublicAddresses: cloneStrings(n.WebRTCDirectPublicAddresses),
		webRTCDirectAddresses:       cloneStrings(n.WebRTCDirectAddresses),
		ready:                       n.ready,
	}
}

// Options 是公共内容服务构造参数。
type Options struct {
	Reader                      *content.Reader // 内容读取器；公共下载从它打开安全文件副本
	AdminToken                  string          // 兼容运维 API 的 Bearer Token；公共内容 API 不需要
	PeerID                      string          // 供应商 PeerId
	PublicKey                   string          // 供应商压缩公钥 hex
	Addresses                   []string        // 兼容旧调用方的本机 listener 地址；/api/status 使用
	WebRTCDirectPublicAddresses []string        // 兼容旧调用方的 YAML WebRTC Direct 公网基础地址
	WebRTCDirectAddresses       []string        // 兼容旧调用方的完整 WebRTC Direct 公网地址
	NetworkInfo                 *NetworkInfo    // 运行时网络信息；用于在 host 监听后填充地址
	AccessMode                  string          // private / public；只用于兼容运维信息展示
	WhitelistSize               int             // private 白名单条数；只展示数量，不返回公钥本身
	Retention                   time.Duration   // invalid 派生数据保留期，用于兼容运维信息
}

// New 创建公共内容服务 http.Handler。
func New(db *indexdb.DB, coord Coordinator, options Options) http.Handler {
	server := &Server{db: db, coord: coord, options: options}
	mux := http.NewServeMux()
	assets, _ := fs.Sub(webFiles, "web")
	fileServer := http.FileServer(http.FS(assets))
	// 无方法根模式同时服务 GET/HEAD 静态资源；API 前缀与具体方法路由都比它更specific，
	// 不会产生 ServeMux 模式冲突。
	mux.Handle("/", securityHeaders(fileServer))

	// 公共内容 API 不要求管理令牌；它们只返回当前有效内容，并由下载处理器
	// 在服务端通过 safefs.Root 打开原文件。兼容运维 API 仍单独受令牌保护。
	mux.HandleFunc("GET /api/files", server.listFiles)
	mux.HandleFunc("/api/files", server.methodNotAllowed)
	mux.HandleFunc("GET /api/files/{seed_hash}", server.fileDetail)
	mux.HandleFunc("/api/files/{seed_hash}", server.methodNotAllowed)
	mux.HandleFunc("GET /api/files/{seed_hash}/download", server.download)
	mux.HandleFunc("/api/files/{seed_hash}/download", server.methodNotAllowed)
	// 网络信息是拨号方建立连接前需要的公开最小信息；不返回 WSS 地址，
	// WSS 必须由当前浏览器页面 URL 在前端生成。
	mux.HandleFunc("GET /api/network-info", server.networkInfo)
	mux.HandleFunc("/api/network-info", server.methodNotAllowed)

	// 兼容已有运维脚本的 API；公共页面不调用这些接口。
	mux.HandleFunc("GET /api/status", server.protect(server.status))
	mux.HandleFunc("/api/status", server.methodNotAllowed)
	mux.HandleFunc("GET /api/scans", server.protect(server.listScans))
	mux.HandleFunc("POST /api/scans", server.protect(server.triggerScan))
	mux.HandleFunc("/api/scans", server.methodNotAllowed)
	mux.HandleFunc("/api/", server.notFound)
	return securityHeaders(mux)
}

// Server 持有公共内容服务及兼容运维 API 的依赖。
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

// protect 始终校验管理 Bearer Token。access_mode=public 不改变管理面的认证要求；
// 即使配置没有 token，也不能把 /api/status 退化成公开接口。
func (s *Server) protect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if s.options.AdminToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.options.AdminToken)) != 1 {
			writeError(w, http.StatusUnauthorized, "admin_token_invalid", "管理令牌无效或缺失")
			return
		}
		next(w, r)
	}
}

func (s *Server) methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", s.allowHeader(r.URL.Path))
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed",
		"该路径不支持此 HTTP 方法；公共内容服务只提供 GET 下载与查询")
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
		"接口不存在；公共页面只提供内容索引、详情和下载")
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
	network := s.network()
	writeJSON(w, 200, map[string]any{
		"service_status":                 "running",
		"service_status_zh":              "运行中",
		"time":                           time.Now().UTC().Format(time.RFC3339),
		"peer_id":                        network.peerID,                           // 供应商 PeerId
		"supplier_public_key":            network.supplierPublicKey,                // 供应商压缩公钥
		"listen_addresses":               network.listenAddresses,                  // 本机实际绑定/运行地址
		"webrtc_direct_public_addresses": network.webRTCDirectPublicAddresses,      // 配置的公网基础地址
		"access_mode":                    s.options.AccessMode,                     // private / public
		"whitelist_size":                 s.options.WhitelistSize,                  // 白名单条数（不含内容）
		"counts":                         counts,                                   // 内容与位置统计
		"scan_running":                   s.coord.Scanning(),                       // 是否正在全量扫描
		"queue_depth":                    s.coord.QueueDepth(),                     // 待处理路径队列深度
		"last_scan":                      lastScan,                                 // 最近一次扫描记录
		"retention_seconds":              int64(s.options.Retention / time.Second), // 失效保留期
	})
}

// networkInfo 返回拨号方所需的最小公开网络信息。
// 它不要求 admin_token，也不返回 WSS multiaddr、内部 listener 或任何运维字段。
func (s *Server) networkInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	network := s.network()
	if !network.ready {
		writeError(w, http.StatusServiceUnavailable, "network_info_not_ready", "网络信息尚未准备完成，请稍后重试")
		return
	}
	directAddresses := network.webRTCDirectAddresses
	if directAddresses == nil {
		directAddresses = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"peer_id":                 network.peerID,
		"supplier_public_key":     network.supplierPublicKey,
		"webrtc_direct_addresses": directAddresses,
	})
}

func (s *Server) network() networkSnapshot {
	hasRuntimeNetworkInfo := s.options.NetworkInfo != nil
	network := s.options.NetworkInfo.snapshot()
	if !hasRuntimeNetworkInfo {
		// 没有运行时容器时，旧嵌入调用方提供的 Options 即是完整静态快照。
		network.ready = true
	}
	// 保留 Options 中的静态字段兼容现有测试和嵌入调用方；正式 NAS 使用
	// NetworkInfo 在 listener 建立后写入的运行时快照。
	if network.peerID == "" {
		network.peerID = s.options.PeerID
	}
	if network.supplierPublicKey == "" {
		network.supplierPublicKey = s.options.PublicKey
	}
	if network.listenAddresses == nil {
		network.listenAddresses = cloneStrings(s.options.Addresses)
	}
	if network.webRTCDirectPublicAddresses == nil {
		network.webRTCDirectPublicAddresses = cloneStrings(s.options.WebRTCDirectPublicAddresses)
	}
	if network.webRTCDirectAddresses == nil {
		network.webRTCDirectAddresses = cloneStrings(s.options.WebRTCDirectAddresses)
	}
	return network
}

func (s *Server) listFiles(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	limit, _ := strconv.Atoi(query.Get("limit"))
	offset, _ := strconv.Atoi(query.Get("offset"))
	state := strings.TrimSpace(query.Get("state"))
	if state != "" && state != indexdb.StateReady {
		writeError(w, 400, "bad_state_filter", "公共内容索引只展示有效文件，不支持其他状态筛选")
		return
	}
	page, err := s.db.ListContents(r.Context(), indexdb.ListQuery{
		Text:          strings.TrimSpace(query.Get("q")), // 匹配完整/前缀 Hash 或建议文件名
		State:         indexdb.StateReady,
		AvailableOnly: true, // 公共索引只展示 ready 且有 valid 文件副本的内容
		Limit:         limit,
		Offset:        offset,
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
	if summary.State != indexdb.StateReady || summary.ValidReplicas == 0 {
		writeError(w, http.StatusNotFound, "content_unavailable", "该文件当前不可用")
		return
	}
	response := map[string]any{
		"content":      summary,                               // 内容摘要（含可用副本数与保留倒计时）
		"download_url": "/api/files/" + hashHex + "/download", // 浏览器下载地址
	}
	// 公共详情不暴露 nas_data 内部布局；带有效运维令牌的旧客户端仍可读取
	// 原有的有效位置字段，保持兼容，不影响公共页面的最小信息面。
	if s.hasAdminToken(r) {
		response["locations"] = validLocations(locations)
	}
	writeJSON(w, 200, response)
}

func (s *Server) hasAdminToken(r *http.Request) bool {
	if s.options.AdminToken == "" {
		return false
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.options.AdminToken)) == 1
}

// validLocations 只保留当前有效位置，避免公共详情页展示失效诊断。
// 旧客户端仍可读取 locations 字段；公共前端不会把内部路径渲染出来。
func validLocations(locations []indexdb.LocationDetail) []indexdb.LocationDetail {
	filtered := make([]indexdb.LocationDetail, 0, len(locations))
	for _, location := range locations {
		if location.State == indexdb.LocationValid {
			filtered = append(filtered, location)
		}
	}
	return filtered
}

// download 提供公共文件下载。文件名来自索引中的 recommended_filename，
// 但文件内容只能由 content.Reader 从当前 valid 副本安全打开。
func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	hashHex := strings.ToLower(strings.TrimSpace(r.PathValue("seed_hash")))
	if _, err := hex.DecodeString(hashHex); err != nil || len(hashHex) != 64 {
		writeError(w, http.StatusBadRequest, "invalid_seed_hash", "Seed Hash 必须是 64 位小写 hex")
		return
	}
	if s.options.Reader == nil {
		writeError(w, http.StatusServiceUnavailable, "download_unavailable", "下载服务尚未就绪")
		return
	}
	file, info, err := s.options.Reader.OpenFileForDownload(r.Context(), hashHex)
	if errors.Is(err, content.ErrContentNotFound) {
		writeError(w, http.StatusNotFound, "content_not_found", "索引中没有该 Seed Hash")
		return
	}
	if errors.Is(err, content.ErrUnavailable) {
		writeError(w, http.StatusNotFound, "content_unavailable", "该文件当前不可用")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "download_failed", "打开下载文件失败")
		return
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "download_failed", "读取下载文件信息失败")
		return
	}
	filename := safeDownloadFilename(info.Filename)
	if filename == "" {
		filename = "download"
	}
	mediaType := info.MediaType
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Content-Disposition", contentDisposition(filename))
	http.ServeContent(w, r, filename, fileInfo.ModTime(), file)
}

// safeDownloadFilename 防止异常索引数据污染 Content-Disposition。
// 正常数据已由 seed.SafeFilename 收敛，这里再做一次 HTTP 层防护。
func safeDownloadFilename(filename string) string {
	filename = strings.TrimSpace(strings.ReplaceAll(filename, "\\", "/"))
	if slash := strings.LastIndexByte(filename, '/'); slash >= 0 {
		filename = filename[slash+1:]
	}
	filename = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '"' {
			return '_'
		}
		return r
	}, filename)
	if filename == "." || filename == ".." {
		return ""
	}
	return filename
}

// contentDisposition 让 ASCII 文件名直接显示，同时为 UTF-8 文件名提供
// RFC 5987 filename*，浏览器会优先使用 filename* 保存用户看到的原文件名。
func contentDisposition(filename string) string {
	if isASCIIHeaderFilename(filename) {
		return `attachment; filename="` + filename + `"`
	}
	encoded := strings.ReplaceAll(url.QueryEscape(filename), "+", "%20")
	return `attachment; filename="download"; filename*=UTF-8''` + encoded
}

func isASCIIHeaderFilename(filename string) bool {
	if filename == "" {
		return false
	}
	for i := 0; i < len(filename); i++ {
		if filename[i] < 0x20 || filename[i] > 0x7e || filename[i] == '"' || filename[i] == '\\' {
			return false
		}
	}
	return true
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

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string(nil), values...)
}
