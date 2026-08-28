// Package config 负责 MSFile NAS V1 的 YAML 配置加载与启动前校验。
// 配置文件必须显式给出 nas_data、seed_data 与 access_mode；
// 不存在“未配置白名单就允许全部”的隐式回退。
package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/benbjohnson/clock"
	ma "github.com/multiformats/go-multiaddr"
	"gopkg.in/yaml.v3"

	"msfile.dev/labs/webrtc-go/internal/identity"
)

// AccessModePrivate 只允许白名单公钥访问；AccessModePublic 允许任意已认证 secp256k1 客户端。
const (
	AccessModePrivate = "private"
	AccessModePublic  = "public"
)

const (
	// MinHashWorkers / MaxHashWorkers 限制同时计算 Seed 的 worker 数量上限。
	MinHashWorkers = 1
	MaxHashWorkers = 32
)

// Duration 包装 time.Duration，让 YAML 可以写 "10m"、"24h" 这类人类可读值。
type Duration time.Duration

// UnmarshalYAML 实现 yaml.v3 的自定义解析；拒绝空串与非法时长。
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	text := strings.TrimSpace(value.Value)
	parsed, err := time.ParseDuration(text)
	if err != nil {
		return fmt.Errorf("时长 %q 不合法，应写成例如 300ms、10m、24h", text)
	}
	if parsed <= 0 {
		return fmt.Errorf("时长 %q 必须大于 0", text)
	}
	*d = Duration(parsed)
	return nil
}

// Standard 返回对应的 time.Duration。
func (d Duration) Standard() time.Duration { return time.Duration(d) }

// Config 是 msfile-nas 的全部配置字段。
type Config struct {
	IdentityKeyFile string `yaml:"identity_key_file"` // 供应商 secp256k1 私钥 hex 文件路径

	NASData  string `yaml:"nas_data"`  // 用户原文件根目录，服务只读且不改变布局
	SeedData string `yaml:"seed_data"` // 派生数据根目录：Seed、SQLite、staging、trash

	AccessMode         string   `yaml:"access_mode"`          // 访问模式：private 或 public
	PublicKeyWhitelist []string `yaml:"public_key_whitelist"` // private 模式的客户端压缩公钥列表（66 位 hex）

	FullScanInterval   Duration `yaml:"full_scan_interval"`   // 周期全量扫描间隔，默认 10m
	FileStableInterval Duration `yaml:"file_stable_interval"` // 文件安静多久才开始计算，默认 3s
	InvalidRetention   Duration `yaml:"invalid_retention"`    // 文件不可见后的派生数据保留时间，默认 24h
	HashWorkers        int      `yaml:"hash_workers"`         // 同时读取原文件并计算 Seed 的 worker 数，默认 1

	ListenAddrs                 []string `yaml:"listen"`                         // NAS 进程在本机真正绑定的 transport 地址（WebRTC Direct、WS、WSS）
	WebRTCDirectPublicAddresses []string `yaml:"webrtc_direct_public_addresses"` // 对外公布的 WebRTC Direct 公网 UDP 基础地址；运行时补齐 certhash/PeerId
	AdminListen                 string   `yaml:"admin_listen"`                   // 已弃用的旧兼容字段；不参与监听、端口或安全校验
	AdminToken                  string   `yaml:"admin_token"`                    // 兼容运维 API 的 Bearer Token；共享入口为非 loopback 时必填；为空时运维 API 禁用

	EnableFileWatcher *bool `yaml:"enable_file_watcher"` // 是否启用文件事件监视器；默认开启。关闭后仅靠周期全量扫描收敛（诊断与测试用途）

	TLSCertFile string `yaml:"tls_cert_file"` // 直接终止 TLS 的 WSS 证书 PEM；与 tls_key_file 成对出现
	TLSKeyFile  string `yaml:"tls_key_file"`  // 直接终止 TLS 的 WSS 私钥 PEM；与 tls_cert_file 成对出现

	Clock clock.Clock `yaml:"-"` // 测试注入用时钟；正常运行使用真实时钟

	degradedNASData bool `yaml:"-"`
}

// Degraded 报告 nas_data 当前不存在（挂载未就绪）。
// 服务以降级状态启动：扫描失败使全部位置进入 24 小时保留期。
func (c *Config) Degraded() bool { return c.degradedNASData }

// Load 读取并完整校验配置文件；校验失败时返回中文错误，不产生任何监听或数据库写入。
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(raw)))
	decoder.KnownFields(true) // 未知字段直接报错，避免拼写错误被静默忽略
	cfg := &Config{}
	if err := decoder.Decode(cfg); err != nil {
		return nil, fmt.Errorf("解析 YAML 配置失败: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.FullScanInterval == 0 {
		c.FullScanInterval = Duration(10 * time.Minute)
	}
	if c.FileStableInterval == 0 {
		c.FileStableInterval = Duration(3 * time.Second)
	}
	if c.InvalidRetention == 0 {
		c.InvalidRetention = Duration(24 * time.Hour)
	}
	if c.HashWorkers == 0 {
		c.HashWorkers = MinHashWorkers
	}
	if len(c.ListenAddrs) == 0 {
		// 默认只开启 loopback Web 入口。WebRTC Direct 的公网 UDP 地址必须由
		// 运维在 YAML 中显式配置，不能由默认值或本机 listener 推测。
		c.ListenAddrs = []string{"/ip4/127.0.0.1/tcp/8080/ws"}
	}
	if c.Clock == nil {
		c.Clock = clock.New()
	}
}

// Validate 执行启动前的全部静态检查；任一失败都阻止服务启动。
func (c *Config) Validate() error {
	if c.IdentityKeyFile == "" {
		return errors.New("配置错误：identity_key_file 不能为空")
	}
	if info, err := os.Stat(c.IdentityKeyFile); err != nil {
		return fmt.Errorf("配置错误：identity_key_file 无法读取: %w", err)
	} else if info.IsDir() {
		return errors.New("配置错误：identity_key_file 是目录而不是私钥文件")
	}

	nasRoot, err := filepath.Abs(c.NASData)
	if err != nil {
		return fmt.Errorf("配置错误：nas_data 路径无效: %w", err)
	}
	c.NASData = nasRoot
	info, statErr := os.Stat(nasRoot)
	switch {
	case statErr == nil && !info.IsDir():
		return errors.New("配置错误：nas_data 必须是目录")
	case statErr != nil && !os.IsNotExist(statErr):
		return fmt.Errorf("配置错误：nas_data 无法访问: %w", statErr)
	case os.IsNotExist(statErr):
		// 挂载尚未就绪：允许以 degraded 状态启动（全部位置按不可见保留 24 小时），
		// 但绝不自动创建挂载点，避免掩盖挂载故障。
		c.degradedNASData = true
	}

	seedRoot, err := filepath.Abs(c.SeedData)
	if err != nil {
		return fmt.Errorf("配置错误：seed_data 路径无效: %w", err)
	}
	c.SeedData = seedRoot
	if err := os.MkdirAll(seedRoot, 0o750); err != nil {
		return fmt.Errorf("配置错误：seed_data 目录无法创建: %w", err)
	}
	if err := checkWritable(seedRoot); err != nil {
		return fmt.Errorf("配置错误：seed_data 目录不可写: %w", err)
	}

	// seed_data 必须位于 nas_data 外部，两个根互不包含，
	// 防止派生文件再次被扫描成用户文件。
	if containedIn(seedRoot, nasRoot) || containedIn(nasRoot, seedRoot) {
		return errors.New("配置错误：nas_data 与 seed_data 不能互相嵌套；请把 seed_data 放到 nas_data 之外")
	}

	switch c.AccessMode {
	case AccessModePrivate, AccessModePublic:
	default:
		return fmt.Errorf("配置错误：access_mode 只能是 private 或 public，当前是 %q", c.AccessMode)
	}

	seen := make(map[string]struct{}, len(c.PublicKeyWhitelist))
	normalized := make([]string, 0, len(c.PublicKeyWhitelist))
	for i, key := range c.PublicKeyWhitelist {
		canonical, keyErr := identity.NormalizeCompressedPubKeyHex(key)
		if keyErr != nil {
			return fmt.Errorf("配置错误：public_key_whitelist 第 %d 项不是合法的 66 位压缩 secp256k1 公钥 hex: %w", i+1, keyErr)
		}
		if _, dup := seen[canonical]; dup {
			continue // 加载时去重，不因重复项报错
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}
	c.PublicKeyWhitelist = normalized

	if c.FullScanInterval <= 0 {
		return errors.New("配置错误：full_scan_interval 必须大于 0")
	}
	if c.FileStableInterval <= 0 {
		return errors.New("配置错误：file_stable_interval 必须大于 0")
	}
	if c.InvalidRetention <= 0 {
		return errors.New("配置错误：invalid_retention 必须大于 0")
	}
	if c.HashWorkers < MinHashWorkers || c.HashWorkers > MaxHashWorkers {
		return fmt.Errorf("配置错误：hash_workers 必须在 %d..%d 之间", MinHashWorkers, MaxHashWorkers)
	}

	if err := c.ValidateNetwork(); err != nil {
		return err
	}

	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return errors.New("配置错误：tls_cert_file 与 tls_key_file 必须同时配置")
	}
	if c.TLSCertFile != "" {
		if _, err := os.Stat(c.TLSCertFile); err != nil {
			return fmt.Errorf("配置错误：tls_cert_file 无法读取: %w", err)
		}
		if _, err := os.Stat(c.TLSKeyFile); err != nil {
			return fmt.Errorf("配置错误：tls_key_file 无法读取: %w", err)
		}
		if _, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile); err != nil {
			return fmt.Errorf("配置错误：TLS 证书与私钥无法解析: %w", err)
		}
	}
	return nil
}

// ValidateNetwork 校验 listen 与 WebRTC Direct 公网发布地址的静态关系。
// 它不创建 socket、不解析 DNS，供 Load 和直接构造 Config 的装配方共同使用。
func (c *Config) ValidateNetwork() error {
	// listen 既是 libp2p 的真实绑定清单，也是 Web/WS 共享入口的 transport
	// 清单。提前解析它，确保 direct 发布约束在任何 listener 建立前就失败。
	features, err := validateListenAddresses(c.ListenAddrs)
	if err != nil {
		return err
	}
	if (strings.TrimSpace(c.TLSCertFile) == "") != (strings.TrimSpace(c.TLSKeyFile) == "") {
		return errors.New("配置错误：tls_cert_file 与 tls_key_file 必须同时配置")
	}
	if features.hasTLSWebSocket && (strings.TrimSpace(c.TLSCertFile) == "" || strings.TrimSpace(c.TLSKeyFile) == "") {
		return errors.New("配置错误：listen 使用 /tls/ws（WSS）时必须同时配置 tls_cert_file 与 tls_key_file")
	}
	if features.hasPlainWebSocket && (strings.TrimSpace(c.TLSCertFile) != "" || strings.TrimSpace(c.TLSKeyFile) != "") {
		return errors.New("配置错误：已配置 TLS 证书时禁止裸 /ws 监听；请显式改为 /tls/ws")
	}

	publicAddresses, err := NormalizeWebRTCDirectPublicAddresses(c.WebRTCDirectPublicAddresses)
	if err != nil {
		return err
	}
	c.WebRTCDirectPublicAddresses = publicAddresses
	if features.hasWebRTCDirect && len(publicAddresses) == 0 {
		return errors.New("配置错误：listen 含 WebRTC Direct listener 时，webrtc_direct_public_addresses 至少配置一项")
	}
	if !features.hasWebRTCDirect && len(publicAddresses) > 0 {
		return errors.New("配置错误：未监听 WebRTC Direct 时禁止配置 webrtc_direct_public_addresses；请删除该字段或增加 WebRTC Direct listener")
	}
	if !features.hasWebSocket {
		return errors.New("配置错误：listen 至少需要一条 /ws 或 /tls/ws 共享 Web/WS 入口")
	}
	if sharedWebSocketNonLoopback(c.ListenAddrs) && strings.TrimSpace(c.AdminToken) == "" {
		return errors.New("配置错误：listen 中共享 Web/WS 入口监听非 loopback 地址时必须配置 admin_token")
	}
	return nil
}

// ListenHasWebSocket 报告 listen 是否包含 WebSocket/WSS 共享 Web 入口。
// 该方法主要供装配层和测试读取已经校验过的 transport 清单。
func (c *Config) ListenHasWebSocket() bool {
	for _, text := range c.ListenAddrs {
		addr, err := ma.NewMultiaddr(strings.TrimSpace(text))
		if err != nil {
			continue
		}
		for _, protocol := range addr.Protocols() {
			if protocol.Code == ma.P_WS || protocol.Code == ma.P_WSS {
				return true
			}
		}
	}
	return false
}

// WebRTCDirectPublicAddrs 返回已规范化的 WebRTC Direct 公网基础地址副本。
// 调用方不能通过修改返回切片改变配置真值。
func (c *Config) WebRTCDirectPublicAddrs() []string {
	return append([]string(nil), c.WebRTCDirectPublicAddresses...)
}

type listenFeatures struct {
	hasWebRTCDirect   bool // 是否存在 WebRTC Direct listener
	hasWebSocket      bool // 是否存在 Web/WS/WSS 共享入口
	hasTLSWebSocket   bool // 是否存在显式 TLS WebSocket（/tls/ws 或 /wss）
	hasPlainWebSocket bool // 是否存在裸 WebSocket（/ws）
}

func validateListenAddresses(addresses []string) (features listenFeatures, err error) {
	if len(addresses) == 0 {
		return listenFeatures{}, errors.New("配置错误：listen 不能为空")
	}
	for i, text := range addresses {
		trimmed := strings.TrimSpace(text)
		addr, parseErr := ma.NewMultiaddr(trimmed)
		if parseErr != nil {
			return listenFeatures{}, fmt.Errorf("配置错误：listen 第 %d 项不是合法的 multiaddr: %w", i+1, parseErr)
		}
		hasWS := false
		hasTLS := false
		for _, protocol := range addr.Protocols() {
			switch protocol.Code {
			case ma.P_WEBRTC_DIRECT:
				features.hasWebRTCDirect = true
			case ma.P_WS:
				hasWS = true
			case ma.P_WSS:
				hasWS = true
				hasTLS = true
			case ma.P_TLS:
				hasTLS = true
			}
		}
		if hasWS {
			features.hasWebSocket = true
			if hasTLS {
				features.hasTLSWebSocket = true
			} else {
				features.hasPlainWebSocket = true
			}
		}
	}
	return features, nil
}

func sharedWebSocketNonLoopback(addresses []string) bool {
	for _, text := range addresses {
		addr, err := ma.NewMultiaddr(strings.TrimSpace(text))
		if err != nil {
			continue
		}
		hasWebSocket := false
		for _, protocol := range addr.Protocols() {
			if protocol.Code == ma.P_WS || protocol.Code == ma.P_WSS {
				hasWebSocket = true
				break
			}
		}
		if !hasWebSocket {
			continue
		}
		for _, protocol := range addr.Protocols() {
			if protocol.Code != ma.P_IP4 && protocol.Code != ma.P_IP6 {
				continue
			}
			value, valueErr := addr.ValueForProtocol(protocol.Code)
			if valueErr != nil {
				return true
			}
			ip := net.ParseIP(value)
			if ip == nil || !ip.IsLoopback() {
				return true
			}
		}
		// DNS listener 的实际绑定范围无法在静态校验时证明是 loopback，
		// 因此按非 loopback 处理，要求运维显式保护 status/scans API。
		if _, err := addr.ValueForProtocol(ma.P_DNS); err == nil {
			return true
		}
		if _, err := addr.ValueForProtocol(ma.P_DNS4); err == nil {
			return true
		}
		if _, err := addr.ValueForProtocol(ma.P_DNS6); err == nil {
			return true
		}
	}
	return false
}

// WhitelistAllowed 表示 private 模式下该规范化公钥是否在白名单中。
// public 模式不调用本方法。private 且列表为空时恒为 false，即拒绝全部客户端。
func (c *Config) WhitelistAllowed(publicKeyHex string) bool {
	if c.AccessMode != AccessModePrivate {
		return false
	}
	for _, key := range c.PublicKeyWhitelist {
		if key == publicKeyHex {
			return true
		}
	}
	return false
}

// WatcherEnabled 报告是否启用文件事件监视器；未配置时默认开启。
func (c *Config) WatcherEnabled() bool { return c.EnableFileWatcher == nil || *c.EnableFileWatcher }

func containedIn(inner, outer string) bool {
	rel, err := filepath.Rel(outer, inner)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}

func checkWritable(dir string) error {
	probe, err := os.CreateTemp(dir, ".write-probe-*")
	if err != nil {
		return err
	}
	name := probe.Name()
	if err := probe.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	return os.Remove(name)
}
