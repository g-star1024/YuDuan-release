// v0.4.31-B 安全 P1：TLS ACME 证书自动续期 + 热重载（纯增量、默认关闭、LAN 零回归）。
//
// 本文件实现 RenewWatcher：仅当 YUDUAN_ACME_AUTORENEW=1 且网络形态为 public 时启用
// （见 RenewalEnabled），周期性读取当前证书 NotAfter，距到期 <RenewDays 天时复用
// 同包 Issue 的 HTTP-01 客户端续期，成功后：
//  1. 先校验新证书/私钥可被 tls.X509KeyPair 加载（绝不把坏证书换上去）；
//  2. 原子替换磁盘 cert/key（同目录临时文件 + rename）；
//  3. 触发热重载回调（由 cmd/hub 注入，swap 内存证书指针，零重启）；
//  4. 计算新证书 SPKI SHA-256 指纹，落盘 + 日志，供运维带外同步副端 YUDUAN_TLS_PIN。
//
// 铁律：失败只记日志 + 指数退避重试，绝不 log.Fatal 杀进程、绝不降级明文。
// 零新增第三方依赖（Go 标准库）；Issue/时间/证书读取/热重载/日志均可注入，便于离线单测。
package acme

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"yuduan/internal/tlsutil"
)

const (
	// DefaultRenewDays：距到期 <20 天进入续期窗口（YUDUAN_ACME_RENEW_DAYS 可覆盖）。
	DefaultRenewDays = 20
	// DefaultCheckInterval：轮询周期（YUDUAN_ACME_CHECK_INTERVAL 可覆盖，单测注入短间隔）。
	DefaultCheckInterval = 12 * time.Hour
	// DefaultMaxBackoff：失败退避上限（YUDUAN_ACME_MAX_BACKOFF 可覆盖）。
	DefaultMaxBackoff = time.Hour
	// DefaultFingerprintFile：新证书 SPKI 指纹落盘位置（运维可取，带外同步副端 PIN）。
	DefaultFingerprintFile = "data/cert-fingerprint"
	// DefaultHTTPListen：standalone HTTP-01 临时监听地址（YUDUAN_ACME_HTTP_LISTEN 可覆盖）。
	DefaultHTTPListen = ":80"
)

// RenewConfig 是 RenewWatcher 的配置。生产由 RenewConfigFromEnv + cmd/hub 接线填充；
// 单测可直接构造并注入全部依赖函数，实现零网络、零副作用。
type RenewConfig struct {
	NetMode         string   // "public" / "lan"；仅 public 启用（RenewalEnabled 判定）
	CertPath        string   // 当前 fullchain 路径（YUDUAN_TLS_CERT，续期替换目标）
	KeyPath         string   // 当前私钥路径（YUDUAN_TLS_KEY，续期替换目标）
	Domains         []string // 续期域名；首个为主域名（当前 Issue 单域名）
	Email           string   // ACME 注册邮箱
	Webroot         string   // 非空走 webroot 模式，空走 standalone
	HTTPListen      string   // standalone HTTP-01 监听地址
	DirectoryURL    string   // 显式 ACME Directory（空则由 Staging 选 LE 端点）
	Staging         bool     // 使用 LE 预发环境
	RenewDays       int      // 续期阈值（天）
	CheckInterval   time.Duration
	MaxBackoff      time.Duration
	FingerprintPath string // SPKI 指纹落盘路径

	// 可注入依赖（零值 = 真实实现）；单测用。
	IssueFn        func(Options) (Result, error)
	LoadNotAfterFn func(string) (time.Time, error)
	Reload         func(certPEM, keyPEM []byte) error
	Now            func() time.Time
	Logf           func(string, ...any)
}

// RenewalEnabled 判定是否启用自动续期：必须同时满足
// YUDUAN_ACME_AUTORENEW=1 且 netMode=public。默认（未设置 / lan）一律 false，
// 保证 LAN 默认行为逐字节不变（铁律 1）。
func RenewalEnabled(netMode string) bool {
	if os.Getenv("YUDUAN_ACME_AUTORENEW") != "1" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(netMode), "public")
}

// RenewConfigFromEnv 读取续期相关环境变量并填充配置（不含热重载等运行时依赖）。
// 新增 env（均为可选覆盖，缺省即默认值）：
//
//	YUDUAN_ACME_DOMAINS        逗号分隔域名；为空回退 YUDUAN_PUBLIC_DOMAIN
//	YUDUAN_ACME_EMAIL          注册邮箱；为空回退 admin@<主域名>
//	YUDUAN_ACME_WEBROOT        webroot 目录；空则 standalone（默认）
//	YUDUAN_ACME_HTTP_LISTEN    standalone 监听地址（默认 :80）
//	YUDUAN_ACME_DIRECTORY      显式 ACME Directory URL（默认按 Staging 选 LE）
//	YUDUAN_ACME_STAGING        1=预发环境（默认 0/生产）
//	YUDUAN_ACME_RENEW_DAYS     续期阈值天数（默认 20）
//	YUDUAN_ACME_CHECK_INTERVAL 轮询周期（默认 12h，如 "30m"）
//	YUDUAN_ACME_MAX_BACKOFF    失败退避上限（默认 1h）
//	YUDUAN_ACME_FINGERPRINT_FILE 指纹落盘路径（默认 data/cert-fingerprint）
func RenewConfigFromEnv(netMode, certPath, keyPath string) RenewConfig {
	var domains []string
	for _, d := range strings.Split(os.Getenv("YUDUAN_ACME_DOMAINS"), ",") {
		if d = strings.TrimSpace(d); d != "" {
			domains = append(domains, d)
		}
	}
	if len(domains) == 0 {
		if d := strings.TrimSpace(os.Getenv("YUDUAN_PUBLIC_DOMAIN")); d != "" {
			domains = []string{d}
		}
	}
	email := strings.TrimSpace(os.Getenv("YUDUAN_ACME_EMAIL"))
	if email == "" && len(domains) > 0 {
		email = "admin@" + domains[0]
	}
	return RenewConfig{
		NetMode:         netMode,
		CertPath:        certPath,
		KeyPath:         keyPath,
		Domains:         domains,
		Email:           email,
		Webroot:         strings.TrimSpace(os.Getenv("YUDUAN_ACME_WEBROOT")),
		HTTPListen:      envStr("YUDUAN_ACME_HTTP_LISTEN", DefaultHTTPListen),
		DirectoryURL:    strings.TrimSpace(os.Getenv("YUDUAN_ACME_DIRECTORY")),
		Staging:         os.Getenv("YUDUAN_ACME_STAGING") == "1",
		RenewDays:       envInt("YUDUAN_ACME_RENEW_DAYS", DefaultRenewDays),
		CheckInterval:   envDur("YUDUAN_ACME_CHECK_INTERVAL", DefaultCheckInterval),
		MaxBackoff:      envDur("YUDUAN_ACME_MAX_BACKOFF", DefaultMaxBackoff),
		FingerprintPath: envStr("YUDUAN_ACME_FINGERPRINT_FILE", DefaultFingerprintFile),
	}
}

// ShouldRenew 是「距到期 <renewDays 天」的纯函数判据（供阈值边界单测）。
// 用精确时长比较：notAfter < now + renewDays*24h 即触发（20 天整不触发）。
func ShouldRenew(now, notAfter time.Time, renewDays int) bool {
	if renewDays <= 0 {
		renewDays = DefaultRenewDays
	}
	return notAfter.Before(now.Add(time.Duration(renewDays) * 24 * time.Hour))
}

// RenewWatcher 持有配置与退避状态。Start 在后台周期运行；Tick 执行一次检查，
// 单测直接调用 Tick 即可覆盖全部续期路径（零网络）。
type RenewWatcher struct {
	cfg            RenewConfig
	issueFn        func(Options) (Result, error)
	loadNotAfterFn func(string) (time.Time, error)
	reloadFn       func([]byte, []byte) error
	nowFn          func() time.Time
	logf           func(string, ...any)

	mu        sync.Mutex
	backoff   time.Duration
	nextRetry time.Time
	failures  int
}

// NewRenewWatcher 填充默认值并绑定依赖（未注入的函数用真实实现）。
func NewRenewWatcher(cfg RenewConfig) *RenewWatcher {
	if cfg.RenewDays <= 0 {
		cfg.RenewDays = DefaultRenewDays
	}
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = DefaultCheckInterval
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = DefaultMaxBackoff
	}
	if cfg.HTTPListen == "" {
		cfg.HTTPListen = DefaultHTTPListen
	}
	if cfg.FingerprintPath == "" {
		cfg.FingerprintPath = DefaultFingerprintFile
	}
	w := &RenewWatcher{
		cfg:            cfg,
		issueFn:        cfg.IssueFn,
		loadNotAfterFn: cfg.LoadNotAfterFn,
		reloadFn:       cfg.Reload,
		nowFn:          cfg.Now,
		logf:           cfg.Logf,
	}
	if w.issueFn == nil {
		w.issueFn = Issue
	}
	if w.loadNotAfterFn == nil {
		w.loadNotAfterFn = tlsutil.LoadCertNotAfter
	}
	if w.nowFn == nil {
		w.nowFn = time.Now
	}
	if w.logf == nil {
		w.logf = log.Printf
	}
	// reloadFn 允许为 nil（仅落盘、不热重载）；生产由 cmd/hub 注入 certHolder.Reload。
	return w
}

// Start 启动后台续期循环（ctx 取消即退出）。启动先检查一次，之后按 CheckInterval 轮询。
// 仅记日志、绝不 log.Fatal：任何失败都被 Tick 内的退避逻辑收口，不杀进程、不降级明文。
func (w *RenewWatcher) Start(ctx context.Context) {
	w.logf("[acme-renew] 已启用：netMode=%s 周期=%s 阈值=%d天 domains=%v",
		w.cfg.NetMode, w.cfg.CheckInterval, w.cfg.RenewDays, w.cfg.Domains)
	w.Tick()
	ticker := time.NewTicker(w.cfg.CheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			w.logf("[acme-renew] 停止")
			return
		case <-ticker.C:
			w.Tick()
		}
	}
}

// Tick 执行一次「读取到期时间 → 判阈值 → 续期」检查。离线单测直接调用本方法。
func (w *RenewWatcher) Tick() {
	now := w.nowFn()

	w.mu.Lock()
	inBackoff := now.Before(w.nextRetry)
	w.mu.Unlock()
	if inBackoff {
		w.logf("[acme-renew] 退避中，跳过本轮检查（下次重试 %s）", w.nextRetry.Format(time.RFC3339))
		return
	}

	notAfter, err := w.loadNotAfterFn(w.cfg.CertPath)
	if err != nil {
		w.fail(fmt.Errorf("读取当前证书到期时间: %w", err))
		return
	}
	if !ShouldRenew(now, notAfter, w.cfg.RenewDays) {
		w.logf("[acme-renew] 未进续期窗口：距到期 %d 天（阈值 %d 天）",
			int(notAfter.Sub(now).Hours()/24), w.cfg.RenewDays)
		w.resetBackoff()
		return
	}
	if len(w.cfg.Domains) == 0 || w.cfg.Domains[0] == "" {
		w.fail(fmt.Errorf("未配置续期域名（请设置 YUDUAN_ACME_DOMAINS 或 YUDUAN_PUBLIC_DOMAIN）"))
		return
	}

	pin, err := w.renew()
	if err != nil {
		w.fail(err)
		return
	}
	w.resetBackoff()
	w.logf("[acme-renew] 续期成功：新证书已原子替换并热重载；SPKI PIN=%s（副端若启用 YUDUAN_TLS_PIN 请带外同步；指纹已写入 %s）",
		pin, w.cfg.FingerprintPath)
}

// renew 执行一次完整续期，返回新证书 SPKI 指纹。任何错误都作为「失败」由 Tick 退避重试。
func (w *RenewWatcher) renew() (string, error) {
	tmpDir, err := os.MkdirTemp("", "yuduan-acme-renew-")
	if err != nil {
		return "", fmt.Errorf("创建临时输出目录: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	domain := w.cfg.Domains[0]
	if len(w.cfg.Domains) > 1 {
		// 当前 Issue 为单域名 CSR（makeCSR 单 SAN）；多域名 SAN 需后续扩展，此处取首个。
		w.logf("[acme-renew] 注意：ACME 客户端为单域名签发，仅使用首个域名 %q；YUDUAN_ACME_DOMAINS 其余域名未签发", domain)
	}
	opts := Options{
		Domain:       domain,
		Email:        w.cfg.Email,
		DirectoryURL: w.cfg.DirectoryURL,
		CertsDir:     tmpDir,
		HTTPListen:   w.cfg.HTTPListen,
		Staging:      w.cfg.Staging,
		Webroot:      w.cfg.Webroot,
	}
	res, err := w.issueFn(opts)
	if err != nil {
		return "", fmt.Errorf("ACME 签发（domain=%s）: %w", domain, err)
	}

	newCert, err := os.ReadFile(res.FullchainPath)
	if err != nil {
		return "", fmt.Errorf("读取新证书: %w", err)
	}
	newKey, err := os.ReadFile(res.KeyPath)
	if err != nil {
		return "", fmt.Errorf("读取新私钥: %w", err)
	}
	// 前置门：绝不把无法加载的证书/私钥换上去（否则 TLS 监听整体不可用）。
	if _, err := tls.X509KeyPair(newCert, newKey); err != nil {
		return "", fmt.Errorf("新证书/私钥无效，拒绝替换: %w", err)
	}

	// SPKI 指纹口径与副端 YUDUAN_TLS_PIN 一致（叶证书 SPKI DER 的 SHA-256 hex 小写），
	// 见 rust/agent/src/tls.rs:143-196（spki_sha256_hex）与 :215-232（verify_server_pin）。
	pin, err := tlsutil.SpkiPinHexFromPEM(newCert)
	if err != nil {
		return "", fmt.Errorf("计算新证书 SPKI 指纹: %w", err)
	}

	// 原子替换磁盘 cert/key：先写同目录临时文件（sync + close）再 rename。
	// 说明：当前进程的热重载走内存指针（reloadFn），磁盘文件仅用于下次启动加载，
	// 因此两次 rename 的极小窗口不影响在线服务；窗口内重启若 cert/key 不匹配，
	// 会走 cmd/hub 既有的「TLS 监听失败降级明文 + 告警」容错，运维可重跑续期恢复。
	if err := atomicWrite(w.cfg.CertPath, newCert, 0o644); err != nil {
		return "", fmt.Errorf("原子替换证书 %s: %w", w.cfg.CertPath, err)
	}
	if err := atomicWrite(w.cfg.KeyPath, newKey, 0o600); err != nil {
		return "", fmt.Errorf("原子替换私钥 %s: %w", w.cfg.KeyPath, err)
	}

	// 触发热重载（内存 swap，零重启）。放在磁盘替换之后，作为「发布」动作。
	if w.reloadFn != nil {
		if err := w.reloadFn(newCert, newKey); err != nil {
			return "", fmt.Errorf("证书热重载回调: %w", err)
		}
	}

	// 指纹落盘 + 日志。h.audit() 属 hub 内部方法且本轮边界禁止改 hub.go，故只落
	// 文件 + 日志（文件方案零侵入、运维可直接 cat 后带外分发）。写失败仅醒目告警，
	// 不判整次续期失败（避免重复签发撞 LE 速率限制），PIN 仍可从日志获取。
	if err := writeFingerprint(w.cfg.FingerprintPath, pin); err != nil {
		w.logf("[acme-renew] 警告：指纹文件写入失败（不影响本次续期，PIN=%s）: %v", pin, err)
	} else {
		w.logf("[acme-renew] 新证书 SPKI 指纹（副端 YUDUAN_TLS_PIN 口径）= %s，已写入 %s；请带外同步副端",
			pin, w.cfg.FingerprintPath)
	}
	return pin, nil
}

// fail 记录失败、按指数退避（cap 到 MaxBackoff）设定下次重试时间。
// 只记日志：绝不 log.Fatal 杀进程、绝不降级明文（铁律：安全失败不静默降级）。
func (w *RenewWatcher) fail(err error) {
	w.mu.Lock()
	w.failures++
	if w.backoff <= 0 {
		w.backoff = w.cfg.CheckInterval
	} else {
		w.backoff *= 2
	}
	if w.backoff > w.cfg.MaxBackoff {
		w.backoff = w.cfg.MaxBackoff
	}
	w.nextRetry = w.nowFn().Add(w.backoff)
	n, b := w.failures, w.backoff
	w.mu.Unlock()
	w.logf("[acme-renew] 续期失败（第 %d 次）：%v；退避 %s 后重试", n, err, b)
}

// resetBackoff 在「无需续期」或「续期成功」后清除退避窗口（failures 累计保留供观测）。
func (w *RenewWatcher) resetBackoff() {
	w.mu.Lock()
	w.backoff = 0
	w.nextRetry = time.Time{}
	w.mu.Unlock()
}

// atomicWrite 把 data 原子写入 path：同目录临时文件 → chmod → 写 → sync → close → rename。
// os.Rename 在 Go 中跨平台支持覆盖已存在文件（Windows 走 MOVEFILE_REPLACE_EXISTING）。
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".renew-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // rename 成功后源文件已不存在，忽略 ENOENT
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// writeFingerprint 把 64 位小写 hex 指纹写入文件（纯 hex + 换行，便于运维 cat / 复制）。
func writeFingerprint(path, pin string) error {
	return atomicWrite(path, []byte(pin+"\n"), 0o644)
}

// ---- env 解析辅助（acme 包私有）----

func envStr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func envDur(k string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}
