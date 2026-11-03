// 御端服务端中枢入口（M2 底座 + M4 远控 + M5 分发 + M6 管理与审计 + 安全基座）。
package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"yuduan/internal/audit"
	"yuduan/internal/auth"
	"yuduan/internal/directory"
	"yuduan/internal/hub"
	"yuduan/internal/keystore"
	"yuduan/internal/store"
	"yuduan/internal/tlsutil"
)

func main() {
	// D-06 全链路日志：YUDUAN_LOG_FILE 指定时，中枢日志同时写 stderr 与文件（落盘持久）。
	// 部署脚本（install.sh / install-macos.sh / register-task.ps1）统一配置该变量，
	// 使 systemd/launchd/计划任务 三种托管方式都能从日志文件取证，不再「零日志」。
	if lf := os.Getenv("YUDUAN_LOG_FILE"); lf != "" {
		if f, err := os.OpenFile(lf, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			log.SetOutput(io.MultiWriter(os.Stderr, f))
			log.Printf("[hub] 日志已落盘（stderr + %s）", lf)
		} else {
			log.Printf("[hub] 警告：无法打开 YUDUAN_LOG_FILE %s: %v", lf, err)
		}
	}

	repoDir := envOr("YUDUAN_REPO", "data/repo")
	dsn := os.Getenv("YUDUAN_DB_DSN")
	// 密钥统一经 keystore 收口（KMS/挂载文件解耦点，避免硬编码）
	secret := keystore.LoadHMACSecret()
	// 复盘 V-05/V-06 修复（v0.2.7 起）：
	//  1) HMAC 默认强制——此前 YUDUAN_HMAC_ENFORCE 默认 0（不强制），生产漏配即旁路验签；
	//     现默认开启（!= "0"），如需显式关闭才设 0（不推荐）。
	//  2) 空密钥不再回退公开 yuduan-dev-secret——此前 auth 空密钥回退公开密钥，
	//     任何能读到源码者即可伪造 admin 令牌与指令签名（完整接管）。
	//     生产必须配置密钥，否则启动即失败；仅本地开发可设 YUDUAN_INSECURE_DEV=1 显式降级。
	enforce := os.Getenv("YUDUAN_HMAC_ENFORCE") != "0"
	if secret == "" {
		if os.Getenv("YUDUAN_INSECURE_DEV") == "1" {
			secret = "yuduan-dev-secret"
			log.Printf("[hub] 警告：YUDUAN_INSECURE_DEV=1 使用公开开发密钥——仅限本地开发，严禁生产！")
		} else {
			log.Fatalf("[hub] 致命：YUDUAN_HMAC_SECRET 未配置，生产必须设置（或经 YUDUAN_HMAC_SECRET_FILE 注入）；仅本地开发可设 YUDUAN_INSECURE_DEV=1 显式降级")
		}
	}
	pepper := envOr("YUDUAN_PEPPER", envOr("YUDUAN_PW_PEPPER", "yuduan-dev-pepper"))
	dirFile := os.Getenv("YUDUAN_DIR_FILE")
	adminMustChangePW := os.Getenv("YUDUAN_ADMIN_MUST_CHANGE_PW") != "0" // 默认开启（生产安全姿态）

	// 软件包签名种子（Ed25519 32 字节，hex）。生产应来自 KMS/密钥管理（keystore 解耦点）。
	// 缺省空 → 软件包仅记 SHA-256、不签名（副端仍做哈希校验，但无验签）。
	signSeed := keystore.LoadSignSeed()
	if len(signSeed) == 32 {
		log.Printf("[hub] 软件包签名：Ed25519 已启用（种子来自 keystore）")
	} else if os.Getenv("YUDUAN_SIGN_SEED") != "" || os.Getenv("YUDUAN_SIGN_SEED_FILE") != "" {
		log.Printf("[hub] 警告：YUDUAN_SIGN_SEED/_FILE 非法（需 32 字节 hex），已退化为不签名")
	} else {
		log.Printf("[hub] 软件包签名：未启用（设置 YUDUAN_SIGN_SEED 启用 Ed25519 签名）")
	}

	// 存储 / 审计 / 账号：有 DSN 则统一走 PostgreSQL，否则内存
	var st store.Store = store.NewMemStore()
	var aud audit.Auditor = audit.NewMemAuditor()
	var us auth.UserStore = store.NewMemUserStore()
	var pgStore *store.PostgresStore
	if dsn != "" {
		pg, err := store.NewPostgresStore(dsn)
		if err != nil {
			log.Fatalf("[hub] PostgreSQL 连接失败: %v", err)
		}
		pgStore = pg
		st, aud, us = pg, pg, pg
		log.Printf("[hub] 持久化后端：PostgreSQL")
	} else {
		log.Printf("[hub] 持久化后端：内存（重启即丢；设置 YUDUAN_DB_DSN 切换到 PostgreSQL）")
	}
	store.SeedDefaultAdmin(us, pepper, adminMustChangePW)
	authSvc := auth.NewAuthService(us, secret, pepper)

	var dirSync *directory.SyncEngine
	if dirFile != "" {
		dirSync = directory.NewSyncEngine(&directory.FileDirectory{Path: dirFile}, directory.DefaultRoleMapping(), us, pepper)
		log.Printf("[hub] 目录同步源：%s", dirFile)
	}

	// 明文监听提前绑定（PublicAddr 兜底要用实际绑定地址）：默认 :8080 被占用
	// （本机常见：Docker Desktop 占 8080，曾致「hub 启动即退、控制台全部网络错误」）
	// 时自动回退候选端口；显式指定 YUDUAN_HUB_ADDR 时失败即退出（生产端口必须可预期）。
	plainLn, plainBound := listenPlainOrFallback(envOr("YUDUAN_HUB_ADDR", ":8080"))

	// §5 加密录像留存（opt-in，默认关闭）：YUDUAN_RC_RECORD=1 开启。
	// 密钥：YUDUAN_RECORD_KEY（32B hex）/ _FILE；未配置时由 HMAC 密钥派生开发态兜底。
	recordEnabled := os.Getenv("YUDUAN_RC_RECORD") == "1"
	recordRetention := 90
	if v := os.Getenv("YUDUAN_RECORD_RETENTION_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			recordRetention = n
		}
	}

	// 设备引导（档位 A）与 TLS 配置：提前解析，供 NewHub（claim 端点）与
	// TLS 监听复用。TLSAddr 仅作 claim 响应的提示字段（连接地址以广播 ws= 为准）。
	tlsAddr := os.Getenv("YUDUAN_TLS_ADDR")
	if _, ok := os.LookupEnv("YUDUAN_TLS_ADDR"); !ok {
		tlsAddr = ":8443"
	}
	caFile := envOr("YUDUAN_CA_CERT", "certs/ca.pem")
	caKey := envOr("YUDUAN_CA_KEY", "certs/ca.key")

	h := hub.NewHub(hub.HubConfig{
		RepoDir: repoDir, Store: st, Auditor: aud, Users: us,
		Auth: authSvc, HMACSecret: secret, HMACEnforce: enforce, DirSync: dirSync,
		HubID: os.Getenv("YUDUAN_HUB_ID"), PublicAddr: envOr("YUDUAN_PUBLIC_ADDR", plainBound),
		SignSeed:            signSeed,
		RecordEnabled:       recordEnabled,
		RecordDir:           envOr("YUDUAN_RECORD_DIR", "data/recordings"),
		RecordRetentionDays: recordRetention,
		RecordKey:           keystore.LoadRecordKey(),
		// 设备引导（档位 A）：claim 端点为副端签发客户端证书所需根 CA
		CACert: caFile, CAKey: caKey, TLSAddr: tlsAddr,
		// P-1 投产阻断：PG 备份/恢复（仅 PostgreSQL 后端生效；内存后端端点报错）
		BackupDir:      envOr("YUDUAN_BACKUP_DIR", "data/backups"),
		BackupKeep:     envIntOr("YUDUAN_BACKUP_KEEP", 7),
		BackupInterval: envDurOr("YUDUAN_BACKUP_INTERVAL", 24*time.Hour),
		// P-2 投产阻断：告警外部通知（webhook 优先）；为空 = 仅站内徽章
		AlertWebhookURL: os.Getenv("YUDUAN_ALERT_WEBHOOK_URL"),
	})
	if adminMustChangePW {
		log.Printf("[hub] 内置 admin 首次登录需强制改密（YUDUAN_ADMIN_MUST_CHANGE_PW=0 可关闭）")
	}

	// 多中枢指令总线（去粘性）：仅 PostgreSQL 后端可用
	if pgStore != nil {
		hubID := os.Getenv("YUDUAN_HUB_ID")
		if err := h.EnableBus(pgStore.Pool(), hubID, dsn); err != nil {
			log.Printf("[hub] 指令总线启用失败（退化为单实例模式）: %v", err)
		}
	}

	if dirSync != nil {
		if res, err := h.RunDirSync("system"); err == nil && res != nil {
			log.Printf("[hub] 目录同步完成: %+v", res)
		} else if err != nil {
			log.Printf("[hub] 目录同步失败: %v", err)
		}
	}

	go h.StartReaper()
	go h.StartRCSweeper() // W2-5：远控会话超时扫描（绝对时长上限 + 主端空闲上限）
	go h.StartBackupScheduler() // P-1 投产阻断：PG 自动备份（仅 PostgreSQL 后端生效）

	// TLS 证书：优先私有 CA 模式（certs/ca.pem 存在 → 自动签发/续签服务器证书，
	// 见 dev/cmd/ca）；无 CA 时退回一次性自签（开发态）。显式 YUDUAN_TLS_CERT/KEY 优先。
	// tlsAddr / caFile / caKey 已在 NewHub 前解析（供 claim 端点复用），此处不再重复。
	cert := envOr("YUDUAN_TLS_CERT", "certs/cert.pem")
	key := envOr("YUDUAN_TLS_KEY", "certs/key.pem")

	if os.Getenv("YUDUAN_TLS_CERT") == "" {
		if _, err := os.Stat(caFile); err == nil {
			// 私有 CA 模式：优先完整链文件（chain.pem = leaf+root，pin 模式临时
			// CAfile 需要根锚）；无链文件退回叶证书（副端需 YUDUAN_TLS_CAFILE=ca.pem）。
			// 私钥同步取 CA 目录（YUDUAN_TLS_KEY 显式指定时不覆盖）。
			caDir := filepath.Dir(caFile)
			if st, err := os.Stat(filepath.Join(caDir, "chain.pem")); err == nil && !st.IsDir() {
				cert = filepath.Join(caDir, "chain.pem")
			}
			if os.Getenv("YUDUAN_TLS_KEY") == "" {
				key = filepath.Join(caDir, "key.pem")
			}
			// 服务器证书缺失时自动签发（SAN 补充本机主机名）；
			// 已存在则沿用（轮换用 dev/cmd/ca issue-server）。启动时到期告警。
			host, _ := os.Hostname()
			if _, err := os.Stat(cert); err != nil {
				if err := tlsutil.IssueServerCert(caFile, envOr("YUDUAN_CA_KEY", "certs/ca.key"),
					cert, key, []string{host}, nil); err != nil {
					log.Printf("[hub] 从私有 CA 签发服务器证书失败: %v", err)
				} else {
					log.Printf("[hub] 已从私有 CA（%s）签发服务器证书 %s", caFile, cert)
				}
			}
			if na, err := tlsutil.LoadCertNotAfter(cert); err == nil {
				if days := int(time.Until(na).Hours() / 24); days < 30 {
					log.Printf("[hub] ⚠️ 服务器证书 %d 天后到期（%s），请运行 ca issue-server 轮换", days, na.Format("2006-01-02"))
				}
			}
		} else if _, err := os.Stat(cert); err != nil {
			if err := tlsutil.GenerateSelfSigned(cert, key); err == nil {
				log.Printf("[hub] 无私有 CA（certs/ca.pem），已生成一次性自签证书: %s（生产请用 dev/cmd/ca 建立根 CA）", cert)
			} else {
				log.Printf("[hub] ❌ 生成证书失败，仅启动明文监听: %v", err)
				log.Printf("[hub] ⚠️ 控制面已降级为明文 http/ws（无加密）。修复：确保可写 certs/ 目录，或设 YUDUAN_TLS_CERT/KEY 指向已有证书，重启后重试")
				log.Printf("[hub] ⚠️ 局域网内副端将回退明文连接（YUDUAN_HUB=ws://...）；生产务必启用 TLS/mTLS")
				tlsAddr = ""
			}
		}
	}
	if tlsAddr != "" {
		go func() {
			log.Printf("[hub] TLS 中枢监听 %s（https + wss）", tlsAddr)
			if err := http.ListenAndServeTLS(tlsAddr, cert, key, h.Handler()); err != nil && err != http.ErrServerClosed {
				// v0.4.1：TLS 监听失败（8443 被占 / 证书不可读）不再 log.Fatal 杀全进程——
				// 否则连明文 8080 都一并停服。降级为仅明文 + 告警，与明文监听的容错对齐。
				// 安全提示：TLS 失败期间局域网副端回退明文连接，生产应尽快排除端口/证书问题。
				log.Printf("[hub] ❌ TLS 中枢监听失败: %v", err)
				log.Printf("[hub] ⚠️ 控制面降级为仅明文 http/ws（无加密）。修复：释放 %s 端口或检查 certs/ 证书后重启", tlsAddr)
			}
		}()
	}

	// 设备通道 mTLS（可选）：YUDUAN_CLIENT_CA 设置时，单独监听 YUDUAN_MTLS_ADDR（默认 :8444），
	// 要求并验证客户端证书（仅放行 /ws/agent，控制台/管理 API 不在此端口暴露）。
	// 副端经 YUDUAN_CLIENT_CERT/YUDUAN_CLIENT_KEY 呈现客户端证书。
	if clientCA := os.Getenv("YUDUAN_CLIENT_CA"); clientCA != "" {
		mtlsAddr := envOr("YUDUAN_MTLS_ADDR", ":8444")
		serverCert, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			log.Printf("[hub] mTLS 加载服务端证书失败，跳过 mTLS 监听: %v", err)
		} else if caPEM, err := os.ReadFile(clientCA); err != nil {
			log.Printf("[hub] mTLS 读取客户端 CA 失败，跳过 mTLS 监听: %v", err)
		} else {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				log.Printf("[hub] mTLS 客户端 CA 解析为空，跳过 mTLS 监听")
			} else {
				tlsCfg := &tls.Config{
					Certificates: []tls.Certificate{serverCert},
					ClientAuth:   tls.RequireAndVerifyClientCert,
					ClientCAs:    pool,
				}
				ln, err := tls.Listen("tcp", mtlsAddr, tlsCfg)
				if err != nil {
					log.Printf("[hub] mTLS 监听失败: %v", err)
				} else {
					log.Printf("[hub] 设备 mTLS 监听 %s（wss，要求并验证客户端证书，仅 /ws/agent）", mtlsAddr)
					go func() {
						log.Fatal(http.Serve(ln, agentOnlyHandler(h.Handler())))
					}()
				}
			}
		}
	}

	// v0.4.14（实测报告问题 3 再修）：v0.4.12 的就绪探针只在【进程内】调用
	// authSvc.Login，只证明账号/存储就绪，不证明「HTTP 监听已真实可服务」——
	// Windows 实测（v0.4.13 报告）：就绪行 0s 命中后 7×3s 登录仍 401。
	// 改为：先在 goroutine 启动明文 HTTP 服务，再经 127.0.0.1 回环对【实际绑定端口】
	// 发真实登录请求：HTTP 200 code=0（默认密码可用）或 401（端点可达、密码非默认，
	// 与部署脚本自检③的 WARN 口径一致）均视为登录链路就绪；连不上/超时才重试。
	// 脚本看到就绪行时，HTTP 登录链路必定已真实可用。
	serveErr := make(chan error, 1)
	go func() { serveErr <- http.Serve(plainLn, h.Handler()) }()
	probePort := plainBound
	if _, port, err := net.SplitHostPort(plainBound); err == nil && port != "" {
		probePort = ":" + port
	}
	probeURL := "http://127.0.0.1" + probePort + "/api/v1/login"
	loginReady := false
	probeClient := &http.Client{Timeout: 2 * time.Second}
	for i := 0; i < 120; i++ {
		req, err := http.NewRequest(http.MethodPost, probeURL, strings.NewReader(`{"username":"admin","password":"admin123"}`))
		if err != nil {
			break
		}
		req.Header.Set("Content-Type", "application/json")
		if resp, err := probeClient.Do(req); err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized {
				loginReady = true
				break
			}
		}
		select {
		case err := <-serveErr:
			log.Fatalf("[hub] 明文中枢服务异常退出: %v", err)
		default:
		}
		time.Sleep(500 * time.Millisecond)
	}
	if loginReady {
		log.Printf("[hub] 内置 admin 账号就绪（回环 HTTP 登录链路自检通过，可登录）")
	} else {
		log.Printf("[hub] 警告：回环登录自检 60s 未通过（默认 admin 可能已改密或监听异常），中枢继续服务；请以实际 HTTP 登录为准")
	}
	log.Printf("[hub] 明文中枢监听 %s（http + ws）；控制台 / ；软件仓库 %s", plainBound, repoDir)
	// §8.4 UDP 自动发现：主端/副端未配置地址时广播 255.255.255.255:18242 即得
	// 响应携带当前有效的一次性注册令牌（档位 A 设备引导，供副端 claim 换取密钥）。
	hub.ServeDiscovery(plainBound, tlsAddr, func() string {
		h, err := os.Hostname()
		if err != nil {
			return ""
		}
		return h
	}(), h.CurrentClaimToken)
	// v0.4.14：明文服务已移至就绪探针前的 goroutine（回环登录自检依赖它），此处常驻等待。
	err := <-serveErr
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("[hub] 明文中枢服务退出: %v", err)
	}
}

// listenPlainOrFallback 绑定明文监听。仅当使用默认 :8080 且失败原因是端口占用时
// 才自动回退候选端口（并醒目提示 Agent 连接地址需同步）；其余失败一律退出。
func listenPlainOrFallback(addr string) (net.Listener, string) {
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		return ln, addr
	}
	if addr != ":8080" || !strings.Contains(err.Error(), "address already in use") {
		log.Fatalf("[hub] 明文端口监听失败 %s: %v（可设 YUDUAN_HUB_ADDR 换端口）", addr, err)
	}
	for _, alt := range []string{":8081", ":8082", ":8083", ":18080"} {
		l2, e2 := net.Listen("tcp", alt)
		if e2 == nil {
			log.Printf("[hub] ⚠️ %s 被占用（本机常见：Docker Desktop），自动改用 %s", addr, alt)
			log.Printf("[hub] ⚠️ 固定端口请设 YUDUAN_HUB_ADDR=%s；Agent 连接需同步 YUDUAN_HUB=ws://<中枢IP>%s/ws/agent", alt, alt)
			return l2, alt
		}
	}
	log.Fatalf("[hub] %s 与候选端口（8081-8083/18080）均被占用，请用 YUDUAN_HUB_ADDR 指定空闲端口", addr)
	return nil, addr
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// envIntOr 解析整型环境变量，非法/缺省返回 def。
func envIntOr(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// envDurOr 解析时长环境变量（如 "24h"、"30m"），非法/缺省返回 def。
func envDurOr(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

// agentOnlyHandler 将全路由处理器限定为仅放行设备通道 /ws/agent；其余路径 404。
// 用于 mTLS 监听，确保强制客户端证书的端口不暴露控制台/管理 API。
func agentOnlyHandler(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws/agent" {
			inner.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}
