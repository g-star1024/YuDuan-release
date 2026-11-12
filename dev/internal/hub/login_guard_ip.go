// v0.4.31-C 安全 P1：登录防爆破增强 —— 全局按源 IP 维度限速 + PG 分布式锁定。
//
// 严格增量约束（零回归）：
//   - 账号维度（username|IP，v0.4.27 F-04「回环不豁免」）逐字不动；本文件只新增
//     「同一来源 IP 跨账号累计」这一独立维度，内聚进 loginGuardBlocked/Record，
//     hub.go 与 login_guard.go 的账号维度逻辑均不改。
//   - 总开关仍是 loginGuardEnabled()（默认关闭；public 形态由 cmd/hub/main.go
//     自动 os.Setenv("YUDUAN_LOGIN_GUARD","1") 开启）。LAN 默认零开销、零行为变化。
//   - 4029 契约不变：仍由 hub.go:550 的 writeErr(HTTP 200, 含秒数) 返回。
//
// 为什么 IP 维度必须对 loopback 放行（与账号维度 F-04 并不矛盾）：
//
//	反代部署下 RemoteAddr 常整体塌缩为 127.0.0.1，若 IP 维度对回环计数，
//	任意外部请求都会累加到同一把「全局锁」，形成跨来源账号的锁定 DoS
//	（README-deploy.md §反代 已记录该风险）。账号维度仍按 F-04 锁定回环，
//	因为它的 key 含 username，不会跨账号串联。
//	中枢就绪探针（POST 127.0.0.1:8080/api/v1/login）也因此天然不受 IP 维度影响：
//	它只发 1 次失败请求，远低于账号维度阈值 5，且 IP 维度完全跳过。
package hub

import (
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"yuduan/internal/store"
)

// loginGuardPGStore 惰性探测持久化后端：仅 *store.PostgresStore 返回非 nil。
// 与 wave3.go:1446 w3PG / wave5a.go:319 w5aPG 同款，无需改 hub.go 接线
// （cmd/hub/main.go:89 已把 pgStore 注入为 h.store）。
func (h *Hub) loginGuardPGStore() *store.PostgresStore {
	pg, _ := h.store.(*store.PostgresStore)
	return pg
}

func logGuardIPLock(ip string, lockSec int) {
	log.Printf("[hub][guard][ip] 来源 IP %s 跨账号登录失败达阈值，临时锁定 %ds（已发布共享锁定）", ip, lockSec)
}

func logGuardIPPGWarn(action string, err error) {
	log.Printf("[hub][guard][ip] 警告：%s失败（降级为单实例内存状态）: %v", action, err)
}

// ---- 新增 env（全部可选，缺省即默认值）----
//
//	YUDUAN_LOGIN_IP_MAX_FAILS   同 IP 跨账号失败阈值（默认 20，高于账号维度 5）
//	YUDUAN_LOGIN_IP_WINDOW_SEC  统计窗口秒（默认 300）
//	YUDUAN_LOGIN_IP_LOCK_SEC    IP 维度锁定秒数（默认 300）
//	YUDUAN_TRUST_PROXY          1=采信 X-Forwarded-For 首段（默认 0，不采信）
//	YUDUAN_LOGIN_GUARD_PG       0=强制仅内存（默认自动：PG 后端可用时共享锁定状态）

type loginGuardIPEntry struct {
	fails       int
	windowStart time.Time
	lockedUntil time.Time
}

type loginGuardIPState struct {
	mu      sync.Mutex
	entries map[string]*loginGuardIPEntry
}

// 按 *Hub 实例隔离（与账号维度 loginGuardStates 同口径，便于并发单测）。
var loginGuardIPStates sync.Map // *Hub -> *loginGuardIPState

func (h *Hub) loginGuardIPState() *loginGuardIPState {
	v, _ := loginGuardIPStates.LoadOrStore(h, &loginGuardIPState{entries: map[string]*loginGuardIPEntry{}})
	return v.(*loginGuardIPState)
}

// loginGuardClientIP 解析「最终判定用」的来源 IP：
// 默认只信 r.RemoteAddr（XFF 可伪造）；仅 YUDUAN_TRUST_PROXY=1 时采信 XFF 首段。
func loginGuardClientIP(r *http.Request) string {
	raw := r.RemoteAddr
	if h, _, err := net.SplitHostPort(raw); err == nil {
		raw = h
	}
	if strings.TrimSpace(os.Getenv("YUDUAN_TRUST_PROXY")) == "1" {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if first != "" {
				raw = first
			}
		}
	}
	return strings.TrimSpace(raw)
}

// loginGuardIPIsLoopback 判定回环（含 IPv4-mapped IPv6）。
func loginGuardIPIsLoopback(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed != nil {
		return parsed.IsLoopback()
	}
	return strings.HasPrefix(strings.ToLower(ip), "::ffff:127.")
}

// loginGuardIPExempt 决定 IP 维度是否跳过该来源。
// 回环一律放行（反代塌缩 DoS 防护 + 就绪探针保护）；强制关闭 PG 时也走内存。
func loginGuardIPExempt(ip string) bool {
	return ip == "" || loginGuardIPIsLoopback(ip)
}

// loginGuardIPBlocked 返回 IP 维度是否被锁定及建议重试秒数。
// 先查本地内存状态，再查 PG 共享锁定（多中枢实例）。两者取较晚的锁定截止。
func (h *Hub) loginGuardIPBlocked(r *http.Request) (bool, int) {
	ip := loginGuardClientIP(r)
	if loginGuardIPExempt(ip) {
		return false, 0
	}
	now := time.Now()
	win := time.Duration(loginGuardIntEnv("YUDUAN_LOGIN_IP_WINDOW_SEC", 300)) * time.Second

	var until time.Time
	st := h.loginGuardIPState()
	st.mu.Lock()
	if e := st.entries[ip]; e != nil {
		if now.Before(e.lockedUntil) {
			until = e.lockedUntil
		} else if !e.windowStart.IsZero() && now.Sub(e.windowStart) > win {
			delete(st.entries, ip)
		}
	}
	st.mu.Unlock()

	// PG 分布式锁定：其它中枢实例触发的锁定也要生效。
	if remote, ok := h.loginGuardIPRemoteLocked(ip); ok && remote.After(now) && remote.After(until) {
		until = remote
	}
	if until.IsZero() {
		return false, 0
	}
	return true, int(until.Sub(now).Seconds()) + 1
}

// loginGuardIPRecord 记录一次登录结果到 IP 维度：成功清零，失败累加并在达阈值时锁定。
// 账号维度仍由 login_guard.go 独立处理，互不影响。
func (h *Hub) loginGuardIPRecord(r *http.Request, ok bool) {
	ip := loginGuardClientIP(r)
	if loginGuardIPExempt(ip) {
		return
	}
	now := time.Now()
	maxFails := loginGuardIntEnv("YUDUAN_LOGIN_IP_MAX_FAILS", 20)
	win := time.Duration(loginGuardIntEnv("YUDUAN_LOGIN_IP_WINDOW_SEC", 300)) * time.Second
	lock := time.Duration(loginGuardIntEnv("YUDUAN_LOGIN_IP_LOCK_SEC", 300)) * time.Second

	st := h.loginGuardIPState()
	st.mu.Lock()
	if ok {
		delete(st.entries, ip)
		st.mu.Unlock()
		h.loginGuardIPClearRemote(ip)
		return
	}
	e := st.entries[ip]
	if e == nil || (!e.windowStart.IsZero() && now.Sub(e.windowStart) > win) {
		e = &loginGuardIPEntry{windowStart: now}
		st.entries[ip] = e
	}
	e.fails++
	triggered := false
	if e.fails >= maxFails {
		e.lockedUntil = now.Add(lock)
		e.fails = 0
		e.windowStart = time.Time{}
		triggered = true
	}
	lockedUntil := e.lockedUntil
	st.mu.Unlock()

	if triggered {
		logGuardIPLock(ip, int(lock.Seconds()))
		h.loginGuardIPPublishRemote(ip, now.Add(lock))
	}
	_ = lockedUntil
}

// loginGuardIPRemotePGEnabled 判定是否允许使用 PG 共享状态。
func loginGuardIPRemotePGEnabled() bool {
	return strings.TrimSpace(os.Getenv("YUDUAN_LOGIN_GUARD_PG")) != "0"
}

// loginGuardIPRemoteLocked 从 PG 读取其它实例发布的锁定截止（epoch 秒）。
// 任何错误一律静默降级为「无共享状态」，绝不阻断登录链路。
func (h *Hub) loginGuardIPRemoteLocked(ip string) (time.Time, bool) {
	pg := h.loginGuardPGStore()
	if pg == nil || !loginGuardIPRemotePGEnabled() {
		return time.Time{}, false
	}
	row, ok, err := pg.QueryOne(
		`SELECT EXTRACT(EPOCH FROM locked_until)::bigint FROM yuduan_login_guard_ip WHERE ip = $1 AND locked_until > NOW()`, ip)
	if err != nil || !ok || len(row) == 0 || row[0] == "" {
		return time.Time{}, false
	}
	sec, err := strconv.ParseInt(row[0], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(sec, 0), true
}

// loginGuardIPPublishRemote 把本实例触发的锁定发布到 PG，供其它中枢实例共享。
// 表由 login_guard_pg.go 的 RegisterMigrate 幂等创建；写入失败仅降级为单实例内存。
func (h *Hub) loginGuardIPPublishRemote(ip string, until time.Time) {
	pg := h.loginGuardPGStore()
	if pg == nil || !loginGuardIPRemotePGEnabled() {
		return
	}
	err := pg.Exec(
		`INSERT INTO yuduan_login_guard_ip (ip, locked_until, updated_at) VALUES ($1, to_timestamp($2), NOW())
		 ON CONFLICT (ip) DO UPDATE SET locked_until = EXCLUDED.locked_until, updated_at = NOW()`,
		ip, until.Unix())
	if err != nil {
		logGuardIPPGWarn("发布共享锁定", err)
	}
}

// loginGuardIPClearRemote 登录成功时清除共享锁定（避免锁定残留跨实例生效）。
func (h *Hub) loginGuardIPClearRemote(ip string) {
	pg := h.loginGuardPGStore()
	if pg == nil || !loginGuardIPRemotePGEnabled() {
		return
	}
	if err := pg.Exec(`DELETE FROM yuduan_login_guard_ip WHERE ip = $1`, ip); err != nil {
		logGuardIPPGWarn("清除共享锁定", err)
	}
}
