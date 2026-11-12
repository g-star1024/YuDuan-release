// Package hub —— v0.4.25 客户自建公网部署安全加固：登录失败锁定 / 防爆破。
//
// 设计约束（铁律 1 v1.1 + Gate 2026-11-06）：
//   - 产品不托管公网服务；公网只是客户自建部署形态，因此本能力**默认关闭**，
//     局域网部署行为一字不改。客户在公网环境部署时显式设置 YUDUAN_LOGIN_GUARD=1 开启。
//   - 不能用「TLS :8443 是否启用」来推断公网部署：cmd/hub/main.go 中 YUDUAN_TLS_ADDR
//     默认即 :8443（LAN 也会启用 TLS），以此判定会破坏 LAN 默认口径。
//   - 粒度为「账号 + 来源 IP」，只信 r.RemoteAddr（不采信可伪造的 X-Forwarded-For）。
//   - v0.4.27 F-04：回环来源不再豁免。原「loopback 全放行」会把本机反向代理 /
//     本地转发的外部请求一并放行（公网防爆破整体失效），且注释声称「会锁住就绪
//     探针」与事实不符——writeErr 恒 HTTP 200，探针首次即 break，最多记 1 次失败，
//     远不达默认阈值 5。现回环与非回环一视同仁地计数与锁定。
//   - 4029 必须继续走 writeErr（HTTP 200）。严禁改成真实 HTTP 429：就绪探针只认
//     200/401，改 429 会让探针走满 120×500ms 触发 60s 告警。
//   - 状态按 *Hub 实例隔离（sync.Map），便于并发测试；不落库、不引入外部依赖。
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
)

type loginGuardEntry struct {
	fails       int
	windowStart time.Time
	lockedUntil time.Time
}

type loginGuardState struct {
	mu      sync.Mutex
	entries map[string]*loginGuardEntry
}

var (
	loginGuardStates sync.Map // *Hub -> *loginGuardState
	loginGuardHint   sync.Once
)

func (h *Hub) loginGuardState() *loginGuardState {
	v, _ := loginGuardStates.LoadOrStore(h, &loginGuardState{entries: map[string]*loginGuardEntry{}})
	return v.(*loginGuardState)
}

func loginGuardIntEnv(name string, def int) int {
	if s := strings.TrimSpace(os.Getenv(name)); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// loginGuardEnabled：默认关闭；YUDUAN_LOGIN_GUARD=1/on/true 开启。
// 首次判定时打印一条启动提示，引导公网自建部署的运维开启该基线。
func loginGuardEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("YUDUAN_LOGIN_GUARD")))
	enabled := v == "1" || v == "on" || v == "true"
	loginGuardHint.Do(func() {
		if enabled {
			log.Printf("[hub][guard] 登录防爆破已启用（%d 次失败 / %ds 窗口 → 锁定 %ds）",
				loginGuardIntEnv("YUDUAN_LOGIN_MAX_FAILS", 5),
				loginGuardIntEnv("YUDUAN_LOGIN_WINDOW_SEC", 300),
				loginGuardIntEnv("YUDUAN_LOGIN_LOCK_SEC", 300))
		} else {
			log.Printf("[hub][guard] 登录防爆破未启用（局域网默认口径不变）；客户自建公网部署须设 YUDUAN_LOGIN_GUARD=1 开启")
		}
	})
	return enabled
}

// loginGuardKey 以「账号 + 来源 IP」为键；只取 r.RemoteAddr，不采信代理头。
func loginGuardKey(r *http.Request, username string) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSpace(username)) + "|" + host
}

// loginGuardBlocked 汇总两个独立维度：账号维度（username|IP）与 v0.4.31-C 新增的
// 全局 IP 维度（同一来源跨账号累计）。任一维度锁定即拒绝，重试秒数取较晚者。
// 账号维度逻辑见 loginGuardAccountBlocked，逐字保持 v0.4.27 F-04 口径不变。
func (h *Hub) loginGuardBlocked(r *http.Request, username string) (bool, int) {
	if !loginGuardEnabled() {
		return false, 0
	}
	acctBlocked, acctRetry := h.loginGuardAccountBlocked(r, username)
	ipBlocked, ipRetry := h.loginGuardIPBlocked(r)
	if !acctBlocked && !ipBlocked {
		return false, 0
	}
	retry := acctRetry
	if ipRetry > retry {
		retry = ipRetry
	}
	return true, retry
}

// loginGuardAccountBlocked 是原账号维度判定（v0.4.27 F-04：回环来源不豁免）。
// v0.4.31-C 仅把外层入口改为 loginGuardBlocked 组合器，本函数体逐字未改。
func (h *Hub) loginGuardAccountBlocked(r *http.Request, username string) (bool, int) {
	if !loginGuardEnabled() {
		return false, 0
	}
	key := loginGuardKey(r, username)
	st := h.loginGuardState()
	now := time.Now()
	win := time.Duration(loginGuardIntEnv("YUDUAN_LOGIN_WINDOW_SEC", 300)) * time.Second
	st.mu.Lock()
	defer st.mu.Unlock()
	e := st.entries[key]
	if e == nil {
		return false, 0
	}
	if now.Before(e.lockedUntil) {
		return true, int(e.lockedUntil.Sub(now).Seconds()) + 1
	}
	if !e.windowStart.IsZero() && now.Sub(e.windowStart) > win {
		delete(st.entries, key)
	}
	return false, 0
}

// loginGuardRecord 记录一次登录结果到两个独立维度：账号维度（原逻辑）与
// v0.4.31-C 新增的全局 IP 维度。账号维度逐字保持 v0.4.27 F-04 口径。
func (h *Hub) loginGuardRecord(r *http.Request, username string, ok bool) {
	if !loginGuardEnabled() {
		return
	}
	h.loginGuardAccountRecord(r, username, ok)
	h.loginGuardIPRecord(r, ok)
}

// loginGuardAccountRecord 是原账号维度记录逻辑，v0.4.31-C 逐字未改。
func (h *Hub) loginGuardAccountRecord(r *http.Request, username string, ok bool) {
	if !loginGuardEnabled() {
		return
	}
	key := loginGuardKey(r, username)
	st := h.loginGuardState()
	now := time.Now()
	maxFails := loginGuardIntEnv("YUDUAN_LOGIN_MAX_FAILS", 5)
	win := time.Duration(loginGuardIntEnv("YUDUAN_LOGIN_WINDOW_SEC", 300)) * time.Second
	lock := time.Duration(loginGuardIntEnv("YUDUAN_LOGIN_LOCK_SEC", 300)) * time.Second
	st.mu.Lock()
	defer st.mu.Unlock()
	if ok {
		delete(st.entries, key)
		return
	}
	e := st.entries[key]
	if e == nil || (!e.windowStart.IsZero() && now.Sub(e.windowStart) > win) {
		e = &loginGuardEntry{windowStart: now}
		st.entries[key] = e
	}
	e.fails++
	if e.fails >= maxFails {
		e.lockedUntil = now.Add(lock)
		e.fails = 0
		e.windowStart = time.Time{}
		log.Printf("[hub][guard] 账号 %s 登录失败达阈值，临时锁定 %ds", username, int(lock.Seconds()))
	}
}
