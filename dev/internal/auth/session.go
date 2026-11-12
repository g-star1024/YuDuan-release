// session.go —— v0.4.31-E 安全 P2「会话安全」：服务端会话表 + 会话键 + 吊销 + 空闲超时。
//
// 设计约束（发版前安全加固，纯增量、默认关闭、LAN 零回归）：
//   - 令牌格式一字不改：绝不往 body 里塞 session ID / jti（否则 4 段变 5 段，破坏
//     crypto.VerifyToken 对 3/4 段令牌的兼容）。会话键由「令牌整体 SHA-256 hex」派生
//     （见 SessionID）——令牌本身不变，只是服务端多一张以 sid 为主键的状态表。
//   - 独立 SessionStore 接口：绝不扩 UserStore（其仅 4 方法，auth_test.go 的 memStore
//     与 directory.SyncEngine 都实现它，扩接口会编译失败）。
//   - 默认关闭：YUDUAN_SESSION_ENFORCE 缺省 0。开关关闭或 sessions 未挂载时，
//     VerifyToken 逐字走原路径（S-10 账号回查）、Login 不建会话——行为零回归。
//   - 平滑迁移：YUDUAN_SESSION_LEGACY_ALLOW=1 时，签名有效 / 未过期 / 无会话记录的
//     旧令牌放行并自动补建会话，避免一开启就把所有已登录客户端踢下线。
//   - 铁律 10：last_active 刷新只发生在 VerifyToken（REST 管理 API + viewer 握手），
//     绝不挂到 /ws/agent 心跳或 viewer 媒体帧（这些链路不调 VerifyToken）。
package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
)

// defaultSessionIdleSec 默认空闲超时（30 分钟），可由 YUDUAN_SESSION_IDLE_SEC 覆盖。
const defaultSessionIdleSec int64 = 30 * 60

// Session 一条服务端会话记录；时间戳均为 unix 秒。
// Revoked 为「标记吊销」而非删除行：已吊销会话在 Get 中仍 ok=true，
// 这样 legacy 宽限（仅在 ok=false 时触发）不会误放行被主动吊销的令牌。
type Session struct {
	SID        string
	Username   string
	Role       string
	IssuedAt   int64
	LastActive int64
	ExpiresAt  int64 // 绝对过期（= 令牌 exp，24h）
	Revoked    bool
}

// SessionStore 独立于 UserStore 的会话状态接口。
// 方法均为纯状态读写；空闲/过期/吊销的策略判定统一在 VerifyToken 完成，
// 保证内存与 PG 两套实现语义一致（二者都不在 Get 里吞掉「已吊销」会话）。
type SessionStore interface {
	Create(sess Session) error         // 新建或按 sid 覆盖（幂等 upsert）
	Get(sid string) (Session, bool)    // 无记录 ok=false
	Touch(sid string, now int64) error // 刷新 last_active
	Revoke(sid string) error           // 吊销单个会话（登出）
	RevokeUser(username string) error  // 吊销某账号全部会话（改密 / 重置密码）
}

// SessionID 由令牌整体派生会话键（SHA-256 hex）。令牌本身不含此值。
func SessionID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

var sessionHint sync.Once

// SessionEnforceEnabled 导出给 cmd/hub/main.go 决定是否挂载 SessionStore；
// 与内部 sessionEnforceEnabled 共用同一判定口径（避免 "1"/"on"/"true" 漂移）。
func SessionEnforceEnabled() bool { return sessionEnforceEnabled() }

// sessionEnforceEnabled：默认关闭。sync.Once 只缓存启动日志，enabled 每次读 env，
// 便于离线单测用 t.Setenv 动态切换（照 loginGuardEnabled 范式）。
func sessionEnforceEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("YUDUAN_SESSION_ENFORCE")))
	enabled := v == "1" || v == "on" || v == "true"
	sessionHint.Do(func() {
		if enabled {
			log.Printf("[auth][session] 会话安全已启用（空闲超时 %ds，legacy_allow=%v）",
				sessionIdleSec(), sessionLegacyAllow())
		} else {
			log.Printf("[auth][session] 会话安全未启用（默认关闭，LAN 零回归）；公网自建部署须设 YUDUAN_SESSION_ENFORCE=1 开启")
		}
	})
	return enabled
}

func sessionLegacyAllow() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("YUDUAN_SESSION_LEGACY_ALLOW")))
	return v == "1" || v == "on" || v == "true"
}

func sessionIdleSec() int64 {
	if s := strings.TrimSpace(os.Getenv("YUDUAN_SESSION_IDLE_SEC")); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return defaultSessionIdleSec
}

// ---- MemSessionStore：sync.Mutex + map，内存后端（重启即丢）----

type MemSessionStore struct {
	mu sync.Mutex
	m  map[string]Session
}

func NewMemSessionStore() *MemSessionStore {
	return &MemSessionStore{m: make(map[string]Session)}
}

var _ SessionStore = (*MemSessionStore)(nil)

func (s *MemSessionStore) Create(sess Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[sess.SID] = sess
	return nil
}

func (s *MemSessionStore) Get(sid string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[sid]
	return sess, ok
}

func (s *MemSessionStore) Touch(sid string, now int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.m[sid]; ok && !sess.Revoked {
		sess.LastActive = now
		s.m[sid] = sess
	}
	return nil
}

func (s *MemSessionStore) Revoke(sid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.m[sid]; ok {
		sess.Revoked = true
		s.m[sid] = sess
	}
	return nil
}

func (s *MemSessionStore) RevokeUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sid, sess := range s.m {
		if sess.Username == username {
			sess.Revoked = true
			s.m[sid] = sess
		}
	}
	return nil
}

// RevokeSession 吊销某个令牌对应的会话（供 hub.handleLogout 调用）。
// sessions 未挂载（开关关闭）时返回 false 且为空操作——前端「无论成败」都清本地态。
func (s *AuthService) RevokeSession(token string) bool {
	if s.sessions == nil {
		return false
	}
	return s.sessions.Revoke(SessionID(token)) == nil
}
