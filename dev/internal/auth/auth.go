// Package auth 实现御端 M6 管理与审计所需的身份认证与 RBAC。
// 角色：admin（全部权限）/ operator（运维操作）/ viewer（只读）。
// 仅依赖标准库，登录令牌由 internal/crypto 签发。
package auth

import (
	"strings"
	"time"

	"yuduan/internal/crypto"
)

// 角色定义。
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

// 权限点（用于接口级门禁）。
const (
	PermDeviceView   = "device:view"
	PermDeviceCmd    = "device:command"
	PermRCSession    = "rc:session"
	PermSoftwareMgmt = "software:manage"
	PermAuditView    = "audit:view"
	PermUserManage   = "user:manage"
	PermDirSync      = "dir:sync"
	// PermRCApprove —— W2-4 敏感设备远控二级审批：仅 admin 持有。
	// operator 可发起远控（PermRCSession）但敏感设备须由 admin 复核放行的设计意图：
	// 「发起」与「审批」分离，避免单人即可触达敏感终端（铁律 4 高危操作审批）。
	PermRCApprove = "rc:approve"
	// PermConfigView —— v0.4.31-A 中枢配置只读（GET）。operator + admin 均持有。
	// 响应绝不回显敏感密钥（HMAC/TLS/CA/PG-DSN 等）。
	PermConfigView = "config:view"
	// PermConfigWrite —— v0.4.31-A 中枢配置写回（POST）。仅 admin 持有：
	// 敏感项（密钥类）任何角色都不开放 API 写，仅能改 env 重启生效。
	PermConfigWrite = "config:write"
)

// rolePerms 定义各角色拥有的权限集合。
var rolePerms = map[string]map[string]bool{
	RoleAdmin:    {PermDeviceView: true, PermDeviceCmd: true, PermRCSession: true, PermSoftwareMgmt: true, PermAuditView: true, PermUserManage: true, PermDirSync: true, PermRCApprove: true, PermConfigView: true, PermConfigWrite: true},
	RoleOperator: {PermDeviceView: true, PermDeviceCmd: true, PermRCSession: true, PermSoftwareMgmt: true, PermAuditView: true, PermConfigView: true},
	RoleViewer:   {PermDeviceView: true, PermAuditView: true},
}

// User 表示一个后台账号。
type User struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	Password    string `json:"-"` // 仅存储摘要
	Disabled    bool   `json:"disabled"`
	// MustChangePW 为 true 时，登录后仅允许调用改密接口，其余一律 403。
	MustChangePW bool   `json:"must_change_password"`
	Source       string `json:"source"` // local=本地账号 / directory=目录同步
}

// UserStore 账号持久化接口；内存与 PostgreSQL 两种实现都遵循它。
type UserStore interface {
	UpsertUser(u User)
	GetUserByName(name string) (User, bool)
	ListUsers() []User
	Count() int
}

// AuthService 提供登录与令牌校验。
type AuthService struct {
	store    UserStore
	secret   string
	pepper   string
	sessions SessionStore // v0.4.31-E：可选会话存储（WithSessionStore 挂载；nil=关闭）
}

// NewAuthService 构造认证服务。
//
// 复盘 V-06 修复（v0.2.7 起）：secret 为空时**不再回退公开 yuduan-dev-secret**——
// 此前任何读到源码者即可用该公开密钥伪造 admin 令牌与指令签名（完整接管）。
// 现保持空 secret，Login/VerifyToken 将一律拒绝（无密钥 = 不可认证），
// 由中枢入口（cmd/hub/main.go）保证生产必须配置密钥，否则启动即失败。
func NewAuthService(store UserStore, secret, pepper string) *AuthService {
	if pepper == "" {
		pepper = "yuduan-dev-pepper"
	}
	return &AuthService{store: store, secret: secret, pepper: pepper}
}

// WithSessionStore 可选挂载服务端会话存储（v0.4.31-E）。
// 保持 NewAuthService 的 3 参签名不变；开关关闭时即便挂载也走原路径（见 VerifyToken）。
func (s *AuthService) WithSessionStore(ss SessionStore) *AuthService {
	s.sessions = ss
	return s
}

// LoginResult 登录成功后的会话信息。
type LoginResult struct {
	Token              string
	Role               string
	MustChangePassword bool
}

// Login 校验口令并签发会话令牌（24h 有效）。
// 旧格式口令（无盐 HMAC）在验证通过后透明升级为 argon2id。
// V-06 修复：无密钥（secret 为空）时拒绝登录——空密钥若被用于 HMAC 签名/验签，
// 两端一致会导致攻击者同样能用空密钥伪造令牌，比无鉴权更隐蔽。
func (s *AuthService) Login(username, password string) (*LoginResult, error) {
	if s.secret == "" {
		return nil, fmtError("auth disabled: no secret configured")
	}
	u, ok := s.store.GetUserByName(username)
	if !ok || u.Disabled {
		return nil, fmtError("invalid credentials")
	}
	if !crypto.VerifyPassword(password, s.pepper, u.Password) {
		return nil, fmtError("invalid credentials")
	}
	if crypto.NeedsRehash(u.Password) {
		if upgraded := crypto.HashPassword(password, s.pepper); upgraded != "" {
			u.Password = upgraded
			s.store.UpsertUser(u)
		}
	}
	exp := time.Now().Add(24 * time.Hour).Unix()
	token := crypto.SignToken(s.secret, u.Username, u.Role, exp, u.MustChangePW)
	// v0.4.31-E：仅当会话安全开关启用且已挂载 SessionStore 时建会话；
	// 开关关闭时逐字保持既有签发路径（LAN 零回归）。
	if sessionEnforceEnabled() && s.sessions != nil {
		now := time.Now().Unix()
		_ = s.sessions.Create(Session{
			SID: SessionID(token), Username: u.Username, Role: u.Role,
			IssuedAt: now, LastActive: now, ExpiresAt: exp, Revoked: false,
		})
	}
	return &LoginResult{Token: token, Role: u.Role, MustChangePassword: u.MustChangePW}, nil
}

// ChangePassword 用户自助改密：校验旧口令、执行强度策略、清除改密标记。
func (s *AuthService) ChangePassword(username, oldPassword, newPassword string) error {
	if err := ValidatePasswordStrength(newPassword); err != nil {
		return err
	}
	u, ok := s.store.GetUserByName(username)
	if !ok || u.Disabled {
		return fmtError("user not found")
	}
	if !crypto.VerifyPassword(oldPassword, s.pepper, u.Password) {
		return fmtError("invalid old password")
	}
	if oldPassword == newPassword {
		return fmtError("new password must differ from old")
	}
	hash := crypto.HashPassword(newPassword, s.pepper)
	if hash == "" {
		return fmtError("password hashing failed")
	}
	u.Password = hash
	u.MustChangePW = false
	s.store.UpsertUser(u)
	// v0.4.31-E：改密后吊销该账号全部会话，堵住「其它标签页 / 已泄露旧令牌
	// 仍有效 24h」的缺口（仅开关启用时生效，关闭时行为逐字不变）。
	if sessionEnforceEnabled() && s.sessions != nil {
		_ = s.sessions.RevokeUser(u.Username)
	}
	return nil
}

// ForcePasswordChange 由 admin 对指定账号设置强制改密（下次登录即生效）。
func (s *AuthService) ForcePasswordChange(username string) error {
	u, ok := s.store.GetUserByName(username)
	if !ok {
		return fmtError("user not found")
	}
	u.MustChangePW = true
	s.store.UpsertUser(u)
	return nil
}

// ValidRole 判断角色是否为合法值（admin/operator/viewer）。
// CreateUser 由 admin 创建本地账号：校验用户名/角色/密码强度，argon2id 落盘。
func (s *AuthService) CreateUser(username, displayName, role, password string) error {
	if username == "" {
		return fmtError("username required")
	}
	if !ValidRole(role) {
		return fmtError("invalid role: must be admin/operator/viewer")
	}
	if err := ValidatePasswordStrength(password); err != nil {
		return err
	}
	if _, ok := s.store.GetUserByName(username); ok {
		return fmtError("user already exists: " + username)
	}
	hash := crypto.HashPassword(password, s.pepper)
	if hash == "" {
		return fmtError("password hashing failed")
	}
	s.store.UpsertUser(User{
		Username: username, DisplayName: displayName, Role: role,
		Password: hash, MustChangePW: false, Source: "local",
	})
	return nil
}

// ResetPassword 由 admin 重置指定账号密码（校验强度；清除强制改密标记）。
func (s *AuthService) ResetPassword(username, newPassword string) error {
	if err := ValidatePasswordStrength(newPassword); err != nil {
		return err
	}
	u, ok := s.store.GetUserByName(username)
	if !ok {
		return fmtError("user not found")
	}
	hash := crypto.HashPassword(newPassword, s.pepper)
	if hash == "" {
		return fmtError("password hashing failed")
	}
	u.Password = hash
	u.MustChangePW = false
	s.store.UpsertUser(u)
	// v0.4.31-E：重置密码后吊销该账号全部会话（仅开关启用时生效）。
	if sessionEnforceEnabled() && s.sessions != nil {
		_ = s.sessions.RevokeUser(u.Username)
	}
	return nil
}

// ValidatePasswordStrength 口令强度策略：≥10 位，且包含大写、小写、数字三类中的至少两类。
func ValidatePasswordStrength(pw string) error {
	if len([]rune(pw)) < 10 {
		return fmtError("password too short: at least 10 characters required")
	}
	var upper, lower, digit, other bool
	for _, r := range pw {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		default:
			other = true
		}
	}
	classes := 0
	for _, ok := range []bool{upper, lower, digit, other} {
		if ok {
			classes++
		}
	}
	if classes < 3 {
		return fmtError("password too weak: need at least 3 of upper/lower/digit/symbol")
	}
	return nil
}

// VerifyToken 校验并返回声明。
//
// 复盘 V-06 修复：无密钥（secret 为空）时拒绝所有令牌——空密钥与空密钥签名两端一致，
// 攻击者可用空密钥伪造任意令牌，故必须显式拒绝而非静默通过。
//
// 复盘 S-10 修复（v0.4.11 夜间接管）：验签通过后**回查账号状态**。此前 Disable 只影响
// 下次登录，已签发的 24h 令牌仍可全权限调用管理 API——人员离职或账号失陷时无法即时
// 收回权限。现对"账号不存在"与"账号已禁用"一律拒绝（fail-closed）。
//
// 性能取舍：该回查使每次 REST 调用多一次账号查询（内存 store 为 map 查找，PG store 为
// 一次主键查询）。管理 API 为低频人工操作，优先保证"权限可即时收回"；WS 长连接通道
// 不走此路径，故不影响 2000 终端心跳等高压链路（铁律 10）。
// store 为 nil 时跳过回查，保持既有行为（便于无持久化场景与单测隔离）。
//
// v0.4.31-E：会话安全开关（YUDUAN_SESSION_ENFORCE，默认关闭）启用且已挂载
// SessionStore 时，在现有账号回查块内一次性补齐：角色变更失效 / 强制改密即时生效 /
// 会话吊销 / 绝对过期 / 空闲超时 / 刷新 last_active。开关关闭或 sessions 为 nil 时
// 逐字走原路径（fail-open 到既有行为），LAN 零回归。
func (s *AuthService) VerifyToken(token string) (crypto.Claims, error) {
	if s.secret == "" {
		return crypto.Claims{}, fmtError("auth disabled: no secret configured")
	}
	claims, err := crypto.VerifyToken(s.secret, token)
	if err != nil {
		return crypto.Claims{}, err
	}
	// enforce 仅在「开关启用 + 已挂载 SessionStore」时为真；为假时会话校验整段跳过，
	// 连同 ①② 都不执行 → 逐字走原路径（零回归）。
	enforce := sessionEnforceEnabled() && s.sessions != nil
	if s.store != nil {
		u, ok := s.store.GetUserByName(claims.Username)
		if !ok {
			return crypto.Claims{}, fmtError("account no longer exists")
		}
		if u.Disabled {
			return crypto.Claims{}, fmtError("account disabled")
		}
		if enforce {
			// ① 权限（角色）变更使旧令牌即时失效：guard 用 claims.Role 判权，
			//    改角色后旧令牌若仍带旧角色可继续用满 24h（P2-E 核心缺口）。
			if u.Role != claims.Role {
				return crypto.Claims{}, fmtError("role changed: re-login required")
			}
			// ② 强制改密即时生效：以账号当前状态覆盖令牌签发时的 MustChange，
			//    ForcePasswordChange 后旧令牌立即被 guard 判为 4033。
			claims.MustChange = u.MustChangePW
		}
	}
	if !enforce {
		return claims, nil
	}
	// ③④ 服务端会话校验（零新增账号查询；会话键由令牌派生，见 SessionID）。
	sid := SessionID(token)
	sess, ok := s.sessions.Get(sid)
	if !ok {
		// 无会话记录 = 开关启用前已签发的旧令牌。legacy 宽限：签名有效（crypto 已验）、
		// 未过期（crypto 已判定）、账号回查已通过 → 放行并自动补建会话，平滑纳入管理。
		if sessionLegacyAllow() {
			now := time.Now().Unix()
			_ = s.sessions.Create(Session{
				SID: sid, Username: claims.Username, Role: claims.Role,
				IssuedAt: now, LastActive: now, ExpiresAt: claims.Exp, Revoked: false,
			})
			return claims, nil
		}
		return crypto.Claims{}, fmtError("session not found: re-login required")
	}
	if sess.Revoked {
		return crypto.Claims{}, fmtError("session revoked: re-login required")
	}
	now := time.Now().Unix()
	if now > sess.ExpiresAt {
		return crypto.Claims{}, fmtError("session expired: re-login required")
	}
	if now-sess.LastActive > sessionIdleSec() {
		return crypto.Claims{}, fmtError("session idle timeout: re-login required")
	}
	// ④ 刷新 last_active（仅 REST 管理 API / viewer 握手走此路径；铁律 10 零回归）。
	_ = s.sessions.Touch(sid, now)
	return claims, nil
}

// HasPerm 判断某角色是否拥有某权限。
func (s *AuthService) HasPerm(role, perm string) bool {
	set, ok := rolePerms[role]
	if !ok {
		return false
	}
	return set[perm]
}

// ValidRole 判断角色名是否合法。
func ValidRole(r string) bool {
	_, ok := rolePerms[r]
	return ok
}

func fmtError(s string) error { return &authErr{s} }

type authErr struct{ m string }

func (e *authErr) Error() string { return e.m }

// TokenFromHeader 从 Authorization: Bearer <token> 中提取令牌。
func TokenFromHeader(authz string) string {
	if strings.HasPrefix(authz, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
	}
	return ""
}
