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
)

// rolePerms 定义各角色拥有的权限集合。
var rolePerms = map[string]map[string]bool{
	RoleAdmin:    {PermDeviceView: true, PermDeviceCmd: true, PermRCSession: true, PermSoftwareMgmt: true, PermAuditView: true, PermUserManage: true, PermDirSync: true, PermRCApprove: true},
	RoleOperator: {PermDeviceView: true, PermDeviceCmd: true, PermRCSession: true, PermSoftwareMgmt: true, PermAuditView: true},
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
	store  UserStore
	secret string
	pepper string
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
func (s *AuthService) VerifyToken(token string) (crypto.Claims, error) {
	if s.secret == "" {
		return crypto.Claims{}, fmtError("auth disabled: no secret configured")
	}
	claims, err := crypto.VerifyToken(s.secret, token)
	if err != nil {
		return crypto.Claims{}, err
	}
	if s.store != nil {
		u, ok := s.store.GetUserByName(claims.Username)
		if !ok {
			return crypto.Claims{}, fmtError("account no longer exists")
		}
		if u.Disabled {
			return crypto.Claims{}, fmtError("account disabled")
		}
	}
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
