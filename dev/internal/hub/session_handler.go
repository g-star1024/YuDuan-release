// session_handler.go —— v0.4.31-E：登出端点（主动吊销当前会话 + 审计）。
package hub

import (
	"net/http"

	"yuduan/internal/auth"
	"yuduan/internal/crypto"
)

// handleLogout 吊销当前令牌对应的会话并写 logout 审计。
// 由 hub.go 路由表以 guardAuthOnly 包裹（只验令牌、不判 must_change，让强制改密账户
// 也能登出）。无论后端是否启用会话安全 / 吊销是否命中，都返回 HTTP 200 + code:0：
// 前端「无论成败」都清本地登录态并跳转（见 console/auth.js），后端不可用/未启用时
// 前端行为逐字不变。会话拒绝一律由 VerifyToken 返回 error → guard 既有 401 通道，
// 本 handler 不引入任何 403/429/500 状态码，就绪探针（只打 /api/v1/login）零回归。
func (h *Hub) handleLogout(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	token := auth.TokenFromHeader(r.Header.Get("Authorization"))
	if h.authSvc.RevokeSession(token) {
		h.audit(claims.Username, "logout", claims.Username, "登出（当前会话已吊销）", "success")
	} else {
		h.audit(claims.Username, "logout", claims.Username, "登出（会话安全未启用/无会话记录）", "success")
	}
	writeJSON(w, map[string]any{"code": 0, "message": "logged out"})
}
