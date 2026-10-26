// Package crypto 提供御端安全基座所需的零依赖密码学原语：
//   - 指令 HMAC-SHA256 签名/验签（铁律 4：关键指令服务端签名、副端验签）
//   - 登录会话令牌的签发与校验（HMAC 绑定 username/role/exp）
//
// 仅依赖 Go 标准库，避免在受限环境拉取第三方依赖。
package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SignCommand 对一条控制指令信封做 HMAC-SHA256 签名。
// 规范串包含 msgID/ts/seq/payloadJSON/nonce，任何字段被篡改都会导致验签失败。
func SignCommand(secret, msgID string, ts, seq int64, payloadJSON, nonce string) string {
	canonical := fmt.Sprintf("%s|%d|%d|%s|%s", msgID, ts, seq, payloadJSON, nonce)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyCommand 校验指令签名，并返回 nonce 与 ts 是否处于可接受窗口。
// maxSkew 为允许的时间偏移（秒），用于防御重放。
func VerifyCommand(secret, sig, msgID string, ts, seq int64, payloadJSON, nonce string, maxSkew int64) bool {
	expected := SignCommand(secret, msgID, ts, seq, payloadJSON, nonce)
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return false
	}
	now := time.Now().Unix()
	if maxSkew > 0 && (now-ts > maxSkew || ts-now > maxSkew) {
		return false
	}
	return true
}

// Nonce 生成一次性随机值，用于防重放。
func Nonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// SignToken 签发登录会话令牌（HMAC 绑定 username|role|exp|mustChange）。
func SignToken(secret, username, role string, exp int64, mustChange bool) string {
	must := "0"
	if mustChange {
		must = "1"
	}
	body := fmt.Sprintf("%s|%s|%d|%s", username, role, exp, must)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return fmt.Sprintf("%s.%s", body, hex.EncodeToString(mac.Sum(nil)))
}

// Claims 是解析后的令牌声明。
type Claims struct {
	Username   string
	Role       string
	Exp        int64
	MustChange bool // 需强制改密：除改密接口外一律 403
}

// VerifyToken 校验登录令牌并返回声明；过期或签名错误返回 error。
func VerifyToken(secret, token string) (Claims, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return Claims{}, fmt.Errorf("malformed token")
	}
	body, sig := parts[0], parts[1]
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	if !hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(sig)) {
		return Claims{}, fmt.Errorf("bad signature")
	}
	var c Claims
	// body 固定格式 "username|role|exp|mustChange"，手动按 '|' 拆分，避免 Go fmt 不支持 scanset 动词。
	// 兼容旧 3 段令牌（无 mustChange 字段时视为 false）。
	fields := strings.Split(body, "|")
	if len(fields) != 3 && len(fields) != 4 {
		return Claims{}, fmt.Errorf("bad claims: expected 3 or 4 fields, got %d", len(fields))
	}
	c.Username = fields[0]
	c.Role = fields[1]
	exp, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return Claims{}, fmt.Errorf("bad claims: %v", err)
	}
	c.Exp = exp
	if len(fields) == 4 {
		c.MustChange = fields[3] == "1"
	}
	if time.Now().Unix() > exp {
		return Claims{}, fmt.Errorf("token expired")
	}
	return c, nil
}

// HashPassword / VerifyPassword / NeedsRehash 见 password.go（argon2id）。
