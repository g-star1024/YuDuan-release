package hub

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// repoDownloadToken 生成短时下载令牌：HMAC(secret, repoID|exp) 编码为 "exp_sig"。
// 副端分发时附加到 software_url 的 st 查询参数，凭此下载（P-4：下载端点此前无鉴权，
// 内网任意主机可拉全部安装包）。TTL 默认 10 分钟，防令牌泄露窗口。
func (h *Hub) repoDownloadToken(repoID string, ttl time.Duration) string {
	exp := time.Now().Add(ttl).Unix()
	mac := hmac.New(sha256.New, []byte(h.secret))
	_, _ = fmt.Fprintf(mac, "%s|%d", repoID, exp)
	return fmt.Sprintf("%d_%s", exp, hex.EncodeToString(mac.Sum(nil)))
}

// verifyRepoDownloadToken 校验短时下载令牌：签名一致且未过期。
func (h *Hub) verifyRepoDownloadToken(repoID, st string) bool {
	parts := strings.SplitN(st, "_", 2)
	if len(parts) != 2 {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	mac := hmac.New(sha256.New, []byte(h.secret))
	_, _ = fmt.Fprintf(mac, "%s|%d", repoID, exp)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(parts[1]), []byte(expected))
}
