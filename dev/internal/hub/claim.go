// 设备引导配置下发（档位 A：一次性注册令牌 + claim 换取）。
//
// 副端经 UDP 广播拿到短时效的一次性注册令牌（discover.go 的 token= 字段），
// 凭它调用本端点换取运行配置：HMAC 验签密钥 +（根 CA 就绪时）mTLS 客户端证书。
//
// 安全设计（与铁律 4 兼容）：
//   - 广播**只携带一次性令牌**，绝不携带 HMAC_SECRET（UDP 明文，任何能收广播者
//     均可抓取；若含共享密钥则指令签名可伪造，控制面失守）。
//   - 令牌 60s 时效、每次广播轮换；HMAC_SECRET 仅在副端 claim 响应中传输一次，
//     响应优先走 TLS（中枢启用 TLS 监听时副端经 https/wss 通道请求）。
//   - 本端点无登录鉴权（副端尚无凭据），依靠令牌本身的门禁；仅放行本路径，
//     不暴露控制面其它 API。
package hub

import (
	"log"
	"net/http"
	"os"
	"time"

	"yuduan/internal/tlsutil"
)

// claimTokenTTL 注册令牌有效期（副端须在窗口内完成 claim；过期即轮换）。
const claimTokenTTL = 60 * time.Second

// CurrentClaimToken 返回当前有效注册令牌；过期则轮换新令牌（并发安全）。
// 导出供 cmd/hub 在 UDP 发现应答时调用。
func (h *Hub) CurrentClaimToken() string {
	h.claimMu.Lock()
	defer h.claimMu.Unlock()
	if h.claimToken != "" && time.Since(h.claimTokenT) < claimTokenTTL {
		return h.claimToken
	}
	h.claimToken = randHex(32) // 64 hex 字符
	h.claimTokenT = time.Now()
	return h.claimToken
}

// claimTokenValid 校验令牌当前有效（且未过期）。
func (h *Hub) claimTokenValid(tok string) bool {
	h.claimMu.Lock()
	defer h.claimMu.Unlock()
	return tok != "" && tok == h.claimToken && time.Since(h.claimTokenT) < claimTokenTTL
}

// consumeClaimToken 令牌单次消费（复盘 S-2/V-02）：claim 校验通过即立刻作废。
// 广播令牌是全网明文可收的，60s 窗口内若可重复 claim，窃听者即可凭同一令牌
// 换走全局 HMAC 密钥与客户端私钥——信任根整体失守。消费后下一次广播自动轮换新令牌。
func (h *Hub) consumeClaimToken() {
	h.claimMu.Lock()
	h.claimToken = ""
	h.claimTokenT = time.Time{}
	h.claimMu.Unlock()
}

// sanitizeClaimCN 清洗 claim 设备标识（客户端证书 CN）：仅保留字母数字与 -_，
// 截断到 64 字符。CN 不可由外部任意指定（避免伪造可读身份/注入证书字段/构造路径样式串）。
func sanitizeClaimCN(s string) string {
	var b []byte
	for i := 0; i < len(s) && len(b) < 64; i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			b = append(b, c)
		}
	}
	return string(b)
}

// claimResponse 设备引导配置下发（档位 A）。
type claimResponse struct {
	HMACSecret string `json:"hmacSecret"`            // 指令验签密钥（副端持久化）
	CACert     string `json:"caPem,omitempty"`       // 根 CA 证书 PEM（mTLS 校验服务端用）
	ClientCert string `json:"clientCert,omitempty"`  // 副端客户端证书 PEM（mTLS 鉴身）
	ClientKey  string `json:"clientKey,omitempty"`   // 副端客户端私钥 PEM
	HubID      string `json:"hubId,omitempty"`       // 中枢节点标识
	TLSAddr    string `json:"tlsAddr,omitempty"`     // 中枢 TLS 监听地址（仅提示，连接以广播 ws= 为准）
}

// handleAgentClaim GET /api/agent/claim?token=&device=&hostname=
//
// 副端用广播取得的一次性注册令牌换取引导配置。令牌非法/过期一律 4003。
func (h *Hub) handleAgentClaim(w http.ResponseWriter, r *http.Request) {
	// 复盘 S-2/V-02：TLS 可用时，claim 一律拒绝明文通道——HMAC 密钥与客户端私钥
	// 绝不经明文 HTTP 下发（此前 claim 挂在 :8080 上，抓一帧广播即可换走信任根）。
	// 无 TLS 的存量开发部署（未配置 TLSAddr）保持原行为，发布部署脚本默认带 TLS。
	if h.tlsAddr != "" && r.TLS == nil {
		log.Printf("[hub] claim 拒绝明文请求（TLS 已启用，请经 %s 请求）from %s", h.tlsAddr, r.RemoteAddr)
		writeErr(w, 4033, "claim_requires_tls: TLS 已启用，请经 https/wss 端口请求 claim")
		return
	}
	tok := r.URL.Query().Get("token")
	device := sanitizeClaimCN(r.URL.Query().Get("device"))
	if tok == "" {
		writeErr(w, 4001, "token_required")
		return
	}
	if !h.claimTokenValid(tok) {
		writeErr(w, 4003, "invalid_or_expired_token")
		return
	}
	// 单次消费：校验通过即作废令牌（并发 claim 只有一个能成功）。
	h.consumeClaimToken()
	resp := claimResponse{
		HMACSecret: h.secret,
		HubID:      h.hubID,
		TLSAddr:    h.tlsAddr,
	}
	// 根 CA 就绪（certs/ca.pem + ca.key）→ 为副端签发一次性客户端证书（mTLS 用）。
	// 中枢是否用 mTLS 验证客户端证书由 YUDUAN_CLIENT_CA 指向同一 CA 决定；副端
	// 拿到证书后即可在 wss/mTLS 端口呈现客户端身份。
	if h.caCert != "" && h.caKey != "" {
		if caPEM, err := os.ReadFile(h.caCert); err == nil {
			resp.CACert = string(caPEM)
		}
		if cert, key, err := issueClientCertPEM(h.caCert, h.caKey, device); err == nil {
			resp.ClientCert = cert
			resp.ClientKey = key
		}
	}
	writeJSON(w, resp)
}

// issueClientCertPEM 用根 CA 为指定设备签发客户端证书，返回 PEM（证书+私钥）。
func issueClientCertPEM(caCert, caKey, cn string) (string, string, error) {
	dir, err := os.MkdirTemp("", "yuduan-claim-*")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(dir)
	certPath := dir + "/client.crt"
	keyPath := dir + "/client.key"
	if cn == "" {
		cn = "agent-claim"
	}
	if err := tlsutil.IssueClientCert(caCert, caKey, certPath, keyPath, cn); err != nil {
		return "", "", err
	}
	cb, err := os.ReadFile(certPath)
	if err != nil {
		return "", "", err
	}
	kb, err := os.ReadFile(keyPath)
	if err != nil {
		return "", "", err
	}
	return string(cb), string(kb), nil
}
