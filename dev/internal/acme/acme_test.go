package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"yuduan/internal/tlsutil"
)

// TestAccountKeyAndThumbprint 验证：
//   - 生成的账户密钥是合法 P-256；
//   - JWK 指纹是 RFC 7638 规范的 base64url(SHA-256(规范JSON))，且确定性（同输入同输出）。
func TestAccountKeyAndThumbprint(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 P-256 密钥: %v", err)
	}
	pub := priv.Public().(*ecdsa.PublicKey)
	if pub.Curve != elliptic.P256() {
		t.Fatalf("期望 P-256 曲线，得到 %v", pub.Curve)
	}

	j := makeJWK(pub)
	if j.Crv != "P-256" || j.Kty != "EC" || j.X == "" || j.Y == "" {
		t.Fatalf("JWK 字段异常: %+v", j)
	}

	// 独立按 RFC 7638 计算：字典序字段 crv,kty,x,y 无空白 JSON。
	canonical := `{"crv":"` + j.Crv + `","kty":"` + j.Kty + `","x":"` + j.X + `","y":"` + j.Y + `"}`
	sum := sha256.Sum256([]byte(canonical))
	want := base64.RawURLEncoding.EncodeToString(sum[:])

	got, err := thumbprint(j)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if got != want {
		t.Fatalf("指纹不符: got=%s want=%s", got, want)
	}

	// 确定性：同密钥再次计算应一致。
	got2, _ := thumbprint(j)
	if got != got2 {
		t.Fatalf("指纹不确定: %s != %s", got, got2)
	}

	// 长度：SHA-256 -> 32 字节 -> base64url 无填充 43 字符。
	if len(got) != 43 {
		t.Fatalf("指纹长度应为 43，得到 %d (%s)", len(got), got)
	}
}

// TestJWSSigning 验证 ES256 JWS 结构合法，且签名可用账户公钥校验。
func TestJWSSigning(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := priv.Public().(*ecdsa.PublicKey)
	j := makeJWK(pub)

	const url = "https://acme.example.com/acme/new-account"
	const nonce = "test-nonce-123"
	payload := []byte(`{"termsOfServiceAgreed":true}`)

	body, err := signJWS(priv, j, "", nonce, url, payload)
	if err != nil {
		t.Fatalf("signJWS: %v", err)
	}

	// 解析 JWS
	var jws struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal([]byte(body), &jws); err != nil {
		t.Fatalf("JWS JSON 解析失败: %v", err)
	}
	if jws.Protected == "" || jws.Payload == "" || jws.Signature == "" {
		t.Fatalf("JWS 缺少字段: %+v", jws)
	}

	// protected 头应含 alg/url/nonce/jwk，且无 kid（注册前）。
	var ph protectedHeader
	if err := json.Unmarshal(decodeB64(t, jws.Protected), &ph); err != nil {
		t.Fatalf("解析 protected 头: %v", err)
	}
	if ph.Alg != "ES256" || ph.URL != url || ph.Nonce != nonce {
		t.Fatalf("protected 头字段异常: %+v", ph)
	}
	if ph.Kid != "" {
		t.Fatalf("注册前不应有 kid")
	}
	if ph.Jwk == nil {
		t.Fatalf("注册前应有 jwk")
	}

	// payload 应可还原
	if string(decodeB64(t, jws.Payload)) != string(payload) {
		t.Fatalf("payload 还原不符")
	}

	// 复现 signing input 并校验签名
	signingInput := jws.Protected + "." + jws.Payload
	h := sha256.Sum256([]byte(signingInput))
	rawSig := decodeB64(t, jws.Signature)
	if len(rawSig) != 64 {
		t.Fatalf("原始签名应为 64 字节，得到 %d", len(rawSig))
	}
	derSig, err := rawToASN1(rawSig)
	if err != nil {
		t.Fatalf("rawToASN1: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, h[:], derSig) {
		t.Fatalf("ES256 签名校验失败")
	}
}

// TestHTTP01KeyAuthorization 验证 key authorization 格式为 token.thumbprint。
func TestHTTP01KeyAuthorization(t *testing.T) {
	const token = "abcDEF123"
	const thumb = "thumbprint-value"
	got := KeyAuthorization(token, thumb)
	if got != token+"."+thumb {
		t.Fatalf("key authorization 格式错误: %s", got)
	}
}

// TestHTTP01Responder 启动真实响应服务并断言 GET 返回正确的 key authorization。
func TestHTTP01Responder(t *testing.T) {
	const token = "tok-xyz"
	const thumb = "thumb-abc"
	responses := map[string]string{token: token + "." + thumb}

	addr, stop, err := startResponder("127.0.0.1:0", responses)
	if err != nil {
		t.Fatalf("startResponder: %v", err)
	}
	defer stop()

	url := "http://" + addr + "/.well-known/acme-challenge/" + token
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET 挑战: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 %d", resp.StatusCode)
	}
	if string(body) != token+"."+thumb {
		t.Fatalf("响应体不符: got=%q want=%q", string(body), token+"."+thumb)
	}

	// 未知 token 应 404
	resp2, err := http.Get("http://" + addr + "/.well-known/acme-challenge/nope")
	if err != nil {
		t.Fatalf("GET 未知: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("未知 token 应 404，得到 %d", resp2.StatusCode)
	}
}

// TestHTTP01ResponderHandler 用 httptest 验证路径解析（不依赖端口）。
func TestHTTP01ResponderHandler(t *testing.T) {
	const token = "t1"
	const keyAuth = "t1.thumb"
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/acme-challenge/", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		if tok == token {
			_, _ = w.Write([]byte(keyAuth))
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/acme-challenge/" + token)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != keyAuth {
		t.Fatalf("got=%q want=%q", string(body), keyAuth)
	}
}

// TestSPKIPin 用 crypto/x509 自签叶证书，比较 tlsutil.SpkiPinHex 与独立计算结果。
func TestSPKIPin(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥: %v", err)
	}
	tmpl := x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "test.example.com"},
		DNSNames:           []string{"test.example.com"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, priv)
	if err != nil {
		t.Fatalf("CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("解析 CSR: %v", err)
	}
	_ = csr

	// 用 CSR 的公钥自签一张证书（仅用于 PIN 测试）。
	certTmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		DNSNames:     []string{"test.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &certTmpl, &certTmpl, csr.PublicKey, priv)
	if err != nil {
		t.Fatalf("自签证书: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	dir := t.TempDir()
	certPath := filepath.Join(dir, "leaf.pem")
	if err := os.WriteFile(certPath, pemBytes, 0o644); err != nil {
		t.Fatalf("写证书: %v", err)
	}

	// 经库（tlsutil.SpkiPinHex，acme 内部同样使用）
	got, err := tlsutil.SpkiPinHex(certPath)
	if err != nil {
		t.Fatalf("SpkiPinHex: %v", err)
	}

	// 独立计算：解析叶证书 -> MarshalPKIXPublicKey -> SHA-256 -> hex
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("解析证书: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(crt.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	want := fmtHex(sha256.Sum256(spki))

	if got != want {
		t.Fatalf("PIN 不符: got=%s want=%s", got, want)
	}
	if len(got) != 64 {
		t.Fatalf("hex PIN 长度应为 64，得到 %d", len(got))
	}
}

func TestParseUpLink(t *testing.T) {
	h := `<https://acme.example.com/acme/issuer/1>; rel="up"`
	if got := parseUpLink(h); got != "https://acme.example.com/acme/issuer/1" {
		t.Fatalf("parseUpLink: got=%q", got)
	}
	if got := parseUpLink(""); got != "" {
		t.Fatalf("空 Link 应返回空: got=%q", got)
	}
}

// TestIssueLiveStaging 是可选的真实预发环境签发测试，默认跳过。
// 运行前需保证：本机能以 root/特权绑定 :80、域名 DNS 已指向本机公网 IP。
//
//	YUDUAN_ACME_TEST_LIVE=1 YUDUAN_ACME_TEST_DOMAIN=your.domain \
//	YUDUAN_ACME_TEST_EMAIL=you@example.com go test -run TestIssueLiveStaging ./internal/acme
func TestIssueLiveStaging(t *testing.T) {
	if os.Getenv("YUDUAN_ACME_TEST_LIVE") == "" {
		t.Skip("跳过真实 ACME 签发测试（置 YUDUAN_ACME_TEST_LIVE=1 启用）")
	}
	domain := os.Getenv("YUDUAN_ACME_TEST_DOMAIN")
	email := os.Getenv("YUDUAN_ACME_TEST_EMAIL")
	if domain == "" || email == "" {
		t.Fatal("需设置 YUDUAN_ACME_TEST_DOMAIN 与 YUDUAN_ACME_TEST_EMAIL")
	}
	res, err := Issue(Options{
		Domain:     domain,
		Email:      email,
		Staging:    true,
		CertsDir:   t.TempDir(),
		HTTPListen: ":80",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	for _, p := range []string{res.FullchainPath, res.KeyPath, res.PinPath} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("缺少输出文件 %s: %v", p, err)
		}
	}
}

// ---- 测试辅助 ----

func decodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url 解码 %q: %v", s, err)
	}
	return b
}

func fmtHex(sum [32]byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, 64)
	for i := 0; i < 32; i++ {
		out[i*2] = hexd[sum[i]>>4]
		out[i*2+1] = hexd[sum[i]&0x0f]
	}
	return string(out)
}
