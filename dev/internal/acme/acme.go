// Package acme 实现一个零第三方依赖的 ACME v2 (RFC 8555) HTTP-01 自动证书签发客户端，
// 仅依赖 Go 标准库。用于在「公网可达最小闭环」里程碑中，让中枢在自己的基础设施上
// 向 Let's Encrypt（或兼容 ACME 的 CA）申请公网证书，避免部署 certbot。
//
// 主要功能（Issue）：
//  1. 生成 EC P-256 账户密钥，计算 JWK 与 RFC 7638 JWK 指纹；
//  2. 拉取 ACME Directory，注册/复用账户；
//  3. 下单（new-order）并对域名做 HTTP-01 校验（自带临时 HTTP 服务）；
//  4. 生成证书密钥 + CSR，finalize 后下载证书链并落盘：
//     <dir>/acme.key、<dir>/acme.fullchain.pem、<dir>/acme.pin。
//
// 输出契约（供 hub / deploy 集成）：
//   - acme.fullchain.pem：叶证书 + 签发者链（PEM），hub 通过
//     YUDUAN_TLS_CERT=certs/acme.fullchain.pem 加载；
//   - acme.key：证书私钥（PEM），hub 通过 YUDUAN_TLS_KEY=certs/acme.key 加载；
//   - acme.pin：叶证书 SPKI SHA-256 hex（小写），与副端 YUDUAN_TLS_PIN 同口径。
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
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"yuduan/internal/tlsutil"
)

// ProductionDirectory / StagingDirectory 是 Let's Encrypt 的 ACME v2 端点。
const (
	ProductionDirectory = "https://acme-v02.api.letsencrypt.org/directory"
	StagingDirectory    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	userAgent           = "yuduan-acme/0.1 (YuDuan P1 closed-loop)"

	// acmeHTTPTimeout 单次 ACME 请求上限（v0.4.27 F-06，可选收紧项）。
	// 原 30s 在真机「外部 timeout 20s」场景下尚未到期就被杀，屏幕零输出即被判挂起。
	// 收紧到 15s 让 Go 侧先返回带上下文的错误；配合各阶段进度日志，失败可见、不再静默。
	// pollAuthz / finalize 的 5 分钟总时限不受影响（那只约束轮询轮数）。
	acmeHTTPTimeout = 15 * time.Second
)

// Options 控制一次证书签发。
type Options struct {
	Domain       string // 要签发的域名（单域名）
	Email        string // 注册邮箱（CA 联系/找回用途）
	DirectoryURL string // 显式指定 Directory；为空时按 Staging 选择 LE 端点
	CertsDir     string // 证书输出目录，默认 "certs"
	HTTPListen   string // HTTP-01 临时监听地址（standalone 模式），默认 ":80"
	Staging      bool   // 是否使用 Let's Encrypt 预发环境
	// Webroot 非空时改用 webroot 模式：把 HTTP-01 应答写入
	// <Webroot>/.well-known/acme-challenge/<token>，由外部 web 服务器提供，
	// 不占用 :80（公网中枢常由 nginx 占用 :80，standalone 会冲突）。
	// v0.4.31-B 增量：为空时走原有 standalone 流程，行为逐字节不变。
	Webroot string
}

// Result 是签发结果中落盘文件的绝对/相对路径。
type Result struct {
	FullchainPath string // acme.fullchain.pem
	KeyPath       string // acme.key
	PinPath       string // acme.pin
	CertPath      string // 叶证书路径（这里与 FullchainPath 一致）
}

// directory 是 ACME Directory 响应中的关键资源端点。
type directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	NewAuthz   string `json:"newAuthz"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
}

type identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type order struct {
	Status         string       `json:"status"`
	Identifiers    []identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate"`
	Expires        string       `json:"expires"`
}

type challenge struct {
	Type   string `json:"type"`
	Status string `json:"status"`
	URL    string `json:"url"`
	Token  string `json:"token"`
}

type authorization struct {
	Status     string      `json:"status"`
	Challenges []challenge `json:"challenges"`
	Identifier identifier  `json:"identifier"`
	Expires    string      `json:"expires"`
}

// jwk 是 RFC 7517 的 EC 公钥表示；字段顺序即 RFC 7638 要求的字典序
// （crv, kty, x, y），Go 的 json.Marshal 按结构体字段顺序输出，故无需手动拼 JSON。
type jwk struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// protectedHeader 是 JWS 受保护头。未注册账户时用 jwk，注册后用 kid（omitempty 二选一）。
type protectedHeader struct {
	Alg   string `json:"alg"`
	URL   string `json:"url"`
	Nonce string `json:"nonce"`
	Kid   string `json:"kid,omitempty"`
	Jwk   *jwk   `json:"jwk,omitempty"`
}

// acmeError 对应 RFC 7807 的 ACME problem document。
type acmeError struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

func (e acmeError) Error() string {
	if e.Type == "" {
		return fmt.Sprintf("ACME 错误 (status=%d)", e.Status)
	}
	return fmt.Sprintf("ACME 错误 %s: %s", e.Type, e.Detail)
}

// client 持有一次签发会话的全部状态。
type client struct {
	http       *http.Client
	accountKey *ecdsa.PrivateKey
	jwk        jwk
	thumb      string // RFC 7638 JWK 指纹（base64url 无填充）
	nonce      string
	accountURL string
	userAgent  string
	dir        directory
}

// Issue 执行一次完整的 ACME HTTP-01 证书签发。网络失败或校验超时返回带上下文的错误。
func Issue(opts Options) (Result, error) {
	dirURL := opts.DirectoryURL
	if dirURL == "" {
		if opts.Staging {
			dirURL = StagingDirectory
		} else {
			dirURL = ProductionDirectory
		}
	}
	listen := opts.HTTPListen
	if listen == "" {
		listen = ":80"
	}
	certsDir := opts.CertsDir
	if certsDir == "" {
		certsDir = "certs"
	}

	// a. 账户密钥 + JWK + 指纹
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Result{}, fmt.Errorf("生成账户密钥: %w", err)
	}
	pub, ok := accountKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return Result{}, fmt.Errorf("无法获取账户公钥")
	}
	j := makeJWK(pub)
	thumb, err := thumbprint(j)
	if err != nil {
		return Result{}, fmt.Errorf("计算 JWK 指纹: %w", err)
	}

	c := &client{
		http:       &http.Client{Timeout: acmeHTTPTimeout},
		accountKey: accountKey,
		jwk:        j,
		thumb:      thumb,
		userAgent:  userAgent,
	}

	// v0.4.27 F-06 / v0.4.28 O-01：各阶段进度日志。纯 log.Printf，不改 RFC8555 流程、
	// 产物与 PIN 口径，也不改 Issue 签名。日志统一 [acme] 前缀走标准 logger；输出目标由调用方
	// 决定（CLI 指到 stdout 以规避 PowerShell 5.1 EAP=Stop，库本身不假定 stderr）。
	// 起始行合并 HTTP-01 监听与输出目录；CLI 不再重复打印，消除真机观察到的双行（O-01）。
	log.Printf("[acme] 开始签发 domain=%s dirURL=%s staging=%t（HTTP-01 监听 %s，输出目录 %s）",
		opts.Domain, dirURL, opts.Staging, listen, certsDir)

	// b. 拉取 Directory
	log.Printf("[acme] 1/8 拉取 ACME Directory：%s", dirURL)
	if err := c.getDirectory(dirURL); err != nil {
		return Result{}, err
	}
	if err := c.refreshNonce(); err != nil {
		return Result{}, fmt.Errorf("获取 nonce: %w", err)
	}
	log.Printf("[acme] 1/8 Directory 就绪（newNonce / newAccount / newOrder）")

	// c. 注册/复用账户
	log.Printf("[acme] 2/8 注册/复用账户（email=%s）", opts.Email)
	acctURL, err := c.ensureAccount(opts.Email)
	if err != nil {
		return Result{}, err
	}
	c.accountURL = acctURL
	log.Printf("[acme] 2/8 账户就绪：%s", acctURL)

	// d. 下单
	log.Printf("[acme] 3/8 下单（new-order，domain=%s）", opts.Domain)
	orderURL, ord, err := c.newOrder(opts.Domain)
	if err != nil {
		return Result{}, err
	}
	log.Printf("[acme] 3/8 订单已创建：%d 个授权待校验", len(ord.Authorizations))

	// e. HTTP-01 校验
	log.Printf("[acme] 4/8 HTTP-01 挑战应答（临时监听 %s）", listen)
	stop, err := c.solveHTTP01(ord.Authorizations, listen, opts.Webroot)
	if err != nil {
		if stop != nil {
			stop()
		}
		return Result{}, fmt.Errorf("HTTP-01 校验: %w", err)
	}
	defer stop()
	log.Printf("[acme] 5/8 所有授权已 valid")

	// f. 生成证书密钥 + CSR + finalize
	log.Printf("[acme] 6/8 生成证书密钥 / CSR，提交 finalize")
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Result{}, fmt.Errorf("生成证书密钥: %w", err)
	}
	csrDER, err := makeCSR(certKey, opts.Domain)
	if err != nil {
		return Result{}, fmt.Errorf("生成 CSR: %w", err)
	}
	ord, err = c.finalize(ord.Finalize, csrDER, orderURL)
	if err != nil {
		return Result{}, err
	}
	if ord.Certificate == "" {
		return Result{}, fmt.Errorf("订单完成但未返回证书 URL")
	}

	// g. 下载证书
	log.Printf("[acme] 7/8 下载证书链：%s", ord.Certificate)
	certPEM, err := c.downloadCert(ord.Certificate)
	if err != nil {
		return Result{}, err
	}
	log.Printf("[acme] 7/8 证书链已下载（%d 字节，%d 张证书）", len(certPEM), countCerts(certPEM))

	// 落盘
	log.Printf("[acme] 8/8 落盘到 %s", certsDir)
	if err := os.MkdirAll(certsDir, 0o700); err != nil {
		return Result{}, fmt.Errorf("创建证书目录: %w", err)
	}
	keyPath := filepath.Join(certsDir, "acme.key")
	fullchainPath := filepath.Join(certsDir, "acme.fullchain.pem")
	pinPath := filepath.Join(certsDir, "acme.pin")

	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return Result{}, fmt.Errorf("序列化证书私钥: %w", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	}), 0o600); err != nil {
		return Result{}, fmt.Errorf("写入 %s: %w", keyPath, err)
	}
	if err := os.WriteFile(fullchainPath, certPEM, 0o644); err != nil {
		return Result{}, fmt.Errorf("写入 %s: %w", fullchainPath, err)
	}

	// acme.pin = 叶证书（fullchain 第一个 PEM 块）的 SPKI SHA-256 hex。
	pin, err := tlsutil.SpkiPinHex(fullchainPath)
	if err != nil {
		return Result{}, fmt.Errorf("计算 SPKI PIN: %w", err)
	}
	if err := os.WriteFile(pinPath, []byte(pin+"\n"), 0o644); err != nil {
		return Result{}, fmt.Errorf("写入 %s: %w", pinPath, err)
	}
	log.Printf("[acme] 8/8 落盘完成：fullchain=%s key=%s pin=%s（SPKI PIN=%s）",
		fullchainPath, keyPath, pinPath, pin)
	log.Printf("[acme] 签发完成 domain=%s", opts.Domain)

	return Result{
		FullchainPath: fullchainPath,
		KeyPath:       keyPath,
		PinPath:       pinPath,
		CertPath:      fullchainPath,
	}, nil
}

// ---- 密钥 / JWK / 指纹 ----

func makeJWK(pub *ecdsa.PublicKey) jwk {
	xb := pub.X.Bytes()
	yb := pub.Y.Bytes()
	x := make([]byte, 32)
	y := make([]byte, 32)
	copy(x[32-len(xb):], xb)
	copy(y[32-len(yb):], yb)
	return jwk{Crv: "P-256", Kty: "EC", X: b64(x), Y: b64(y)}
}

// thumbprint 计算 RFC 7638 JWK 指纹：base64url(SHA-256(规范 JSON))。
func thumbprint(j jwk) (string, error) {
	// 利用结构体字段顺序（crv,kty,x,y）保证字典序、无空白。
	b, err := json.Marshal(j)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return b64(sum[:]), nil
}

// KeyAuthorization 返回 HTTP-01 校验用的 key authorization 字符串：token.thumbprint。
func KeyAuthorization(token, thumbprint string) string {
	return token + "." + thumbprint
}

// ---- 底层 HTTP（含 429/503 退避重试、Retry-After、nonce 维护）----

func (c *client) doOnce(req *http.Request) (int, []byte, http.Header, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	if nc := resp.Header.Get("Replay-Nonce"); nc != "" {
		c.nonce = nc
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return 0, nil, nil, fmt.Errorf("读取响应体: %w", err)
	}
	return resp.StatusCode, body, resp.Header, nil
}

func (c *client) refreshNonce() error {
	req, _ := http.NewRequest(http.MethodGet, c.dir.NewNonce, nil)
	req.Header.Set("User-Agent", c.userAgent)
	st, _, h, err := c.doOnce(req)
	if err != nil {
		return err
	}
	if nc := h.Get("Replay-Nonce"); nc != "" {
		c.nonce = nc
	}
	_ = st
	return nil
}

func (c *client) get(url, accept string) (int, []byte, http.Header, error) {
	var lastStatus int
	var lastBody []byte
	var lastHeader http.Header
	for attempt := 0; attempt < 5; attempt++ {
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.Header.Set("User-Agent", c.userAgent)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		st, b, h, err := c.doOnce(req)
		if err != nil {
			return 0, nil, nil, err
		}
		lastStatus, lastBody, lastHeader = st, b, h
		if st == http.StatusTooManyRequests || st == http.StatusServiceUnavailable {
			wait := retryAfter(h)
			// v0.4.27 F-06：限流/服务不可用的等待点必须有进度输出，否则屏幕全空像挂死。
			log.Printf("[acme] GET HTTP %d，等待 %d 秒，第 %d 次重试（最多 5 次）",
				st, int(wait.Seconds()), attempt+1)
			time.Sleep(wait)
			continue
		}
		return st, b, h, nil
	}
	return lastStatus, lastBody, lastHeader, nil
}

// post 发送 JWS，useKid 为 true 时使用 kid（已注册账户），否则用 jwk（注册前）。
func (c *client) post(url string, useKid bool, payload []byte) (int, []byte, http.Header, error) {
	kid := ""
	if useKid {
		kid = c.accountURL
	}
	var lastStatus int
	var lastBody []byte
	var lastHeader http.Header
	for attempt := 0; attempt < 5; attempt++ {
		body, err := signJWS(c.accountKey, c.jwk, kid, c.nonce, url, payload)
		if err != nil {
			return 0, nil, nil, err
		}
		req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/jose+json")
		req.Header.Set("User-Agent", c.userAgent)
		st, b, h, err := c.doOnce(req)
		if err != nil {
			return 0, nil, nil, err
		}
		lastStatus, lastBody, lastHeader = st, b, h
		if st == http.StatusTooManyRequests || st == http.StatusServiceUnavailable {
			wait := retryAfter(h)
			// v0.4.27 F-06：限流/服务不可用的等待点必须有进度输出，否则屏幕全空像挂死。
			log.Printf("[acme] POST HTTP %d，等待 %d 秒，第 %d 次重试（最多 5 次）",
				st, int(wait.Seconds()), attempt+1)
			time.Sleep(wait)
			if err := c.refreshNonce(); err != nil {
				return st, b, h, err
			}
			continue
		}
		return st, b, h, nil
	}
	return lastStatus, lastBody, lastHeader, nil
}

// postAsGet 以 POST 方式执行「GET」（ACME 无状态读取），payload 为空。
func (c *client) postAsGet(url string, useKid bool) (int, []byte, http.Header, error) {
	return c.post(url, useKid, []byte(""))
}

func retryAfter(h http.Header) time.Duration {
	if v := h.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 3 * time.Second
}

// ---- JWS 签名 ----

// signJWS 构造 application/jose+json 请求体（protected.payload.signature）。
func signJWS(priv *ecdsa.PrivateKey, j jwk, kid, nonce, url string, payload []byte) (string, error) {
	ph := protectedHeader{Alg: "ES256", URL: url, Nonce: nonce}
	if kid != "" {
		ph.Kid = kid
	} else {
		jj := j
		ph.Jwk = &jj
	}
	phB, err := json.Marshal(ph)
	if err != nil {
		return "", err
	}
	protectedB64 := b64(phB)
	payloadB64 := b64(payload)
	signingInput := protectedB64 + "." + payloadB64
	sig, err := rawES256(priv, []byte(signingInput))
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(map[string]string{
		"protected": protectedB64,
		"payload":   payloadB64,
		"signature": b64(sig),
	})
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// rawES256 用账户密钥对 signingInput 做 ES256 签名，返回 64 字节原始 R||S（ACME JWS 要求）。
func rawES256(priv *ecdsa.PrivateKey, signingInput []byte) ([]byte, error) {
	h := sha256.Sum256(signingInput)
	sigDER, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		return nil, err
	}
	r, s, err := parseECDSASigDER(sigDER)
	if err != nil {
		return nil, err
	}
	rb := r.Bytes()
	sb := s.Bytes()
	out := make([]byte, 64)
	copy(out[32-len(rb):32], rb)
	copy(out[64-len(sb):], sb)
	return out, nil
}

// rawToASN1 将 64 字节原始签名还原为 DER（供验证使用）。
// 注：Go 1.27 起 crypto/asn1 已移除，这里手写最小 DER 编解码。
func rawToASN1(sig []byte) ([]byte, error) {
	if len(sig) != 64 {
		return nil, fmt.Errorf("原始签名长度 %d != 64", len(sig))
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return buildECDSASigDER(r, s), nil
}

// parseECDSASigDER 解析 DER 编码的 ECDSA 签名 SEQUENCE { INTEGER r, INTEGER s }。
func parseECDSASigDER(der []byte) (r, s *big.Int, err error) {
	if len(der) < 2 || der[0] != 0x30 {
		return nil, nil, fmt.Errorf("ECDSA 签名非 SEQUENCE")
	}
	_, off := readDERLen(der, 1)
	if off >= len(der) || der[off] != 0x02 {
		return nil, nil, fmt.Errorf("ECDSA 签名缺少 INTEGER r")
	}
	r, off, err = readDERInt(der, off)
	if err != nil {
		return nil, nil, err
	}
	if off >= len(der) || der[off] != 0x02 {
		return nil, nil, fmt.Errorf("ECDSA 签名缺少 INTEGER s")
	}
	s, _, err = readDERInt(der, off)
	if err != nil {
		return nil, nil, err
	}
	return r, s, nil
}

// buildECDSASigDER 将 (r, s) 编码为 DER（用于 crypto/ecdsa.VerifyASN1 校验）。
func buildECDSASigDER(r, s *big.Int) []byte {
	rb := derIntBytes(r)
	sb := derIntBytes(s)
	ri := append([]byte{0x02, byte(len(rb))}, rb...)
	si := append([]byte{0x02, byte(len(sb))}, sb...)
	content := append(ri, si...)
	return append([]byte{0x30, byte(len(content))}, content...)
}

// derIntBytes 返回 DER INTEGER 的内容字节（高位置位时补前导 0x00）。
func derIntBytes(v *big.Int) []byte {
	b := v.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0x00}, b...)
	}
	return b
}

func readDERLen(b []byte, i int) (int, int) {
	if b[i]&0x80 == 0 {
		return int(b[i]), i + 1
	}
	n := int(b[i] & 0x7f)
	length := 0
	for j := 0; j < n; j++ {
		length = length<<8 | int(b[i+1+j])
	}
	return length, i + 1 + n
}

func readDERInt(b []byte, i int) (*big.Int, int, error) {
	if b[i] != 0x02 {
		return nil, 0, fmt.Errorf("期望 INTEGER")
	}
	length, off := readDERLen(b, i+1)
	val := new(big.Int).SetBytes(b[off : off+length])
	return val, off + length, nil
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---- ACME 流程步骤 ----

func (c *client) getDirectory(dirURL string) error {
	st, body, _, err := c.get(dirURL, "application/json")
	if err != nil {
		return fmt.Errorf("获取 Directory: %w", err)
	}
	if st != http.StatusOK {
		return fmt.Errorf("获取 Directory 失败: status %d", st)
	}
	if err := json.Unmarshal(body, &c.dir); err != nil {
		return fmt.Errorf("解析 Directory: %w", err)
	}
	if c.dir.NewNonce == "" || c.dir.NewAccount == "" || c.dir.NewOrder == "" {
		return fmt.Errorf("Directory 缺少必要端点")
	}
	return nil
}

// ensureAccount 先用 onlyReturnExisting 探测，若账户不存在再以 ToS+contact 创建。
func (c *client) ensureAccount(email string) (string, error) {
	probe, _ := json.Marshal(map[string]any{"onlyReturnExisting": true})
	st, body, h, err := c.post(c.dir.NewAccount, false, probe)
	if err != nil {
		return "", fmt.Errorf("探测账户: %w", err)
	}
	if st == http.StatusOK {
		loc := h.Get("Location")
		if loc == "" {
			return "", fmt.Errorf("探测账户成功但缺少 Location")
		}
		return loc, nil
	}
	if st == http.StatusBadRequest {
		var prob acmeError
		_ = json.Unmarshal(body, &prob)
		if !strings.Contains(prob.Type, "accountDoesNotExist") {
			return "", fmt.Errorf("探测账户: %w", prob)
		}
	} else if st >= 400 {
		var prob acmeError
		_ = json.Unmarshal(body, &prob)
		return "", fmt.Errorf("探测账户: %w", prob)
	}

	// 创建账户
	create, _ := json.Marshal(map[string]any{
		"termsOfServiceAgreed": true,
		"contact":              []string{"mailto:" + email},
	})
	st, body, h, err = c.post(c.dir.NewAccount, false, create)
	if err != nil {
		return "", fmt.Errorf("创建账户: %w", err)
	}
	if st != http.StatusCreated && st != http.StatusOK {
		var prob acmeError
		_ = json.Unmarshal(body, &prob)
		return "", fmt.Errorf("创建账户: %w", prob)
	}
	loc := h.Get("Location")
	if loc == "" {
		return "", fmt.Errorf("创建账户缺少 Location 头")
	}
	return loc, nil
}

func (c *client) newOrder(domain string) (string, order, error) {
	body, _ := json.Marshal(map[string]any{
		"identifiers": []identifier{{Type: "dns", Value: domain}},
	})
	st, respBody, h, err := c.post(c.dir.NewOrder, true, body)
	if err != nil {
		return "", order{}, fmt.Errorf("下单: %w", err)
	}
	if st != http.StatusCreated {
		var prob acmeError
		_ = json.Unmarshal(respBody, &prob)
		return "", order{}, fmt.Errorf("下单: %w", prob)
	}
	var o order
	if err := json.Unmarshal(respBody, &o); err != nil {
		return "", order{}, fmt.Errorf("解析订单: %w", err)
	}
	loc := h.Get("Location")
	if loc == "" {
		return "", order{}, fmt.Errorf("下单缺少 Location 头")
	}
	return loc, o, nil
}

// solveHTTP01 处理所有授权中的 HTTP-01 挑战：准备应答（standalone 临时服务或
// webroot 文件）、回应挑战、轮询至 valid。webroot 为空时走原有 standalone 流程，
// 行为逐字节不变（v0.4.31-B 增量）。
func (c *client) solveHTTP01(authzURLs []string, listen, webroot string) (func(), error) {
	type pending struct {
		url   string
		token string
	}
	var pend []pending
	responses := map[string]string{}

	// 1) 取每个授权的 HTTP-01 挑战 token
	log.Printf("[acme] 读取 %d 个授权的 HTTP-01 挑战", len(authzURLs))
	for _, az := range authzURLs {
		st, body, _, err := c.postAsGet(az, true)
		if err != nil {
			return nil, err
		}
		if st != http.StatusOK {
			return nil, fmt.Errorf("获取授权 %s 失败: status %d", az, st)
		}
		var a authorization
		if err := json.Unmarshal(body, &a); err != nil {
			return nil, fmt.Errorf("解析授权: %w", err)
		}
		if a.Status == "valid" {
			continue
		}
		var chal *challenge
		for i := range a.Challenges {
			if a.Challenges[i].Type == "http-01" {
				chal = &a.Challenges[i]
				break
			}
		}
		if chal == nil {
			return nil, fmt.Errorf("授权 %s 不含 http-01 挑战", az)
		}
		keyAuth := KeyAuthorization(chal.Token, c.thumb)
		responses[chal.Token] = keyAuth
		pend = append(pend, pending{url: chal.URL, token: chal.Token})
	}

	// 2) 准备 HTTP-01 应答（必须先于回应挑战，CA 会立即回查）。
	//    默认（webroot 空）：standalone 临时响应服务，行为与 v0.4.31-B 之前一致。
	//    webroot 非空：把应答写入 webroot/.well-known/acme-challenge/，由外部
	//    web 服务器提供，不占用 :80（公网中枢常由反向代理占用该端口）。
	var stop func()
	if webroot != "" {
		log.Printf("[acme] 启动 HTTP-01 webroot 应答（%d 个 token，目录 %s）", len(responses), webroot)
		var err error
		stop, err = writeWebrootChallenges(webroot, responses)
		if err != nil {
			return nil, fmt.Errorf("写入 HTTP-01 webroot 应答: %w", err)
		}
	} else {
		log.Printf("[acme] 启动 HTTP-01 临时响应服务（%d 个 token，监听 %s）", len(responses), listen)
		addr, stopResponder, err := startResponder(listen, responses)
		if err != nil {
			return nil, fmt.Errorf("启动 HTTP-01 响应服务: %w", err)
		}
		stop = stopResponder
		log.Printf("[acme] HTTP-01 响应服务已就绪 %s", addr)
	}

	// 3) 回应每个挑战
	log.Printf("[acme] 回应 %d 个 HTTP-01 挑战", len(pend))
	for _, p := range pend {
		st, body, _, err := c.post(p.url, true, []byte("{}"))
		if err != nil {
			stop()
			return nil, err
		}
		if st >= 400 {
			var prob acmeError
			_ = json.Unmarshal(body, &prob)
			stop()
			return nil, fmt.Errorf("回应挑战 %s: %w", p.token, prob)
		}
	}
	// 4) 轮询每个授权直至 valid
	for _, az := range authzURLs {
		if err := c.pollAuthz(az, 5*time.Minute); err != nil {
			stop()
			return nil, err
		}
	}
	return stop, nil
}

func (c *client) pollAuthz(az string, timeout time.Duration) error {
	start := time.Now()
	deadline := start.Add(timeout)
	log.Printf("[acme] 等待授权变为 valid（最长 %s）：%s", timeout, az)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	polls := 0
	for {
		polls++
		// 每 ~30s 输出一次进度（10 次轮询 × 3s），避免 5 分钟内刷 100 行，
		// 同时保证「屏幕不再全空」——这是 F-06 真机挂起体感的核心成因。
		if polls == 1 || polls%10 == 0 {
			log.Printf("[acme] 等待授权：第 %d 次轮询，已等待 %s，最长 %s",
				polls, time.Since(start).Truncate(time.Second), timeout)
		}
		st, body, _, err := c.postAsGet(az, true)
		if err != nil {
			return err
		}
		if st != http.StatusOK {
			return fmt.Errorf("轮询授权 %s 失败: status %d", az, st)
		}
		var a authorization
		if err := json.Unmarshal(body, &a); err != nil {
			return fmt.Errorf("解析授权: %w", err)
		}
		switch a.Status {
		case "valid":
			log.Printf("[acme] 授权已 valid（第 %d 次轮询，耗时 %s）", polls, time.Since(start).Truncate(time.Second))
			return nil
		case "invalid":
			return fmt.Errorf("授权 %s 失败: %s", az, strings.TrimSpace(string(body)))
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("授权 %s 超时（%s）", az, timeout)
		}
		<-ticker.C
	}
}

func (c *client) finalize(finalizeURL string, csrDER []byte, orderURL string) (order, error) {
	body, _ := json.Marshal(map[string]any{"csr": b64(csrDER)})
	st, respBody, _, err := c.post(finalizeURL, true, body)
	if err != nil {
		return order{}, fmt.Errorf("finalize: %w", err)
	}
	if st != http.StatusOK {
		var prob acmeError
		_ = json.Unmarshal(respBody, &prob)
		return order{}, fmt.Errorf("finalize: %w", prob)
	}
	var o order
	if err := json.Unmarshal(respBody, &o); err != nil {
		return order{}, fmt.Errorf("解析订单: %w", err)
	}

	start := time.Now()
	deadline := start.Add(5 * time.Minute)
	log.Printf("[acme] 等待订单签发完成（最长 5 分钟）")
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	polls := 0
	for {
		polls++
		// 与 pollAuthz 同口径：每 ~30s 一行进度，避免日志刷屏又保证可见。
		if polls == 1 || polls%10 == 0 {
			log.Printf("[acme] 等待订单：第 %d 次轮询，已等待 %s，订单状态=%s",
				polls, time.Since(start).Truncate(time.Second), o.Status)
		}
		if o.Certificate != "" {
			log.Printf("[acme] 订单已签发（第 %d 次轮询，耗时 %s）", polls, time.Since(start).Truncate(time.Second))
			return o, nil
		}
		if o.Status == "invalid" {
			return o, fmt.Errorf("订单无效: %s", strings.TrimSpace(string(respBody)))
		}
		if time.Now().After(deadline) {
			return o, fmt.Errorf("finalize 超时")
		}
		<-ticker.C
		st, body2, _, err := c.postAsGet(orderURL, true)
		if err != nil {
			return o, err
		}
		if st != http.StatusOK {
			return o, fmt.Errorf("轮询订单失败: status %d", st)
		}
		respBody = body2
		if err := json.Unmarshal(body2, &o); err != nil {
			return o, fmt.Errorf("解析订单: %w", err)
		}
	}
}

func (c *client) downloadCert(certURL string) ([]byte, error) {
	st, body, h, err := c.get(certURL, "application/pem-certificate-chain")
	if err != nil {
		return nil, fmt.Errorf("下载证书: %w", err)
	}
	if st != http.StatusOK {
		return nil, fmt.Errorf("下载证书失败: status %d", st)
	}
	// Let's Encrypt 通常已返回叶+链；若只含叶证书，则通过 Link rel="up" 拉取签发者链并追加。
	if countCerts(body) < 2 {
		if up := parseUpLink(h.Get("Link")); up != "" {
			st2, chain, _, err2 := c.postAsGet(up, true)
			if err2 == nil && st2 == http.StatusOK && len(chain) > 0 {
				var b strings.Builder
				b.Write(body)
				if !strings.HasSuffix(b.String(), "\n") {
					b.WriteByte('\n')
				}
				b.Write(chain)
				body = []byte(b.String())
			}
		}
	}
	return body, nil
}

func countCerts(pemBytes []byte) int {
	n := 0
	rest := pemBytes
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			n++
		}
		rest = next
	}
	return n
}

// parseUpLink 从 Link 头中解析 rel="up" 的 URL（用于获取签发者链）。
func parseUpLink(link string) string {
	for _, part := range strings.Split(link, ",") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "<") {
			continue
		}
		end := strings.Index(part, ">")
		if end < 0 {
			continue
		}
		url := part[1:end]
		if strings.Contains(part, `rel="up"`) {
			return url
		}
	}
	return ""
}

// ---- CSR ----

func makeCSR(priv *ecdsa.PrivateKey, domain string) ([]byte, error) {
	tmpl := x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: domain},
		DNSNames:           []string{domain},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	return x509.CreateCertificateRequest(rand.Reader, &tmpl, priv)
}

// ---- HTTP-01 响应服务 ----

// startResponder 在 listen 上启动一个极简 HTTP 服务，按 token 返回 key authorization。
// 返回实际监听地址（listen 可为 ":0" 以随机端口）、停止函数。
func startResponder(listen string, responses map[string]string) (string, func(), error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/acme-challenge/", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		if ka, ok := responses[token]; ok {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte(ka))
			return
		}
		http.NotFound(w, r)
	})
	srv := &http.Server{Handler: mux}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return "", nil, err
	}
	addr := ln.Addr().String()
	go func() { _ = srv.Serve(ln) }()
	stop := func() { _ = srv.Close() }
	return addr, stop, nil
}

// writeWebrootChallenges 把 HTTP-01 key authorization 应答写入 webroot 目录，
// 返回清理函数（删除已写文件）。由外部 web 服务器把
// /.well-known/acme-challenge/* 映射到该目录。v0.4.31-B 新增，webroot 为空时
// 不会调用此函数，原有 standalone 流程不受影响。
func writeWebrootChallenges(webroot string, responses map[string]string) (func(), error) {
	dir := filepath.Join(webroot, ".well-known", "acme-challenge")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var written []string
	cleanup := func() {
		for _, p := range written {
			_ = os.Remove(p)
		}
	}
	for token, ka := range responses {
		// ACME token 为 base64url；拒绝路径分隔符与 "." / ".."，防止目录穿越写文件。
		if token == "" || strings.ContainsAny(token, `/\`) || token == "." || token == ".." {
			cleanup()
			return nil, fmt.Errorf("非法 HTTP-01 token %q", token)
		}
		p := filepath.Join(dir, token)
		if err := os.WriteFile(p, []byte(ka), 0o644); err != nil {
			cleanup()
			return nil, err
		}
		written = append(written, p)
	}
	return cleanup, nil
}
