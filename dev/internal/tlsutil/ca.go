// Package tlsutil —— 私有 CA 支持（§5 安全基座 / M6）。
//
// 内网部署的正确信任模型：企业自建根 CA（离线保管）→ 给中枢签服务器证书、
// 给副端签 mTLS 客户端证书。替代早期「一次性自签」，副端可用两种方式校验：
//   - YUDUAN_TLS_CAFILE=<ca.pem>：openssl 链式严格校验（信任根 CA）；
//   - YUDUAN_TLS_PIN=<SPKI SHA-256>：RFC 7469 公钥固定（叶证书，pin 即信任）。
//
// 全部使用 Go 标准库，零第三方依赖（铁律）。
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	// RootValidity 根 CA 有效期：10 年（内网根，到期前用 ca check 告警轮换）。
	RootValidity = 10 * 365 * 24 * time.Hour
	// LeafValidity 叶证书有效期：1 年（到期自动告警，用 ca issue-server 轮换）。
	LeafValidity = 365 * 24 * time.Hour
)

// CAPaths 约定目录布局：<dir>/ca.pem、ca.key、cert.pem、key.pem。
type CAPaths struct{ Dir string }

func (p CAPaths) CACert() string    { return p.Dir + "/ca.pem" }
func (p CAPaths) CAKey() string     { return p.Dir + "/ca.key" }
func (p CAPaths) Server() string    { return p.Dir + "/cert.pem" }
func (p CAPaths) ServerKey() string { return p.Dir + "/key.pem" }

// GenerateRootCA 生成自签根 CA（离线保管的信任锚）。已存在时直接返回（不覆盖）。
func GenerateRootCA(caCert, caKey, org string) error {
	if _, err := os.Stat(caCert); err == nil {
		return nil // 已有根：幂等，绝不覆盖（覆盖 = 全网信任重置）
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "YuDuan Root CA", Organization: []string{org}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(RootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0, // 只允许直接签发叶证书（扁平链，缩小风险面）
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	if err := writePEM(caCert, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	return writePEM(caKey, "EC PRIVATE KEY", keyBytes, 0o600)
}

// IssueCert 用 CA 给「服务器 / 客户端」签发叶证书。
// eku 决定用途（ServerAuth / ClientAuth）；dns/IP 为 SAN（服务器至少要含中枢主机名或 IP）。
// loadCA 读取并解析私有 CA（证书 + 私钥），供各签发函数复用。
func loadCA(caCertPath, caKeyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	caDER, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("读取 CA 证书: %w", err)
	}
	caBlock, _ := pem.Decode(caDER)
	if caBlock == nil {
		return nil, nil, errors.New("CA 证书 PEM 解析失败")
	}
	caX509, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("解析 CA 证书: %w", err)
	}
	caKeyDER, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("读取 CA 私钥: %w", err)
	}
	caKeyBlock, _ := pem.Decode(caKeyDER)
	if caKeyBlock == nil {
		return nil, nil, errors.New("CA 私钥 PEM 解析失败")
	}
	caKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("解析 CA 私钥: %w", err)
	}
	return caX509, caKey, nil
}

func IssueCert(caCertPath, caKeyPath, outCert, outKey, cn string,
	dnsNames []string, ips []net.IP, eku []x509.ExtKeyUsage) error {

	caX509, caKey, err := loadCA(caCertPath, caKeyPath)
	if err != nil {
		return err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"YuDuan"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(LeafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, caX509, &priv.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := writePEM(outCert, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	return writePEM(outKey, "EC PRIVATE KEY", keyBytes, 0o600)
}

// IssueServerCert 签发中枢服务器证书（SAN：localhost + 127.0.0.1 + 调用方补充）。
func IssueServerCert(caCertPath, caKeyPath, outCert, outKey string,
	dnsNames []string, ips []net.IP) error {
	allDNS := append([]string{"localhost"}, dnsNames...)
	allIPs := append([]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, ips...)
	return IssueCert(caCertPath, caKeyPath, outCert, outKey, "YuDuan Hub", allDNS, allIPs,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

// IssueClientCert 签发副端 mTLS 客户端证书（CN = 设备标识，便于中枢审计对账）。
func IssueClientCert(caCertPath, caKeyPath, outCert, outKey, deviceID string) error {
	return IssueCert(caCertPath, caKeyPath, outCert, outKey, deviceID, nil, nil,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
}

// IssueClientCertRSA 签发 **RSA** 客户端证书（私钥以 PKCS#8 PEM 输出）。
//
// 为什么需要：macOS 原生 TLS 栈（Security.framework）经 native-tls 装载客户端身份时
// **无法导入 SEC1 的 EC 私钥**（errSecUnknownFormat / "Unknown format in import"），
// PKCS#8 的 RSA 私钥可正常导入。副端走 openssl s_client（两种格式都接受）不受影响，
// 因此默认仍签发 EC；仅主端（Tauri / native-tls）或要求 PKCS#8 的下游用本函数。
func IssueClientCertRSA(caCertPath, caKeyPath, outCert, outKey, cn string) error {
	caX509, caKey, err := loadCA(caCertPath, caKeyPath)
	if err != nil {
		return err
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"YuDuan"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(LeafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, caX509, &priv.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := writePEM(outCert, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	return writePEM(outKey, "PRIVATE KEY", keyBytes, 0o600)
}

// SpkiPinHex 计算证书的 SPKI SHA-256（hex，小写）——RFC 7469 公钥固定指纹，
// 直接对应副端 YUDUAN_TLS_PIN 的取值（与 rust/agent/src/tls.rs 同一口径）。
func SpkiPinHex(certPath string) (string, error) {
	der, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(der)
	if block == nil {
		return "", errors.New("证书 PEM 解析失败")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(crt.PublicKey)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(spkiDER)
	return fmt.Sprintf("%x", sum), nil
}

// WriteServerChain 生成完整链文件（leaf + root 拼接，Go/openssl 均按序下发）。
// 中枢 TLS 监听应使用链文件：客户端 pin 模式的临时 CAfile 依赖链中的根锚。
func WriteServerChain(certPath, caCertPath, chainPath string) error {
	leaf, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	root, err := os.ReadFile(caCertPath)
	if err != nil {
		return err
	}
	var chain []byte
	chain = append(chain, leaf...)
	if !endsWithNewline(chain) {
		chain = append(chain, '\n')
	}
	chain = append(chain, root...)
	return os.WriteFile(chainPath, chain, 0o644)
}

func endsWithNewline(b []byte) bool {
	return len(b) > 0 && b[len(b)-1] == '\n'
}

// LoadCertNotAfter 读取证书到期时间（用于启动时告警与轮换检查）。
func LoadCertNotAfter(certPath string) (time.Time, error) {
	der, err := os.ReadFile(certPath)
	if err != nil {
		return time.Time{}, err
	}
	block, _ := pem.Decode(der)
	if block == nil {
		return time.Time{}, errors.New("证书 PEM 解析失败")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return crt.NotAfter, nil
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}
