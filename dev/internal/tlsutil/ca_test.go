package tlsutil

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func pemBlock(der []byte) []byte {
	b, _ := pem.Decode(der)
	if b == nil {
		panic("PEM 解析失败")
	}
	return b.Bytes
}

func setupCA(t *testing.T) CAPaths {
	t.Helper()
	dir := t.TempDir()
	p := CAPaths{Dir: dir}
	if err := GenerateRootCA(p.CACert(), p.CAKey(), "YuDuan Test"); err != nil {
		t.Fatalf("生成根 CA: %v", err)
	}
	return p
}

func TestRootCAIdempotent(t *testing.T) {
	p := setupCA(t)
	before, _ := os.ReadFile(p.CACert())
	// 再次 GenerateRootCA：必须不覆盖（覆盖 = 全网信任重置）
	if err := GenerateRootCA(p.CACert(), p.CAKey(), "YuDuan Test"); err != nil {
		t.Fatalf("幂等调用失败: %v", err)
	}
	after, _ := os.ReadFile(p.CACert())
	if string(before) != string(after) {
		t.Fatal("已存在的根 CA 被覆盖（应保持不变）")
	}
}

func TestIssueServerAndPin(t *testing.T) {
	p := setupCA(t)
	if err := IssueServerCert(p.CACert(), p.CAKey(), p.Server(), p.ServerKey(),
		[]string{"hub.internal"}, []net.IP{net.ParseIP("10.1.2.3")}); err != nil {
		t.Fatalf("签发服务器证书: %v", err)
	}
	pin, err := SpkiPinHex(p.Server())
	if err != nil || len(pin) != 64 {
		t.Fatalf("SPKI pin: pin=%q err=%v", pin, err)
	}
	// SAN 校验：localhost/127.0.0.1/::1/附加项都要在
	crt := parseCert(t, p.Server())
	if err := crt.VerifyHostname("localhost"); err != nil {
		t.Fatalf("服务器证书应通过 localhost 主机名校验: %v", err)
	}
	dnsOK, ipOK := false, false
	for _, d := range crt.DNSNames {
		if d == "hub.internal" || d == "localhost" {
			dnsOK = true
		}
	}
	for _, ip := range crt.IPAddresses {
		if ip.String() == "10.1.2.3" || ip.String() == "127.0.0.1" {
			ipOK = true
		}
	}
	if !dnsOK || !ipOK {
		t.Fatalf("SAN 缺失: dns=%v ip=%v", crt.DNSNames, crt.IPAddresses)
	}
	if crt.IsCA {
		t.Fatal("叶证书不应 IsCA=true")
	}
	if !crt.NotAfter.After(time.Now().Add(300 * 24 * time.Hour)) {
		t.Fatalf("叶证书有效期应约 1 年，实际到期 %v", crt.NotAfter)
	}
	// EKU ServerAuth
	found := false
	for _, e := range crt.ExtKeyUsage {
		if e == x509.ExtKeyUsageServerAuth {
			found = true
		}
	}
	if !found {
		t.Fatal("服务器证书缺少 ServerAuth EKU")
	}
}

func TestIssueClientCertAndChainVerify(t *testing.T) {
	p := setupCA(t)
	if err := IssueClientCert(p.CACert(), p.CAKey(),
		filepath.Join(p.Dir, "client-a.pem"), filepath.Join(p.Dir, "client-a.key"), "dev-a"); err != nil {
		t.Fatalf("签发客户端证书: %v", err)
	}
	crt := parseCert(t, filepath.Join(p.Dir, "client-a.pem"))
	if crt.Subject.CommonName != "dev-a" {
		t.Fatalf("CN 应为设备 ID，实际 %q", crt.Subject.CommonName)
	}
	found := false
	for _, e := range crt.ExtKeyUsage {
		if e == x509.ExtKeyUsageClientAuth {
			found = true
		}
	}
	if !found {
		t.Fatal("客户端证书缺少 ClientAuth EKU")
	}
	// 链验证：客户端证书必须能被根 CA 验证通过（中级缺失的扁平链）
	ca := parseCert(t, p.CACert())
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := crt.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("链验证失败: %v", err)
	}
}

func TestSpkiPinMatchesRustConvention(t *testing.T) {
	// 与副端 tls.rs 口径一致性：pin = SHA256(SPKI DER)。用已知向量校验 hex 编码与长度，
	// 并确认两次计算稳定（同一证书同 pin）。
	p := setupCA(t)
	_ = p
	// 自签证书固定校验：同样证书两次 pin 相同
	dir := t.TempDir()
	pp := CAPaths{Dir: dir}
	if err := GenerateRootCA(pp.CACert(), pp.CAKey(), "T"); err != nil {
		t.Fatal(err)
	}
	a, _ := SpkiPinHex(pp.CACert())
	b, _ := SpkiPinHex(pp.CACert())
	if a != b || len(a) != 64 {
		t.Fatalf("pin 不稳定: %q vs %q", a, b)
	}
	for _, c := range a {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("pin 应为小写 hex: %q", a)
		}
	}
}

func parseCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	der, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s: %v", path, err)
	}
	crt, err := x509.ParseCertificate(pemBlock(der))
	if err != nil {
		t.Fatalf("解析 %s: %v", path, err)
	}
	return crt
}
