// v0.4.31-B：ACME 自动续期离线单测（零网络、零真实 ACME Directory）。
// 通过 RenewConfig 的可注入依赖（IssueFn/LoadNotAfterFn/Reload/Now/Logf）
// 覆盖：默认关闭、阈值边界、失败退避不杀进程、原子替换+热重载、指纹口径。
package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"yuduan/internal/tlsutil"
)

// mkTestCertPEM 生成一张自签测试证书 + RSA 私钥（仅单测用，不落生产路径）。
func mkTestCertPEM(t *testing.T, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "renew-test.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"renew-test.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	return
}

func quietLog() func(string, ...any) { return func(string, ...any) {} }

// ---- 1) 默认关闭：未设 YUDUAN_ACME_AUTORENEW 时一律 false；=1 但 lan 也 false ----

func TestRenewalEnabled_GatedByEnvAndNetMode(t *testing.T) {
	t.Setenv("YUDUAN_ACME_AUTORENEW", "")
	if RenewalEnabled("public") {
		t.Fatal("未设置开关时 public 也不得启用（默认关闭）")
	}
	t.Setenv("YUDUAN_ACME_AUTORENEW", "1")
	if RenewalEnabled("lan") {
		t.Fatal("LAN 形态即使开关=1 也不得启用（铁律 1 零回归）")
	}
	if !RenewalEnabled("PUBLIC") {
		t.Fatal("public（大小写不敏感）且开关=1 应启用")
	}
}

// ---- 2) 阈值边界：19/20/21 天 ----

func TestShouldRenew_ThresholdBoundary(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		days int
		want bool
	}{
		{19, true},  // 距到期 19 天 < 20 天阈值 → 触发
		{20, false}, // 恰好 20 天：notAfter 不 Before(now+20d) → 不触发
		{21, false}, // 21 天 → 不触发
	}
	for _, c := range cases {
		na := now.Add(time.Duration(c.days) * 24 * time.Hour)
		if got := ShouldRenew(now, na, 20); got != c.want {
			t.Errorf("距到期 %d 天: 期望 %v，实际 %v", c.days, c.want, got)
		}
	}
	// renewDays<=0 回退默认 20 天
	if !ShouldRenew(now, now.Add(19*24*time.Hour), 0) {
		t.Fatal("renewDays=0 应回退默认 20 天阈值")
	}
	// 已过期证书必然触发
	if !ShouldRenew(now, now.Add(-time.Hour), 20) {
		t.Fatal("已过期证书应触发续期")
	}
}

// ---- 3) 失败退避：Issue 失败不得 panic / 不得调用 Reload / 下轮跳过 ----

func TestRenewWatcher_FailureBackoff_NoReload_NoPanic(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	certPEM, keyPEM := mkTestCertPEM(t, now.Add(10*24*time.Hour))
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	issueCalls, reloadCalls := 0, 0
	w := NewRenewWatcher(RenewConfig{
		CertPath:        filepath.Join(dir, "cert.pem"),
		KeyPath:         filepath.Join(dir, "key.pem"),
		Domains:         []string{"renew-test.local"},
		RenewDays:       20,
		CheckInterval:   time.Hour,
		MaxBackoff:      2 * time.Hour,
		FingerprintPath: filepath.Join(dir, "pin"),
		IssueFn: func(Options) (Result, error) {
			issueCalls++
			return Result{}, errors.New("模拟 ACME Directory 不可达")
		},
		LoadNotAfterFn: func(string) (time.Time, error) { return now.Add(10 * 24 * time.Hour), nil },
		Reload:         func([]byte, []byte) error { reloadCalls++; return nil },
		Now:            func() time.Time { return now },
		Logf:           quietLog(),
	})
	// 连续三次 Tick：第 1 次失败进入退避，后两次应被跳过（issueCalls 保持 1）
	for i := 0; i < 3; i++ {
		w.Tick()
	}
	if issueCalls != 1 {
		t.Fatalf("失败退避应跳过后续检查，Issue 调用期望 1 次，实际 %d 次", issueCalls)
	}
	if reloadCalls != 0 {
		t.Fatalf("签发失败绝不能热重载，Reload 调用期望 0 次，实际 %d 次", reloadCalls)
	}
	if _, err := os.Stat(filepath.Join(dir, "pin")); !os.IsNotExist(err) {
		t.Fatal("签发失败不得落指纹文件")
	}
}

// ---- 4) 成功路径：原子替换 cert/key + Reload 被触发 + 指纹与副端口径一致 ----

func TestRenewWatcher_Success_AtomicReplace_Reload_Fingerprint(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	pinPath := filepath.Join(dir, "pin")

	oldCert, oldKey := mkTestCertPEM(t, now.Add(10*24*time.Hour))
	if err := os.WriteFile(certPath, oldCert, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, oldKey, 0o600); err != nil {
		t.Fatal(err)
	}
	// 新证书 90 天后到期（模拟续期产物）
	newCert, newKey := mkTestCertPEM(t, now.Add(90*24*time.Hour))
	wantPin, err := tlsutil.SpkiPinHexFromPEM(newCert)
	if err != nil {
		t.Fatal(err)
	}

	issueDir := t.TempDir()
	newCertPath := filepath.Join(issueDir, "fullchain.pem")
	newKeyPath := filepath.Join(issueDir, "key.pem")
	if err := os.WriteFile(newCertPath, newCert, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newKeyPath, newKey, 0o600); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var reloadCert, reloadKey []byte
	w := NewRenewWatcher(RenewConfig{
		CertPath:        certPath,
		KeyPath:         keyPath,
		Domains:         []string{"renew-test.local"},
		RenewDays:       20,
		CheckInterval:   time.Hour,
		MaxBackoff:      time.Hour,
		FingerprintPath: pinPath,
		IssueFn: func(Options) (Result, error) {
			return Result{FullchainPath: newCertPath, KeyPath: newKeyPath}, nil
		},
		LoadNotAfterFn: func(string) (time.Time, error) { return now.Add(10 * 24 * time.Hour), nil },
		Reload: func(c, k []byte) error {
			mu.Lock()
			defer mu.Unlock()
			reloadCert, reloadKey = append([]byte(nil), c...), append([]byte(nil), k...)
			return nil
		},
		Now:  func() time.Time { return now },
		Logf: quietLog(),
	})
	w.Tick()

	gotCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	gotKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotCert) != string(newCert) || string(gotKey) != string(newKey) {
		t.Fatal("磁盘 cert/key 未被原子替换为新证书")
	}
	mu.Lock()
	rc, rk := reloadCert, reloadKey
	mu.Unlock()
	if string(rc) != string(newCert) || string(rk) != string(newKey) {
		t.Fatal("热重载回调未收到新证书（或根本未触发）")
	}
	pinBytes, err := os.ReadFile(pinPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(pinBytes)) != wantPin {
		t.Fatalf("SPKI 指纹与副端口径不一致：期望 %s，实际 %s", wantPin, strings.TrimSpace(string(pinBytes)))
	}
	// 无残留临时文件（atomicWrite 的 .renew-* 已清理）
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".renew-") {
			t.Fatalf("原子写残留临时文件: %s", e.Name())
		}
	}
}

// ---- 5) 无效证书前置门：Issue 返回坏证书时拒绝替换、不触发 Reload ----

func TestRenewWatcher_RejectsInvalidCert(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	origCert, origKey := mkTestCertPEM(t, now.Add(10*24*time.Hour))
	_ = os.WriteFile(certPath, origCert, 0o644)
	_ = os.WriteFile(keyPath, origKey, 0o600)

	badPath := filepath.Join(t.TempDir(), "bad.pem")
	_ = os.WriteFile(badPath, []byte("not a certificate"), 0o644)
	reloads := 0
	w := NewRenewWatcher(RenewConfig{
		CertPath:        certPath,
		KeyPath:         keyPath,
		Domains:         []string{"renew-test.local"},
		FingerprintPath: filepath.Join(dir, "pin"),
		IssueFn: func(Options) (Result, error) {
			return Result{FullchainPath: badPath, KeyPath: keyPath}, nil
		},
		LoadNotAfterFn: func(string) (time.Time, error) { return now.Add(10 * 24 * time.Hour), nil },
		Reload:         func([]byte, []byte) error { reloads++; return nil },
		Now:            func() time.Time { return now },
		Logf:           quietLog(),
	})
	w.Tick()
	if reloads != 0 {
		t.Fatal("坏证书绝不能触发热重载")
	}
	got, _ := os.ReadFile(certPath)
	if string(got) != string(origCert) {
		t.Fatal("坏证书不得覆盖现有磁盘证书")
	}
}

// ---- 6) webroot 模式：token 路径穿越必须被拒绝 ----

func TestWriteWebrootChallenges_RejectsPathTraversal(t *testing.T) {
	root := t.TempDir()
	_, err := writeWebrootChallenges(root, map[string]string{"../evil": "ka"})
	if err == nil {
		t.Fatal("含路径分隔符的 token 必须被拒绝")
	}
	if _, err := writeWebrootChallenges(root, map[string]string{"..": "ka"}); err == nil {
		t.Fatal("token='..' 必须被拒绝")
	}
	stop, err := writeWebrootChallenges(root, map[string]string{"validToken123": "keyAuth"})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, ".well-known", "acme-challenge", "validToken123")
	b, err := os.ReadFile(p)
	if err != nil || string(b) != "keyAuth" {
		t.Fatalf("合法 token 应答未写入 webroot: %v", err)
	}
	stop()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("清理函数应删除已写应答文件")
	}
}
