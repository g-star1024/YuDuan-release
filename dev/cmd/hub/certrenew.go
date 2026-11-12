// v0.4.31-B 安全 P1：TLS 证书热重载 + ACME 自动续期接线（cmd/hub 侧）。
//
// 把原 main.go 的 http.ListenAndServeTLS 换成自建 http.Server + tls.Config.GetCertificate：
// 证书放在 atomic.Pointer[tls.Certificate] 中，续期后 swap 指针即可零重启轮换。
//
// 零回归关键：用 srv.ServeTLS(ln, "", "") 而非裸 srv.Serve(tlsListener)。
// 前者与 http.ListenAndServeTLS 走同一条 Server.ServeTLS 路径，会自动
// setupHTTP2_ServeTLS（h2 ALPN 保持一致）；且当 TLSConfig.GetCertificate 非 nil、
// certFile/keyFile 传空时，ServeTLS 判定 configHasCert=true，不会用
// LoadX509KeyPair 覆盖证书，从而保留我们的热重载回调。默认关闭续期时，
// GetCertificate 始终返回启动时加载的那一张证书，握手字节与原来完全一致。
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync/atomic"

	"yuduan/internal/acme"
)

// certHolder 用 atomic.Pointer 持有当前证书，支持零重启热重载。
// GetCertificate 每次 TLS 握手读取当前指针；Reload 在续期成功后 swap。
type certHolder struct {
	cur atomic.Pointer[tls.Certificate]
}

func newCertHolder(certPEM, keyPEM []byte) (*certHolder, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	h := &certHolder{}
	h.cur.Store(&pair)
	return h, nil
}

// GetCertificate 实现 tls.Config.GetCertificate，返回当前有效证书。
func (h *certHolder) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := h.cur.Load()
	if c == nil {
		return nil, errors.New("TLS 证书未加载")
	}
	return c, nil
}

// Reload 原子替换当前证书（由 ACME RenewWatcher 续期成功后回调）。
func (h *certHolder) Reload(certPEM, keyPEM []byte) error {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	h.cur.Store(&pair)
	return nil
}

// StartTLSListenerWithRenewal 启动 TLS 中枢监听（https + wss），并在
// YUDUAN_ACME_AUTORENEW=1 且 netMode=public 时挂载 ACME 自动续期 watcher。
//
// 容错语义与原 main.go:251-262 完全一致：TLS 监听/证书加载失败仅降级为明文 +
// 告警，不 log.Fatal 杀全进程（否则明文 8080 也会一并停服）。
func StartTLSListenerWithRenewal(tlsAddr, cert, key, netMode string, handler http.Handler, onReady func()) {
	go func() {
		log.Printf("[hub] TLS 中枢监听 %s（https + wss）", tlsAddr)

		degrade := func(err error) {
			log.Printf("[hub] ❌ TLS 中枢监听失败: %v", err)
			log.Printf("[hub] ⚠️ 控制面降级为仅明文 http/ws（无加密）。修复：释放 %s 端口或检查 certs/ 证书后重启", tlsAddr)
		}

		// 启动时加载一次初始证书（默认关闭续期时等价于 ListenAndServeTLS 的
		// LoadX509KeyPair(certFile, keyFile)）。失败即降级，不杀进程。
		holder, err := loadInitialCert(cert, key)
		if err != nil {
			degrade(err)
			return
		}
		ln, err := net.Listen("tcp", tlsAddr)
		if err != nil {
			degrade(err)
			return
		}
		if onReady != nil {
			onReady() // TLS 监听已真正建立（证书加载 + 端口绑定成功），用于 info.tls_enabled 如实回显
		}

		srv := &http.Server{
			Addr:      tlsAddr,
			Handler:   handler,
			TLSConfig: &tls.Config{GetCertificate: holder.GetCertificate},
		}

		// 仅 public + AUTORENEW=1 启用：把 holder.Reload 注入 watcher，换证后
		// swap 内存证书指针即可热重载，无需重启监听。LAN 默认不进入此分支。
		if acme.RenewalEnabled(netMode) {
			cfg := acme.RenewConfigFromEnv(netMode, cert, key)
			cfg.Reload = holder.Reload
			go acme.NewRenewWatcher(cfg).Start(context.Background())
			log.Printf("[hub] ACME 证书自动续期已启用（YUDUAN_ACME_AUTORENEW=1, public）：domain=%v 周期=%s 阈值=%d天 指纹文件=%s",
				cfg.Domains, cfg.CheckInterval, cfg.RenewDays, cfg.FingerprintPath)
		}

		// ServeTLS(ln, "", "")：走 setupHTTP2_ServeTLS（h2 ALPN 与原来一致），
		// 且 GetCertificate 非 nil + 空 cert/key 路径时不会覆盖热重载回调。
		if err := srv.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
			degrade(err)
		}
	}()
}

// loadInitialCert 读取磁盘 cert/key 并构造 certHolder。
func loadInitialCert(cert, key string) (*certHolder, error) {
	certPEM, err := os.ReadFile(cert)
	if err != nil {
		return nil, fmt.Errorf("读取证书 %s: %w", cert, err)
	}
	keyPEM, err := os.ReadFile(key)
	if err != nil {
		return nil, fmt.Errorf("读取私钥 %s: %w", key, err)
	}
	return newCertHolder(certPEM, keyPEM)
}
