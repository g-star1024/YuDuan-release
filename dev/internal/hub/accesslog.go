package hub

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"
)

// statusWriter 记录响应状态码供访问日志统计；并透传 http.Hijacker
// （WebSocket 升级需要 http.Hijacker 断言，缺失会 panic）。
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("hijack not supported")
}

// withAccessLog 记录每个 HTTP 请求（来源/method/path/status/耗时）到中枢日志。
//
// 目的：部署或登录失败时，从 hub.log 一眼判断「请求是否到达后端」——
//   - 日志无该请求行        → 进程未收到（进程未跑 / 网络层阻断 / 端口不符）
//   - 日志有该行且 status=200 → 后端已处理（看响应 code 判定业务成败）
//
// WebSocket 升级后连接长驻，完成日志在连接断开时输出；普通 HTTP 请求即时记录。
func (h *Hub) withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		log.Printf("[http] %s %s %s -> %d (%s)", clientIP(r), r.Method, r.URL.Path, sw.status, time.Since(start).Round(time.Millisecond))
	})
}

// clientIP 提取来源 IP（不含端口）。
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
