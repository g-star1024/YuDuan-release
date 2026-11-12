package hub

import (
	"strings"
	"testing"
)

func TestDiscoveryReplyFormat(t *testing.T) {
	got := DiscoveryReply("192.168.1.24", ":18241", "", "hub-host", "tok123")
	want := "proto=yuduan-disc http=http://192.168.1.24:18241 ws=ws://192.168.1.24:18241/ws/agent hostname=hub-host token=tok123"
	if got != want {
		t.Fatalf("回复格式不符\n got: %s\nwant: %s", got, want)
	}
	for _, tok := range strings.Fields(got) {
		if strings.HasPrefix(tok, "http=") || strings.HasPrefix(tok, "ws=") {
			if !strings.Contains(tok, "192.168.1.24") {
				t.Fatalf("字段 %q 未携带中枢 IP", tok)
			}
		}
	}
}

// 复盘 S-2：TLS 启用时广播必须携带 wss=/https=，副端才能走 TLS 通道 claim。
func TestDiscoveryReplyAdvertisesTLS(t *testing.T) {
	got := DiscoveryReply("192.168.1.24", ":8080", ":8443", "hub-host", "tok")
	for _, want := range []string{"wss=wss://192.168.1.24:8443/ws/agent", "https=https://192.168.1.24:8443"} {
		if !strings.Contains(got, want) {
			t.Fatalf("TLS 启用时缺少 %q: %s", want, got)
		}
	}
}

func TestDiscoveryReplyOmitsTokenWhenEmpty(t *testing.T) {
	got := DiscoveryReply("192.168.1.24", ":18241", "", "hub-host", "")
	if strings.Contains(got, "token=") {
		t.Fatalf("token 为空时不应携带 token 字段: %s", got)
	}
	if !strings.HasPrefix(got, "proto=yuduan-disc http=") {
		t.Fatalf("基础字段缺失: %s", got)
	}
}

func TestLocalIPv4sExcludesLoopback(t *testing.T) {
	for _, ip := range localIPv4s() {
		if strings.HasPrefix(ip, "127.") {
			t.Fatalf("localIPv4s 不应包含环回地址: %s", ip)
		}
	}
}
