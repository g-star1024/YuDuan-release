package hub

import (
	"strings"
	"testing"
)

func TestDiscoveryReplyFormat(t *testing.T) {
	got := DiscoveryReply("192.168.1.24", ":18241", "hub-host")
	want := "proto=yuduan-disc http=http://192.168.1.24:18241 ws=ws://192.168.1.24:18241/ws/agent hostname=hub-host"
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

func TestLocalIPv4sExcludesLoopback(t *testing.T) {
	for _, ip := range localIPv4s() {
		if strings.HasPrefix(ip, "127.") {
			t.Fatalf("localIPv4s 不应包含环回地址: %s", ip)
		}
	}
}
