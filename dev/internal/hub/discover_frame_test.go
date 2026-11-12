package hub

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// 帧格式回归锁（F-07）：本次改动只允许把「发现监听端口」做成可配置，严禁触碰
// DiscoveryReply 的单行文本拼接——畸形帧历史裁决见
// deploy/hub/README-deploy.md:183-185、:270。以下用例逐字钉死各分支输出，
// 任何拼接改动都会在此失败。
func TestDiscoveryReplyFrameFrozen(t *testing.T) {
	cases := []struct {
		name                              string
		ip, plainPort, tlsPort, host, tok string
		want                              string
	}{
		{
			name: "明文_无token",
			ip:   "192.168.1.24", plainPort: ":18241", tlsPort: "", host: "hub-host", tok: "",
			want: "proto=yuduan-disc http=http://192.168.1.24:18241 ws=ws://192.168.1.24:18241/ws/agent hostname=hub-host",
		},
		{
			name: "明文_带token",
			ip:   "192.168.1.24", plainPort: ":18241", tlsPort: "", host: "hub-host", tok: "tok123",
			want: "proto=yuduan-disc http=http://192.168.1.24:18241 ws=ws://192.168.1.24:18241/ws/agent hostname=hub-host token=tok123",
		},
		{
			name: "TLS_wss_https_带token",
			ip:   "192.168.1.24", plainPort: ":8080", tlsPort: ":8443", host: "hub-host", tok: "tok",
			want: "proto=yuduan-disc http=http://192.168.1.24:8080 ws=ws://192.168.1.24:8080/ws/agent wss=wss://192.168.1.24:8443/ws/agent https=https://192.168.1.24:8443 hostname=hub-host token=tok",
		},
		{
			name: "TLS_wss_https_无token",
			ip:   "10.0.0.9", plainPort: ":18081", tlsPort: ":8443", host: "h2", tok: "",
			want: "proto=yuduan-disc http=http://10.0.0.9:18081 ws=ws://10.0.0.9:18081/ws/agent wss=wss://10.0.0.9:8443/ws/agent https=https://10.0.0.9:8443 hostname=h2",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DiscoveryReply(c.ip, c.plainPort, c.tlsPort, c.host, c.tok)
			if got != c.want {
				t.Fatalf("帧格式被改动\n got: %q\nwant: %q", got, c.want)
			}
		})
	}
}

// TestServeDiscoveryCustomPort 用临时空闲高端口实际起 ServeDiscovery，UDP 探测收帧，
// 断言帧内控制面地址为传入的 plainPort 而非发现端口，验证 port 参数确实生效。
// 端口借 :0 动态申请，避免与其它实例/测试冲突；探测 socket 设 Deadline，确保
// 即使绑定失败也不会挂死（ServeDiscovery 的应答 goroutine 随测试进程退出而终止）。
func TestServeDiscoveryCustomPort(t *testing.T) {
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("申请临时端口失败: %v", err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()

	const plainPort = ":18081"
	const host = "custom-port-host"
	ServeDiscovery(port, plainPort, "", host, nil)

	conn, err := net.Dial("udp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("连接发现端口失败: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("设置超时失败: %v", err)
	}
	if _, err := conn.Write([]byte(DiscoveryProbe)); err != nil {
		t.Fatalf("发送探测包失败: %v", err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("未收到发现应答（发现端口 %d 可能绑定失败或被占用）: %v", port, err)
	}
	frame := string(buf[:n])
	if !strings.HasPrefix(frame, "proto=yuduan-disc http=") {
		t.Fatalf("应答帧格式异常: %q", frame)
	}
	httpField := discoveryFrameField(frame, "http")
	if !strings.HasSuffix(httpField, plainPort) {
		t.Fatalf("帧内控制面端口应为 %s，实际 http=%s（疑似误用了发现端口）", plainPort, httpField)
	}
	// 反向确认：控制面端口绝不能等于本次的发现端口。
	if strings.HasSuffix(httpField, fmt.Sprintf(":%d", port)) {
		t.Fatalf("帧内控制面端口误用了发现端口 %d: %q", port, frame)
	}
	if got := discoveryFrameField(frame, "hostname"); got != host {
		t.Fatalf("hostname 应为 %s，实际 %s", host, got)
	}
}

func discoveryFrameField(frame, key string) string {
	for _, tok := range strings.Fields(frame) {
		if strings.HasPrefix(tok, key+"=") {
			return strings.TrimPrefix(tok, key+"=")
		}
	}
	return ""
}
