package hub

// UDP 自动发现（§8.4）：主端/副端在未配置中枢地址时，向 255.255.255.255:18242
// 广播探测包 "YUDUAN_DISCOVER"，本服务对每个非环回 IPv4 地址回一帧单行文本：
//
//	proto=yuduan-disc http=http://<ip>:<port> ws=ws://<ip>:<port>/ws/agent hostname=<h>
//
// 客户端无需 JSON 解析（副端零依赖约束）；多网卡时逐地址回复，客户端取首个可达项。
// 仅限可信内网使用（铁律 1 场景）；报文只含中枢地址与主机名，无敏感信息。

import (
	"fmt"
	"log"
	"net"
	"strings"
)

// DiscoveryPort 发现服务固定 UDP 端口（与控制面 18241/默认 8080 相邻，易记）。
const DiscoveryPort = 18242

// DiscoveryProbe 客户端探测包内容。
const DiscoveryProbe = "YUDUAN_DISCOVER"

// DiscoveryReply 构造单行回复文本（导出供单测）。
func DiscoveryReply(ip, plainPort, hostname string) string {
	return fmt.Sprintf("proto=yuduan-disc http=http://%s%s ws=ws://%s%s/ws/agent hostname=%s",
		ip, plainPort, ip, plainPort, hostname)
}

// ServeDiscovery 启动 UDP 发现应答循环（阻塞调用方无需等待，内部 goroutine）。
// plainPort 形如 ":18241"（含冒号的监听地址端口段）。
func ServeDiscovery(plainPort, hostname string) {
	pc, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", DiscoveryPort))
	if err != nil {
		log.Printf("[hub] UDP 发现服务未启动（端口 %d 可能被占用）: %v", DiscoveryPort, err)
		return
	}
	go func() {
		buf := make([]byte, 64)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if strings.TrimSpace(string(buf[:n])) != DiscoveryProbe {
				continue
			}
			ips := localIPv4s()
			if len(ips) == 0 {
				// 兜底：取不到本机 IPv4 时用回环地址回复（同机测试仍可用）
				ips = []string{"127.0.0.1"}
			}
			for _, ip := range ips {
				if _, err := pc.WriteTo([]byte(DiscoveryReply(ip, plainPort, hostname)), addr); err != nil {
					log.Printf("[hub] UDP 发现应答失败: %v", err)
				}
			}
		}
	}()
	log.Printf("[hub] UDP 自动发现监听 :%d（主端/副端未配置地址时广播即得）", DiscoveryPort)
}

// localIPv4s 枚举本机非环回、已启用的 IPv4 地址。
func localIPv4s() []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if v4 := ipnet.IP.To4(); v4 != nil {
				out = append(out, v4.String())
			}
		}
	}
	return out
}
