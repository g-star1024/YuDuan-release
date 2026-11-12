package hub

// UDP 自动发现（§8.4）：主端/副端在未配置中枢地址时，向 255.255.255.255:18242
// 广播探测包 "YUDUAN_DISCOVER"，本服务对每个非环回 IPv4 地址回一帧单行文本：
//
//	proto=yuduan-disc http=http://<ip>:<port> ws=ws://<ip>:<port>/ws/agent hostname=<h> [token=<t>]
//
// 客户端无需 JSON 解析（副端零依赖约束）；多网卡时逐地址回复，客户端取首个可达项。
// 仅限可信内网使用（铁律 1 场景）。
//
// 安全（档位 A 设备引导）：token= 为**一次性注册令牌**（短时效、每次广播轮换），
// 副端凭它向 /api/agent/claim 换取 HMAC 密钥与客户端证书。**绝不**在此携带长期
// 共享密钥（HMAC_SECRET）——UDP 广播为明文，任何能收广播的主机都能抓取，若含
// 密钥则铁律 4 的指令签名可被伪造，整个控制面失守。

import (
	"fmt"
	"log"
	"net"
	"strings"
)

// DiscoveryPort 发现服务默认 UDP 端口（与控制面默认 8080/TLS 8443 相邻易记）。
// F-07：可由 YUDUAN_DISCOVERY_PORT 覆盖；本常量保留作默认值供其它包/测试引用。
const DiscoveryPort = 18242

// DiscoveryProbe 客户端探测包内容。
const DiscoveryProbe = "YUDUAN_DISCOVER"

// DiscoveryReply 构造单行回复文本（导出供单测）。
// token 非空时追加一次性注册令牌字段；空则不携带（向后兼容）。
// tlsPort 非空（如 ":8443"）时追加 wss=/https= 地址——复盘 S-2：claim 在 TLS 启用时
// 拒绝明文，副端必须优先走 wss/https 引导，否则拿到密钥的通道仍是明文。
func DiscoveryReply(ip, plainPort, tlsPort, hostname, token string) string {
	line := fmt.Sprintf("proto=yuduan-disc http=http://%s%s ws=ws://%s%s/ws/agent",
		ip, plainPort, ip, plainPort)
	if tlsPort != "" {
		line += fmt.Sprintf(" wss=wss://%s%s/ws/agent https=https://%s%s", ip, tlsPort, ip, tlsPort)
	}
	line += " hostname=" + hostname
	if token != "" {
		line += " token=" + token
	}
	return line
}

// ServeDiscovery 启动 UDP 发现应答循环（阻塞调用方无需等待，内部 goroutine）。
// port 为发现服务监听的 UDP 端口（YUDUAN_DISCOVERY_PORT 覆盖，默认 DiscoveryPort）；
// plainPort 形如 ":8080"（含冒号的监听地址端口段）；tlsPort 形如 ":8443"，为空则
// 不广播 wss=/https=（TLS 未启用）。
// tokenFn 在每次应答时调用，返回当前有效的一次性注册令牌（可为空，空则不下发）。
func ServeDiscovery(port int, plainPort, tlsPort, hostname string, tokenFn func() string) {
	pc, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", port))
	if err != nil {
		// 绑定失败仍只告警、不 Fatal：发现服务属可选增强，端口占用不应拖垮整个中枢
		// （保持 LAN 零回归）；多实例并存时给出可操作的端口隔离提示。
		log.Printf("[hub] ⚠️ UDP 发现服务未启动：配置的发现端口 %d 绑定失败（%v）；端口可能被占用，多实例并存请给各实例及客户端设置不同 YUDUAN_DISCOVERY_PORT", port, err)
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
			var token string
			if tokenFn != nil {
				token = tokenFn()
			}
			for _, ip := range ips {
				if _, err := pc.WriteTo([]byte(DiscoveryReply(ip, plainPort, tlsPort, hostname, token)), addr); err != nil {
					log.Printf("[hub] UDP 发现应答失败: %v", err)
				}
			}
		}
	}()
	log.Printf("[hub] UDP 自动发现监听 :%d（主端/副端未配置地址时广播即得）", port)
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
