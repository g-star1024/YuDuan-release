// 御端私有 CA 管理工具（dev/cmd/ca）—— 内网信任锚的签发与运维（§5 安全基座）。
//
// 零第三方依赖（纯 Go 标准库）。目录布局（默认 certs/）：
//
//	ca.pem / ca.key      根 CA（ca.key 离线保管，不落中枢生产机）
//	cert.pem / key.pem   中枢服务器证书（SAN：localhost/127.0.0.1/-dns/-ip）
//	client-<id>.pem/.key 副端 mTLS 客户端证书
//
// 子命令：
//
//	ca init    -dir certs [-org YuDuan] [-dns h1,d2] [-ip 10.0.0.5]   建根 CA + 签服务器证书
//	ca issue-server -dir certs [-dns ...] [-ip ...]                   轮换服务器证书（1 年有效）
//	ca issue-client -dir certs -cn <设备ID> [-out client-x]           签副端 mTLS 客户端证书
//	ca pin     -cert certs/cert.pem                                   输出 SPKI SHA-256（YUDUAN_TLS_PIN）
//	ca check   -dir certs                                             到期检查（<30 天退出码 1，供 cron 告警）
//
// 副端接入：分发 ca.pem 后
//   - 严格链校验：YUDUAN_TLS_CAFILE=/path/ca.pem
//   - 公钥固定（推荐，防 CAfile 泄露面）：YUDUAN_TLS_PIN=$(ca pin -cert certs/cert.pem)
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"yuduan/internal/tlsutil"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "init":
		cmdInit(os.Args[2:])
	case "issue-server":
		cmdIssueServer(os.Args[2:])
	case "issue-client":
		cmdIssueClient(os.Args[2:])
	case "pin":
		cmdPin(os.Args[2:])
	case "check":
		cmdCheck(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "用法: ca <init|issue-server|issue-client|pin|check> [参数]（-h 看各子命令）")
	os.Exit(2)
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	return fs
}

func cmdInit(args []string) {
	fs := newFlagSet("init")
	dir := fs.String("dir", "certs", "证书目录")
	org := fs.String("org", "YuDuan", "组织名（写入 CA Subject）")
	dns := fs.String("dns", "", "服务器证书附加 DNS SAN（逗号分隔）")
	ips := fs.String("ip", "", "服务器证书附加 IP SAN（逗号分隔）")
	_ = fs.Parse(args)

	p := tlsutil.CAPaths{Dir: *dir}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		fatal(err)
	}
	if err := tlsutil.GenerateRootCA(p.CACert(), p.CAKey(), *org); err != nil {
		fatal(fmt.Errorf("生成根 CA: %w", err))
	}
	fmt.Printf("根 CA: %s（%s 离线保管！仅签发用）\n", p.CACert(), p.CAKey())
	if err := tlsutil.IssueServerCert(p.CACert(), p.CAKey(), p.Server(), p.ServerKey(),
		splitDNS(*dns), splitIPs(*ips)); err != nil {
		fatal(fmt.Errorf("签发服务器证书: %w", err))
	}
	_ = tlsutil.WriteServerChain(p.Server(), p.CACert(), p.Dir+"/chain.pem")
	printServerInfo(p)
}

func cmdIssueServer(args []string) {
	fs := newFlagSet("issue-server")
	dir := fs.String("dir", "certs", "证书目录")
	dns := fs.String("dns", "", "附加 DNS SAN")
	ips := fs.String("ip", "", "附加 IP SAN")
	_ = fs.Parse(args)
	p := tlsutil.CAPaths{Dir: *dir}
	if err := tlsutil.IssueServerCert(p.CACert(), p.CAKey(), p.Server(), p.ServerKey(),
		splitDNS(*dns), splitIPs(*ips)); err != nil {
		fatal(err)
	}
	_ = tlsutil.WriteServerChain(p.Server(), p.CACert(), p.Dir+"/chain.pem")
	printServerInfo(p)
}

func cmdIssueClient(args []string) {
	fs := newFlagSet("issue-client")
	dir := fs.String("dir", "certs", "证书目录")
	cn := fs.String("cn", "", "设备 ID（写入 CN，供中枢审计对账）")
	out := fs.String("out", "", "输出前缀（默认 client-<cn>）")
	rsaMode := fs.Bool("rsa", false, "签发 RSA 私钥（PKCS#8 PEM）——主端 native-tls 客户端证书需要（macOS 无法导入 SEC1 EC 私钥）")
	_ = fs.Parse(args)
	if *cn == "" {
		fatal(fmt.Errorf("缺少 -cn <设备ID>"))
	}
	p := tlsutil.CAPaths{Dir: *dir}
	prefix := *out
	if prefix == "" {
		prefix = *dir + "/client-" + *cn
	}
	if *rsaMode {
		if err := tlsutil.IssueClientCertRSA(p.CACert(), p.CAKey(), prefix+".pem", prefix+".key", *cn); err != nil {
			fatal(err)
		}
		fmt.Printf("客户端证书(RSA/PKCS#8): %s + %s（主端配 YUDUAN_CLIENT_CERT=%s YUDUAN_CLIENT_KEY=%s）\n",
			prefix+".pem", prefix+".key", prefix+".pem", prefix+".key")
		return
	}
	if err := tlsutil.IssueClientCert(p.CACert(), p.CAKey(), prefix+".pem", prefix+".key", *cn); err != nil {
		fatal(err)
	}
	fmt.Printf("客户端证书: %s + %s（副端配 YUDUAN_CLIENT_CERT=%s YUDUAN_CLIENT_KEY=%s）\n",
		prefix+".pem", prefix+".key", prefix+".pem", prefix+".key")
}

func cmdPin(args []string) {
	fs := newFlagSet("pin")
	cert := fs.String("cert", "certs/cert.pem", "证书路径")
	_ = fs.Parse(args)
	pin, err := tlsutil.SpkiPinHex(*cert)
	if err != nil {
		fatal(err)
	}
	fmt.Println(pin)
}

func cmdCheck(args []string) {
	fs := newFlagSet("check")
	dir := fs.String("dir", "certs", "证书目录")
	_ = fs.Parse(args)
	p := tlsutil.CAPaths{Dir: *dir}
	bad := false
	for _, f := range []string{p.CACert(), p.Server()} {
		na, err := tlsutil.LoadCertNotAfter(f)
		if err != nil {
			fmt.Printf("!! %s 读取失败: %v\n", f, err)
			bad = true
			continue
		}
		days := int(time.Until(na).Hours() / 24)
		mark := "OK"
		if days < 30 {
			mark = "!! 即将到期"
			bad = true
		}
		fmt.Printf("%-16s 到期 %s（剩 %d 天）%s\n", f, na.Format("2006-01-02"), days, mark)
	}
	if bad {
		os.Exit(1)
	}
}

func printServerInfo(p tlsutil.CAPaths) {
	pin, err := tlsutil.SpkiPinHex(p.Server())
	if err != nil {
		fatal(err)
	}
	na, _ := tlsutil.LoadCertNotAfter(p.Server())
	fmt.Printf("服务器证书: %s + %s（到期 %s）\n", p.Server(), p.ServerKey(), na.Format("2006-01-02"))
	fmt.Printf("完整链文件: %s/chain.pem（中枢 YUDUAN_TLS_CERT 指向它，含根锚供 pin 模式校验）\n", p.Dir)
	fmt.Printf("副端 YUDUAN_TLS_PIN=%s\n", pin)
	fmt.Printf("副端（链式校验）: YUDUAN_TLS_CAFILE=%s\n", p.CACert())
}

func splitDNS(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, d := range strings.Split(s, ",") {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	return out
}

func splitIPs(s string) []net.IP {
	var out []net.IP
	for _, ip := range splitDNS(s) {
		if v := net.ParseIP(ip); v != nil {
			out = append(out, v)
		}
	}
	return out
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "错误:", err)
	os.Exit(1)
}
