// yuduan-acme —— 御端 P1「公网可达最小闭环」的 ACME 证书签发命令行工具。
//
// 零第三方依赖（纯 Go 标准库），可在客户自有基础设施直接运行，无需 certbot。
//
// 子命令：
//
//	issue  -domain <域名> -email <邮箱> [-staging] [-dir certs] [-listen :80] [-api <dir-url>]
//
// 成功后在 -dir 下写出：
//
//	acme.fullchain.pem  acme.key  acme.pin
//
// 并打印 SPKI PIN（供部署向导捕获，写入副端 YUDUAN_TLS_PIN）。
//
// 部署向导约定调用：
//
//	yuduan-acme issue --domain example.com --email admin@example.com
//	（预发验证追加 --staging；自定义监听/目录用 --listen / --dir）
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"yuduan/internal/acme"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "issue":
		cmdIssue(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "用法: yuduan-acme <issue> [参数]")
	fmt.Fprintln(os.Stderr, "  issue  -domain <域名> -email <邮箱> [-staging] [-dir certs] [-listen :80] [-api <dir-url>]")
	os.Exit(2)
}

func cmdIssue(args []string) {
	// v0.4.27 F-06：把标准 logger 指到 stdout。
	// 部署向导（register-task.ps1:707 / install.sh:140）用 2>&1 捕获 ACME 输出，
	// 而向导全局 $ErrorActionPreference="Stop"、且 -Public 段不在 Continue 作用域内。
	// Windows PowerShell 5.1 下原生命令写 stderr 会被包成 ErrorRecord 并触发终止错误，
	// 进度日志走 stderr 会直接打断向导；改走 stdout 后 2>&1 仍能完整捕获、且不产生 ErrorRecord。
	// 仅影响 CLI 进程的 logger 目标，不改 acme 库行为、不改 Issue 签名。
	log.SetOutput(os.Stdout)

	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	domain := fs.String("domain", "", "要签发的域名（必填）")
	email := fs.String("email", "", "注册邮箱（必填）")
	staging := fs.Bool("staging", false, "使用 Let's Encrypt 预发环境（测试用，不被浏览器信任）")
	dir := fs.String("dir", "certs", "证书输出目录")
	listen := fs.String("listen", ":80", "HTTP-01 校验临时监听地址（需公网 :80 可达）")
	api := fs.String("api", "", "显式指定 ACME Directory URL（覆盖 -staging）")
	_ = fs.Parse(args)

	if *domain == "" || *email == "" {
		fmt.Fprintln(os.Stderr, "错误: --domain 与 --email 均为必填")
		os.Exit(2)
	}

	// v0.4.28 O-01：起始行去重。domain / dirURL / staging / HTTP-01 监听 / 输出目录
	// 统一由 acme.Issue 的第一条 [acme] 阶段日志输出（CLI 已把标准 logger 指到 stdout），
	// 不再用 fmt.Printf 重复打印一行无时间戳的同名日志；dirURL 推导也只保留在库内一处。
	// 故障定位能力不变：「1/8 拉取 ACME Directory」之前仍会打印目标与形态。

	res, err := acme.Issue(acme.Options{
		Domain:       *domain,
		Email:        *email,
		Staging:      *staging,
		CertsDir:     *dir,
		HTTPListen:   *listen,
		DirectoryURL: *api,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}

	pin := ""
	if b, err := os.ReadFile(res.PinPath); err == nil {
		pin = strings.TrimSpace(string(b))
	}

	fmt.Println("ACME 证书签发成功:")
	fmt.Printf("  fullchain : %s\n", res.FullchainPath)
	fmt.Printf("  key       : %s\n", res.KeyPath)
	fmt.Printf("  pin       : %s\n", res.PinPath)
	fmt.Printf("  SPKI PIN  : %s\n", pin)
	fmt.Println()
	fmt.Printf("中枢加载: YUDUAN_TLS_CERT=%s YUDUAN_TLS_KEY=%s\n", res.FullchainPath, res.KeyPath)
	fmt.Printf("副端固定: YUDUAN_TLS_PIN=%s\n", pin)
}
