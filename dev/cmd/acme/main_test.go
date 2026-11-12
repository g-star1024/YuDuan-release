package main

// v0.4.28 真机实测反馈回归：
//   - O-01：CLI 不得再重复打印「[acme] 开始签发」起始行（真机观察到
//     一行无时间戳 fmt + 一行带时间戳 logger），该行统一由 internal/acme.Issue 输出；
//   - F-11：成功提示必须是「中枢加载」，不得退回「枢组加载」错字；
//   - 上轮 F-06 的 stdout 约束必须保留，避免 PowerShell 5.1 EAP=Stop 打断 -Public 向导。
//
// 这里用源码文本断言而非运行 cmdIssue：cmdIssue 会 os.Exit，且成功路径需要真实
// ACME 交互，无法在离线单测里走通；源码断言足以阻止这两类文案/日志回归。

import (
	"os"
	"strings"
	"testing"
)

func TestCLIStartLogIsNotDuplicated(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("读取 main.go 失败: %v", err)
	}
	src := string(b)

	if strings.Contains(src, `fmt.Printf("[acme] 开始签发`) ||
		strings.Contains(src, `fmt.Println("[acme] 开始签发`) {
		t.Fatal("CLI 仍重复打印 [acme] 开始签发 起始行（O-01 回归）；应仅由 internal/acme.Issue 输出")
	}
	if strings.Count(src, "[acme] 开始签发") != 0 {
		t.Fatal("CLI 源码不应再出现 [acme] 开始签发 字样（O-01 回归）")
	}
	if !strings.Contains(src, "log.SetOutput(os.Stdout)") {
		t.Fatal("CLI 必须把标准 logger 指到 stdout，规避 PowerShell 5.1 EAP=Stop")
	}
}

func TestCLISuccessHintUsesCorrectWord(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("读取 main.go 失败: %v", err)
	}
	src := string(b)

	if strings.Contains(src, "枢组加载") {
		t.Fatal("成功提示仍含错字「枢组加载」（F-11 回归）")
	}
	if !strings.Contains(src, "中枢加载: YUDUAN_TLS_CERT") {
		t.Fatal("成功提示应为「中枢加载」，与「副端固定」对齐（F-11）")
	}
}
