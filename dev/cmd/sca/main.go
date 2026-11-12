// 御端 SCA（软件成分分析）扫描器 —— 供应链安全基线核查。
//
// 设计约束：御端副端（Rust）/ 中枢（Go）均刻意采用「零第三方依赖、仅标准库」，
// 以最小化供应链攻击面（铁律：离线构建、不拉取 crates.io / go modules）。
// 因此本 SCA 的核心价值是：
//   1) 枚举全部依赖成分（go.mod / Cargo.toml），固化「零第三方依赖」基线；
//   2) 清点 Rust 源中的 unsafe / extern(FFI) 块，强制安全评审；
//   3) 扫描硬编码凭据/密钥字面量，提示泄漏风险；
//   4) 产出 SBOM（JSON）+ 人类可读风险报告（Markdown）。
//
// 用法：go run ./cmd/sca -root <项目根> [-json out.json] [-md out.md]
// 退出码：0 = PASS（可接受基线）；1 = 发现需处理的高危项（如意外第三方依赖）。

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Component struct {
	Ecosystem string `json:"ecosystem"` // go / rust / std
	Name      string `json:"name"`
	Version   string `json:"version"`
	Direct    bool   `json:"direct"`
}

type Finding struct {
	Severity string `json:"severity"` // info / warn
	Category string `json:"category"` // unsafe / ffi / credential / thirdparty
	File     string `json:"file"`
	Line     int    `json:"line"`
	Detail   string `json:"detail"`
}

type Report struct {
	GeneratedAt string      `json:"generated_at"`
	Root        string      `json:"root"`
	Components  []Component `json:"components"`
	Findings    []Finding   `json:"findings"`
	Verdict     string      `json:"verdict"`
}

// 跳过目录
var skipDirs = map[string]bool{
	".git": true, "target": true, "node_modules": true, "vendor": true,
	"data": true, "bin": true, ".workbuddy": true,
}

var (
	reGoRequire   = regexp.MustCompile(`^\s*([\w\.\-/]+)\s+v([\w\.\-\+]+)(\s+//\s*indirect)?\s*$`)
	reCargoDep    = regexp.MustCompile(`^([\w\-\_]+)\s*=\s*(.+)$`)
	reCredLiteral = regexp.MustCompile(`(?i)(password|secret|api[_-]?key|private[_-]?key|token)\s*[:=]\s*["']([^"'<]{3,})["']`)
	reUseExt      = regexp.MustCompile(`^\s*use\s+([a-zA-Z_][\w:]*)`)
	reModDecl     = regexp.MustCompile(`^mod\s+([a-zA-Z_][\w]*)\b`)
)

func main() {
	root := flag.String("root", ".", "项目根目录")
	jsonOut := flag.String("json", "sca-report.json", "JSON 报告输出路径")
	mdOut := flag.String("md", "sca-report.md", "Markdown 报告输出路径")
	flag.Parse()

	r := &Report{Root: *root, GeneratedAt: time.Now().UTC().Format(time.RFC3339)}

	// 1) 依赖成分枚举（go.mod / Cargo.toml）
	thirdParty := scanModules(*root, r)
	// 2) Rust 源审计（unsafe / FFI / 第三方 use）
	scanRustSources(*root, r)
	// 3) 硬编码凭据扫描
	scanCredentials(*root, r)

	if thirdParty == 0 {
		r.Components = append(r.Components, Component{Ecosystem: "std", Name: "go-stdlib", Version: goVersion(*root), Direct: true})
		r.Components = append(r.Components, Component{Ecosystem: "std", Name: "rust-stdlib", Version: "edition2021", Direct: true})
	}

	// 判定：任何第三方依赖 = 高危（违反零依赖基线）；其余为 info/warn。
	highRisk := thirdParty > 0
	if highRisk {
		r.Verdict = fmt.Sprintf("FAIL: 发现 %d 个第三方依赖，违反零依赖供应链基线", thirdParty)
	} else if countWarn(r) > 0 {
		r.Verdict = fmt.Sprintf("PASS(with notes): 零第三方依赖；%d 项需安全评审（unsafe/ffi/credential）", countWarn(r))
	} else {
		r.Verdict = "PASS: 零第三方依赖，无额外风险项"
	}

	writeJSON(*jsonOut, r)
	writeMD(*mdOut, r)
	fmt.Printf("[sca] 组件 %d 项，发现 %d 项，判定：%s\n", len(r.Components), len(r.Findings), r.Verdict)
	if highRisk {
		os.Exit(1)
	}
}

func countWarn(r *Report) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == "warn" {
			n++
		}
	}
	return n
}

// scanModules 解析 go.mod / Cargo.toml，返回第三方依赖数量。
func scanModules(root string, r *Report) int {
	third := 0
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() && skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Base(path) {
		case "go.mod":
			n := parseGoMod(path, r)
			third += n
		case "Cargo.toml":
			n := parseCargoToml(path, r)
			third += n
		}
		return nil
	})
	return third
}

func parseGoMod(path string, r *Report) int {
	data, _ := os.ReadFile(path)
	lines := strings.Split(string(data), "\n")
	inRequire := false
	third := 0
	for _, ln := range lines {
		s := strings.TrimSpace(ln)
		if strings.HasPrefix(s, "require (") {
			inRequire = true
			continue
		}
		if inRequire {
			if s == ")" {
				inRequire = false
				continue
			}
			if m := reGoRequire.FindStringSubmatch(s); m != nil {
				indirect := strings.Contains(s, "indirect")
				r.Components = append(r.Components, Component{
					Ecosystem: "go", Name: m[1], Version: m[2], Direct: !indirect,
				})
				third++
			}
			continue
		}
		// 单行 require module v1.2.3
		if strings.HasPrefix(s, "require ") {
			rest := strings.TrimPrefix(s, "require ")
			if m := reGoRequire.FindStringSubmatch(rest); m != nil {
				r.Components = append(r.Components, Component{
					Ecosystem: "go", Name: m[1], Version: m[2], Direct: !strings.Contains(rest, "indirect"),
				})
				third++
			}
		}
	}
	return third
}

func parseCargoToml(path string, r *Report) int {
	data, _ := os.ReadFile(path)
	lines := strings.Split(string(data), "\n")
	inDeps := false
	third := 0
	for _, ln := range lines {
		s := strings.TrimSpace(ln)
		if s == "[dependencies]" {
			inDeps = true
			continue
		}
		if strings.HasPrefix(s, "[") && s != "[dependencies]" {
			inDeps = false
			continue
		}
		if inDeps && s != "" && !strings.HasPrefix(s, "#") {
			if m := reCargoDep.FindStringSubmatch(s); m != nil {
				name := m[1]
				ver := strings.Trim(m[2], `"{} `)
				// 仅记录显式写出版本/来源的（空依赖块不会产生条目）
				if ver != "" && !strings.HasPrefix(ver, "#") {
					r.Components = append(r.Components, Component{
						Ecosystem: "rust", Name: name, Version: ver, Direct: true,
					})
					third++
				}
			}
		}
	}
	return third
}

func goVersion(root string) string {
	data, _ := os.ReadFile(filepath.Join(root, "dev", "go.mod"))
	for _, ln := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "go ") {
			return strings.TrimSpace(strings.TrimPrefix(ln, "go "))
		}
	}
	return "unknown"
}

// scanRustSources 清点 Rust 源中的 unsafe / extern(FFI) / 第三方 use。
func scanRustSources(root string, r *Report) {
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() && skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".rs") {
			return nil
		}
		data, _ := os.ReadFile(path)
		lines := strings.Split(string(data), "\n")
		// 收集本文件内声明的本地模块（如 mod win32 { ... }），避免误判为第三方 crate。
		localMods := map[string]bool{}
		for _, ln := range lines {
			if m := reModDecl.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
				localMods[m[1]] = true
			}
		}
		for i, ln := range lines {
			line := i + 1
			if strings.Contains(ln, "unsafe") {
				r.Findings = append(r.Findings, Finding{
					Severity: "warn", Category: "unsafe", File: rel(root, path), Line: line,
					Detail: strings.TrimSpace(ln),
				})
			}
			if strings.Contains(ln, `extern "C"`) || strings.Contains(ln, "extern \"C\"") {
				r.Findings = append(r.Findings, Finding{
					Severity: "warn", Category: "ffi", File: rel(root, path), Line: line,
					Detail: "FFI 外部函数接口（需评审：参数封送/生命周期）",
				})
			}
			if m := reUseExt.FindStringSubmatch(ln); m != nil {
				top := strings.SplitN(m[1], "::", 2)[0]
				if isLocalPath(top, localMods) {
					continue
				}
				r.Findings = append(r.Findings, Finding{
					Severity: "warn", Category: "thirdparty", File: rel(root, path), Line: line,
					Detail: "第三方 crate 引用: " + m[1],
				})
			}
		}
		return nil
	})
}

// 路径关键字与本地模块名不算第三方依赖。
func isLocalPath(top string, localMods map[string]bool) bool {
	switch top {
	case "std", "core", "alloc", "crate", "self", "super":
		return true
	}
	return localMods[top]
}

// scanCredentials 扫描硬编码凭据/密钥字面量（非测试文件）。
func scanCredentials(root string, r *Report) {
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() && skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".rs") {
			return nil
		}
		// 测试/示例文件内的种子凭据不计入高危，仅标注 info
		isTest := strings.HasSuffix(path, "_test.go") || strings.Contains(path, "/test/")
		data, _ := os.ReadFile(path)
		for i, ln := range strings.Split(string(data), "\n") {
			if m := reCredLiteral.FindStringSubmatch(ln); m != nil {
				val := m[2]
				// 过滤明显的占位/变量（如 %s、env 取值）
				if strings.Contains(val, "%") || strings.Contains(val, "<") || len(val) < 3 {
					continue
				}
				r.Findings = append(r.Findings, Finding{
					Severity: sevFor(isTest, val),
					Category: "credential", File: rel(root, path), Line: i + 1,
					Detail: fmt.Sprintf("%s = %q%s", m[1], val, flagTest(isTest)),
				})
			}
		}
		return nil
	})
}

func sevFor(isTest bool, val string) string {
	if isTest {
		return "info"
	}
	// 形如 admin123/operator123 的默认口令 = 高危
	return "warn"
}

func flagTest(isTest bool) string {
	if isTest {
		return " (测试文件)"
	}
	return ""
}

func rel(root, path string) string {
	r, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return r
}

func writeJSON(path string, r *Report) {
	b, _ := json.MarshalIndent(r, "", "  ")
	_ = os.WriteFile(path, b, 0o644)
}

func writeMD(path string, r *Report) {
	var b strings.Builder
	fmt.Fprintf(&b, "# 御端 SCA 软件成分分析报告\n\n")
	fmt.Fprintf(&b, "- 生成时间：%s\n", r.GeneratedAt)
	fmt.Fprintf(&b, "- 扫描根：%s\n", r.Root)
	fmt.Fprintf(&b, "- 判定：**%s**\n\n", r.Verdict)

	fmt.Fprintf(&b, "## 1. 依赖成分（SBOM）\n\n")
	fmt.Fprintf(&b, "| 生态 | 组件 | 版本 | 直接依赖 |\n|---|---|---|---|\n")
	for _, c := range r.Components {
		fmt.Fprintf(&b, "| %s | %s | %s | %v |\n", c.Ecosystem, c.Name, c.Version, c.Direct)
	}
	if len(r.Components) == 0 {
		fmt.Fprintf(&b, "| - | （无依赖） | - | - |\n")
	}

	fmt.Fprintf(&b, "\n## 2. 安全发现\n\n")
	fmt.Fprintf(&b, "| 级别 | 类别 | 文件 | 行 | 说明 |\n|---|---|---|---|---|\n")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %s |\n", f.Severity, f.Category, f.File, f.Line, f.Detail)
	}
	if len(r.Findings) == 0 {
		fmt.Fprintf(&b, "| - | （无） | - | - | - |\n")
	}

	fmt.Fprintf(&b, "\n## 3. 结论\n\n")
	if strings.HasPrefix(r.Verdict, "FAIL") {
		fmt.Fprintf(&b, "发现第三方依赖，违反「零依赖、仅标准库」的供应链安全基线，需在合并前清理。\n")
	} else {
		fmt.Fprintf(&b, "供应链攻击面收敛于语言标准库（Go stdlib / Rust stdlib）。\n")
		fmt.Fprintf(&b, "请对标注的 `unsafe` / `extern \"C\"`(FFI) / 硬编码凭据逐项进行安全评审；\n")
		fmt.Fprintf(&b, "生产环境应由 KMS/配置下发密钥，禁止源码硬编码。\n")
	}
	_ = os.WriteFile(path, []byte(b.String()), 0o644)
}
