package main

// wave5a.go —— 波次 5a 副端侧实现（W5-1 合规基线采集 / W5-2 违规软件卸载 / W5-5 补丁修复）。
//
// 设计纪律（与 wave5b 同构）：
//  1. 诚实回告：平台不支持或执行失败的采集/管控项一律回告 unknown/failed 并附原因，严禁伪造。
//  2. 执行层与回执层分离：卸载/补丁默认 dry-run（YUDUAN_W5A_UNINSTALL=1 才真实卸载），
//     避免不可逆破坏；补丁真实安装依赖分发管线（波次 3 副端），本文件仅做计划回告。
//  3. 纯标准库、无第三方依赖；系统操作仅限平台原生工具。
//
// 注：sw_uninstall 同时承载 W3-3（差异升级前置卸载）与 W5-2（黑名单卸载）两类语义，
// 二者 action 同名同义，统一在此处理，避免重复注册。

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"yuduan/internal/collect"
	"yuduan/internal/proto"
	"yuduan/internal/ws"
)

func init() { registerWaveAction(wave5aCommand) }

// w5aUninstallEnabled 是否允许真实卸载（默认 false，仅演练）。
func w5aUninstallEnabled() bool { return os.Getenv("YUDUAN_W5A_UNINSTALL") == "1" }

// wave5aCommand 接管波次 5a 指令；返回 true=已接管（必须自行 sendResult 回执）。
func wave5aCommand(conn *ws.Conn, c proto.CommandPayload) bool {
	switch c.Action {
	case proto.ActionComplianceCollect:
		// 采集四/五类合规项并以 JSON 回传。
		items := collect.Compliance()
		rep := proto.ComplianceReportPayload{
			Platform: runtime.GOOS,
			Items:    items,
		}
		out, _ := json.Marshal(rep)
		log.Printf("[agent] 合规采集回执 platform=%s 项=%d", runtime.GOOS, len(items))
		sendResult(conn, proto.ResultPayload{TaskID: c.TaskID, State: "success", ExitCode: 0, OutputLog: string(out)})
		return true

	case proto.ActionSwUninstall:
		// 同一 action 承载两类语义，载荷字段不同，需兼容：
		//   - W3-3 差异升级前置卸载：SwDistDetail（package 字段）
		//   - W5-2 违规软件黑名单卸载：Wave5aCommand（software 字段）
		target, dryRun := "", false
		var sd proto.SwDistDetail
		if err := json.Unmarshal([]byte(c.Command), &sd); err == nil && sd.Package != "" {
			target, dryRun = sd.Package, false
		} else {
			var p proto.Wave5aCommand
			if err := json.Unmarshal([]byte(c.Command), &p); err != nil {
				sendResult(conn, proto.ResultPayload{TaskID: c.TaskID, State: "failed",
					ExitCode: -1, OutputLog: "卸载载荷解析失败: " + err.Error()})
				return true
			}
			target, dryRun = p.Software, p.DryRun
		}
		res := w5aUninstall(target, dryRun || !w5aUninstallEnabled())
		out, _ := json.Marshal(res)
		log.Printf("[agent] 卸载回执 software=%s dry_run=%v state=%s", target, res.DryRun, res.State)
		st := "success"
		if res.State == "failed" {
			st = "failed"
		}
		sendResult(conn, proto.ResultPayload{TaskID: c.TaskID, State: st, ExitCode: 0, OutputLog: string(out)})
		return true

	case proto.ActionPatchApply:
		var p proto.Wave5aCommand
		if err := json.Unmarshal([]byte(c.Command), &p); err != nil {
			sendResult(conn, proto.ResultPayload{TaskID: c.TaskID, State: "failed",
				ExitCode: -1, OutputLog: "补丁载荷解析失败: " + err.Error()})
			return true
		}
		// 补丁真实安装依赖分发管线（波次 3 副端），此处仅做诚实的「计划/演练」回告。
		msg := fmt.Sprintf("patch_plan software=%s target_version=%s repo_item=%s dry_run=true (实际安装待分发管线)",
			p.Software, p.TargetVer, p.RepoItemID)
		log.Printf("[agent] 补丁回执 %s", msg)
		sendResult(conn, proto.ResultPayload{TaskID: c.TaskID, State: "success", ExitCode: 0, OutputLog: msg})
		return true
	}
	return false
}

// w5aUninstallResult 卸载回执（与中枢侧期望的 JSON 结构对齐）。
type w5aUninstallResult struct {
	Software string `json:"software"`
	Platform string `json:"platform"`
	DryRun   bool   `json:"dry_run"`
	State    string `json:"state"` // success/failed/unsupported
	Detail   string `json:"detail"`
}

// w5aUninstall 按平台尽力卸载指定软件；dryRun=true 时仅回告计划不改动系统。
func w5aUninstall(software string, dryRun bool) w5aUninstallResult {
	res := w5aUninstallResult{Software: software, Platform: runtime.GOOS, DryRun: dryRun, State: "failed"}
	if strings.TrimSpace(software) == "" {
		res.Detail = "软件名为空"
		return res
	}
	switch runtime.GOOS {
	case "windows":
		unin, ok := w5aFindUninstallString(software)
		if !ok {
			res.State = "unsupported"
			res.Detail = "未在注册表 Uninstall 找到匹配项"
			return res
		}
		if dryRun {
			res.State = "success"
			res.Detail = "演练：将执行 " + unin
			return res
		}
		if out, err := exec.Command("cmd", "/C", unin).CombinedOutput(); err != nil {
			res.Detail = "执行失败: " + err.Error() + " | " + string(out)
			return res
		}
		res.State = "success"
		res.Detail = "已执行卸载：" + unin
		return res

	case "darwin":
		app := w5aFindApp(software)
		if app == "" {
			res.State = "unsupported"
			res.Detail = "未在 /Applications 找到匹配 .app"
			return res
		}
		if dryRun {
			res.State = "success"
			res.Detail = "演练：将删除 " + app
			return res
		}
		if err := os.RemoveAll(app); err != nil {
			res.Detail = "删除失败: " + err.Error()
			return res
		}
		res.State = "success"
		res.Detail = "已删除：" + app
		return res

	case "linux":
		pkg := w5aFindDebRpm(software)
		if pkg == nil {
			res.State = "unsupported"
			res.Detail = "未找到 dpkg/rpm 包"
			return res
		}
		if dryRun {
			res.State = "success"
			res.Detail = "演练：将执行 " + pkg.cmd
			return res
		}
		if out, err := exec.Command(pkg.mgr, pkg.rm, pkg.name).CombinedOutput(); err != nil {
			res.Detail = "执行失败: " + err.Error() + " | " + string(out)
			return res
		}
		res.State = "success"
		res.Detail = "已卸载：" + pkg.name
		return res
	}
	res.State = "unsupported"
	res.Detail = "平台不支持"
	return res
}

// w5aFindUninstallString 在 Windows 三根 Uninstall 键中按显示名模糊匹配，返回 UninstallString。
func w5aFindUninstallString(software string) (string, bool) {
	keys := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
	}
	needle := strings.ToLower(software)
	for _, base := range keys {
		out, err := exec.Command("reg", "query", `HKLM\`+base, "/s").CombinedOutput()
		if err != nil {
			continue
		}
		var curKey, dispName, uninStr string
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "HKEY") {
				curKey = line
				dispName, uninStr = "", ""
				continue
			}
			if strings.HasPrefix(line, "DisplayName") {
				dispName = strings.TrimSpace(strings.SplitN(line, "REG_SZ", 2)[1])
			}
			if strings.HasPrefix(line, "UninstallString") {
				parts := strings.SplitN(line, "REG_SZ", 2)
				if len(parts) == 2 {
					uninStr = strings.TrimSpace(parts[1])
				}
			}
		}
		if strings.Contains(strings.ToLower(dispName), needle) && uninStr != "" {
			return uninStr, true
		}
		_ = curKey
	}
	return "", false
}

// w5aFindApp 在 /Applications 中按名称（不区分大小写）查找 .app 完整路径。
func w5aFindApp(software string) string {
	entries, err := os.ReadDir("/Applications")
	if err != nil {
		return ""
	}
	needle := strings.ToLower(software)
	for _, e := range entries {
		n := strings.ToLower(e.Name())
		if !strings.HasSuffix(n, ".app") {
			continue
		}
		base := strings.TrimSuffix(n, ".app")
		if strings.Contains(base, needle) {
			return "/Applications/" + e.Name()
		}
	}
	return ""
}

type w5aPkgRef struct {
	mgr, name, rm, cmd string
}

// w5aFindDebRpm 在 Debian/RedHat 系查找已安装包（按名称包含匹配）。
func w5aFindDebRpm(software string) *w5aPkgRef {
	needle := strings.ToLower(software)
	// dpkg 优先
	if out, err := exec.Command("dpkg-query", "-W", "-f=${Package} ${Version}\n").CombinedOutput(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) >= 1 && strings.Contains(strings.ToLower(f[0]), needle) {
				return &w5aPkgRef{mgr: "dpkg", name: f[0], rm: "-r", cmd: "dpkg -r " + f[0]}
			}
		}
	}
	if out, err := exec.Command("rpm", "-qa", "--qf", "%{NAME}\n").CombinedOutput(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(strings.ToLower(line), needle) {
				return &w5aPkgRef{mgr: "rpm", name: line, rm: "-e", cmd: "rpm -e " + line}
			}
		}
	}
	return nil
}
