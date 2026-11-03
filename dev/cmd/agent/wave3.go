// wave3.go —— 波次 3 副端侧实现（W3-1 静默参数模板落地 / W3-2 分发安装 / W3-3 差异升级安装）。
//
// 设计纪律（与 wave5a/wave5b 同构）：
//  1. 诚实回告：下载失败 / 校验失败 / 平台不支持 / 执行失败一律回告明确原因，严禁伪造成功。
//  2. 执行层与回执层分离：安装动作按平台尽力执行并回告真实结果；安装包默认只做
//     SHA-256 校验（M5 加固，若中枢提供了 Sha256），校验不一致拒绝安装。
//  3. 可选分发（optional）：首次收到 sw_dist 且未确认时回告 confirm_required（非终态），
//     中枢挂起该记录；用户确认后中枢以 Confirmed=true 重发，副端此时才真正安装。
//  4. 纯标准库、零第三方依赖；安装仅用平台原生工具（msiexec / installer / dpkg / rpm）。
//
// 注：sw_uninstall 由 wave5a.go 统一处理（W3-3 卸载旧版与 W5-2 黑名单卸载同名同义），
// 本文件不重复注册，避免 dispatchWaveAction 重复接管。

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"yuduan/internal/proto"
	"yuduan/internal/ws"
)

func init() { registerWaveAction(wave3Command) }

// ---- 分发相关环境开关 ----

// w3InstallEnabled 是否允许真实安装（默认 false，仅下载+校验+演练，避免误装）。
// 部署侧需显式置 1 才真正执行安装（合规受控，类比 W5a 卸载开关）。
func w3InstallEnabled() bool { return os.Getenv("YUDUAN_W3_INSTALL") == "1" }

// w3MaxPackageBytes 单安装包上限（512MB，与分发仓储上限一致）。
const w3MaxPackageBytes = 512 << 20

// wave3Command 接管波次 3 指令；返回 true=已接管（必须自行 sendResult 回执）。
func wave3Command(conn *ws.Conn, c proto.CommandPayload) bool {
	switch c.Action {
	case proto.ActionSwDist:
		var d proto.SwDistDetail
		if err := json.Unmarshal([]byte(c.Command), &d); err != nil {
			sendResult(conn, proto.ResultPayload{TaskID: c.TaskID, State: "failed",
				ExitCode: -1, OutputLog: "分发载荷解析失败: " + err.Error()})
			return true
		}
		res := w3Install(c, d)
		out, _ := json.Marshal(res)
		log.Printf("[agent] 分发回执 pkg=%s mode=%s confirmed=%v state=%s detail=%s",
			c.PkgName, d.Mode, d.Confirmed, res.State, firstN(res.Detail, 90))
		sendResult(conn, proto.ResultPayload{TaskID: c.TaskID, State: res.State, ExitCode: res.ExitCode, OutputLog: string(out)})
		return true
	}
	return false
}

// ---- 分发结果（与中枢 w3DispatchRecord 期望对齐） ----

type w3InstallResult struct {
	State    string `json:"state"` // success/failed/confirm_required/skipped
	ExitCode int    `json:"exit_code"`
	Detail   string `json:"detail,omitempty"`
	DryRun   bool   `json:"dry_run"`
	Pkg      string `json:"pkg,omitempty"`
	Platform string `json:"platform"`
}

// w3Install 执行一次分发安装。
func w3Install(c proto.CommandPayload, d proto.SwDistDetail) w3InstallResult {
	res := w3InstallResult{Platform: runtime.GOOS, ExitCode: -1, State: "failed"}
	if strings.TrimSpace(c.SoftwareURL) == "" && strings.TrimSpace(d.CustomArgs) == "" {
		res.Detail = "缺少安装包地址与自定义命令行"
		return res
	}
	// ---- 可选分发：未确认时挂起（非终态） ----
	if d.Mode == proto.DistModeOptional && !d.Confirmed {
		res.State = proto.ResultConfirmRequired
		res.ExitCode = 0
		res.Detail = "可选分发：等待终端用户确认安装"
		return res
	}
	// ---- 下载安装包（若给了 URL） ----
	local := ""
	if strings.TrimSpace(c.SoftwareURL) != "" {
		dl, err := w3Download(c.SoftwareURL)
		if err != nil {
			res.Detail = "下载安装包失败: " + err.Error()
			return res
		}
		defer os.Remove(dl)
		local = dl
		// ---- M5 加固 / S-8 修复：SHA-256 强制校验（缺省即拒绝）----
		//
		// 此前摘要为「有则校，无则放行」，配合下载侧 InsecureSkipVerify=true（内网自签
		// 证书）构成完整攻击链：内网任一对路径者可以替换安装包，而安装包最终由
		// msiexec / installer / dpkg 以 SYSTEM/root 权限执行——MITM 直接等价 RCE。
		// 摘要来自中枢经 HMAC 签名的指令通道（不可篡改），是与传输无关的完整性依据，
		// 故在 TLS 信任策略完成迁移前，先把「无摘要不许装」这条底线立住。
		if strings.TrimSpace(c.Sha256) == "" {
			res.Detail = "拒绝安装：分发指令缺少 SHA-256 摘要（伪造包防护强制项）；" +
				"仓库包请在软件仓库重新上传以生成摘要，外部地址请在任务里显式提供 sha256"
			os.Remove(local)
			return res
		}
		sum, err := w3Sha256File(local)
		if err != nil || !strings.EqualFold(sum, strings.TrimSpace(c.Sha256)) {
			res.Detail = fmt.Sprintf("SHA-256 校验失败: 期望 %s 实得 %s (%v)", c.Sha256, sum, err)
			os.Remove(local)
			return res
		}
	}
	// ---- 静默安装 ----
	if !w3InstallEnabled() {
		res.State = "success"
		res.ExitCode = 0
		res.DryRun = true
		res.Detail = "演练：安装包已就绪并通过校验，但未开启真实安装（YUDUAN_W3_INSTALL!=1）"
		return res
	}
	args := strings.TrimSpace(d.SilentArgs)
	if args == "" {
		args = strings.TrimSpace(d.CustomArgs)
	}
	if args == "" {
		args = w3DefaultArgs(c.Platform, c.PkgName)
	}
	out, code, err := w3RunInstaller(c.Platform, local, c.PkgName, args)
	if err != nil {
		res.Detail = "安装执行失败: " + err.Error()
		if code != 0 {
			res.ExitCode = code
		}
		return res
	}
	res.State = "success"
	res.ExitCode = code
	res.DryRun = false
	res.Detail = firstN("安装完成: "+out, 400)
	return res
}

// ---- 下载与校验 ----

// w3Download 从中枢 REST 下载安装包到临时文件。
//
// ⚠️ 安全现状（复盘 S-8 遗留项）：此处仍 InsecureSkipVerify=true，历史原因是
// 内网中枢默认自签/自生成证书。v0.4.3 起以「SHA-256 强制校验」堵住 MITM→RCE 的
// 落地路径，但**真正的修复是把这里的 TLS 信任策略收口到私有 CA 或 SPKI pin**
// （与 T-4 主端/副端已经支持的 CAFILE/pin 同口径）。该改动会一次性打断所有自签部署，
// 属需要变更窗口与回滚预案的运维动作，已列入待用户决策，不在夜间私自执行。
func w3Download(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	// 相对路径或仅 host:port → 补协议与中枢地址
	if !u.IsAbs() {
		base := w3HubREST()
		if base == "" {
			return "", fmt.Errorf("无法解析中枢地址（YUDUAN_HUB 未配置）")
		}
		rawURL = strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(rawURL, "/")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // 内网自签证书
	client := &http.Client{Timeout: 10 * time.Minute, Transport: tr}
	resp, err := client.Get(rawURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	tmp, err := os.CreateTemp("", "yuduan-pkg-*")
	if err != nil {
		return "", err
	}
	defer tmp.Close()
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, w3MaxPackageBytes+1))
	if err != nil {
		return "", err
	}
	if n > w3MaxPackageBytes {
		return "", fmt.Errorf("安装包超过上限 %d 字节", w3MaxPackageBytes)
	}
	return tmp.Name(), nil
}

// w3HubREST 从 YUDUAN_HUB 推导中枢 REST 基址（ws://host:port/ws/agent → http://host:port）。
func w3HubREST() string {
	hub := strings.TrimSpace(os.Getenv("YUDUAN_HUB"))
	if hub == "" {
		return ""
	}
	hub = strings.TrimPrefix(hub, "ws://")
	hub = strings.TrimPrefix(hub, "wss://")
	if i := strings.Index(hub, "/"); i >= 0 {
		hub = hub[:i]
	}
	return "http://" + hub
}

func w3Sha256File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ---- 静默安装执行 ----

// w3DefaultArgs 平台默认静默参数（模板未命中时兜底，避免交互式安装挂起）。
func w3DefaultArgs(platform, pkgName string) string {
	switch platform {
	case "windows":
		switch strings.ToLower(filepath.Ext(pkgName)) {
		case ".msi":
			return "/qn /norestart"
		case ".exe":
			return "/VERYSILENT /NORESTART"
		default:
			return "/S"
		}
	case "darwin":
		if strings.HasSuffix(strings.ToLower(pkgName), ".dmg") {
			return "mount-and-copy"
		}
		return "-target /"
	default: // linux
		return ""
	}
}

// w3RunInstaller 按平台执行静默安装。platform 用中枢下发的目标平台（可能跨平台交叉）。
func w3RunInstaller(platform, local, pkgName, args string) (string, int, error) {
	switch platform {
	case "windows":
		ext := strings.ToLower(filepath.Ext(pkgName))
		if ext == ".msi" {
			cmd := exec.Command("msiexec", append([]string{"/i", local}, strings.Fields(args)...)...)
			out, err := cmd.CombinedOutput()
			return string(out), exitCode(err), err
		}
		cmd := exec.Command(local, strings.Fields(args)...)
		out, err := cmd.CombinedOutput()
		return string(out), exitCode(err), err

	case "darwin":
		// dmg：挂载→拷 .app→卸载（尽力而为）；pkg：installer -pkg
		if strings.HasSuffix(strings.ToLower(pkgName), ".dmg") {
			return w3InstallDMG(local, args)
		}
		if strings.HasSuffix(strings.ToLower(pkgName), ".pkg") {
			cmd := exec.Command("installer", append([]string{"-pkg", local, "-target", "/"}, strings.Fields(args)...)...)
			out, err := cmd.CombinedOutput()
			return string(out), exitCode(err), err
		}
		// 普通 app：拷到 /Applications
		cmd := exec.Command("ditto", local, "/Applications/"+filepath.Base(local))
		out, err := cmd.CombinedOutput()
		return string(out), exitCode(err), err

	default: // linux
		if strings.HasSuffix(strings.ToLower(pkgName), ".deb") {
			cmd := exec.Command("dpkg", append([]string{"-i", local}, strings.Fields(args)...)...)
			out, err := cmd.CombinedOutput()
			return string(out), exitCode(err), err
		}
		if strings.HasSuffix(strings.ToLower(pkgName), ".rpm") {
			cmd := exec.Command("rpm", append([]string{"-i", local}, strings.Fields(args)...)...)
			out, err := cmd.CombinedOutput()
			return string(out), exitCode(err), err
		}
		cmd := exec.Command("sh", "-c", local+" "+args)
		out, err := cmd.CombinedOutput()
		return string(out), exitCode(err), err
	}
}

// w3InstallDMG 挂载 dmg、拷贝 .app、卸载（macOS）。
func w3InstallDMG(local, args string) (string, int, error) {
	mnt, err := os.MkdirTemp("", "yuduan-dmg-*")
	if err != nil {
		return "", -1, err
	}
	defer os.RemoveAll(mnt)
	if out, err := exec.Command("hdiutil", "attach", local, "-mountpoint", mnt).CombinedOutput(); err != nil {
		return string(out), exitCode(err), err
	}
	defer exec.Command("hdiutil", "detach", mnt).Run()
	apps, _ := filepath.Glob(filepath.Join(mnt, "*.app"))
	if len(apps) == 0 {
		return "未找到 .app", -1, fmt.Errorf("dmg 内无 .app")
	}
	for _, app := range apps {
		dst := "/Applications/" + filepath.Base(app)
		if out, err := exec.Command("ditto", app, dst).CombinedOutput(); err != nil {
			return string(out), exitCode(err), err
		}
	}
	return "已安装 " + filepath.Base(apps[0]), 0, nil
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
