// 复盘 S-8/V-08：软件分发完整性（SHA-256 强制）的回归用例。
//
// 风险链条：副端下载安装包时 InsecureSkipVerify=true（内网自签证书历史包袱），
// 且摘要为「有则校、无则放行」。两者叠加意味着内网任一对路径者可以替换响应体，
// 而安装包最终由 msiexec / installer / dpkg 以 SYSTEM/root 权限执行——
// 一次 MITM 即等价任意代码执行。
//
// 本文件的用例锚定修复的两个面：
//  1. 中枢：外部 URL 任务必须能把管理员给出的摘要带进下发的 sw_install 指令；
//  2. 副端：下发的安装包没有摘要时必须拒绝安装（见 dev/e2e_s8.py 的真机对抗环节）。
package hub

import (
	"strings"
	"testing"

	"yuduan/internal/proto"
)

// TestDistTaskSha256PropagatedToCommand：创建任务时给出的 sha256 必须出现在
// 下发给副端的 sw_install 指令载荷里——否则外部 URL 分发在强制摘要后无法合规下发。
func TestDistTaskSha256PropagatedToCommand(t *testing.T) {
	h := NewHub(HubConfig{HMACSecret: "s8-secret"})
	tasks := h.w3().tasks
	const taskID = "dt-s8"
	wantSum := strings.Repeat("ab", 32) // 64 hex
	tasks[taskID] = &W3DistTask{
		ID:          taskID,
		SoftwareURL: "http://192.168.1.99:9000/vendor-pkg.exe", // 非仓库外部地址
		PkgName:     "vendor-pkg.exe",
		Platform:    "windows",
		Sha256:      wantSum,
		Mode:        "forced",
		State:       "dispatching",
		CreatedBy:   "admin",
	}

	c := h.w3BuildInstallCommand(&W3Record{ID: "rec-s8", DeviceID: "dev-s8", Attempt: 1}, *tasks[taskID], "sw_install", proto.SwDistDetail{})
	if c.Sha256 != wantSum {
		t.Fatalf("外部 URL 任务的摘要未随指令下发：got=%q want=%q", c.Sha256, wantSum)
	}
	if c.SoftwareURL == "" || c.PkgName == "" {
		t.Fatalf("指令缺少下载要素：url=%q pkg=%q", c.SoftwareURL, c.PkgName)
	}
	// 指令必须带 nonce 且可被签名——即处于 HMAC 签名通道保护之下
	if c.TaskID == "" {
		t.Fatal("指令缺少 task_id")
	}
	// 仓库包场景：摘要须来自仓库清单而非任务（防管理员填错导致"看起来有校验实则错摘要"）
	h.mu.Lock()
	h.software["repo-s8"] = &proto.SoftwareItem{ID: "repo-s8", Name: "p.exe", Sha256: strings.Repeat("cd", 32)}
	h.mu.Unlock()
	repoTask := &W3DistTask{ID: "dt-repo", SoftwareURL: "http://127.0.0.1:18080/api/v1/repo/repo-s8", PkgName: "p.exe", Platform: "windows"}
	c2 := h.w3BuildInstallCommand(&W3Record{ID: "r2", DeviceID: "d2", Attempt: 1}, *repoTask, "sw_install", proto.SwDistDetail{})
	if c2.Sha256 != strings.Repeat("cd", 32) {
		t.Fatalf("仓库包摘要未取自软件清单：got=%q", c2.Sha256)
	}
	if c2.SoftwareURL == repoTask.SoftwareURL {
		t.Fatal("仓库下载 URL 未附加短时令牌（P-4 下载鉴权回归失败）")
	}
}
