// 御端副端 —— M4 远程控制模块（Go 参考实现）。
// 说明：捕获/输入注入为平台原生能力，Rust 生产版将在对应平台模块落地；本参考实现
// 在 macOS 上提供真实屏幕采集与最佳努力的键入注入，Linux/Windows 提供合成帧与日志，
// 用于打通「信令-中继-画面-合规提示-审计」全链路。
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	_ "image/png"
	"log"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"yuduan/internal/proto"
	"yuduan/internal/ws"
)

const shotPath = "/tmp/yuduan_shot.png"

var (
	rcMu     sync.Mutex
	rcStopCh chan struct{}
)

// startRC 开启远控捕获循环，直到 stopCh 关闭。
func startRC(conn *ws.Conn, sessionID string) {
	rcMu.Lock()
	if rcStopCh != nil {
		close(rcStopCh) // 结束上一个会话
	}
	stop := make(chan struct{})
	rcStopCh = stop
	rcMu.Unlock()

	// 合规提示：被控端本地弹窗 + 日志（远端提示铁律，员工可拒绝）
	showRemoteNotice()
	sendRCEvent(conn, sessionID, "consent_required", "管理员请求远程控制本机，您可拒绝", true, false)
	// 开发态自动授权（生产必须等员工确认）；仅用于打通链路演示
	go func() {
		time.Sleep(800 * time.Millisecond)
		sendRCEvent(conn, sessionID, "consent_granted", "员工已确认（开发态自动）", false, true)
	}()

	if runtime.GOOS == "windows" {
		// v0.4.14（实测报告问题 4 根修）：Windows 服务运行于 Session 0，GDI 抓屏
		// 看不到用户桌面，此前甚至只有合成帧。走「服务 + 用户会话助手」双进程：
		// 助手在活动会话内真实抓屏/注入，服务经回环 TCP 中继；助手握手成功才报
		// rc_ready ok=true，失败报 ok=false + 原因（viewer 可见，不再黑盒超时）。
		rcLoopWindows(conn, sessionID, stop)
		return
	}
	sendRCReady(conn, sessionID, true, "")
	rcLoopSynthetic(conn, sessionID, stop)
}

// rcLoopSynthetic 通用帧生成循环（macOS/Linux 真实采集；Windows 无助手时兜底合成帧）。
func rcLoopSynthetic(conn *ws.Conn, sessionID string, stop chan struct{}) {
	ticker := time.NewTicker(500 * time.Millisecond)
	seq := int64(0)
	for {
		select {
		case <-stop:
			ticker.Stop()
			log.Printf("[agent] rc session stopped %s", sessionID)
			return
		case <-ticker.C:
			seq++
			// W2-3：帧生成统一走 frameBytes（含黑屏/水印处理），与 Rust 副端同构。
			frame, w, h := frameBytes()
			if frame == nil {
				continue
			}
			payload := proto.RCFramePayload{
				SessionID: sessionID, Seq: seq, Width: w, Height: h,
				Format: "jpeg", Data: base64.StdEncoding.EncodeToString(frame), TS: time.Now().Unix(),
			}
			env, _ := proto.NewEnvelope(proto.TypeRCFrame, nextSeq(), payload)
			if b, err := json.Marshal(env); err == nil {
				_ = conn.WriteMessage(b)
			}
		}
	}
}

// stopRC 结束当前远控会话。
func stopRC() {
	rcMu.Lock()
	defer rcMu.Unlock()
	if rcStopCh != nil {
		close(rcStopCh)
		rcStopCh = nil
	}
	// W2-3/W2-1：会话结束复位画面状态并清理未完成传输（避免残留到下一次会话）。
	resetDisplay()
	cleanupTransfers()
}

// applyInput 处理键鼠输入；macOS 最佳努力注入可打印字符，其余平台/类型记录并回执。
func applyInput(conn *ws.Conn, sessionID string, p proto.RCInputPayload) {
	// W2-6 Ctrl+Alt+Del：安全注意序列不能由用户态注入合成（Windows 仅 Winlogon 安全桌面
	// 受理），走官方可达路径；其余平台无此语义，诚实回告不支持（与 Rust 副端同构）。
	if p.Kind == "cad" {
		handleCAD(conn, sessionID)
		return
	}
	// v0.4.14：Windows 键鼠经用户会话助手里注入（Session 0 内 SendInput 无法触达用户桌面）。
	if runtime.GOOS == "windows" && forwardRCInput(p) {
		sendRCEvent(conn, sessionID, "input_received", fmt.Sprintf("received %s", p.Kind), false, false)
		return
	}
	log.Printf("[agent] input %s x=%d y=%d key=%s", p.Kind, p.X, p.Y, p.Key)
	if runtime.GOOS == "darwin" && p.Kind == "key_press" && len(p.Key) == 1 {
		_ = exec.Command("osascript", "-e", fmt.Sprintf(`tell application "System Events" to keystroke "%s"`, p.Key)).Run()
	}
	sendRCEvent(conn, sessionID, "input_received", fmt.Sprintf("received %s", p.Kind), false, false)
}

// captureScreen 采集一帧屏幕并编码为 JPEG。
func captureScreen() ([]byte, int, int) {
	switch runtime.GOOS {
	case "darwin":
		return captureViaCmd("screencapture", "-x", "-t", "png", shotPath)
	case "linux":
		if _, err := exec.LookPath("scrot"); err == nil {
			return captureViaCmd("scrot", "-o", shotPath)
		}
		if _, err := exec.LookPath("import"); err == nil {
			return captureViaCmd("import", "-window", "root", shotPath)
		}
		return syntheticFrame()
	default:
		return syntheticFrame()
	}
}

func captureViaCmd(name string, args ...string) ([]byte, int, int) {
	_ = exec.Command(name, args...).Run()
	f, err := os.Open(shotPath)
	if err != nil {
		return syntheticFrame()
	}
	defer f.Close()
	img, _, err := image.Decode(f)
	if err != nil {
		return syntheticFrame()
	}
	return encodeJPEG(img)
}

func syntheticFrame() ([]byte, int, int) {
	const w, h = 1280, 800
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{uint8(x % 255), uint8(y % 255), 90, 255})
		}
	}
	return encodeJPEG(img)
}

func encodeJPEG(img image.Image) ([]byte, int, int) {
	b := &bytes.Buffer{}
	if err := jpeg.Encode(b, img, &jpeg.Options{Quality: 55}); err != nil {
		return nil, 0, 0
	}
	return b.Bytes(), img.Bounds().Dx(), img.Bounds().Dy()
}

// showRemoteNotice 在被控端弹出远端提示（macOS 通知；合规要求员工知情）。
func showRemoteNotice() {
	if runtime.GOOS == "darwin" {
		_ = exec.Command("osascript", "-e",
			`display notification "管理员正在请求远程控制本机，您可拒绝" with title "御端远端提示"`).Run()
	}
	log.Printf("[agent] [远端提示] 管理员请求远程控制，员工可拒绝")
}

func sendRCReady(conn *ws.Conn, sessionID string, ok bool, reason string) {
	p := proto.RCReadyPayload{SessionID: sessionID, OK: ok, Reason: reason}
	env, _ := proto.NewEnvelope(proto.TypeRCReady, nextSeq(), p)
	if b, err := json.Marshal(env); err == nil {
		_ = conn.WriteMessage(b)
	}
}

func sendRCEvent(conn *ws.Conn, sessionID, kind, msg string, req, consented bool) {
	p := proto.RCEventPayload{SessionID: sessionID, Kind: kind, Message: msg, RequireConsent: req, Consented: consented}
	env, _ := proto.NewEnvelope(proto.TypeRCEvent, nextSeq(), p)
	if b, err := json.Marshal(env); err == nil {
		_ = conn.WriteMessage(b)
	}
}
