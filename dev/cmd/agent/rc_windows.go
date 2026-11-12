// Windows 远控「服务 + 用户会话助手」双进程（v0.4.14，实测报告问题 4 根修）。
//
// 根因：副端以 Windows 服务运行于 Session 0，GDI 抓屏只能看到无交互的 Session 0
// 桌面，用户交互桌面在活动会话（实测 Session 2），导致中枢 rc_frame/rc_ready 计数
// 为 0、viewer 约 5s 超时断开。修复：服务经 WTSGetActiveConsoleSessionId +
// WTSQueryUserToken + CreateProcessAsUser 在活动会话拉起本 exe 的助手模式
// （--rc-helper <addr>），助手在用户桌面内真实抓屏（GDI）与输入注入（SendInput），
// 经 127.0.0.1 回环 TCP 与服务中继（4 字节小端长度前缀 + JSON 消息）。
//
// 零依赖约束：项目 go.mod 无第三方依赖，Windows API 一律走 stdlib syscall。
//go:build windows

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image"
	"image/draw"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"yuduan/internal/proto"
	"yuduan/internal/ws"
)

// ---- Windows API（零依赖，stdlib syscall）----

var (
	modkernel32    = syscall.NewLazyDLL("kernel32.dll")
	modwtsapi32    = syscall.NewLazyDLL("wtsapi32.dll")
	modadvapi32    = syscall.NewLazyDLL("advapi32.dll")
	procWTSSession = modkernel32.NewProc("WTSGetActiveConsoleSessionId")
	procWTSQueryTk = modwtsapi32.NewProc("WTSQueryUserToken")
	procCloseH     = modkernel32.NewProc("CloseHandle")
	procTerminate  = modkernel32.NewProc("TerminateProcess")
	procCreateAsU  = modadvapi32.NewProc("CreateProcessAsUserW")
)

const wtsInvalidSession = 0xFFFFFFFF

// wtsActiveSessionID 返回活动控制台会话 ID；无活动会话返回 0。
func wtsActiveSessionID() uint32 {
	if err := procWTSSession.Find(); err != nil {
		return 0
	}
	r1, _, _ := procWTSSession.Call()
	sid := uint32(r1)
	if sid == wtsInvalidSession {
		return 0
	}
	return sid
}

// ---- IPC：4 字节小端长度前缀 + JSON ----

func rcIPCReadMsg(c net.Conn) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(lenBuf[:])
	if n == 0 || n > 16<<20 { // 单帧上限 16MB（4K JPEG 富余）
		return nil, fmt.Errorf("ipc 消息长度异常: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func rcIPCWriteMsg(c net.Conn, b []byte) error {
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(b)))
	if _, err := c.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := c.Write(b)
	return err
}

// ---- 助手进程管理 ----

// rcHelper 表示一个已握手的用户会话助手。
type rcHelper struct {
	conn   net.Conn
	frames chan rcFrameMsg
	kill   func()
	pid    int
	once   sync.Once
}

type rcFrameMsg struct {
	JPEG []byte
	W, H int
}

var (
	rcHelperMu   sync.Mutex
	activeHelper *rcHelper // 当前会话助手（applyInput 经此转发键鼠）
)

// launchRCHelper 在活动用户会话拉起助手并等待握手。失败返回 nil 与可诊断原因。
func launchRCHelper() (*rcHelper, string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "本机回环监听失败: " + err.Error()
	}
	port := ln.Addr().(*net.TCPAddr).Port
	exe, err := os.Executable()
	if err != nil {
		ln.Close()
		return nil, "无法定位本 exe: " + err.Error()
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	var kill func()
	pid := 0
	launchedVia := ""
	if sid := wtsActiveSessionID(); sid != 0 {
		var tok syscall.Handle
		r1, _, callErr := procWTSQueryTk.Call(uintptr(sid), uintptr(unsafe.Pointer(&tok)))
		if r1 != 0 {
			ph, p, ok := createProcessAsUser(tok, exe, addr)
			procCloseH.Call(uintptr(tok))
			if ok {
				hProc := ph
				kill = func() { procTerminate.Call(uintptr(hProc), 1); procCloseH.Call(uintptr(hProc)) }
				pid = p
				launchedVia = fmt.Sprintf("CreateProcessAsUser(session=%d)", sid)
			}
		} else {
			log.Printf("[agent] WTSQueryUserToken(session=%d) 失败: %v", sid, callErr)
		}
	} else {
		log.Printf("[agent] 无活动控制台会话（WTSGetActiveConsoleSessionId=invalid）")
	}
	if kill == nil {
		// 兜底：服务本就运行在用户会话（开发态/前台运行）→ 直接子进程拉起。
		cmd := exec.Command(exe, "--rc-helper", addr)
		if err := cmd.Start(); err == nil {
			p := cmd.Process
			kill = func() { _ = p.Kill() }
			pid = p.Pid
			launchedVia = "exec.Command(同会话兜底)"
		}
	}
	if kill == nil {
		ln.Close()
		return nil, "无法在用户会话拉起抓屏助手（无活动登录桌面或权限不足；锁屏/未登录时远控画面不可用属预期安全行为）"
	}
	log.Printf("[agent] rc 助手已拉起（pid=%d via %s）", pid, launchedVia)

	// 等助手回连握手（10s）。
	if tc, ok := ln.(*net.TCPListener); ok {
		_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	}
	hc, err := ln.Accept()
	ln.Close()
	if err != nil {
		kill()
		return nil, "助手未在 10s 内回连（用户会话可能无桌面或被策略拦截）"
	}
	// 读 hello 确认握手。
	hc.SetDeadline(time.Now().Add(3 * time.Second))
	hello, err := rcIPCReadMsg(hc)
	hc.SetDeadline(time.Time{})
	if err != nil {
		hc.Close()
		kill()
		return nil, "助手握手读取失败: " + err.Error()
	}
	var m map[string]any
	if json.Unmarshal(hello, &m) != nil || m["type"] != "hello" {
		hc.Close()
		kill()
		return nil, "助手握手消息异常"
	}

	h := &rcHelper{
		conn:   hc,
		frames: make(chan rcFrameMsg, 2),
		kill:   kill,
		pid:    pid,
	}
	// 助手读循环：帧 / 日志。
	go func() {
		for {
			b, err := rcIPCReadMsg(h.conn)
			if err != nil {
				log.Printf("[agent] rc 助手连接结束: %v", err)
				h.shutdown()
				return
			}
			var m map[string]any
			if json.Unmarshal(b, &m) != nil {
				continue
			}
			switch t, _ := m["type"].(string); t {
			case "frame":
				s, _ := m["jpeg_b64"].(string)
				jb, _ := base64.StdEncoding.DecodeString(s)
				w, _ := m["w"].(float64)
				hh, _ := m["h"].(float64)
				if len(jb) == 0 || int(w) <= 0 || int(hh) <= 0 {
					continue
				}
				msg := rcFrameMsg{JPEG: jb, W: int(w), H: int(hh)}
				select {
				case h.frames <- msg:
				default: // 上一帧未消费完则丢弃，保持低延迟
				}
			case "log":
				msg, _ := m["msg"].(string)
				log.Printf("[agent][rc助手] %s", msg)
			}
		}
	}()
	return h, ""
}

// shutdown 通知助手停止并回收进程。
func (h *rcHelper) shutdown() {
	h.once.Do(func() {
		_ = rcIPCWriteMsg(h.conn, []byte(`{"type":"stop"}`))
		time.Sleep(300 * time.Millisecond)
		h.conn.Close()
		if h.kill != nil {
			h.kill()
		}
		log.Printf("[agent] rc 助手已停止（pid=%d）", h.pid)
	})
}

// createProcessAsUser 以用户令牌在目标会话内拉起助手（DETACHED_PROCESS 无窗口）。
func createProcessAsUser(tok syscall.Handle, exe, addr string) (syscall.Handle, int, bool) {
	cmdline, err := syscall.UTF16PtrFromString(fmt.Sprintf(`"%s" --rc-helper %s`, exe, addr))
	if err != nil {
		return 0, 0, false
	}
	exePtr, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return 0, 0, false
	}
	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi syscall.ProcessInformation
	const detach = 0x00000008 // DETACHED_PROCESS
	r1, _, callErr := procCreateAsU.Call(
		uintptr(tok),
		uintptr(unsafe.Pointer(exePtr)),
		uintptr(unsafe.Pointer(cmdline)),
		0, 0, 0, uintptr(detach), 0, 0,
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if r1 == 0 {
		log.Printf("[agent] CreateProcessAsUser 失败: %v", callErr)
		return 0, 0, false
	}
	return pi.Process, int(pi.ProcessId), true
}

// ---- 服务侧会话循环 ----

// rcLoopWindows Windows 远控主循环：拉起用户会话助手 → rc_ready → 帧中继。
// 助手握手成功才报 ok=true；失败报 ok=false + 原因（viewer 可见，可诊断）。
func rcLoopWindows(conn *ws.Conn, sessionID string, stop chan struct{}) {
	h, reason := launchRCHelper()
	if h == nil {
		log.Printf("[agent] rc 会话 %s 助手不可用: %s", sessionID, reason)
		sendRCReady(conn, sessionID, false, reason)
		<-stop
		return
	}
	rcHelperMu.Lock()
	activeHelper = h
	rcHelperMu.Unlock()
	defer func() {
		rcHelperMu.Lock()
		if activeHelper == h {
			activeHelper = nil
		}
		rcHelperMu.Unlock()
		h.shutdown()
		log.Printf("[agent] rc session stopped (windows helper) %s", sessionID)
	}()
	sendRCReady(conn, sessionID, true, "")
	log.Printf("[agent] rc 会话 %s：用户会话助手就绪（pid=%d）", sessionID, h.pid)

	seq := int64(0)
	for {
		select {
		case <-stop:
			return
		case fm, ok := <-h.frames:
			if !ok {
				log.Printf("[agent] rc 助手断开，会话结束 %s", sessionID)
				return
			}
			out, w, hh := processFrame(fm)
			if out == nil {
				continue
			}
			seq++
			payload := proto.RCFramePayload{
				SessionID: sessionID, Seq: seq, Width: w, Height: hh,
				Format: "jpeg", Data: base64.StdEncoding.EncodeToString(out), TS: time.Now().Unix(),
			}
			env, _ := proto.NewEnvelope(proto.TypeRCFrame, nextSeq(), payload)
			if b, err := json.Marshal(env); err == nil {
				_ = conn.WriteMessage(b)
			}
		}
	}
}

// processFrame 复用 W2-3 画面控制（防窥黑屏 / 水印）：助手送原始帧，服务侧加工。
func processFrame(fm rcFrameMsg) ([]byte, int, int) {
	dispMu.RLock()
	blank, wm, text := rcBlank, rcWatermark, rcWmText
	dispMu.RUnlock()
	if blank {
		w, h := lastDims.X, lastDims.Y
		if w <= 0 {
			w, h = fm.W, fm.H
		}
		img := image.NewRGBA(image.Rect(0, 0, w, h))
		draw.Draw(img, img.Bounds(), image.NewUniform(image.Black), image.Point{}, draw.Src)
		dispMu.Lock()
		lastDims = image.Pt(w, h)
		dispMu.Unlock()
		return encodeJPEG(img)
	}
	if wm {
		img, _, err := image.Decode(bytes.NewReader(fm.JPEG))
		if err == nil {
			img = drawWatermark(img, text)
			return encodeJPEG(img)
		}
		// 解码失败则透传原始帧（无水印），保证画面链路优先。
	}
	dispMu.Lock()
	lastDims = image.Pt(fm.W, fm.H)
	dispMu.Unlock()
	return fm.JPEG, fm.W, fm.H
}

// forwardRCInput 把 viewer 键鼠事件经回环 IPC 转发给用户会话助手注入。
func forwardRCInput(p proto.RCInputPayload) bool {
	rcHelperMu.Lock()
	h := activeHelper
	rcHelperMu.Unlock()
	if h == nil {
		return false
	}
	b, _ := json.Marshal(map[string]any{
		"type": "input", "kind": p.Kind, "x": p.X, "y": p.Y, "button": p.Button, "key": p.Key,
	})
	return rcIPCWriteMsg(h.conn, b) == nil
}
