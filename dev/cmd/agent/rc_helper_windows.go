// Windows 远控助手模式：运行在活动用户会话内（服务经 CreateProcessAsUser 拉起），
// 在用户桌面执行真实 GDI 抓屏与 SendInput 键鼠注入，经 127.0.0.1 回环 TCP 与服务中继。
// 由 cmd/agent/main.go 的 --rc-helper 参数进入，启动后常驻直至服务下发 stop 或断连。
//go:build windows

package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image"
	"log"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

var (
	moduser32           = syscall.NewLazyDLL("user32.dll")
	modgdi32            = syscall.NewLazyDLL("gdi32.dll")
	procGetDC           = moduser32.NewProc("GetDC")
	procReleaseDC       = moduser32.NewProc("ReleaseDC")
	procGetSysMetrics   = moduser32.NewProc("GetSystemMetrics")
	procSetDPIAware     = moduser32.NewProc("SetProcessDPIAware")
	procSendInput       = moduser32.NewProc("SendInput")
	procCreateCompatDC  = modgdi32.NewProc("CreateCompatibleDC")
	procDeleteDC        = modgdi32.NewProc("DeleteDC")
	procCreateCompatBmp = modgdi32.NewProc("CreateCompatibleBitmap")
	procDeleteObject    = modgdi32.NewProc("DeleteObject")
	procSelectObject    = modgdi32.NewProc("SelectObject")
	procBitBlt          = modgdi32.NewProc("BitBlt")
	procGetDIBits       = modgdi32.NewProc("GetDIBits")
)

const (
	smCXScreen = 0
	smCYScreen = 1

	srccopyBit   = 0x00CC0020
	captureblt   = 0x40000000
	biRGB        = 0
	dibRGBColors = 0

	inputMouse    = 0
	inputKeyboard = 1

	mouseeventfMove      = 0x0001
	mouseeventfLeftDown  = 0x0002
	mouseeventfLeftUp    = 0x0004
	mouseeventfRightDown = 0x0008
	mouseeventfRightUp   = 0x0010
	mouseeventfMidDown   = 0x0020
	mouseeventfMidUp     = 0x0040
	mouseeventfWheel     = 0x0800
	mouseeventfAbsolute  = 0x8000

	keyeventfExtended = 0x0001
	keyeventfKeyUp    = 0x0002
	keyeventfUnicode  = 0x0004

	wheelDelta = 120
)

// bitmapInfoHeader 与 Win32 BITMAPINFOHEADER（40 字节）逐字段对齐。
type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

// runRCHelper 助手主循环：回连服务 → hello 握手 → 帧采集 + 输入消费。
func runRCHelper(addr string) {
	log.Printf("[agent] rc 助手启动，回连服务 %s", addr)
	var conn net.Conn
	var err error
	for i := 0; i < 50; i++ { // 约 10s 重连窗口，与服务侧握手超时对齐
		conn, err = net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		log.Printf("[agent] rc 助手无法回连服务 %s: %v", addr, err)
		os.Exit(1)
	}
	defer conn.Close()
	_ = setProcessDPIAware()

	hello, _ := json.Marshal(map[string]any{
		"type": "hello", "pid": os.Getpid(), "session": wtsActiveSessionID(),
	})
	if err := rcIPCWriteMsg(conn, hello); err != nil {
		log.Printf("[agent] rc 助手握手发送失败: %v", err)
		return
	}
	log.Printf("[agent] rc 助手握手完成（screen=%dx%d）", screenW(), screenH())

	// 帧采集循环（2fps，与服务侧既有节拍一致；QoS 自适应后续接 rc_qos）。
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			jb, w, h, err := captureScreenGDI()
			if err != nil {
				lb, _ := json.Marshal(map[string]any{"type": "log", "msg": "抓屏失败: " + err.Error()})
				if rcIPCWriteMsg(conn, lb) != nil {
					return
				}
				continue
			}
			msg, _ := json.Marshal(map[string]any{
				"type": "frame", "jpeg_b64": base64.StdEncoding.EncodeToString(jb), "w": w, "h": h,
			})
			if rcIPCWriteMsg(conn, msg) != nil {
				return
			}
		}
	}()

	// 输入消费循环（读侧独占；写侧仅帧采集 goroutine，两个方向天然无竞争）。
	for {
		b, err := rcIPCReadMsg(conn)
		if err != nil {
			log.Printf("[agent] rc 助手服务连接结束: %v", err)
			return
		}
		var m map[string]any
		if json.Unmarshal(b, &m) != nil {
			continue
		}
		switch t, _ := m["type"].(string); t {
		case "stop":
			log.Printf("[agent] rc 助手收到停止指令")
			return
		case "input":
			applyHelperInput(m)
		}
	}
}

func screenW() int {
	r1, _, _ := procGetSysMetrics.Call(smCXScreen)
	return int(int32(r1))
}

func screenH() int {
	r1, _, _ := procGetSysMetrics.Call(smCYScreen)
	return int(int32(r1))
}

func setProcessDPIAware() error {
	if err := procSetDPIAware.Find(); err != nil {
		return err
	}
	procSetDPIAware.Call()
	return nil
}

// captureScreenGDI 真实 GDI 抓屏：BitBlt 整屏 → GetDIBits 32bpp → JPEG。
func captureScreenGDI() ([]byte, int, int, error) {
	w, h := screenW(), screenH()
	if w <= 0 || h <= 0 {
		return nil, 0, 0, fmt.Errorf("屏幕尺寸异常 %dx%d", w, h)
	}
	hdc, _, _ := procGetDC.Call(0)
	if hdc == 0 {
		return nil, 0, 0, fmt.Errorf("GetDC(0) 失败")
	}
	defer procReleaseDC.Call(0, hdc)
	memDC, _, _ := procCreateCompatDC.Call(hdc)
	if memDC == 0 {
		return nil, 0, 0, fmt.Errorf("CreateCompatibleDC 失败")
	}
	defer procDeleteDC.Call(memDC)
	bmp, _, _ := procCreateCompatBmp.Call(hdc, uintptr(w), uintptr(h))
	if bmp == 0 {
		return nil, 0, 0, fmt.Errorf("CreateCompatibleBitmap 失败")
	}
	oldObj, _, _ := procSelectObject.Call(memDC, bmp)
	defer procSelectObject.Call(memDC, oldObj)
	defer procDeleteObject.Call(bmp)
	if r1, _, err := procBitBlt.Call(memDC, 0, 0, uintptr(w), uintptr(h), hdc, 0, 0,
		uintptr(srccopyBit|captureblt)); r1 == 0 {
		return nil, 0, 0, fmt.Errorf("BitBlt 失败: %v", err)
	}
	bi := bitmapInfoHeader{
		Size: 40, Width: int32(w), Height: -int32(h), // 负高度 = 自顶向下行序
		Planes: 1, BitCount: 32, Compression: biRGB,
	}
	buf := make([]byte, w*h*4)
	if r1, _, err := procGetDIBits.Call(memDC, bmp, 0, uintptr(h),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&bi)), dibRGBColors); r1 == 0 {
		return nil, 0, 0, fmt.Errorf("GetDIBits 失败: %v", err)
	}
	// BGRA（X）→ RGBA
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i, j := 0, 0; i < len(img.Pix); i, j = i+4, j+4 {
		img.Pix[i+0] = buf[j+2]
		img.Pix[i+1] = buf[j+1]
		img.Pix[i+2] = buf[j+0]
		img.Pix[i+3] = 255
	}
	jb, ew, eh := encodeJPEG(img)
	if jb == nil {
		return nil, 0, 0, fmt.Errorf("JPEG 编码失败")
	}
	return jb, ew, eh, nil
}

// ---- 键鼠注入（SendInput，[40]byte 显式布局规避 x64 INPUT 联合体对齐差异）----
// INPUT x64 布局：type@0（u32+4pad），MOUSEINPUT@8（dx8 dy12 data16 flags20 time24 extra32），
// 共 40 字节；KEYBDINPUT@8（wVk8 wScan10 flags12 time16 extra24）。cbSize 恒 40。

func sendInputRaw(in *[40]byte) bool {
	r1, _, _ := procSendInput.Call(1, uintptr(unsafe.Pointer(in)), 40)
	return r1 == 1
}

func fillMouseAbs(in *[40]byte, x, y, w, h int) {
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}
	nx := uint32(0)
	ny := uint32(0)
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	if x > w-1 {
		x = w - 1
	}
	if y > h-1 {
		y = h - 1
	}
	if w > 1 {
		nx = uint32(x * 65535 / (w - 1))
	}
	if h > 1 {
		ny = uint32(y * 65535 / (h - 1))
	}
	binary.LittleEndian.PutUint32(in[0:], inputMouse)
	binary.LittleEndian.PutUint32(in[8:], nx)
	binary.LittleEndian.PutUint32(in[12:], ny)
	binary.LittleEndian.PutUint32(in[20:], mouseeventfMove|mouseeventfAbsolute)
}

var vkMap = map[string]uint16{
	"enter": 0x0D, "return": 0x0D, "backspace": 0x08, "tab": 0x09,
	"escape": 0x1B, "esc": 0x1B, "space": 0x20, "delete": 0x2E, "del": 0x2E,
	"insert": 0x2D, "home": 0x24, "end": 0x23, "pageup": 0x21, "pagedown": 0x22,
	"up": 0x26, "down": 0x28, "left": 0x25, "right": 0x27,
	"arrowup": 0x26, "arrowdown": 0x28, "arrowleft": 0x25, "arrowright": 0x27,
	"ctrl": 0x11, "control": 0x11, "alt": 0x12, "shift": 0x10,
	"win": 0x5B, "meta": 0x5B, "cmd": 0x5B, "menu": 0x5D, "apps": 0x5D,
}
var vkExtended = map[uint16]bool{
	0x25: true, 0x26: true, 0x27: true, 0x28: true, // 方向键
	0x21: true, 0x22: true, 0x23: true, 0x24: true, // PgUp/PgDn/Home/End
	0x2D: true, 0x2E: true, // Ins/Del
}

func init() {
	for i := 0; i < 12; i++ {
		vkMap[fmt.Sprintf("f%d", i+1)] = uint16(0x70 + i)
	}
}

func sendKeyVK(vk uint16, up bool) {
	var in [40]byte
	binary.LittleEndian.PutUint32(in[0:], inputKeyboard)
	binary.LittleEndian.PutUint16(in[8:], vk)
	flags := uint32(0)
	if vkExtended[vk] {
		flags |= keyeventfExtended
	}
	if up {
		flags |= keyeventfKeyUp
	}
	binary.LittleEndian.PutUint32(in[12:], flags)
	sendInputRaw(&in)
}

func sendKeyUnicode(r rune, up bool) {
	var in [40]byte
	binary.LittleEndian.PutUint32(in[0:], inputKeyboard)
	binary.LittleEndian.PutUint16(in[10:], uint16(r))
	flags := uint32(keyeventfUnicode)
	if up {
		flags |= keyeventfKeyUp
	}
	binary.LittleEndian.PutUint32(in[12:], flags)
	sendInputRaw(&in)
}

// applyHelperInput 处理服务转发来的键鼠事件（kind 语义与 proto.RCInputPayload 一致）。
func applyHelperInput(m map[string]any) {
	kind, _ := m["kind"].(string)
	x, _ := m["x"].(float64)
	y, _ := m["y"].(float64)
	button, _ := m["button"].(float64)
	key, _ := m["key"].(string)
	w, h := screenW(), screenH()

	switch kind {
	case "mouse_move":
		var in [40]byte
		fillMouseAbs(&in, int(x), int(y), w, h)
		sendInputRaw(&in)
	case "mouse_down", "mouse_up":
		var in [40]byte
		fillMouseAbs(&in, int(x), int(y), w, h)
		var f uint32
		switch int(button) {
		case 2:
			f = mouseeventfRightDown
			if kind == "mouse_up" {
				f = mouseeventfRightUp
			}
		case 3:
			f = mouseeventfMidDown
			if kind == "mouse_up" {
				f = mouseeventfMidUp
			}
		default:
			f = mouseeventfLeftDown
			if kind == "mouse_up" {
				f = mouseeventfLeftUp
			}
		}
		binary.LittleEndian.PutUint32(in[20:], mouseeventfMove|mouseeventfAbsolute|f)
		sendInputRaw(&in)
	case "mouse_wheel":
		var in [40]byte
		fillMouseAbs(&in, int(x), int(y), w, h)
		delta := int32(y) * wheelDelta
		binary.LittleEndian.PutUint32(in[16:], uint32(delta))
		binary.LittleEndian.PutUint32(in[20:], mouseeventfMove|mouseeventfAbsolute|mouseeventfWheel)
		sendInputRaw(&in)
	case "key_down", "key_up", "key_press":
		up := kind == "key_up"
		if len(key) == 1 {
			r := []rune(key)[0]
			if kind == "key_press" {
				sendKeyUnicode(r, false)
				sendKeyUnicode(r, true)
			} else {
				sendKeyUnicode(r, up)
			}
			return
		}
		vk, ok := vkMap[key]
		if !ok {
			// 未知键名：退化为逐字符 Unicode 注入
			for _, r := range key {
				sendKeyUnicode(r, false)
				sendKeyUnicode(r, true)
			}
			return
		}
		if kind == "key_press" {
			sendKeyVK(vk, false)
			sendKeyVK(vk, true)
		} else {
			sendKeyVK(vk, up)
		}
	default:
		log.Printf("[agent][rc助手] 未支持的输入类型: %s", kind)
	}
}
