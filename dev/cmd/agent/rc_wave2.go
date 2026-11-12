// 波次 2：远控会话内协作（Go 参考副端实现，与 Rust 生产副端同构）。
//
// 覆盖：W2-1 会话内文件传输（push 接收 / pull 发送，pull 默认关闭）、
//
//	W2-2 会话内消息（远端员工提示）、W2-3 黑屏防窥 / 水印、
//	W2-6 Ctrl+Alt+Del（Windows 安全屏幕；其余平台无 SAS 语义，诚实回告不支持）。
//
// Go 参考副端用于打通「协议/平台无关逻辑」，与 Rust 生产副端保持同构（铁律 2/9）：
// 同一套消息类型、同一套校验规则、同样的诚实回退（能力不足即回告，不伪造成功）。
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"yuduan/internal/proto"
	"yuduan/internal/ws"
)

// ---- W2-3 画面状态（黑屏 / 水印）----

var (
	dispMu      sync.RWMutex
	rcBlank     bool
	rcWatermark bool
	rcWmText    string
	lastDims    = image.Pt(1280, 800)
)

// resetDisplay 会话结束时复位画面状态（避免残留到下一次会话）。
func resetDisplay() {
	dispMu.Lock()
	rcBlank, rcWatermark, rcWmText = false, false, ""
	dispMu.Unlock()
}

// setDisplay 应用主端下发的画面控制，返回实际生效状态。
func setDisplay(blank, watermark bool, text string) (bool, bool, string) {
	if text == "" {
		text = "御端远控 " + time.Now().Format("2006-01-02 15:04")
	}
	dispMu.Lock()
	rcBlank, rcWatermark, rcWmText = blank, watermark, text
	dispMu.Unlock()
	return blank, watermark, text
}

// frameBytes 生成一帧（含画面控制处理）；返回 JPEG 字节与尺寸。
func frameBytes() ([]byte, int, int) {
	dispMu.RLock()
	blank, wm, text := rcBlank, rcWatermark, rcWmText
	dispMu.RUnlock()

	if blank {
		// 防窥视：纯黑帧（沿用最近尺寸，主端画面不跳变；会话不中断、控制权保留）
		w, h := lastDims.X, lastDims.Y
		img := image.NewRGBA(image.Rect(0, 0, w, h))
		draw.Draw(img, img.Bounds(), image.NewUniform(color.RGBA{0, 0, 0, 255}), image.ZP, draw.Src)
		return encodeJPEG(img)
	}
	img := captureImage()
	if img == nil {
		return nil, 0, 0
	}
	dispMu.Lock()
	lastDims = image.Pt(img.Bounds().Dx(), img.Bounds().Dy())
	dispMu.Unlock()
	if wm {
		img = drawWatermark(img, text)
	}
	return encodeJPEG(img)
}

// drawWatermark 在画面三处（左上 / 中心 / 右下）叠加半透明文本水印。
// 字体为内置 5×7 点阵（与 Rust 副端同一套字形表，保证两端水印观感一致），
// 不引入任何第三方依赖。
func drawWatermark(src image.Image, text string) image.Image {
	b := src.Bounds()
	dst := image.NewRGBA(b)
	draw.Draw(dst, b, src, b.Min, draw.Src)
	scale := 2
	cw, ch := 6*scale, 8*scale
	tw := len(text) * cw
	margin := 24
	spots := []image.Point{
		b.Min.Add(image.Pt(margin, margin)),
		b.Max.Sub(image.Pt(tw+margin, ch+margin)),
		b.Min.Add(image.Pt((b.Dx()-tw)/2, (b.Dy()-ch)/2)),
	}
	for _, p0 := range spots {
		if p0.X < b.Min.X || p0.Y < b.Min.Y || p0.X+tw > b.Max.X || p0.Y+ch > b.Max.Y {
			continue
		}
		for i, r := range text {
			g, ok := glyph5x7(r)
			if !ok {
				continue
			}
			gx, gy := p0.X+i*cw, p0.Y
			for row := 0; row < 7; row++ {
				for col := 0; col < 5; col++ {
					if (g[row]>>(4-col))&1 == 0 {
						continue
					}
					for dy := 0; dy < scale; dy++ {
						for dx := 0; dx < scale; dx++ {
							x, y := gx+col*scale+dx, gy+row*scale+dy
							shade(dst, x+1, y+1, -90) // 暗描边（浅色底可辨）
							shade(dst, x, y, 70)      // 亮字
						}
					}
				}
			}
		}
	}
	return dst
}

// shade 调整单像素亮度（delta 可正可负），越界忽略。
func shade(dst draw.Image, x, y, delta int) {
	b := dst.Bounds()
	if x < b.Min.X || y < b.Min.Y || x >= b.Max.X || y >= b.Max.Y {
		return
	}
	r, g, bb, a := dst.At(x, y).RGBA()
	r8 := clampByte(int(r>>8) + delta)
	g8 := clampByte(int(g>>8) + delta)
	b8 := clampByte(int(bb>>8) + delta)
	dst.Set(x, y, color.RGBA{r8, g8, b8, uint8(a >> 8)})
}

func clampByte(v int) uint8 {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return uint8(v)
}

// glyph5x7 返回字符的 5×7 点阵（每行 5 bit，bit4=最左列）。
// 与 Rust 副端 rc_wave2::glyph 同一套数据，修改时两端须同步（铁律 9）。
func glyph5x7(ch rune) ([7]byte, bool) {
	if ch >= 'a' && ch <= 'z' {
		ch = ch - 'a' + 'A'
	}
	table := map[rune][7]byte{
		'0': {0b01110, 0b10001, 0b10011, 0b10101, 0b11001, 0b10001, 0b01110},
		'1': {0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110},
		'2': {0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b01000, 0b11111},
		'3': {0b11111, 0b00010, 0b00100, 0b00010, 0b00001, 0b10001, 0b01110},
		'4': {0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010},
		'5': {0b11111, 0b10000, 0b11110, 0b00001, 0b00001, 0b10001, 0b01110},
		'6': {0b00110, 0b01000, 0b10000, 0b11110, 0b10001, 0b10001, 0b01110},
		'7': {0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000},
		'8': {0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110},
		'9': {0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00010, 0b01100},
		'A': {0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001},
		'B': {0b11110, 0b10001, 0b10001, 0b11110, 0b10001, 0b10001, 0b11110},
		'C': {0b01110, 0b10001, 0b10000, 0b10000, 0b10000, 0b10001, 0b01110},
		'D': {0b11110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11110},
		'E': {0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111},
		'F': {0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b10000},
		'G': {0b01110, 0b10001, 0b10000, 0b10111, 0b10001, 0b10001, 0b01110},
		'H': {0b10001, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001},
		'I': {0b01110, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110},
		'J': {0b00001, 0b00001, 0b00001, 0b00001, 0b10001, 0b10001, 0b01110},
		'K': {0b10001, 0b10010, 0b10100, 0b11000, 0b10100, 0b10010, 0b10001},
		'L': {0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b11111},
		'M': {0b10001, 0b11011, 0b10101, 0b10101, 0b10001, 0b10001, 0b10001},
		'N': {0b10001, 0b11001, 0b10101, 0b10011, 0b10001, 0b10001, 0b10001},
		'O': {0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110},
		'P': {0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000, 0b10000},
		'Q': {0b01110, 0b10001, 0b10001, 0b10001, 0b10101, 0b10010, 0b01101},
		'R': {0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001},
		'S': {0b01111, 0b10000, 0b10000, 0b01110, 0b00001, 0b00001, 0b11110},
		'T': {0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100},
		'U': {0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110},
		'V': {0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01010, 0b00100},
		'W': {0b10001, 0b10001, 0b10001, 0b10101, 0b10101, 0b11011, 0b10001},
		'X': {0b10001, 0b10001, 0b01010, 0b00100, 0b01010, 0b10001, 0b10001},
		'Y': {0b10001, 0b10001, 0b01010, 0b00100, 0b00100, 0b00100, 0b00100},
		'Z': {0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b10000, 0b11111},
		' ': {0, 0, 0, 0, 0, 0, 0},
		':': {0, 0b01100, 0b01100, 0, 0b01100, 0b01100, 0},
		'-': {0, 0, 0, 0b11111, 0, 0, 0},
		'.': {0, 0, 0, 0, 0, 0, 0b01100},
		'/': {0b00001, 0b00010, 0b00010, 0b00100, 0b01000, 0b01000, 0b10000},
		'@': {0b01110, 0b10001, 0b10111, 0b10101, 0b10111, 0b10000, 0b01110},
		'_': {0, 0, 0, 0, 0, 0, 0b11111},
		'#': {0b01010, 0b01010, 0b11111, 0b01010, 0b11111, 0b01010, 0b01010},
	}
	g, ok := table[ch]
	return g, ok
}

// ---- W2-2 会话内消息 ----

// handleChat 主端消息：在被控端提示（best-effort 通知）+ 回告已送达。
// 远端→主端的回复需要常驻托盘 UI 提供输入源，本波次未实现（协议与中继双向已打通）。
func handleChat(conn *ws.Conn, sessionID, from, text string) {
	shown := notifyChat(text)
	msg := "会话消息已在被控端提示"
	if !shown {
		msg = "会话消息已记录（本机无可用通知通道，已写入运行日志）"
	}
	log.Printf("[agent] [会话消息] %s：%s", from, text)
	sendRCEvent(conn, sessionID, "chat_delivered", msg, false, false)
}

func notifyChat(text string) bool {
	msg := strings.ReplaceAll(text, "\"", "'")
	if len(msg) > 120 {
		msg = msg[:120]
	}
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("osascript", "-e",
			fmt.Sprintf(`display notification "%s" with title "御端 · 管理员消息"`, msg)).Run() == nil
	case "linux":
		return exec.Command("notify-send", "御端 · 管理员消息", msg).Run() == nil
	case "windows":
		return exec.Command("powershell", "-NoProfile", "-Command",
			fmt.Sprintf(`Add-Type -AssemblyName System.Windows.Forms;[System.Windows.Forms.MessageBox]::Show('%s','御端 · 管理员消息')`,
				strings.ReplaceAll(msg, "'", ""))).Run() == nil
	}
	return false
}

// ---- W2-6 Ctrl+Alt+Del ----

// handleCAD 安全注意序列（SAS）不能由用户态输入注入合成——Windows 仅在 Winlogon
// 安全桌面受理。走官方可达路径拉起「Windows 安全」屏幕；其余平台无此语义，
// 不做伪造注入，诚实回告不支持。
func handleCAD(conn *ws.Conn, sessionID string) {
	if runtime.GOOS == "windows" {
		err := exec.Command("explorer.exe", "shell:::{2559a1f2-21d7-11d4-bdaf-00c04f60b9f0}").Run()
		if err != nil {
			sendRCEvent(conn, sessionID, "cad", "拉起 Windows 安全屏幕失败（可能被策略拦截）", false, false)
			return
		}
		sendRCEvent(conn, sessionID, "cad", "已拉起 Windows 安全屏幕", false, false)
		return
	}
	sendRCEvent(conn, sessionID, "cad_unsupported", "当前平台无 Ctrl+Alt+Del 安全序列语义，已忽略该指令", false, false)
}

// ---- W2-1 会话内文件传输 ----

const (
	maxTransferBytes = 50 * 1024 * 1024
	defaultChunk     = 64 * 1024
)

type transfer struct {
	direction string
	name      string
	path      string
	size      int64
	expectSHA string
	received  int64
	buf       []byte
	nextSeq   int64
	chunk     int
}

var (
	tfMu      sync.Mutex
	transfers = map[string]*transfer{}
)

// transferDir 接收目录：优先 ~/Downloads/YuDuan，其次临时目录。
func transferDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "yuduan-transfer")
	}
	dl := filepath.Join(home, "Downloads")
	if st, err := os.Stat(dl); err == nil && st.IsDir() {
		return filepath.Join(dl, "YuDuan")
	}
	return filepath.Join(home, "YuDuan")
}

// safeName 拒绝路径分隔符与相对路径穿越，只接受扁平文件名。
func safeName(name string) (string, bool) {
	n := strings.TrimSpace(name)
	if n == "" || strings.ContainsAny(n, "/\\") || strings.Contains(n, "..") || strings.HasPrefix(n, ".") {
		return "", false
	}
	return n, true
}

func sendFileDone(conn *ws.Conn, sessionID, tid string, ok bool, errMsg string, n int64, sha string) {
	p := proto.RCFileDonePayload{SessionID: sessionID, TransferID: tid, OK: ok, Error: errMsg, Bytes: n, Sha256: sha}
	env, _ := proto.NewEnvelope(proto.TypeRCFileDone, nextSeq(), p)
	if b, e := json.Marshal(env); e == nil {
		_ = conn.WriteMessage(b)
	}
}

func sendFileAccept(conn *ws.Conn, sessionID, tid string, accept bool, reason string, chunkOrSize int) {
	p := proto.RCFileAcceptPayload{SessionID: sessionID, TransferID: tid, Accept: accept, Reason: reason, ChunkSize: chunkOrSize}
	env, _ := proto.NewEnvelope(proto.TypeRCFileAccept, nextSeq(), p)
	if b, e := json.Marshal(env); e == nil {
		_ = conn.WriteMessage(b)
	}
}

// handleFileOffer 处理传输提议（push 接收 / pull 发送）。
func handleFileOffer(conn *ws.Conn, p proto.RCFileOfferPayload) {
	if p.TransferID == "" {
		return
	}
	if p.Direction == "pull" {
		handlePullOffer(conn, p)
		return
	}
	name, ok := safeName(p.Name)
	if !ok {
		sendFileDone(conn, p.SessionID, p.TransferID, false, "文件名非法（含路径分隔符或相对路径）", 0, "")
		return
	}
	if p.Size > maxTransferBytes {
		sendFileDone(conn, p.SessionID, p.TransferID, false, "文件超过 50MB 上限", 0, "")
		return
	}
	dir := transferDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		sendFileDone(conn, p.SessionID, p.TransferID, false, "创建接收目录失败: "+err.Error(), 0, "")
		return
	}
	tfMu.Lock()
	transfers[p.TransferID] = &transfer{
		direction: "push", name: name, path: filepath.Join(dir, name),
		size: p.Size, expectSHA: p.Sha256, chunk: defaultChunk,
	}
	tfMu.Unlock()
	log.Printf("[agent] 接收文件提议 tid=%s name=%s size=%dB", p.TransferID, name, p.Size)
	sendFileAccept(conn, p.SessionID, p.TransferID, true, "", defaultChunk)
}

// handlePullOffer 从本机拉取文件（合规默认关闭：须配置 YUDUAN_RC_PULL_ROOT）。
func handlePullOffer(conn *ws.Conn, p proto.RCFileOfferPayload) {
	root := os.Getenv("YUDUAN_RC_PULL_ROOT")
	if root == "" {
		sendFileDone(conn, p.SessionID, p.TransferID, false, "本机未启用文件拉取（未配置 YUDUAN_RC_PULL_ROOT）", 0, "")
		return
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		sendFileDone(conn, p.SessionID, p.TransferID, false, "允许根目录非法", 0, "")
		return
	}
	target, err := filepath.Abs(p.Path)
	if err != nil || !strings.HasPrefix(target, absRoot+string(os.PathSeparator)) {
		sendFileDone(conn, p.SessionID, p.TransferID, false, "目标路径不在允许根目录内，已拒绝", 0, "")
		return
	}
	st, err := os.Stat(target)
	if err != nil || st.IsDir() {
		sendFileDone(conn, p.SessionID, p.TransferID, false, "文件不存在或不是普通文件", 0, "")
		return
	}
	if st.Size() > maxTransferBytes {
		sendFileDone(conn, p.SessionID, p.TransferID, false, "文件超过 50MB 上限", 0, "")
		return
	}
	data, err := os.ReadFile(target)
	if err != nil {
		sendFileDone(conn, p.SessionID, p.TransferID, false, "读取文件失败", 0, "")
		return
	}
	sum := sha256.Sum256(data)
	tfMu.Lock()
	transfers[p.TransferID] = &transfer{
		direction: "pull", name: filepath.Base(target), path: target,
		size: int64(len(data)), expectSHA: hex.EncodeToString(sum[:]),
		buf: data, chunk: defaultChunk,
	}
	tfMu.Unlock()
	sendFileAccept(conn, p.SessionID, p.TransferID, true, "", len(data))
}

// handleFileAccept 主端应答：pull 方向开始分片上传。
func handleFileAccept(conn *ws.Conn, p proto.RCFileAcceptPayload) {
	tfMu.Lock()
	t, ok := transfers[p.TransferID]
	tfMu.Unlock()
	if !ok {
		return
	}
	if !p.Accept {
		tfMu.Lock()
		delete(transfers, p.TransferID)
		tfMu.Unlock()
		log.Printf("[agent] 主端拒绝传输 tid=%s", p.TransferID)
		return
	}
	if p.ChunkSize > 0 {
		tfMu.Lock()
		t.chunk = clampInt(p.ChunkSize, 1024, 1024*1024)
		tfMu.Unlock()
	}
	if t.direction != "pull" {
		return // push 方向等主端分片到达
	}
	cs := t.chunk
	seq := int64(0)
	for off := 0; off < len(t.buf); off += cs {
		end := off + cs
		if end > len(t.buf) {
			end = len(t.buf)
		}
		cp := proto.RCFileChunkPayload{
			SessionID: p.SessionID, TransferID: p.TransferID, Seq: seq,
			Data: base64.StdEncoding.EncodeToString(t.buf[off:end]),
		}
		env, _ := proto.NewEnvelope(proto.TypeRCFileChunk, nextSeq(), cp)
		if b, e := json.Marshal(env); e == nil {
			_ = conn.WriteMessage(b)
		}
		seq++
	}
	sendFileDone(conn, p.SessionID, p.TransferID, true, "", int64(len(t.buf)), t.expectSHA)
	tfMu.Lock()
	delete(transfers, p.TransferID)
	tfMu.Unlock()
}

// handleFileChunk 累积 push 分片，收满即落盘并校验 SHA-256。
func handleFileChunk(conn *ws.Conn, p proto.RCFileChunkPayload) {
	tfMu.Lock()
	t, ok := transfers[p.TransferID]
	if !ok {
		tfMu.Unlock()
		return
	}
	if t.nextSeq > 0 && p.Seq != t.nextSeq {
		tfMu.Unlock()
		sendFileDone(conn, p.SessionID, p.TransferID, false,
			fmt.Sprintf("分片序号不连续（期望 %d 收到 %d）", t.nextSeq, p.Seq), 0, "")
		tfMu.Lock()
		delete(transfers, p.TransferID)
		tfMu.Unlock()
		return
	}
	raw, err := base64.StdEncoding.DecodeString(p.Data)
	if err != nil {
		tfMu.Unlock()
		sendFileDone(conn, p.SessionID, p.TransferID, false, "分片 base64 解码失败", 0, "")
		return
	}
	t.nextSeq = p.Seq + 1
	t.buf = append(t.buf, raw...)
	t.received += int64(len(raw))
	if t.received < t.size {
		tfMu.Unlock()
		return
	}
	path, expect, total, data := t.path, t.expectSHA, t.received, t.buf
	delete(transfers, p.TransferID)
	tfMu.Unlock()

	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])
	if expect != "" && !strings.EqualFold(expect, actual) {
		sendFileDone(conn, p.SessionID, p.TransferID, false,
			fmt.Sprintf("校验失败 期望 %s 实得 %s", expect, actual), total, actual)
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		sendFileDone(conn, p.SessionID, p.TransferID, false, "写入失败: "+err.Error(), total, actual)
		return
	}
	log.Printf("[agent] 文件接收完成 tid=%s → %s（%dB sha256=%s）", p.TransferID, path, total, actual)
	sendFileDone(conn, p.SessionID, p.TransferID, true, "", total, actual)
}

// cleanupTransfers 会话结束清理未完成传输。
func cleanupTransfers() {
	tfMu.Lock()
	if len(transfers) > 0 {
		log.Printf("[agent] 清理未完成的会话内传输 %d 项", len(transfers))
	}
	transfers = map[string]*transfer{}
	tfMu.Unlock()
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// captureImage 返回一帧图像（平台采集或合成帧），供画面控制后处理。
func captureImage() image.Image {
	switch runtime.GOOS {
	case "darwin":
		return captureImageViaCmd("screencapture", "-x", "-t", "png", shotPath)
	case "linux":
		if _, err := exec.LookPath("scrot"); err == nil {
			return captureImageViaCmd("scrot", "-o", shotPath)
		}
		if _, err := exec.LookPath("import"); err == nil {
			return captureImageViaCmd("import", "-window", "root", shotPath)
		}
	}
	return syntheticImage()
}

func captureImageViaCmd(name string, args ...string) image.Image {
	_ = exec.Command(name, args...).Run()
	f, err := os.Open(shotPath)
	if err != nil {
		return syntheticImage()
	}
	defer f.Close()
	img, _, err := image.Decode(f)
	if err != nil {
		return syntheticImage()
	}
	return img
}

func syntheticImage() image.Image {
	const w, h = 1280, 800
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{uint8(x % 255), uint8(y % 255), 90, 255})
		}
	}
	return img
}

func encodeJPEGImg(img image.Image) ([]byte, int, int) {
	b := &bytes.Buffer{}
	if err := jpeg.Encode(b, img, &jpeg.Options{Quality: 55}); err != nil {
		return nil, 0, 0
	}
	return b.Bytes(), img.Bounds().Dx(), img.Bounds().Dy()
}
