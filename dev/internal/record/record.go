// Package record 实现远控会话录像的加密留存（protocol.md §5）。
//
// 文件格式（.yrec）：
//
//	行1: "YDREC01"                — 魔数+版本
//	行2: <metadata JSON>          — 会话元数据（session/device/operator/started_at）
//	之后: N 个加密块               — [4B 大端明文长度][12B nonce][AES-256-GCM 密文+16B tag]
//
// 每块明文为一帧原始媒体帧（24B 帧头 + payload，§8.3）。密钥按会话派生：
// sha256(master || session_id)，master 来自 keystore（YUDUAN_RECORD_KEY，
// 未配置时由 HMAC 密钥派生——开发态兜底，生产必须显式配置独立密钥）。
// 落盘始终为密文；回放需持 master 密钥（ReadAll）。
// 留存期由 Janitor 按 mtime 清理（默认 90 天）。
package record

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Magic 是 .yrec 文件首行标识（含版本）。
const Magic = "YDREC01"

// Meta 是录像文件的会话元数据（明文 JSON 首行，便于运维检索/审计）。
type Meta struct {
	SessionID  string    `json:"session_id"`
	DeviceID   string    `json:"device_id"`
	Hostname   string    `json:"hostname,omitempty"`
	Operator   string    `json:"operator"`
	StartedAt  time.Time `json:"started_at"`
	Codec      string    `json:"codec,omitempty"`
	Transport  string    `json:"transport,omitempty"`
	Consent    bool      `json:"consent"`
	RecordedAt time.Time `json:"recorded_at"`
}

// Writer 将媒体帧逐块加密写入一个 .yrec 文件。
type Writer struct {
	f      *os.File
	gcm    cipher.AEAD
	Path   string
	Meta   Meta
	frames int
	bytes  int64 // 密文总字节数（不含头部）
	closed bool
}

// DeriveMaster 由 HMAC 密钥派生录像主密钥（开发态兜底）。
// 生产环境应通过 YUDUAN_RECORD_KEY 显式提供独立 32 字节密钥（见 keystore.LoadRecordKey）。
func DeriveMaster(hmacSecret string) []byte {
	sum := sha256.Sum256([]byte("yuduan-record:" + hmacSecret))
	return sum[:]
}

// sessionKey 按会话派生块密钥：sha256(master || session_id)。
func sessionKey(master []byte, sessionID string) []byte {
	h := sha256.New()
	h.Write(master)
	h.Write([]byte(sessionID))
	return h.Sum(nil)
}

// Open 创建录像文件并写入头部。目录不存在会自动创建（0o700）。
func Open(dir string, master []byte, meta Meta) (*Writer, error) {
	if dir == "" {
		return nil, fmt.Errorf("record: 录像目录为空")
	}
	if meta.SessionID == "" {
		return nil, fmt.Errorf("record: session_id 不能为空")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("record: 创建目录失败: %w", err)
	}
	meta.RecordedAt = time.Now().UTC()
	name := fmt.Sprintf("%s_%s_%s.yrec",
		meta.StartedAt.UTC().Format("20060102-150405"),
		sanitize(meta.DeviceID), sanitize(meta.SessionID))
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("record: 创建文件失败: %w", err)
	}
	key := sessionKey(master, meta.SessionID)
	block, err := aes.NewCipher(key)
	if err != nil {
		f.Close()
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		f.Close()
		return nil, err
	}
	mj, _ := json.Marshal(meta)
	if _, err := fmt.Fprintf(f, "%s\n%s\n", Magic, mj); err != nil {
		f.Close()
		return nil, err
	}
	return &Writer{f: f, gcm: gcm, Path: path, Meta: meta}, nil
}

// WriteFrame 追加一帧（任意字节序列，典型为 24B 帧头+payload 的二进制媒体帧）。
// 每帧独立 nonce，独立可解密；单帧损坏不影响其余帧（GCM tag 校验失败即报错）。
func (w *Writer) WriteFrame(raw []byte) error {
	return w.write(raw)
}

func (w *Writer) write(raw []byte) error {
	if w.closed {
		return fmt.Errorf("record: writer 已关闭")
	}
	nonce := make([]byte, w.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := w.gcm.Seal(nil, nonce, raw, nil)
	var lbuf [4]byte
	binary.BigEndian.PutUint32(lbuf[:], uint32(len(raw)))
	if _, err := w.f.Write(lbuf[:]); err != nil {
		return err
	}
	if _, err := w.f.Write(nonce); err != nil {
		return err
	}
	if _, err := w.f.Write(ct); err != nil {
		return err
	}
	w.frames++
	w.bytes += int64(4 + len(nonce) + len(ct))
	return nil
}

// Close 落盘并关闭文件，返回 (路径, 帧数, 密文字节数)。
func (w *Writer) Close() (string, int, int64) {
	if w.closed {
		return w.Path, w.frames, w.bytes
	}
	w.closed = true
	_ = w.f.Sync()
	_ = w.f.Close()
	return w.Path, w.frames, w.bytes
}

// Frames 返回已写入帧数。
func (w *Writer) Frames() int { return w.frames }

// Recording 汇总一次回放的元数据与帧。
type Recording struct {
	Meta   Meta
	Frames [][]byte
}

// ReadAll 解密整个录像文件（回放/审计用；需 master 密钥）。
func ReadAll(path string, master []byte) (*Recording, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.SplitN(string(data), "\n", 3)
	if len(lines) < 3 || lines[0] != Magic {
		return nil, fmt.Errorf("record: 非法录像文件 %s", filepath.Base(path))
	}
	var rec Recording
	if err := json.Unmarshal([]byte(lines[1]), &rec.Meta); err != nil {
		return nil, fmt.Errorf("record: 元数据解析失败: %w", err)
	}
	key := sessionKey(master, rec.Meta.SessionID)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	body := []byte(lines[2])
	for off := 0; off < len(body); {
		if off+4 > len(body) {
			return nil, fmt.Errorf("record: 文件截断（长度头）")
		}
		plen := binary.BigEndian.Uint32(body[off : off+4])
		off += 4
		ns := gcm.NonceSize()
		if off+ns+int(plen)+16 > len(body) {
			return nil, fmt.Errorf("record: 文件截断（块体）")
		}
		nonce := body[off : off+ns]
		off += ns
		ct := body[off : off+int(plen)+16]
		off += int(plen) + 16
		pt, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			return nil, fmt.Errorf("record: 块解密失败（密钥不符或文件被篡改）: %w", err)
		}
		rec.Frames = append(rec.Frames, pt)
	}
	return &rec, nil
}

// CleanOnce 删除目录中 mtime 超过 retentionDays 的 .yrec 文件，返回被删除文件名。
func CleanOnce(dir string, retentionDays int) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	cutoff := time.Now().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	var removed []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yrec") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(filepath.Join(dir, e.Name())); err == nil {
				removed = append(removed, e.Name())
			}
		}
	}
	sort.Strings(removed)
	return removed, nil
}

// StartJanitor 启动周期清理（默认每小时扫一次），返回停止函数。
func StartJanitor(dir string, retentionDays int, interval time.Duration) (stop func()) {
	if interval <= 0 {
		interval = time.Hour
	}
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if removed, err := CleanOnce(dir, retentionDays); err == nil && len(removed) > 0 {
					for _, n := range removed {
						// 留存期清理是策略行为而非异常：仅提示，不进审计告警。
						fmt.Printf("[record] 留存期清理: %s\n", n)
					}
				}
			}
		}
	}()
	return func() { close(done) }
}

// sanitize 清洗文件名成分（防路径注入）。
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return -1
	}, s)
	if len(s) > 40 {
		s = s[:40]
	}
	if s == "" {
		s = "unknown"
	}
	return s
}
