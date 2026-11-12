package record

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testFrame(i int) []byte {
	// 模拟 24B 帧头 + payload：magic YDYF + version + seq 递增 + 若干 payload 字节
	f := make([]byte, 24+i*7)
	copy(f, "YDYF")
	f[4] = 1
	f[8] = byte(i)
	for j := 24; j < len(f); j++ {
		f[j] = byte(i*31 + j)
	}
	return f
}

func TestRoundtripAndTamperDetection(t *testing.T) {
	dir := t.TempDir()
	master := DeriveMaster("dev-secret")
	meta := Meta{
		SessionID: "s-roundtrip", DeviceID: "dev-01", Hostname: "macbook",
		Operator: "admin", StartedAt: time.Now().UTC(), Consent: true,
	}
	w, err := Open(dir, master, meta)
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	var want [][]byte
	for i := 0; i < 5; i++ {
		fr := testFrame(i)
		if err := w.WriteFrame(fr); err != nil {
			t.Fatalf("WriteFrame #%d: %v", i, err)
		}
		want = append(want, fr)
	}
	path, frames, nbytes := w.Close()
	if frames != 5 || nbytes == 0 {
		t.Fatalf("Close 返回 frames=%d bytes=%d", frames, nbytes)
	}
	if filepath.Base(path) == "" || filepath.Ext(path) != ".yrec" {
		t.Fatalf("非法文件名 %s", path)
	}

	// 回放：逐帧字节相等
	rec, err := ReadAll(path, master)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if rec.Meta.SessionID != "s-roundtrip" || rec.Meta.Operator != "admin" || !rec.Meta.Consent {
		t.Fatalf("元数据不符: %+v", rec.Meta)
	}
	if len(rec.Frames) != len(want) {
		t.Fatalf("帧数不符: got %d want %d", len(rec.Frames), len(want))
	}
	for i := range want {
		if !bytes.Equal(rec.Frames[i], want[i]) {
			t.Fatalf("帧 #%d 内容不符", i)
		}
	}

	// 错误密钥 → 解密失败（不产生明文泄露）
	if _, err := ReadAll(path, DeriveMaster("wrong-key")); err == nil {
		t.Fatal("错误密钥应解密失败")
	}

	// 篡改密文 → GCM 校验失败
	data, _ := os.ReadFile(path)
	data[len(data)-1] ^= 0xFF
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAll(path, master); err == nil {
		t.Fatal("篡改后应解密失败")
	}
}

func TestSessionKeyIsolation(t *testing.T) {
	// 不同会话派生不同块密钥：拿会话 A 的文件用会话 B 的 master 派生路径解不开
	master := DeriveMaster("k")
	if bytes.Equal(sessionKey(master, "a"), sessionKey(master, "b")) {
		t.Fatal("不同会话的派生密钥不应相同")
	}
}

func TestCleanOnceByMtime(t *testing.T) {
	dir := t.TempDir()
	master := DeriveMaster("k")
	oldPath := filepath.Join(dir, "2020-0101-000000_dev_old.yrec")
	newPath := filepath.Join(dir, "2099-0101-000000_dev_new.yrec")
	for _, p := range []string{oldPath, newPath} {
		w, err := Open(dir, master, Meta{SessionID: "s-" + filepath.Base(p), DeviceID: "d"})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		_ = w.WriteFrame(testFrame(0))
		w.Close()
		// 统一改名以控制文件名（Open 自动命名，这里仅验证清理逻辑）
		os.Rename(w.Path, p)
	}
	past := time.Now().Add(-91 * 24 * time.Hour)
	future := time.Now().Add(24 * time.Hour)
	if err := os.Chtimes(oldPath, past, past); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(newPath, future, future); err != nil {
		t.Fatal(err)
	}
	removed, err := CleanOnce(dir, 90)
	if err != nil {
		t.Fatalf("CleanOnce: %v", err)
	}
	if len(removed) != 1 || removed[0] != "2020-0101-000000_dev_old.yrec" {
		t.Fatalf("应仅清理过期文件: %v", removed)
	}
	if _, err := os.Stat(newPath); err != nil {
		t.Fatal("未过期文件不应被删除")
	}
}

func TestRejectsBadInput(t *testing.T) {
	if _, err := Open(t.TempDir(), DeriveMaster("k"), Meta{SessionID: ""}); err == nil {
		t.Fatal("空 session_id 应拒绝")
	}
	if _, err := Open("", DeriveMaster("k"), Meta{SessionID: "s"}); err == nil {
		t.Fatal("空目录应拒绝")
	}
}
