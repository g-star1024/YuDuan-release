// wave4_dir_push_test.go —— v0.4.25「W4 目录下发（push 方向）」回归用例。
//
// 风险锚点：
//  1. 目录递归展开是 hub 侧纯增量编排，必须证明**单文件 push 与 v0.4.24 逐字节
//     等价**（transferID / Path / Overwrite / Resume / Offset / Sha256 / ChunkSize）。
//  2. 副端 fsPushes 以 TransferID 为 map key，若目录内 N 个文件复用同一 ID，
//     后续分片会覆盖前面文件造成串包（QA C-25）→ 必须逐文件唯一 ID。
//  3. 默认 LAN 零影响：非目录源不进入新分支；空目录不产生任何指令。
//  4. 铁律 5 诚实回告：超限 / 子文件失败必须明确报错，不得伪造成功。
//
// 测试替身：w4SendFileCmdFn 是生产代码里唯一的可替换间接层（默认恒为
// (*Hub).w4SendFileCmd）。本文件不用 t.Parallel，避免包级变量并发替换。
package hub

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"yuduan/internal/proto"
)

// ---- 测试替身：一个会说 file.push_* 协议的假副端 ----

type w4FakeAgent struct {
	mu     sync.Mutex
	begins []proto.FilePushBeginReq
	ends   []string
	data   map[string][]byte // transferID -> 已落盘字节

	failChunkAt   int // 全局第 N 个 chunk 注入一次失败（0=不注入）
	chunkN        int
	chunkFailed   bool
	failBeginPath map[string]bool // 指定 Path 的 push_begin 直接失败
	hardErr       error           // 注入网络层硬错误
}

func newW4FakeAgent() *w4FakeAgent {
	return &w4FakeAgent{data: map[string][]byte{}, failBeginPath: map[string]bool{}}
}

func (f *w4FakeAgent) send(_ *Hub, _ string, action, command string, _ time.Duration) (proto.ResultPayload, error) {
	if f.hardErr != nil {
		return proto.ResultPayload{}, f.hardErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	switch action {
	case proto.ActionFilePushBegin:
		var req proto.FilePushBeginReq
		if e := json.Unmarshal([]byte(command), &req); e != nil {
			return proto.ResultPayload{}, e
		}
		f.begins = append(f.begins, req)
		if f.failBeginPath[req.Path] {
			return proto.ResultPayload{State: "failed", OutputLog: "injected begin failure"}, nil
		}
		if req.Resume {
			if cur, ok := f.data[req.TransferID]; ok && int64(len(cur)) > req.Offset {
				f.data[req.TransferID] = cur[:req.Offset]
			}
		} else {
			f.data[req.TransferID] = nil
		}
		out, _ := json.Marshal(proto.FilePushBeginResp{
			OK: true, Offset: req.Offset, TransferID: req.TransferID, Size: req.Size,
		})
		return proto.ResultPayload{State: "success", OutputLog: string(out)}, nil

	case proto.ActionFilePushChunk:
		var req proto.FilePushChunkReq
		if e := json.Unmarshal([]byte(command), &req); e != nil {
			return proto.ResultPayload{}, e
		}
		f.chunkN++
		if f.failChunkAt > 0 && f.chunkN == f.failChunkAt && !f.chunkFailed {
			f.chunkFailed = true
			return proto.ResultPayload{State: "failed", OutputLog: "injected chunk failure"}, nil
		}
		raw, e := base64.StdEncoding.DecodeString(req.Data)
		if e != nil {
			return proto.ResultPayload{}, e
		}
		f.data[req.TransferID] = append(f.data[req.TransferID], raw...)
		have := int64(len(f.data[req.TransferID]))
		out, _ := json.Marshal(proto.FilePushChunkResp{OK: true, Have: have, Received: int64(len(raw))})
		return proto.ResultPayload{State: "success", OutputLog: string(out)}, nil

	case proto.ActionFilePushEnd:
		var req proto.FilePushEndReq
		if e := json.Unmarshal([]byte(command), &req); e != nil {
			return proto.ResultPayload{}, e
		}
		f.ends = append(f.ends, req.TransferID)
		body := f.data[req.TransferID]
		sum := sha256.Sum256(body)
		out, _ := json.Marshal(proto.FilePushEndResp{
			OK: true, Bytes: int64(len(body)), Sha256: hex.EncodeToString(sum[:]),
		})
		return proto.ResultPayload{State: "success", OutputLog: string(out)}, nil
	}
	return proto.ResultPayload{}, fmt.Errorf("unexpected action %q", action)
}

func w4HookAgent(t *testing.T, f *w4FakeAgent) {
	t.Helper()
	old := w4SendFileCmdFn
	w4SendFileCmdFn = f.send
	t.Cleanup(func() { w4SendFileCmdFn = old })
}

// deviceOnlineLocal 只查 conns 里 key 是否存在；注入替身后 sendToDevice 不会被调用，
// 故放一个占位 value 即可，避免为单测拉起真实 WebSocket 服务端。
func w4TestHub(devID string) *Hub {
	h := NewHub(HubConfig{})
	h.mu.Lock()
	h.conns[devID] = nil
	h.mu.Unlock()
	return h
}

func w4Write(t *testing.T, dir, rel, content string) string {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func w4SHA(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// ---- 用例 1：单文件回归（默认行为逐字节等价）----

func TestW4DirPush_SingleFileByteEquivalent(t *testing.T) {
	dir := t.TempDir()
	src := w4Write(t, dir, "pkg.bin", "single-file-baseline")
	const devID = "dev-1"
	h := w4TestHub(devID)
	f := newW4FakeAgent()
	w4HookAgent(t, f)

	task := &W4FileTask{ID: "fs-regression", Kind: "push", Source: src, Dest: "dest/pkg.bin"}
	rec := W4FileRec{DeviceID: devID}
	if err := h.w4PushToDevice(task, devID, &rec); err != nil {
		t.Fatalf("单文件 push 失败: %v", err)
	}
	if len(f.begins) != 1 || len(f.ends) != 1 {
		t.Fatalf("单文件应恰好 1 次 begin/end，实得 begin=%d end=%d", len(f.begins), len(f.ends))
	}
	b := f.begins[0]
	if b.TransferID != "fs-regression-dev-1" {
		t.Errorf("transferID 被改动: got=%q want=%q", b.TransferID, "fs-regression-dev-1")
	}
	if b.Path != "dest/pkg.bin" {
		t.Errorf("Path 被改动: got=%q want=%q", b.Path, "dest/pkg.bin")
	}
	if b.Size != int64(len("single-file-baseline")) {
		t.Errorf("Size 不符: got=%d", b.Size)
	}
	if b.Sha256 != w4SHA(t, src) {
		t.Error("Sha256 不符")
	}
	if b.ChunkSize != w4ChunkSize {
		t.Errorf("ChunkSize 被改动: got=%d want=%d", b.ChunkSize, w4ChunkSize)
	}
	if !b.Overwrite || b.Resume || b.Offset != 0 {
		t.Errorf("首传标志被改动: Overwrite=%v Resume=%v Offset=%d", b.Overwrite, b.Resume, b.Offset)
	}
	if f.ends[0] != "fs-regression-dev-1" {
		t.Errorf("push_end transferID 不符: %q", f.ends[0])
	}
	if rec.Bytes != int64(len("single-file-baseline")) || rec.SHA256 != w4SHA(t, src) {
		t.Errorf("rec 统计不符: Bytes=%d SHA=%q", rec.Bytes, rec.SHA256)
	}
}

// ---- 用例 2：空目录（零指令、不失败）----

func TestW4DirPush_EmptyDirNoCommands(t *testing.T) {
	dir := t.TempDir()
	const devID = "dev-1"
	h := w4TestHub(devID)
	f := newW4FakeAgent()
	w4HookAgent(t, f)

	task := &W4FileTask{ID: "fs-empty", Kind: "push", Source: dir, Dest: "dest"}
	rec := W4FileRec{DeviceID: devID}
	if err := h.w4PushToDevice(task, devID, &rec); err != nil {
		t.Fatalf("空目录不应报错: %v", err)
	}
	if len(f.begins) != 0 || len(f.ends) != 0 {
		t.Fatalf("空目录不应下发任何指令: begin=%d end=%d", len(f.begins), len(f.ends))
	}
	if rec.Bytes != 0 {
		t.Errorf("空目录 rec.Bytes 应为 0，实得 %d", rec.Bytes)
	}
}

// ---- 用例 3：嵌套目录（rel/ToSlash/dest 拼接 + 唯一 transferID）----

func TestW4DirPush_NestedRelAndUniqueTransferIDs(t *testing.T) {
	dir := t.TempDir()
	w4Write(t, dir, "a.txt", "aaa")
	w4Write(t, dir, "sub/b.txt", "bbbb")
	w4Write(t, dir, "sub/deep/c.txt", "cc")
	if err := os.MkdirAll(filepath.Join(dir, "sub", "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	const devID = "dev-1"
	h := w4TestHub(devID)
	f := newW4FakeAgent()
	w4HookAgent(t, f)

	task := &W4FileTask{ID: "fs-dir", Kind: "push", Source: dir, Dest: "target/root"}
	rec := W4FileRec{DeviceID: devID}
	if err := h.w4PushToDevice(task, devID, &rec); err != nil {
		t.Fatalf("嵌套目录下发失败: %v", err)
	}
	if len(f.begins) != 3 || len(f.ends) != 3 {
		t.Fatalf("应展开 3 个普通文件，实得 begin=%d end=%d", len(f.begins), len(f.ends))
	}
	want := map[string]int64{
		"target/root/a.txt":          3,
		"target/root/sub/b.txt":      4,
		"target/root/sub/deep/c.txt": 2,
	}
	seenID := map[string]bool{}
	for _, b := range f.begins {
		n, ok := want[b.Path]
		if !ok {
			t.Errorf("非预期 Path（空目录或 rel 拼接错误）: %q", b.Path)
			continue
		}
		if b.Size != n {
			t.Errorf("%s Size=%d want=%d", b.Path, b.Size, n)
		}
		if strings.Contains(b.Path, "\\") {
			t.Errorf("rel 未 ToSlash: %q", b.Path)
		}
		if seenID[b.TransferID] {
			t.Errorf("transferID 重复会导致副端 fsPushes 串包: %q", b.TransferID)
		}
		seenID[b.TransferID] = true
		if !strings.HasSuffix(b.TransferID, "-f0") &&
			!strings.HasSuffix(b.TransferID, "-f1") &&
			!strings.HasSuffix(b.TransferID, "-f2") {
			t.Errorf("目录子文件 transferID 缺序号后缀: %q", b.TransferID)
		}
		if b.TransferID == "fs-dir-dev-1" {
			t.Error("目录子文件不得复用单文件形态的 transferID")
		}
	}
	if rec.Bytes != 3+4+2 {
		t.Errorf("rec.Bytes=%d want=9", rec.Bytes)
	}
	if rec.SHA256 != "" {
		t.Errorf("目录不应伪造单一 SHA256，实得 %q", rec.SHA256)
	}
}

// ---- 用例 4：非普通文件跳过（symlink / 目录符号链接）----

func TestW4DirPush_SkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	w4Write(t, dir, "real.txt", "R")
	if err := os.Symlink(filepath.Join(dir, "real.txt"), filepath.Join(dir, "link.txt")); err != nil {
		t.Skipf("当前环境不允许创建符号链接，跳过: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "outside"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "outside"), filepath.Join(dir, "linkdir")); err != nil {
		t.Skipf("当前环境不允许创建符号链接，跳过: %v", err)
	}
	const devID = "dev-1"
	h := w4TestHub(devID)
	f := newW4FakeAgent()
	w4HookAgent(t, f)

	task := &W4FileTask{ID: "fs-sym", Kind: "push", Source: dir, Dest: "d"}
	rec := W4FileRec{DeviceID: devID}
	if err := h.w4PushToDevice(task, devID, &rec); err != nil {
		t.Fatalf("含 symlink 目录下发失败: %v", err)
	}
	if len(f.begins) != 1 {
		t.Fatalf("只应下发 1 个普通文件，实得 %d: %+v", len(f.begins), f.begins)
	}
	if f.begins[0].Path != "d/real.txt" {
		t.Errorf("Path 不符: %q", f.begins[0].Path)
	}
}

// ---- 用例 5：两道上限（文件数 / 字节总量），校验失败必须零指令 ----

func TestW4DirPush_FileCountLimit(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i <= w4MaxDirFiles; i++ { // 故意多 1 个
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%05d.dat", i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const devID = "dev-1"
	h := w4TestHub(devID)
	f := newW4FakeAgent()
	w4HookAgent(t, f)

	task := &W4FileTask{ID: "fs-limit", Kind: "push", Source: dir, Dest: "d"}
	rec := W4FileRec{DeviceID: devID}
	err := h.w4PushToDevice(task, devID, &rec)
	if err == nil || !strings.Contains(err.Error(), "文件数超过上限") {
		t.Fatalf("应明确报文件数超限，实得 err=%v", err)
	}
	if len(f.begins) != 0 {
		t.Errorf("校验失败不得产生半成品下发: begin=%d", len(f.begins))
	}
}

func TestW4DirPush_TotalBytesLimit(t *testing.T) {
	dir := t.TempDir()
	// 稀疏文件：只占目录项元数据，不实际分配 2GiB 磁盘（WalkDir 仅 d.Info() 不读内容）。
	big := filepath.Join(dir, "big.dat")
	fp, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := fp.Truncate(int64(w4MaxDirBytes) + 1); err != nil {
		fp.Close()
		t.Skipf("当前文件系统不支持创建稀疏大文件，跳过: %v", err)
	}
	fp.Close()

	const devID = "dev-1"
	h := w4TestHub(devID)
	f := newW4FakeAgent()
	w4HookAgent(t, f)

	task := &W4FileTask{ID: "fs-bytes", Kind: "push", Source: dir, Dest: "d"}
	rec := W4FileRec{DeviceID: devID}
	err = h.w4PushToDevice(task, devID, &rec)
	if err == nil || !strings.Contains(err.Error(), "总字节超过上限") {
		t.Fatalf("应明确报字节总量超限，实得 err=%v", err)
	}
	if len(f.begins) != 0 {
		t.Errorf("校验失败不得产生半成品下发: begin=%d", len(f.begins))
	}
}

// ---- 用例 6：子文件失败保留已完成记录、整体诚实回告 ----

func TestW4DirPush_PartialFailureKeepsCompleted(t *testing.T) {
	dir := t.TempDir()
	w4Write(t, dir, "a.txt", "aaa")
	w4Write(t, dir, "b.txt", "bbbb")
	w4Write(t, dir, "c.txt", "cc")
	const devID = "dev-1"
	h := w4TestHub(devID)
	f := newW4FakeAgent()
	f.failBeginPath["d/b.txt"] = true
	w4HookAgent(t, f)

	task := &W4FileTask{ID: "fs-partial", Kind: "push", Source: dir, Dest: "d"}
	rec := W4FileRec{DeviceID: devID}
	err := h.w4PushToDevice(task, devID, &rec)
	if err == nil || !strings.Contains(err.Error(), "部分失败") || !strings.Contains(err.Error(), "成功 2/3") {
		t.Fatalf("应汇总为部分失败（成功 2/3），实得 err=%v", err)
	}
	if len(f.begins) != 3 {
		t.Errorf("子文件失败不应中断后续文件: begin=%d want=3", len(f.begins))
	}
	if len(f.ends) != 2 {
		t.Errorf("成功文件应有 2 次 push_end，实得 %d", len(f.ends))
	}
	if rec.Bytes != 3+2 {
		t.Errorf("已完成记录应保留: rec.Bytes=%d want=5", rec.Bytes)
	}
}

// ---- 用例 7：断点续传基线不变（抽离后重试语义不回归）----

func TestW4DirPush_ResumeBaselineUnchanged(t *testing.T) {
	dir := t.TempDir()
	content := strings.Repeat("Z", 2*w4ChunkSize+100) // 3 个分片
	src := w4Write(t, dir, "big.bin", content)
	const devID = "dev-1"
	h := w4TestHub(devID)
	f := newW4FakeAgent()
	f.failChunkAt = 2 // 第 1 片成功后第 2 片失败 → confirmed>0 → 触发续传重试
	w4HookAgent(t, f)

	task := &W4FileTask{ID: "fs-resume", Kind: "push", Source: src, Dest: "dest/big.bin"}
	rec := W4FileRec{DeviceID: devID}
	if err := h.w4PushToDevice(task, devID, &rec); err != nil {
		t.Fatalf("断点续传后应最终成功: %v", err)
	}
	if len(f.begins) != 2 {
		t.Fatalf("应发生 1 次续传握手（共 2 次 begin），实得 %d", len(f.begins))
	}
	if f.begins[0].Resume || f.begins[0].Offset != 0 {
		t.Errorf("首传不得带续传标志: %+v", f.begins[0])
	}
	if !f.begins[1].Resume || f.begins[1].Offset <= 0 {
		t.Errorf("第 2 轮必须 Resume=true 且 Offset>0: %+v", f.begins[1])
	}
	if rec.Bytes != int64(len(content)) || rec.SHA256 != w4SHA(t, src) {
		t.Errorf("续传后统计/摘要不符: Bytes=%d SHA=%q", rec.Bytes, rec.SHA256)
	}
}

// ---- 用例 8：设备离线守卫不变（目录分支也必须先判在线）----

func TestW4DirPush_OfflineGuardUnchanged(t *testing.T) {
	dir := t.TempDir()
	w4Write(t, dir, "a.txt", "a")
	h := NewHub(HubConfig{}) // 故意不登记任何在线设备
	f := newW4FakeAgent()
	w4HookAgent(t, f)

	task := &W4FileTask{ID: "fs-off", Kind: "push", Source: dir, Dest: "d"}
	rec := W4FileRec{DeviceID: "dev-offline"}
	err := h.w4PushToDevice(task, "dev-offline", &rec)
	if err == nil || !strings.Contains(err.Error(), "设备离线") {
		t.Fatalf("离线守卫失效: err=%v", err)
	}
	if len(f.begins) != 0 {
		t.Errorf("离线不得下发: begin=%d", len(f.begins))
	}
}
