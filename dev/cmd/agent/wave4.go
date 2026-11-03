// 波次 4：后台文件分发与采集（PRD 5.4）的 Go 参考副端实现。
//
// 与波次 2 的「远控会话内文件传输」是两条不同边界：
//   - rc_wave2.go 只在既有远控会话内、按会话作用域收发（有员工在场，可控）；
//   - 本文件是无远控会话的后台分发/采集（file_push / file_pull），属于「终端可能被无人值守
//     操作」的能力，因此默认关闭：必须显式配置允许根才放行，路径逃逸一律拒绝（铁律 5）。
//
// 与 Rust 生产副端保持同构（铁律 2/9）：同一套动作名、同一套允许根校验规则、
// 同样的诚实回退（能力不足就回告失败原因，绝不伪造成功）。
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"yuduan/internal/proto"
	"yuduan/internal/ws"
)

func init() { registerWaveAction(wave4Command) }

// ---- 常量与默认 ----

const (
	fsDefaultChunk   = 256 * 1024 // 默认分片 256KB（PRD 5.4：分片大小可配）
	fsMinChunk       = 4 * 1024
	fsMaxChunk       = 2 * 1024 * 1024
	fsMaxFileBytes   = 512 << 20 // 单文件上限 512MB（超限一律拒绝，避免撑爆终端磁盘）
	fsMaxPullEntries = 2000      // 单次采集的文件条目上限
	fsMaxPullBytes   = 2 << 30   // 单次采集的字节总量上限
	fsIdleTTL        = 30 * time.Minute
)

// ---- 允许根（allowlist）----
// 未配置 ⇒ 未启用。默认拒绝是合规姿态：后台写文件/采集文件的权限必须由终端侧
// 显式授予（部署侧写入服务环境变量），而不是中枢单方面决定。

func fsWriteRoot() string { return strings.TrimSpace(os.Getenv("YUDUAN_FS_WRITE_ROOT")) }

func fsPullRoot() string { return strings.TrimSpace(os.Getenv("YUDUAN_FS_PULL_ROOT")) }

// ---- 路径安全 ----

// fsRejectTraversal 拒绝显式相对路径穿越段（哪怕最终路径仍在根内，也不接受该写法本身）。
func fsRejectTraversal(p string) error {
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return errors.New("路径含 '..' 穿越段，已拒绝")
		}
	}
	return nil
}

// fsResolveInRoot 把目标路径解析到 root 内部，三重防护：
//  1. 字面量检查（.. 段）；
//  2. filepath.Rel 判定是否真的落在 root 下（挡住 /rootX 这类前缀冒充）；
//  3. EvalSymlinks 解析，挡住「根内软链接指向根外」的经典穿越。
func fsResolveInRoot(root, p string) (string, error) {
	if root == "" {
		return "", errors.New("本机未配置文件允许根")
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", errors.New("允许根路径非法")
	}
	rootAbs = filepath.Clean(rootAbs)
	// 根路径自身可能含符号链接段（如 macOS 的 /tmp → /private/tmp），
	// 先归一化到真实路径，再与 EvalSymlinks 后的目标对比，避免误判越界。
	if realRoot, rErr := filepath.EvalSymlinks(rootAbs); rErr == nil {
		rootAbs = realRoot
	}
	if err := fsRejectTraversal(p); err != nil {
		return "", err
	}
	var target string
	if filepath.IsAbs(p) {
		target = filepath.Clean(p)
	} else {
		target = filepath.Join(rootAbs, p)
	}
	if !fsInside(rootAbs, target) {
		return "", fmt.Errorf("目标路径不在允许根 %s 内，已拒绝", rootAbs)
	}
	// 符号链接穿越：能解析的最终路径必须仍在根内（目标文件不存在时改判其父目录）
	real := target
	if r, rErr := filepath.EvalSymlinks(target); rErr == nil {
		real = r
	} else {
		parent := filepath.Dir(target)
		if rp, rpErr := filepath.EvalSymlinks(parent); rpErr == nil {
			real = filepath.Join(rp, filepath.Base(target))
		}
	}
	if !fsInside(rootAbs, real) {
		return "", fmt.Errorf("目标路径经符号链接解析后越出允许根 %s，已拒绝", rootAbs)
	}
	return target, nil
}

// fsInside 判定 child 是否严格位于 parent 之内。
func fsInside(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func fsClampChunk(n int) int {
	switch {
	case n <= 0:
		return fsDefaultChunk
	case n < fsMinChunk:
		return fsMinChunk
	case n > fsMaxChunk:
		return fsMaxChunk
	}
	return n
}

// ---- 下发（file_push）状态 ----

type fsPushState struct {
	id        string
	path      string
	f         *os.File
	size      int64
	expectSHA string
	chunk     int
	have      int64
	nextSeq   int64
	bits      []byte
	lastUse   time.Time
}

// fsPullState 采集方向的连续读状态：同一文件必须顺序推进，方能串接出全文件 SHA-256。
type fsPullState struct {
	h    hash.Hash
	next int64
}

var (
	fsMu     sync.Mutex
	fsPushes = map[string]*fsPushState{}
	fsPulls  = map[string]*fsPullState{}
)

// fsFailOnce 一次性故障注入：YUDUAN_E2E_CHUNK_FAIL_AT=N 时，下一个到达分片序号 N 的
// 传输会被动失败一次（模拟链路中断），用于 e2e 验证断点续传。未配置则完全不生效，
// 生产路径零成本（仅一次环境变量读取 + 一个 bool 判断）。
var (
	fsFailOnce  sync.Once
	fsFailAt    int64 = -1
	fsFailArmed bool
	fsFailUsed  bool
)

func fsFailConfigured() {
	fsFailOnce.Do(func() {
		v := strings.TrimSpace(os.Getenv("YUDUAN_E2E_CHUNK_FAIL_AT"))
		if v == "" {
			return
		}
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			fsFailAt, fsFailArmed = n, true
			log.Printf("[agent] ⚠️ e2e 故障注入已启用：分片序号 %d 将触发一次链路中断", n)
		}
	})
}

// fsShouldFail 返回 true 时本次分片回复失败（每个进程仅触发一次）。
func fsShouldFail(seq int64) bool {
	fsFailConfigured()
	if !fsFailArmed || fsFailUsed || seq != fsFailAt {
		return false
	}
	fsFailUsed = true
	return true
}

// fsSetBit 置位并返回位图的 base64 表示（供中枢侧断点续传观测）。
func fsSetBit(bits *[]byte, seq int64) string {
	need := seq>>3 + 1
	if int64(len(*bits)) < need {
		nb := make([]byte, need)
		copy(nb, *bits)
		*bits = nb
	}
	(*bits)[seq>>3] |= 1 << (uint(seq) & 7)
	return fsBitmapOf(*bits)
}

func fsBitmapOf(bits []byte) string {
	if len(bits) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(bits)
}

func fsCountBits(bits []byte) int64 {
	n := int64(0)
	for _, b := range bits {
		for i := 0; i < 8; i++ {
			if b&(1<<uint(i)) != 0 {
				n++
			}
		}
	}
	return n
}

// fsDropPush 关闭并清理一次下发状态（失败/中止/完成都走这里，避免句柄与半文件残留）。
func fsDropPush(id string) {
	fsMu.Lock()
	defer fsMu.Unlock()
	if st, ok := fsPushes[id]; ok && st.f != nil {
		_ = st.f.Close()
	}
	delete(fsPushes, id)
}

// fsSweepIdle 清理超时无进展的下发状态（链路或中枢异常中断后不残留句柄）。
func fsSweepIdle() {
	fsMu.Lock()
	defer fsMu.Unlock()
	for id, st := range fsPushes {
		if time.Since(st.lastUse) > fsIdleTTL {
			if st.f != nil {
				_ = st.f.Close()
			}
			delete(fsPushes, id)
			log.Printf("[agent] 清理超时未完成的下发传输 %s", id)
		}
	}
}

// ---- 指令分发 ----

// wave4Command 处理 file.* 动作；非本波次动作返回 false 交还给主分发链。
func wave4Command(conn *ws.Conn, c proto.CommandPayload) bool {
	if !strings.HasPrefix(c.Action, proto.Wave4ActionPrefix) {
		return false
	}
	res := proto.ResultPayload{TaskID: c.TaskID, State: "success"}
	var (
		body string
		err  error
		ok   bool
	)
	switch c.Action {
	case proto.ActionFilePushBegin:
		var req proto.FilePushBeginReq
		if err = proto.DecodeWave4Body(c.Command, &req); err == nil {
			var resp proto.FilePushBeginResp
			resp, ok = fsHandlePushBegin(req)
			body, _ = proto.EncodeWave4Body(resp)
		}
	case proto.ActionFilePushChunk:
		var req proto.FilePushChunkReq
		if err = proto.DecodeWave4Body(c.Command, &req); err == nil {
			var resp proto.FilePushChunkResp
			resp, ok = fsHandlePushChunk(req)
			body, _ = proto.EncodeWave4Body(resp)
		}
	case proto.ActionFilePushEnd:
		var req proto.FilePushEndReq
		if err = proto.DecodeWave4Body(c.Command, &req); err == nil {
			var resp proto.FilePushEndResp
			resp, ok = fsHandlePushEnd(req)
			body, _ = proto.EncodeWave4Body(resp)
		}
	case proto.ActionFilePullMeta:
		var req proto.FilePullMetaReq
		if err = proto.DecodeWave4Body(c.Command, &req); err == nil {
			var resp proto.FilePullMetaResp
			resp, ok = fsHandlePullMeta(req)
			body, _ = proto.EncodeWave4Body(resp)
		}
	case proto.ActionFilePullChunk:
		var req proto.FilePullChunkReq
		if err = proto.DecodeWave4Body(c.Command, &req); err == nil {
			var resp proto.FilePullChunkResp
			resp, ok = fsHandlePullChunk(req)
			body, _ = proto.EncodeWave4Body(resp)
		}
	case proto.ActionFileAbort:
		var req proto.FileAbortReq
		if err = proto.DecodeWave4Body(c.Command, &req); err == nil {
			fsDoAbort(req)
			body, _ = proto.EncodeWave4Body(proto.FileAbortResp{OK: true})
			ok = true
		}
	default:
		res.State = "failed"
		res.OutputLog = "unknown wave4 action: " + c.Action
		sendResult(conn, res)
		return true
	}
	if err != nil {
		res.State = "failed"
		res.OutputLog = "参数解析失败: " + err.Error()
		sendResult(conn, res)
		return true
	}
	if !ok {
		res.State = "failed"
	}
	res.OutputLog = body
	sendResult(conn, res)
	return true
}

// ---- 下发实现 ----

func fsHandlePushBegin(req proto.FilePushBeginReq) (proto.FilePushBeginResp, bool) {
	resp := proto.FilePushBeginResp{TransferID: req.TransferID}
	root := fsWriteRoot()
	if root == "" {
		resp.Error = "本机未配置文件写入根（YUDUAN_FS_WRITE_ROOT），拒绝接收下发文件"
		return resp, false
	}
	if req.Path == "" {
		resp.Error = "缺少目标路径"
		return resp, false
	}
	if req.Size < 0 || req.Size > fsMaxFileBytes {
		resp.Error = fmt.Sprintf("文件大小非法或超过 %dMB 上限", fsMaxFileBytes>>20)
		return resp, false
	}
	target, err := fsResolveInRoot(root, req.Path)
	if err != nil {
		resp.Error = err.Error()
		return resp, false
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		resp.Error = "创建目标目录失败: " + err.Error()
		return resp, false
	}
	exists := int64(0)
	if info, statErr := os.Stat(target); statErr == nil {
		if info.IsDir() {
			resp.Error = "目标路径是目录"
			return resp, false
		}
		exists = info.Size()
	}
	offset, resumed := int64(0), false
	switch {
	case req.Resume && req.Offset > 0 && exists >= req.Offset && req.Offset <= req.Size:
		offset, resumed = req.Offset, true
	case exists > 0 && !req.Resume && !req.Overwrite:
		resp.Error = "目标文件已存在（未允许覆盖/续传）"
		return resp, false
	}
	f, err := os.OpenFile(target, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		resp.Error = "打开目标文件失败: " + err.Error()
		return resp, false
	}
	if err := f.Truncate(offset); err != nil {
		_ = f.Close()
		resp.Error = "截断目标文件失败: " + err.Error()
		return resp, false
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		_ = f.Close()
		resp.Error = "定位目标文件失败: " + err.Error()
		return resp, false
	}
	chunk := fsClampChunk(req.ChunkSize)
	fsSweepIdle()
	fsMu.Lock()
	delete(fsPushes, req.TransferID)
	fsPushes[req.TransferID] = &fsPushState{
		id: req.TransferID, path: target, f: f, size: req.Size, expectSHA: req.Sha256,
		chunk: chunk, have: offset, nextSeq: offset / int64(chunk), lastUse: time.Now(),
	}
	fsMu.Unlock()
	resp.OK, resp.Offset, resp.Exists, resp.Size, resp.Resumed, resp.Path = true, offset, exists, req.Size, resumed, target
	log.Printf("[agent] 下发握手 tid=%s → %s 续传=%v offset=%d/%d", req.TransferID, target, resumed, offset, req.Size)
	return resp, true
}

func fsHandlePushChunk(req proto.FilePushChunkReq) (proto.FilePushChunkResp, bool) {
	resp := proto.FilePushChunkResp{}
	fsMu.Lock()
	st, ok := fsPushes[req.TransferID]
	fsMu.Unlock()
	if !ok {
		resp.Error = "传输不存在或已结束（请先 push_begin）"
		return resp, false
	}
	// e2e 一次性故障注入：模拟链路在此处中断（每个进程仅一次）
	if fsShouldFail(req.Seq) {
		log.Printf("[agent] 注入链路中断 tid=%s seq=%d（e2e 断点续传场景）", req.TransferID, req.Seq)
		fsDropPush(req.TransferID)
		resp.Error = "simulated link failure"
		return resp, false
	}
	if req.Seq != st.nextSeq {
		fsDropPush(req.TransferID)
		resp.Error = fmt.Sprintf("分片序号不连续（期望 %d 收到 %d），已中断本次传输", st.nextSeq, req.Seq)
		return resp, false
	}
	raw, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		resp.Error = "分片 base64 解码失败"
		return resp, false
	}
	n, err := st.f.Write(raw)
	if err != nil {
		fsDropPush(req.TransferID)
		resp.Error = "写入失败: " + err.Error()
		return resp, false
	}
	st.have += int64(n)
	st.nextSeq = req.Seq + 1
	st.lastUse = time.Now()
	bitmap := fsSetBit(&st.bits, req.Seq)
	_ = st.f.Sync() // 逐片落盘：进程异常退出也保留已传部分，供续传
	resp.OK, resp.Received, resp.Have, resp.Size = true, int64(n), st.have, st.size
	resp.ChunksDone, resp.Bitmap, resp.EOF = fsCountBits(st.bits), bitmap, st.have >= st.size
	return resp, true
}

func fsHandlePushEnd(req proto.FilePushEndReq) (proto.FilePushEndResp, bool) {
	resp := proto.FilePushEndResp{}
	fsMu.Lock()
	st, ok := fsPushes[req.TransferID]
	fsMu.Unlock()
	if !ok {
		resp.Error = "传输不存在或已结束（可能已被中断）"
		return resp, false
	}
	if st.have < st.size {
		resp.Error = fmt.Sprintf("文件未传完（已收 %d/%d），需续传", st.have, st.size)
		return resp, false
	}
	if err := st.f.Sync(); err != nil {
		resp.Error = "落盘失败: " + err.Error()
		return resp, false
	}
	sum, err := fsFileSHA256(st.path)
	if err != nil {
		resp.Error = "整文件校验失败（无法读取落盘文件）: " + err.Error()
		return resp, false
	}
	actual := hex.EncodeToString(sum)
	resp.Bytes, resp.Sha256, resp.Expected = st.have, actual, st.expectSHA
	resp.ChunksDone, resp.Bitmap = fsCountBits(st.bits), fsBitmapOf(st.bits)
	if st.expectSHA != "" && !strings.EqualFold(st.expectSHA, actual) {
		resp.Error = fmt.Sprintf("SHA-256 校验不一致（期望 %s 实得 %s）", st.expectSHA, actual)
		log.Printf("[agent] ❌ 下发文件校验失败 tid=%s → %s", req.TransferID, st.path)
		return resp, false
	}
	resp.OK = true
	fsDropPush(req.TransferID)
	log.Printf("[agent] 下发完成 tid=%s → %s（%dB sha256=%s…）", req.TransferID, st.path, st.have, actual[:16])
	return resp, true
}

// ---- 采集实现 ----

func fsHandlePullMeta(req proto.FilePullMetaReq) (proto.FilePullMetaResp, bool) {
	resp := proto.FilePullMetaResp{Entries: []proto.FilePullEntry{}}
	root := fsPullRoot()
	if root == "" {
		resp.Error = "本机未配置文件采集根（YUDUAN_FS_PULL_ROOT），拒绝采集"
		return resp, false
	}
	target, err := fsResolveInRoot(root, req.Path)
	if err != nil {
		resp.Error = err.Error()
		return resp, false
	}
	rootAbs, _ := filepath.Abs(root)
	resp.Root = filepath.Clean(rootAbs)
	info, err := os.Stat(target)
	if err != nil {
		resp.Error = "来源不存在: " + err.Error()
		return resp, false
	}
	if !info.IsDir() {
		resp.Entries = append(resp.Entries, proto.FilePullEntry{
			Rel: filepath.Base(target), Path: target, Size: info.Size(),
		})
		resp.OK = true
		return resp, true
	}
	if !req.Recursive {
		resp.Error = "来源是目录但未声明递归采集（recursive=true）"
		return resp, false
	}
	total := int64(0)
	walkErr := filepath.Walk(target, func(p string, fi os.FileInfo, werr error) error {
		if werr != nil {
			return nil // 单个不可读条目跳过，不阻断整次采集
		}
		if fi.IsDir() || !fi.Mode().IsRegular() {
			return nil // 跳过目录与非常规文件（含软链：避免采集出允许根之外的文件）
		}
		if len(resp.Entries) >= fsMaxPullEntries {
			return fmt.Errorf("采集条目超过上限 %d", fsMaxPullEntries)
		}
		total += fi.Size()
		if total > fsMaxPullBytes {
			return fmt.Errorf("采集字节总量超过上限 %dMB", fsMaxPullBytes>>20)
		}
		rel, relErr := filepath.Rel(target, p)
		if relErr != nil {
			rel = filepath.Base(p)
		}
		resp.Entries = append(resp.Entries, proto.FilePullEntry{Rel: filepath.ToSlash(rel), Path: p, Size: fi.Size()})
		return nil
	})
	if walkErr != nil {
		resp.Error = walkErr.Error()
		return resp, false
	}
	resp.OK = true
	log.Printf("[agent] 采集清单 path=%s 条目=%d", target, len(resp.Entries))
	return resp, true
}

func fsHandlePullChunk(req proto.FilePullChunkReq) (proto.FilePullChunkResp, bool) {
	resp := proto.FilePullChunkResp{Offset: req.Offset}
	root := fsPullRoot()
	if root == "" {
		resp.Error = "本机未配置文件采集根（YUDUAN_FS_PULL_ROOT），拒绝采集"
		return resp, false
	}
	target, err := fsResolveInRoot(root, req.Path)
	if err != nil {
		resp.Error = err.Error()
		return resp, false
	}
	info, err := os.Stat(target)
	if err != nil || !info.Mode().IsRegular() {
		resp.Error = "文件不存在或不是普通文件"
		return resp, false
	}
	size := info.Size()
	if req.Offset < 0 || req.Offset > size {
		resp.Error = "读取偏移越界"
		return resp, false
	}
	// 哈希必须在「同一文件的连续顺序读」上累加：offset 回到 0 或不连续时重开一次摘要。
	key := fmt.Sprintf("%s|%s", req.TaskID, target)
	fsMu.Lock()
	st, existed := fsPulls[key]
	if !existed || req.Offset == 0 || st.next != req.Offset {
		st = &fsPullState{h: sha256.New()}
		fsPulls[key] = st
	}
	fsMu.Unlock()

	f, err := os.Open(target)
	if err != nil {
		resp.Error = "打开文件失败: " + err.Error()
		return resp, false
	}
	defer f.Close()
	if _, err := f.Seek(req.Offset, io.SeekStart); err != nil {
		resp.Error = "定位失败: " + err.Error()
		return resp, false
	}
	buf := make([]byte, fsClampChunk(req.ChunkSize))
	n, rerr := io.ReadFull(f, buf)
	if rerr != nil && rerr != io.ErrUnexpectedEOF && rerr != io.EOF {
		resp.Error = "读取失败: " + rerr.Error()
		return resp, false
	}
	buf = buf[:n]
	_, _ = st.h.Write(buf)
	st.next = req.Offset + int64(n)
	resp.OK, resp.Data, resp.Read, resp.Size = true, base64.StdEncoding.EncodeToString(buf), int64(n), size
	resp.EOF = req.Offset+int64(n) >= size
	if resp.EOF {
		resp.Sha256 = hex.EncodeToString(st.h.Sum(nil))
		fsMu.Lock()
		delete(fsPulls, key)
		fsMu.Unlock()
	}
	return resp, true
}

func fsDoAbort(req proto.FileAbortReq) {
	if req.TransferID != "" {
		fsDropPush(req.TransferID)
	}
	if req.Path != "" {
		fsMu.Lock()
		for k := range fsPulls {
			if strings.HasSuffix(k, "|"+req.Path) {
				delete(fsPulls, k)
			}
		}
		fsMu.Unlock()
	}
}

// fsFileSHA256 流式计算文件 SHA-256（不全量入内存）。
func fsFileSHA256(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
