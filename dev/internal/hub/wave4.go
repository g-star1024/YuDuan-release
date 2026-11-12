// wave4.go —— 波次 4 中枢编排（W4-1 文件/目录下发与拉取 / W4-2 周期同步 / W4-3 断点续传+哈希
// / W4-4 批量脚本+异常高亮 / W4-5 危险操作二次确认+审批）。
//
// 设计：不修改 hub.go / store.go / proto.go（多波次并行集成纪律）。运行时任务态以
// 本文件内存表为权威（e2e 默认内存模式）；*PostgresStore 时做尽力而为双写。
// 副端侧复用 cmd/agent/wave4.go 已实现的 file.* 协议（fsHandlePushBegin/Chunk/End/PullMeta/PullChunk），
// 中枢经既有 sendToDevice + awaitTaskResult 通道下发并等待回执（复用 TypeCommand 信封+签名）。
package hub

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"yuduan/internal/auth"
	"yuduan/internal/crypto"
	"yuduan/internal/proto"
	"yuduan/internal/store"
)

// ---- W4 内存态（按 Hub 指针存于 sync.Map，与 wave3 的 w3States 同构，避免改 hub.go）----

var w4States sync.Map

type wave4State struct {
	mu    sync.Mutex
	tasks map[string]*W4FileTask
	batch map[string]*W4BatchTask
	seq   int64
}

type W4FileTask struct {
	ID        string      `json:"id"`
	Kind      string      `json:"kind"` // push / pull / sync
	Name      string      `json:"name"`
	Source    string      `json:"source,omitempty"` // push: 中枢侧源路径; sync: 源路径
	Dest      string      `json:"dest,omitempty"`   // push: 副端目标路径; pull: 中枢侧落盘目录
	DeviceIDs []string    `json:"device_ids,omitempty"`
	Interval  int         `json:"interval_sec,omitempty"` // sync: 周期（0=单次）
	State     string      `json:"state"`                  // pending/running/success/failed/cancelled
	Result    string      `json:"result,omitempty"`
	Err       string      `json:"error,omitempty"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
	Records   []W4FileRec `json:"records,omitempty"`
}

type W4FileRec struct {
	DeviceID string `json:"device_id"`
	State    string `json:"state"` // success/failed/skipped
	Bytes    int64  `json:"bytes,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Msg      string `json:"msg,omitempty"`
}

type W4BatchTask struct {
	ID         string         `json:"id"`
	Script     string         `json:"script"`
	DeviceIDs  []string       `json:"device_ids"`
	Keyword    string         `json:"keyword,omitempty"`
	Danger     bool           `json:"danger"`
	DangerRule string         `json:"danger_rule,omitempty"`
	Confirmed  bool           `json:"confirmed"`
	ApprovalID string         `json:"approval_id,omitempty"`
	State      string         `json:"state"` // pending/awaiting_approval/running/success/failed/cancelled
	CreatedBy  string         `json:"created_by"`
	CreatedAt  time.Time      `json:"created_at"`
	Results    []W4BatchItem  `json:"results"`
	Summary    W4BatchSummary `json:"summary"`
}

type W4BatchItem struct {
	DeviceID string `json:"device_id"`
	State    string `json:"state"`
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output,omitempty"`
	Abnormal bool   `json:"abnormal"`
}

type W4BatchSummary struct {
	Total    int `json:"total"`
	Success  int `json:"success"`
	Failed   int `json:"failed"`
	Abnormal int `json:"abnormal"`
}

// ---- 常量 ----

const (
	w4StatePending          = "pending"
	w4StateRunning          = "running"
	w4StateSuccess          = "success"
	w4StateFailed           = "failed"
	w4StateCancelled        = "cancelled"
	w4StateAwaitingApproval = "awaiting_approval"
)

const (
	w4ChunkSize    = 256 * 1024
	w4MaxPushBytes = 512 << 20
	w4BatchConcur  = 8
	w4PushMaxRetry = 3 // 断点续传最大重试轮数

	// v0.4.25 目录下发（hub 侧递归展开）的两道闸门。与副端 fsMaxPullEntries /
	// fsMaxPullBytes 同口径，避免中枢侧无限遍历把内存与带宽打满。
	w4MaxDirFiles = 2000    // 单次目录下发最多文件数（与副端采集上限对齐）
	w4MaxDirBytes = 2 << 30 // 单次目录下发字节总量上限 2GiB
)

// ---- 危险命令规则（W4-5） ----

var w4DangerPatterns = []struct {
	Name     string
	Re       *regexp.Regexp
	Critical bool
}{
	{"rm -rf 递归删除", regexp.MustCompile(`(?i)rm\s+-[a-z]*r[a-z]*f`), true},
	{"fork 炸弹", regexp.MustCompile(`:\(\)\s*\{`), true},
	{"磁盘格式化", regexp.MustCompile(`(?i)\b(mkfs|format)\b`), true},
	{"dd 写设备", regexp.MustCompile(`(?i)\bdd\s+if=`), true},
	{"关机重启", regexp.MustCompile(`(?i)\b(shutdown|reboot|halt|poweroff)\b`), true},
	{"Windows 递归删", regexp.MustCompile(`(?i)del\s+/[a-z]*s[a-z]*\s+/[a-z]*q`), true},
	{"注册表删除", regexp.MustCompile(`(?i)reg\s+delete`), true},
	{"账户管理", regexp.MustCompile(`(?i)\bnet\s+user\b`), true},
}

func w4MatchDanger(script string) (string, bool, bool) {
	for _, p := range w4DangerPatterns {
		if p.Re.MatchString(script) {
			return p.Name, p.Critical, true
		}
	}
	return "", false, false
}

// ---- 路由 ----

func wave4Routes(mux *http.ServeMux, h *Hub) {
	// W4-1/W4-2/W4-3 文件同步
	mux.HandleFunc("/api/v1/filesync/tasks", h.guard(auth.PermDeviceCmd, h.handleW4FileTasks))
	mux.HandleFunc("/api/v1/filesync/tasks/", h.guard(auth.PermDeviceCmd, h.handleW4FileTaskItem))
	// W4-4/W4-5 批量命令与危险审批
	mux.HandleFunc("/api/v1/batchcmd/tasks", h.guard(auth.PermDeviceCmd, h.handleW4BatchTasks))
	mux.HandleFunc("/api/v1/batchcmd/tasks/", h.guard(auth.PermDeviceCmd, h.handleW4BatchTaskItem))
}

// w4() 惰性初始化内存态（线程安全）。
func (h *Hub) w4() *wave4State {
	if v, ok := w4States.Load(h); ok {
		return v.(*wave4State)
	}
	st := &wave4State{tasks: map[string]*W4FileTask{}, batch: map[string]*W4BatchTask{}}
	actual, _ := w4States.LoadOrStore(h, st)
	return actual.(*wave4State)
}

// w4NewID 生成波次 4 任务 ID（并发安全）。
func (h *Hub) w4NewID(prefix string) string {
	st := h.w4()
	st.mu.Lock()
	st.seq++
	n := st.seq
	st.mu.Unlock()
	return fmt.Sprintf("%s-%d-%s", prefix, n, randHex(4))
}

// ---- W4-1/W4-2 文件同步任务 ----

func (h *Hub) handleW4FileTasks(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	switch r.Method {
	case http.MethodGet:
		st := h.w4()
		st.mu.Lock()
		out := make([]*W4FileTask, 0, len(st.tasks))
		for _, t := range st.tasks {
			out = append(out, t)
		}
		st.mu.Unlock()
		sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
		writeJSON(w, map[string]any{"code": 0, "total": len(out), "tasks": out})
	case http.MethodPost:
		var body struct {
			Kind      string   `json:"kind"`
			Name      string   `json:"name"`
			Source    string   `json:"source"`
			Dest      string   `json:"dest"`
			DeviceIDs []string `json:"device_ids"`
			Interval  int      `json:"interval_sec"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 4010, "bad request: "+err.Error())
			return
		}
		if body.Kind != "push" && body.Kind != "pull" && body.Kind != "sync" {
			writeErr(w, 4011, "kind 应为 push/pull/sync")
			return
		}
		if len(body.DeviceIDs) == 0 {
			writeErr(w, 4012, "device_ids 必填")
			return
		}
		if body.Kind != "pull" && strings.TrimSpace(body.Source) == "" {
			writeErr(w, 4013, "source 必填")
			return
		}
		if body.Kind == "pull" && strings.TrimSpace(body.Dest) == "" {
			writeErr(w, 4014, "dest 必填")
			return
		}
		if body.Name == "" {
			body.Name = body.Kind + "-" + time.Now().Format("150405")
		}
		id := h.w4NewID("fs")
		task := &W4FileTask{
			ID: id, Kind: body.Kind, Name: body.Name, Source: body.Source, Dest: body.Dest,
			DeviceIDs: body.DeviceIDs, Interval: body.Interval,
			State: w4StatePending, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		}
		st := h.w4()
		st.mu.Lock()
		st.tasks[id] = task
		st.mu.Unlock()
		h.w4PersistFileTask(task)
		go h.w4RunFileTask(id)
		writeJSON(w, map[string]any{"code": 0, "id": id, "task": task})
	}
}

func (h *Hub) handleW4FileTaskItem(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	rest := strings.Trim(idAfterPrefix(r.URL.Path, "/api/v1/filesync/tasks/"), "/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeErr(w, 3020, "缺少任务 ID")
		return
	}
	id := parts[0]
	if r.Method == http.MethodGet {
		st := h.w4()
		st.mu.Lock()
		t := st.tasks[id]
		st.mu.Unlock()
		if t == nil {
			writeErr(w, 4040, "任务不存在")
			return
		}
		writeJSON(w, map[string]any{"code": 0, "task": t})
		return
	}
	if len(parts) == 2 && parts[1] == "cancel" && r.Method == http.MethodPost {
		st := h.w4()
		st.mu.Lock()
		if t := st.tasks[id]; t != nil && (t.State == w4StatePending || t.State == w4StateRunning) {
			t.State = w4StateCancelled
			t.UpdatedAt = time.Now().UTC()
		}
		st.mu.Unlock()
		h.w4PersistFileTask(h.w4FileGet(id))
		writeJSON(w, map[string]any{"code": 0})
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (h *Hub) w4FileGet(id string) *W4FileTask {
	st := h.w4()
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.tasks[id]
}

// w4RunFileTask 执行一个文件同步任务（push/pull；sync=周期，先执行一次后按 interval 循环）。
func (h *Hub) w4RunFileTask(id string) {
	t := h.w4FileGet(id)
	if t == nil {
		return
	}
	for {
		st := h.w4()
		st.mu.Lock()
		cur := st.tasks[id]
		if cur == nil || cur.State == w4StateCancelled {
			st.mu.Unlock()
			return
		}
		cur.State = w4StateRunning
		cur.UpdatedAt = time.Now().UTC()
		cur.Records = nil
		devices := append([]string(nil), cur.DeviceIDs...)
		st.mu.Unlock()

		var recs []W4FileRec
		for _, devID := range devices {
			rec := W4FileRec{DeviceID: devID, State: "pending"}
			var err error
			switch t.Kind {
			case "pull":
				err = h.w4PullFromDevice(t, devID, &rec)
			case "sync":
				err = h.w4PushToDevice(t, devID, &rec)
			default: // push
				err = h.w4PushToDevice(t, devID, &rec)
			}
			if err != nil {
				rec.State, rec.Msg = "failed", err.Error()
			} else {
				rec.State = "success"
			}
			recs = append(recs, rec)
		}

		allOK := true
		for _, r := range recs {
			if r.State != "success" {
				allOK = false
				break
			}
		}
		st.mu.Lock()
		cur = st.tasks[id]
		if cur != nil {
			cur.Records = recs
			if allOK {
				cur.State = w4StateSuccess
			} else {
				cur.State = w4StateFailed
			}
			cur.UpdatedAt = time.Now().UTC()
			st.mu.Unlock()
			h.w4PersistFileTask(cur)
		} else {
			st.mu.Unlock()
		}

		if t.Interval <= 0 {
			return // 单次
		}
		time.Sleep(time.Duration(t.Interval) * time.Second)
	}
}

// w4PushToDevice 下发一个「文件或目录」到设备（走 file.push_begin/chunk/end）。
// v0.4.25：目录递归展开为 N 个既有单文件传输（零契约、副端零改动）；单文件路径
// 抽到 w4PushOneFile，行为与 v0.4.24 逐字节一致（transferID=t.ID+"-"+devID、
// dest=t.Dest、断点续传重试与回执解析均未改）。
//
// w4SendFileCmdFn 是指令下发的可替换间接层：生产恒为 (*Hub).w4SendFileCmd，
// 默认行为零变化；仅供单测注入假回执以核验线协议载荷。因是包级变量，相关
// 单测一律不使用 t.Parallel，避免并发替换。
var w4SendFileCmdFn = func(h *Hub, devID, action, command string, timeout time.Duration) (proto.ResultPayload, error) {
	return h.w4SendFileCmd(devID, action, command, timeout)
}

// w4DirFile 目录下发展开后的一个普通文件条目。
type w4DirFile struct {
	src  string      // 中枢侧源路径
	rel  string      // 相对根，已 ToSlash
	info os.FileInfo // WalkDir 取得，避免二次 Stat
}

func (h *Hub) w4PushToDevice(t *W4FileTask, devID string, rec *W4FileRec) error {
	if !h.deviceOnlineLocal(devID) {
		return fmt.Errorf("设备离线")
	}
	src := t.Source
	fi, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("源文件不可读: %w", err)
	}
	if !fi.IsDir() {
		// 单文件：与 v0.4.24 完全等价
		return h.w4PushOneFile(devID, src, t.Dest, t.ID+"-"+devID, fi, rec)
	}
	return h.w4PushDirToDevice(t, devID, src, rec)
}

// w4PushOneFile 把一个普通文件按既有 file.push_begin/chunk/end 链路下发。
// 函数体是 v0.4.24 w4PushToDevice 单文件分支的原样抽离：仅把 src / dest /
// transferID 参数化（单文件调用时三者与旧值完全相同），其余（断点续传重试、
// 回执解析、SHA-256 校验、错误文案）逐字未改。
func (h *Hub) w4PushOneFile(devID, src, dest, transferID string, fi os.FileInfo, rec *W4FileRec) error {
	if fi.Size() > w4MaxPushBytes {
		return fmt.Errorf("文件超过 %dMB 上限", w4MaxPushBytes>>20)
	}
	sum, err := w4FileSHA256(src)
	if err != nil {
		return fmt.Errorf("计算源文件哈希失败: %w", err)
	}
	size := fi.Size()

	// 已确认偏移（副端落盘字节数）；0=全新传输。
	var confirmed int64
	var lastErr error
	for attempt := 0; attempt < w4PushMaxRetry; attempt++ {
		if attempt > 0 {
			log.Printf("[hub] 断点续传第 %d 轮：%s → %s 从 offset=%d 续传", attempt+1, transferID, dest, confirmed)
		}
		begin, _ := json.Marshal(proto.FilePushBeginReq{
			TransferID: transferID, Path: dest, Size: size, Sha256: sum,
			ChunkSize: w4ChunkSize, Overwrite: true,
			Resume: confirmed > 0, Offset: confirmed,
		})
		beginResp, berr := w4SendFileCmdFn(h, devID, proto.ActionFilePushBegin, string(begin), 30*time.Second)
		if berr != nil {
			lastErr = fmt.Errorf("push_begin: %w", berr)
			if attempt == w4PushMaxRetry-1 {
				return lastErr
			}
			continue
		}
		if beginResp.State != "success" {
			msg := "副端拒绝接收"
			if beginResp.OutputLog != "" {
				msg = beginResp.OutputLog
			}
			return fmt.Errorf("push_begin 失败: %s", msg)
		}
		var br proto.FilePushBeginResp
		if err := json.Unmarshal([]byte(beginResp.OutputLog), &br); err != nil || !br.OK {
			msg := "副端拒绝接收"
			if err == nil && br.Error != "" {
				msg = br.Error
			}
			return fmt.Errorf("push_begin 失败: %s", msg)
		}
		offset := br.Offset // 副端确认的起始偏移（>= confirmed）
		f, ferr := os.Open(src)
		if ferr != nil {
			return ferr
		}
		if _, serr := f.Seek(offset, io.SeekStart); serr != nil {
			f.Close()
			return serr
		}
		buf := make([]byte, w4ChunkSize)
		var chunkErr error
		for {
			n, rerr := f.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				chunkReq, _ := json.Marshal(proto.FilePushChunkReq{
					TransferID: transferID, Seq: offset / w4ChunkSize,
					Data: base64.StdEncoding.EncodeToString(chunk),
				})
				chunkResp, cerr := w4SendFileCmdFn(h, devID, proto.ActionFilePushChunk, string(chunkReq), 30*time.Second)
				if cerr != nil || chunkResp.State != "success" {
					msg := ""
					if cerr != nil {
						msg = cerr.Error()
					} else if chunkResp.OutputLog != "" {
						msg = chunkResp.OutputLog
					}
					chunkErr = fmt.Errorf("push_chunk@%d: %s", offset, msg)
					break
				}
				// 从回执取已确认偏移（断点续传观测）；解析失败则按发送量推进。
				var cresp proto.FilePushChunkResp
				if jerr := json.Unmarshal([]byte(chunkResp.OutputLog), &cresp); jerr == nil && cresp.Have > offset {
					offset = cresp.Have
				} else {
					offset += int64(n)
				}
				confirmed = offset
				rec.Bytes = offset
			}
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				chunkErr = fmt.Errorf("读取源文件: %w", rerr)
				break
			}
		}
		f.Close()
		if chunkErr != nil {
			lastErr = chunkErr
			if confirmed <= 0 || attempt == w4PushMaxRetry-1 {
				return chunkErr
			}
			continue // 续传重试
		}
		// 全部片发送成功 → push_end（哈希校验）
		endReq, _ := json.Marshal(proto.FilePushEndReq{TransferID: transferID})
		endResp, eerr := w4SendFileCmdFn(h, devID, proto.ActionFilePushEnd, string(endReq), 60*time.Second)
		if eerr != nil || endResp.State != "success" {
			msg := ""
			if eerr != nil {
				msg = eerr.Error()
			} else if endResp.OutputLog != "" {
				msg = endResp.OutputLog
			}
			return fmt.Errorf("push_end 校验失败: %s", msg)
		}
		var er proto.FilePushEndResp
		if err := json.Unmarshal([]byte(endResp.OutputLog), &er); err != nil {
			return fmt.Errorf("push_end 回执解析: %w", err)
		}
		if !er.OK {
			return fmt.Errorf("push_end 校验失败: %s", er.Error)
		}
		if er.Sha256 != "" && !strings.EqualFold(er.Sha256, sum) {
			return fmt.Errorf("SHA-256 不一致: 期望 %s 实得 %s", sum, er.Sha256)
		}
		rec.SHA256 = er.Sha256
		rec.Bytes = er.Bytes
		return nil
	}
	return lastErr
}

// w4PushDirToDevice 把目录递归展开为 N 个既有单文件 push（零契约、副端零改动）。
//
// 设计（v0.4.25 / Gate「纯增量、默认 LAN 零影响」）：
//   - 单文件任务走 w4PushToDevice → w4PushOneFile，transferID 与 dest 与 v0.4.24
//     逐字节一致；只有「源是目录」才进入本函数这一新增分支。
//   - 不改 proto：复用 file.push_begin/chunk/end，Path 支持相对副端写入根，
//     副端 Go/Rust 均已 create_dir_all(parent)，故零副端改动、零新增 action/端口。
//   - 先 WalkDir 收集 + 校验（数量/字节/相对路径），再逐个下发，避免校验失败
//     产生半成品副作用；子文件失败不中断后续文件（保留已完成记录），最终汇总回告。
func (h *Hub) w4PushDirToDevice(t *W4FileTask, devID, root string, rec *W4FileRec) error {
	destBase := strings.TrimSuffix(filepath.ToSlash(t.Dest), "/")

	type entry struct {
		src  string
		dest string
		info os.FileInfo
	}
	var entries []entry
	var total int64
	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		if !info.Mode().IsRegular() {
			// symlink / 设备 / 管道 / socket 一律跳过；WalkDir 也不跟随符号链接目录。
			return nil
		}
		if len(entries) >= w4MaxDirFiles {
			return fmt.Errorf("目录下发文件数超过上限 %d", w4MaxDirFiles)
		}
		total += info.Size()
		if total > w4MaxDirBytes {
			return fmt.Errorf("目录下发总字节超过上限 %d 字节", w4MaxDirBytes)
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if rel == ".." || strings.HasPrefix(rel, "../") || path.IsAbs(rel) {
			return fmt.Errorf("目录下发相对路径非法: %s", rel)
		}
		entries = append(entries, entry{src: p, dest: path.Join(destBase, rel), info: info})
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("遍历下发目录失败: %w", walkErr)
	}
	if len(entries) == 0 {
		// 空目录：无普通文件可下发，不视为失败（与 w4PullFromDevice 空 Entries 同口径）。
		return nil
	}

	var sent int64
	var failed []string
	for i, e := range entries {
		// 每个子文件唯一 transferID：副端 fsPushes 以 TransferID 为 map key，
		// 复用同一 ID 会让后续分片覆盖前面文件，造成串包（QA C-25）。
		transferID := fmt.Sprintf("%s-%s-f%d", t.ID, devID, i)
		one := W4FileRec{DeviceID: devID}
		if err := h.w4PushOneFile(devID, e.src, e.dest, transferID, e.info, &one); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", path.Base(e.dest), err))
			continue // 保留已完成记录，继续其余文件
		}
		sent += one.Bytes
	}
	rec.Bytes = sent
	rec.SHA256 = "" // 目录无单一摘要，不伪造
	if len(failed) > 0 {
		return fmt.Errorf("目录下发部分失败（成功 %d/%d 文件，共 %d 字节）：%s",
			len(entries)-len(failed), len(entries), sent, strings.Join(failed, "; "))
	}
	return nil
}

// w4PullFromDevice 从设备拉取文件到中枢侧目录（目录递归展开，逐文件分片）。
func (h *Hub) w4PullFromDevice(t *W4FileTask, devID string, rec *W4FileRec) error {
	if !h.deviceOnlineLocal(devID) {
		return fmt.Errorf("设备离线")
	}
	metaReq, _ := json.Marshal(proto.FilePullMetaReq{Path: t.Source, Recursive: true})
	metaResp, err := h.w4SendFileCmd(devID, proto.ActionFilePullMeta, string(metaReq), 30*time.Second)
	if err != nil {
		return fmt.Errorf("pull_meta: %w", err)
	}
	var mr proto.FilePullMetaResp
	if err := json.Unmarshal([]byte(metaResp.OutputLog), &mr); err != nil || !mr.OK {
		msg := "副端拒绝"
		if err == nil && mr.Error != "" {
			msg = mr.Error
		}
		return fmt.Errorf("pull_meta 失败: %s", msg)
	}
	if err := os.MkdirAll(t.Dest, 0o755); err != nil {
		return fmt.Errorf("创建落盘目录: %w", err)
	}
	total := int64(0)
	for _, e := range mr.Entries {
		if e.IsDir {
			continue
		}
		if err := h.w4PullOne(devID, e, t.Dest, rec); err != nil {
			return err
		}
		total += e.Size
	}
	rec.Bytes = total
	return nil
}

func (h *Hub) w4PullOne(devID string, e proto.FilePullEntry, destDir string, rec *W4FileRec) error {
	rel := filepath.Base(e.Rel)
	if rel == "" || rel == "." {
		rel = filepath.Base(e.Path)
	}
	local := filepath.Join(destDir, rel)
	out, err := os.Create(local)
	if err != nil {
		return fmt.Errorf("创建落盘文件 %s: %w", local, err)
	}
	defer out.Close()
	offset := int64(0)
	hasher := sha256.New()
	taskID := "pull-" + randHex(8)
	for {
		chunkReq, _ := json.Marshal(proto.FilePullChunkReq{
			Path: e.Path, Offset: offset, ChunkSize: w4ChunkSize, TaskID: taskID,
		})
		resp, err := h.w4SendFileCmd(devID, proto.ActionFilePullChunk, string(chunkReq), 30*time.Second)
		if err != nil {
			return fmt.Errorf("pull_chunk@%d: %w", offset, err)
		}
		var cr proto.FilePullChunkResp
		if err := json.Unmarshal([]byte(resp.OutputLog), &cr); err != nil || !cr.OK {
			msg := "pull_chunk 失败"
			if err == nil && cr.Error != "" {
				msg = cr.Error
			}
			return fmt.Errorf("%s: %s", msg, cr.Error)
		}
		if cr.Read == 0 && cr.EOF {
			break
		}
		data, derr := base64.StdEncoding.DecodeString(cr.Data)
		if derr != nil {
			return fmt.Errorf("分片解码失败: %w", derr)
		}
		if _, werr := out.Write(data); werr != nil {
			return fmt.Errorf("写落盘文件: %w", werr)
		}
		hasher.Write(data)
		offset += int64(len(data))
		if cr.EOF {
			break
		}
	}
	rec.SHA256 = hex.EncodeToString(hasher.Sum(nil))
	return nil
}

// w4SendFileCmd 下发一条 file.* 指令并等待回执（复用 TypeCommand 信封+签名）。
func (h *Hub) w4SendFileCmd(devID, action, command string, timeout time.Duration) (proto.ResultPayload, error) {
	taskID := newTaskID()
	env, err := proto.NewEnvelope(proto.TypeCommand, 0, proto.CommandPayload{
		Action: action, TaskID: taskID, Command: command,
	})
	if err != nil {
		return proto.ResultPayload{}, err
	}
	h.sign(&env)
	raw, _ := json.Marshal(env)
	// V-01 修复：先注册等待通道再发送（回调），消除「先发送后注册」竞态
	return h.awaitTaskResult(taskID, timeout, func() error {
		if !h.sendToDevice(devID, raw) {
			return fmt.Errorf("指令发送失败")
		}
		return nil
	})
}

func (h *Hub) w4PersistFileTask(t *W4FileTask) {
	if pg, ok := h.store.(*store.PostgresStore); ok && t != nil {
		payload, _ := json.Marshal(t)
		_ = store.Wave4UpsertTask(pg, "filesync_tasks", t.ID, t.State, string(payload), t.CreatedAt)
	}
}

// ---- W4-4/W4-5 批量命令与危险审批 ----

func (h *Hub) handleW4BatchTasks(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	switch r.Method {
	case http.MethodGet:
		st := h.w4()
		st.mu.Lock()
		out := make([]*W4BatchTask, 0, len(st.batch))
		for _, t := range st.batch {
			out = append(out, t)
		}
		st.mu.Unlock()
		sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
		writeJSON(w, map[string]any{"code": 0, "total": len(out), "tasks": out})
	case http.MethodPost:
		var body struct {
			Script    string   `json:"script"`
			DeviceIDs []string `json:"device_ids"`
			Keyword   string   `json:"keyword"`
			Confirmed bool     `json:"confirmed"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 4020, "bad request: "+err.Error())
			return
		}
		if strings.TrimSpace(body.Script) == "" {
			writeErr(w, 4021, "script 必填")
			return
		}
		if len(body.DeviceIDs) == 0 {
			writeErr(w, 4022, "device_ids 必填")
			return
		}
		rule, _, isDanger := w4MatchDanger(body.Script)
		id := h.w4NewID("bc")
		task := &W4BatchTask{
			ID: id, Script: body.Script, DeviceIDs: body.DeviceIDs, Keyword: body.Keyword,
			CreatedBy: claims.Username, CreatedAt: time.Now().UTC(),
		}
		st := h.w4()
		if isDanger && !body.Confirmed {
			task.Danger, task.DangerRule, task.State = true, rule, w4StateAwaitingApproval
			task.ApprovalID = h.w4NewID("apr")
			st.mu.Lock()
			st.batch[id] = task
			st.mu.Unlock()
			h.audit(claims.Username, "batchcmd_danger_await", id, "危险命令等待二次确认: "+rule, "pending")
			writeJSON(w, map[string]any{"code": 0, "id": id, "task": task,
				"danger": true, "rule": rule, "confirmed": false,
				"message": "命中危险命令，需二次确认（confirmed=true）后执行"})
			return
		}
		if isDanger && body.Confirmed {
			task.Danger, task.DangerRule, task.Confirmed = true, rule, true
		}
		task.State = w4StatePending
		st.mu.Lock()
		st.batch[id] = task
		st.mu.Unlock()
		h.w4PersistBatch(task)
		go h.w4RunBatch(id)
		writeJSON(w, map[string]any{"code": 0, "id": id, "task": task})
	}
}

func (h *Hub) handleW4BatchTaskItem(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	rest := strings.Trim(idAfterPrefix(r.URL.Path, "/api/v1/batchcmd/tasks/"), "/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeErr(w, 3020, "缺少任务 ID")
		return
	}
	id := parts[0]
	if r.Method == http.MethodGet {
		st := h.w4()
		st.mu.Lock()
		t := st.batch[id]
		st.mu.Unlock()
		if t == nil {
			writeErr(w, 4040, "任务不存在")
			return
		}
		writeJSON(w, map[string]any{"code": 0, "task": t})
		return
	}
	// {id}/confirm —— 危险命令二次确认后放行
	if len(parts) == 2 && parts[1] == "confirm" && r.Method == http.MethodPost {
		var body struct {
			Confirmed bool `json:"confirmed"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		st := h.w4()
		st.mu.Lock()
		t := st.batch[id]
		shouldRun := false
		if t != nil && t.Danger && t.State == w4StateAwaitingApproval && body.Confirmed {
			t.Confirmed = true
			t.State = w4StatePending
			shouldRun = true
		}
		st.mu.Unlock()
		if shouldRun {
			go h.w4RunBatch(id)
			h.audit(claims.Username, "batchcmd_danger_approved", id, "危险命令审批通过", "success")
		}
		writeJSON(w, map[string]any{"code": 0})
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// w4RunBatch 执行批量脚本（并发受控）。
func (h *Hub) w4RunBatch(id string) {
	st := h.w4()
	st.mu.Lock()
	t := st.batch[id]
	if t == nil {
		st.mu.Unlock()
		return
	}
	t.State = w4StateRunning
	devices := append([]string(nil), t.DeviceIDs...)
	keyword := strings.ToLower(t.Keyword)
	if keyword == "" {
		keyword = "error|fail|denied|not found|permission"
	}
	script := t.Script
	st.mu.Unlock()

	sem := make(chan struct{}, w4BatchConcur)
	var wg sync.WaitGroup
	for _, devID := range devices {
		wg.Add(1)
		sem <- struct{}{}
		go func(dev string) {
			defer wg.Done()
			defer func() { <-sem }()
			item := W4BatchItem{DeviceID: dev, State: "success"}
			taskID := newTaskID()
			env, _ := proto.NewEnvelope(proto.TypeCommand, 0, proto.CommandPayload{
				Action: "shell", TaskID: taskID, Command: script,
			})
			h.sign(&env)
			raw, _ := json.Marshal(env)
			// V-01 修复：先注册等待通道再发送（回调），消除「先发送后注册」竞态
			res, aerr := h.awaitTaskResult(taskID, 120*time.Second, func() error {
				if !h.sendToDevice(dev, raw) {
					return fmt.Errorf("指令发送失败")
				}
				return nil
			})
			if aerr != nil {
				item.State, item.ExitCode, item.Output = "failed", -1, aerr.Error()
			} else {
				item.State = res.State
				item.ExitCode = res.ExitCode
				item.Output = firstLine(res.OutputLog, "")
				if res.State == "failed" {
					item.Abnormal = true
				} else if w4MatchKeyword(item.Output, keyword) {
					item.Abnormal = true
				}
			}
			st.mu.Lock()
			if cur := st.batch[id]; cur != nil {
				cur.Results = append(cur.Results, item)
			}
			st.mu.Unlock()
		}(devID)
	}
	wg.Wait()

	st.mu.Lock()
	cur := st.batch[id]
	if cur != nil {
		for _, r := range cur.Results {
			cur.Summary.Total++
			if r.State == "success" {
				cur.Summary.Success++
			} else {
				cur.Summary.Failed++
			}
			if r.Abnormal {
				cur.Summary.Abnormal++
			}
		}
		if cur.Summary.Failed > 0 {
			cur.State = w4StateFailed
		} else {
			cur.State = w4StateSuccess
		}
	}
	st.mu.Unlock()
	h.w4PersistBatch(h.w4BatchGet(id))
}

func (h *Hub) w4BatchGet(id string) *W4BatchTask {
	st := h.w4()
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.batch[id]
}

func (h *Hub) w4PersistBatch(t *W4BatchTask) {
	if pg, ok := h.store.(*store.PostgresStore); ok && t != nil {
		payload, _ := json.Marshal(t)
		_ = store.Wave4UpsertTask(pg, "batchcmd_tasks", t.ID, t.State, string(payload), t.CreatedAt)
	}
}

// w4MatchKeyword 命中异常关键字（大小写不敏感）。
func w4MatchKeyword(output, keywords string) bool {
	lo := strings.ToLower(output)
	for _, kw := range strings.Split(keywords, "|") {
		kw = strings.TrimSpace(kw)
		if kw != "" && strings.Contains(lo, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

func w4FileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hh := sha256.New()
	if _, err := io.Copy(hh, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hh.Sum(nil)), nil
}
