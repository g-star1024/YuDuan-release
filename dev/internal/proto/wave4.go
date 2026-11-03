// 波次 4：后台文件分发与采集（PRD 5.4）+ 远程命令批量脚本（PRD 5.5）线协议。
//
// 传输方式：沿用既有 TypeCommand 控制通道，不新增消息类型、不新增端口（铁律 1/3）。
// CommandPayload 的字段是 M1 冻结的（不可变），因此本波次的业务参数统一 JSON 序列化后
// 放进 CommandPayload.Command（副端由 handleCommand → dispatchWaveAction 按 Action 前缀
// 接管，不会当作 shell 文本执行）；回执同样把结果 JSON 放进 ResultPayload.OutputLog。
//
// 这样做的好处：
//  1. 协议 docker 化：既有 TypeCommand 链路的 HMAC 签名 / nonce 防重放 / task-result 关联
//     全部复用，不重造安全通道；
//  2. 语义隔离：业务 JSON 不会被任何一端的 shell 解释器消费（`file.*` action 与 shell 分流）。
package proto

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
)

// 波次 4 指令动作常量。副端按 Wave4ActionPrefix 前缀判定接管。
const (
	ActionFilePushBegin = "file.push_begin" // 下发：创建/续传打开目标文件
	ActionFilePushChunk = "file.push_chunk" // 下发：单个分片
	ActionFilePushEnd   = "file.push_end"   // 下发：收尾并做全文件 SHA-256 校验
	ActionFilePullMeta  = "file.pull_meta"  // 采集：列出来源文件（目录则递归展开）
	ActionFilePullChunk = "file.pull_chunk" // 采集：按偏移取一片
	ActionFileAbort     = "file.abort"      // 任一方向：中止传输并清理
)

// Wave4ActionPrefix 动作前缀（副端据此判定是否属于自己的 action）。
const Wave4ActionPrefix = "file."

// ---- FilePushBegin：下发握手 ----

// FilePushBeginReq 下发握手请求。Offset>0 表示断点续传（从中枢记录的已传偏移继续）。
// Sha256 为空时跳过副端侧整文件比对（由中枢在 push_end 后自行比对实际值）。
type FilePushBeginReq struct {
	TransferID string `json:"transfer_id"`
	Path       string `json:"path"`       // 落地路径（绝对，或相对于副端写入根）
	Size       int64  `json:"size"`       // 源文件总字节
	Sha256     string `json:"sha256"`     // 预期哈希（hex，可为空）
	ChunkSize  int    `json:"chunk_size"` // 分片大小
	Offset     int64  `json:"offset"`     // 期望起始偏移
	Resume     bool   `json:"resume"`     // 是否允许续传
	Overwrite  bool   `json:"overwrite"`  // 已存在且不允许续传时是否覆盖
}

// FilePushBeginResp 下发握手回执：Offset 为副端实际采用的续传偏移（可能与请求不同，
// 例如目标文件已被删除或不足缓冲时被降级为 0，中枢必须以此为准）。
type FilePushBeginResp struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	TransferID string `json:"transfer_id,omitempty"`
	Path       string `json:"path,omitempty"`
	Offset     int64  `json:"offset"`
	Exists     int64  `json:"exists"`
	Size       int64  `json:"size"`
	Resumed    bool   `json:"resumed"`
}

// ---- FilePushChunk：下发分片 ----

// FilePushChunkReq 单个分片。Seq 为全局分片序号（= offset/chunk_size），便于检测乱序/缺失。
type FilePushChunkReq struct {
	TransferID string `json:"transfer_id"`
	Seq        int64  `json:"seq"`
	Data       string `json:"data"` // base64(原始字节)
}

// FilePushChunkResp 分片回执。Bitmap 为「已接收分片位图」的 base64 表示（供断点续传观测）。
type FilePushChunkResp struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	Received   int64  `json:"received"`
	Have       int64  `json:"have"`
	Size       int64  `json:"size"`
	ChunksDone int64  `json:"chunks_done"`
	Bitmap     string `json:"bitmap,omitempty"`
	EOF        bool   `json:"eof"`
}

// ---- FilePushEnd：下发收尾校验 ----

type FilePushEndReq struct {
	TransferID string `json:"transfer_id"`
}

// FilePushEndResp 收尾回执：Sha256 为副端对落盘文件的实算值，中枢据此判定传输是否完整。
type FilePushEndResp struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	Bytes      int64  `json:"bytes"`
	Sha256     string `json:"sha256,omitempty"`
	Expected   string `json:"expected,omitempty"`
	ChunksDone int64  `json:"chunks_done"`
	Bitmap     string `json:"bitmap,omitempty"`
}

// ---- FilePullMeta：采集清单 ----

// FilePullMetaReq 采集来源探测。Recursive=true 时目录会被递归展开为若干普通文件。
type FilePullMetaReq struct {
	Path      string `json:"path"`
	Recursive bool   `json:"recursive"`
}

// FilePullEntry 一个可采集的文件项。Rel 为相对来源根的路径（中枢据此重建目录层级）。
type FilePullEntry struct {
	Rel   string `json:"rel"`
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	IsDir bool   `json:"is_dir,omitempty"`
}

type FilePullMetaResp struct {
	OK      bool            `json:"ok"`
	Error   string          `json:"error,omitempty"`
	Root    string          `json:"root,omitempty"`
	Entries []FilePullEntry `json:"entries"`
}

// ---- FilePullChunk：采集分片 ----

type FilePullChunkReq struct {
	Path      string `json:"path"`
	Offset    int64  `json:"offset"`
	ChunkSize int    `json:"chunk_size"`
	TaskID    string `json:"task_id,omitempty"` // 同一文件的多次连续读取用同一个 id 串哈希
}

// FilePullChunkResp 采集分片回执。EOF=true 时 Sha256 为该文件的全文件实算值。
type FilePullChunkResp struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Data   string `json:"data,omitempty"` // base64
	Offset int64  `json:"offset"`
	Read   int64  `json:"read"`
	Size   int64  `json:"size"`
	EOF    bool   `json:"eof"`
	Sha256 string `json:"sha256,omitempty"`
}

// FileAbortReq 中止（清理副端未完成的分片状态）。
type FileAbortReq struct {
	TransferID string `json:"transfer_id,omitempty"`
	Path       string `json:"path,omitempty"`
}

type FileAbortResp struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// ---- 编解码助手 ----

// EncodeWave4Body 将业务参数编码为可放进 CommandPayload.Command 的文本。
func EncodeWave4Body(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DecodeWave4Body 从 CommandPayload.Command 解析业务参数。
func DecodeWave4Body(s string, v any) error {
	if s == "" {
		return errWave4("empty body")
	}
	return json.Unmarshal([]byte(s), v)
}

// NewWave4Command 构造一条波次 4 指令信封，返回值 (信封, taskID, 错误)。
// taskID 自动分配，副端回执时原样带回，中枢据此关联 awaitTaskResult。
func NewWave4Command(action string, body any) (Envelope, string, error) {
	raw, err := EncodeWave4Body(body)
	if err != nil {
		return Envelope{}, "", err
	}
	env, err := NewEnvelope(TypeCommand, 0, CommandPayload{
		Action:  action,
		TaskID:  newWave4TaskID(),
		Command: raw,
	})
	if err != nil {
		return Envelope{}, "", err
	}
	var p struct {
		TaskID string `json:"task_id"`
	}
	_ = json.Unmarshal(env.Payload, &p)
	return env, p.TaskID, nil
}

type wave4Err string

func (e wave4Err) Error() string { return string(e) }

func errWave4(s string) error { return wave4Err(s) }

func newWave4TaskID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "w4-" + hex.EncodeToString(b)
}
