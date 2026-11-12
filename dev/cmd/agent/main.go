// 御端副端参考 Agent 入口（M2 底座 + M4 远控 + M5 分发 + M6 安全基座）。
// 说明：本文件为 Go 参考实现，用于打通协议；生产副端将以 Rust 重写（逻辑等价）。
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"yuduan/internal/collect"
	"yuduan/internal/crypto"
	"yuduan/internal/proto"
	"yuduan/internal/ws"
)

const agentVersion = "0.1.0"

var seq int64
var hmacSecret string
var hmacEnforce bool
var seenNonces sync.Map // 防重放：已见 nonce

func nextSeq() int64 { return atomic.AddInt64(&seq, 1) }

func main() {
	// v0.4.14（实测报告问题 4）：Windows 远控「用户会话助手」模式入口——
	// 服务（Session 0）经 CreateProcessAsUser 在活动会话拉起本 exe，
	// 由 runRCHelper 完成用户桌面内的真实抓屏与键鼠注入。
	if len(os.Args) >= 3 && os.Args[1] == "--rc-helper" {
		runRCHelper(os.Args[2])
		return
	}
	hubURL := envOr("YUDUAN_HUB", "ws://127.0.0.1:8080/ws/agent")
	hmacSecret = os.Getenv("YUDUAN_HMAC_SECRET")
	hmacEnforce = os.Getenv("YUDUAN_HMAC_ENFORCE") == "1"
	for {
		if err := run(hubURL); err != nil {
			log.Printf("[agent] 连接错误: %v; 5s 后重连", err)
			time.Sleep(5 * time.Second)
		}
	}
}

func run(hubURL string) error {
	conn, err := ws.Dial(hubURL)
	if err != nil {
		return err
	}
	defer conn.Close()

	// ---- §9.1 注册凭据握手（复盘 S-3 修复）----
	//
	// 中枢在连接建立后即下发随机挑战，副端须以共享 HMAC 密钥自证后再注册；
	// 未实现本握手的客户端（含伪造设备）会被中枢直接断开，既不能新建假设备，
	// 也不能报出他人令牌顶替在线设备。密钥与指令验签同源，不新增凭据管理面。
	//
	// 向后兼容：老中枢（无 §9.1 握手）不会下发挑战，此时有界等待 3s 后回落
	// 为「直发 register」的旧流程，滚动升级期间新旧中枢均可接入。
	agentToken := envOr("YUDUAN_TOKEN", loadAgentToken())
	if err := handshake(conn, agentToken); err != nil {
		return err
	}

	a := collect.Gather(agentVersion)
	reg := proto.RegisterPayload{
		Hostname: a.Hostname, OS: a.OS, OSVersion: a.OSVersion, Arch: a.Arch,
		CPU: a.CPU, MemoryGB: a.MemoryGB, DiskGB: a.DiskGB, SerialNo: a.SerialNo,
		MAC: a.MAC, IP: a.IP, AgentVersion: a.AgentVersion,
		// W1-1 软件资产清单：注册即上报（进程级缓存，重连不重复枚举）。
		Software: collect.Software(),
		// 设备身份持久化（Windows 实机验证报告建议项）：env 优先，其次本地状态文件。
		// hub 按 token 复用设备身份——重启不再产生新设备条目（与 Rust 副端同构）。
		Token: agentToken,
		// v0.4.10（实测报告问题 4）：硬件指纹稳定 ID——hub 台账被清空（内存模式重启/
		// 重装）时 token 复用失效，指纹 ID 保证同一台机器永远拿回同一设备 ID。
		ProposedID: collect.StableDeviceID(a.Hostname, a.MAC, a.SerialNo),
	}
	if env, err := proto.NewEnvelope(proto.TypeRegister, nextSeq(), reg); err == nil {
		if b, err := json.Marshal(env); err == nil {
			_ = conn.WriteMessage(b)
		}
	}

	raw, err := conn.ReadMessage()
	if err != nil {
		return err
	}
	var ackEnv proto.Envelope
	if err := json.Unmarshal(raw, &ackEnv); err != nil {
		return err
	}
	var ack proto.RegisterAckPayload
	if err := ackEnv.DecodePayload(&ack); err != nil || !ack.OK {
		return fmt.Errorf("register rejected")
	}
	os.Setenv("YUDUAN_TOKEN", ack.Token)
	saveAgentState(ack.DeviceID, ack.Token) // 身份落盘，重启复用（失败不影响注册）
	log.Printf("[agent] 注册成功 device_id=%s host=%s os=%s arch=%s", ack.DeviceID, a.Hostname, a.OS, a.Arch)

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for range ticker.C {
			hb, _ := proto.NewEnvelope(proto.TypeHeartbeat, nextSeq(), proto.HeartbeatPayload{Load: collect.Load(), IP: a.IP})
			if b, err := json.Marshal(hb); err == nil {
				_ = conn.WriteMessage(b)
			}
		}
	}()

	for {
		raw, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		var env proto.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			continue
		}
		switch env.Type {
		case proto.TypeCommand:
			var c proto.CommandPayload
			if err := env.DecodePayload(&c); err != nil {
				continue
			}
			// 安全基座：HMAC 验签（默认不强制，便于兼容未签名的演示链路）
			if !verifyCmd(&env) {
				sendResult(conn, proto.ResultPayload{TaskID: c.TaskID, State: "failed", ExitCode: -1, OutputLog: "HMAC 验签失败或重放被拒"})
				continue
			}
			if c.Action == "sw_install" {
				go handleSwInstall(conn, c)
			} else {
				go handleCommand(conn, c)
			}
		case proto.TypeRCRequest:
			var p proto.RCRequestPayload
			if err := env.DecodePayload(&p); err != nil {
				continue
			}
			log.Printf("[agent] rc request session=%s operator=%s", p.SessionID, p.Operator)
			go startRC(conn, p.SessionID)
		case proto.TypeRCInput:
			var p proto.RCInputPayload
			if err := env.DecodePayload(&p); err != nil {
				continue
			}
			applyInput(conn, p.SessionID, p)
		case proto.TypeRCStop:
			stopRC()
		// ---- 波次 2：远控会话内协作（与 Rust 生产副端同构）----
		case proto.TypeRCDisplay:
			var p proto.RCDisplayPayload
			if err := env.DecodePayload(&p); err != nil {
				continue
			}
			b, wm, used := setDisplay(p.Blank, p.Watermark, p.Text)
			log.Printf("[agent] 画面控制 黑屏=%v 水印=%v 文本=%s", b, wm, used)
			sendRCEvent(conn, p.SessionID, "display_state", fmt.Sprintf("黑屏=%v 水印=%v", b, wm), false, false)
		case proto.TypeRCChat:
			var p proto.RCChatPayload
			if err := env.DecodePayload(&p); err != nil {
				continue
			}
			handleChat(conn, p.SessionID, p.From, p.Text)
		case proto.TypeRCFileOffer:
			var p proto.RCFileOfferPayload
			if err := env.DecodePayload(&p); err != nil {
				continue
			}
			handleFileOffer(conn, p)
		case proto.TypeRCFileAccept:
			var p proto.RCFileAcceptPayload
			if err := env.DecodePayload(&p); err != nil {
				continue
			}
			handleFileAccept(conn, p)
		case proto.TypeRCFileChunk:
			var p proto.RCFileChunkPayload
			if err := env.DecodePayload(&p); err != nil {
				continue
			}
			handleFileChunk(conn, p)
		case proto.TypeRCFileDone:
			var p proto.RCFileDonePayload
			if err := env.DecodePayload(&p); err != nil {
				continue
			}
			log.Printf("[agent] 传输结束 tid=%s ok=%v", p.TransferID, p.OK)
			if !p.OK {
				cleanupTransfers()
			}
		default:
			// 未知消息类型优雅忽略（如 Rust 副端不识别的远控消息）
		}
	}
}

// handshake 完成 §9.1 注册凭据握手。
//
// 新中枢：连接建立后立即下发 auth_challenge，副端回 tau MAC = HMAC-SHA256(
// 共享密钥, "yuduan-register|nonce|token")，通过后才能发 register。
// 老中枢（升级前）：不下发挑战，3s 内有界等待超时后按旧流程直接注册。
//
// token 参与签名，使应答与「本次声明的设备身份」绑定——即便攻击者录得一份
// 有效应答，也无法换成别的 token 重放。nonce 逐连接唯一，跨连接重放同样失效。
func handshake(conn *ws.Conn, token string) error {
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	raw, err := conn.ReadMessage()
	_ = conn.SetReadDeadline(time.Time{}) // 复位：后续读为长阻塞（指令/远控帧）
	if err != nil {
		// 超时或读失败：判定为老中枢，回落旧流程（由调用方直发 register）。
		log.Printf("[agent] 未收到注册挑战（老中枢？按旧流程注册）: %v", err)
		return nil
	}
	var env proto.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil
	}
	if env.Type != proto.TypeAuthChallenge {
		// 首帧不是挑战（老中枢直接给了 register_ack 之类）：交回上层处理太绕，
		// 由调用方继续既有流程即可。
		return nil
	}
	var ch proto.AuthChallengePayload
	if err := env.DecodePayload(&ch); err != nil || ch.Nonce == "" {
		return fmt.Errorf("注册挑战载荷无效")
	}
	respEnv, err := proto.NewEnvelope(proto.TypeAuthResponse, nextSeq(), proto.AuthResponsePayload{
		Nonce: ch.Nonce,
		MAC:   crypto.SignRegisterAuth(hmacSecret, ch.Nonce, token),
		Token: token,
	})
	if err != nil {
		return err
	}
	b, err := json.Marshal(respEnv)
	if err != nil {
		return err
	}
	if err := conn.WriteMessage(b); err != nil {
		return err
	}
	if hmacSecret == "" {
		// 开发态空密钥：仍能应答，但任何人都可以算出来——必须显式告知运维。
		log.Printf("[agent] 警告：未配置 YUDUAN_HMAC_SECRET，注册凭据以空密钥计算，任何人可伪造（仅可用于本机开发）")
	}
	return nil
}

// verifyCmd 校验指令 HMAC 签名与重放；未启用签名时直接放行。
func verifyCmd(env *proto.Envelope) bool {
	if hmacSecret == "" {
		return true
	}
	valid := crypto.VerifyCommand(hmacSecret, env.Sig, env.MsgID, env.Ts, env.Seq, string(env.Payload), env.Nonce, 300)
	if valid {
		if hmacEnforce {
			if _, seen := seenNonces.LoadOrStore(env.Nonce, true); seen {
				log.Printf("[agent] 拒绝重放指令 nonce=%s", env.Nonce)
				return false
			}
		}
		return true
	}
	if hmacEnforce {
		log.Printf("[agent] 拒绝签名无效指令 msg_id=%s", env.MsgID)
		return false
	}
	log.Printf("[agent] 警告：指令签名无效但未强制拒绝（enforce=off）msg_id=%s", env.MsgID)
	return true
}

func handleCommand(conn *ws.Conn, c proto.CommandPayload) {
	res := proto.ResultPayload{TaskID: c.TaskID}
	switch c.Action {
	case "shell":
		out, code := runShell(c.Command)
		res.State = "success"
		if code != 0 {
			res.State = "failed"
		}
		res.ExitCode = code
		res.OutputLog = out
	case "collect":
		a := collect.Gather(agentVersion)
		res.State = "success"
		res.OutputLog = fmt.Sprintf("re-collected: host=%s os=%s mem=%dGB disk=%dGB cpu=%s", a.Hostname, a.OS, a.MemoryGB, a.DiskGB, a.CPU)
	default:
		// 波次 3/4/5 扩展动作（各波次在 waveN.go 内 init 注册）
		if !dispatchWaveAction(conn, c) {
			res.State = "failed"
			res.OutputLog = "unknown action: " + c.Action
			return
		}
		return // 已由波次处理器自行回执
	}
	sendResult(conn, res)
}

// waveActionHandlers 由各波次模块的 init() 通过 registerWaveAction 注册。
var waveActionHandlers []func(conn *ws.Conn, c proto.CommandPayload) bool

// registerWaveAction 注册一个波次指令处理器；返回 true 表示已接管该 action。
func registerWaveAction(fn func(conn *ws.Conn, c proto.CommandPayload) bool) {
	waveActionHandlers = append(waveActionHandlers, fn)
}

// dispatchWaveAction 依次尝试已注册的波次处理器。
func dispatchWaveAction(conn *ws.Conn, c proto.CommandPayload) bool {
	for _, fn := range waveActionHandlers {
		if fn(conn, c) {
			return true
		}
	}
	return false
}

func sendResult(conn *ws.Conn, res proto.ResultPayload) {
	if env, err := proto.NewEnvelope(proto.TypeResult, nextSeq(), res); err == nil {
		if b, err := json.Marshal(env); err == nil {
			_ = conn.WriteMessage(b)
		}
	}
}

func runShell(command string) (string, int) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	return string(out), code
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// —— 设备身份持久化（与 Rust 副端 agentstate.rs 同构）——
// 存储位置：YUDUAN_STATE_FILE 优先，否则 ~/.yuduan/agent-state.json。
// 格式：{"device_id":"...","token":"..."}；损坏/缺失静默回退（重启即新身份）。

func agentStatePath() string {
	if p := os.Getenv("YUDUAN_STATE_FILE"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".yuduan", "agent-state.json")
}

func loadAgentToken() string {
	path := agentStatePath()
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var st struct {
		DeviceID string `json:"device_id"`
		Token    string `json:"token"`
	}
	if json.Unmarshal(b, &st) != nil {
		return ""
	}
	if st.Token != "" {
		log.Printf("[agent] 已恢复本地设备身份 device_id=%s（复用 token 注册；YUDUAN_STATE_FILE 可覆盖存储位置）", st.DeviceID)
	}
	return st.Token
}

func saveAgentState(deviceID, token string) {
	path := agentStatePath()
	if path == "" || token == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	b, _ := json.Marshal(map[string]string{"device_id": deviceID, "token": token})
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, path)
	}
}
