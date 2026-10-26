package proto

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// nowUnix 返回当前 Unix 秒级时间戳。
func nowUnix() int64 { return time.Now().Unix() }

// newMsgID 生成随消息 ID（16 字节十六进制，碰撞概率可忽略）。
func newMsgID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// newNonce 生成一次性随机值（16 字节十六进制），用于关键指令防重放。
func newNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// IsRCControl 判定消息类型是否属于「远控控制指令」。
// 铁律 4 将 remote_control 列为必须签名 + 防重放的关键指令：主端/控制台发出的
// rc_request（发起会话）、rc_input（键鼠注入）、rc_stop、rc_select/rc_offer/rc_candidate
// （媒体协商与 P2P 候选）、rc_qos、rc_ping 均具备「驱动被控端执行动作」的能力，
// 因而与 command 同口径纳入验签门禁。
// 反向消息（rc_ready/rc_frame/rc_capabilities/rc_answer/rc_event/rc_pong）由副端发出，
// 属上报而非指令，不在此列。
func IsRCControl(t string) bool {
	switch t {
	case TypeRCRequest, TypeRCInput, TypeRCStop, TypeRCSelect,
		TypeRCOffer, TypeRCCandidate, TypeRCQos, TypeRCPing:
		return true
	}
	return false
}

// NormalizeForSigning 补齐签名所需的信封字段（msg_id / ts / nonce），
// 使来自不同客户端的信封在中枢签发前口径一致。
//
// 背景：Tauri 主端构造的信封只带 msg_id/ts/type/payload，不带 nonce；
// 而副端验签要求 nonce 非空（缺失即判 Malformed 拒绝）。中枢是三端契约的
// 唯一签发方，因此统一在中枢转发前补齐，而不是要求每个客户端各自实现。
// 已存在的字段保持原值（不覆盖），避免改变既有语义。
func NormalizeForSigning(e *Envelope) {
	if e == nil {
		return
	}
	if e.MsgID == "" {
		e.MsgID = newMsgID()
	}
	if e.Ts == 0 {
		e.Ts = nowUnix()
	}
	if e.Nonce == "" {
		e.Nonce = newNonce()
	}
}
