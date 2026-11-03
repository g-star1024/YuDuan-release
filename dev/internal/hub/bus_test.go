package hub

import (
	"errors"
	"testing"
	"time"

	"yuduan/internal/proto"
)

// 本文件补齐复盘（v0.2.6 全面复盘）点名的测试盲区 TOP5 第 1 条：
// 「bus.go 指令总线 0 个单测——T-1/T-2/T-3 三个缺陷全在这」。
//
// 设计约束：bus.go 的主体（Dispatch/claimAndRun/sweepLoop）依赖 PostgreSQL，而
// postgres_integration_test 默认 skip（CI 等于没测）。故将所有**判定逻辑**抽为纯函数
// （sweepDecision），使其可在无 DB 环境下验证；DB 交互层只做调用编排。

// TestSweepDecision_T3_CrossInstance 复盘 T-3：实例 A 的 sweeper 不得误杀连在实例 B 上、
// 正在正常执行中的 sending 指令（原逻辑只看本实例视角的 deviceOnlineLocal）。
func TestSweepDecision_T3_CrossInstance(t *testing.T) {
	cases := []struct {
		name                    string
		self, owner             string
		ownerAlive, localOnline bool
		wantSweep               bool // true = 应兜底判 failed
		why                     string
	}{
		{
			name: "他实例持有_心跳新鲜_本实例看不到设备_不得误杀", self: "hub-a", owner: "hub-b",
			ownerAlive: true, localOnline: false, wantSweep: false,
			why: "T-3 核心回归：修复前仅凭 localOnline=false 即误标 failed，发起方重试→副端重复执行",
		},
		{
			name: "他实例持有_心跳新鲜_本实例也在线", self: "hub-a", owner: "hub-b",
			ownerAlive: true, localOnline: true, wantSweep: false,
			why: "",
		},
		{
			name: "他实例持有_心跳过期_实例已死_判失败", self: "hub-a", owner: "hub-b",
			ownerAlive: false, localOnline: false, wantSweep: true,
			why: "持有实例已死，否则指令永久卡在 sending（不能因 T-3 修复而放任悬挂）",
		},
		{
			name: "本实例持有_设备在线_仍在等回执", self: "hub-a", owner: "hub-a",
			ownerAlive: true, localOnline: true, wantSweep: false,
			why: "",
		},
		{
			name: "本实例持有_设备离线_判失败", self: "hub-a", owner: "hub-a",
			ownerAlive: true, localOnline: false, wantSweep: true,
			why: "",
		},
		{
			name: "归属未知_设备在线_不动", self: "hub-a", owner: "",
			ownerAlive: true, localOnline: true, wantSweep: false,
			why: "兼容旧数据（hub_id 为空）：退回原本地在线语义",
		},
		{
			name: "归属未知_设备离线_判失败", self: "hub-a", owner: "",
			ownerAlive: true, localOnline: false, wantSweep: true,
			why: "兼容旧数据",
		},
	}
	for _, c := range cases {
		got := sweepDecision(c.self, c.owner, c.ownerAlive, c.localOnline)
		if got != c.wantSweep {
			t.Errorf("%s: sweepDecision=%v，期望 %v %s", c.name, got, c.wantSweep, c.why)
		}
	}
}

// TestSweepDecision_T3_OldLogicWouldKill 证明该用例确实敏感：旧逻辑（仅看本实例在线）
// 在跨实例场景下会误杀，新逻辑不会。防止用例退化成"永远通过"的空断言。
func TestSweepDecision_T3_OldLogicWouldKill(t *testing.T) {
	localOnline := false // 设备连在实例 B 上，实例 A 看不到它
	oldLogic := !localOnline
	if !oldLogic {
		t.Fatal("用例前提错误：旧逻辑在此场景本应判 sweep，否则本测试无意义")
	}
	if sweepDecision("hub-a", "hub-b", true, localOnline) {
		t.Error("T-3 回归失败：新逻辑仍在误杀他实例正常执行中的指令")
	}
}

// deliverResult 模拟中枢结果处理器的投递语义（hub.go TypeResult 分支）：
// 查 pending 通道，查不到则回执被丢弃。
func deliverResult(h *Hub, taskID string, res proto.ResultPayload) bool {
	h.mu.Lock()
	ch, ok := h.pending[taskID]
	h.mu.Unlock()
	if !ok {
		return false // 回执无处可投 → 被丢弃，正是旧「先发送后注册」竞态的形态
	}
	ch <- res
	return true
}

// TestAwaitTaskResult_T1_FastReplyNotLost 复盘 T-1：局域网副端「秒回」时，若先发送后
// 注册等待通道，回执早于注册到达即被丢弃 → 超时 → 上层重发 → 副端重复执行
// （实机「指令失败重发重复执行」根因）。本用例在 send 回调内同步投递回执，
// 精确复现该竞态窗口。
func TestAwaitTaskResult_T1_FastReplyNotLost(t *testing.T) {
	h := &Hub{pending: make(map[string]chan proto.ResultPayload)}
	taskID := "task-t1-fast-reply"

	var dropped bool
	send := func() error {
		ok := deliverResult(h, taskID, proto.ResultPayload{
			TaskID: taskID, State: "success", ExitCode: 0, OutputLog: "ok",
		})
		dropped = !ok
		return nil
	}

	res, err := h.awaitTaskResult(taskID, 2*time.Second, send)
	if err != nil {
		t.Fatalf("T-1 回归失败：副端秒回的回执被丢失（超时）: %v", err)
	}
	if dropped {
		t.Fatal("T-1 回归失败：send 时 pending 通道尚未注册，回执被丢弃（先发送后注册竞态）")
	}
	if res.State != "success" || res.OutputLog != "ok" || res.ExitCode != 0 {
		t.Fatalf("回执内容不符: %+v", res)
	}

	h.mu.Lock()
	_, leaked := h.pending[taskID]
	h.mu.Unlock()
	if leaked {
		t.Error("pending 通道未注销，存在泄漏")
	}
}

// TestAwaitTaskResult_SendFailedCleansUp send 失败时须返回错误并注销通道
// （副端未收到指令，不会有回执，通道不应悬挂）。
func TestAwaitTaskResult_SendFailedCleansUp(t *testing.T) {
	h := &Hub{pending: make(map[string]chan proto.ResultPayload)}
	taskID := "task-t1-send-failed"
	wantErr := errors.New("send failed")

	_, err := h.awaitTaskResult(taskID, time.Second, func() error { return wantErr })
	if !errors.Is(err, wantErr) {
		t.Fatalf("期望透传 send 错误 %v，实际 %v", wantErr, err)
	}
	h.mu.Lock()
	_, leaked := h.pending[taskID]
	h.mu.Unlock()
	if leaked {
		t.Error("send 失败后 pending 通道未注销")
	}
}

// TestMaxBusRetries_T2_Bounded 复盘 T-2：总线曾无限重试（超时无条件归还 pending →
// dispatchLoop 无限认领重发 → 副端反复执行同一指令）。锁住重试上限为有限值，
// 防止后续改动把上限调成 0/极大而回归。
//
// 注：SQL 侧表达式为 `retries + 1 > maxBusRetries THEN 'failed'`（bus.go claimAndRun），
// 常量 maxBusRetries 是单一来源；此处以同语义的循环验证其有限性。
func TestMaxBusRetries_T2_Bounded(t *testing.T) {
	if maxBusRetries <= 0 {
		t.Fatalf("maxBusRetries=%d 非法：必须为有限正整数（0 会导致首失败即 failed）", maxBusRetries)
	}
	if maxBusRetries > 10 {
		t.Fatalf("maxBusRetries=%d 过大：重试上限过大等于放任副端重复执行", maxBusRetries)
	}
	retries := 0
	state := "pending"
	for i := 0; i < 1000 && state == "pending"; i++ {
		if retries+1 > maxBusRetries {
			state = "failed"
		} else {
			retries++
		}
	}
	if state != "failed" {
		t.Fatal("重试未收敛到 failed：总线将无限重发指令（T-2 回归）")
	}
	if retries != maxBusRetries {
		t.Errorf("重试次数 %d 与上限 %d 不符（应为恰好 maxBusRetries 次重发后判失败）", retries, maxBusRetries)
	}
}
