// audit_anchor_test.go —— v0.4.31-D 审计防篡改增强离线单测（无真实 PG、无网络、无密钥）。
//
// 说明：PostgresStore.VerifyChain 仅负责取数（SELECT→构造 []Event）并委托
// audit.ReplayChain 完成全部判据与锚点逻辑。因此 ID 连续性、首条 id>1、
// 链尾锚点等判据均由本文件针对 ReplayChain 的函数级单测覆盖，无需启动真实 PG；
// 集成测试（internal/store/postgres_integration_test.go）另由 YUDUAN_TEST_DSN 门控。
//
// v0.4.31-D 第二轮：新增库外锚文件 append-only / 缺锚不误报 / 签名验签闭环 /
// 密钥三级优先 / 离线核验 等纯离线用例。
package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// resetAnchorHooks 保证每个用例从「签名器 / 库外文件 sink 均未注入」开始，结束时复位，
// 避免包级全局钩子在用例间串扰（本文件用例不并行）。
func resetAnchorHooks(t *testing.T) {
	t.Helper()
	SetAnchorSigner(nil)
	SetAnchorSink(nil)
	t.Cleanup(func() {
		SetAnchorSigner(nil)
		SetAnchorSink(nil)
	})
}

// buildLinkedChain 用给定 IDs 构造哈希自洽的链：逐条 prev_hash 链接、hash 由 EventHash 计算。
// basePrev 为首条之前的前序哈希（模拟裁剪/窗口/恢复场景时传非空值）。
func buildLinkedChain(ids []int64, basePrev string) []Event {
	out := make([]Event, 0, len(ids))
	prev := basePrev
	for _, id := range ids {
		e := Event{
			ID: id, Time: 1700000000 + id, Actor: "u", Action: "a",
			Target: "t", Detail: "d", Result: "success", PrevHash: prev,
		}
		e.Hash = EventHash(e)
		out = append(out, e)
		prev = e.Hash
	}
	return out
}

// ① EventHash canonical 串逐字钉死：改动 canonical（含把 ID 纳入）都会被此用例拦下。
func TestEventHashCanonicalPinned(t *testing.T) {
	e := Event{
		ID: 999, Time: 1700000000, Actor: "admin", Action: "login",
		Target: "", Detail: "detail-1", Result: "success", PrevHash: "prevABC",
	}
	// canonical = "1700000000|admin|login||detail-1|success|prevABC" 的 SHA-256。
	const want = "0842db42879ee57397835327991d2f915b346c390292b072b4091d6869f26295"
	if got := EventHash(e); got != want {
		t.Fatalf("EventHash canonical 串被改动：got=%s want=%s", got, want)
	}
	// ID 明确排除在 canonical 之外：仅改 ID，哈希不变。
	e2 := e
	e2.ID = 123456
	if EventHash(e2) != want {
		t.Fatalf("ID 不应参与 EventHash canonical")
	}
	// PrevHash 在 canonical 之内：改前序哈希必须改变本条哈希。
	e3 := e
	e3.PrevHash = "prevABC-x"
	if EventHash(e3) == want {
		t.Fatalf("PrevHash 必须参与 EventHash canonical")
	}
}

// ② >5000 条裁剪后 VerifyChain 仍 Valid（旧缺陷：从 prev="" 起校验必误报断链）；
// 同时验证 AuditCount 累计总数与 Query 值拷贝语义、首条 id>1 不误报。
func TestMemAuditorTrimVerifyChainValid(t *testing.T) {
	resetAnchorHooks(t)
	m := NewMemAuditor()
	const total = 5003
	for i := 0; i < total; i++ {
		m.Record(Event{Actor: "u", Action: "a", Detail: strconv.Itoa(i)})
	}
	// AuditCount 应为累计总数（旧实现返回裁剪后 5000）。
	if got := m.AuditCount(); got != total {
		t.Fatalf("AuditCount 累计总数 got=%d want=%d", got, total)
	}
	q := m.Query(100000)
	if len(q) != 5000 {
		t.Fatalf("裁剪后保留条数 got=%d want=5000", len(q))
	}
	// 保留段首条 id>1（这里应为 4）——见 ④。
	if q[0].ID != total-5000+1 {
		t.Fatalf("裁剪后首条 ID got=%d want=%d", q[0].ID, total-5000+1)
	}
	// Query 返回值拷贝：改副本不影响内部链。
	q[0].Detail = "tampered-copy"
	if m.Query(100000)[0].Detail == "tampered-copy" {
		t.Fatalf("Query 必须返回值拷贝（append-only 对外语义）")
	}
	rep := m.VerifyChain()
	if !rep.Valid {
		t.Fatalf("裁剪后 VerifyChain 应仍 Valid，got=%+v", rep)
	}
	if rep.Checked != 5000 {
		t.Fatalf("Checked 应为回放窗口大小 5000，got=%d", rep.Checked)
	}
}

// ③ ID 跳号被检出且 Reason 正确：构造「哈希链自洽但 id 跳号」的链，
// 这是旧判据（仅 prev_hash/hash）漏检、新增 ID 连续性检查才能捕获的整链伪造。
func TestReplayChainIDContinuityGap(t *testing.T) {
	resetAnchorHooks(t)
	// 连续链作为对照：必须 Valid。
	if rep := ReplayChain(buildLinkedChain([]int64{1, 2, 3}, ""), ""); !rep.Valid {
		t.Fatalf("连续 ID 链应 Valid，got=%+v", rep)
	}
	// id 1→2→4：prev_hash/hash 全对，但 id 从 2 跳到 4。
	rep := ReplayChain(buildLinkedChain([]int64{1, 2, 4}, ""), "")
	if rep.Valid {
		t.Fatalf("ID 跳号应被检出，got=%+v", rep)
	}
	if rep.Reason != "ID 连续性断裂 at id=4" {
		t.Fatalf("Reason got=%q want=%q", rep.Reason, "ID 连续性断裂 at id=4")
	}
	if rep.FirstBadID != 4 || rep.Checked != 4 {
		t.Fatalf("FirstBadID/Checked got=%d/%d want=4/4", rep.FirstBadID, rep.Checked)
	}
	// ID 绝不纳入 EventHash：buildLinkedChain 已用 EventHash 计算哈希且前两条通过校验，
	// 若 ID 被纳入 canonical，则 id=4 那条哈希会先于 ID 检查报「hash 不匹配」。
}

// ④ 首条 id>1 仍 Valid（兼容裁剪 / TRUNCATE ... RESTART IDENTITY 恢复 / 旧库），
// 起点取保留段首条的 PrevHash（非空）。
func TestReplayChainFirstIDGreaterThanOne(t *testing.T) {
	resetAnchorHooks(t)
	const base = "seed-prev-hash-of-trimmed-row"
	events := buildLinkedChain([]int64{100, 101, 102}, base)
	rep := ReplayChain(events, base)
	if !rep.Valid {
		t.Fatalf("首条 id>1 应仍 Valid，got=%+v", rep)
	}
	if rep.Checked != 3 {
		t.Fatalf("Checked got=%d want=3", rep.Checked)
	}
	if rep.Reason != "" || rep.FirstBadID != 0 {
		t.Fatalf("健康链旧字段异常：%+v", rep)
	}
}

// ⑤ signer 为 nil 时 Anchored=false、旧四字段语义不变，且 JSON omitempty 不输出锚点键
// （前端 / e2e 零回归的关键证据）。
func TestNilSignerNoAnchorAndLegacyFields(t *testing.T) {
	resetAnchorHooks(t)
	m := NewMemAuditor()
	for i := 0; i < 5; i++ {
		m.Record(Event{Actor: "u", Action: "a"})
	}
	rep := m.VerifyChain()
	if !rep.Valid || rep.Checked != 5 || rep.FirstBadID != 0 || rep.Reason != "" {
		t.Fatalf("旧四字段语义被改动：%+v", rep)
	}
	if rep.Anchored || rep.AnchorTailID != 0 || rep.AnchorSig != "" || rep.AnchorSignedAt != 0 {
		t.Fatalf("signer=nil 时不应锚定：%+v", rep)
	}
	b, _ := json.Marshal(rep)
	s := string(b)
	for _, key := range []string{"anchored", "anchor_tail_id", "anchor_sig", "anchor_signed_at"} {
		if strings.Contains(s, key) {
			t.Fatalf("omitempty 失效：默认 JSON 含 %q → %s", key, s)
		}
	}
	if !strings.Contains(s, `"valid":true`) {
		t.Fatalf("旧字段 valid 应保留：%s", s)
	}
}

// ⑥ signer 注入后锚点字段正确，且签的正是链尾 (id, hash)；失败链不锚定。
func TestInjectedSignerAnchorsChainTail(t *testing.T) {
	resetAnchorHooks(t)
	var gotID int64
	var gotHash string
	const fixedSigAt = int64(1700009999)
	SetAnchorSigner(func(tailID int64, tailHash string) (string, int64) {
		gotID, gotHash = tailID, tailHash
		return fmt.Sprintf("SIG(%d|%s)", tailID, tailHash), fixedSigAt
	})
	m := NewMemAuditor()
	var last Event
	for i := 0; i < 4; i++ {
		last = m.Record(Event{Actor: "u", Action: "a", Detail: strconv.Itoa(i)})
	}
	rep := m.VerifyChain()
	if !rep.Valid || !rep.Anchored {
		t.Fatalf("注入签名器后应 Valid 且 Anchored=true：%+v", rep)
	}
	if rep.AnchorTailID != last.ID {
		t.Fatalf("AnchorTailID got=%d want=%d", rep.AnchorTailID, last.ID)
	}
	// 签名器收到的实参必须是本次计算时刻的链尾快照 (lastID, lastHash)。
	if gotID != last.ID || gotHash != last.Hash {
		t.Fatalf("签名器收到的不是链尾：got=(%d,%s) want=(%d,%s)", gotID, gotHash, last.ID, last.Hash)
	}
	wantSig := fmt.Sprintf("SIG(%d|%s)", last.ID, last.Hash)
	if rep.AnchorSig != wantSig {
		t.Fatalf("AnchorSig got=%q want=%q", rep.AnchorSig, wantSig)
	}
	if rep.AnchorSignedAt != fixedSigAt {
		t.Fatalf("AnchorSignedAt got=%d want=%d", rep.AnchorSignedAt, fixedSigAt)
	}
	b, _ := json.Marshal(rep)
	s := string(b)
	for _, key := range []string{"anchored", "anchor_tail_id", "anchor_sig", "anchor_signed_at"} {
		if !strings.Contains(s, key) {
			t.Fatalf("锚定后 JSON 应含 %q：%s", key, s)
		}
	}
	// 校验失败时不得锚定（即便签名器已注入）。
	bad := buildLinkedChain([]int64{1, 2}, "")
	bad[1].Detail = "tampered" // 不改 Hash → hash 不匹配
	if r := ReplayChain(bad, ""); r.Anchored || r.Valid {
		t.Fatalf("失败链不应锚定：%+v", r)
	}
}

// ⑦（附加）signer 返回空 sig 时等同关闭：Anchored=false 且链仍 Valid。
func TestEmptySigSignerNoAnchor(t *testing.T) {
	resetAnchorHooks(t)
	SetAnchorSigner(func(int64, string) (string, int64) { return "", 0 })
	m := NewMemAuditor()
	m.Record(Event{Actor: "u", Action: "a"})
	rep := m.VerifyChain()
	if !rep.Valid || rep.Anchored {
		t.Fatalf("空 sig 应不锚定且仍 Valid：%+v", rep)
	}
}

// ⑧（附加）内存后端 WORM 语义：直接篡改内部 events（绕过代码自律）会被哈希校验检出。
func TestMemAuditorTamperDetected(t *testing.T) {
	resetAnchorHooks(t)
	m := NewMemAuditor()
	m.Record(Event{Actor: "u", Action: "a", Detail: "orig"})
	m.Record(Event{Actor: "u", Action: "a", Detail: "orig2"})
	m.events[1].Detail = "tampered" // 白盒篡改内存
	rep := m.VerifyChain()
	if rep.Valid {
		t.Fatalf("篡改应被检出")
	}
	if rep.Reason != "hash 不匹配 at id=2" {
		t.Fatalf("Reason got=%q", rep.Reason)
	}
}

// ⑨（缺口1）库外锚文件 append-only：连续两次 VerifyChain → 文件恰好 2 行、
// 第 1 行字节不变；两行 sig 均可用当前 key 复算（离线核验通过）。
func TestAppendAnchorFileAppendOnly(t *testing.T) {
	resetAnchorHooks(t)
	const key = "test-anchor-key"
	path := filepath.Join(t.TempDir(), "audit-anchor.jsonl")
	SetAnchorSigner(func(tailID int64, tailHash string) (string, int64) {
		return AnchorSig(key, tailID, tailHash), 1700009999
	})
	SetAnchorSink(func(a ChainAnchor) error {
		a.KeySource = "YUDUAN_AUDIT_ANCHOR_KEY"
		return AppendAnchorFile(path, a)
	})
	m := NewMemAuditor()
	m.Record(Event{Actor: "u", Action: "a", Detail: "1"})
	m.Record(Event{Actor: "u", Action: "a", Detail: "2"})
	if rep := m.VerifyChain(); !rep.Valid || !rep.Anchored {
		t.Fatalf("首次校验应 Valid 且 Anchored：%+v", rep)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读锚文件: %v", err)
	}
	// 逐字段 json.Unmarshal：首行 6 个字段齐全（库外锚文件的取证完整性）。
	var a0 ChainAnchor
	if err := json.Unmarshal(bytes.TrimSpace(first), &a0); err != nil {
		t.Fatalf("首行不是合法 JSON: %v", err)
	}
	if a0.TailID == 0 || a0.TailHash == "" || a0.Sig == "" ||
		a0.SignedAt == 0 || a0.AnchorFromID == 0 || a0.KeySource == "" {
		t.Fatalf("首行字段不全: %+v", a0)
	}
	// 行内 sig 正是用当前 key 对 (tail_id|tail_hash) 复算的结果（签名闭环）。
	if a0.Sig != AnchorSig(key, a0.TailID, a0.TailHash) {
		t.Fatalf("行内 sig 与 AnchorSig 不一致: %+v", a0)
	}
	// 链再增长一条后二次校验 → 再追加一行。
	m.Record(Event{Actor: "u", Action: "a", Detail: "3"})
	if rep := m.VerifyChain(); !rep.Valid || !rep.Anchored {
		t.Fatalf("二次校验应 Valid 且 Anchored：%+v", rep)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读锚文件: %v", err)
	}
	lines := bytes.Split(bytes.TrimRight(second, "\n"), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("锚文件应恰好 2 行，got=%d content=%q", len(lines), string(second))
	}
	// 两行都必须是 6 字段完整的合法新记录。
	for i, ln := range lines {
		var a ChainAnchor
		if err := json.Unmarshal(bytes.TrimSpace(ln), &a); err != nil {
			t.Fatalf("第 %d 行不是合法 JSON: %v", i+1, err)
		}
		if a.TailID == 0 || a.TailHash == "" || a.Sig == "" ||
			a.SignedAt == 0 || a.AnchorFromID == 0 || a.KeySource == "" {
			t.Fatalf("第 %d 行字段不全: %+v", i+1, a)
		}
	}
	// append-only：第二次写入不得改动第 1 行任何字节。
	if !bytes.HasPrefix(second, first) {
		t.Fatalf("append-only 被破坏：第 1 行字节改变\nfirst=%q\nsecond=%q", first, second)
	}
	vr := VerifyAnchorFile(path, key)
	if !vr.Valid || vr.Lines != 2 {
		t.Fatalf("锚文件离线核验应通过：%+v", vr)
	}
	if vr.LastTailID != 3 {
		t.Fatalf("LastTailID got=%d want=3", vr.LastTailID)
	}
}

// ⑩（缺口1）签名/验签闭环：真实 AnchorSig + AppendAnchorFile + VerifyAnchorFile 通过；
// 篡改 tail_hash 后 sig 复算不一致 → 验签失败。
func TestAnchorSignVerifyClosedLoopAndTamper(t *testing.T) {
	resetAnchorHooks(t)
	const key = "closed-loop-key"
	path := filepath.Join(t.TempDir(), "a.jsonl")
	a := ChainAnchor{
		TailID: 7, TailHash: "H7", Sig: AnchorSig(key, 7, "H7"),
		SignedAt: 1700009999, AnchorFromID: 1, KeySource: "YUDUAN_AUDIT_ANCHOR_KEY",
	}
	if err := AppendAnchorFile(path, a); err != nil {
		t.Fatalf("追加锚: %v", err)
	}
	if rep := VerifyAnchorFile(path, key); !rep.Valid {
		t.Fatalf("签名闭环应通过：%+v", rep)
	}
	// 模拟攻击者改写锚行 tail_hash（保持原 sig）。
	b, _ := os.ReadFile(path)
	tampered := bytes.Replace(b, []byte(`"tail_hash":"H7"`), []byte(`"tail_hash":"EVIL"`), 1)
	if bytes.Equal(b, tampered) {
		t.Fatalf("替换未生效，检查 JSON tag")
	}
	path2 := filepath.Join(t.TempDir(), "b.jsonl")
	if err := os.WriteFile(path2, tampered, 0o600); err != nil {
		t.Fatalf("写篡改文件: %v", err)
	}
	rep2 := VerifyAnchorFile(path2, key)
	if rep2.Valid {
		t.Fatalf("篡改 tail_hash 后应验签失败：%+v", rep2)
	}
	if !strings.Contains(rep2.Reason, "sig 不匹配") {
		t.Fatalf("Reason got=%q", rep2.Reason)
	}
}

// ⑪（缺口2）key_source 三级优先各分支：① 独立密钥 > ② 回退 > ③ 皆空。
func TestResolveAnchorKeyThreeLevels(t *testing.T) {
	resetAnchorHooks(t)
	t.Setenv("YUDUAN_AUDIT_ANCHOR_KEY", "")
	// ③ 两者皆空 → anchor_enabled=false（空密钥、空来源）。
	if k, s := ResolveAnchorKey(func() string { return "" }); k != "" || s != "" {
		t.Fatalf("③ both empty: got=(%q,%q)", k, s)
	}
	// ② 回退 keystore.LoadHMACSecret()（强度打折，source 明确标注）。
	if k, s := ResolveAnchorKey(func() string { return "fallback-secret" }); k != "fallback-secret" || s != "hmac-secret-fallback" {
		t.Fatalf("② fallback: got=(%q,%q)", k, s)
	}
	// ① 独立密钥优先（即使 fallback 有值也覆盖）。
	t.Setenv("YUDUAN_AUDIT_ANCHOR_KEY", "independent-key")
	if k, s := ResolveAnchorKey(func() string { return "fallback-secret" }); k != "independent-key" || s != "YUDUAN_AUDIT_ANCHOR_KEY" {
		t.Fatalf("① independent: got=(%q,%q)", k, s)
	}
}

// ⑫（缺口1）离线核验：锚文件 tail_id 单调不减，回退（TRUNCATE 恢复后重锚）被检出。
func TestVerifyAnchorFileMonotonic(t *testing.T) {
	resetAnchorHooks(t)
	const key = "mono-key"
	path := filepath.Join(t.TempDir(), "a.jsonl")
	_ = AppendAnchorFile(path, ChainAnchor{TailID: 10, TailHash: "H10", Sig: AnchorSig(key, 10, "H10")})
	if rep := VerifyAnchorFile(path, key); !rep.Valid {
		t.Fatalf("单行应通过：%+v", rep)
	}
	_ = AppendAnchorFile(path, ChainAnchor{TailID: 5, TailHash: "H5", Sig: AnchorSig(key, 5, "H5")})
	rep := VerifyAnchorFile(path, key)
	if rep.Valid {
		t.Fatalf("tail_id 回退应被检出：%+v", rep)
	}
	if !strings.Contains(rep.Reason, "非单调") {
		t.Fatalf("Reason got=%q", rep.Reason)
	}
}

// ⑬（缺口1）离线比对入口：库外锚尾与导出 JSON 的库内链尾一致 / 不一致。
func TestVerifyAnchorTail(t *testing.T) {
	resetAnchorHooks(t)
	const key = "tail-key"
	path := filepath.Join(t.TempDir(), "a.jsonl")
	_ = AppendAnchorFile(path, ChainAnchor{TailID: 42, TailHash: "H42", Sig: AnchorSig(key, 42, "H42")})
	if ok, why := VerifyAnchorTail(path, key, 42, "H42"); !ok {
		t.Fatalf("一致应通过: %s", why)
	}
	if ok, _ := VerifyAnchorTail(path, key, 42, "FORGED"); ok {
		t.Fatalf("链尾 hash 不一致应失败")
	}
	if ok, _ := VerifyAnchorTail(path, key, 99, "H42"); ok {
		t.Fatalf("链尾 id 不一致应失败")
	}
	empty := filepath.Join(t.TempDir(), "empty.jsonl")
	if ok, _ := VerifyAnchorTail(empty, key, 1, "H1"); ok {
		t.Fatalf("空/缺失锚文件不应通过")
	}
}

// ⑭（缺口1）库外锚文件写入失败：只放弃锚定，绝不动链校验结果、绝不误报损坏。
func TestAnchorSinkFailureNoFalseAlarm(t *testing.T) {
	resetAnchorHooks(t)
	SetAnchorSigner(func(int64, string) (string, int64) { return "SIG", 1700009999 })
	SetAnchorSink(func(ChainAnchor) error { return fmt.Errorf("disk full") })
	m := NewMemAuditor()
	m.Record(Event{Actor: "u", Action: "a"})
	rep := m.VerifyChain()
	if !rep.Valid || rep.Checked != 1 || rep.Reason != "" {
		t.Fatalf("锚文件写失败绝不误报链损坏：%+v", rep)
	}
	if rep.Anchored || rep.AnchorSig != "" {
		t.Fatalf("写失败应不锚定：%+v", rep)
	}
}

// ⑮（缺口2/3）缺密钥（③ 分支）：Anchored=false、Valid 仍 true、sink 不调用、
// JSON 不含锚点键（控制台据此走绿色分支，缺锚不变红）。
func TestMissingKeyNoFalseAlarm(t *testing.T) {
	resetAnchorHooks(t)
	sinkCalled := false
	SetAnchorSigner(func(int64, string) (string, int64) { return "", 0 })
	SetAnchorSink(func(ChainAnchor) error { sinkCalled = true; return nil })
	m := NewMemAuditor()
	for i := 0; i < 3; i++ {
		m.Record(Event{Actor: "u", Action: "a"})
	}
	rep := m.VerifyChain()
	if !rep.Valid || rep.Checked != 3 || rep.Reason != "" {
		t.Fatalf("缺密钥不得影响链校验结果：%+v", rep)
	}
	if rep.Anchored || sinkCalled {
		t.Fatalf("缺密钥应 anchor_enabled=false 且不写锚文件：%+v sinkCalled=%v", rep, sinkCalled)
	}
	b, _ := json.Marshal(rep)
	if strings.Contains(string(b), "anchored") {
		t.Fatalf("缺锚 JSON 不应含锚点键（控制台不变红）：%s", b)
	}
}

// ⑯（缺口1/2）错误密钥验签失败 + 默认关闭（开关关 / 无密钥→空 sig）时
// 一次文件都不创建、sink 不被调用、链仍 Valid。
func TestVerifyAnchorFileWrongKeyAndDefaultOff(t *testing.T) {
	resetAnchorHooks(t)
	const key = "right-key"
	path := filepath.Join(t.TempDir(), "a.jsonl")
	_ = AppendAnchorFile(path, ChainAnchor{TailID: 1, TailHash: "H1", Sig: AnchorSig(key, 1, "H1")})
	// 错误 key → sig 复算不一致，验签失败。
	if rep := VerifyAnchorFile(path, "wrong-key"); rep.Valid {
		t.Fatalf("错误 key 应验签失败：%+v", rep)
	} else if !strings.Contains(rep.Reason, "sig 不匹配") {
		t.Fatalf("Reason got=%q", rep.Reason)
	}
	// 默认关闭：signer 返回空 sig，sink 不应被调用、锚文件不应被创建。
	neverPath := filepath.Join(t.TempDir(), "never-created.jsonl")
	sinkCalled := false
	SetAnchorSigner(func(int64, string) (string, int64) { return "", 0 })
	SetAnchorSink(func(a ChainAnchor) error {
		sinkCalled = true
		return AppendAnchorFile(neverPath, a)
	})
	m := NewMemAuditor()
	m.Record(Event{Actor: "u", Action: "a"})
	rep := m.VerifyChain()
	if !rep.Valid || rep.Anchored || sinkCalled {
		t.Fatalf("默认关闭应 Valid 且不锚定、不触发文件写入：%+v sinkCalled=%v", rep, sinkCalled)
	}
	if _, err := os.Stat(neverPath); !os.IsNotExist(err) {
		t.Fatalf("默认关闭时不应创建任何锚文件: %v", err)
	}
}

// ⑰（缺口1 · 诚实边界）整库回滚检出：库外锚文件曾到过 id=100，
// 恢复备份（TRUNCATE ... RESTART IDENTITY CASCADE）后库内链尾退到 id=80；
// 用导出 JSON 的链尾 (80, H80) 与锚尾人工比对，必须报「不一致」。
func TestVerifyAnchorTailDetectsWholeDBRollback(t *testing.T) {
	resetAnchorHooks(t)
	const key = "rollback-key"
	path := filepath.Join(t.TempDir(), "audit-anchor.jsonl")
	// 锚文件历史：链一路增长到 id=100（库外 append-only，不随库内回滚而丢失）。
	for _, id := range []int64{80, 90, 100} {
		h := fmt.Sprintf("H%d", id)
		_ = AppendAnchorFile(path, ChainAnchor{
			TailID: id, TailHash: h, Sig: AnchorSig(key, id, h),
			SignedAt: 1700000000 + id, AnchorFromID: 1, KeySource: "YUDUAN_AUDIT_ANCHOR_KEY",
		})
	}
	// 导出 JSON 的库内链尾（被恢复到旧状态）。
	const rolledTailID, rolledTailHash = int64(80), "H80"
	ok, why := VerifyAnchorTail(path, key, rolledTailID, rolledTailHash)
	if ok {
		t.Fatalf("整库回滚必须被人工比对发现：锚尾=100 库内链尾=80 不应判一致")
	}
	if !strings.Contains(why, "不一致") {
		t.Fatalf("应给出不一致原因，got=%q", why)
	}
	// 锚文件自身仍完整、末行 tail_id=100——这正是库外锚存在的意义：
	// 没有任何攻击者改不到的地方留存过「曾经到过 id=100」这一事实，检测就无从发生。
	vr := VerifyAnchorFile(path, key)
	if !vr.Valid || vr.LastTailID != 100 {
		t.Fatalf("库外锚文件历史应完好且末行 tail_id=100：%+v", vr)
	}
}
