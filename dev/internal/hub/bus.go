package hub

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"yuduan/internal/pg"
	"yuduan/internal/proto"
)

// maxBusRetries 单条指令在 outbox 的失败重试上限（复盘 V-04：此前超时无条件归还
// pending，dispatchLoop 无限认领重发——副端反复执行同一指令）。超限置 failed。
const maxBusRetries = 3

// CommandBus 是多中枢指令总线：所有指令先落 PG outbox，再由持有该设备长连接的
// 实例认领执行，从而去掉「会话粘性」——任意中枢实例都能发起指令，设备连到哪个
// 实例就在哪个实例执行，结果经 outbox 回传，发起方轮询/被唤醒后取回。
// 通知通道：NOTIFY cmd_outbox（低延迟）；轮询兜底（可靠）。
type CommandBus struct {
	h      *Hub
	pool   *pg.Pool
	hubID  string
	dsn    string
	notify chan string
	stop   chan struct{}
	once   sync.Once
}

// EnableBus 装配指令总线（需 PostgreSQL 后端）；立即返回，后台启动调度/心跳。
// dsn 用于建立 LISTEN 监听连接（失败则退化为纯轮询，不影响正确性）。
func (h *Hub) EnableBus(pool *pg.Pool, hubID, dsn string) error {
	if pool == nil {
		return fmt.Errorf("bus requires postgres pool")
	}
	if hubID == "" {
		hubID = h.hubID
	}
	if hubID == "" {
		hubID = "hub-unknown"
	}
	b := &CommandBus{h: h, pool: pool, hubID: hubID, dsn: dsn, notify: make(chan string, 128), stop: make(chan struct{})}
	// 多实例并发启动时，CREATE TABLE IF NOT EXISTS 可能撞 PostgreSQL 目录竞态
	// （duplicate key / tuple concurrently updated 等）：重试即可（表已由另一实例建好）。
	var migrateErr error
	for attempt := 0; attempt < 5; attempt++ {
		if migrateErr = b.migrate(); migrateErr == nil {
			break
		}
		log.Printf("[bus] migrate 重试 %d/4: %v", attempt+1, migrateErr)
		time.Sleep(time.Duration(attempt+1) * 300 * time.Millisecond)
	}
	if migrateErr != nil {
		return migrateErr
	}
	if dsn != "" {
		if ln, err := pg.NewListenerFromDSN(dsn, "cmd_outbox"); err != nil {
			log.Printf("[bus] LISTEN 失败，退化为纯轮询: %v", err)
		} else {
			go func() {
				for {
					select {
					case <-b.stop:
						_ = ln.Close()
						return
					case p := <-ln.Notifications():
						select {
						case b.notify <- p:
						default:
						}
					}
				}
			}()
		}
	}
	h.bus = b
	go b.dispatchLoop()
	go b.heartbeatLoop()
	go b.sweepLoop()
	log.Printf("[bus] 指令总线已启用 hub_id=%s（去粘性：任意实例可发起指令）", hubID)
	return nil
}

func (b *CommandBus) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS cmd_outbox (
			id TEXT PRIMARY KEY, device_id TEXT NOT NULL, envelope TEXT NOT NULL,
			state TEXT NOT NULL DEFAULT 'pending', hub_id TEXT, result TEXT, error TEXT,
			retries INT NOT NULL DEFAULT 0,
			created_at TIMESTAMP, updated_at TIMESTAMP)`,
		// 既有表升级（V-04 重试上限）：补 retries 列（幂等）
		`ALTER TABLE cmd_outbox ADD COLUMN IF NOT EXISTS retries INT NOT NULL DEFAULT 0`,
		`CREATE INDEX IF NOT EXISTS idx_outbox_pending ON cmd_outbox (state, device_id)`,
		`CREATE TABLE IF NOT EXISTS hub_nodes (
			id TEXT PRIMARY KEY, addr TEXT, started_at TIMESTAMP, last_seen TIMESTAMP)`,
	}
	for _, s := range stmts {
		if err := b.exec(s); err != nil {
			return fmt.Errorf("bus migrate: %v", err)
		}
	}
	return nil
}

func (b *CommandBus) exec(sql string, args ...any) error {
	c, err := b.pool.Acquire()
	if err != nil {
		return err
	}
	if err := c.ExecArgs(sql, args...); err != nil {
		b.pool.Discard(c)
		return err
	}
	b.pool.Release(c)
	return nil
}

func (b *CommandBus) query(sql string, args ...any) ([][]string, error) {
	c, err := b.pool.Acquire()
	if err != nil {
		return nil, err
	}
	_, rows, err := c.QueryArgs(sql, args...)
	if err != nil {
		b.pool.Discard(c)
		return nil, err
	}
	b.pool.Release(c)
	return rows, nil
}

// fireNotify 尽力发送 NOTIFY（失败不影响正确性，轮询兜底）。
func (b *CommandBus) fireNotify() {
	_ = b.exec("NOTIFY cmd_outbox")
}

// Dispatch 发起一条指令：落 outbox → 本地可发则认领发送，否则等待其他实例执行。
// 返回副端回执；超时/失败返回 error。
func (b *CommandBus) Dispatch(deviceID, taskID string, envBytes []byte, timeout time.Duration) (proto.ResultPayload, error) {
	now := time.Now().UTC()
	if err := b.exec(`INSERT INTO cmd_outbox (id,device_id,envelope,state,hub_id,created_at,updated_at)
		VALUES ($1,$2,$3,'pending',$4,$5,$5)`, taskID, deviceID, string(envBytes), b.hubID, now); err != nil {
		return proto.ResultPayload{}, fmt.Errorf("bus: %v", err)
	}
	b.fireNotify()

	deadline := time.Now().Add(timeout)
	for {
		// 1) 设备在本实例在线 → 尝试认领并发送
		if b.h.deviceOnlineLocal(deviceID) {
			rows, err := b.query(`UPDATE cmd_outbox SET state='sending', hub_id=$1, updated_at=$2
				WHERE id=$3 AND state='pending' RETURNING id`, b.hubID, time.Now().UTC(), taskID)
			if err == nil && len(rows) > 0 {
				// V-01 修复：awaitTaskResult 先注册等待通道再发送，消除「先发送后注册」竞态
				// （回执早于注册到达被丢弃 → 超时 → 重发重复执行）。send 失败置 failed 并返回。
				res, aerr := b.h.awaitTaskResult(taskID, time.Until(deadline), func() error {
					if !b.h.sendToDevice(deviceID, envBytes) {
						return fmt.Errorf("send failed")
					}
					return nil
				})
				if aerr != nil {
					_ = b.exec("UPDATE cmd_outbox SET state='failed', error=$1, updated_at=$2 WHERE id=$3",
						aerr.Error(), time.Now().UTC(), taskID)
					b.fireNotify()
					return proto.ResultPayload{}, aerr
				}
				b.finish(taskID, res)
				return res, nil
			}
		}
		// 2) 非本实例执行：观察 outbox 终态
		rows, err := b.query("SELECT state,result,error FROM cmd_outbox WHERE id=$1", taskID)
		if err == nil && len(rows) > 0 {
			switch rows[0][0] {
			case "done":
				var res proto.ResultPayload
				if err := json.Unmarshal([]byte(rows[0][1]), &res); err == nil {
					return res, nil
				}
				return proto.ResultPayload{}, fmt.Errorf("bus: bad result payload")
			case "failed":
				return proto.ResultPayload{}, fmt.Errorf("bus: %s", rows[0][2])
			}
		}
		// 3) 等待通知或轮询
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return proto.ResultPayload{}, fmt.Errorf("command timeout")
		}
		wait := 300 * time.Millisecond
		if remaining < wait {
			wait = remaining
		}
		select {
		case <-b.notify:
		case <-time.After(wait):
		case <-b.stop:
			return proto.ResultPayload{}, fmt.Errorf("bus stopped")
		}
	}
}

// finish 标记完成并写回执（供发起方与其他实例观察）。
func (b *CommandBus) finish(taskID string, res proto.ResultPayload) {
	raw, _ := json.Marshal(res)
	_ = b.exec("UPDATE cmd_outbox SET state='done', result=$1, updated_at=$2 WHERE id=$3",
		string(raw), time.Now().UTC(), taskID)
	b.fireNotify()
}

// dispatchLoop 认领「本实例在线设备」的待发指令并执行。
func (b *CommandBus) dispatchLoop() {
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-tick.C:
		case <-b.notify:
		}
		b.claimAndRun()
	}
}

func (b *CommandBus) claimAndRun() {
	ids := b.h.localDeviceIDs()
	if len(ids) == 0 {
		return
	}
	rows, err := b.query(`UPDATE cmd_outbox SET state='sending', hub_id=$1, updated_at=$2
		WHERE id IN (SELECT id FROM cmd_outbox WHERE state='pending' AND device_id = ANY(string_to_array($3, ','))
		             FOR UPDATE SKIP LOCKED LIMIT 32) RETURNING id, device_id, envelope`,
		b.hubID, time.Now().UTC(), strings.Join(ids, ","))
	if err != nil || len(rows) == 0 {
		return
	}
	for _, r := range rows {
		taskID, deviceID, envelope := r[0], r[1], []byte(r[2])
		if !b.h.deviceOnlineLocal(deviceID) {
			// 设备刚掉线：归还 pending 重试（不计 retries——非指令执行失败）
			_ = b.exec("UPDATE cmd_outbox SET state='pending', updated_at=$1 WHERE id=$2", time.Now().UTC(), taskID)
			continue
		}
		// V-01 修复：先注册等待通道再发送，消除「先发送后注册」竞态（回执早于注册
		// 到达被丢弃 → 超时 → 重发重复执行）。
		res, err := b.h.awaitTaskResult(taskID, 2*time.Minute, func() error {
			if !b.h.sendToDevice(deviceID, envelope) {
				return fmt.Errorf("send failed")
			}
			return nil
		})
		if err != nil {
			// 超时/失败：retries+1，超上限置 failed，否则归还 pending 重试。
			// 修复「总线无限重试」：此前超时无条件归还 pending → dispatchLoop 无限认领重发。
			_ = b.exec(`UPDATE cmd_outbox SET
				retries = retries + 1,
				state = CASE WHEN retries + 1 > $1 THEN 'failed' ELSE 'pending' END,
				error = CASE WHEN retries + 1 > $1 THEN 'retries exceeded' ELSE $2 END,
				updated_at = $3 WHERE id = $4`,
				maxBusRetries, err.Error(), time.Now().UTC(), taskID)
			b.fireNotify()
			continue
		}
		b.finish(taskID, res)
	}
}

// sweepDecision 判定一条 sending 指令是否应被**本实例**兜底判失败（复盘 T-3）。
//
// 背景：sending 指令由持有该设备长连接的中枢实例认领。原逻辑只看「本实例能否看到该
// 设备在线」，于是实例 A 的 sweeper 会把连在实例 B 上、正在正常执行中的指令误标
// failed（跨实例误判失败），发起方据此重试 → 副端重复执行。现按归属判定：
//   - owner 为本实例：维持原语义（本地在线=仍在等回执，不 sweep；离线=判失败）
//   - owner 为其他实例且心跳新鲜：跳过，由持有实例自行处理 —— T-3 修复点
//   - owner 为其他实例但心跳已过期（该实例已死）：判失败，避免指令永久卡在 sending
//   - owner 未知（空，兼容旧数据）：退回原本地在线语义
//
// 纯函数（不访问数据库），便于无 PostgreSQL 环境下单测（QA：integration test 默认
// skip，等于没测，故判定逻辑必须可脱离 DB 验证）。
func sweepDecision(selfHubID, ownerHubID string, ownerAlive, localOnline bool) bool {
	if ownerHubID != "" && ownerHubID != selfHubID {
		// 其他实例持有：只要它还活着就不插手，避免误杀跨实例执行中的指令
		return !ownerAlive
	}
	// 本实例持有，或归属未知（兼容旧数据）→ 按本地在线语义
	return !localOnline
}

// nodeAlive 判断某中枢实例心跳是否新鲜（跨实例 sweep 判定用）。
// 查询失败时保守返回 true：宁可不 sweep，也不误杀正常执行中的指令。
func (b *CommandBus) nodeAlive(hubID string) bool {
	rows, err := b.query(`SELECT 1 FROM hub_nodes WHERE id=$1 AND last_seen > $2 LIMIT 1`,
		hubID, time.Now().UTC().Add(-30*time.Second))
	if err != nil {
		return true
	}
	return len(rows) > 0
}

// sweepLoop 兜底：sending 超 3 分钟且不应由其他存活实例继续等待 → 标记 failed，
// 避免永久卡死（复盘 T-3：不得误杀连在其他实例上正常执行中的指令）。
func (b *CommandBus) sweepLoop() {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-tick.C:
		}
		rows, err := b.query(`SELECT id, device_id, COALESCE(hub_id,'') FROM cmd_outbox WHERE state='sending'
			AND updated_at < $1 LIMIT 64`, time.Now().UTC().Add(-3*time.Minute))
		if err != nil {
			continue
		}
		for _, r := range rows {
			owner := ""
			if len(r) > 2 {
				owner = r[2]
			}
			ownerAlive := true
			if owner != "" && owner != b.hubID {
				ownerAlive = b.nodeAlive(owner)
			}
			// T-3：跨实例且持有实例心跳新鲜 → 跳过，交由持有实例处理
			if !sweepDecision(b.hubID, owner, ownerAlive, b.h.deviceOnlineLocal(r[1])) {
				continue // 仍在等待回执（本实例或他实例）
			}
			_ = b.exec("UPDATE cmd_outbox SET state='failed', error='device offline (swept)', updated_at=$1 WHERE id=$2",
				time.Now().UTC(), r[0])
			b.fireNotify()
		}
	}
}

// heartbeatLoop 中枢节点心跳，供 /api/v1/hubs 观察集群。
func (b *CommandBus) heartbeatLoop() {
	beat := func() {
		_ = b.exec(`INSERT INTO hub_nodes (id, addr, started_at, last_seen) VALUES ($1,$2,$3,$3)
			ON CONFLICT (id) DO UPDATE SET addr=EXCLUDED.addr, last_seen=EXCLUDED.last_seen`,
			b.hubID, b.h.publicAddr, time.Now().UTC())
	}
	beat()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-tick.C:
			beat()
		}
	}
}

// Stop 停止总线。
func (b *CommandBus) Stop() {
	b.once.Do(func() { close(b.stop) })
}

// HubNode 集群节点视图。
type HubNode struct {
	ID        string `json:"id"`
	Addr      string `json:"addr"`
	StartedAt int64  `json:"started_at"`
	LastSeen  int64  `json:"last_seen"`
}

// Nodes 返回近期心跳的中枢节点。
func (b *CommandBus) Nodes() []HubNode {
	rows, err := b.query(`SELECT id, addr, EXTRACT(EPOCH FROM started_at)::bigint, EXTRACT(EPOCH FROM last_seen)::bigint
		FROM hub_nodes WHERE last_seen > $1 ORDER BY id`, time.Now().UTC().Add(-30*time.Second))
	if err != nil {
		return nil
	}
	out := make([]HubNode, 0, len(rows))
	for _, r := range rows {
		started, _ := atoi64(r[2])
		seen, _ := atoi64(r[3])
		out = append(out, HubNode{ID: r[0], Addr: r[1], StartedAt: started, LastSeen: seen})
	}
	return out
}
