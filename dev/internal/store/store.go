// Package store 提供设备资产管理的数据访问层。
// M2/M3 使用内存实现以快速打通端到端；接口化设计便于后续替换为 PostgreSQL（见 dev/proto/schema.sql）。
package store

import (
	"encoding/json"
	"sync"
	"time"

	"yuduan/internal/proto"
)

// Device 对应 schema.sql 的 devices 表字段（M3 资产管理台账）。
type Device struct {
	ID           string    `json:"id"`
	Hostname     string    `json:"hostname"`
	OS           string    `json:"os"`
	OSVersion    string    `json:"os_version"`
	Arch         string    `json:"arch"`
	CPU          string    `json:"cpu"`
	MemoryGB     int       `json:"memory_gb"`
	DiskGB       int       `json:"disk_gb"`
	SerialNo     string    `json:"serial_no"`
	MAC          string    `json:"mac"`
	IP           string    `json:"ip"`
	AgentVersion string    `json:"agent_version"`
	Token        string    `json:"-"`
	Online       bool      `json:"online"`
	LastSeen     time.Time `json:"last_heartbeat"`
	CreatedAt    time.Time `json:"created_at"`

	// W1-1 软件资产清单（JSON 序列化存储，按需解析；避免设备×软件 N+1 表）
	SoftwareJSON string                    `json:"-"`                  // 持久化 backing（PG 列）
	Software     []proto.InstalledSoftware `json:"software,omitempty"` // API 视图（解析后数组）
	// W1-2 资产台账分组（部门/楼层/批次 + 自定义标签）
	Department string   `json:"department,omitempty"`
	Floor      string   `json:"floor,omitempty"`
	Batch      string   `json:"batch,omitempty"`
	TagsJSON   string   `json:"-"`              // 持久化 backing（PG 列）
	Tags       []string `json:"tags,omitempty"` // API 视图（解析后数组）
	// W1-3 生命周期状态流转
	Lifecycle     string    `json:"lifecycle,omitempty"` // in_stock/issued/transferred/returned/retired
	Assignee      string    `json:"assignee,omitempty"`
	AssignedAt    time.Time `json:"assigned_at,omitempty"`
	LifecycleNote string    `json:"lifecycle_note,omitempty"`
	// W2-4 敏感设备标记：标记为敏感后，远控须经 admin 二级审批放行（默认 false = 不敏感）。
	Sensitive bool `json:"sensitive"`
	// v0.4.32 §9.2 设备证明：副端每设备 Ed25519 公钥（hex 32B，旧副端为空）；
	// Attested 标记该设备最近一次注册是否经中枢验证通过设备证明（require_attest 启用时）。
	AgentPubkey string `json:"agent_pubkey,omitempty"`
	Attested    bool   `json:"attested"`
	// v0.4.40 P3-9：服务端观察到的连接来源地址（反代下取 XFF 首段，区别于副端
	// 自报的私有 LAN IP）；omitempty 兼容旧副端 / 内存模式空值，不污染既有 API。
	SourceAddr string `json:"source_addr,omitempty"`
}

// 生命周期状态常量（W1-3）。
const (
	LifecycleInStock     = "in_stock"    // 在库
	LifecycleIssued      = "issued"      // 领用
	LifecycleTransferred = "transferred" // 调拨
	LifecycleReturned    = "returned"    // 归还
	LifecycleRetired     = "retired"     // 报废
)

// DefaultLifecycle 返回新设备默认生命周期状态（在库）。
func DefaultLifecycle() string { return LifecycleInStock }

// Tags 解析 TagsJSON 为标签数组。
func (d *Device) TagList() []string {
	if d.TagsJSON == "" {
		return d.Tags
	}
	var t []string
	_ = json.Unmarshal([]byte(d.TagsJSON), &t)
	return t
}

// SetTags 序列化标签数组到 TagsJSON 与 API 视图。
func (d *Device) SetTags(t []string) {
	d.Tags = t
	if len(t) == 0 {
		d.TagsJSON = ""
		return
	}
	b, _ := json.Marshal(t)
	d.TagsJSON = string(b)
}

// Software 解析 SoftwareJSON 为软件清单。
func (d *Device) SoftwareList() []proto.InstalledSoftware {
	if d.SoftwareJSON == "" {
		return d.Software
	}
	var s []proto.InstalledSoftware
	_ = json.Unmarshal([]byte(d.SoftwareJSON), &s)
	return s
}

// SetSoftware 序列化软件清单到 SoftwareJSON 与 API 视图。
func (d *Device) SetSoftware(s []proto.InstalledSoftware) {
	d.Software = s
	if len(s) == 0 {
		d.SoftwareJSON = ""
		return
	}
	b, _ := json.Marshal(s)
	d.SoftwareJSON = string(b)
}

// DeviceMeta 台账分组元数据（W1-2，主端可编辑）。
type DeviceMeta struct {
	Department string   `json:"department,omitempty"`
	Floor      string   `json:"floor,omitempty"`
	Batch      string   `json:"batch,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	// W2-4 敏感设备标记（false 显式关闭；true 开启二级审批）。
	Sensitive *bool `json:"sensitive,omitempty"`
}

// LifecycleTransition 生命周期状态流转（W1-3）。
type LifecycleTransition struct {
	State    string `json:"state"`
	Assignee string `json:"assignee,omitempty"`
	Note     string `json:"note,omitempty"`
}

// Alert 是实时告警事件（W1-5，PRD 5.8 F2）。
type Alert struct {
	ID         int64     `json:"id"`
	Type       string    `json:"type"`     // device_offline/asset_change/ip_conflict/lifecycle/compliance/rc_abnormal
	Severity   string    `json:"severity"` // info/warning/critical
	DeviceID   string    `json:"device_id,omitempty"`
	DeviceName string    `json:"device_name,omitempty"`
	Message    string    `json:"message"`
	Detail     string    `json:"detail,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	Read       bool      `json:"read"`
}

// 告警类型常量（W1-5）。
const (
	AlertDeviceOffline = "device_offline"
	AlertAssetChange   = "asset_change"
	AlertIPConflict    = "ip_conflict"
	AlertLifecycle     = "lifecycle"
	AlertCompliance    = "compliance"
	// v0.4.34（测试报告 N2）：设备证明（§9.2）校验失败告警——副端未完成/未通过
	// Ed25519 验签或度量白名单命中即拒。addAlert 按 Type+DeviceID 去重，握手期
	// DeviceID 尚为空 → 同类拒绝自动聚合为单条未读告警，避免拒绝风暴刷屏。
	AlertAttestFailed = "attest_failed"
	AlertRCAbnormal   = "rc_abnormal"
	// W2-4/W2-5：远控审批与会话超时告警
	AlertRCApproval = "rc_approval"
	AlertRCTimeout  = "rc_timeout"
)

// 告警级别常量。
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Store 定义设备仓储接口；内存实现与未来的 Postgres 实现都遵循它。
type Store interface {
	Upsert(d Device) Device
	Get(id string) (Device, bool)
	GetByToken(token string) (Device, bool)
	// FindByIdentity 按硬件身份查找设备（v0.4.8 幂等注册）：serial 优先，
	// 其次 hostname+mac。token 轮换（重装/密钥轮换重新 claim）后凭此复用既有
	// 设备 ID，避免同一台机器在台账中重复建档。
	FindByIdentity(hostname, mac, serial string) (Device, bool)
	List() []Device
	MarkOffline(id string)
	Touch(id string)
	Count() int

	// W1-2 台账分组元数据更新
	UpdateMeta(id string, meta DeviceMeta) (Device, bool)
	// W1-3 生命周期状态流转（状态机校验在 hub 层，此处仅落库）
	TransitionLifecycle(id string, lc LifecycleTransition) (Device, bool)
	// W1-5 实时告警
	AddAlert(a Alert) Alert
	ListAlerts(limit int) []Alert
	MarkAlertRead(id int64)
	MarkAllAlertsRead()
	UnreadAlertCount() int
}

// MemStore 是内存版仓储，线程安全，仅用于 M2/M3 联调与演示。
type MemStore struct {
	mu      sync.RWMutex
	devices map[string]*Device
	byToken map[string]string // token -> deviceID
	alerts  map[int64]*Alert
	nextID  int64
}

// NewMemStore 构造内存仓储。
func NewMemStore() *MemStore {
	return &MemStore{
		devices: make(map[string]*Device),
		byToken: make(map[string]string),
		alerts:  make(map[int64]*Alert),
	}
}

// Upsert 注册或更新设备；若携带已知 token 则复用既有设备身份（重连场景）。
func (m *MemStore) Upsert(d Device) Device {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	if d.Token != "" {
		if id, ok := m.byToken[d.Token]; ok {
			existing := m.devices[id]
			existing.Hostname = d.Hostname
			existing.OS = d.OS
			existing.OSVersion = d.OSVersion
			existing.Arch = d.Arch
			existing.CPU = d.CPU
			existing.MemoryGB = d.MemoryGB
			existing.DiskGB = d.DiskGB
			existing.SerialNo = d.SerialNo
			existing.MAC = d.MAC
			existing.IP = d.IP
			// v0.4.40 P3-9：与 postgres Upsert 的 CASE 守卫同口径——本次注册携带
			// 来源地址才刷新，空值（部分构造的 Device）不清空既有台账记录。
			if d.SourceAddr != "" {
				existing.SourceAddr = d.SourceAddr
			}
			existing.AgentVersion = d.AgentVersion
			// v0.4.32 §9.2：仅当本次注册携带公钥时才刷新证明态；旧副端（无公钥）
			// 不得清空既有台账中的公钥 / 证明态（避免重连降级误清）。
			if d.AgentPubkey != "" {
				existing.AgentPubkey = d.AgentPubkey
				existing.Attested = d.Attested
			}
			// W1-1：软件清单随注册更新（空=旧副端未上报，保留既有清单）
			if d.SoftwareJSON != "" {
				existing.SoftwareJSON = d.SoftwareJSON
				existing.Software = d.Software
			}
			existing.Online = true
			existing.LastSeen = now
			return *existing
		}
	}

	if d.ID == "" {
		d.ID = newID()
	}
	if d.Token == "" {
		d.Token = newToken()
	}
	d.Online = true
	d.LastSeen = now
	if d.CreatedAt.IsZero() {
		d.CreatedAt = now
	}
	if d.Lifecycle == "" {
		d.Lifecycle = DefaultLifecycle() // 新设备默认在库
	}
	cp := d
	// v0.4.8 幂等注册：按既有 ID 覆盖更新时（token 轮换复用身份），清理旧 token
	// 映射，避免失效 token 仍能通过 GetByToken 命中该设备。
	if prev, ok := m.devices[d.ID]; ok && prev.Token != "" && prev.Token != d.Token {
		delete(m.byToken, prev.Token)
	}
	m.devices[d.ID] = &cp
	m.byToken[d.Token] = d.ID
	return cp
}

// Get 按 ID 取设备。
func (m *MemStore) Get(id string) (Device, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.devices[id]
	if !ok {
		return Device{}, false
	}
	return *d, true
}

// GetByToken 按令牌取设备（重连身份复用）。
func (m *MemStore) GetByToken(token string) (Device, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.byToken[token]
	if !ok {
		return Device{}, false
	}
	d, ok := m.devices[id]
	if !ok {
		return Device{}, false
	}
	return *d, true
}

// FindByIdentity 按硬件身份查找设备（v0.4.8 幂等注册）：serial 优先，其次 hostname+mac。
func (m *MemStore) FindByIdentity(hostname, mac, serial string) (Device, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if serial != "" {
		for _, d := range m.devices {
			if d.SerialNo == serial {
				return *d, true
			}
		}
	}
	if hostname != "" && mac != "" {
		for _, d := range m.devices {
			if d.Hostname == hostname && d.MAC == mac {
				return *d, true
			}
		}
	}
	return Device{}, false
}

// List 返回全部设备快照。
func (m *MemStore) List() []Device {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Device, 0, len(m.devices))
	for _, d := range m.devices {
		out = append(out, *d)
	}
	return out
}

// MarkOffline 将设备标记为离线。
func (m *MemStore) MarkOffline(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d, ok := m.devices[id]; ok {
		d.Online = false
	}
}

// Count 返回设备总数。
func (m *MemStore) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.devices)
}

// ---- W1-2 台账分组元数据 ----

// UpdateMeta 更新设备分组元数据（部门/楼层/批次/标签）。
func (m *MemStore) UpdateMeta(id string, meta DeviceMeta) (Device, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok {
		return Device{}, false
	}
	d.Department = meta.Department
	d.Floor = meta.Floor
	d.Batch = meta.Batch
	d.SetTags(meta.Tags)
	if meta.Sensitive != nil {
		d.Sensitive = *meta.Sensitive
	}
	return *d, true
}

// ---- W1-3 生命周期状态流转 ----

// TransitionLifecycle 落库生命周期状态（状态机校验在 hub 层）。
func (m *MemStore) TransitionLifecycle(id string, lc LifecycleTransition) (Device, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok {
		return Device{}, false
	}
	d.Lifecycle = lc.State
	d.Assignee = lc.Assignee
	d.LifecycleNote = lc.Note
	if lc.State == LifecycleIssued || lc.State == LifecycleTransferred {
		d.AssignedAt = time.Now().UTC()
	}
	return *d, true
}

// ---- W1-5 实时告警 ----

// AddAlert 追加一条告警（同类型未读去重：避免离线每次心跳重复弹）。
func (m *MemStore) AddAlert(a Alert) Alert {
	m.mu.Lock()
	defer m.mu.Unlock()
	// 去重：同 device+type 且未读 → 仅更新时间/详情（不新增）
	for _, existing := range m.alerts {
		if !existing.Read && existing.DeviceID == a.DeviceID && existing.Type == a.Type {
			existing.Message = a.Message
			existing.Detail = a.Detail
			existing.CreatedAt = time.Now().UTC()
			return *existing
		}
	}
	m.nextID++
	a.ID = m.nextID
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	cp := a
	m.alerts[a.ID] = &cp
	return cp
}

// ListAlerts 返回最近 limit 条告警（新→旧）。
func (m *MemStore) ListAlerts(limit int) []Alert {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	out := make([]Alert, 0, len(m.alerts))
	for _, a := range m.alerts {
		out = append(out, *a)
	}
	// 按 ID 倒序（新→旧）
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].ID > out[i].ID {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// MarkAlertRead 标记单条告警已读。
func (m *MemStore) MarkAlertRead(id int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a, ok := m.alerts[id]; ok {
		a.Read = true
	}
}

// MarkAllAlertsRead 标记全部告警已读。
func (m *MemStore) MarkAllAlertsRead() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.alerts {
		a.Read = true
	}
}

// UnreadAlertCount 返回未读告警数。
func (m *MemStore) UnreadAlertCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, a := range m.alerts {
		if !a.Read {
			n++
		}
	}
	return n
}
