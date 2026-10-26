// Package store 提供设备资产管理的数据访问层。
// M2/M3 使用内存实现以快速打通端到端；接口化设计便于后续替换为 PostgreSQL（见 dev/proto/schema.sql）。
package store

import (
	"sync"
	"time"
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
}

// Store 定义设备仓储接口；内存实现与未来的 Postgres 实现都遵循它。
type Store interface {
	Upsert(d Device) Device
	Get(id string) (Device, bool)
	List() []Device
	MarkOffline(id string)
	Touch(id string)
	Count() int
}

// MemStore 是内存版仓储，线程安全，仅用于 M2/M3 联调与演示。
type MemStore struct {
	mu      sync.RWMutex
	devices map[string]*Device
	byToken map[string]string // token -> deviceID
}

// NewMemStore 构造内存仓储。
func NewMemStore() *MemStore {
	return &MemStore{
		devices: make(map[string]*Device),
		byToken: make(map[string]string),
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
			existing.AgentVersion = d.AgentVersion
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
	cp := d
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
