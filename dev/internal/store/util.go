package store

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func newToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Touch 刷新设备在线状态与最后心跳时间（心跳路径专用，避免覆盖其他字段）。
func (m *MemStore) Touch(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d, ok := m.devices[id]; ok {
		d.Online = true
		d.LastSeen = time.Now().UTC()
	}
}
