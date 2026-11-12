// v0.4.32 §9.2 设备证明：内存仓储对 AgentPubkey / Attested 字段的落库与重连守卫。
package store

import (
	"testing"
)

func TestMemStoreUpsertAttestFields(t *testing.T) {
	m := NewMemStore()
	d := Device{Hostname: "a", Token: "tok-a", AgentPubkey: "deadbeef", Attested: true}
	saved := m.Upsert(d)
	if saved.AgentPubkey != "deadbeef" {
		t.Fatalf("AgentPubkey 未落库: got=%q", saved.AgentPubkey)
	}
	if !saved.Attested {
		t.Fatal("Attested 未落库")
	}
	got, ok := m.Get(saved.ID)
	if !ok || got.AgentPubkey != "deadbeef" || !got.Attested {
		t.Fatalf("回读设备字段不符: %+v", got)
	}
}

// TestMemStoreReconnectOldAgentDoesNotClearPubkey：已证明设备以旧副端形态重连
// （不携带公钥）时，台账既有 AgentPubkey / Attested 不得被清空（避免重连降级误清）。
func TestMemStoreReconnectOldAgentDoesNotClearPubkey(t *testing.T) {
	m := NewMemStore()
	first := m.Upsert(Device{Hostname: "a", Token: "tok-a", AgentPubkey: "pub1", Attested: true})
	if !first.Attested || first.AgentPubkey != "pub1" {
		t.Fatalf("首次建档字段不符: %+v", first)
	}
	// 重连：同一 token、但旧副端未携带公钥（AgentPubkey 空）
	second := m.Upsert(Device{Hostname: "a", Token: "tok-a"})
	if second.AgentPubkey != "pub1" {
		t.Fatalf("重连清空了 AgentPubkey: got=%q", second.AgentPubkey)
	}
	if !second.Attested {
		t.Fatal("重连清空了 Attested——证明态丢失")
	}
}

// TestMemStoreUpsertRefreshesPubkeyWhenPresent：携带新公钥重连时刷新（换密钥场景）。
func TestMemStoreUpsertRefreshesPubkeyWhenPresent(t *testing.T) {
	m := NewMemStore()
	m.Upsert(Device{Hostname: "a", Token: "tok-a", AgentPubkey: "pub1", Attested: true})
	reproved := m.Upsert(Device{Hostname: "a", Token: "tok-a", AgentPubkey: "pub2", Attested: true})
	if reproved.AgentPubkey != "pub2" {
		t.Fatalf("重连未刷新公钥: got=%q", reproved.AgentPubkey)
	}
}
