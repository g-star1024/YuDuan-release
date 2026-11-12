// 非 Windows 平台的远控桩：服务本就运行在用户上下文（launchd/systemd 用户服务/
// 前台运行），无 Session 0 隔离问题，无需「用户会话助手」双进程。
//go:build !windows

package main

import (
	"log"

	"yuduan/internal/proto"
	"yuduan/internal/ws"
)

// rcLoopWindows 在非 Windows 平台不存在 Session 0 隔离，直接走通用采集循环。
func rcLoopWindows(conn *ws.Conn, sessionID string, stop chan struct{}) {
	rcLoopSynthetic(conn, sessionID, stop)
}

// forwardRCInput 非 Windows 平台不经助手中继（rc.go 内各自有原生注入路径）。
func forwardRCInput(p proto.RCInputPayload) bool {
	_ = p
	return false
}

// runRCHelper 非 Windows 平台不存在助手模式。
func runRCHelper(addr string) {
	_ = addr
	log.Printf("[agent] rc 助手模式仅在 Windows 可用")
}
