package hub

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"yuduan/internal/crypto"
	"yuduan/internal/store"
)

// StartBackupScheduler 启动定时自动备份（仅 PostgreSQL 后端；内存后端跳过并记录）。
func (h *Hub) StartBackupScheduler() {
	if h.backupInterval <= 0 {
		log.Printf("[hub] 备份调度未启用（YUDUAN_BACKUP_INTERVAL=0 或未配置自动间隔）")
		return
	}
	if _, ok := h.store.(store.Backupable); !ok {
		log.Printf("[hub] 备份调度未启用：当前存储后端不支持（仅 PostgreSQL；设置 YUDUAN_DB_DSN）")
		return
	}
	go func() {
		// 启动后延迟首备份（避免与启动/目录同步争抢），再按间隔循环
		time.Sleep(10 * time.Second)
		if _, err := h.runBackup(); err != nil {
			log.Printf("[hub] 启动备份失败: %v", err)
		}
		ticker := time.NewTicker(h.backupInterval)
		defer ticker.Stop()
		for range ticker.C {
			if _, err := h.runBackup(); err != nil {
				log.Printf("[hub] 定时备份失败: %v", err)
			}
		}
	}()
}

// runBackup 执行一次备份（导出全库 SQL 落盘 + 轮转），返回备份文件路径。
func (h *Hub) runBackup() (string, error) {
	bk, ok := h.store.(store.Backupable)
	if !ok {
		return "", fmt.Errorf("当前存储后端不支持备份（仅 PostgreSQL；设置 YUDUAN_DB_DSN）")
	}
	data, err := bk.BackupSQL()
	if err != nil {
		return "", fmt.Errorf("导出 SQL 失败: %v", err)
	}
	h.backupMu.Lock()
	defer h.backupMu.Unlock()
	name := "yuduan-backup-" + time.Now().UTC().Format("20060102-150405") + ".sql"
	path := filepath.Join(h.backupDir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("写备份文件失败: %v", err)
	}
	h.backupLast = time.Now().UTC()
	h.rotateBackups()
	log.Printf("[hub] 备份完成: %s (%d bytes)", path, len(data))
	return path, nil
}

// rotateBackups 按 BackupKeep 轮转：删除最旧的超出保留份数的备份。
func (h *Hub) rotateBackups() {
	files := h.listBackups()
	if len(files) <= h.backupKeep {
		return
	}
	for _, f := range files[h.backupKeep:] {
		_ = os.Remove(filepath.Join(h.backupDir, f))
		log.Printf("[hub] 备份轮转清理: %s", f)
	}
}

// listBackups 返回备份文件名（字典序 = 时间序，含时间戳前缀）。
func (h *Hub) listBackups() []string {
	entries, err := os.ReadDir(h.backupDir)
	if err != nil {
		return nil
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		files = append(files, e.Name())
	}
	sort.Strings(files)
	return files
}

// handleAdminBackup POST /api/v1/admin/backup 手动触发一次备份。
func (h *Hub) handleAdminBackup(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path, err := h.runBackup()
	if err != nil {
		h.audit(claims.Username, "backup", "", "手动备份失败: "+err.Error(), "failed")
		writeErr(w, 5001, err.Error())
		return
	}
	h.audit(claims.Username, "backup", filepath.Base(path), "手动触发备份", "success")
	writeJSON(w, map[string]any{"code": 0, "file": filepath.Base(path), "dir": h.backupDir})
}

// handleAdminBackups GET /api/v1/admin/backups 列出备份文件。
func (h *Hub) handleAdminBackups(w http.ResponseWriter, r *http.Request, _ crypto.Claims) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	files := h.listBackups()
	out := make([]map[string]any, 0, len(files))
	for _, f := range files {
		fi, err := os.Stat(filepath.Join(h.backupDir, f))
		size := int64(0)
		mod := ""
		if err == nil {
			size = fi.Size()
			mod = fi.ModTime().UTC().Format(time.RFC3339)
		}
		out = append(out, map[string]any{"file": f, "size": size, "modified": mod})
	}
	writeJSON(w, map[string]any{"code": 0, "dir": h.backupDir, "keep": h.backupKeep, "backups": out})
}

// handleAdminBackupRestore POST /api/v1/admin/backup/restore 从备份全库恢复。
// body: {"file":"yuduan-backup-....sql"}。恢复前自动备份一次（安全网）。
func (h *Hub) handleAdminBackupRestore(w http.ResponseWriter, r *http.Request, claims crypto.Claims) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		File string `json:"file"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.File == "" || strings.Contains(body.File, "..") || strings.ContainsAny(body.File, "/\\") {
		writeErr(w, 4001, "file 参数非法（仅允许备份目录内的文件名）")
		return
	}
	path := filepath.Join(h.backupDir, body.File)
	if _, err := os.Stat(path); err != nil {
		writeErr(w, 4004, "备份文件不存在: "+body.File)
		return
	}
	bk, ok := h.store.(store.Backupable)
	if !ok {
		writeErr(w, 5001, "当前存储后端不支持恢复（仅 PostgreSQL）")
		return
	}
	// 恢复前自动备份一次（破坏性操作安全网：误恢复可回滚到此刻）
	if _, err := h.runBackup(); err != nil {
		log.Printf("[hub] 恢复前自动备份失败: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		writeErr(w, 5001, "读取备份失败: "+err.Error())
		return
	}
	if err := bk.RestoreSQL(data); err != nil {
		h.audit(claims.Username, "backup_restore", body.File, "恢复失败: "+err.Error(), "failed")
		writeErr(w, 5001, "恢复失败: "+err.Error())
		return
	}
	h.audit(claims.Username, "backup_restore", body.File, "全库恢复成功（恢复前已自动备份）", "success")
	writeJSON(w, map[string]any{"code": 0, "message": "restored"})
}
