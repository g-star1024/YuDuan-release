package hub

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"yuduan/internal/store"
)

// notifyAlertWebhook 异步 POST 告警到配置的 webhook（不阻塞主流程）。
// 失败退避重试 3 次（1s/2s/4s）；webhookURL 为空时静默跳过（仅站内徽章）。
func (h *Hub) notifyAlertWebhook(a store.Alert) {
	if h.alertWebhookURL == "" {
		return
	}
	payload, err := json.Marshal(a)
	if err != nil {
		log.Printf("[hub] 告警 webhook 序列化失败: %v", err)
		return
	}
	url := h.alertWebhookURL
	client := &http.Client{Timeout: 5 * time.Second}
	go func() {
		// 3 次退避重试：1s / 2s / 4s（总最坏 ~7s，异步不阻塞告警写入）
		for attempt := 0; attempt < 3; attempt++ {
			req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Yuduan-Event", "alert")
			req.Header.Set("X-Yuduan-Alert-Id", strconv.FormatInt(a.ID, 10))
			resp, err := client.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					log.Printf("[hub] 告警 webhook 送达: type=%s url=%s", a.Type, url)
					return
				}
				err = fmt.Errorf("http %d", resp.StatusCode)
			}
			log.Printf("[hub] 告警 webhook 失败(attempt=%d/3): %v", attempt+1, err)
			time.Sleep(time.Duration(1<<attempt) * time.Second)
		}
	}()
}
