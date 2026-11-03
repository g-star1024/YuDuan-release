package hub

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"yuduan/internal/store"
)

// TestNotifyAlertWebhook 验证告警 webhook：送达 URL / payload 正确 / 事件头。
// 用 channel 同步 handler 协程与主协程，避免 -race 下共享变量无同步读写。
func TestNotifyAlertWebhook(t *testing.T) {
	type capture struct {
		event, alertID string
		payload        map[string]any
	}
	gotCh := make(chan capture, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p map[string]any
		_ = json.NewDecoder(r.Body).Decode(&p)
		gotCh <- capture{
			event:   r.Header.Get("X-Yuduan-Event"),
			alertID: r.Header.Get("X-Yuduan-Alert-Id"),
			payload: p,
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	h := NewHub(HubConfig{HMACSecret: "webhook-test-secret", AlertWebhookURL: srv.URL})
	a := store.Alert{ID: 42, Type: "device_offline", Severity: "critical",
		DeviceID: "d1", DeviceName: "h1", Message: "设备离线"}
	h.notifyAlertWebhook(a)

	select {
	case got := <-gotCh:
		if got.event != "alert" || got.alertID != "42" {
			t.Fatalf("事件头错误: event=%q alert_id=%q", got.event, got.alertID)
		}
		if got.payload["type"] != "device_offline" || got.payload["message"] != "设备离线" {
			t.Fatalf("payload 错误: %#v", got.payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("webhook 未收到请求")
	}
}

// TestNotifyAlertWebhookDisabled 验证未配置 URL 时静默跳过（不 panic）。
func TestNotifyAlertWebhookDisabled(t *testing.T) {
	h := NewHub(HubConfig{HMACSecret: "webhook-test-secret"}) // 无 URL
	h.notifyAlertWebhook(store.Alert{Type: "device_offline", Message: "x"})
}
