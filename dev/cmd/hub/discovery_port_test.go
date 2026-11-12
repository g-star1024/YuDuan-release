package main

import (
	"os"
	"testing"
)

// TestEnvIntOrDiscoveryPort 验证 F-07 发现端口环境变量的解析：
// envIntOr 对「未设置 / 合法整数 / 非法值」分别回退默认、覆盖默认、回退默认。
func TestEnvIntOrDiscoveryPort(t *testing.T) {
	const key = "YUDUAN_DISCOVERY_PORT"
	const def = 18242

	t.Run("未设置回退默认", func(t *testing.T) {
		// t.Setenv 先登记清理（结束时恢复原值），再真实 Unsetenv 制造「未设置」。
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("Unsetenv 失败: %v", err)
		}
		if got := envIntOr(key, def); got != def {
			t.Fatalf("未设置时应回退默认 %d，实际 %d", def, got)
		}
	})

	t.Run("合法值覆盖默认", func(t *testing.T) {
		t.Setenv(key, "18243")
		if got := envIntOr(key, def); got != 18243 {
			t.Fatalf("合法值应覆盖为 18243，实际 %d", got)
		}
	})

	t.Run("非法值回退默认", func(t *testing.T) {
		t.Setenv(key, "not-a-port")
		if got := envIntOr(key, def); got != def {
			t.Fatalf("非法值应回退默认 %d，实际 %d", def, got)
		}
	})
}
