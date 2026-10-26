package keystore

import (
	"os"
	"testing"
)

func TestParseHexSeed(t *testing.T) {
	good := "79756475616e2d656432353531392d63726f7373636865636b2d736565642d33"
	b := parseHexSeed(good)
	if len(b) != 32 {
		t.Fatalf("期望 32 字节，实际 %d", len(b))
	}
	if parseHexSeed("xyz") != nil {
		t.Fatalf("非法输入应返回 nil")
	}
	if parseHexSeed("") != nil {
		t.Fatalf("空输入应返回 nil")
	}
}

func TestLoadSignSeed_FromEnv(t *testing.T) {
	os.Setenv("YUDUAN_SIGN_SEED", "79756475616e2d656432353531392d63726f7373636865636b2d736565642d33")
	defer os.Unsetenv("YUDUAN_SIGN_SEED")
	if len(LoadSignSeed()) != 32 {
		t.Fatalf("应从环境变量读到 32 字节种子")
	}
}

func TestLoadSignSeed_FromFile(t *testing.T) {
	f, err := os.CreateTemp("", "seed-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString("79756475616e2d656432353531392d63726f7373636865636b2d736565642d33\n")
	f.Close()
	os.Setenv("YUDUAN_SIGN_SEED_FILE", f.Name())
	defer os.Unsetenv("YUDUAN_SIGN_SEED_FILE")
	if len(LoadSignSeed()) != 32 {
		t.Fatalf("应从文件读到 32 字节种子")
	}
}

func TestLoadHMACSecret_FromEnvAndFile(t *testing.T) {
	os.Setenv("YUDUAN_HMAC_SECRET", "topsecret")
	defer os.Unsetenv("YUDUAN_HMAC_SECRET")
	if LoadHMACSecret() != "topsecret" {
		t.Fatalf("应从环境变量读到 HMAC 密钥")
	}

	f, _ := os.CreateTemp("", "hmac-*.txt")
	f.WriteString("file-secret\n")
	f.Close()
	defer os.Remove(f.Name())
	os.Setenv("YUDUAN_HMAC_SECRET_FILE", f.Name())
	defer os.Unsetenv("YUDUAN_HMAC_SECRET_FILE")
	os.Unsetenv("YUDUAN_HMAC_SECRET")
	if LoadHMACSecret() != "file-secret" {
		t.Fatalf("应从文件读到 HMAC 密钥")
	}
}

func TestLoadDefaultsToNilOrEmpty(t *testing.T) {
	os.Unsetenv("YUDUAN_SIGN_SEED")
	os.Unsetenv("YUDUAN_SIGN_SEED_FILE")
	os.Unsetenv("YUDUAN_HMAC_SECRET")
	os.Unsetenv("YUDUAN_HMAC_SECRET_FILE")
	if LoadSignSeed() != nil {
		t.Fatalf("未配置时种子应为 nil")
	}
	if LoadHMACSecret() != "" {
		t.Fatalf("未配置时 HMAC 应为空串")
	}
}
