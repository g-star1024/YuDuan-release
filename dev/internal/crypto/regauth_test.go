// 注册挑战应答（§9.1）黄金向量——跨实现防漂移护栏。
//
// 规范串一旦在中枢 / Go 副端 / Rust 副端 / e2e 脚本任一处发生哪怕一个字节的变化，
// 全网设备将无法完成注册；而这类故障在"单端自测全绿"下是不可见的。
// 故以固定输入 + 期望 hex 三方互锁：本用例在 Go 侧锚定，Rust secure.rs 与
// dev/e2e_regauth.py 使用同一组期望值。
package crypto

import "testing"

func TestSignRegisterAuthGolden(t *testing.T) {
	cases := []struct {
		name, secret, nonce, token, want string
	}{
		{
			name:   "带设备令牌",
			secret: "yuduan-golden-secret",
			nonce:  "000102030405060708090a0b0c0d0e0f",
			token:  "dev-token-1",
			want:   "29ad76ae575ea8e5f224b8668f8b94fba27cd3f59339919ab731e2ac8c9a1b45",
		},
		{
			name:   "首次注册令牌为空",
			secret: "yuduan-golden-secret",
			nonce:  "000102030405060708090a0b0c0d0e0f",
			token:  "",
			want:   "f1decc1d2b2969404323ac050c79f332dfcba6800182a0bb77d8deefd06c502b",
		},
		{
			name:   "另一组密钥",
			secret: "s3-cret",
			nonce:  "nonce-empty-token",
			token:  "",
			want:   "9896f83576ea8f969c12de9282dc1828e201f66be92f4a763de626ae74fd76f4",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := SignRegisterAuth(c.secret, c.nonce, c.token)
			if got != c.want {
				t.Fatalf("MAC 与黄金向量不一致：got=%s want=%s", got, c.want)
			}
			if !VerifyRegisterAuth(c.secret, c.nonce, c.token, c.want) {
				t.Fatalf("同一 MAC 未能通过校验")
			}
		})
	}
}

func TestVerifyRegisterAuthNegative(t *testing.T) {
	const secret, nonce, token = "yuduan-golden-secret", "abc123", "tok"
	mac := SignRegisterAuth(secret, nonce, token)

	neg := []struct {
		name, got string
	}{
		{"空 MAC", ""},
		{"错值", "deadbeef"},
		{"前缀正确尾部多字节", mac + "00"},
		{"大小写篡改", upperFirst(mac)},
	}
	for _, c := range neg {
		t.Run(c.name, func(t *testing.T) {
			if VerifyRegisterAuth(secret, nonce, token, c.got) {
				t.Fatalf("应拒绝，却通过：%s", c.got)
			}
		})
	}

	// 绑定维度：token 不同（拿 A 设备的应答去注册 B 设备）→ 必须失败
	if VerifyRegisterAuth(secret, nonce, "tok2", mac) {
		t.Fatal("不同 token 的应答竟通过校验（身份未绑定）")
	}
	// 密钥不同 → 必须失败
	if VerifyRegisterAuth("wrong-secret", nonce, token, mac) {
		t.Fatal("错误密钥竟通过校验")
	}
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	r := []byte(s)
	if r[0] >= 'a' && r[0] <= 'z' {
		r[0] -= 32
	}
	return string(r)
}
