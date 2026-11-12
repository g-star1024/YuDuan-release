package collect

import "testing"

// v0.4.10（实测报告问题 4）：稳定设备 ID 黄金向量——与 Rust 副端 stable_device_id
// （main.rs）共用同一期望值，任何一端规范串漂移都会在此暴露。向量同时覆盖
// trim + 小写归一（输入大小写/空白与规范形式不一致仍必须命中同一 ID）。
func TestStableDeviceIDGoldenVector(t *testing.T) {
	got := StableDeviceID("Host1", "AA:BB:CC:DD:EE:FF", " Serial1 ")
	want := "2f4a3ec08455b175"
	if got != want {
		t.Fatalf("StableDeviceID 归一化黄金向量不符: got=%s want=%s", got, want)
	}
	// 规范形式输入同值
	if got2 := StableDeviceID("host1", "aa:bb:cc:dd:ee:ff", "serial1"); got2 != want {
		t.Fatalf("规范输入与归一输入不一致: %s vs %s", got2, want)
	}
	// 空身份（三段全空）仍应产出确定值而非空串
	if StableDeviceID("", "", "") == "" {
		t.Fatal("空身份不应产出空 ID")
	}
}
