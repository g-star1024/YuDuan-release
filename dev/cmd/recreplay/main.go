// recreplay —— 御端加密录像回放工具（protocol.md §8.3.12）。
//
// 解密 .yrec 录像文件，逐帧导出或仅校验。需持有录像主密钥：
//
//	recreplay -file 20261023-234511_xxx.yrec -key <32B hex>          # 显式主密钥
//	recreplay -file x.yrec -secret <HMAC 密钥>                        # 开发态派生密钥
//	recreplay -file x.yrec -secret s -out /tmp/frames                 # 导出帧文件
//	recreplay -file x.yrec -secret s -verify ffmpeg                   # 校验后逐帧调 ffmpeg
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"yuduan/internal/keystore"
	"yuduan/internal/record"
)

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "recreplay: "+f+"\n", a...)
	os.Exit(1)
}

func main() {
	file := flag.String("file", "", "录像文件路径（.yrec）")
	keyHex := flag.String("key", "", "录像主密钥（32 字节 hex；与 -secret 二选一）")
	secret := flag.String("secret", "", "HMAC 密钥（开发态派生录像主密钥）")
	out := flag.String("out", "", "帧导出目录（缺省仅校验不导出）")
	verify := flag.String("verify", "", "对每个导出帧执行的外部解码器（如 ffmpeg；占位符 {} 为帧路径）")
	flag.Parse()
	if *file == "" {
		fatal("需指定 -file")
	}

	var master []byte
	if *keyHex != "" {
		k, err := hex.DecodeString(*keyHex)
		if err != nil || len(k) != 32 {
			fatal("-key 需为 32 字节 hex（64 字符）")
		}
		master = k
	} else if *secret != "" {
		master = record.DeriveMaster(*secret)
	} else if k := keystore.LoadRecordKey(); k != nil {
		master = k
	} else {
		fatal("需提供 -key / -secret / YUDUAN_RECORD_KEY 之一")
	}

	rec, err := record.ReadAll(*file, master)
	if err != nil {
		fatal("解密失败: %v", err)
	}
	m := rec.Meta
	fmt.Printf("会话: %s  设备: %s (%s)  操作者: %s\n", m.SessionID, m.DeviceID, m.Hostname, m.Operator)
	fmt.Printf("开始: %s  授权: %v  帧数: %d\n", m.StartedAt.Format("2006-01-02 15:04:05 MST"), m.Consent, len(rec.Frames))

	if *out != "" {
		if err := os.MkdirAll(*out, 0o700); err != nil {
			fatal("创建导出目录失败: %v", err)
		}
	}
	for i, fr := range rec.Frames {
		if len(fr) >= 4 && string(fr[:4]) == "YDYF" {
			fmt.Printf("帧 #%-3d %6d B  media 头: % x\n", i+1, len(fr), fr[:24])
		} else {
			fmt.Printf("帧 #%-3d %6d B\n", i+1, len(fr))
		}
		if *out != "" {
			p := filepath.Join(*out, fmt.Sprintf("frame-%03d.bin", i+1))
			if err := os.WriteFile(p, fr, 0o600); err != nil {
				fatal("写帧失败: %v", err)
			}
			if *verify != "" {
				cmd := exec.Command("sh", "-c", replacePlaceholder(*verify, p))
				cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
				if err := cmd.Run(); err != nil {
					fatal("外部校验失败（帧 #%d）: %v", i+1, err)
				}
			}
		}
	}
	fmt.Printf("回放完成: %d 帧\n", len(rec.Frames))
}

func replacePlaceholder(pattern, p string) string {
	for i := 0; i+1 < len(pattern); i++ {
		if pattern[i] == '{' && pattern[i+1] == '}' {
			return pattern[:i] + p + pattern[i+2:]
		}
	}
	return pattern + " " + p
}
