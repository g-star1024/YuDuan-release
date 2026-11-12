// 非 Windows 平台的软件清单采集（macOS / Linux）。
//
//go:build !windows

package collect

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"yuduan/internal/proto"
)

func platformSoftware() []proto.InstalledSoftware {
	if runtime.GOOS == "darwin" {
		return macSoftware()
	}
	return linuxSoftware()
}

// ---- macOS：扫描 .app 包读 Info.plist（快，无 N 子进程）----

func macSoftware() []proto.InstalledSoftware {
	dirs := []string{"/Applications", "/System/Applications"}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "Applications"))
	}
	seen := map[string]bool{}
	var out []proto.InstalledSoftware
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".app") {
				continue
			}
			bundle := filepath.Join(dir, name)
			info := filepath.Join(bundle, "Contents", "Info.plist")
			b, err := os.ReadFile(info)
			if err != nil {
				continue
			}
			appName := plistString(b, "CFBundleName")
			if appName == "" {
				appName = strings.TrimSuffix(name, ".app")
			}
			key := strings.ToLower(appName)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, proto.InstalledSoftware{
				Name:      appName,
				Version:   plistString(b, "CFBundleShortVersionString"),
				Source:    "app_bundle:" + dir,
				Publisher: plistString(b, "CFBundleIdentifier"),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// plistString 从 Apple Info.plist XML 中提取 <key>k</key><string>v</string> 的 v。
// 只处理 string 类型值（CFBundleName/ShortVersionString/Identifier 均为 string）。
func plistString(xmlData []byte, key string) string {
	s := string(xmlData)
	idx := strings.Index(s, "<key>"+key+"</key>")
	if idx < 0 {
		return ""
	}
	rest := s[idx+len("<key>"+key+"</key>"):]
	si := strings.Index(rest, "<string>")
	if si < 0 {
		return ""
	}
	rest = rest[si+len("<string>"):]
	ei := strings.Index(rest, "</string>")
	if ei < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:ei])
}

// ---- Linux：dpkg 优先，rpm 回退 ----

func linuxSoftware() []proto.InstalledSoftware {
	if out, code := runCollect("dpkg-query", "-W", "-f=${Package}\t${Version}\t${Maintainer}\n"); code == 0 && strings.Contains(out, "\t") {
		return parseTabLines(out)
	}
	if out, code := runCollect("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\t%{VENDOR}\n"); code == 0 && strings.Contains(out, "\t") {
		return parseTabLines(out)
	}
	return nil
}

// parseTabLines 解析 "name\tversion\tpublisher" 逐行清单。
func parseTabLines(out string) []proto.InstalledSoftware {
	var items []proto.InstalledSoftware
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		it := proto.InstalledSoftware{Source: "linux_pkg"}
		if len(f) > 0 {
			it.Name = strings.TrimSpace(f[0])
		}
		if len(f) > 1 {
			it.Version = strings.TrimSpace(f[1])
		}
		if len(f) > 2 {
			it.Publisher = strings.TrimSpace(f[2])
		}
		if it.Name != "" {
			items = append(items, it)
		}
	}
	sort.Slice(items, func(i, j int) bool { return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name) })
	return items
}

// runCollect 执行命令并返回 (stdout, exitCode)；失败返回空串与 -1。
func runCollect(name string, args ...string) (string, int) {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", ee.ExitCode()
		}
		return "", -1
	}
	return string(out), 0
}
