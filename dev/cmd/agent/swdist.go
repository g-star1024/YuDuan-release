// 御端副端 —— M5 软件分发安装模块（Go 参考实现）。
// 说明：演示链路覆盖「下载→按平台静默安装（或解包）→回报状态」；真实的静默安装命令
// 已按平台写明，生产 Rust 副端将在对应平台模块落地（需管理员权限）。
package main

import (
	"archive/zip"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"yuduan/internal/proto"
	"yuduan/internal/ws"
)

// handleSwInstall 处理软件安装指令：下载安装包并按平台静默安装。
func handleSwInstall(conn *ws.Conn, c proto.CommandPayload) {
	res := proto.ResultPayload{TaskID: c.TaskID}
	log.Printf("[agent] sw_install url=%s platform=%s pkg=%s", c.SoftwareURL, c.Platform, c.PkgName)

	tmp, err := downloadFile(c.SoftwareURL)
	if err != nil {
		res.State = "failed"
		res.OutputLog = "download failed: " + err.Error()
		sendResult(conn, res)
		return
	}
	defer os.Remove(tmp)

	log := installPackage(tmp, c.PkgName)
	res.State = "success"
	res.OutputLog = fmt.Sprintf("downloaded %s -> %s", filepath.Base(tmp), log)
	sendResult(conn, res)
}

func downloadFile(url string) (string, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http %d", resp.StatusCode)
	}
	f, err := os.CreateTemp("", "yuduan-sw-*")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return "", err
	}
	return f.Name(), nil
}

// installPackage 按平台执行静默安装或解包，返回执行摘要。
func installPackage(tmp, pkgName string) string {
	ext := filepath.Ext(pkgName)
	if ext == "" {
		ext = filepath.Ext(tmp)
	}
	switch ext {
	case ".zip":
		dest := filepath.Join(os.TempDir(), "yuduan-sw", baseName(pkgName))
		_ = os.MkdirAll(dest, 0o755)
		n, err := unzip(tmp, dest)
		if err != nil {
			return "unzip failed: " + err.Error()
		}
		return fmt.Sprintf("unzipped %d files to %s", n, dest)
	case ".pkg":
		if runtime.GOOS == "darwin" {
			out, err := runCmd("installer", "-pkg", tmp, "-target", "/")
			if err != nil {
				return "installer failed: " + err.Error() + " | out: " + out
			}
			return "macOS installer -target / ok: " + out
		}
		return "[TODO] pkg 仅 macOS 支持，当前平台跳过（生产 Rust 副端实现）"
	case ".dmg":
		return "[TODO] dmg 挂载+拷贝：hdiutil attach + cp to /Applications（生产 Rust 副端实现）"
	case ".msi":
		if runtime.GOOS == "windows" {
			out, err := runCmd("msiexec", "/i", tmp, "/qn")
			if err != nil {
				return "msiexec failed: " + err.Error()
			}
			return "msiexec /qn ok: " + out
		}
		return "[TODO] msi 仅 Windows 支持（生产 Rust 副端实现）"
	case ".exe":
		if runtime.GOOS == "windows" {
			out, err := runCmd(tmp, "/S")
			if err != nil {
				return "exe /S failed: " + err.Error()
			}
			return "exe /S ok: " + out
		}
		return "[TODO] exe 静默需 Windows（生产 Rust 副端实现）"
	case ".deb":
		if runtime.GOOS == "linux" {
			out, err := runCmd("dpkg", "-i", tmp)
			if err != nil {
				return "dpkg -i failed: " + err.Error() + " | out: " + out
			}
			return "dpkg -i ok: " + out
		}
		return "[TODO] deb 仅 Linux 支持（生产 Rust 副端实现）"
	case ".rpm":
		if runtime.GOOS == "linux" {
			out, err := runCmd("rpm", "-i", tmp)
			if err != nil {
				return "rpm -i failed: " + err.Error() + " | out: " + out
			}
			return "rpm -i ok: " + out
		}
		return "[TODO] rpm 仅 Linux 支持（生产 Rust 副端实现）"
	default:
		return "unsupported package ext " + ext + "，已下载至 " + tmp + "（生产按类型扩展）"
	}
}

func unzip(src, dest string) (int, error) {
	r, err := zip.OpenReader(src)
	if err != nil {
		return 0, err
	}
	defer r.Close()
	n := 0
	for _, f := range r.File {
		p := filepath.Join(dest, f.Name)
		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(p, 0o755)
			continue
		}
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		rc, err := f.Open()
		if err != nil {
			return n, err
		}
		out, err := os.Create(p)
		if err != nil {
			rc.Close()
			return n, err
		}
		_, _ = io.Copy(out, rc)
		out.Close()
		rc.Close()
		n++
	}
	return n, nil
}

func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func baseName(name string) string {
	e := filepath.Ext(name)
	if e == "" {
		return name
	}
	return name[:len(name)-len(e)]
}
