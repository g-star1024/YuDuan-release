#!/usr/bin/env python3
# 御端 · 复盘 S-8/V-08（软件分发完整性）端到端对抗验证。
#
# 风险：副端下载安装包时 TLS 校验关闭（InsecureSkipVerify，内网自签历史包袱），
#       且摘要「有则校、无则放行」。两者叠加 ⇒ 内网对路径者替换响应体后，
#       安装包由 msiexec/installer/dpkg 以 SYSTEM/root 权限执行 —— MITM 等价 RCE。
#
# 本脚本以**真实编译产物**（中枢 + Go 参考副端 + Rust 生产副端）与一个本地
# 假软件源（扮演对路径者）验证三条底线：
#   ① 无摘要 → 拒绝安装（不得落到安装环节）
#   ② 摘要不符 → 拒绝安装（换包被识破）
#   ③ 摘要正确 → 正常放行（不得把正常链路打死）
#
# 仅依赖标准库。用法：python3 dev/e2e_s8.py
import hashlib, json, os, socket, subprocess, sys, threading, time, urllib.request, urllib.error

urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))

DEV = "/Users/huluobo/WorkBuddy/jiankong/dev"
RUST = "/Users/huluobo/WorkBuddy/jiankong/rust"
BIN = "/tmp/yuduan-s8"
HUB = os.path.join(BIN, "hub")
AGENT = os.path.join(BIN, "agent")
RUST_AGENT = os.path.join(RUST, "agent", "target", "agent")
SECRET = "s8-secret"
os.makedirs(BIN, exist_ok=True)

PASS = FAIL = 0
PKG = b"YUDUAN-FAKE-INSTALLER-BINARY-PAYLOAD-0001"


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print("  ✓ " + name)
    else:
        FAIL += 1
        print("  ✗ " + name + "  " + detail)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = str(s.getsockname()[1])
    s.close()
    return p


class FakeRepo(threading.Thread):
    """假软件源：始终返回安装包正文，可被"对路径者"替换内容。"""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.port = int(port)
        self.body = PKG
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", self.port))
        self.srv.listen(8)
        self.stop = False

    def run(self):
        while not self.stop:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            try:
                c.settimeout(3)
                buf = b""
                while b"\r\n\r\n" not in buf:
                    d = c.recv(4096)
                    if not d:
                        break
                    buf += d
                head = (
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                    "Content-Length: %d\r\nConnection: close\r\n\r\n" % len(self.body)
                ).encode()
                c.sendall(head + self.body)
            except Exception:
                pass
            finally:
                try:
                    c.close()
                except Exception:
                    pass

    def shutdown(self):
        self.stop = True
        try:
            self.srv.close()
        except Exception:
            pass


def http(base, path, data=None, token=None, timeout=10):
    req = urllib.request.Request(base + path, method="POST" if data is not None else "GET")
    if data is not None:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(data).encode()
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            try:
                return r.status, json.loads(raw)
            except Exception:
                return r.status, {"_raw": raw[:200]}
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}
    except Exception as e:
        return -1, {"error": str(e)}


def wait_hub(base, timeout=25):
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(base + "/api/v1/login", timeout=2)
        except urllib.error.HTTPError:
            return True
        except Exception:
            pass
        time.sleep(0.3)
    return False


def wait_device(base, token, want_version=None, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        st, b = http(base, "/api/v1/devices", token=token)
        if st == 200:
            for d in b.get("devices", []):
                if d.get("online"):
                    if want_version and want_version not in (d.get("agent_version") or ""):
                        continue
                    return d
        time.sleep(0.5)
    return None


def task_records(base, token, task_id, contains=None, timeout=40):
    """等待首条记录带回升执；记录态会在 retry_waiting 间流转（W3-4 自动重试），
    故以「回执内容」而非终态作为判定依据。"""
    end = time.time() + timeout
    last = None
    while time.time() < end:
        st, b = http(base, "/api/v1/swdist/tasks/" + task_id, token=token)
        if st == 200:
            recs = (b.get("task") or {}).get("records") or b.get("records") or []
            if recs:
                r = recs[0]
                last = r
                out = str(r.get("output") or "")
                if out and (contains is None or contains in out):
                    return r
                if r.get("state") in ("success", "skipped"):
                    return r
        time.sleep(0.5)
    return last


def main():
    print("[build] 编译中枢与参考副端…")
    for name, pkg in [("hub", "./cmd/hub"), ("agent", "./cmd/agent")]:
        subprocess.run(["go", "build", "-o", os.path.join(BIN, name), pkg], cwd=DEV, check=True)

    port = free_port()
    base = "http://127.0.0.1:" + port
    repo_port = free_port()
    repo = FakeRepo(repo_port)
    repo.start()
    time.sleep(0.3)
    pkg_url = "http://127.0.0.1:%s/vendor-installer.pkg" % repo_port
    good_sha = hashlib.sha256(PKG).hexdigest()

    hub = subprocess.Popen([HUB], cwd=DEV,
                           env=dict(os.environ, YUDUAN_HMAC_SECRET=SECRET, YUDUAN_HUB_ADDR=":" + port,
                                    YUDUAN_REPO="/tmp/yuduan-s8-repo"),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    procs = [hub]
    try:
        check("中枢启动就绪", wait_hub(base))
        st, b = http(base, "/api/v1/login", {"username": "admin", "password": "admin123"})
        if st != 200 or not b.get("token"):
            print("登录失败:", b)
            return
        st, b2 = http(base, "/api/v1/password", {"old_password": "admin123", "new_password": "Admin@2026x"},
                      token=b["token"])
        tok = b2.get("token") or b["token"]

        agent = subprocess.Popen([AGENT], cwd=DEV,
                                 env=dict(os.environ, YUDUAN_HUB="ws://127.0.0.1:%s/ws/agent" % port,
                                          YUDUAN_HMAC_SECRET=SECRET,
                                          YUDUAN_STATE_FILE="/tmp/yuduan-s8-go.json"))
        procs.append(agent)
        dev = wait_device(base, tok)
        check("合规副端上线", dev is not None)
        if not dev:
            return

        print("\n[1/4] 无 SHA-256 摘要的外部地址 → 必须拒绝安装（MITM 防护底线）")
        st, b = http(base, "/api/v1/swdist/tasks", {
            "software_url": pkg_url, "pkg_name": "vendor-installer.pkg", "platform": "macos",
            "targets": {"device_ids": [dev["id"]]}, "mode": "forced",
        }, token=tok)
        check("创建无摘要分发任务", st == 200 and b.get("code") == 0, f"st={st} b={str(b)[:120]}")
        tid = b.get("id") or (b.get("task") or {}).get("id")
        check("创建响应返回任务 ID", bool(tid), str(b)[:160])
        if tid:
            r = task_records(base, tok, tid, contains="缺少 SHA-256")
            out = json.dumps(r or {}, ensure_ascii=False)
            refused = bool(r) and ("缺少 SHA-256" in str(r.get("output"))) and str(r.get("state")) in ("failed", "retry_waiting")
            check("副端拒绝无摘要的安装包", refused, out[:260])

        print("\n[2/4] 摘要不符（安装包被替换）→ 必须拒绝")
        st, b = http(base, "/api/v1/swdist/tasks", {
            "software_url": pkg_url, "pkg_name": "vendor-installer.pkg", "platform": "macos",
            "sha256": "0" * 64, "targets": {"device_ids": [dev["id"]]}, "mode": "forced",
        }, token=tok)
        check("创建错摘要分发任务", st == 200 and b.get("code") == 0, f"st={st} b={str(b)[:120]}")
        tid2 = b.get("id") or (b.get("task") or {}).get("id")
        if tid2:
            r = task_records(base, tok, tid2, contains="SHA-256 校验失败")
            out = json.dumps(r or {}, ensure_ascii=False)
            refused = bool(r) and ("SHA-256 校验失败" in str(r.get("output"))) and str(r.get("state")) in ("failed", "retry_waiting")
            check("副端识破被替换的安装包", refused, out[:260])

        print("\n[3/4] 摘要正确 → 正常放行（门禁不得误杀）")
        st, b = http(base, "/api/v1/swdist/tasks", {
            "software_url": pkg_url, "pkg_name": "vendor-installer.pkg", "platform": "macos",
            "sha256": good_sha, "version": "9.9.9", "targets": {"device_ids": [dev["id"]]}, "mode": "forced",
        }, token=tok)
        check("创建带正确摘要的任务", st == 200 and b.get("code") == 0, f"st={st} b={str(b)[:120]}")
        tid3 = b.get("id") or (b.get("task") or {}).get("id")
        if tid3:
            r = task_records(base, tok, tid3)
            out = json.dumps(r or {}, ensure_ascii=False)
            check("副端通过校验并进入安装环节", (r or {}).get("state") == "success", out[:260])

        print("\n[4/4] Rust 生产副端（三平台主力）同口径")
        if not os.path.exists(RUST_AGENT):
            print("      未找到 Rust 产物，跳过（需先 rustc 构建）")
        else:
            rust = subprocess.Popen([RUST_AGENT],
                                    env=dict(os.environ, YUDUAN_HUB="ws://127.0.0.1:%s/ws/agent" % port,
                                             YUDUAN_HMAC_SECRET=SECRET,
                                             YUDUAN_STATE_FILE="/tmp/yuduan-s8-rust.json"))
            procs.append(rust)
            rdev = wait_device(base, tok, want_version="rust", timeout=60)
            if not rdev:
                # 设备列表的 agent_version 未必含 rust 标记：取第二台在线设备
                st2, b2 = http(base, "/api/v1/devices", token=tok)
                online = [d for d in (b2.get("devices") or []) if d.get("online")]
                rdev = online[-1] if online else None
            check("Rust 副端上线", rdev is not None)
            if rdev:
                st, b = http(base, "/api/v1/swdist/tasks", {
                    "software_url": pkg_url, "pkg_name": "vendor-installer.pkg", "platform": "macos",
                    "targets": {"device_ids": [rdev["id"]]}, "mode": "forced",
                }, token=tok)
                tid4 = b.get("id") or (b.get("task") or {}).get("id")
                if tid4:
                    r = task_records(base, tok, tid4, contains="缺少 SHA-256")
                    out = json.dumps(r or {}, ensure_ascii=False)
                    refused = bool(r) and ("缺少 SHA-256" in str(r.get("output"))) and str(r.get("state")) in ("failed", "retry_waiting")
                    check("Rust 副端同样拒绝无摘要安装包", refused, out[:260])
    finally:
        repo.shutdown()
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in procs:
            try:
                p.wait(timeout=5)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    print("\n==== s8: %d/%d PASS ====" % (PASS, PASS + FAIL))
    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()
