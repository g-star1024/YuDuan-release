#!/usr/bin/env python3
"""e2e：主端自更新检查链路（T-4 方案 B，2026-10-25）。

验证面：hub M5 软件仓库 API（/api/v1/software）返回字段与主端
hub_client::SoftwareItem serde 反序列化口径一致；上传 version/platform
后能作为更新源被 latest_update 语义消费。

前置：无（脚本自起 hub / 自清理）。
用法：python3 e2e_tauri_update.py
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error

DEV = os.path.dirname(os.path.abspath(__file__))
HUB_BIN = os.path.join(DEV, "bin", "hub")
PORT = 18777
BASE = f"http://127.0.0.1:{PORT}"

PASS = 0
FAIL = 0

def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"[OK] {name}" + (f"：{detail}" if detail else ""))
    else:
        FAIL += 1
        print(f"[FAIL] {name} {detail}")

def api(path, method="GET", token=None, data=None, raw=None, ctype=None):
    req = urllib.request.Request(BASE + path, method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    body = raw
    if data is not None:
        body = json.dumps(data).encode()
        req.add_header("Content-Type", "application/json")
    elif raw is not None:
        req.add_header("Content-Type", ctype or "application/octet-stream")
    try:
        with urllib.request.urlopen(req, body, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")

def multipart_upload(path, file_bytes, fields):
    b = "----yuduan-e2e-boundary"
    parts = []
    for k, v in fields.items():
        parts.append(f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    parts.append(
        f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="yuduan-main.dmg"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n".encode() + file_bytes + b"\r\n"
    )
    parts.append(f"--{b}--\r\n".encode())
    req = urllib.request.Request(BASE + path, method="POST", data=b"".join(parts))
    req.add_header("Content-Type", f"multipart/form-data; boundary={b}")
    req.add_header("Authorization", "Bearer " + ADMIN_TOKEN[0])
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())

ADMIN_TOKEN = [""]

def main():
    if not os.path.exists(HUB_BIN):
        subprocess.run(["go", "build", "-o", HUB_BIN, "./cmd/hub"], cwd=DEV, check=True)
    tmp = tempfile.mkdtemp(prefix="yuduan-e2e-update-")
    log = open(os.path.join(tmp, "hub.log"), "w")
    hub = subprocess.Popen(
        [HUB_BIN],
        cwd=tmp,
        env={**os.environ, "YUDUAN_HUB_ADDR": f":{PORT}", "YUDUAN_TLS_ADDR": ""},
        stdout=log, stderr=subprocess.STDOUT,
    )
    try:
        for _ in range(50):
            try:
                api("/api/v1/devices")
                break
            except Exception:
                time.sleep(0.2)
        # 登录（seed admin 首登强制改密）
        st, v = api("/api/v1/login", "POST", data={"username": "admin", "password": "admin123"})
        tok = v.get("token", "")
        st, v = api("/api/v1/password", "POST", token=tok,
                    data={"old_password": "admin123", "new_password": "Admin@2026x"})
        ADMIN_TOKEN[0] = v.get("token", tok)
        check("登录+改密续签", st == 200 and ADMIN_TOKEN[0], f"code={v.get('code')}")

        # 上传「新版主端安装包」：name=yuduan-main version=0.2.0 platform=macos
        payload = b"YUDUAN-MAIN-DMG-FAKE-" + os.urandom(2048)
        up = multipart_upload("/api/v1/software", payload,
                              {"name": "yuduan-main", "version": "0.2.0", "platform": "macos"})
        check("上传 0.2.0/macos", up.get("code") == 0 or up.get("id"), str(up)[:120])

        # 干扰项：其他平台 + 其他包名
        multipart_upload("/api/v1/software", b"x", {"name": "yuduan-main", "version": "9.9.9", "platform": "windows"})
        multipart_upload("/api/v1/software", b"x", {"name": "other", "version": "9.9.9", "platform": "macos"})

        st, v = api("/api/v1/software", token=ADMIN_TOKEN[0])
        items = v.get("items", [])
        check("软件列表可达", st == 200 and len(items) == 3, f"total={v.get('total')}")
        want_keys = {"id", "name", "version", "platform", "file_name", "size"}
        got_keys = set(items[0].keys()) if items else set()
        check("SoftwareItem 字段与主端 serde 口径一致", want_keys <= got_keys,
              f"missing={want_keys - got_keys}")

        # 主端侧语义校验：本地 0.1.0 → 应命中 0.2.0/macos（9.9.9/windows 与 other 不参选）
        rust = subprocess.run(
            ["cargo", "test", "-q", "--manifest-path",
             os.path.join(DEV, "..", "main", "src-tauri", "Cargo.toml"), "latest_update"],
            capture_output=True, text=True)
        check("主端 latest_update 单测", rust.returncode == 0 and "1 passed" in (rust.stdout + rust.stderr),
              (rust.stdout + rust.stderr).strip().splitlines()[-1] if rust.stdout else "")
    finally:
        hub.send_signal(signal.SIGTERM)
        try:
            hub.wait(timeout=5)
        except Exception:
            hub.kill()
        log.close()
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"\ne2e_tauri_update: {PASS} pass / {FAIL} fail")
    sys.exit(1 if FAIL else 0)

if __name__ == "__main__":
    main()
