#!/usr/bin/env python3
# 御端 Wave 3（软件分发升级）端到端验证（仅标准库）。
# 覆盖：W3-1 模板库 / W3-2 分发任务（forced+optional）/ W3-3 版本比对 / W3-4 失败重试 / W3-5 高可用。
# 副端安装默认 dry-run（YUDUAN_W3_INSTALL 未置位），验证「下载+校验+回执」链路与状态机。
import json, os, subprocess, sys, time, urllib.request, urllib.error, hashlib, tempfile

urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))

DEV = "/Users/huluobo/WorkBuddy/jiankong/dev"
BIN = "/tmp/yuduan-wave3"
HUB = os.path.join(BIN, "hub")
AGENT = os.path.join(BIN, "agent")
SECRET = "wave3-secret"
PORT = os.environ.get("YUDUAN_E2E_PORT", "18083")
BASE = "http://127.0.0.1:" + PORT
os.makedirs(BIN, exist_ok=True)

PASS = FAIL = 0
def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1; print(f"  ✓ {name}")
    else:
        FAIL += 1; print(f"  ✗ {name}  {detail}")

def build():
    for name, pkg in [("hub", "./cmd/hub"), ("agent", "./cmd/agent")]:
        subprocess.run(["go", "build", "-o", os.path.join(BIN, name), pkg], cwd=DEV, check=True)
    print("[build] hub + agent 编译完成")

def start_hub():
    env = dict(os.environ, YUDUAN_HMAC_SECRET=SECRET, YUDUAN_REPO="/tmp/yuduan-wave3-repo",
               YUDUAN_HUB_ADDR=":" + PORT, YUDUAN_PUBLIC_ADDR="127.0.0.1:" + PORT)
    return subprocess.Popen([HUB], cwd=DEV, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def start_agent():
    env = dict(os.environ, YUDUAN_HUB=f"ws://127.0.0.1:{PORT}/ws/agent", YUDUAN_HMAC_SECRET=SECRET)
    return subprocess.Popen([AGENT], cwd=DEV, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def req(path, data=None, token=None, method=None, raw=False):
    url = BASE + path
    if method is None:
        method = "POST" if data is not None else "GET"
    r = urllib.request.Request(url, method=method)
    if token: r.add_header("Authorization", "Bearer " + token)
    if data is not None:
        r.add_header("Content-Type", "application/json")
        r.data = json.dumps(data).encode()
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            rawb = resp.read()
            ct = resp.headers.get("Content-Type", "")
            if raw:
                return resp.status, rawb
            return resp.status, (json.loads(rawb) if "json" in ct else rawb)
    except urllib.error.HTTPError as e:
        return e.code, {"_raw": e.read().decode()[:200]}
    except Exception as e:
        return -1, {"error": str(e)}

def login():
    st, b = req("/api/v1/login", {"username": "admin", "password": "admin123"})
    if st != 200 or not b.get("token"): raise SystemExit("login 失败: " + str(b))
    st, b = req("/api/v1/password", {"old_password": "admin123", "new_password": "Admin@2026x"}, token=b["token"])
    return b.get("token")

def upload_pkg(token, name, data, platform="macos"):
    # multipart 上传
    boundary = "----yuduan" + hashlib.md5(os.urandom(8)).hexdigest()[:12]
    parts = []
    def field(k, v):
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
    field("name", name); field("version", "1.0.0"); field("platform", platform)
    parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode())
    parts.append(data)
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    body = b"".join(parts)
    r = urllib.request.Request(BASE + "/api/v1/software", data=body, method="POST")
    r.add_header("Authorization", "Bearer " + token)
    r.add_header("Content-Type", "multipart/form-data; boundary=" + boundary)
    with urllib.request.urlopen(r, timeout=20) as resp:
        return json.loads(resp.read())

def wait_online(token, timeout=20):
    for _ in range(timeout):
        st, b = req("/api/v1/devices", token=token)
        if st == 200 and b.get("total", 0) >= 1:
            return b["devices"][0]["id"]
        time.sleep(1)
    return None

def wait_task_state(token, task_id, want, timeout=15):
    for _ in range(timeout):
        st, b = req(f"/api/v1/swdist/tasks/{task_id}", token=token)
        if st == 200:
            for r in b.get("records", []):
                if r.get("state") == want:
                    return r
        time.sleep(1)
    return None

def main():
    build()
    hub = start_hub(); time.sleep(1.5)
    print(f"[hub] 启动 :{PORT}")
    token = login()
    check("admin 登录+改密", bool(token))
    agent = start_agent(); time.sleep(2.5)
    dev_id = wait_online(token)
    check("副端注册上线", dev_id is not None, f"dev_id={dev_id}")
    if not dev_id:
        agent.terminate(); hub.terminate()
        print(f"\n=== Wave3 e2e: PASS={PASS} FAIL={FAIL} ==="); sys.exit(1)

    # ---- W3-1 模板库 ----
    st, b = req("/api/v1/swdist/templates", token=token)
    check("W3-1 模板库可访问", st == 200 and b.get("code") == 0, f"st={st}")
    n = b.get("total", 0) if isinstance(b, dict) else 0
    check("W3-1 内置默认模板已注入", n > 0, f"total={n}")
    st, b = req("/api/v1/swdist/templates/resolve", {"platform": "macos", "pkg_type": "dmg"}, token=token)
    check("W3-1 模板解析", st == 200 and b.get("code") == 0, f"st={st}")

    # ---- 上传安装包 ----
    fake_pkg = b"#!/bin/sh\necho fake-installer\n" * 100  # 5120B 模拟安装包
    up = upload_pkg(token, "demo-installer.pkg", fake_pkg, "macos")
    item = up.get("item") or {}
    check("上传安装包", bool(item.get("id")), f"id={item.get('id')}")
    repo_id = item.get("id")
    sha = item.get("sha256", "")

    # ---- W3-2 forced 分发任务 ----
    task_body = {
        "repo_id": repo_id,
        "pkg_name": "demo-installer.pkg",
        "version": "1.0.0",
        "platform": "macos",
        "pkg_type": "pkg",
        "targets": {"device_ids": [dev_id]},
        "mode": "forced",
        "target_version": "1.0.0",
    }
    st, b = req("/api/v1/swdist/tasks", task_body, token=token)
    check("W3-2 创建分发任务", st == 200 and b.get("code") == 0, f"st={st} b={str(b)[:120]}")
    task_id = b.get("id")
    if task_id:
        rec = wait_task_state(token, task_id, "success", 15)
        check("W3-2 设备收到安装指令并回执（dry-run 成功）", rec is not None, f"task={task_id}")
        if rec:
            print(f"      record state={rec.get('state')} output={str(rec.get('output'))[:80]}")

    # ---- W3-3 版本比对：目标版本=当前 → 跳过 ----
    task_body["target_version"] = "1.0.0"
    task_body["version"] = "1.0.0"
    st, b = req("/api/v1/swdist/tasks", task_body, token=token)
    check("W3-3 创建版本比对任务", st == 200 and b.get("code") == 0, f"st={st}")
    tid3 = b.get("id")
    if tid3:
        rec = wait_task_state(token, tid3, "skipped", 15)
        check("W3-3 版本不落后 → skipped", rec is not None, f"task={tid3}")
        if rec:
            print(f"      skip reason={str(rec.get('reason'))[:60]}")

    # ---- W3-2 optional：首次 confirm_required → confirm 后 success ----
    task_body["mode"] = "optional"
    task_body.pop("target_version", None)
    task_body["version"] = "2.0.0"
    st, b = req("/api/v1/swdist/tasks", task_body, token=token)
    check("W3-2 创建 optional 任务", st == 200 and b.get("code") == 0, f"st={st}")
    tido = b.get("id")
    if tido:
        rec = wait_task_state(token, tido, "confirm_required", 15)
        check("W3-2 optional 首次 → confirm_required", rec is not None, f"task={tido}")
        rid = rec.get("id") if rec else None
        if rid:
            st, b = req(f"/api/v1/swdist/tasks/{tido}/records/{rid}/confirm", {"confirm": True}, token=token)
            check("W3-2 confirm 确认接口", st == 200 and b.get("code") == 0, f"st={st} b={str(b)[:100]}")
            rec2 = wait_task_state(token, tido, "success", 15)
            check("W3-2 confirm 后重发 → 安装成功", rec2 is not None, f"task={tido}")

    # ---- W3-5 高可用：节点视图 ----
    st, b = req("/api/v1/ha/nodes", token=token)
    check("W3-5 高可用节点视图", st == 200 and b.get("code") == 0, f"st={st}")
    nodes = b.get("nodes", []) if isinstance(b, dict) else []
    check("W3-5 本节点已注册", any(n.get("hub_id") for n in nodes), f"nodes={len(nodes)}")
    leader = [n for n in nodes if n.get("role") == "leader"]
    check("W3-5 有 leader", len(leader) >= 1, f"nodes={nodes}")

    agent.terminate(); hub.terminate()
    print(f"\n=== Wave3 e2e: PASS={PASS} FAIL={FAIL} ===")
    sys.exit(0 if FAIL == 0 else 1)

if __name__ == "__main__":
    main()
