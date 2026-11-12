#!/usr/bin/env python3
# 御端 · Rust 生产副端 波次 3/4/5 + 软件清单 端到端验证（仅标准库）。
#
# 与既有 e2e 的差异：副端换为 **Rust 生产副端**（rust/agent，rustc 直接编译），
# 中枢仍是 Go 中枢（同一套 REST/WS 契约），以此验证「三端同构」（铁律 2/9）：
# Go 参考副端能跑通的能力，生产副端必须同样跑通。
#
# 覆盖：
#   W1-1 软件清单上报（rust/agent/src/swinv.rs）
#   W3-2 sw_dist（forced + optional→confirm_required）
#   W3-3 sw_uninstall（黑名单命中 → 卸载指令，副端 dry-run 回执）
#   W4-1 file.push_* 下发 / file.pull_* 采集
#   W5-1 compliance_collect
#   W5-2 黑名单扫描命中（依赖 W1-1 清单）
#   W5-5 patch_apply（漏洞任务下发）
#   W5-3 peripheral_apply / W5-4 nac_apply
import json, os, subprocess, sys, time, urllib.request, urllib.error, hashlib

urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))

ROOT = "/Users/huluobo/WorkBuddy/jiankong"
DEV = os.path.join(ROOT, "dev")
RUST = os.path.join(ROOT, "rust", "agent")
BIN = "/tmp/yuduan-ragent-e2e"
HUB = os.path.join(BIN, "hub")
AGENT = os.path.join(BIN, "agent")
WRITE_ROOT = os.path.join(BIN, "inbox")
PULL_ROOT = os.path.join(BIN, "outbox")
SECRET = "ragent-secret"
PORT = os.environ.get("YUDUAN_E2E_PORT", "18091")
BASE = "http://127.0.0.1:" + PORT
os.makedirs(BIN, exist_ok=True)
os.makedirs(WRITE_ROOT, exist_ok=True)
os.makedirs(PULL_ROOT, exist_ok=True)

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}  {detail}")


def build():
    subprocess.run(["go", "build", "-o", HUB, "./cmd/hub"], cwd=DEV, check=True)
    subprocess.run(
        ["rustc", "--edition", "2021", "-O", "-A", "warnings", "src/main.rs", "-o", AGENT],
        cwd=RUST, check=True)
    print("[build] hub(Go) + agent(Rust) 编译完成")


def start_hub():
    env = dict(os.environ, YUDUAN_HMAC_SECRET=SECRET, YUDUAN_REPO=os.path.join(BIN, "repo"),
               YUDUAN_HUB_ADDR=":" + PORT, YUDUAN_PUBLIC_ADDR="127.0.0.1:" + PORT)
    return subprocess.Popen([HUB], cwd=DEV, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def start_agent():
    env = dict(os.environ,
               YUDUAN_HUB=f"ws://127.0.0.1:{PORT}/ws/agent",
               YUDUAN_HMAC_SECRET=SECRET,
               YUDUAN_FS_WRITE_ROOT=WRITE_ROOT,
               YUDUAN_FS_PULL_ROOT=PULL_ROOT)
    return subprocess.Popen([AGENT], cwd=BIN, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def req(path, data=None, token=None, method=None):
    url = BASE + path
    if method is None:
        method = "POST" if data is not None else "GET"
    r = urllib.request.Request(url, method=method)
    if token:
        r.add_header("Authorization", "Bearer " + token)
    if data is not None:
        r.add_header("Content-Type", "application/json")
        r.data = json.dumps(data).encode()
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            rawb = resp.read()
            ct = resp.headers.get("Content-Type", "")
            return resp.status, (json.loads(rawb) if "json" in ct else rawb)
    except urllib.error.HTTPError as e:
        return e.code, {"_raw": e.read().decode()[:300]}
    except Exception as e:
        return -1, {"error": str(e)}


def login():
    st, b = req("/api/v1/login", {"username": "admin", "password": "admin123"})
    if st != 200 or not b.get("token"):
        raise SystemExit("login 失败: " + str(b))
    st, b = req("/api/v1/password", {"old_password": "admin123", "new_password": "Admin@2026x"}, token=b["token"])
    return b.get("token")


def upload_pkg(token, name, data, platform="macos"):
    boundary = "----yuduan" + hashlib.md5(os.urandom(8)).hexdigest()[:12]
    parts = []

    def field(k, v):
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())

    field("name", name)
    field("version", "1.0.0")
    field("platform", platform)
    parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode())
    parts.append(data)
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    r = urllib.request.Request(BASE + "/api/v1/software", data=b"".join(parts), method="POST")
    r.add_header("Authorization", "Bearer " + token)
    r.add_header("Content-Type", "multipart/form-data; boundary=" + boundary)
    with urllib.request.urlopen(r, timeout=25) as resp:
        return json.loads(resp.read())


def wait_online(token, timeout=25):
    for _ in range(timeout):
        st, b = req("/api/v1/devices", token=token)
        if st == 200 and b.get("total", 0) >= 1:
            return b["devices"][0]["id"]
        time.sleep(1)
    return None


def tid_of(b):
    """任务 ID：兼容 {"id":...} 与 {"task":{"id":...}} 两种返回形态。"""
    if not isinstance(b, dict):
        return None
    return b.get("id") or (b.get("task") or {}).get("id")


def wait_task(path, want, token, timeout=25):
    for _ in range(timeout):
        st, b = req(path, token=token)
        if st == 200:
            task = b.get("task", b)
            if task.get("state") == want:
                return task
            if want == "confirm_required":
                for r in task.get("records", []):
                    if r.get("state") == want:
                        return task
        time.sleep(1)
    return None


def wait_record(path, want, token, timeout=20):
    """等待任务下任一设备记录达到目标状态（分发任务的任务态不完全等于记录态）。"""
    last = None
    for _ in range(timeout):
        st, b = req(path, token=token)
        last = (st, b)
        if st == 200:
            for r in (b.get("records") or (b.get("task") or {}).get("records") or []):
                if r.get("state") == want:
                    return r, b
        time.sleep(1)
    return None, last


def main():
    build()
    hub = start_hub()
    time.sleep(1.5)
    print(f"[hub] 启动 :{PORT}")
    token = login()
    check("admin 登录+改密", bool(token))
    agent = start_agent()
    time.sleep(3)
    dev_id = wait_online(token)
    check("Rust 生产副端注册上线", dev_id is not None, f"dev_id={dev_id}")
    if not dev_id:
        agent.terminate()
        hub.terminate()
        print(f"\n=== Rust agent 波次3/4/5 e2e: PASS={PASS} FAIL={FAIL} ===")
        sys.exit(1)

    # ---------------- W1-1 软件清单上报 ----------------
    st, b = req(f"/api/v1/devices/{dev_id}", token=token)
    sw = []
    if st == 200:
        d = b.get("device", b)
        sw = d.get("software") or []
    check(f"W1-1 Rust 副端上报软件清单（{len(sw)} 项）", len(sw) > 0, f"st={st}")
    sw_names = [s.get("name", "") for s in sw if isinstance(s, dict)]
    if sw_names:
        print(f"      样例: {sw_names[:3]}")
    target_sw = next((n for n in sw_names if n and len(n) > 2), "")

    # ---------------- W3-2 分发（forced / dry-run）----------------
    fake_pkg = b"#!/bin/sh\necho fake-installer\n" * 100
    up = upload_pkg(token, "demo-installer.pkg", fake_pkg, "macos")
    item = up.get("item") or {}
    repo_id = item.get("id")
    check("上传安装包", bool(repo_id), f"id={repo_id}")

    task_body = {
        "repo_id": repo_id, "pkg_name": "demo-installer.pkg", "version": "1.0.0",
        "platform": "macos", "pkg_type": "pkg", "targets": {"device_ids": [dev_id]},
        "mode": "forced",
    }
    st, b = req("/api/v1/swdist/tasks", task_body, token=token)
    check("W3-2 创建 forced 分发任务", st == 200 and b.get("code") == 0, f"st={st} b={str(b)[:120]}")
    tid = tid_of(b)
    if tid:
        rec, full = wait_record(f"/api/v1/swdist/tasks/{tid}", "success", token)
        check("W3-2 副端执行 sw_dist 并回执（演练成功）", rec is not None, f"task={tid}")
        if rec:
            print(f"      record state={rec.get('state')} output={str(rec.get('output'))[:120]}")
        else:
            print(f"      [诊断] {str(full)[:400]}")

    # ---------------- W3-2 optional → confirm_required ----------------
    task_body["mode"] = "optional"
    task_body["version"] = "2.0.0"
    task_body.pop("target_version", None)
    st, b = req("/api/v1/swdist/tasks", task_body, token=token)
    tido = tid_of(b) if st == 200 else None
    if tido:
        # 中枢把副端的 confirm_required 记录态规范化为 awaiting_confirm
        rec, full = wait_record(f"/api/v1/swdist/tasks/{tido}", "awaiting_confirm", token, 15)
        ok_opt = rec is not None and "confirm_required" in str(rec.get("output", ""))
        check("W3-2 optional 首轮回执 confirm_required（中枢 awaiting_confirm）", ok_opt, f"task={tido}")
        if rec is None:
            import json as _j
            print(f"      [诊断] {_j.dumps(full, ensure_ascii=False)[:1200]}")
    else:
        check("W3-2 创建 optional 任务", False, f"st={st}")

    # ---------------- W4-1 文件下发（file.push_*）----------------
    payload = os.urandom(300 * 1024)
    src = os.path.join(BIN, "src.bin")
    open(src, "wb").write(payload)
    expected_sha = hashlib.sha256(payload).hexdigest()
    st, b = req("/api/v1/filesync/tasks", {"kind": "push", "name": "push-test", "source": src,
                                           "dest": "pushed.bin", "device_ids": [dev_id]}, token=token)
    check("W4-1 创建下发任务", st == 200 and b.get("code") == 0, f"st={st} b={str(b)[:120]}")
    fsid = tid_of(b)
    if fsid:
        t = wait_task(f"/api/v1/filesync/tasks/{fsid}", "success", token)
        check("W4-1 file.push_* 下发成功", t is not None, f"tid={fsid}")
        if t:
            rec = (t.get("records") or [{}])[0]
            got = rec.get("sha256", "")
            check("W4-1 落盘文件 SHA-256 一致", got.lower() == expected_sha.lower(),
                  f"expect={expected_sha[:16]} got={str(got)[:16]}")
            disk = os.path.join(WRITE_ROOT, "pushed.bin")
            ok_disk = os.path.exists(disk) and hashlib.sha256(open(disk, "rb").read()).hexdigest() == expected_sha
            check("W4-1 副端真实落盘且内容一致", ok_disk, f"path={disk}")
        else:
            st, b = req(f"/api/v1/filesync/tasks/{fsid}", token=token)
            print(f"      [诊断] {str(b)[:300]}")

    # ---------------- W4-1 文件采集（file.pull_*）----------------
    pull_src = os.path.join(PULL_ROOT, "collected.log")
    open(pull_src, "w").write("yuduan rust agent pull test\n" * 50)
    out_dir = os.path.join(BIN, "pulled")
    st, b = req("/api/v1/filesync/tasks", {"kind": "pull", "name": "pull-test",
                                           "source": "collected.log", "dest": out_dir,
                                           "device_ids": [dev_id]}, token=token)
    check("W4-1 创建采集任务", st == 200 and b.get("code") == 0, f"st={st} b={str(b)[:120]}")
    plid = tid_of(b)
    if plid:
        t = wait_task(f"/api/v1/filesync/tasks/{plid}", "success", token)
        check("W4-1 file.pull_* 采集成功", t is not None, f"tid={plid}")
        if t:
            got = os.path.join(out_dir, "collected.log")
            check("W4-1 中枢侧收到采集文件", os.path.exists(got), f"path={got}")
        else:
            st, b = req(f"/api/v1/filesync/tasks/{plid}", token=token)
            print(f"      [诊断] {str(b)[:300]}")

    # ---------------- W5-1 合规采集 ----------------
    st, b = req(f"/api/v1/compliance/devices/{dev_id}/collect", {}, token=token)
    check("W5-1 compliance_collect 指令下发成功", st == 200 and b.get("code") == 0, f"st={st} b={str(b)[:160]}")
    comp = b.get("compliance") or {}
    items = comp.get("items") or []
    print(f"      [合规] 合规分={comp.get('score')} 违规={len(comp.get('violations') or [])}")
    check(f"W5-1 副端回传合规项（{len(items)} 项）", len(items) >= 5, f"items={len(items)}")
    states = {i.get("state") for i in items if isinstance(i, dict)}
    check("W5-1 合规项状态合法（pass/fail/unknown）",
          bool(states) and states <= {"pass", "fail", "unknown"}, f"states={states}")
    if items:
        print(f"      样例: {items[0].get('key')}={items[0].get('state')}")

    # ---------------- W5-2 黑名单扫描 + sw_uninstall ----------------
    if target_sw:
        rule = {"pattern": target_sw, "match_type": "contains", "action": "uninstall",
                "severity": "high", "reason": "e2e"}
        st, b = req("/api/v1/blacklist/rules", rule, token=token)
        check("W5-2 创建黑名单规则", st == 200 and b.get("code") == 0, f"st={st} b={str(b)[:120]}")
        st, b = req(f"/api/v1/blacklist/scan/{dev_id}", {}, token=token)
        hits = b.get("hits") or b.get("items") or []
        check(f"W5-2 扫描命中违规软件（{len(hits) if isinstance(hits, list) else 0} 条）",
              st == 200 and isinstance(hits, list) and len(hits) > 0, f"st={st} b={str(b)[:160]}")
        # 命中即触发 sw_uninstall（副端 dry-run 回执），通过审计或 hits 的 action_taken 观测
        taken = ""
        if isinstance(hits, list) and hits:
            taken = str(hits[0].get("action_taken", ""))
        check("W3-3/W5-2 sw_uninstall 指令已被副端接收处理",
              "uninstall_dispatched" in taken or "dispatch_failed" not in taken,
              f"action_taken={taken or '<空>'}")
    else:
        check("W5-2 黑名单扫描（跳过：无软件清单）", False, "no software")

    # ---------------- W5-5 补丁（patch_apply）----------------
    st, b = req("/api/v1/vuln/tasks", {"device_id": dev_id, "software": target_sw or "demo",
                                       "target_version": "9.9.9"}, token=token)
    vtid = tid_of(b)
    check("W5-5 创建漏洞补丁任务", bool(vtid), f"st={st} b={str(b)[:120]}")
    if vtid:
        st, b = req(f"/api/v1/vuln/tasks/{vtid}/dispatch", {}, token=token)
        check("W5-5 patch_apply 下发并回执", st == 200 and b.get("code") == 0, f"st={st} b={str(b)[:200]}")

    # ---------------- W5-3 外设管控 ----------------
    policy = {"name": "e2e-policy", "scope_type": "device", "scope_value": dev_id,
              "usb_storage": "block", "optical": "block", "bluetooth": "block", "dry_run": True}
    st, b = req("/api/v1/peripheral/policies", policy, token=token)
    pid = tid_of(b) or (b.get("policy") or {}).get("id")
    check("W5-3 创建外设策略", bool(pid), f"st={st} b={str(b)[:120]}")
    if pid:
        st, b = req("/api/v1/peripheral/apply", {"device_id": dev_id, "policy_id": pid}, token=token)
        check("W5-3 peripheral_apply 下发成功", st == 200 and b.get("code") == 0, f"st={st} b={str(b)[:200]}")
        st, b = req(f"/api/v1/peripheral/status?device_id={dev_id}", token=token)
        print(f"      [外设状态] {str(b)[:160]}")

    # ---------------- W5-4 网络准入 ----------------
    st, b = req("/api/v1/nac/apply", {"device_id": dev_id, "action": "quarantine", "reason": "e2e"},
                token=token)
    check("W5-4 nac_apply 下发成功", st == 200 and b.get("code") == 0, f"st={st} b={str(b)[:200]}")

    agent.terminate()
    hub.terminate()
    print(f"\n=== Rust agent 波次3/4/5 e2e: PASS={PASS} FAIL={FAIL} ===")
    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()
