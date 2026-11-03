#!/usr/bin/env python3
# 御端 Wave 5c e2e —— W5-6 策略中心（模板/分组差异化/灰度+回滚/生效统计）。
# 造数：3 个 agent 各用独立 YUDUAN_STATE_FILE → 3 台设备（去重按 token），
# 2 台归「研发部」、1 台归「财务部」，模板按部门分组过滤 + 灰度推进/回滚。
import json, os, subprocess, sys, time, urllib.request, urllib.error

urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))

DEV = "/Users/huluobo/WorkBuddy/jiankong/dev"
BIN = "/tmp/yuduan-wave5c"
HUB = os.path.join(BIN, "hub")
AGENT = os.path.join(BIN, "agent")
SECRET = "wave5c-secret"
PORT = os.environ.get("YUDUAN_E2E_PORT", "18088")
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
    env = dict(os.environ, YUDUAN_HMAC_SECRET=SECRET, YUDUAN_REPO="/tmp/yuduan-wave5c-repo",
               YUDUAN_HUB_ADDR=":" + PORT)
    return subprocess.Popen([HUB], cwd=DEV, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def start_agent(tag):
    # v0.4.8 幂等注册：设备身份按硬件指纹（serial → hostname+mac）复用，同一台宿主机
    # 多个 token 会被合并为一台设备（v0.4.7 实测报告问题 4 的产品语义）。e2e 模拟
    # 「3 台不同设备」必须为每个 agent 伪造不同硬件身份（YUDUAN_HOSTNAME/MAC/SERIAL）。
    n = tag
    env = dict(os.environ, YUDUAN_HUB=f"ws://127.0.0.1:{PORT}/ws/agent", YUDUAN_HMAC_SECRET=SECRET,
               YUDUAN_STATE_FILE=os.path.join(BIN, f"agent-{tag}.json"),
               YUDUAN_HOSTNAME=f"w5c-host-{n}", YUDUAN_MAC=f"02:00:00:00:00:0{n}",
               YUDUAN_SERIAL=f"W5C-SN-{n}")
    return subprocess.Popen([AGENT], cwd=DEV, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def req(path, data=None, token=None, method=None):
    url = BASE + path
    if method is None:
        method = "POST" if data is not None else "GET"
    r = urllib.request.Request(url, method=method)
    if token: r.add_header("Authorization", "Bearer " + token)
    if data is not None:
        r.add_header("Content-Type", "application/json")
        r.data = json.dumps(data).encode()
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            raw = resp.read()
            ct = resp.headers.get("Content-Type", "")
            return resp.status, (json.loads(raw) if "json" in ct else raw)
    except urllib.error.HTTPError as e:
        return e.code, {"_raw": e.read().decode()[:200]}
    except Exception as e:
        return -1, {"error": str(e)}

def login():
    st, b = req("/api/v1/login", {"username": "admin", "password": "admin123"})
    if st != 200 or not b.get("token"): raise SystemExit("login 失败: " + str(b))
    st, b = req("/api/v1/password", {"old_password": "admin123", "new_password": "Admin@2026x"}, token=b["token"])
    return b.get("token")

def wait_devices(token, n, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        st, b = req("/api/v1/devices", token=token)
        if st == 200 and isinstance(b.get("devices"), list) and len(b["devices"]) >= n:
            return b["devices"]
        time.sleep(0.5)
    return None

def main():
    build()
    hub = start_hub(); time.sleep(1.5)
    print(f"[hub] 启动 :{PORT}")
    token = login()
    check("admin 登录+改密", bool(token))

    agents = [start_agent(t) for t in ("a", "b", "c")]
    time.sleep(1.0)
    devs = wait_devices(token, 3)
    check("3 台设备注册", devs is not None and len(devs) == 3,
          f"devices={len(devs) if devs else 0}")
    if not devs:
        for a in agents:
            a.terminate()
        hub.terminate()
        print(f"\n{'-'*50}\nTOTAL: {PASS} PASS / {FAIL} FAIL")
        sys.exit(1)
    devs = sorted(devs, key=lambda d: d.get("id", ""))
    da, db, dc = devs[0]["id"], devs[1]["id"], devs[2]["id"]
    print(f"  [devices] {da} / {db} / {dc}")

    # 分组：研发部×2、财务部×1
    st, b = req(f"/api/v1/devices/meta/{da}", {"department": "研发部", "tags": ["核心"]}, token=token)
    check("da 设为研发部", st == 200 and b.get("department") == "研发部", str(b)[:120])
    st, b = req(f"/api/v1/devices/meta/{db}", {"department": "研发部"}, token=token)
    check("db 设为研发部", st == 200 and b.get("department") == "研发部", str(b)[:120])
    st, b = req(f"/api/v1/devices/meta/{dc}", {"department": "财务部"}, token=token)
    check("dc 设为财务部", st == 200 and b.get("department") == "财务部", str(b)[:120])

    # 创建模板：组合合规基线 + 外设策略，按部门=研发部，目标 100%
    tpl = {"name": "研发部安全基线", "desc": "研发部专项基线（补丁合规+USB禁用）",
           "rules": [
               {"domain": "compliance", "ref_id": "cb-1", "name": "补丁合规基线"},
               {"domain": "peripheral", "ref_id": "pp-1", "name": "USB 存储禁用"},
               {"domain": "blacklist", "ref_id": "bl-1", "name": "违规软件黑名单"},
           ],
           "departments": ["研发部"], "target_pct": 100}
    st, b = req("/api/v1/strategy/templates", tpl, token=token)
    tid = b.get("template", {}).get("id")
    check("创建策略模板", st == 200 and bool(tid), str(b)[:160])
    check("模板初始为草稿", b.get("template", {}).get("status") == "draft", str(b)[:120])

    st, b = req("/api/v1/strategy/templates", token=token)
    check("模板列表含新模板", st == 200 and any(t["id"] == tid for t in b.get("templates", [])), str(b)[:120])

    st, b = req(f"/api/v1/strategy/templates/{tid}", token=token)
    detail = b.get("template", {})
    check("模板详情 group_size=2（研发部）", st == 200 and detail.get("group_size") == 2,
          f"group_size={detail.get('group_size')} status={detail.get('status')}")

    # 灰度：推进到 50% → 1 台研发部设备生效
    st, b = req(f"/api/v1/strategy/templates/{tid}/rollout", {"action": "advance", "pct": 50}, token=token)
    check("灰度推进 50%", st == 200 and b.get("template", {}).get("current_pct") == 50,
          f"current_pct={b.get('template', {}).get('current_pct')}")

    st, b = req("/api/v1/strategy/stats", token=token)
    ts = next((t for t in b.get("templates", []) if t["id"] == tid), None)
    check("统计: 覆盖 1 台/覆盖 50%", ts is not None and ts.get("applied") == 1 and ts.get("coverage_pct") == 50,
          f"applied={ts.get('applied')} cov={ts.get('coverage_pct')}")

    # 灰度：推进到 100% → 2 台研发部设备全部生效
    st, b = req(f"/api/v1/strategy/templates/{tid}/rollout", {"action": "advance", "pct": 100}, token=token)
    check("灰度推进 100%", st == 200 and b.get("template", {}).get("current_pct") == 100,
          f"current_pct={b.get('template', {}).get('current_pct')}")
    st, b = req("/api/v1/strategy/stats", token=token)
    ts = next((t for t in b.get("templates", []) if t["id"] == tid), None)
    check("统计: 覆盖 2 台/覆盖 100%", ts is not None and ts.get("applied") == 2 and ts.get("coverage_pct") == 100,
          f"applied={ts.get('applied')} cov={ts.get('coverage_pct')}")

    # 灰度回退拒绝（HTTP 200 + 非零业务 code）
    st, b = req(f"/api/v1/strategy/templates/{tid}/rollout", {"action": "advance", "pct": 50}, token=token)
    check("灰度回退被拒绝", st == 200 and b.get("code") != 0, f"st={st} code={b.get('code')} {str(b)[:80]}")

    # 暂停 / 恢复
    st, b = req(f"/api/v1/strategy/templates/{tid}/rollout", {"action": "pause"}, token=token)
    check("灰度暂停", st == 200 and b.get("template", {}).get("status") == "paused", str(b)[:120])
    st, b = req(f"/api/v1/strategy/templates/{tid}/rollout", {"action": "resume"}, token=token)
    check("灰度恢复", st == 200 and b.get("template", {}).get("status") == "active", str(b)[:120])

    # 回滚 → 全部撤销
    st, b = req(f"/api/v1/strategy/templates/{tid}/rollout", {"action": "rollback"}, token=token)
    check("灰度回滚", st == 200 and b.get("template", {}).get("status") == "rolled_back", str(b)[:120])
    st, b = req("/api/v1/strategy/stats", token=token)
    ts = next((t for t in b.get("templates", []) if t["id"] == tid), None)
    check("统计: 回滚后覆盖 0/已回滚 2", ts is not None and ts.get("applied") == 0 and ts.get("rolled_back") == 2,
          f"applied={ts.get('applied')} rolled={ts.get('rolled_back')}")

    # 非法域拒绝
    bad = {"name": "非法模板", "rules": [{"domain": "hack", "ref_id": "x", "name": "bad"}]}
    st, b = req("/api/v1/strategy/templates", bad, token=token)
    check("非法策略域被拒绝", st == 200 and b.get("code") != 0, f"st={st} code={b.get('code')} {str(b)[:80]}")

    # 空规则拒绝
    st, b = req("/api/v1/strategy/templates", {"name": "空模板", "rules": []}, token=token)
    check("空规则被拒绝", st == 200 and b.get("code") != 0, f"st={st} code={b.get('code')} {str(b)[:80]}")

    # 删除模板
    st, b = req(f"/api/v1/strategy/templates/{tid}", token=token, method="DELETE")
    check("删除模板", st == 200, f"st={st} {str(b)[:80]}")
    st, b = req("/api/v1/strategy/templates", token=token)
    check("删除后列表不含", st == 200 and not any(t["id"] == tid for t in b.get("templates", [])), str(b)[:80])

    for a in agents:
        a.terminate()
    hub.terminate()
    print(f"\n{'-'*50}\nTOTAL: {PASS} PASS / {FAIL} FAIL")
    sys.exit(0 if FAIL == 0 else 1)

if __name__ == "__main__":
    main()
