#!/usr/bin/env python3
# 御端 Wave 5a 定向冒烟 —— W5-2 违规软件黑名单 + W5-5 漏洞扫描/补丁闭环（仅标准库）。
# 复用 e2e_wave5a 的 harness；黑名单/漏洞扫描支持 POST 注入软件清单（确定性判定）。
import json, os, subprocess, sys, time, urllib.request, urllib.error

urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))

DEV = "/Users/huluobo/WorkBuddy/jiankong/dev"
BIN = "/tmp/yuduan-wave5a2"
HUB = os.path.join(BIN, "hub")
AGENT = os.path.join(BIN, "agent")
SECRET = "wave5a2-secret"
PORT = os.environ.get("YUDUAN_E2E_PORT", "18087")
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
    env = dict(os.environ, YUDUAN_HMAC_SECRET=SECRET, YUDUAN_REPO="/tmp/yuduan-wave5a2-repo",
               YUDUAN_HUB_ADDR=":" + PORT)
    return subprocess.Popen([HUB], cwd=DEV, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def start_agent():
    env = dict(os.environ, YUDUAN_HUB=f"ws://127.0.0.1:{PORT}/ws/agent", YUDUAN_HMAC_SECRET=SECRET)
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

def main():
    build()
    hub = start_hub(); time.sleep(1.5)
    print(f"[hub] 启动 :{PORT}")
    token = login()
    check("admin 登录+改密", bool(token))
    agent = start_agent(); time.sleep(2.5)
    print("[agent] 启动，等待注册…")
    time.sleep(2)

    st, b = req("/api/v1/devices", token=token)
    check("设备列表", st == 200 and b.get("total", 0) >= 1, f"total={b.get('total')}")
    devs = b.get("devices", [])
    if not devs:
        print("  (无设备，无法继续)"); agent.terminate(); hub.terminate()
        print(f"\n=== Wave5a2 e2e: PASS={PASS} FAIL={FAIL} ==="); sys.exit(1)
    dev_id = devs[0]["id"]

    # ---------- W5-2 违规软件黑名单 ----------
    st, b = req("/api/v1/blacklist/rules", {"pattern": "Zoom", "match_type": "contains",
                                            "action": "uninstall", "severity": "high"}, token=token)
    rule_id = (b.get("rule") or {}).get("id")
    check("W5-2 创建黑名单规则", st == 200 and b.get("code") == 0 and rule_id, f"st={st} b={str(b)[:120]}")
    st, b = req("/api/v1/blacklist/rules", token=token)
    check("W5-2 黑名单规则列表", st == 200 and b.get("total", 0) >= 1, f"total={b.get('total')}")
    # 注入软件清单，确定性命中
    st, b = req(f"/api/v1/blacklist/scan/{dev_id}",
                {"software": [{"name": "Zoom Workplace", "version": "5.0", "vendor": "Zoom"}]}, token=token)
    hits = b.get("hits") or []
    check("W5-2 扫描命中违规软件", st == 200 and b.get("code") == 0 and len(hits) >= 1,
          f"hits={len(hits)} b={str(b)[:140]}")
    st, b = req("/api/v1/blacklist/hits", token=token)
    check("W5-2 命中列表可访问", st == 200 and b.get("code") == 0, f"st={st}")
    st, b = req(f"/api/v1/blacklist/by-device?device_id={dev_id}", token=token)
    check("W5-2 按设备命中", st == 200 and b.get("code") == 0, f"st={st}")
    st, b = req("/api/v1/blacklist/export?format=json", token=token)
    check("W5-2 黑名单导出", st == 200 and b.get("code") == 0, f"st={st}")

    # ---------- W5-5 漏洞扫描 + 补丁闭环 ----------
    st, b = req("/api/v1/vuln/rules", {"software": "Zoom", "cve": "CVE-2024-12345",
                                       "affected_versions": "<=5.0", "fix_version": "5.2",
                                       "severity": "high"}, token=token)
    vr_id = (b.get("rule") or {}).get("id")
    check("W5-5 创建漏洞规则", st == 200 and b.get("code") == 0 and vr_id, f"st={st} b={str(b)[:120]}")
    st, b = req("/api/v1/vuln/rules", token=token)
    check("W5-5 漏洞规则列表", st == 200 and b.get("total", 0) >= 1, f"total={b.get('total')}")
    st, b = req(f"/api/v1/vuln/scan/{dev_id}",
                {"software": [{"name": "Zoom Workplace", "version": "5.0", "vendor": "Zoom"}]}, token=token)
    items = b.get("items") or []
    check("W5-5 扫描产生漏洞项", st == 200 and b.get("code") == 0 and len(items) >= 1,
          f"items={len(items)} b={str(b)[:140]}")
    st, b = req("/api/v1/vuln/items", token=token)
    check("W5-5 漏洞项列表", st == 200 and b.get("code") == 0, f"st={st}")
    st, b = req("/api/v1/vuln/summary", token=token)
    summ = (b.get("summary") or {})
    check("W5-5 漏洞概览(open>0)", st == 200 and b.get("code") == 0 and summ.get("open", 0) >= 1,
          f"open={summ.get('open')} b={str(b)[:140]}")
    # 创建补丁任务并下发（副端回执 dry-run 计划）
    st, b = req("/api/v1/vuln/tasks", {"device_id": dev_id, "software": "Zoom"}, token=token)
    task_id = (b.get("task") or {}).get("id")
    check("W5-5 创建补丁任务", st == 200 and b.get("code") == 0 and task_id, f"st={st} b={str(b)[:140]}")
    st, b = req(f"/api/v1/vuln/tasks/{task_id}/dispatch", {}, token=token)
    task = b.get("task") or {}
    check("W5-5 下发补丁(副端回执)", st == 200 and b.get("code") == 0,
          f"st={st} b={str(b)[:140]}")
    check("W5-5 任务含诚实回执", bool(task.get("result") or task.get("receipt") or task.get("state")),
          f"state={task.get('state')}")

    agent.terminate(); hub.terminate()
    print(f"\n=== Wave5a2 e2e: PASS={PASS} FAIL={FAIL} ===")
    sys.exit(0 if FAIL == 0 else 1)

if __name__ == "__main__":
    main()
