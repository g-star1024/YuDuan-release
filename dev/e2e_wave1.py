#!/usr/bin/env python3
# 御端 Wave 1（资产生命周期闭环）端到端验证脚本（仅标准库）。
# 覆盖：W1-1 软件清单采集 / W1-2 台账分组元数据 / W1-3 生命周期流转+状态机 /
#       W1-5 告警（生命周期触发+去重+已读）/ W1-6 报表导出(CSV+XLSX) / W1-7 审计导出(CSV+JSON)。
import json, os, subprocess, sys, time, urllib.request, urllib.error

urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))

DEV = "/Users/huluobo/WorkBuddy/jiankong/dev"
BIN = "/tmp/yuduan-wave1"
HUB = os.path.join(BIN, "hub")
AGENT = os.path.join(BIN, "agent")
SECRET = "wave1-secret"
PORT = os.environ.get("YUDUAN_E2E_PORT", "18081")
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
    env = dict(os.environ, YUDUAN_HMAC_SECRET=SECRET, YUDUAN_REPO="/tmp/yuduan-wave1-repo",
               YUDUAN_HUB_ADDR=":" + PORT)
    p = subprocess.Popen([HUB], cwd=DEV, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p

def start_agent():
    env = dict(os.environ, YUDUAN_HUB=f"ws://127.0.0.1:{PORT}/ws/agent", YUDUAN_HMAC_SECRET=SECRET)
    return subprocess.Popen([AGENT], cwd=DEV, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def req(path, data=None, token=None):
    url = BASE + path
    r = urllib.request.Request(url, method="POST" if data is not None else "GET")
    if token: r.add_header("Authorization", "Bearer " + token)
    if data is not None:
        r.add_header("Content-Type", "application/json")
        r.data = json.dumps(data).encode()
    try:
        with urllib.request.urlopen(r, timeout=8) as resp:
            raw = resp.read()
            ct = resp.headers.get("Content-Type", "")
            if "json" in ct:
                return resp.status, json.loads(raw)
            return resp.status, raw
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

    # W1-1 软件清单
    st, b = req("/api/v1/devices", token=token)
    check("设备列表", st == 200 and b.get("total", 0) >= 1, f"total={b.get('total')}")
    devs = b.get("devices", [])
    dev = devs[0]
    dev_id = dev["id"]
    sw = dev.get("software") or []
    check("W1-1 软件清单已上报", len(sw) > 0, f"软件数={len(sw)}")
    if sw:
        check("W1-1 软件含名称/版本字段", bool(sw[0].get("name")), str(sw[0])[:80])
    check("W1-2 设备默认生命周期=在库", dev.get("lifecycle") == "in_stock", dev.get("lifecycle"))

    # W1-2 台账分组元数据
    st, b = req(f"/api/v1/devices/meta/{dev_id}", {"department": "IT", "floor": "3F", "batch": "2026-Q4", "tags": ["办公", "测试"]}, token=token)
    check("W1-2 元数据更新", st == 200 and b.get("department") == "IT" and b.get("floor") == "3F", str(b)[:120])
    check("W1-2 标签写入", "tags" in b and len(b.get("tags", [])) == 2, str(b.get("tags")))

    # W1-3 生命周期流转
    st, b = req(f"/api/v1/devices/lifecycle/{dev_id}", {"state": "issued", "assignee": "zhang", "note": "领用"}, token=token)
    check("W1-3 在库→领用", st == 200 and b.get("lifecycle") == "issued" and b.get("assignee") == "zhang", str(b)[:120])
    st, b = req(f"/api/v1/devices/lifecycle/{dev_id}", {"state": "returned"}, token=token)
    check("W1-3 领用→归还", st == 200 and b.get("lifecycle") == "returned", str(b)[:120])
    st, b = req(f"/api/v1/devices/lifecycle/{dev_id}", {"state": "in_stock"}, token=token)
    check("W1-3 归还→在库", st == 200 and b.get("lifecycle") == "in_stock", str(b)[:120])
    st, b = req(f"/api/v1/devices/lifecycle/{dev_id}", {"state": "transferred"}, token=token)
    check("W1-3 非法流转拒绝(在库→调拨)", st == 200 and b.get("code") == 2002, str(b)[:120])

    # W1-5 告警（生命周期已产生 info 告警）
    st, b = req("/api/v1/alerts", token=token)
    alerts = b.get("alerts", [])
    unread = b.get("unread", 0)
    check("W1-5 告警中心有数据", len(alerts) >= 1 and unread >= 1, f"alerts={len(alerts)} unread={unread}")
    has_lc = any(a.get("type") == "lifecycle" for a in alerts)
    check("W1-5 含生命周期告警", has_lc)
    if alerts:
        aid = alerts[0]["id"]
        st, b = req(f"/api/v1/alerts/{aid}/read", {}, token=token)
        st2, b2 = req("/api/v1/alerts/unread", token=token)
        check("W1-5 告警已读", st == 200 and b2.get("unread", unread) < unread, f"unread={b2.get('unread')}")

    # W1-6 报表导出
    st, raw = req("/api/v1/report/export?format=csv", token=token)
    csv_ok = st == 200 and raw.count(b"\n") >= 2 and b"ID" in raw
    check("W1-6 CSV 导出(含表头+数据行)", csv_ok, f"st={st} len={len(raw)}")
    st, raw = req("/api/v1/report/export?format=xlsx", token=token)
    xlsx_ok = st == 200 and raw[:2] == b"PK" and len(raw) > 1000
    check("W1-6 XLSX 导出(合法zip)", xlsx_ok, f"st={st} len={len(raw)} head={raw[:4]}")

    # W1-7 审计导出
    st, raw = req("/api/v1/audit/export?format=csv", token=token)
    check("W1-7 审计CSV导出", st == 200 and b"ID" in raw and raw.count(b"\n") >= 2, f"st={st} len={len(raw)}")
    st, raw = req("/api/v1/audit/export?format=json", token=token)
    try:
        # req 对 JSON Content-Type 已自动解析为 Python 对象
        ev = raw if isinstance(raw, list) else json.loads(raw)
        ok = isinstance(ev, list) and any(e.get("hash") for e in ev)
        detail = f"events={len(ev) if isinstance(ev,list) else '?'}"
    except Exception as ex:
        ok = False; detail = "json parse fail: " + str(ex)
    check("W1-7 审计JSON导出(含WORM哈希)", ok, detail)

    agent.terminate(); hub.terminate()
    print(f"\n=== Wave1 e2e: PASS={PASS} FAIL={FAIL} ===")
    sys.exit(0 if FAIL == 0 else 1)

if __name__ == "__main__":
    main()
