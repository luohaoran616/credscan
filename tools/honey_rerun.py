#!/usr/bin/env python3
"""蜜凭据复跑自动化（SOP 配套工具，k=6/7 用）。

全链自动化：造牺牲 AK（管理员 AK 调 RAM CreateAccessKey）→ 登记（只存 sha256）→
植入公开 Gist（t0=平台 created_at）→ 轮询生产库等 daemon 自动检出（t1）→ 验证
告警（t2）与云侧禁用（t3，ListAccessKeys+RequestId）→ 取证 JSON 落 evidence/ → 清理。

用法（阿特，code 目录）：
  PYTHONPATH=. python3 ../tools/honey_rerun.py \
      --db ../data/credscan.db --gist-token "$GITHUB_TOKEN" \
      --admin-id "$CREDSCAN_DEMO_ALIYUN_AK_ID" --admin-secret "$CREDSCAN_DEMO_ALIYUN_AK_SECRET" \
      --user credscan-demo --wait 900

红线（每次执行前重读）：牺牲 AK 必须零权限；植入只进自有 Gist；处置只作用于登记命中的自有 AK。
"""
import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # credscan/ 或阿特 code/
from credscan.response import _rpc_call, _http_post  # noqa: E402


def create_sacrificial_ak(admin_id: str, admin_secret: str, user: str) -> dict:
    r = _rpc_call("CreateAccessKey", {"UserName": user}, admin_id, admin_secret)
    resp = json.loads(r["resp"])
    if r["http_status"] != 200 or "AccessKey" not in resp:
        raise RuntimeError(f"CreateAccessKey 失败: {r['http_status']} {r['resp'][:200]}")
    return resp["AccessKey"]


def post_gist(token: str, content: str) -> dict:
    body = json.dumps({"description": "credscan honeytoken rerun fixture",
                       "public": True,
                       "files": {"app_config_demo.py": {"content": content}}}).encode()
    status, raw = _http_post("https://api.github.com/gists", body,
                             {"Authorization": f"token {token}",
                              "Accept": "application/vnd.github+json"})
    g = json.loads(raw.decode("utf-8", "ignore"))
    if status >= 300 or "id" not in g:
        raise RuntimeError(f"gist 创建失败: {status} {raw.decode('utf-8','ignore')[:200]}")
    return g


def wait_detect(db_path: str, sha256hex: str, timeout: int) -> dict | None:
    import sqlite3
    deadline = time.time() + timeout
    conn = sqlite3.connect(db_path)
    while time.time() < deadline:
        row = conn.execute(
            "SELECT ts, latency_sec, channel, confidence FROM findings WHERE secret_sha256=?"
            " ORDER BY ts LIMIT 1", (sha256hex,)).fetchone()
        if row:
            return {"ts": row[0], "latency_sec": row[1], "channel": row[2], "confidence": row[3]}
        time.sleep(10)
    return None


def verify_inactive(admin_id: str, admin_secret: str, user: str, ak_id: str) -> dict:
    r = _rpc_call("ListAccessKeys", {"UserName": user}, admin_id, admin_secret)
    resp = json.loads(r["resp"])
    keys = resp.get("AccessKeys", {}).get("AccessKey", [])
    target = [k for k in keys if k["AccessKeyId"] == ak_id]
    return {"status": target[0]["Status"] if target else "NOT_FOUND",
            "request_id": resp.get("RequestId")}


def _log(msg: str) -> None:
    print(msg, flush=True)


def _registry_path(db_path: str) -> str:
    """从 daemon.json 读登记表绝对路径（口径必须与 daemon 一致，否则处置不命中）。"""
    cand = Path(db_path).resolve().parent.parent / "daemon.json"  # 阿特布局 ../daemon.json
    if not cand.exists():
        cand = Path(db_path).resolve().parent / "daemon.json"
    cfg = json.loads(cand.read_text(encoding="utf-8"))
    return cfg.get("honeytokens", str(cand.parent / "honeytokens.json"))


def cleanup(token: str, gist_id: str, admin_id: str, admin_secret: str, user: str, ak_id: str):
    import subprocess
    subprocess.run(["curl", "-s", "-m", "60", "-X", "DELETE", "-H", f"Authorization: token {token}",
                    f"https://api.github.com/gists/{gist_id}"],
                   capture_output=True, check=False)
    _rpc_call("DeleteAccessKey", {"UserName": user, "UserAccessKeyId": ak_id}, admin_id, admin_secret)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--gist-token", required=True)
    ap.add_argument("--admin-id", required=True)
    ap.add_argument("--admin-secret", required=True)
    ap.add_argument("--user", default="credscan-demo")
    ap.add_argument("--wait", type=int, default=900)
    ap.add_argument("--keep", action="store_true", help="跳过清理（调试用）")
    a = ap.parse_args()

    print("[1/6] 造牺牲 AK（零权限子账号）…")
    ak = create_sacrificial_ak(a.admin_id, a.admin_secret, a.user)
    ak_id, ak_secret = ak["AccessKeyId"], ak["AccessKeySecret"]
    print(f"    AK id: {ak_id}")

    print("[2/6] 登记蜜凭据（只存 sha256，口径与 finding.secret_sha256 一致：登记 AK 值本身）…")
    import subprocess
    reg_path = _registry_path(a.db)
    _log(f"    登记表 = {reg_path}（与 daemon.json 一致）")
    subprocess.run([sys.executable, "-m", "credscan", "honeytoken", "add",
                    "--registry", reg_path, "--user", a.user, "--ak-id", ak_id],
                   input=ak_id.encode(), check=True, capture_output=True)

    fixture = (f"# demo app config (fixture)\n"
               f"ALIYUN_ACCESS_KEY_ID = \"{ak_id}\"\n"
               f"ALIYUN_ACCESS_KEY_SECRET = \"{ak_secret}\"\n"
               f"REGION = \"cn-hangzhou\"\n")
    print("[3/6] 植入公开 Gist（t0）…")
    gist = post_gist(a.gist_token, fixture)
    t0 = gist["created_at"]
    print(f"    gist {gist['id']} created_at={t0}")

    sha = hashlib.sha256(ak_id.encode()).hexdigest()
    print(f"[4/6] 等待 daemon 自动检出（≤{a.wait}s）…")
    det = wait_detect(a.db, sha, a.wait)
    if not det:
        print("    超时未检出（走 SOP 失败处置）")
        if not a.keep:
            cleanup(a.gist_token, gist["id"], a.admin_id, a.admin_secret, a.user, ak_id)
        return 2
    t1 = det["ts"]
    print(f"    检出 {t1}（latency_sec={det['latency_sec']}，{det['channel']}/{det['confidence']}）")

    print("[5/6] 验证云侧禁用…")
    time.sleep(15)
    v = verify_inactive(a.admin_id, a.admin_secret, a.user, ak_id)
    print(f"    状态 {v['status']}  RequestId {v['request_id']}")

    result = {"k": "6", "ak_id": ak_id, "gist_id": gist["id"], "t0": t0, "t1": t1,
              "latency_sec": det["latency_sec"], "status": v["status"],
              "request_id": v["request_id"]}
    ev_dir = Path(__file__).resolve().parent.parent / "evidence"
    ev_dir.mkdir(exist_ok=True)
    out = ev_dir / f"honey-k6-{time.strftime('%Y%m%d')}.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"[6/6] 取证 → {out}")

    if not a.keep:
        print("    清理：删 gist + 删牺牲 AK")
        cleanup(a.gist_token, gist["id"], a.admin_id, a.admin_secret, a.user, ak_id)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
