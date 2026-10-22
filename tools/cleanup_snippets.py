#!/usr/bin/env python3
"""一次性运维工具：掩码历史 findings.snippet 中的漏网明文。

背景：早期版本 snippet 只脱敏"本命中的那个值"，
同一行内其他凭据的明文会残留入库。核心扫描路径已修复（_masked_snippet 全行掩码），
本工具对既有库做一次性补偿：对每条 snippet 跑全部检测器，把命中的明文替换为
redact() 形态后回写。

用法（在 code/ 目录、PYTHONPATH=.）：
  python3 ../tools/cleanup_snippets.py --db ../data/credscan.db            # dry-run
  python3 ../tools/cleanup_snippets.py --db ../data/credscan.db --apply    # 回写
  python3 ../tools/cleanup_snippets.py --db ../data/credscan.db --apply --backup /path/db.bak

安全性质：只改 findings.snippet 一列；替换值 = redact(secret)（等长脱敏形态，
不含明文）；dry-run 缺省零写入。
"""
import argparse
import shutil
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # credscan/ 或阿特 code/
from credscan.core import DETECTORS, redact  # noqa: E402


def mask_snippet(snippet: str) -> str | None:
    """对 snippet 跑全检测器，掩码全部命中值；无命中返回 None。

    跳过已是脱敏形态的命中（含 … 或全 *）——旧版 redact 产物会被宽检测器
    （password_pair 等）再次命中，二次掩码只会损失可读线索、并无明文可防。
    """
    hits = []
    for det in DETECTORS.values():
        try:
            for h in det.match(snippet):
                secret = h["secret"]
                if "…" in secret or set(secret) <= {"*"}:
                    continue
                hits.append((secret, h["pos"]))
        except Exception:
            continue
    if not hits:
        return None
    out = snippet
    for secret, pos in sorted(hits, key=lambda x: -x[1]):
        end = pos + len(secret)
        if 0 <= pos < len(out):
            out = out[:pos] + redact(secret) + out[end:]
    return out if out != snippet else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--backup", default=None)
    a = ap.parse_args()

    if not a.apply:
        print("[dry-run] 只读扫描，不写入；加 --apply 回写")
    db = sqlite3.connect(f"file:{a.db}?mode=ro" if not a.apply else a.db, uri=True)
    rows = list(db.execute("SELECT dedup, snippet FROM findings"))
    affected = []
    for dedup, snippet in rows:
        if not snippet:
            continue
        masked = mask_snippet(snippet)
        if masked:
            affected.append((dedup, snippet, masked))
    print(f"扫描 {len(rows)} 行；需掩码 {len(affected)} 行")
    for dedup, old, new in affected[:10]:
        print(f"  {dedup[:12]}…  {old[:70]}")
        print(f"         → {new[:70]}")
    if not a.apply:
        return 0
    if a.backup:
        shutil.copy2(a.db, a.backup)
        print(f"已备份 → {a.backup}")
    conn = sqlite3.connect(a.db)
    with conn:
        for dedup, _, masked in affected:
            conn.execute("UPDATE findings SET snippet=? WHERE dedup=?", (masked, dedup))
    print(f"已回写 {len(affected)} 行")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
