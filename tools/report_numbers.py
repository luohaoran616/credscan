#!/usr/bin/env python3
"""M8：报告数字快照——作品报告/技术说明书/答辩 PPT 引用数字的唯一事实源。

10/21 全量数字刷新 = 重跑本工具；report_tex（LaTeX 报告）可直接消费 JSON。
口径与 panel /api/overview、/api/latency 完全一致（P50/P90 同 nearest-rank 式）。
只读打开生产库。用法（credscan/ 目录下）：

  python3 tools/report_numbers.py --db ../data/credscan.db --config ../daemon.json \
      [--out ../docs/report-snapshot.json] [--md]
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # credscan 包在上级

import credscan  # noqa: F401,E402  注册插件
from credscan.channels import SITE_TARGETS   # noqa: E402
from credscan.core import CHANNELS, DETECTORS   # noqa: E402


def _pct(xs: list, q: float):
    """与 panel /api/latency 完全同式：排序后取 xs[min(int(n*q), n-1)]。"""
    xs = sorted(xs)
    if not xs:
        return None
    return round(xs[min(int(len(xs) * q), len(xs) - 1)])


def build_snapshot(conn: sqlite3.Connection, every_sec: dict | None = None) -> dict:
    """生产库 + 注册表 → 报告引用的全部数字（dict，JSON 可序列化）。"""
    every_sec = every_sec or {}
    q = conn.execute
    tiers = dict(q("SELECT confidence, COUNT(DISTINCT secret_sha256) FROM findings "
                   "GROUP BY confidence").fetchall())
    snap = {
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "registry": {
            "detectors": len(DETECTORS),
            "families": len({d.family for d in DETECTORS.values()}),
            "adapters": len(CHANNELS),
            "channels": len(CHANNELS) - 1 + len(SITE_TARGETS),  # searx 按站点展开
        },
        "totals": {
            "findings": q("SELECT COUNT(*) FROM findings").fetchone()[0],
            "unique": q("SELECT COUNT(DISTINCT secret_sha256) FROM findings").fetchone()[0],
            "strong_unique": q("SELECT COUNT(DISTINCT secret_sha256) FROM findings "
                               "WHERE confidence='strong'").fetchone()[0],
            "unique_by_tier": tiers,
        },
        "channels": [
            {"channel": ch, "findings": n, "uniques": u}
            for ch, n, u in q("SELECT channel, COUNT(*), COUNT(DISTINCT secret_sha256) "
                              "FROM findings GROUP BY channel ORDER BY 2 DESC")
        ],
        "latency": [],
    }
    for (ch,) in q("SELECT DISTINCT channel FROM findings "
                   "WHERE latency_sec IS NOT NULL AND latency_sec>=0"):
        xs = [r[0] for r in q("SELECT latency_sec FROM findings "
                              "WHERE channel=? AND latency_sec>=0", (ch,))]
        cid = "searx_matrix" if ch.startswith("searx:") else ch
        T = every_sec.get(cid)
        snap["latency"].append({
            "channel": ch, "n": len(xs),
            "p50": _pct(xs, 0.5), "p90": _pct(xs, 0.9),
            "mean": round(sum(xs) / len(xs)) if xs else None,
            "pred_t_half": round(T / 2) if T else None,  # E[R]=T/2+c 的结构性项
        })
    # 渠道 × 凭据族矩阵（图 3-4 数据源；detector→family 由注册表映射，层内唯一 sha256 去重口径）
    fam_of = {did: d.family for did, d in DETECTORS.items()}
    fams = sorted({f for f in fam_of.values() if f})
    chs = [c["channel"] for c in snap["channels"]]
    cell = {}
    for ch, det, u in q("SELECT channel, detector, COUNT(DISTINCT secret_sha256) "
                        "FROM findings GROUP BY 1, 2"):
        key = (ch, fam_of.get(det, "?"))
        cell[key] = cell.get(key, 0) + u
    snap["matrix"] = {
        "families": fams,
        "channels": chs,
        "cells": [{"channel": ch, "family": f, "uniques": cell.get((ch, f), 0)}
                  for ch in chs for f in fams],
    }
    return snap


def markdown(snap: dict) -> str:
    """人贴版：关键数字 markdown 块（报告/说明书的"数字卡"）。"""
    t, reg = snap["totals"], snap["registry"]
    lines = [
        f"## 数字快照（{snap['generated_at']}，生成：tools/report_numbers.py）",
        "",
        f"- 检测器 {reg['detectors']} 个 / 凭据族 {reg['families']} / "
        f"适配器 {reg['adapters']} / 监测口径 {reg['channels']}",
        f"- 累计 findings {t['findings']:,} / 唯一凭据 {t['unique']:,} / "
        f"strong 唯一 {t['strong_unique']:,}（分层唯一：{t['unique_by_tier']}）",
        "",
        "| 渠道 | findings | 唯一 |", "|---|---|---|",
    ]
    for r in snap["channels"][:12]:
        lines.append(f"| {r['channel']} | {r['findings']:,} | {r['uniques']:,} |")
    lines += ["", "| 渠道 | n | P50(s) | P90(s) | 均值(s) | 模型 T/2 |", "|---|---|---|---|---|---|"]
    for r in snap["latency"]:
        lines.append(f"| {r['channel']} | {r['n']:,} | {r['p50']} | {r['p90']} "
                     f"| {r['mean']} | {r['pred_t_half']} |")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True, help="findings 库路径（只读打开）")
    ap.add_argument("--config", default="../daemon.json", help="daemon.json（取渠道周期）")
    ap.add_argument("--out", default=None, help="JSON 输出路径（不填则只打印）")
    ap.add_argument("--md", action="store_true", help="同时打印 markdown 数字卡")
    args = ap.parse_args()

    every_sec = {k: v.get("every_sec") for k, v in
                 json.load(open(args.config, encoding="utf-8"))["channels"].items()}
    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    snap = build_snapshot(conn, every_sec=every_sec)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(snap, f, ensure_ascii=False, indent=1)
        print(f"written: {args.out}")
    if args.md or not args.out:
        print(markdown(snap))


if __name__ == "__main__":
    main()
