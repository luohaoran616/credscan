#!/usr/bin/env python3
"""M3：轮询周期推导（数学模型方案 §2.6）——速率预算下的平方根律分配。

模型：渠道价值权重 w_c（近 24h 唯一发现数代理）、每轮成本 a_c，
目标 min_c Σ w_c·T_c/2（平均 AoI 的结构性项），约束 Σ a_c/T_c ≤ Q（总请求速率预算）。
拉格朗日条件 w_c/2 = λ·a_c/T_c² 给出闭式解：

    T_c* = Q · sqrt(a_c / w_c) / Σ_j sqrt(a_j · w_j)

即单通道 EOQ 平方根律 k* = sqrt(2C/c)（timing bandit，arXiv:2609.37932）在
多通道预算约束下的推广。Q 默认取当前配置的实际请求速率（保持现状预算，只重分配）。

用法（credscan/ 目录下）：
  python3 tools/suggest_intervals.py --db ../data/credscan.db --config ../daemon.json [--floor 60]
"""
from __future__ import annotations

import argparse
import json
import math
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

# 每轮轮询的请求成本（保守估计：一轮列表抓取 = 1 个预算单位；dockerhub 走
# 仓库→标签→manifest 多层，记 3）。简化口径，答辩如实陈述。
COST = {"dockerhub": 3}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--config", required=True, help="daemon.json 路径")
    ap.add_argument("--floor", type=int, default=60, help="单通道最小周期（礼貌下限，秒）")
    a = ap.parse_args()

    cfg = json.loads(Path(a.config).read_text(encoding="utf-8"))
    chcfg = cfg.get("channels", {})

    # w_c：近 24h 唯一发现数（价值代理）；无记录渠道给底值 0.1（新通道冷启动）
    c = sqlite3.connect(f"file:{a.db}?mode=ro", uri=True)
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds")
    w = {ch: 0.1 for ch in chcfg}
    for ch, n in c.execute(
            "SELECT channel, COUNT(DISTINCT secret_sha256) FROM findings "
            "WHERE ts >= ? GROUP BY channel", (since,)):
        key = "searx_matrix" if ch.startswith("searx:") else ch
        if key in w:
            w[key] = max(w[key], n)
        else:
            w[key] = n

    chs = [ch for ch in chcfg if chcfg[ch].get("every_sec")]
    a_c = {ch: COST.get(ch, 1) for ch in chs}
    T_cur = {ch: chcfg[ch]["every_sec"] for ch in chs}
    Q = sum(a_c[ch] / T_cur[ch] for ch in chs)          # 现状总请求速率（次/秒）

    def allocate(active: list) -> dict:
        denom = sum(math.sqrt(a_c[ch] * w[ch]) for ch in active)
        # T_c* = sqrt(2λ)·sqrt(a_c/w_c)，其中 sqrt(2λ) = Σ_j sqrt(a_j·w_j) / Q
        return {ch: max(a.floor, denom * math.sqrt(a_c[ch] / w[ch]) / Q) if Q > 0 else a.floor
                for ch in active}

    # 两轮分配：被 floor 截断的通道固定在 floor，剩余预算在其余通道间重分配
    T = allocate(chs)
    floored = [ch for ch in chs if T[ch] <= a.floor + 1e-9]
    if floored and len(floored) < len(chs):
        rest = [ch for ch in chs if ch not in floored]
        Q_rest = Q - sum(a_c[ch] / a.floor for ch in floored)
        if Q_rest > 0:
            denom = sum(math.sqrt(a_c[ch] * w[ch]) for ch in rest)
            for ch in rest:
                T[ch] = max(a.floor, denom * math.sqrt(a_c[ch] / w[ch]) / Q_rest)

    print(f"预算 Q = 现状总请求速率 = {Q:.4f} 次/秒（≈{Q*3600:.0f} 次/小时，保持不变只重分配）")
    print(f"价值权重 w_c = 近 24h 唯一发现数（无记录=0.1 冷启动底值）；成本 a_c ∈ {{1,3}}\n")
    print("| 渠道 | w(24h唯一) | 现行 T(s) | 建议 T*(s) | Δ |")
    print("|---|---|---|---|---|")
    for ch in sorted(chs, key=lambda k: -w[k]):
        t = round(T[ch])
        d = t - T_cur[ch]
        print(f"| {ch} | {w[ch]:g} | {T_cur[ch]} | {t} | {'+' if d>=0 else ''}{d} |")
    print("\n公式: T_c* = sqrt(2λ)·sqrt(a_c/w_c)，sqrt(2λ) = Σ_j sqrt(a_j·w_j)/Q（平方根律的预算约束推广）")
    print("诚实边界: w 用唯一发现数代理价值（未区分置信层/真实有效性）；a_c 为简化口径；")
    print("结果用于答辩演示『周期可推导』与方向性调参，不自动改配。")


if __name__ == "__main__":
    main()
