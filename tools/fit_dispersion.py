#!/usr/bin/env python3
"""M7：发现流过散检验与负二项拟合（数学模型方案 §3）。

增长层把发现流建模为 compound-Poisson；此前 gists 小时口径 disp=σ²/μ≈64，远超 Poisson
的 1（§3 登记为 open problem）。本工具用矩法把过散显式参数化：

  - 负二项（Γ-Poisson 混合）：Var = μ + μ²/r，矩法 r̂ = μ²/(σ²−μ)
  - compound-Poisson 等效解释：批量均值 = σ²/μ（Poisson 批量=1）

把"过散"从定性现象变成两个可报告的参数，§3 由 open problem 升级为显式建模。
只读打开生产库，不写任何内容。用法（credscan/ 目录下）：

  python3 tools/fit_dispersion.py --db ../data/credscan.db [--hours 168] [--top 6]
"""
from __future__ import annotations

import argparse
import sqlite3


def nb_moments(counts: list) -> dict | None:
    """计数序列 → {n,mean,var,disp_index,nb_r,batch_mean}；空序列 None。

    disp_index=σ²/μ（Poisson=1，>1 过散）；σ²≤μ 时 nb_r=None（NB 退化）。
    """
    n = len(counts)
    if n == 0:
        return None
    mu = sum(counts) / n
    var = sum((x - mu) ** 2 for x in counts) / n
    disp = var / mu if mu > 0 else None
    r = mu * mu / (var - mu) if (mu > 0 and var > mu) else None
    return {"n": n, "mean": mu, "var": var,
            "disp_index": disp, "nb_r": r, "batch_mean": disp}


def hourly_new_uniques(conn: sqlite3.Connection, channel: str,
                       max_hours: int) -> list:
    """按 ts 小时桶去重新增数（ISO 文本序即可排序，取末 max_hours 桶）。"""
    rows = conn.execute(
        "SELECT substr(ts,1,13) h, COUNT(DISTINCT secret_sha256) n "
        "FROM findings WHERE channel=? GROUP BY h ORDER BY h",
        (channel,)).fetchall()
    return [r[1] for r in rows][-max_hours:]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True, help="findings 库路径（只读打开）")
    ap.add_argument("--hours", type=int, default=168, help="取最近 N 个小时桶")
    ap.add_argument("--top", type=int, default=6, help="按发现量取前 N 个渠道")
    args = ap.parse_args()

    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    chans = [r[0] for r in conn.execute(
        "SELECT channel FROM findings GROUP BY channel "
        "ORDER BY COUNT(*) DESC LIMIT ?", (args.top,))]

    print(f"{'渠道':<22}{'小时桶':>6}{'μ':>9}{'σ²':>11}{'D=σ²/μ':>9}{'NB r̂':>9}")
    for ch in chans:
        counts = hourly_new_uniques(conn, ch, args.hours)
        m = nb_moments(counts)
        if not m or m["n"] < 24:
            print(f"{ch:<22}{m['n'] if m else 0:>6}  （桶<24，样本不足不拟合）")
            continue
        r_txt = f"{m['nb_r']:.2f}" if m["nb_r"] is not None else "-"
        print(f"{ch:<22}{m['n']:>6}{m['mean']:>9.1f}{m['var']:>11.1f}"
              f"{m['disp_index']:>9.2f}{r_txt:>9}")
    print("\n解释：D≈1 → Poisson 足够；D>>1 → 过散，NB r̂ 越小尾部越重"
          "（小时级爆发），compound-Poisson 等效批量=D。")


if __name__ == "__main__":
    main()
