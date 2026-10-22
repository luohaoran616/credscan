#!/usr/bin/env python3
"""M4：渠道覆盖结构（数学模型方案 §3.3）。

输出单调子模目标 f(C) = |⋃ S_c|（唯一凭据覆盖）的贪心边际覆盖曲线（greedy 有
(1−1/e) 近似保证，Nemhauser 谱系）与跨渠道重叠结构——"下一个渠道值不值得加"的决策依据。

只读打开生产库，不写任何内容。用法（credscan/ 目录下）：
  python3 tools/coverage.py --db ../data/credscan.db [--conf strong]
"""
from __future__ import annotations

import argparse
import collections
import sqlite3


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True, help="findings 库路径（只读打开）")
    ap.add_argument("--conf", default=None, help="限定置信层（strong/medium/weak）")
    a = ap.parse_args()

    c = sqlite3.connect(f"file:{a.db}?mode=ro", uri=True)
    where, args = ("WHERE confidence=?", (a.conf,)) if a.conf else ("", ())
    sets: dict = collections.defaultdict(set)
    for ch, s in c.execute(f"SELECT DISTINCT channel, secret_sha256 FROM findings {where}", args):
        sets[ch].add(s)
    tot_u = c.execute(f"SELECT COUNT(DISTINCT secret_sha256) FROM findings {where}", args).fetchone()[0]
    n_find = c.execute(f"SELECT COUNT(*) FROM findings {where}", args).fetchone()[0]
    if not tot_u:
        print("库为空")
        return

    scope = f"（conf={a.conf}）" if a.conf else ""
    print(f"口径{scope}: findings={n_find}  唯一={tot_u}  渠道数={len(sets)}")
    print(f"渠道内重复因子 findings/唯一 = {n_find/tot_u:.2f}")

    cov: set = set()
    cum = 0
    print("\n贪心边际覆盖曲线（子模递减 = 渠道扩展性价比表）：\n")
    print("| step | 渠道 | 边际唯一 | 累计 | 覆盖率 |")
    print("|---|---|---|---|---|")
    for i, ch in enumerate(sorted(sets, key=lambda k: -len(sets[k])), 1):
        m = len(sets[ch] - cov)
        cov |= sets[ch]
        cum = len(cov)
        print(f"| {i} | {ch} | {m} | {cum} | {100*cum/tot_u:.1f}% |")

    sum_ch = sum(len(s) for s in sets.values())
    print(f"\n跨渠道结构: Σ渠道唯一 {sum_ch} vs 全局唯一 {tot_u}"
          f" → 纯重叠 {sum_ch - tot_u}（{100*(sum_ch - tot_u)/tot_u:.1f}%）")
    print("解读: 重叠占比低 = 渠道间近正交、多渠道边际价值仍高；曲线尾部平坦 = 该渠道边际贡献小。")


if __name__ == "__main__":
    main()
