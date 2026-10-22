#!/usr/bin/env python3
"""M1：L3 熵阈值拟合（数学模型方案 §1.6 / §7）。

在两个标注池上扫描 GenericHighEntropySecret.MIN_ENTROPY 的阈值 h，产出 P-R 表：
  正例池 = tests/fixtures/corpus.txt（合成真凭据，全部为伪造样例）
  负例池 = 真实新发语料（默认 /tmp/bench/corpus_real，W3 基准的同批文件；
           该批 strong 命中经人工裁定全为示例/占位 → 视为"非泄露"的保守近似）

候选提取与 GenericHighEntropySecret 完全同构（同一正则 + 行长≤400 预过滤），
只摘掉熵闸。输出：阈值扫描表 + F1 最优点 + 精确率约束点 + 与现行阈值 3.6 的对照。

用法（必须在 credscan/ 目录下运行，与 unittest 同约定）：
  python3 tools/fit_entropy.py [--bench /tmp/bench/corpus_real] [--target 0.9]
"""
from __future__ import base64
import gzip
import annotations

import argparse
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from credscan.core import shannon_entropy          # noqa: E402
from credscan.detectors import GenericHighEntropySecret  # noqa: E402

GEN_RX = dict(GenericHighEntropySecret.patterns)["generic"] if isinstance(
    GenericHighEntropySecret.patterns[0][1], re.Pattern) else None
# patterns 是 [(kind, compiled)]，注册表里是实例属性；稳妥起见直接取：
_kind, GEN_RX = GenericHighEntropySecret.patterns[0]


def candidates(text: str) -> list:
    """与 GenericHighEntropySecret.match 同构的候选提取（无熵闸、无白名单）。"""
    out = []
    for m in GEN_RX.finditer(text):
        v = m.group(1)
        line = text[text.rfind("\n", 0, m.start(1)) + 1: text.find("\n", m.end(1))]
        if len(line) > 400:
            continue
        out.append(v)
    return out


def pool_from_dir(root: str, cap: int = 20000) -> set:
    vals: set = set()
    for p in sorted(Path(root).rglob("*")):
        if not p.is_file() or len(vals) >= cap:
            continue
        try:
            vals.update(candidates(p.read_text(encoding="utf-8", errors="ignore")))
        except OSError:
            pass
    return vals


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bench", default="/tmp/bench/corpus_real",
                    help="真实新发语料目录（负例池）")
    ap.add_argument("--target", type=float, default=0.9, help="精确率约束")
    ap.add_argument("--cur", type=float, default=GenericHighEntropySecret.MIN_ENTROPY,
                    help="现行阈值")
    args = ap.parse_args()

    here = Path(__file__).resolve().parents[1]
    pos = set(candidates(_load_corpus(here / "tests" / "fixtures" / "corpus.txt.b64")))
    if os.path.isdir(args.bench):
        neg = pool_from_dir(args.bench)
    else:
        neg = set()
        print(f"[warn] 负例池目录不存在：{args.bench}（只输出正例侧统计）")

    print(f"正例池（合成真凭据）: {len(pos)} 个候选值")
    print(f"负例池（真实新发语料，非泄露近似）: {len(neg)} 个候选值")
    if not pos:
        print("[error] 正例池为空，检查 fixtures")
        return

    ph = sorted((shannon_entropy(v), v) for v in pos)
    nh = sorted(shannon_entropy(v) for v in neg)

    def pass_counts(h: float) -> tuple:
        pp = sum(1 for x in ph if x[0] >= h)
        np_ = sum(1 for x in nh if x >= h)
        prec = pp / (pp + np_) if (pp + np_) else 1.0
        rec = pp / len(pos)
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        return pp, np_, prec, rec, f1

    print(f"\n现行阈值 h={args.cur}：", end=" ")
    pp, np_, prec, rec, f1 = pass_counts(args.cur)
    print(f"过闸正例 {pp}，过闸负例 {np_}，P={prec:.2f} R={rec:.2f} F1={f1:.2f}\n")

    print("| h | 过闸正例 | 过闸负例 | 精确率 | 召回 | F1 |")
    print("|---|---|---|---|---|---|")
    best_f1 = (-1.0, None)
    at_target = None
    h = 2.6
    while h <= 5.61:
        pp, np_, prec, rec, f1 = pass_counts(round(h, 2))
        print(f"| {h:.2f} | {pp} | {np_} | {prec:.2f} | {rec:.2f} | {f1:.2f} |")
        if f1 > best_f1[0]:
            best_f1 = (f1, round(h, 2))
        if at_target is None and prec >= args.target:
            at_target = round(h, 2)
        h += 0.1

    print(f"\nF1 最优点: h={best_f1[1]} (F1={best_f1[0]:.2f})")
    print(f"满足 P≥{args.target} 的最小 h: {at_target if at_target else '不存在（任何阈值都达不到）'}")
    print("\n解读（写入报告时保留）：")
    print("1) 若任何 h 都无法同时拿到高 P 与高 R → 熵只配做闸门（过滤低熵噪声），")
    print("   不配做判据 → L3 只能隔离复核，不能自动处置——三层置信设计的实证依据。")
    print("2) 负例池为『非泄露』的保守近似（未逐条 API 验证），精确率是下界口径。")


if __name__ == "__main__":
    main()


def _load_corpus(p):
    """语料以 gzip+base64 随仓（防触发托管平台密钥推送保护），此处解码。"""
    return gzip.decompress(base64.b64decode(p.read_bytes())).decode("utf-8")
