#!/usr/bin/env python3
"""O4：蜜凭据生成器 + 四维可信度自评（PHANTOM arXiv:2605.02992 框架的规则版落地）。

四维评分（0-1）：
  syntactic     厂商形态符合度（前缀/长度/字符集正则）；
  statistical   统计合理性——熵落在真实凭据区间 [4.0,6.0]、长度落在 [16,40]，线性衰减；
  semantic      组织上下文嵌入——由 --context 提供部署语境时满分（PHANTOM：语义连贯是
                模板蜜凭据可被识别的主因，生成后需人工嵌入真实感配置上下文）；
  detectability 可检出性——自检：值能被本系统检测器命中（蜜凭据闭环的前提）；
  overall       加权 0.3*syn + 0.3*stat + 0.2*sem + 0.2*det。

红线：明文只在生成时一次性打印（用户手动复制植入），登记表条目只含 sha256；
与 response.Registry.make_entry 字段对齐，可直接 add 进 honeytokens.json。

用法（credscan/ 目录下）：
  python3 tools/honeygen.py --provider aliyun --context "prod-payment rotation key" [--count 3]
"""
from __future__ import annotations

import argparse
import json
import re
import secrets as _sec
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # credscan 包在上级

import credscan  # noqa: F401,E402  注册插件
from credscan.core import DETECTORS, shannon_entropy  # noqa: E402
from credscan.response import Registry  # noqa: E402

# 厂商形态库：前缀 + 长度 + 字符集（与 detectors.py 的结构特征层同源）
PROVIDERS = {
    "aliyun":  {"rx": re.compile(r"^LTAI[A-Za-z0-9]{13,17}$"), "prefix": "LTAI", "len": (17, 20), "cs": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"},
    "aws":     {"rx": re.compile(r"^AKIA[A-Z0-9]{16}$"),        "prefix": "AKIA", "len": (20, 20), "cs": "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"},
    "tencent": {"rx": re.compile(r"^AKID[A-Za-z0-9]{32,40}$"),  "prefix": "AKID", "len": (36, 44), "cs": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"},
}

# 真实凭据统计区间（生产层观测 + 检测器熵闸拟合 tools/fit_entropy.py 的先验）
ENTROPY_BAND = (4.0, 6.0)
LENGTH_BAND = (16, 40)


def _band_score(x: float, lo: float, hi: float, slope: float = 0.35) -> float:
    """落在 [lo,hi] 内得 1.0，区间外按 slope 线性衰减（不低于 0）。"""
    if lo <= x <= hi:
        return 1.0
    d = (lo - x) if x < lo else (x - hi)
    return max(0.0, 1.0 - d * slope)


def score(provider: str, value: str, context: str | None) -> dict:
    """四维可信度评分。纯函数（detectability 走本地检测器内存匹配）。"""
    spec = PROVIDERS[provider]
    syn = 1.0 if spec["rx"].match(value) else 0.0
    stat = 0.7 * _band_score(shannon_entropy(value), *ENTROPY_BAND) \
         + 0.3 * _band_score(float(len(value)), *LENGTH_BAND)
    sem = 1.0 if (context and context.strip()) else 0.0
    det = 0.0
    for d in DETECTORS.values():
        if any(h["secret"] == value for h in d.match(value)):
            det = 1.0
            break
    overall = 0.3 * syn + 0.3 * stat + 0.2 * sem + 0.2 * det
    return {"syntactic": round(syn, 3), "statistical": round(stat, 3),
            "semantic": round(sem, 3), "detectability": round(det, 3),
            "overall": round(overall, 3)}


def generate(provider: str, context: str | None = None) -> dict:
    """生成一个蜜凭据并评分。返回 value/sha256/scores/entry。"""
    spec = PROVIDERS[provider]
    n = _sec.randbelow(spec["len"][1] - spec["len"][0] + 1) + spec["len"][0]
    value = spec["prefix"] + "".join(_sec.choice(spec["cs"]) for _ in range(n - len(spec["prefix"])))
    sha, entry = Registry.make_entry(
        value, provider=provider,
        user_name="honey-" + _sec.token_hex(4),
        access_key_id=value[:8] + "…", note=context or "")
    return {"value": value, "sha256": sha, "scores": score(provider, value, context), "entry": entry}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="蜜凭据生成 + 四维可信度自评")
    ap.add_argument("--provider", required=True, choices=sorted(PROVIDERS))
    ap.add_argument("--context", default=None, help="组织上下文（语义嵌入说明，如 prod-payment rotation key）")
    ap.add_argument("--count", type=int, default=1)
    args = ap.parse_args(argv)
    out = []
    for _ in range(args.count):
        tok = generate(args.provider, args.context)
        out.append(tok)
        print(f"value     : {tok['value']}   （一次性显示，请立即复制植入）")
        print(f"scores    : {json.dumps(tok['scores'], ensure_ascii=False)}")
        print(f"registry  : {json.dumps(tok['entry'], ensure_ascii=False)}")
        print("-" * 60)
    print(f"# 共 {len(out)} 条；把 registry 行 add 进 honeytokens.json（value 不落盘）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
