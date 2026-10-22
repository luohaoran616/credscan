"""熵阈值防漂移回归：GenericHighEntropySecret 的熵闸不得在正例池上塌陷召回。

背景：θ = MIN_ENTROPY 是泛化兜底检测器的香农熵闸，定太高会漏报（召回塌陷）。
本测试用正例池（tests/fixtures/corpus.txt 的合成真凭据候选）做护栏：
在现行阈值下正例召回必须 ≥ 0.9，防止 θ 被误抬升或正则/语料被改坏。

负例侧的精确率拟合需外部语料（/tmp/bench/corpus_real，47 值，未入库），
本测试不覆盖——完整 P-R 扫描见 tools/fit_entropy.py（负例缺失时仅输出正例侧）。
"""
import unittest
from pathlib import Path

import credscan  # noqa: F401  注册插件
from credscan.core import shannon_entropy
from credscan.detectors import GenericHighEntropySecret

FIXTURE = Path(__file__).parent / "fixtures" / "corpus.txt"
from fixture_loader import corpus_text  # 编码语料运行时解码
MIN_RECALL = 0.9


class TestEntropyFit(unittest.TestCase):
    def _positives(self) -> list:
        """与 tools/fit_entropy.py 同构的正例候选提取（无熵闸、行长≤400 预过滤）。"""
        text = corpus_text()
        kind, rx = GenericHighEntropySecret.patterns[0]
        vals = []
        for m in rx.finditer(text):
            v = m.group(1)
            line = text[text.rfind("\n", 0, m.start(1)) + 1: text.find("\n", m.end(1))]
            if len(line) > 400:
                continue
            vals.append(v)
        return vals

    def test_threshold_keeps_positive_recall(self):
        vals = self._positives()
        self.assertGreater(len(vals), 10, "正例池候选过少，疑似正则/语料被改坏")
        th = GenericHighEntropySecret.MIN_ENTROPY
        passed = sum(1 for v in vals if shannon_entropy(v) >= th)
        recall = passed / len(vals)
        self.assertGreaterEqual(
            recall, MIN_RECALL,
            f"θ={th} 时正例召回 {recall:.2f}（{passed}/{len(vals)}）低于 {MIN_RECALL}，熵闸漂移/塌陷")
