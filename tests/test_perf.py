"""性能预算回归测试：全检测器在大文本上扫描须在预算内完成。

背景：解析筛选模块的 56 个检测器逐一对整段文本跑正则，其中 `cloud_aksk_pair`
（`{0,200}?`）与 `generic_entropy_secret`（`{0,60}?`）含懒惰量词。若未来新增
检测器引入灾难性回溯（catastrophic backtracking），整轮扫描会数量级变慢。
本测试用「大量不成对的 access_key + 超长单行」合成大文本做回归护栏。

预算取宽松值 10s（实测约 0.5s），只拦数量级退化、不拦正常波动。
"""
import time
import unittest

import credscan  # noqa: F401  注册插件
from credscan.core import Item, scan_item


class TestPerformanceBudget(unittest.TestCase):
    BUDGET_SEC = 10.0

    def test_scan_large_text_within_budget(self):
        # 1 万条 access_key（触发 cloud_aksk_pair 懒惰扫描但不成对）+ 20 万字符超长单行
        keys = "\n".join(f"access_key = K{i:020d}" for i in range(10_000))
        minified = 'cfg = "' + ("A" * 200_000) + '"'
        text = f"{keys}\n{minified}\napi_key = 'C52a9Xz8Kq3Lm7Ve2Rt6Yu0Wp4Nj1Hd5'"
        t0 = time.monotonic()
        list(scan_item(Item(channel="t", uri="u", text=text)))
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, self.BUDGET_SEC,
                        f"全检测器扫描 {len(text)} 字符耗时 {elapsed:.2f}s，超预算 {self.BUDGET_SEC}s")
