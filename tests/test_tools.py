"""tools/ 纯函数层测试（2026-10-13）：
M7 fit_dispersion.nb_moments —— 负二项矩法拟合（过散建模）
M8 report_numbers.build_snapshot —— 报告数字快照（10/21 全量刷新的唯一事实源）
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import fit_dispersion   # noqa: E402
import honeygen         # noqa: E402
import report_numbers   # noqa: E402

import credscan  # noqa: F401,E402  注册插件
from credscan.core import Finding, Store


class TestNBMoments(unittest.TestCase):
    def test_constant_counts_underdispersed(self):
        r = fit_dispersion.nb_moments([2, 2, 2, 2])
        self.assertEqual(r["mean"], 2.0)
        self.assertEqual(r["var"], 0.0)
        self.assertIsNone(r["nb_r"])           # σ²≤μ 时 NB 退化，不给 r̂
        self.assertLess(r["disp_index"], 1.0)

    def test_overdispersed_known_values(self):
        # [0,0,0,0,4,4,4,4]: μ=2, σ²=4 → D=σ²/μ=2, r̂=μ²/(σ²−μ)=2
        r = fit_dispersion.nb_moments([0, 0, 0, 0, 4, 4, 4, 4])
        self.assertEqual(r["mean"], 2.0)
        self.assertEqual(r["var"], 4.0)
        self.assertAlmostEqual(r["disp_index"], 2.0)
        self.assertAlmostEqual(r["nb_r"], 2.0)

    def test_empty_returns_none(self):
        self.assertIsNone(fit_dispersion.nb_moments([]))


class TestSnapshot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.store = Store(str(Path(cls.tmp.name) / "s.db"))
        rows = [
            ("github_gists", "a" * 64, "strong", 10.0),
            ("github_gists", "b" * 64, "weak",   30.0),
            ("npm_feed",     "c" * 64, "strong", 300.0),
        ]
        for i, (ch, sha, conf, lat) in enumerate(rows):
            cls.store.save(Finding(
                channel=ch, source_uri=f"u{i}", detector="d1", secret_sha256=sha,
                preview="p", snippet="s", line_no=1, severity="medium",
                confidence=conf, latency_sec=lat))
        cls.snap = report_numbers.build_snapshot(
            cls.store.db, every_sec={"github_gists": 100, "npm_feed": 600})

    def test_totals(self):
        self.assertEqual(self.snap["totals"]["findings"], 3)
        self.assertEqual(self.snap["totals"]["unique"], 3)
        self.assertEqual(self.snap["totals"]["strong_unique"], 2)

    def test_latency_matches_panel_convention(self):
        # gists 实测 [10,30]：P50=xs[len//2]=30（与 panel /api/latency 同式）；
        # 模型结构性项 pred = every_sec/2 = 50
        g = {r["channel"]: r for r in self.snap["latency"]}["github_gists"]
        self.assertEqual(g["p50"], 30)
        self.assertEqual(g["mean"], 20)
        self.assertEqual(g["pred_t_half"], 50)

    def test_channels_sorted_by_volume(self):
        chs = [r["channel"] for r in self.snap["channels"]]
        self.assertEqual(chs, ["github_gists", "npm_feed"])

    def test_registry_counts_present(self):
        self.assertGreaterEqual(self.snap["registry"]["detectors"], 54)
        self.assertGreaterEqual(self.snap["registry"]["families"], 12)
        self.assertGreaterEqual(self.snap["registry"]["channels"], 38)


class TestCleanupSnippets(unittest.TestCase):
    """红线③历史补偿（运维工具）：掩码漏网明文、跳过已脱敏形态。"""

    def test_plaintext_siblings_masked(self):
        from tools.cleanup_snippets import mask_snippet
        s = 'access_key:"LTAI5tK8x2q9vZ3wTb1c", secret:"sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"'
        out = mask_snippet(s)
        self.assertIsNotNone(out)
        self.assertNotIn("LTAI5t", out)
        self.assertNotIn("sk-proj", out)

    def test_already_redacted_untouched(self):
        from tools.cleanup_snippets import mask_snippet
        for s in ('access_key:"LTA…1c", secret:"sk-…89"', 'password: "MyP…3!"', 'PWD = ******'):
            self.assertIsNone(mask_snippet(s), f"脱敏形态被二次掩码: {s}")


class TestHoneyGen(unittest.TestCase):
    """O4：蜜凭据生成时四维可信度评估（PHANTOM arXiv:2605.02992 框架的规则版落地）。

    四维：syntactic（厂商形态符合度）/ statistical（长度-熵落在真实凭据分布区间）/
    semantic（组织上下文嵌入，由 --context 提供时满分）/ detectability（自检：能被
    本系统检测器命中——蜜凭据闭环的前提）。明文只在生成时一次性输出，登记表只存哈希。
    """

    def test_generate_aliyun_token_scores(self):
        import honeygen
        tok = honeygen.generate("aliyun", context="prod-payment rotation key")
        self.assertRegex(tok["value"], r"^LTAI[A-Za-z0-9]{13,}$")
        s = tok["scores"]
        self.assertEqual(s["syntactic"], 1.0)
        self.assertGreaterEqual(s["statistical"], 0.8, "LTAI 形态 16-24 位应落在真实分布区间")
        self.assertEqual(s["semantic"], 1.0, "提供 context 应得语义分满分")
        self.assertEqual(s["detectability"], 1.0, "自有检测器应能检出 LTAI 形态")
        self.assertGreaterEqual(s["overall"], 0.9)

    def test_low_statistical_score_for_degenerate_token(self):
        import honeygen
        s = honeygen.score("aws", "AKIA" + "A" * 16, context=None)
        self.assertLess(s["statistical"], 0.5, "重复字符骨架的熵过低，统计分应低")
        self.assertEqual(s["semantic"], 0.0, "未提供 context 语义分为 0")

    def test_entry_direct_registry_compatible(self):
        import honeygen
        from credscan.core import hashlib
        tok = honeygen.generate("aws", context="demo")
        self.assertEqual(tok["sha256"], hashlib.sha256(tok["value"].encode()).hexdigest())
        # 登记条目字段与 response.Registry.make_entry 对齐
        for k in ("provider", "user_name", "access_key_id", "note"):
            self.assertIn(k, tok["entry"])


class TestPanelRoutes(unittest.TestCase):
    """O5：表 4-4 面板路由行号核对（纯数字行号列，锚点层不覆盖）。"""

    def test_panel_routes_table_matches_source(self):
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
        from check_anchors import check_panel_routes
        manual_path = (Path(__file__).resolve().parents[2] / "docs"
                       / "技术说明书-从零重写版.md")
        if not manual_path.exists():
            self.skipTest("manual not shipped in this repository")
        manual = manual_path.read_text(encoding="utf-8")
        self.assertEqual(check_panel_routes(manual), 0)

    def test_panel_routes_detects_drift(self):
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
        from check_anchors import check_panel_routes
        fake = "**表 4-4　管理台 HTTP 端点**\n\n| 路由 | 行号 | 返回内容 |\n|---|---|---|\n| `/api/overview` | 1 | x |\n"
        self.assertEqual(check_panel_routes(fake), 1)

    def test_module_lines_detects_drift(self):
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
        from check_anchors import check_module_lines
        fake = "**表 2-1　模块清单、代码规模与依赖方向**\n\n| 模块 | 行数 | 职责 |\n|---|---|---|\n| `core.py` | 1 | x |\n"
        self.assertEqual(check_module_lines(fake), 1)

    def test_counts_detect_drift(self):
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
        from check_anchors import check_counts
        fake = "正文写 3 个检测器。"
        self.assertGreaterEqual(check_counts(fake), 1)


if __name__ == "__main__":
    unittest.main()


# 噪音治理（追加于文件尾，不移动既有行号锚点）：unittest 运行前会 simplefilter("default")
# 重置模块级 warning 过滤，故改在 setUpModule 内过滤（其执行晚于重置），
# 抑制测试内短生命周期 Store 连接 GC 回收触发的 ResourceWarning。
import warnings as _w


def setUpModule():
    _w.filterwarnings("ignore", category=ResourceWarning)
