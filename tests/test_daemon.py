"""daemon 调度逻辑测试（不碰网络，不动真实渠道）。"""
import json
import tempfile
import unittest
from pathlib import Path

import credscan  # noqa: F401
from credscan.core import CHANNELS, Item
from credscan.daemon import Daemon


def write_cfg(tmp: Path, channels: dict) -> str:
    p = tmp / "daemon.json"
    p.write_text(json.dumps({"db": "t.db", "channels": channels}), encoding="utf-8")
    return str(p)


class TestDaemon(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def daemon(self, channels: dict) -> Daemon:
        return Daemon(write_cfg(self.dir, channels))

    def test_due_respects_interval_and_state(self):
        d = self.daemon({"github_gists": {"every_sec": 300}})
        now = 10000.0
        self.assertTrue(d.due("github_gists", now))            # 从未跑过 → 立即到期
        d.state["github_gists"]["last_run"] = now
        self.assertFalse(d.due("github_gists", now + 299))
        self.assertTrue(d.due("github_gists", now + 300))

    def test_disabled_and_unknown_channels_never_due(self):
        d = self.daemon({"local_fs": {"enabled": False},
                         "no_such_channel": {"every_sec": 1}})
        self.assertFalse(d.due("local_fs", 1e9))
        self.assertFalse(d.due("no_such_channel", 1e9))

    def test_query_rotation_wraps_and_persists(self):
        d = self.daemon({"github_search": {"every_sec": 60,
                                           "queries": ["a", "b", "c"]}})
        got = [d.next_query("github_search") for _ in range(7)]
        self.assertEqual(got, ["a", "b", "c", "a", "b", "c", "a"])   # 轮换回绕
        d.save_state()
        d2 = Daemon(str(self.dir / "daemon.json"))                   # 重启续轮
        self.assertEqual(d2.next_query("github_search"), "b")

    def test_run_channel_rotates_query_and_stores_findings(self):
        # 注入假渠道（本地注册表，测完移除）
        from credscan.core import register_channel, Channel

        @register_channel
        class FakeChannel(Channel):
            id = "fake_test"; title = "fake"; needs_net = False

            def iter_items(self, query: str = "", **kw):
                yield Item(channel=self.id, uri="mem://1", published_at="2026-10-10T00:00:00+00:00",
                           text="access_key_id = LTAI5tFakeKeyAbCdEfGhIjKlMnOp\n"
                                "password = S3cretPassw0rdNotReal!!\n"
                                f"q={query}")

        self.addCleanup(CHANNELS.pop, "fake_test", None)
        d = self.daemon({"fake_test": {"every_sec": 10, "queries": ["q1", "q2"]}})
        s1 = d.run_channel("fake_test")
        self.assertGreaterEqual(s1["items"], 1)
        self.assertEqual(s1["query"], "q1")
        self.assertGreaterEqual(s1["new"], 1)                        # 检出入库
        s2 = d.run_channel("fake_test")
        self.assertEqual(s2["query"], "q2")                           # 轮到下一个词
        self.assertEqual(s2["new"], 0)                                # 去重生效


if __name__ == "__main__":
    unittest.main()


# 噪音治理（追加于文件尾，不移动既有行号锚点）：unittest 运行前会 simplefilter("default")
# 重置模块级 warning 过滤，故改在 setUpModule 内过滤（其执行晚于重置），
# 抑制测试内短生命周期 Store 连接 GC 回收触发的 ResourceWarning。
import warnings as _w


def setUpModule():
    _w.filterwarnings("ignore", category=ResourceWarning)
