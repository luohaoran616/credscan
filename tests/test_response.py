"""响应层测试（unittest，纯标准库）：告警脱敏、置信过滤、第三方凭据绝不处置、
蜜凭据 dry-run 闭环、阿里云 RPC 请求形状（全部 mock，不打真实 API）。"""
import json
import os
import tempfile
import unittest
import urllib.parse
from pathlib import Path

import credscan  # noqa: F401  注册插件
from credscan import response
from credscan.core import Finding, Store
from credscan.response import (AliyunRAMProvider, JsonlSink, Registry, Responder,
                               WebhookSink, alert_payload)


def make_finding(secret_sha256="a" * 64, confidence="strong", detector="aliyun_ak") -> Finding:
    return Finding(channel="github_gists", source_uri="https://gist.github.com/x",
                   detector=detector, secret_sha256=secret_sha256,
                   preview="LTA…1D", snippet="access_key_id = LTA…1D", line_no=3,
                   severity="high", confidence=confidence, published_at="2026-10-07T00:00:00+00:00")


class ResponseTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.store = Store(str(self.dir / "t.db"))
        self.calls = []
        self._orig_post = response._http_post
        response._http_post = self._fake_post
        self._orig_env = {k: os.environ.get(k) for k in
                          ("CREDSCAN_RESPOND_LIVE", "CREDSCAN_DEMO_ALIYUN_AK_ID",
                           "CREDSCAN_DEMO_ALIYUN_AK_SECRET")}
        for k in self._orig_env:
            os.environ.pop(k, None)

    def tearDown(self):
        response._http_post = self._orig_post
        for k, v in self._orig_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _fake_post(self, url, body, headers, timeout=15):
        self.calls.append({"url": url, "body": body, "headers": headers})
        return 200, b"{}"

    def registry(self, name="h.json", entries=None):
        reg = Registry(str(self.dir / name))
        reg.entries.update(entries or {})
        return reg


class TestAlerts(ResponseTestBase):
    def test_webhook_payload_never_carries_plaintext(self):
        WebhookSink("https://example.com/hook").emit(alert_payload(make_finding()))
        self.assertEqual(len(self.calls), 1)
        payload = json.loads(self.calls[0]["body"])
        self.assertEqual(payload["secret_sha256"], "a" * 64)
        self.assertEqual(payload["preview"], "LTA…1D")
        self.assertNotIn("text", payload)
        self.assertNotIn("secret", payload)

    def test_alert_fires_only_for_configured_confidence(self):
        resp = Responder(sinks=[JsonlSink(str(self.dir / "a.jsonl"))], providers={},
                         registry=self.registry(), store=self.store)
        resp.on_new_finding(make_finding(confidence="weak"))       # weak：不告警
        self.assertEqual(self.store.recent_events(), [])
        resp.on_new_finding(make_finding(confidence="medium"))     # medium：告警
        evs = self.store.recent_events()
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0][1], "alert")

    def test_sink_failure_does_not_raise(self):
        class BoomSink:
            id = "boom"

            def emit(self, payload):
                raise RuntimeError("webhook down")

        resp = Responder(sinks=[BoomSink()], providers={}, registry=self.registry(),
                         store=self.store)
        resp.on_new_finding(make_finding())                         # 不得抛异常
        self.assertEqual(self.store.recent_events()[0][3], "error")


class TestRedlines(ResponseTestBase):
    def test_third_party_finding_never_triggers_response(self):
        seen = []

        class SpyProvider:
            id = "spy"

            def execute(self, finding, meta, live):
                seen.append((meta, live))
                return {"action": "spy", "status": "ok", "detail": ""}

        reg = self.registry(entries={"b" * 64: {"provider": "spy", "user_name": "u",
                                                 "access_key_id": "LTAIxx"}})
        resp = Responder(sinks=[JsonlSink(str(self.dir / "a.jsonl"))], providers={"spy": SpyProvider()},
                         registry=reg, store=self.store)
        resp.on_new_finding(make_finding(secret_sha256="a" * 64))   # 未登记的 sha
        self.assertEqual(seen, [])                                 # 红线②：绝不处置
        self.assertEqual([e[1] for e in self.store.recent_events()], ["alert"])

    def test_honeytoken_defaults_to_dry_run(self):
        seen = []

        class SpyProvider:
            id = "spy"

            def execute(self, finding, meta, live):
                seen.append(live)
                return {"action": "spy.disable", "status": "dry_run", "detail": ""}

        reg = self.registry(entries={"a" * 64: {"provider": "spy", "user_name": "u",
                                                 "access_key_id": "LTAIxx"}})
        resp = Responder(sinks=[JsonlSink(str(self.dir / "a.jsonl"))], providers={"spy": SpyProvider()},
                         registry=reg, store=self.store)
        resp.on_new_finding(make_finding(secret_sha256="a" * 64))
        self.assertEqual(seen, [False])                            # 红线①：默认 dry-run
        evs = self.store.recent_events()
        kinds = [e[1] for e in evs]
        self.assertIn("response", kinds)                           # 检测→告警→处置链留痕
        self.assertIn("alert", kinds)

    def test_live_requires_double_switch(self):
        from credscan.response import live_enabled
        self.assertFalse(live_enabled(True))                       # 只有 --respond 不够
        os.environ["CREDSCAN_RESPOND_LIVE"] = "1"
        self.assertTrue(live_enabled(True))
        self.assertFalse(live_enabled(False))


class TestRegistry(ResponseTestBase):
    def test_registry_stores_sha256_only(self):
        reg = self.registry()
        entry = reg.add("LTAI5tPLAINTEXTSECRETxxxxx", "aliyun_ram", "credscan-demo",
                        "LTAI5tABCD", "planted gist")
        raw = (self.dir / "h.json").read_text()
        self.assertNotIn("PLAINTEXTSECRET", raw)                   # 明文绝不落盘
        self.assertIn(entry["sha256"], raw)
        self.assertEqual(oct((self.dir / "h.json").stat().st_mode)[-3:], "600")

    def test_registry_hot_reloads_external_add(self):
        """daemon 常驻期间 CLI 登记的新蜜凭据，无需重启即可命中（生产事故回归：2026-10-15 复跑#2/#3）。"""
        reg = self.registry()                                       # daemon 侧实例（启动时加载）
        other = Registry(str(self.dir / "h.json"))                  # 模拟另一次 CLI 登记
        sha, _ = Registry.make_entry("LTAI5tHOTRELOADSECRETxxx", "aliyun",
                                     "honey-hot", "LTAI5tHOT")
        other.add("LTAI5tHOTRELOADSECRETxxx", "aliyun", "honey-hot", "LTAI5tHOT")
        self.assertIsNotNone(reg.get(sha))                          # 未重启也要能查到


class TestAliyunProvider(ResponseTestBase):
    def test_dry_run_never_touches_network(self):
        out = AliyunRAMProvider().execute(
            make_finding(), {"access_key_id": "LTAI5tX", "user_name": "demo"}, live=False)
        self.assertEqual(out["status"], "dry_run")
        self.assertIn("Inactive", out["action"])
        self.assertEqual(self.calls, [])                           # 无 HTTP 发生

    def test_rpc_request_shape(self):
        os.environ["CREDSCAN_DEMO_ALIYUN_AK_ID"] = "LTAIADMIN"
        os.environ["CREDSCAN_DEMO_ALIYUN_AK_SECRET"] = "adminsecret"
        out = AliyunRAMProvider().execute(
            make_finding(), {"access_key_id": "LTAI5tHONEY", "user_name": "demo"}, live=True)
        self.assertEqual(out["status"], "ok")
        body = self.calls[0]["body"].decode()
        params = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
        self.assertEqual(params["Action"], "UpdateAccessKey")
        self.assertEqual(params["Status"], "Inactive")
        self.assertEqual(params["UserAccessKeyId"], "LTAI5tHONEY")
        self.assertEqual(params["UserName"], "demo")
        self.assertEqual(params["AccessKeyId"], "LTAIADMIN")
        self.assertGreater(len(params["Signature"]), 20)           # HMAC-SHA1 base64


if __name__ == "__main__":
    unittest.main()


# 噪音治理（追加于文件尾，不移动既有行号锚点）：unittest 运行前会 simplefilter("default")
# 重置模块级 warning 过滤，故改在 setUpModule 内过滤（其执行晚于重置），
# 抑制测试内短生命周期 Store 连接 GC 回收触发的 ResourceWarning。
import warnings as _w


def setUpModule():
    _w.filterwarnings("ignore", category=ResourceWarning)
