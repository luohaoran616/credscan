"""离线测试：本地渠道 + 全检测器。不依赖网络。"""
import tempfile
import unittest
from pathlib import Path

import credscan  # noqa: F401  注册插件
from credscan.channels import SITE_TARGETS
from credscan.core import CHANNELS, DETECTORS, Item, Store, scan_item

FIXTURE = Path(__file__).parent / "fixtures" / "corpus.txt"
from fixture_loader import corpus_text  # 编码语料运行时解码


class TestInventory(unittest.TestCase):
    def test_enough_detectors(self):
        self.assertGreaterEqual(len(DETECTORS), 30)

    def test_enough_channels(self):
        self.assertGreaterEqual(len(CHANNELS), 7)
        self.assertGreaterEqual(len(SITE_TARGETS), 15)

    def test_so_family_site_targets(self):
        """Stack Overflow 家族：配置粘贴泄露高发区，searx 矩阵口径扩展。"""
        domains = {d for d, _ in SITE_TARGETS}
        for dom in ("stackoverflow.com", "superuser.com", "serverfault.com", "askubuntu.com"):
            self.assertIn(dom, domains)

    def test_expected_channels_present(self):
        for cid in ("local_fs", "github_search", "github_commits", "github_gists", "gitee_search",
                    "pypi_feed", "npm_feed", "dockerhub", "searx_matrix",
                    "hf_feed", "sourcegraph_search", "nuget_catalog",
                    "rubygems_activity", "juejin_search", "csdn_search"):
            self.assertIn(cid, CHANNELS)


class TestDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = corpus_text() + (
            "\ntencent_secret_id = " + "AKID" + "wz8kZyXq1AbCdEfGhIjKlMnOpQrStUvW\n")
        cls.item = Item(channel="local_fs", uri=FIXTURE.as_uri(), text=cls.text)
        cls.findings = list(scan_item(cls.item))

    def test_expected_detectors_fired(self):
        fired = {f.detector for f in self.findings}
        expected = {
            "aliyun_access_key_id", "tencent_secret_id", "aliyun_sts_ak", "jdcloud_access_key",
            "volcengine_ak", "cloud_aksk_pair",
            "aws_access_key_id", "gcp_api_key", "azure_storage_conn", "azure_sas",
            "baidu_qianfan_key", "qingcloud_ak",
            "huawei_cloud_pair", "qiniu_pair", "ctyun_pair", "ucloud_pair",
            "private_key_pem", "putty_ppk", "gcp_service_account",
            "db_uri", "jdbc_password", "slack_token", "telegram_bot_token", "discord_token",
            "sendgrid_key", "twilio_key", "stripe_key", "github_token", "gitlab_pat",
            "npm_token", "mailgun_key", "facebook_token",
            "openai_key", "anthropic_key", "llm_hex32_key", "zhipu_key", "xai_key", "groq_key",
            "minimax_api_key", "moonshot_api_key",
            "google_oauth_secret", "google_client_id", "wechat_appid", "oauth_secret_pair",
            "wecom_corpsecret", "feishu_app_id",
            "feishu_webhook", "dingtalk_webhook", "wecom_webhook",
            "bare_b64_private_key", "wepay_key",
            "jwt", "basic_auth_url", "password_pair", "shadow_hash", "generic_entropy_secret",
        }
        missing = expected - fired
        self.assertEqual(missing, set(), f"未命中: {missing}")

    def test_stopwords_not_matched(self):
        text = "password = changeme\npassword: 123456\n"
        finds = list(scan_item(Item(channel="t", uri="u", text=text)))
        self.assertEqual([f for f in finds if f.detector == "password_pair"], [])

    def test_snippet_masks_sibling_secret_on_same_line(self):
        """红线③同行扩展：一行两把凭据时，任一记录的 snippet 都不得含任一把明文。"""
        ak = "LTAI5tK8x2q9vZ3wTb1c"  # 阿里云 AK 形态：LTAI 前缀 + 16 位
        sk = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
        text = f'access_key:"{ak}", secret:"{sk}"'
        finds = list(scan_item(Item(channel="t", uri="u", text=text)))
        self.assertGreaterEqual(len(finds), 1, "双凭据行至少应有一条命中")
        for f in finds:
            self.assertNotIn(ak, f.snippet, f"{f.detector} 的 snippet 泄漏同行 AK")
            self.assertNotIn(sk, f.snippet, f"{f.detector} 的 snippet 泄漏同行 SK")

    def test_example_secrets_whitelisted(self):
        """官方文档示例值（AWS docs）不得计入检出。"""
        text = ("aws_example = AKIAIOSFODNN7EXAMPLE\n"
                "aws_secret_example = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                "real_aws = AKIA2M9O7X3QPLMBVCXZ\n")
        finds = list(scan_item(Item(channel="t", uri="u", text=text)))
        aws = [f.preview for f in finds if f.detector == "aws_access_key_id"]
        self.assertEqual(aws, ["AKI…XZ"], f"白名单失效: {aws}")

    def test_new_vendor_example_secrets_whitelisted(self):
        """W2 批次官方示例值（华为云/千帆/青云）不入库。"""
        text = ("huawei_doc_ak = P83EVBZJMXCYTMUII\n"
                "qianfan_doc = bce-v3/ALTAK-a1b2c3d4e5f60718293a4b5cXX\n"
                "qingcloud_doc = QYACCESSKEYIDEXAMPLE\n")
        finds = list(scan_item(Item(channel="t", uri="u", text=text)))
        previews = sorted({f.detector for f in finds
                           if any(x in f.preview for x in ("P83…UII", "QYA…PLE"))})
        self.assertEqual(previews, [], f"新白名单失效: {previews}")

    def test_wecom_requires_corpid_context(self):
        """孤立 corpsecret（无 corpid 上下文）不判企微。"""
        text = "corpsecret = NoContextCorpSecret012345\n"
        finds = list(scan_item(Item(channel="t", uri="u", text=text)))
        self.assertEqual([f for f in finds if f.detector == "wecom_corpsecret"], [])

    def test_dedup_same_input_twice(self):
        with tempfile.TemporaryDirectory() as td:
            store = Store(f"{td}/t.db")
            for f in self.findings:
                store.save(f)
            first = store.stats()["total"]
            for f in self.findings:
                store.save(f)
            self.assertEqual(store.stats()["total"], first)

    def test_store_never_contains_full_secret(self):
        secrets = []
        for line in self.text.splitlines():
            # 抽取等号/冒号右侧的裸值用于校验
            for sep in ("= ", ": ", '="', ':"'):
                if sep in line:
                    v = line.split(sep, 1)[1].strip().strip('"')
                    if len(v) >= 16 and " " not in v:
                        secrets.append(v)
        with tempfile.TemporaryDirectory() as td:
            store = Store(f"{td}/t.db")
            for f in self.findings:
                store.save(f)
            dump = store.dump_text()
            leaked = [s for s in secrets if s in dump]
            self.assertEqual(leaked, [], f"存储中出现完整明文: {leaked}")

    def test_preview_redacted(self):
        for f in self.findings:
            if "…" not in f.preview and not set(f.preview) <= {"*"}:
                self.fail(f"preview 未脱敏: {f.preview!r} ({f.detector})")
            self.assertLessEqual(len(f.preview), 12)


class TestWebhookDetectors(unittest.TestCase):
    """协作机器人 Webhook 令牌族（形态依据见 detectors.py 注释：官方文档 + GitHub
    公开代码字面量实测）。域名+路径+精确 token 形态三层约束 → strong 置信。"""

    def _hits(self, det_id, text):
        return list(DETECTORS[det_id].match(text))

    def test_feishu_webhook_uuid(self):
        hook = "https://open.feishu.cn/open-apis/bot/v2/hook/6dca11aa-22bb-4c33-8d44-0e5f66778899"
        t = f'FEISHU_WEBHOOK = "{hook}"'
        # secret=完整 URL（group(0)，与 slack_token 等惯例一致）：webhook 本身即凭据，
        # 拿到 URL 即可直接调用，无需重组。
        self.assertEqual([h["secret"] for h in self._hits("feishu_webhook", t)], [hook])

    def test_lark_intl_domain(self):
        t = "https://open.larksuite.com/open-apis/bot/v2/hook/143fa1bb-2c3d-4e5f-8a9b-112233445566"
        self.assertEqual(len(self._hits("feishu_webhook", t)), 1)

    def test_dingtalk_webhook_hex64(self):
        t = "curl 'https://oapi.dingtalk.com/robot/send?access_token=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'"
        self.assertEqual(len(self._hits("dingtalk_webhook", t)), 1)

    def test_wecom_webhook_uuid(self):
        t = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=4e11aa22-b33c-4d44-8e55-6f778899aabb"
        self.assertEqual(len(self._hits("wecom_webhook", t)), 1)

    def test_templates_not_matched(self):
        """模板占位（%s/${}/文档 x 串/非 hex）不得命中。"""
        for text in (
            'dingtalk.url = "https://oapi.dingtalk.com/robot/send?access_token=%s"',
            "url = f'https://oapi.dingtalk.com/robot/send?access_token={self.key}'",
            "https://open.feishu.cn/open-apis/bot/v2/hook/" + "larkPushKey",
            "https://open.feishu.cn/open-apis/bot/v2/hook/xxxxxxxxxxxxxxxxx",
            "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=${QYWX_KEY}",
            "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=693a91f6-7xxx-4bc4-97a0-0ec2sifa5aaa",
        ):
            for det_id in ("feishu_webhook", "dingtalk_webhook", "wecom_webhook"):
                self.assertEqual(self._hits(det_id, text), [], f"{det_id} 误报: {text}")


class TestBareB64Key(unittest.TestCase):
    """无 PEM 头单行 base64 私钥（支付宝 app_private_key 是典型形态；形态依据
    2026-10-13 GitHub 实测：字面量 17/17=MII 前缀、完整长度 1590–1626）。"""

    def _hits(self, text):
        return list(DETECTORS["bare_b64_private_key"].match(text))

    def test_alipay_config_style(self):
        key = "MIIEvQ" + "A" * 1200   # 形态真实（PKCS8 2048≈1624 b64 字符），内容合成
        t = f"alipay:\n  app_private_key: {key}\n"
        self.assertEqual([h["secret"] for h in self._hits(t)], [key])

    def test_short_b64_ignored(self):
        t = "app_private_key: MIIEvQ" + "A" * 100 + "\n"   # <200：真私钥不可能这么短
        self.assertEqual(self._hits(t), [])

    def test_no_key_context_ignored(self):
        t = "blob = MIIEvQ" + "A" * 1200 + "\n"            # 无 key 上下文（可能是任意 base64）
        self.assertEqual(self._hits(t), [])

    def test_pem_block_not_double_fired(self):
        """带 -----BEGIN----- 头的 PEM 由 private_key_pem 负责；裸 base64 检测器
        不得对 PEM 体二次命中。"""
        t = ("private_key = '-----BEGIN PRIVATE KEY-----\\n"
             "MIIEvQ" + "A" * 300 + "'")
        self.assertEqual(self._hits(t), [])


class TestWePayKey(unittest.TestCase):
    """微信支付 v2 API key：用户自定义 32 字符、无固定字符集 → 只能上下文+长度约束，
    诚实定级 medium（形态依据 2026-10-13 GitHub 实测：mchKey 字面量 1/1=32 位字母数字）。"""

    def _hits(self, text):
        return list(DETECTORS["wepay_key"].match(text))

    def test_mchkey_literal(self):
        t = 'mchKey := "C52a9Xz8Kq3Lm7Ve2Rt6Yu0Wp4Nj1Hd5"'   # 32 位合成字母数字
        self.assertEqual(len(self._hits(t)), 1)

    def test_generic_apikey_not_fired(self):
        t = 'apiKey = "C52a9Xz8Kq3Lm7Ve2Rt6Yu0Wp4Nj1Hd5"'
        self.assertEqual(self._hits(t), [])

    def test_placeholders_not_fired(self):
        for v in ("YOUR_API_KEY_1234567890ABCDEF", "12345678901234567890123456789012",
                  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "C52a9Xz8Kq3Lm7Ve2Rt6Yu0Wp4Nj1Hd"):
            t = f'mchKey = "{v}"'
            self.assertEqual(self._hits(t), [], f"误报: {v}")


class TestRuleOverlap(unittest.TestCase):
    """M6（数学模型方案 §4.4）：规则交叠 CI——命题 2（正则交可判定）的工程化近似。

    两级判据：
    ① 命中集完全相同 = 冗余死规则，判失败（必须消除）；
    ② 语义包含 A⊆B 且 B 非兜底规则 = 重复计数，判失败；
       兜底规则（generic_entropy_secret / cloud_aksk_pair）覆盖其它规则属分层兜底
       的故意重叠，予以放行。
    """

    # 兜底检测器：允许其命中集覆盖其它检测器（分层兜底的故意重叠）
    FALLBACK = {"generic_entropy_secret", "cloud_aksk_pair"}

    def _hit_sets(self):
        from credscan.core import EXAMPLE_SECRETS
        text = corpus_text()
        hits = {}
        for det in DETECTORS.values():
            s = {h["secret"] for h in det.match(text)} - EXAMPLE_SECRETS
            if s:
                hits[det.id] = s
        return hits

    def test_no_identical_hit_sets(self):
        hits = self._hit_sets()
        ids = sorted(hits)
        self.assertGreater(len(ids), 10, "命中检测器过少，疑似注册表异常")
        for i, a in enumerate(ids):
            for b in ids[i + 1:]:
                self.assertNotEqual(
                    hits[a], hits[b], f"冗余规则: {a} 与 {b} 命中集完全相同")

    def test_no_semantic_subsumption(self):
        """语义包含：A 的命中集被 B 完全包含且 B 非兜底 = 重复计数，判失败。"""
        hits = self._hit_sets()
        for a in hits:
            for b in hits:
                if a == b or b in self.FALLBACK:
                    continue
                if hits[a] and hits[a] <= hits[b]:
                    self.fail(f"语义重复: {a} ⊆ {b}（{b} 已覆盖 {a} 的全部命中，重复计数）")


class TestPlaceholderClass(unittest.TestCase):
    """O3 规则版三分类：weak 层占位符细分（借 SecretBench 特征字段与三分类论文上下文信号）。

    confidence 新增第四值 "placeholder"——weak 的可解释子类，默认告警口径（strong,medium）
    不含它，headline 统计不变；只细分、只降级，绝不升级。
    """

    def test_explicit_placeholder_value_words(self):
        from credscan.core import is_placeholder_secret
        for v in ["your_api_key_here_abc123xyz456",
                  "my-super-secret-token-placeholder",
                  "enter_your_access_key_xxxxxxxxxx"]:
            self.assertTrue(is_placeholder_secret(v, f'token = "{v}"'), v)

    def test_repeated_char_skeleton(self):
        from credscan.core import is_placeholder_secret
        self.assertTrue(is_placeholder_secret("aaaaaaaaaaaaaaaaaaaaaaaa", 'pwd = aaaaaaaaaaaaaaaaaaaaaaaa'))

    def test_key_name_test_marker(self):
        from credscan.core import is_placeholder_secret
        # 键名带测试标记、值本身高熵过闸——上下文才能识别（generic_entropy 命中形态）
        self.assertTrue(is_placeholder_secret(
            "Zx9wKmPq4RbTuvYh8jN5vLcE", 'test_api_key = "Zx9wKmPq4RbTuvYh8jN5vLcE"'))

    def test_fixture_uri_marker(self):
        from credscan.core import is_placeholder_secret
        self.assertTrue(is_placeholder_secret(
            "Zx9wKmPq4RbTuvYh8jN5vLcE", 'api_key = "Zx9wKmPq4RbTuvYh8jN5vLcE"',
            uri="https://example.com/repo/tests/fixtures/config.yml"))

    def test_real_weak_secret_stays_weak(self):
        from credscan.core import is_placeholder_secret
        self.assertFalse(is_placeholder_secret(
            "Tr0ub4dor&3xYz", 'password = "Tr0ub4dor&3xYz"', uri="https://x.com/a/b/blob/main/cfg.env"))

    def test_strong_confidence_never_downgraded(self):
        text = 'aws_key = "AKIAIOSFODNN7EXAMPLEX99"\ntest note here'
        findings = list(scan_item(Item(channel="t", uri="u", text=text)))
        strong = [f for f in findings if f.detector == "aws_access_key_id"]
        for f in strong:
            self.assertEqual(f.confidence, "strong")

    def test_scan_item_downgrades_weak_to_placeholder(self):
        text = 'test_api_key = "Zx9wKmPq4RbTuvYh8jN5vLcE"'
        findings = list(scan_item(Item(channel="t", uri="u", text=text)))
        gen = [f for f in findings if f.detector == "generic_entropy_secret"]
        self.assertTrue(gen, "generic_entropy 应命中该高熵值")
        for f in gen:
            self.assertEqual(f.confidence, "placeholder", "键名带 test 标记的 weak 命中应细分为 placeholder")
            self.assertEqual(f.severity, "low")


class TestItemPathAggregation(unittest.TestCase):
    """弱层同包路径级聚合：Item 级路径入库（档案标记行解析，零改动文本与去重键）。"""

    ARCHIVE_TEXT = (
        "# ==== pkg-1.0/setup.py ====\n"
        "user = root\n"
        "password = Ahz6tGkQwOkd2Vbx\n"
        "# ==== pkg-1.0/tests/test_conf.py ====\n"
        "user = admin\n"
        "password = Zr5mXqLp8Wn3Jd7f\n"
    )

    def test_archive_marker_path_resolved(self):
        finds = list(scan_item(Item(channel="pypi_feed", uri="https://pypi.org/pkg-1.0",
                                    text=self.ARCHIVE_TEXT)))
        pw = [f for f in finds if f.detector == "password_pair"]
        self.assertEqual(len(pw), 2)
        paths = {f.line_no: f.item_path for f in pw}
        setup = [p for p in paths.values() if p.endswith("setup.py")]
        tests = [p for p in paths.values() if "test_conf" in p]
        self.assertEqual(len(setup), 1, f"setup.py 命中应解析到包内路径: {paths}")
        self.assertEqual(len(tests), 1, f"tests 命中应解析到各自路径: {paths}")

    def test_non_archive_item_path_empty(self):
        finds = list(scan_item(Item(channel="gists", uri="https://gist/x",
                                    text="user = root\npassword = Ahz6tGkQwOkd2Vbx\n")))
        self.assertTrue(all(f.item_path == "" for f in finds))

    def test_store_persists_and_groups_weak_by_path(self):
        import tempfile, os
        from credscan.core import Finding
        with tempfile.TemporaryDirectory() as td:
            st = Store(os.path.join(td, "t.db"))
            base = dict(channel="pypi_feed", source_uri="https://pypi.org/pkg-1.0",
                        detector="generic_entropy_secret", preview="x…", snippet="s",
                        severity="low", confidence="weak")
            for i, (path, sha) in enumerate([("a/config.py", "s1"), ("a/config.py", "s2"),
                                             ("b/util.py", "s3")]):
                st.save(Finding(secret_sha256=sha, line_no=i + 1, item_path=path, **base))
            groups = st.weak_path_groups(min_count=2)
            self.assertEqual(groups, [("https://pypi.org/pkg-1.0", "a/config.py", 2, 2)],
                             f"同包同路径≥2 才成组: {groups}")

    def test_store_migrates_old_schema_without_item_path(self):
        import tempfile, os, sqlite3
        with tempfile.TemporaryDirectory() as td:
            db = os.path.join(td, "old.db")
            con = sqlite3.connect(db)
            con.execute("CREATE TABLE findings(dedup TEXT PRIMARY KEY, ts TEXT, channel TEXT,"
                        " source_uri TEXT, published_at TEXT, detector TEXT, severity TEXT,"
                        " confidence TEXT, secret_sha256 TEXT, preview TEXT, snippet TEXT,"
                        " line_no INTEGER, latency_sec REAL)")
            con.commit(); con.close()
            st = Store(db)  # 打开即迁移
            self.assertEqual(st.weak_path_groups(), [])


class TestCliWeakPaths(unittest.TestCase):
    def test_stats_weak_paths_flag(self):
        """stats --weak-paths 输出弱层路径聚合（复核队列优先级视图）。"""
        import io, json, os, tempfile, contextlib
        from credscan.core import Finding
        from credscan import cli
        with tempfile.TemporaryDirectory() as td:
            db = os.path.join(td, "t.db")
            st = Store(db)
            base = dict(channel="pypi_feed", source_uri="https://pypi.org/p1",
                        detector="generic_entropy_secret", preview="x…", snippet="s",
                        severity="low", confidence="weak", item_path="cfg/keys.py")
            for i, sha in enumerate(("s1", "s2")):
                st.save(Finding(secret_sha256=sha, line_no=i + 1, **base))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.main(["stats", "--db", db, "--weak-paths"])
            self.assertEqual(rc, 0)
            out = json.loads(buf.getvalue())
            self.assertIn("weak_path_groups", out)
            self.assertEqual(out["weak_path_groups"][0]["item_path"], "cfg/keys.py")


if __name__ == "__main__":
    unittest.main()


# 噪音治理（追加于文件尾，不移动既有行号锚点）：unittest 运行前会 simplefilter("default")
# 重置模块级 warning 过滤，故改在 setUpModule 内过滤（其执行晚于重置），
# 抑制测试内短生命周期 Store 连接 GC 回收触发的 ResourceWarning。
import warnings as _w


def setUpModule():
    _w.filterwarnings("ignore", category=ResourceWarning)
