"""结果聚合层（aggregation.py）单元测试。

覆盖点：findings 行聚类为唯一凭据实体（credential）与出现记录（occurrence），
身份指纹采用长度前缀帧 + HMAC-SHA256（无密钥回落裸 sha256，scheme 自描述）。
身份指纹采用长度前缀帧 + HMAC-SHA256（无密钥回落裸 sha256，scheme 自描述）。
"""

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from credscan.aggregation import Fingerprints, frame, rebuild, summary
from credscan.core import Finding, Store


def _mk(secret: str, uri: str, line: int, detector: str = "aliyun_ak",
        ts: str = "2026-10-19T12:00:00+08:00", confidence: str = "strong",
        severity: str = "high", channel: str = "github_gists") -> Finding:
    return Finding(channel=channel, source_uri=uri, detector=detector,
                   secret_sha256=secret, preview="LTA***XY", snippet="ak = LTA...",
                   line_no=line, severity=severity, confidence=confidence, ts=ts)


class TestFrame(unittest.TestCase):
    """长度前缀帧：字段拼接无歧义（规格书核心性质）。"""

    def test_length_prefix_disambiguates_concat(self):
        self.assertNotEqual(frame(["ab", "c"]), frame(["a", "bc"]))
        self.assertNotEqual(frame(["ab", "c"]), frame(["abc"]))

    def test_frame_encoding(self):
        self.assertEqual(frame([]), b"")
        self.assertEqual(frame(["x"]), b"\x00\x00\x00\x01x")

    def test_frame_preserves_case(self):
        # 规格要求：不对区分大小写的凭据值做小写转换
        self.assertNotEqual(frame(["ABcd"]), frame(["abcd"]))


class TestFingerprints(unittest.TestCase):
    """凭据/出现身份指纹：确定性、密钥敏感性、回落自描述。"""

    def setUp(self):
        self.hmac_fp = Fingerprints(b"unit-test-key")
        self.plain_fp = Fingerprints(None)

    def test_credential_id_stable(self):
        self.assertEqual(self.hmac_fp.credential("a" * 64),
                         self.hmac_fp.credential("a" * 64))

    def test_key_sensitivity(self):
        self.assertNotEqual(self.hmac_fp.credential("a" * 64),
                            self.plain_fp.credential("a" * 64))

    def test_fallback_is_plain_sha256_over_frame(self):
        import hashlib
        want = hashlib.sha256(frame(["credscan.credential.v1", "a" * 64])).hexdigest()
        self.assertEqual(self.plain_fp.credential("a" * 64), want)

    def test_scheme_marker(self):
        self.assertEqual(self.hmac_fp.scheme, "hmac-sha256")
        self.assertEqual(self.plain_fp.scheme, "sha256")

    def test_occurrence_binds_credential_and_position(self):
        c1 = self.hmac_fp.credential("a" * 64)
        base = self.hmac_fp.occurrence(c1, "https://gist/1", 7)
        self.assertEqual(base, self.hmac_fp.occurrence(c1, "https://gist/1", 7))
        self.assertNotEqual(base, self.hmac_fp.occurrence(c1, "https://gist/1", 8))
        self.assertNotEqual(base, self.hmac_fp.occurrence(
            self.hmac_fp.credential("b" * 64), "https://gist/1", 7))

    def test_from_env_reads_key(self):
        os.environ["CREDSCAN_HMAC_KEY"] = "env-key"
        try:
            fp = Fingerprints.from_env()
            self.assertEqual(fp.scheme, "hmac-sha256")
            self.assertEqual(fp.credential("a" * 64),
                             Fingerprints(b"env-key").credential("a" * 64))
        finally:
            del os.environ["CREDSCAN_HMAC_KEY"]
        self.assertEqual(Fingerprints.from_env().scheme, "sha256")


class TestRebuildAndSummary(unittest.TestCase):
    """聚类重建与汇总：唯一凭据 = DISTINCT secret_sha256（与三量纲口径一致）。"""

    def _db(self) -> sqlite3.Connection:
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.store = Store(self.tmp.name)
        return self.store.db

    def tearDown(self):
        store = getattr(self, "store", None)
        if store is not None:
            store.db.close()
        tmp = getattr(self, "tmp", None)
        if tmp is not None:
            Path(tmp.name).unlink(missing_ok=True)
            for suffix in ("-wal", "-shm"):
                Path(tmp.name + suffix).unlink(missing_ok=True)

    def test_clusters_by_secret_and_occurrence(self):
        db = self._db()
        s1, s2 = "a" * 64, "b" * 64
        db_rows = [
            _mk(s1, "uriA", 1),            # S1 第一处
            _mk(s1, "uriA", 2),            # S1 同 URI 不同行
            _mk(s1, "uriB", 5, channel="pypi_feed"),
            _mk(s1, "uriA", 1, detector="generic_entropy_secret",
                confidence="weak", severity="medium"),  # 同位不同检测器：同出现
            _mk(s2, "uriA", 1),            # S2 独立凭据
        ]
        for f in db_rows:
            self.store.save(f)
        stats = rebuild(db, Fingerprints(b"k"))
        self.assertEqual(stats["credentials"], 2)
        self.assertEqual(stats["occurrences"], 4)  # S1×3 + S2×1
        row = db.execute(
            "SELECT finding_count, occurrence_count FROM credential_entities"
            " WHERE secret_sha256=?", (s1,)).fetchone()
        self.assertEqual(row[0], 4)   # 4 条 findings 行（含同位不同检测器）
        self.assertEqual(row[1], 3)   # 3 个不同 (uri, line) 出现

    def test_first_last_seen_and_max_tiers(self):
        # findings 表 dedup=detector|secret|uri|line，同位重复扫描只留首条，
        # 故实体级 first/last_seen 来自不同出现位置的时间差。
        db = self._db()
        s1 = "c" * 64
        for line, ts, conf, sev in [
            (1, "2026-10-01T08:00:00+08:00", "weak", "low"),
            (2, "2026-10-05T09:00:00+08:00", "strong", "medium"),
            (3, "2026-10-03T07:00:00+08:00", "medium", "high"),
        ]:
            self.store.save(_mk(s1, "uriA", line, ts=ts, confidence=conf,
                                severity=sev))
        rebuild(db, Fingerprints(b"k"))
        row = db.execute(
            "SELECT first_seen_at, last_seen_at, max_confidence, max_severity"
            " FROM credential_entities WHERE secret_sha256=?", (s1,)).fetchone()
        self.assertEqual(row[0], "2026-10-01T08:00:00+08:00")
        self.assertEqual(row[1], "2026-10-05T09:00:00+08:00")
        self.assertEqual(row[2], "strong")
        self.assertEqual(row[3], "high")

    def test_rebuild_idempotent(self):
        db = self._db()
        for i in range(3):
            self.store.save(_mk("d" * 64, f"uri{i}", i))
        rebuild(db, Fingerprints(b"k"))
        first = db.execute(
            "SELECT COUNT(*), SUM(finding_count) FROM credential_entities").fetchone()
        rebuild(db, Fingerprints(b"k"))
        second = db.execute(
            "SELECT COUNT(*), SUM(finding_count) FROM credential_entities").fetchone()
        self.assertEqual(first, second)

    def test_rebuild_empty_db(self):
        db = self._db()
        stats = rebuild(db, Fingerprints(b"k"))
        self.assertEqual(stats["credentials"], 0)
        self.assertEqual(summary(db)["credentials"], 0)

    def test_rebuild_missing_findings_table(self):
        # 指向空文件/非本工具库时不应裸 traceback：按空集处理并建好聚合表
        import tempfile as _tf
        with _tf.NamedTemporaryFile(suffix=".db", delete=False) as fh:
            path = fh.name
        try:
            db = sqlite3.connect(path)
            stats = rebuild(db, Fingerprints(b"k"))
            self.assertEqual(stats, {"credentials": 0, "occurrences": 0})
            self.assertEqual(summary(db)["credentials"], 0)
            db.close()
        finally:
            Path(path).unlink(missing_ok=True)

    def test_summary_totals_and_top(self):
        db = self._db()
        s1, s2 = "e" * 64, "f" * 64
        rows = [_mk(s1, "uriA", 1), _mk(s1, "uriB", 2, channel="pypi_feed"),
                _mk(s1, "uriC", 3, channel="npm_feed"), _mk(s2, "uriD", 1)]
        for f in rows:
            self.store.save(f)
        rebuild(db, Fingerprints(b"k"))
        s = summary(db, top=2)
        self.assertEqual(s["credentials"], 2)
        self.assertEqual(s["occurrences"], 4)
        self.assertEqual(s["scheme"], "hmac-sha256")
        self.assertEqual(s["top"][0]["occurrence_count"], 3)
        self.assertEqual(s["top"][0]["channel_spread"], 3)  # 跨渠道扩散度
        self.assertEqual(s["top"][0]["secret_sha256"], s1)


if __name__ == "__main__":
    unittest.main()
