"""结果聚合层：把 findings 行聚类为唯一凭据实体与出现记录。

本模块是 findings 表之上的**派生视图**：只读扫描写路径的既有
口径（命中/发现/唯一凭据三量纲与生产数字不受影响），把同一条凭据在
口径（命中/发现/唯一凭据三量纲与锁定生产数字不受影响），把同一条凭据在
多个位置/多个检测器下的命中折叠为两层结构——

  credential_entities  唯一凭据实体（身份 = DISTINCT secret_sha256，与
                       Store.stats 的 unique_secrets 口径一致）
  credential_occurrences  出现记录（同凭据 × 不同 (source_uri, line_no)；
                       同位不同检测器折叠为同一出现，检测器并列保留）

身份指纹：长度前缀帧（4 字节大端长度 + UTF-8 字节）杜绝字段拼接歧义，
不做小写归一（区分大小写的凭据值不坍缩）；HMAC-SHA256(系统密钥) 计算，
未配置 CREDSCAN_HMAC_KEY 时回落裸 sha256——scheme 字段自描述，保证与
历史库/生产数字可比，且无密钥库与有密钥库的指纹互不兼容（防混账）。

用法：python3 -m credscan.aggregation --db demo.db [--top 10] [--json]
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sqlite3
from typing import Iterable, Optional

CREDENTIAL_DOMAIN = "credscan.credential.v1"
OCCURRENCE_DOMAIN = "credscan.occurrence.v1"

_CONF_ORDER = {"placeholder": 0, "weak": 1, "medium": 2, "strong": 3}
_SEV_ORDER = {"low": 1, "medium": 2, "high": 3}

AGG_SCHEMA = """
CREATE TABLE IF NOT EXISTS credential_entities(
  credential_id TEXT PRIMARY KEY,
  secret_sha256 TEXT NOT NULL,
  scheme TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  finding_count INTEGER NOT NULL,
  occurrence_count INTEGER NOT NULL,
  channels TEXT NOT NULL,
  detectors TEXT NOT NULL,
  max_confidence TEXT,
  max_severity TEXT
);
CREATE INDEX IF NOT EXISTS idx_ce_secret ON credential_entities(secret_sha256);
CREATE TABLE IF NOT EXISTS credential_occurrences(
  occurrence_id TEXT PRIMARY KEY,
  credential_id TEXT NOT NULL REFERENCES credential_entities(credential_id),
  source_uri TEXT NOT NULL,
  line_no INTEGER,
  channel TEXT,
  detectors TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_co_credential ON credential_occurrences(credential_id);
"""


def frame(parts: Iterable[str]) -> bytes:
    """长度前缀帧：每段 4 字节大端长度 + UTF-8 字节，拼接无歧义。"""
    out = bytearray()
    for p in parts:
        b = p.encode("utf-8")
        out += len(b).to_bytes(4, "big") + b
    return bytes(out)


class Fingerprints:
    """凭据/出现身份指纹：HMAC-SHA256（无密钥回落裸 sha256）。"""

    def __init__(self, key: Optional[bytes]):
        self.key = key
        self.scheme = "hmac-sha256" if key else "sha256"

    @classmethod
    def from_env(cls) -> "Fingerprints":
        raw = os.environ.get("CREDSCAN_HMAC_KEY", "").strip()
        return cls(raw.encode("utf-8") if raw else None)

    def _digest(self, parts: Iterable[str]) -> str:
        data = frame(parts)
        if self.key:
            return hmac.new(self.key, data, hashlib.sha256).hexdigest()
        return hashlib.sha256(data).hexdigest()

    def credential(self, secret_sha256: str) -> str:
        return self._digest([CREDENTIAL_DOMAIN, secret_sha256])

    def occurrence(self, cred_id: str, source_uri: str, line_no: int) -> str:
        return self._digest([OCCURRENCE_DOMAIN, cred_id, source_uri, str(line_no)])


def _max_by(order: dict, values: set) -> Optional[str]:
    alive = [(order[v], v) for v in values if v in order]
    return max(alive)[1] if alive else None


def rebuild(db: sqlite3.Connection, fp: Fingerprints) -> dict:
    """从 findings 全量重建两张聚合表：单事务、幂等、失败整体回滚。

    明文不在本层出现——findings 里只有 sha256 指纹与脱敏字段，聚合
    过程不接触任何凭据内容。
    """
    entities: dict = {}   # secret_sha256 -> 聚合中间态
    occs: dict = {}       # (secret, uri, line) -> 聚合中间态
    has_findings = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='findings'"
    ).fetchone() is not None
    if has_findings:
        for secret, uri, line, channel, det, ts, conf, sev in db.execute(
            "SELECT secret_sha256, source_uri, line_no, channel, detector, ts,"
            " confidence, severity FROM findings"):
            e = entities.setdefault(secret, {
                "first": ts, "last": ts, "n_find": 0, "channels": set(),
                "detectors": set(), "confs": set(), "sevs": set()})
            e["n_find"] += 1
            e["channels"].add(channel or "")
            e["detectors"].add(det)
            e["confs"].add(conf or "")
            e["sevs"].add(sev or "")
            if ts < e["first"]:
                e["first"] = ts
            if ts > e["last"]:
                e["last"] = ts
            o = occs.setdefault((secret, uri, line), {
                "channel": channel, "detectors": set(), "first": ts, "last": ts})
            o["detectors"].add(det)
            if ts < o["first"]:
                o["first"] = ts
            if ts > o["last"]:
                o["last"] = ts

    db.executescript(AGG_SCHEMA)
    db.execute("BEGIN")
    try:
        db.execute("DELETE FROM credential_occurrences")
        db.execute("DELETE FROM credential_entities")
        n_occ_by_secret = {}
        for (secret, _uri, _line), o in occs.items():
            n_occ_by_secret[secret] = n_occ_by_secret.get(secret, 0) + 1
        for secret, e in entities.items():
            cred_id = fp.credential(secret)
            db.execute(
                "INSERT INTO credential_entities"
                "(credential_id, secret_sha256, scheme, first_seen_at, last_seen_at,"
                " finding_count, occurrence_count, channels, detectors,"
                " max_confidence, max_severity) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (cred_id, secret, fp.scheme, e["first"], e["last"], e["n_find"],
                 n_occ_by_secret[secret], ",".join(sorted(e["channels"])),
                 ",".join(sorted(e["detectors"])),
                 _max_by(_CONF_ORDER, e["confs"]), _max_by(_SEV_ORDER, e["sevs"])))
        for (secret, uri, line), o in occs.items():
            db.execute(
                "INSERT INTO credential_occurrences"
                "(occurrence_id, credential_id, source_uri, line_no, channel,"
                " detectors, first_seen_at, last_seen_at) VALUES (?,?,?,?,?,?,?,?)",
                (fp.occurrence(fp.credential(secret), uri, line),
                 fp.credential(secret), uri, line, o["channel"],
                 ",".join(sorted(o["detectors"])), o["first"], o["last"]))
        db.commit()
    except Exception:
        db.rollback()
        raise
    return {"credentials": len(entities), "occurrences": len(occs)}


def summary(db: sqlite3.Connection, top: int = 10) -> dict:
    """聚合汇总：总量、时间窗、Top 扩散凭据（出现数/跨渠道数）。"""
    try:
        total = db.execute("SELECT COUNT(*) FROM credential_entities").fetchone()[0]
    except sqlite3.OperationalError:
        return {"credentials": 0, "occurrences": 0, "top": []}
    window = db.execute(
        "SELECT MIN(first_seen_at), MAX(last_seen_at) FROM credential_entities"
    ).fetchone()
    top_rows = db.execute(
        "SELECT secret_sha256, finding_count, occurrence_count, channels,"
        "       max_confidence, max_severity, first_seen_at, last_seen_at"
        "  FROM credential_entities"
        " ORDER BY occurrence_count DESC, finding_count DESC LIMIT ?", (top,)
    ).fetchall()
    n_occ = db.execute("SELECT COUNT(*) FROM credential_occurrences").fetchone()[0]
    scheme = db.execute("SELECT scheme FROM credential_entities LIMIT 1").fetchone()
    return {
        "credentials": total,
        "occurrences": n_occ,
        "scheme": scheme[0] if scheme else None,
        "window": {"first": window[0], "last": window[1]},
        "top": [{
            "secret_sha256": r[0], "finding_count": r[1], "occurrence_count": r[2],
            "channel_spread": len([c for c in r[3].split(",") if c]),
            "max_confidence": r[4], "max_severity": r[5],
            "first_seen_at": r[6], "last_seen_at": r[7],
        } for r in top_rows],
    }


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python3 -m credscan.aggregation",
        description="结果聚合：findings → 唯一凭据实体 + 出现记录（派生视图）")
    ap.add_argument("--db", required=True, help="findings 库路径")
    ap.add_argument("--top", type=int, default=10, help="Top 扩散凭据条数")
    ap.add_argument("--json", action="store_true", help="JSON 输出")
    args = ap.parse_args(argv)
    db = sqlite3.connect(args.db)
    try:
        stats = rebuild(db, Fingerprints.from_env())
        s = summary(db, top=args.top)
        s.update(stats)
        if args.json:
            print(json.dumps(s, ensure_ascii=False, indent=2))
        else:
            print(f"唯一凭据 {s['credentials']} / 出现 {s['occurrences']}"
                  f"（指纹方案 {s['scheme']}，窗口 {s['window']['first']}"
                  f" ~ {s['window']['last']}）")
            for i, t in enumerate(s["top"], 1):
                print(f"{i}. {t['secret_sha256'][:12]}… 出现 {t['occurrence_count']}"
                      f" 处（{t['channel_spread']} 渠道 / {t['finding_count']} 命中，"
                      f"最高 {t['max_confidence']}/{t['max_severity']}）")
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
