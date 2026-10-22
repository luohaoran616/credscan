"""credscan core：数据模型、插件注册表、扫描引擎、去重存储。纯标准库、零第三方依赖。"""
from __future__ import annotations

import hashlib
import math
import os
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional

# ---------------------------------------------------------------- 示例值白名单（误报治理第一道闸）
# 官方文档/教程中的示例凭据不是泄露：入库前直接跳过。
# 维护方式：编辑 credscan/example_secrets.txt（每行一个值，# 注释），或 CREDSCAN_WHITELIST 环境变量指向外部文件。


def _load_example_secrets() -> set:
    vals = {
        # AWS 官方文档示例（几乎所有配置教程都会出现）
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "wJalrXUtnFEMI/K7MDENG/MxRfiCYEXAMPLEKEY",
    }
    path = os.environ.get("CREDSCAN_WHITELIST") or str(Path(__file__).with_name("example_secrets.txt"))
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    vals.add(line)
    except OSError:
        pass
    return vals


EXAMPLE_SECRETS = _load_example_secrets()

# ---------------------------------------------------------------- 数据模型

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_iso(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass
class Item:
    """一个待扫描的内容单元（一段文本 + 它的来源定位）。"""
    channel: str
    uri: str
    text: str
    published_at: Optional[str] = None   # 内容公开时间（ISO），用于时效性指标
    meta: dict = field(default_factory=dict)


@dataclass
class Finding:
    channel: str
    source_uri: str
    detector: str
    secret_sha256: str
    preview: str          # 脱敏预览，永不存完整明文
    snippet: str          # 脱敏后的上下文行
    line_no: int
    severity: str         # high / medium / low
    confidence: str       # strong / medium / weak（+ placeholder 弱层子类）
    published_at: Optional[str] = None
    ts: str = field(default_factory=now_iso)
    latency_sec: Optional[float] = None  # 公开时间 → 检出时间的差（秒）
    item_path: str = ""   # 命中所在包内文件路径（档案标记行解析；非档案渠道为空）


# ---------------------------------------------------------------- 脱敏与熵

def redact(secret: str) -> str:
    if len(secret) <= 8:
        return "*" * len(secret)
    return secret[:3] + "…" + secret[-2:]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


# ---------------------------------------------------------------- 占位符细分（规则版三分类）
# O3（2026-10-14）：weak 层的可解释降级。借鉴 SecretBench 特征字段（is_template/has_words）
# 与三分类范式（arXiv:2605.31520）的上下文信号——占位符显式建模可解释告警构成。
# 只细分（weak→placeholder）只降级（severity→low），绝不升级；不确定一律保持 weak。
# 保守性依据：placeholder 与 weak 同属隔离层，默认告警口径（strong,medium）不含二者。

# S1 值本身携带显式占位语（前缀/后缀/整词）
_PLACEHOLDER_VALUE_RX = re.compile(
    r"(?i)(?:^|[-_.])(?:your|my|the|enter|insert|replace|put|placeholder|example|sample|dummy|"
    r"changeme|change[_-]?me|todo|fixme|fake|mock)(?:$|[-_.])")
# S2 骨架值：连续重复字符 ≥6（aaaa…/1111…）
_SKELETON_RX = re.compile(r"(.)\1{5,}")
# S3 键名测试标记：secret 左侧最近的赋值键名含 test/demo/mock 等前缀
_KEY_MARKER_RX = re.compile(
    r"(?i)[\"']?\s*(?:test|tests|testing|dummy|example|demo|mock|fake|sample|placeholder)[_-]\w*\s*[:=]\s*[\"']?\s*$")
# S4 行内占位指示词（中英文）
_CTX_MARKER_RX = re.compile(
    r"(?i)\b(?:dummy[_-]?(?:user|pass|account|value)|for[_-]test(?:ing)?|test[_-]only|sample[_-]data|"
    r"示例|样例|占位|仅供测试)\b")
# S5 来源路径测试标记（tests/fixtures/examples/docs 目录，test_/mock_ 文件名）
_URI_MARKER_RX = re.compile(
    r"(?i)/(?:tests?|testing|fixtures?|examples?|samples?|docs?|demo|mock)s?/|/(?:test|example|sample|mock|dummy)[_-]\w+\.\w+$")


def is_placeholder_secret(secret: str, line: str, uri: str = "") -> bool:
    """判断一个 weak 层命中是否可解释为占位符（值形态 / 键名 / 行上下文 / 来源路径）。"""
    if not secret:
        return False
    if _PLACEHOLDER_VALUE_RX.search(secret):
        return True
    if _SKELETON_RX.search(secret):
        return True
    if line:
        left = line[:line.find(secret)] if secret in line else line[-64:]
        if _KEY_MARKER_RX.search(left) or _CTX_MARKER_RX.search(line):
            return True
    if uri and _URI_MARKER_RX.search(uri):
        return True
    return False


# ---------------------------------------------------------------- 插件注册表

CHANNELS: Dict[str, "Channel"] = {}
DETECTORS: Dict[str, "Detector"] = {}


def register_channel(cls):
    CHANNELS[cls.id] = cls()
    return cls


def register_detector(cls):
    DETECTORS[cls.id] = cls()
    return cls


class Channel:
    """渠道插件基类：iter_items 产出 Item 流。"""
    id: str = ""
    title: str = ""
    kind: str = "network"          # network / local / matrix
    needs_net: bool = True

    def iter_items(self, **kw) -> Iterator[Item]:
        raise NotImplementedError
        yield  # pragma: no cover


class Detector:
    """凭据检测插件基类：match 在文本上产出命中。"""
    id: str = ""
    title: str = ""
    family: str = ""
    severity: str = "high"
    confidence: str = "strong"
    rationale: str = ""            # 置信分档依据（非显然分档时填写，供审计）
    patterns: list = []            # [(kind, re.compile(...))]

    def match(self, text: str) -> Iterator[dict]:
        for kind, rx in self.patterns:
            for m in rx.finditer(text):
                yield {"kind": kind, "secret": m.group(0), "pos": m.start()}


# ---------------------------------------------------------------- 扫描引擎

def _archive_marker_index(text: str) -> Optional[List[tuple]]:
    """包档案拼接文本的标记行索引：[(标记行号, 包内路径)]，非档案文本返回 None。

    channels._slurp_archive_text 在每个成员文件前插入 `# ==== <path> ====` 标记行，
    据此可把任意行号回溯到包内路径——不改动拼接文本本身，去重键与历史数字不变。
    """
    if "# ==== " not in text:
        return None
    idx = []
    for i, line in enumerate(text.splitlines(), start=1):
        m = re.match(r"^# ==== (.+) ====$", line)
        if m:
            idx.append((i, m.group(1)))
    return idx or None


def _resolve_item_path(markers: Optional[List[tuple]], line_no: int) -> str:
    """行号 → 最近一个在其之前的标记行路径（bisect，O(log n)）。"""
    if not markers:
        return ""
    lo, hi = 0, len(markers)
    while lo < hi:
        mid = (lo + hi) // 2
        if markers[mid][0] < line_no:
            lo = mid + 1
        else:
            hi = mid
    return markers[lo - 1][1] if lo > 0 else ""


def _masked_snippet(text: str, ln: int, secrets: list[tuple[str, int]]) -> str:
    """命中行 snippet：把该行内全部命中的秘密值替换为脱敏形态（红线③同行扩展）。

    只替换"本命中的那个值"会在同行多凭据场景下把兄弟凭据明文入库——
    后往前替换以保持前部位置不变。
    """
    lines = text.splitlines()
    raw = lines[ln - 1] if 0 < ln <= len(lines) else ""
    line_start = text.rfind("\n", 0, secrets[0][1]) + 1 if secrets else 0
    for secret, pos in sorted(secrets, key=lambda x: -x[1]):
        rel = pos - line_start
        end = rel + len(secret)
        if 0 <= rel < len(raw):
            raw = raw[:rel] + redact(secret) + raw[end:]
    return raw[:240]


def scan_item(item: Item, detectors: Optional[List[Detector]] = None) -> Iterator[Finding]:
    dets = detectors or list(DETECTORS.values())
    pub_dt = parse_iso(item.published_at)
    det_dt = parse_iso(now_iso())
    latency = (det_dt - pub_dt).total_seconds() if pub_dt and det_dt else None
    markers = _archive_marker_index(item.text)
    # 两阶段：先收集全部命中按行分组，再组装 Finding——
    # snippet 需要"该行全部命中"才能做全行掩码（红线③同行扩展）
    by_line: dict[int, list[tuple[Detector, dict]]] = {}
    for det in dets:
        for hit in det.match(item.text):
            if hit["secret"] in EXAMPLE_SECRETS:      # 官方示例值，跳过（误报治理）
                continue
            by_line.setdefault(line_of(item.text, hit["pos"]), []).append((det, hit))
    lines = item.text.splitlines()
    for ln, pairs in by_line.items():
        raw_line = lines[ln - 1] if 0 < ln <= len(lines) else ""
        secrets = [(h["secret"], h["pos"]) for _, h in pairs]
        for det, hit in pairs:
            secret = hit["secret"]
            conf = det.confidence
            sev = det.severity
            if conf == "weak":
                # O3 占位符细分：取命中所在原始行做上下文判定
                if is_placeholder_secret(secret, raw_line, item.uri):
                    conf, sev = "placeholder", "low"
            yield Finding(
                channel=item.channel,
                source_uri=item.uri,
                detector=det.id,
                secret_sha256=hashlib.sha256(secret.encode("utf-8", "ignore")).hexdigest(),
                preview=redact(secret),
                snippet=_masked_snippet(item.text, ln, secrets),
                line_no=ln,
                severity=sev,
                confidence=conf,
                published_at=item.published_at,
                latency_sec=latency,
                item_path=_resolve_item_path(markers, ln),
            )


# ---------------------------------------------------------------- 存储

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings(
  dedup TEXT PRIMARY KEY,
  ts TEXT, channel TEXT, source_uri TEXT, published_at TEXT,
  detector TEXT, severity TEXT, confidence TEXT,
  secret_sha256 TEXT, preview TEXT, snippet TEXT,
  line_no INTEGER, latency_sec REAL, item_path TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_f_channel ON findings(channel);
CREATE INDEX IF NOT EXISTS idx_f_detector ON findings(detector);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT, kind TEXT, finding_dedup TEXT,
  action TEXT, status TEXT, detail TEXT
);
"""


class Store:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path)
        # 并发纪律：panel 与 daemon 同库双写。
        # WAL 让读写并行（写者不阻塞读者）；busy_timeout 让写锁竞争等待而非立即 SQLITE_BUSY。
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        """旧库平滑迁移：缺列则补（对既有生产库零破坏，旧行 item_path=''）。"""
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(findings)")}
        if "item_path" not in cols:
            self.db.execute("ALTER TABLE findings ADD COLUMN item_path TEXT DEFAULT ''")
            self.db.commit()

    @staticmethod
    def dedup_key(f: Finding) -> str:
        raw = f"{f.detector}|{f.secret_sha256}|{f.source_uri}|{f.line_no}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def save(self, f: Finding) -> bool:
        cur = self.db.execute(
            "INSERT OR IGNORE INTO findings"
            "(dedup,ts,channel,source_uri,published_at,detector,severity,confidence,"
            "secret_sha256,preview,snippet,line_no,latency_sec,item_path)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (self.dedup_key(f), f.ts, f.channel, f.source_uri, f.published_at,
             f.detector, f.severity, f.confidence, f.secret_sha256,
             f.preview, f.snippet, f.line_no, f.latency_sec, f.item_path),
        )
        self.db.commit()
        return cur.rowcount > 0

    def weak_path_groups(self, min_count: int = 2, limit: int = 50) -> list:
        """弱层（weak+placeholder）同包同路径聚合：识别"单包单文件倾倒"型候选。

        §3.4.5 弱层结构量化的路径级下钻——同包同文件 ≥min_count 个命中，
        提示测试夹具/配置模板等批量来源，供复核队列优先级排序。
        """
        return self.db.execute(
            "SELECT source_uri, item_path, COUNT(*) AS n,"
            "       COUNT(DISTINCT secret_sha256) AS uniq"
            "  FROM findings"
            " WHERE confidence IN ('weak','placeholder') AND item_path != ''"
            " GROUP BY source_uri, item_path HAVING n >= ?"
            " ORDER BY n DESC LIMIT ?", (min_count, limit)).fetchall()

    def stats(self) -> dict:
        q = self.db.execute
        total = q("SELECT COUNT(*) FROM findings").fetchone()[0]
        by_channel = q("SELECT channel, COUNT(*) FROM findings GROUP BY channel ORDER BY 2 DESC").fetchall()
        by_detector = q("SELECT detector, COUNT(*) FROM findings GROUP BY detector ORDER BY 2 DESC").fetchall()
        lat = q("SELECT latency_sec FROM findings WHERE latency_sec IS NOT NULL").fetchall()
        lats = sorted(x[0] for x in lat)
        p = lambda a: (lats[int(len(lats) * a)] if lats else None)
        return {
            "total": total,
            "unique_secrets": q("SELECT COUNT(DISTINCT secret_sha256) FROM findings").fetchone()[0],
            "by_confidence": q("SELECT confidence, COUNT(*) FROM findings GROUP BY confidence").fetchall(),
            "by_channel": by_channel,
            "by_detector": by_detector,
            "latency": {
                "samples": len(lats),
                "median_sec": p(0.5), "p90_sec": p(0.9), "max_sec": lats[-1] if lats else None,
            },
        }

    def log_event(self, kind: str, finding_dedup: str, action: str,
                  status: str, detail: str = "") -> None:
        """响应层事件留痕：检测→告警→处置时间戳链（评分轴⑤证据）。"""
        self.db.execute("INSERT INTO events(ts,kind,finding_dedup,action,status,detail)"
                        " VALUES (?,?,?,?,?,?)",
                        (now_iso(), kind, finding_dedup, action, status, detail))
        self.db.commit()

    def recent_events(self, limit: int = 50) -> list:
        return self.db.execute(
            "SELECT ts,kind,action,status,detail FROM events ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()

    def dump_text(self) -> str:
        """导出全部存储文本（测试用：验证库里没有完整明文凭据）。"""
        rows = self.db.execute("SELECT preview, snippet, source_uri, detector FROM findings").fetchall()
        return "\n".join(" ".join(str(x) for x in r) for r in rows)
