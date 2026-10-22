"""credscan 守护进程：按渠道节奏调度扫描 + 查询词轮换 + 状态续跑。纯标准库。

用法：credscan daemon --config daemon.json
- 配置里的相对路径一律相对 config 文件所在目录解析；
- 状态（各渠道 last_run / 查询词下标）存 <config>.state.json，重启续跑；
- 单渠道异常隔离（不影响其他渠道），SIGTERM 优雅退出；
- 频率纪律：各渠道 every_sec 必须尊重平台配额（如 github_search 10 次/分 → 一轮一查询、
  间隔 ≥ 7 分钟），宁可慢不可封。
"""
from __future__ import annotations

import json
import signal
import time
from pathlib import Path
from typing import Optional

from .core import CHANNELS, Store, now_iso, scan_item
from .response import (AliyunRAMProvider, JsonlSink, Registry, Responder,
                       WebhookSink, live_enabled)

TICK_SEC = 15


def log(msg: str) -> None:
    print(f"[{now_iso()}] {msg}", flush=True)


class Daemon:
    def __init__(self, cfg_path: str):
        base = Path(cfg_path).resolve().parent
        cfg = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
        self.channels: dict = cfg.get("channels", {})
        self.state_path = base / (Path(cfg_path).name + ".state.json")
        self.state: dict = self._load_state()
        self.store = Store(str(base / cfg.get("db", "credscan.db")))
        sinks = []
        if cfg.get("alert_jsonl"):
            sinks.append(JsonlSink(str(base / cfg["alert_jsonl"])))
        if cfg.get("webhook"):
            sinks.append(WebhookSink(cfg["webhook"]))
        self.responder = Responder(
            sinks=sinks, providers={"aliyun": AliyunRAMProvider(),
                                    "aliyun_ram": AliyunRAMProvider()},
            registry=Registry(str(base / cfg.get("honeytokens", "honeytokens.json"))),
            store=self.store, live=live_enabled(cfg.get("respond", False)))
        self._stop = False

    # ---- 状态持久化 ----

    def _load_state(self) -> dict:
        if self.state_path.exists():
            try:
                return json.loads(self.state_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                pass
        return {}

    def save_state(self) -> None:
        self.state_path.write_text(json.dumps(self.state, ensure_ascii=False, indent=1),
                                   encoding="utf-8")

    # ---- 调度 ----

    def next_query(self, cid: str) -> Optional[str]:
        """轮换取下一个查询词；无词表返回 None。下标存状态文件，重启续轮。"""
        qs = self.channels.get(cid, {}).get("queries") or []
        if not qs:
            return None
        st = self.state.setdefault(cid, {})
        qi = st.get("qi", 0) % len(qs)
        st["qi"] = qi + 1
        return qs[qi]

    def due(self, cid: str, now: float) -> bool:
        ch = self.channels.get(cid, {})
        if not ch.get("enabled", True) or cid not in CHANNELS:
            return False
        return now - self.state.setdefault(cid, {}).get("last_run", 0) >= ch.get("every_sec", 600)

    def run_channel(self, cid: str) -> dict:
        ch = CHANNELS[cid]
        kw = {}
        q = self.next_query(cid)
        if q:
            kw["query"] = q
        stat = {"items": 0, "new": 0, "query": q or "-"}
        for item in ch.iter_items(**kw):
            stat["items"] += 1
            for f in scan_item(item):
                if self.store.save(f):
                    stat["new"] += 1
                    self.responder.on_new_finding(f)
        return stat

    # ---- 主循环 ----

    def stop(self, *_a) -> None:
        self._stop = True

    def serve(self) -> None:
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)
        log(f"daemon 启动：渠道 {list(self.channels)}")
        while not self._stop:
            for cid in list(self.channels):
                if self._stop:
                    break
                if not self.due(cid, time.time()):
                    continue
                t0 = time.monotonic()
                try:
                    stat = self.run_channel(cid)
                    log(f"{cid}: items={stat['items']} new={stat['new']} "
                        f"query={stat['query']} ({time.monotonic() - t0:.1f}s)")
                except Exception as e:  # 单渠道故障不拖垮守护
                    log(f"{cid}: ERROR {type(e).__name__}: {str(e)[:150]}")
                self.state.setdefault(cid, {})["last_run"] = time.time()
                self.save_state()
            time.sleep(TICK_SEC)
        self.save_state()
        log("daemon 退出（状态已保存）")
