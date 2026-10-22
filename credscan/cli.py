"""CLI：scan / list / stats / honeytoken。"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List

from . import __version__
from .channels import SITE_TARGETS
from .core import CHANNELS, DETECTORS, Item, Store, scan_item
from .response import (AliyunRAMProvider, ConsoleSink, JsonlSink, Registry,
                       Responder, WebhookSink, live_enabled)


def _build_responder(args, store: Store) -> Responder:
    sinks = []
    if args.verbose:
        sinks.append(ConsoleSink())
    if args.alert_jsonl:
        sinks.append(JsonlSink(args.alert_jsonl))
    if args.webhook:
        sinks.append(WebhookSink(args.webhook))
    return Responder(
        sinks=sinks,
        providers={"aliyun_ram": AliyunRAMProvider()},
        registry=Registry(args.honeytokens),
        store=store,
        live=live_enabled(args.respond),
        alert_on=tuple(args.alert_confidence.split(",")),
    )


def cmd_list(args) -> int:
    inv = {
        "channels": [
            {"id": c.id, "title": c.title, "kind": c.kind, "needs_net": c.needs_net}
            for c in CHANNELS.values()
        ],
        "channels_total": len(CHANNELS) + len(SITE_TARGETS) - 1,  # 矩阵按站点展开计
        "detectors": [
            {"id": d.id, "title": d.title, "family": d.family,
             "severity": d.severity, "confidence": d.confidence}
            for d in DETECTORS.values()
        ],
        "detectors_total": len(DETECTORS),
        "version": __version__,
    }
    if getattr(args, "export", None) == "markdown":
        lines = [f"# CredScan v{__version__} 支持清单（自动生成：credscan list --export markdown）", "",
                 f"- 监测口径总数：{inv['channels_total']}（{len(inv['channels'])} 类适配器，矩阵按站点展开）",
                 f"- 凭据检测器：{inv['detectors_total']} 个", "",
                 "## 交付件③：支持的公开渠道列表", "",
                 "| # | 渠道 id | 型别 | 需网络 | 说明 |", "|---|---|---|---|---|"]
        for i, c in enumerate(inv["channels"], 1):
            lines.append(f"| {i} | {c['id']} | {c['kind']} | {'是' if c['needs_net'] else '否'} | {c['title']} |")
        lines.append(f"（另：SearxNG 矩阵按 {len(SITE_TARGETS)} 个站点展开计入口径总数。）")
        lines += ["", "## 交付件④：支持的凭据类型列表", "",
                  "| # | 检测器 id | 凭据族 | 置信 | 严重度 | 说明 |", "|---|---|---|---|---|---|"]
        for i, d in enumerate(inv["detectors"], 1):
            lines.append(f"| {i} | {d['id']} | {d['family']} | {d['confidence']} | {d['severity']} | {d['title']} |")
        print("\n".join(lines))
        return 0
    print(json.dumps(inv, ensure_ascii=False, indent=2))
    return 0


def cmd_scan(args) -> int:
    store = Store(args.db)
    responder = _build_responder(args, store)
    summary = {"items": 0, "new": 0, "dup": 0, "per_channel": {}}
    for chan_id in args.channel:
        ch = CHANNELS.get(chan_id)
        if ch is None:
            print(f"unknown channel: {chan_id}", file=sys.stderr)
            continue
        kw = {}
        if chan_id == "local_fs":
            kw["path"] = args.path or "."
        if args.query:
            kw["query"] = args.query
        if args.max_items:
            kw["max_items"] = args.max_items
        stat = summary["per_channel"].setdefault(chan_id, {"items": 0, "new": 0})
        try:
            for item in ch.iter_items(**kw):
                summary["items"] += 1
                stat["items"] += 1
                for f in scan_item(item):
                    if store.save(f):
                        summary["new"] += 1
                        stat["new"] += 1
                        if args.verbose:
                            print(f"[+] {f.channel} {f.detector} {f.preview} @ {f.source_uri}")
                        responder.on_new_finding(f)   # 告警 →（蜜凭据命中时）处置
                    else:
                        summary["dup"] += 1
        except KeyboardInterrupt:
            break
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def cmd_stats(args) -> int:
    store = Store(args.db)
    out = store.stats()
    if getattr(args, "weak_paths", False):
        # 弱层（weak+placeholder）同包同路径聚合：复核队列优先级视图（§3.4.5 下钻）
        out["weak_path_groups"] = [
            {"source_uri": u, "item_path": p, "findings": n, "uniques": q}
            for u, p, n, q in store.weak_path_groups()
        ]
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def cmd_honeytoken(args) -> int:
    reg = Registry(args.registry)
    if args.honey_action == "list":
        if not reg.entries:
            print("{}（空登记表：还没有自有蜜凭据）")
        for sha, meta in reg.entries.items():
            print(json.dumps({"sha256": sha, **meta}, ensure_ascii=False))
        return 0
    # add：secret 从文件或 stdin 读，绝不回显、绝不进日志
    import pathlib
    if args.secret_file and args.secret_file != "-":
        secret = pathlib.Path(args.secret_file).read_text(encoding="utf-8").strip()
    else:
        secret = sys.stdin.read().strip()
    if not secret:
        print("empty secret", file=sys.stderr)
        return 1
    entry = reg.add(secret, args.provider, args.user, args.ak_id, args.note)
    print(json.dumps({**entry, "secret_file": "(已丢弃，只留 sha256)"}, ensure_ascii=False))
    return 0


def cmd_daemon(args) -> int:
    from .daemon import Daemon          # 延迟导入：daemon 专用
    Daemon(args.config).serve()
    return 0


def cmd_batch(args) -> int:
    """历史批扫：pypi_top / dockerhub_sweep / commits_deep（对照实验的批扫翼）。"""
    from .batch import BATCHES
    store = Store(args.db)
    summary = {"items": 0, "new": 0, "dup": 0, "per_batch": {}}
    for name in args.batch:
        fn = BATCHES.get(name)
        if fn is None:
            print(f"unknown batch: {name}", file=sys.stderr)
            continue
        kw = {}
        if name == "dockerhub_sweep":
            kw["queries"] = args.queries or ["python", "node", "golang"]
        stat = summary["per_batch"].setdefault(name, {"items": 0, "new": 0})
        try:
            for item in fn(**kw):
                summary["items"] += 1
                stat["items"] += 1
                for f in scan_item(item):
                    if store.save(f):
                        summary["new"] += 1
                        stat["new"] += 1
                        if args.verbose:
                            print(f"[+] {f.channel} {f.detector} {f.preview} @ {f.source_uri}")
                    else:
                        summary["dup"] += 1
        except KeyboardInterrupt:
            break
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="credscan", description="云上凭据泄露自动化检测与响应")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="扫描渠道并入库")
    s.add_argument("--channel", action="append", required=True,
                   help=f"渠道 id（可重复）：{', '.join(CHANNELS)}")
    s.add_argument("--query", help="搜索词（github/gitee/searx_matrix 用）")
    s.add_argument("--path", help="本地路径（local_fs 用）")
    s.add_argument("--db", default="credscan.db")
    s.add_argument("--max-items", type=int, default=0)
    s.add_argument("-v", "--verbose", action="store_true")
    # 响应层
    s.add_argument("--webhook", help="告警 webhook URL（POST 脱敏 JSON）")
    s.add_argument("--alert-jsonl", help="告警流落盘路径（panel/事后分析用）")
    s.add_argument("--alert-confidence", default="strong,medium",
                   help="触发告警的置信层（默认 strong,medium）")
    s.add_argument("--respond", action="store_true",
                   help="启用蜜凭据处置（默认 dry-run；live 需再设 CREDSCAN_RESPOND_LIVE=1）")
    s.add_argument("--honeytokens", default="honeytokens.json",
                   help="自有蜜凭据登记表路径")
    s.set_defaults(fn=cmd_scan)

    h = sub.add_parser("honeytoken", help="自有蜜凭据登记（牺牲凭据闭环）")
    h.add_argument("honey_action", choices=["add", "list"])
    h.add_argument("--secret-file", default="-",
                   help="凭据文件路径，- 或省略 = stdin（不回显）")
    h.add_argument("--provider", default="aliyun_ram")
    h.add_argument("--user", required=True, help="RAM 用户名（如 credscan-demo）")
    h.add_argument("--ak-id", required=True, help="牺牲 AK 的 AccessKeyId（如 LTAI5t…）")
    h.add_argument("--note", default="", help="备注（植入位置等）")
    h.add_argument("--registry", default="honeytokens.json")
    h.set_defaults(fn=cmd_honeytoken)

    d = sub.add_parser("daemon", help="守护进程（按渠道节奏调度 + 查询词轮换）")
    d.add_argument("--config", default="daemon.json")
    d.set_defaults(fn=cmd_daemon)

    p = sub.add_parser("panel", help="运维工作台（标准库 HTTP 服务 + 单页 ECharts）")
    p.add_argument("--db", default="credscan.db")
    p.add_argument("--config", help="daemon.json 路径（展示渠道节奏/健康度）")
    p.add_argument("--alerts", help="alerts.jsonl 路径（响应联动页）")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8088)
    p.set_defaults(fn=lambda a: __import__("credscan.panel", fromlist=["serve"]).serve(
        a.db, a.host, a.port, a.config, a.alerts))

    b = sub.add_parser("batch", help="历史批扫（pypi_top/dockerhub_sweep/commits_deep）")
    b.add_argument("--batch", action="append", required=True,
                   help="批扫名（可重复）：pypi_top / dockerhub_sweep / commits_deep")
    b.add_argument("--queries", nargs="*", help="dockerhub_sweep 的镜像关键词")
    b.add_argument("--db", default="credscan.db")
    b.add_argument("-v", "--verbose", action="store_true")
    b.set_defaults(fn=cmd_batch)

    l = sub.add_parser("list", help="渠道与凭据类型清单（交付件③④）")
    l.add_argument("--export", choices=["markdown"], help="导出 markdown（默认 JSON）")
    l.set_defaults(fn=cmd_list)

    t = sub.add_parser("stats", help="检出统计与时效性")
    t.add_argument("--db", default="credscan.db")
    t.add_argument("--weak-paths", action="store_true",
                   help="弱层同包同路径聚合（复核队列优先级视图）")
    t.set_defaults(fn=cmd_stats)

    args = ap.parse_args(argv)
    return args.fn(args)
