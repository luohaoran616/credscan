"""历史批扫模式（batch）：对存量公开制品做一次性深扫。

与 daemon 的事件流构成"批扫 vs 事件驱动"对照实验的两翼（评分轴⑤）：
  事件型（daemon）——只看新增，延迟=分钟级；
  批扫型（batch）——覆盖存量，延迟=内容年龄（发现即滞后）。
纪律与渠道一致：预算墙 + max_items + 只扫公开制品。
"""
from __future__ import annotations

import time
from typing import Iterator, List

from .channels import (_slurp_archive_text, http_get, http_json)
from .core import Item

PYPI_TOP_URL = ("https://raw.githubusercontent.com/hugovk/top-pypi-packages/"
                "main/top-pypi-packages-30-days.json")


def pypi_top(max_items: int = 60, budget_sec: int = 600,
             max_pkg_bytes: int = 8 * 1024 * 1024) -> Iterator[Item]:
    """PyPI 热门包（社区 30 天下载榜，静态 JSON）：扫历史高流量包的 sdist/wheel。"""
    deadline = time.monotonic() + budget_sec
    try:
        import json as _json
        data = _json.loads(http_get(PYPI_TOP_URL, max_bytes=2 * 1024 * 1024))
        rows = data.get("rows") or []
    except Exception as e:
        print(f"[batch:pypi_top] 榜单拉取失败: {e}")
        return
    got = 0
    for row in rows:
        if got >= max_items or time.monotonic() > deadline:
            return
        name = row.get("project")
        if not name:
            continue
        try:
            meta = http_json(f"https://pypi.org/pypi/{name}/json")
        except Exception:
            continue
        info = meta.get("info") or {}
        ver = info.get("version") or ""
        published = ((meta.get("urls") or [{}])[0].get("upload_time_iso_8601"))
        target = None
        for u in meta.get("urls") or []:
            if u.get("packagetype") in ("sdist", "bdist_wheel"):
                target = u
                if u.get("packagetype") == "sdist":
                    break
        if not target or (target.get("size") or 0) > max_pkg_bytes:
            continue
        try:
            blob = http_get(target["url"], max_bytes=max_pkg_bytes)
        except Exception:
            continue
        text = _slurp_archive_text(blob, target.get("filename") or "pkg")
        if not text:
            continue
        got += 1
        yield Item(channel="batch:pypi_top",
                   uri=target["url"],
                   text=text, published_at=published,
                   meta={"package": f"{name}@{ver}", "downloads_30d": row.get("download_count")})


def dockerhub_sweep(queries: List[str], per_query: int = 2, budget_sec: int = 600) -> Iterator[Item]:
    """Docker Hub 热门镜像多关键词扫（复用 dockerhub 渠道，query 逐个跑）。"""
    from .channels import DockerHubChannel
    ch = DockerHubChannel()
    deadline = time.monotonic() + budget_sec
    for q in queries:
        if time.monotonic() > deadline:
            return
        try:
            yield from ch.iter_items(query=q, repos=per_query, budget_sec=120)
        except Exception as e:
            print(f"[batch:dockerhub] {q!r} 失败: {e}")


def commits_deep(hours: int = 72, budget_sec: int = 400) -> Iterator[Item]:
    """GitHub 增量提交深回溯窗（事件型 90 分钟窗 vs 批扫 72 小时窗的对照组）。"""
    from .channels import GitHubCommitsChannel
    try:
        yield from GitHubCommitsChannel().iter_items(
            window_min=hours * 60, max_repos=14, max_items=20, budget_sec=budget_sec)
    except Exception as e:
        print(f"[batch:commits_deep] 失败: {e}")


BATCHES = {"pypi_top": pypi_top, "dockerhub_sweep": dockerhub_sweep, "commits_deep": commits_deep}
