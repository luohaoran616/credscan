"""渠道插件包：iter_items 产出待扫描 Item 流。

在线渠道全部走标准库 urllib，令牌一律从环境变量读：
  GITHUB_TOKEN / GITEE_TOKEN / SEARX_URL（默认本机 http://127.0.0.1:8888）
渠道矩阵：本地目录（App/小程序/镜像层离线制品）× GitHub（搜索/增量提交/Gist 流）× Gitee（议题/仓库）
        × PyPI × npm × NuGet catalog0 × RubyGems × Docker Hub × HuggingFace（spaces/datasets 流）
        × Sourcegraph（全球代码流式搜索）× 掘金 × CSDN × 搜索引擎站点矩阵。
工程纪律：每个网络渠道自带 budget_sec 时间预算与 max_items 上限——宁可少拿，不可拖死守护/被封。
"""
from __future__ import annotations

import gzip
import io
import json
import os
import re
import tarfile
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from datetime import timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Iterator, List, Optional

from .core import Channel, Item, register_channel

UA = {"User-Agent": "credscan/1.0 (research; contest entry)"}
TIMEOUT = 25
TEXT_SUFFIX = {".py", ".txt", ".cfg", ".toml", ".ini", ".json", ".yml", ".yaml", ".env",
               ".md", ".xml", ".sh", ".html", ".js", ".ts", ".java", ".go", ".php", ".rb",
               ".conf", ".properties", ".pem", ".key", ".sql", ".service", ".bat", ".ps1"}
MAX_FILE = 4 * 1024 * 1024        # 单文件 4MB
MAX_ITEM_TEXT = 2 * 1024 * 1024   # 单 Item 拼接文本 2MB


def http_get(url: str, headers: Optional[dict] = None, timeout: int = TIMEOUT,
             max_bytes: Optional[int] = None, retries: int = 2) -> bytes:
    last: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={**UA, **(headers or {})})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if max_bytes is None:
                    return resp.read()
                return resp.read(max_bytes)
        except Exception as e:  # 瞬时网络错误（SSL EOF/重置/超时）退避重试
            last = e
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
    raise last


def http_json(url: str, headers: Optional[dict] = None) -> dict:
    return json.loads(http_get(url, headers).decode("utf-8", "ignore"))


def to_iso(s: Optional[str]) -> Optional[str]:
    """RSS pubDate（RFC2822）→ ISO8601（UTC）；已是 ISO 则原样返回。

    判据用前缀形态：YYYY-MM-DD 开头且带 T/Z 才是 ISO。
    旧判据 `"T" in s or "+" in s[10:]` 会把 RFC2822（含 +0800 时区）误判为 ISO
    原样返回 → core.parse_iso 失败 → latency_sec=None，渠道静默退出时效统计
    （按此判据修正，避免静默退出时效统计）。
    """
    if not s:
        return None
    if re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", s):
        return s
    try:
        return parsedate_to_datetime(s).astimezone(timezone.utc).isoformat(timespec="seconds")
    except Exception:
        return s


def _slurp_archive_text(blob: bytes, filename: str, limit: int = 3) -> str:
    """从 zip/tar(gz) 制品里抽取文本文件内容（限量），供包管理器/镜像层渠道复用。"""
    out: List[str] = []
    total = 0
    try:
        if filename.endswith((".whl", ".zip", ".nupkg")):  # nupkg 即 zip
            with zipfile.ZipFile(io.BytesIO(blob)) as z:
                for n in z.namelist():
                    if Path(n).suffix.lower() in TEXT_SUFFIX and not n.startswith("__MACOSX"):
                        # file_size 预检：跳过超大成员而非全量解压后切片
                        # （z.read(n)[:MAX_FILE] 先解压后截断，MAX_FILE 不构成内存防护，
                        #  与 tar 分支预检不一致，故按 file_size 预检）
                        if z.getinfo(n).file_size > MAX_FILE:
                            continue
                        data = z.read(n)
                        out.append(f"# ==== {n} ====\n" + data.decode("utf-8", "ignore"))
                        total += 1
                        if total >= limit * 40:
                            break
        elif filename.endswith((".tar.gz", ".tgz", ".tar")):
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as t:
                for m in t.getmembers():
                    if m.isfile() and Path(m.name).suffix.lower() in TEXT_SUFFIX and m.size <= MAX_FILE:
                        data = t.extractfile(m).read()
                        out.append(f"# ==== {m.name} ====\n" + data.decode("utf-8", "ignore"))
                        total += 1
                        if total >= limit * 40:
                            break
    except Exception:
        pass
    return "\n".join(out)[:MAX_ITEM_TEXT]


# ---------------------------------------------------------------- 离线 / 本地


@register_channel
class LocalFSChannel(Channel):
    """本地文件与离线制品：源码目录、App APK 解包目录、小程序 wxapkg 解包目录、容器镜像导出层。"""
    id = "local_fs"; title = "本地文件/离线制品（App 解包、小程序包、镜像层导出）"; kind = "local"
    needs_net = False

    def iter_items(self, path: str = ".", **kw) -> Iterator[Item]:
        root = Path(path)
        files = [root] if root.is_file() else sorted(root.rglob("*"))
        for p in files:
            if not p.is_file() or p.suffix.lower() not in TEXT_SUFFIX:
                continue
            try:
                if p.stat().st_size > MAX_FILE:
                    continue
                text = p.read_text("utf-8", "ignore")
            except OSError:
                continue
            yield Item(channel=self.id, uri=p.resolve().as_uri(), text=text,
                       published_at=time.strftime("%Y-%m-%dT%H:%M:%S+00:00",
                                                  time.gmtime(p.stat().st_mtime)),
                       meta={"file": str(p)})


# ---------------------------------------------------------------- GitHub


@register_channel
class GitHubSearchChannel(Channel):
    id = "github_search"; title = "GitHub 代码搜索（Search API）"; kind = "network"

    def iter_items(self, query: str = "", per_page: int = 30, **kw) -> Iterator[Item]:
        if not query:
            return
        headers = {"Accept": "application/vnd.github.text-match+json"}
        tok = os.environ.get("GITHUB_TOKEN")
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        url = ("https://api.github.com/search/code?q=" + urllib.parse.quote(query)
               + f"&per_page={min(per_page, 100)}")
        try:
            data = http_json(url, headers)
        except Exception as e:
            print(f"[github_search] fetch failed: {e}")
            return
        for it in data.get("items", []):
            frags = [tm.get("fragment", "") for tm in it.get("text_matches", [])]
            if frags:
                yield Item(channel=self.id, uri=it.get("html_url", ""),
                           text="\n".join(frags), published_at=None,
                           meta={"repo": it.get("repository", {}).get("full_name")})


@register_channel
class GitHubCommitsChannel(Channel):
    """事件驱动主通路：搜索最近 push 的仓库 → 拉取增量 commit patch（分钟级）。
    背景：/events 自 2025-10 起移除 PushEvent 的 commits 摘要（凭据监控视角已死），
    改走「仓库发现（repositories 搜索，配额与 code search 分离）+ commits?since= 轮询」。"""
    id = "github_commits"; title = "GitHub 增量提交轮询（近实时）"; kind = "network"

    def iter_items(self, window_min: int = 90, max_repos: int = 10,
                   commits_per_repo: int = 2, max_items: int = 12,
                   budget_sec: int = 180, **kw) -> Iterator[Item]:
        headers = {"Accept": "application/vnd.github+json"}
        tok = os.environ.get("GITHUB_TOKEN")
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - window_min * 60))
        deadline = time.monotonic() + budget_sec
        try:
            data = http_json("https://api.github.com/search/repositories?q=pushed%3A"
                             + urllib.parse.quote(since)
                             + "&sort=updated&order=desc&per_page=30", headers)
        except Exception as e:
            print(f"[github_commits] repo search failed: {e}")
            return
        n = 0
        for r in data.get("items", [])[:max_repos]:
            if n >= max_items or time.monotonic() > deadline:
                return
            full = r["full_name"]
            try:
                cs = http_json(f"https://api.github.com/repos/{full}/commits?since="
                               + urllib.parse.quote(since)
                               + f"&per_page={commits_per_repo}", headers)
            except Exception as e:
                print(f"[github_commits] {full}: {type(e).__name__}: {str(e)[:100]}")
                continue
            for c in cs[:commits_per_repo]:
                sha = c.get("sha")
                if not sha:
                    continue
                pub = ((c.get("commit") or {}).get("committer") or {}).get("date")
                try:
                    patch = http_get(f"https://api.github.com/repos/{full}/commits/{sha}",
                                     headers={**headers, "Accept": "application/vnd.github.patch"},
                                     max_bytes=MAX_FILE).decode("utf-8", "ignore")
                except Exception:
                    continue
                n += 1
                yield Item(channel=self.id, uri=f"https://github.com/{full}/commit/{sha}",
                           text=patch, published_at=pub, meta={"repo": full})


@register_channel
class GitHubGistsChannel(Channel):
    """公共 gist 流：创建后分钟级可见（2026-10 实测），text-match 之外的高性价比事件通道。"""
    id = "github_gists"; title = "GitHub 公共 Gist 流（近实时）"; kind = "network"

    def iter_items(self, per_page: int = 50, pages: int = 2, max_items: int = 25,
                   budget_sec: int = 150, **kw) -> Iterator[Item]:
        headers = {}
        tok = os.environ.get("GITHUB_TOKEN")
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        deadline = time.monotonic() + budget_sec
        n = 0
        for page in range(1, pages + 1):
            if time.monotonic() > deadline:
                return
            try:
                gists = http_json(
                    f"https://api.github.com/gists/public?per_page={per_page}&page={page}", headers)
            except Exception as e:
                print(f"[github_gists] page {page} failed: {e}")
                return
            for g in gists:
                if n >= max_items or time.monotonic() > deadline:
                    return
                for fname, meta in list((g.get("files") or {}).items())[:3]:
                    if Path(fname).suffix.lower() not in TEXT_SUFFIX \
                            or (meta.get("size") or 0) > MAX_FILE:
                        continue
                    try:
                        text = http_get(meta["raw_url"], headers,
                                        max_bytes=MAX_FILE).decode("utf-8", "ignore")
                    except Exception:
                        continue
                    n += 1
                    yield Item(channel=self.id,
                               uri=meta.get("html_url") or g.get("html_url", ""),
                               text=text, published_at=g.get("created_at"),
                               meta={"gist": g.get("id"), "file": fname})


# ---------------------------------------------------------------- Gitee


@register_channel
class GiteeSearchChannel(Channel):
    """Gitee 开放 API v5：议题搜索（正文直扫）+ 仓库搜索（配置类文件 raw 拉取）。
    事实边界：v5 无代码搜索 API；匿名搜索恒返回空，必须私人令牌（2026-10 实测）。"""
    id = "gitee_search"; title = "Gitee 仓库/议题搜索（内容级）"; kind = "network"

    @staticmethod
    def _hot_path(path: str) -> bool:
        base = path.rsplit("/", 1)[-1].lower()
        stem = base.rsplit(".", 1)[0]
        if base in {".env", "id_rsa", "id_ed25519"} or base.endswith((".pem", ".key", ".env")):
            return True
        return any(k in stem for k in ("config", "setting", "secret", "token",
                                       "credential", "passwd", "password", "aksk"))

    def iter_items(self, query: str = "", per_page: int = 10, max_items: int = 15,
                   budget_sec: int = 150, **kw) -> Iterator[Item]:
        if not query:
            return
        tok = os.environ.get("GITEE_TOKEN", "")
        if not tok:
            print("[gitee_search] GITEE_TOKEN 未设置（匿名搜索恒为空）")
            return
        deadline = time.monotonic() + budget_sec
        n = 0
        # 1) 议题搜索：标题+正文即待扫文本（issue 里粘贴日志/配置是泄露高发形态）
        try:
            issues = http_json("https://gitee.com/api/v5/search/issues?q="
                               + urllib.parse.quote(query)
                               + f"&per_page={min(per_page, 50)}&access_token={tok}")
        except Exception as e:
            print(f"[gitee_search] issues failed: {e}")
            issues = []
        for it in issues if isinstance(issues, list) else []:
            if n >= max_items:
                return
            body = (it.get("title") or "") + "\n" + (it.get("body") or "")
            if body.strip():
                n += 1
                yield Item(channel=self.id, uri=it.get("html_url", ""), text=body,
                           published_at=it.get("created_at"), meta={"kind": "issue"})
        # 2) 仓库搜索：默认分支树里挑配置类文件拉 raw 全文
        try:
            repos = http_json("https://gitee.com/api/v5/search/repositories?q="
                              + urllib.parse.quote(query)
                              + f"&per_page={min(per_page, 20)}&access_token={tok}")
        except Exception as e:
            print(f"[gitee_search] repos failed: {e}")
            repos = []
        for r in repos if isinstance(repos, list) else []:
            if n >= max_items or time.monotonic() > deadline:
                return
            full = r.get("full_name", "")
            br = r.get("default_branch") or "master"
            try:
                tree = http_json(f"https://gitee.com/api/v5/repos/{full}/git/trees/"
                                 f"{br}?access_token={tok}")
            except Exception:
                continue
            paths = [t.get("path", "") for t in tree.get("tree", [])
                     if t.get("type") == "blob" and self._hot_path(t.get("path", ""))
                     and Path(t.get("path", "")).suffix.lower() in TEXT_SUFFIX]
            for path in paths[:4]:
                try:
                    raw = http_get(f"https://gitee.com/{full}/raw/{br}/{urllib.parse.quote(path)}",
                                   max_bytes=MAX_FILE).decode("utf-8", "ignore")
                except Exception:
                    continue
                n += 1
                yield Item(channel=self.id,
                           uri=f"https://gitee.com/{full}/blob/{br}/{path}",
                           text=raw, published_at=r.get("updated_at"),
                           meta={"repo": full, "path": path})


# ---------------------------------------------------------------- 包管理器公开制品


@register_channel
class PyPIFeedChannel(Channel):
    """PyPI 更新 RSS → 拉取最新包的 sdist/wheel 并扫描。新包即公开时刻，时效性可测。
    带总时间预算（budget_sec），防止单渠道拖死整个守护进程。"""
    id = "pypi_feed"; title = "PyPI 新发布包（sdist/wheel 内容扫描）"; kind = "network"

    def iter_items(self, max_items: int = 10, budget_sec: int = 120, **kw) -> Iterator[Item]:
        deadline = time.monotonic() + budget_sec
        try:
            rss = http_get("https://pypi.org/rss/updates.xml").decode("utf-8", "ignore")
        except Exception as e:
            print(f"[pypi_feed] rss failed: {e}")
            return
        for el in ET.fromstring(rss).iter("item"):
            if max_items <= 0 or time.monotonic() > deadline:
                return
            title = (el.findtext("title") or "").strip()
            pkg = title.split()[0] if title else ""     # RSS title 形如 "zen-engine 2.1.3"
            pub = to_iso(el.findtext("pubDate"))
            if not pkg:
                continue
            try:
                meta = http_json(f"https://pypi.org/pypi/{urllib.parse.quote(pkg)}/json")
                for f in meta.get("urls", []):
                    if f.get("packagetype") in ("sdist", "bdist_wheel") and 0 < f.get("size", 0) <= 8 * 1024 * 1024:
                        blob = http_get(f["url"], max_bytes=8 * 1024 * 1024)
                        text = _slurp_archive_text(blob, f["filename"])
                        if text:
                            max_items -= 1
                            yield Item(channel=self.id, uri=f["url"], text=text,
                                       published_at=pub, meta={"package": pkg})
                        break
            except Exception:
                continue


@register_channel
class NpmFeedChannel(Channel):
    """npm 变更流（replicate.npmjs.com/registry/_changes，2025-03 迁移后唯一入口；
    feed/include_docs 已废，用 descending 拿最新）→ 拉取 tarball 扫描。
    published_at 取该版本发布时间（time[version]），时效性按版本公开时刻计。"""
    id = "npm_feed"; title = "npm 新发布包（tarball 内容扫描）"; kind = "network"

    def iter_items(self, max_items: int = 10, budget_sec: int = 180, **kw) -> Iterator[Item]:
        deadline = time.monotonic() + budget_sec
        try:
            ch = http_json("https://replicate.npmjs.com/registry/_changes?descending=true&limit=50")
        except Exception as e:
            print(f"[npm_feed] changes failed: {e}")
            return
        for r in ch.get("results", []):
            if max_items <= 0 or time.monotonic() > deadline:
                return
            pkg = r.get("id", "")
            if not pkg or pkg.startswith("_"):
                continue
            try:
                meta = http_json(f"https://registry.npmjs.org/{urllib.parse.quote(pkg)}")
                ver = meta.get("dist-tags", {}).get("latest")
                dist = (meta.get("versions", {}).get(ver, {}) or {}).get("dist", {})
                url = dist.get("tarball", "")
                if url and dist.get("shasum"):
                    blob = http_get(url, max_bytes=8 * 1024 * 1024)
                    text = _slurp_archive_text(blob, "pkg.tgz")
                    if text:
                        times = meta.get("time", {}) or {}
                        max_items -= 1
                        yield Item(channel=self.id, uri=url, text=text,
                                   published_at=times.get(ver) or times.get("modified"),
                                   meta={"package": pkg, "version": ver})
            except Exception:
                continue


# ---------------------------------------------------------------- 容器镜像

ACCEPT_MANIFEST = ", ".join([
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
])


@register_channel
class DockerHubChannel(Channel):
    """Docker Hub：搜索公开镜像 → 拉取最近 tag 的层 blob（tar.gz）扫描。
    兼容 docker v2 与 OCI manifest/index（2026 年新镜像多为 OCI）。"""
    id = "dockerhub"; title = "Docker Hub 公开镜像层扫描"; kind = "network"

    def iter_items(self, query: str = "python", repos: int = 3, layers: int = 3,
                   budget_sec: int = 240, **kw) -> Iterator[Item]:
        deadline = time.monotonic() + budget_sec
        try:
            res = http_json("https://hub.docker.com/v2/search/repositories/"
                            "?query=" + urllib.parse.quote(query) + f"&page_size={repos}")
        except Exception as e:
            print(f"[dockerhub] search failed: {e}")
            return
        for r in res.get("results", []):
            if time.monotonic() > deadline:
                return
            name = "library/" + r["repo_name"] if r.get("is_official") else r["repo_name"]
            name = "library/" + r["repo_name"] if r.get("is_official") else r["repo_name"]
            try:
                tok = http_json("https://auth.docker.io/token?service=registry.docker.io"
                                "&scope=repository:" + urllib.parse.quote(name) + ":pull")["token"]
                hdr = {"Authorization": "Bearer " + tok}
                tags = http_json(f"https://registry-1.docker.io/v2/{name}/tags/list?n=3", hdr)
                tag = (tags.get("tags") or ["latest"])[-1]
                man = http_json(f"https://registry-1.docker.io/v2/{name}/manifests/{tag}",
                                {**hdr, "Accept": ACCEPT_MANIFEST})
                if not man.get("layers") and man.get("manifests"):   # OCI index → 取第一个平台 manifest
                    sub = man["manifests"][0]["digest"]
                    man = http_json(f"https://registry-1.docker.io/v2/{name}/manifests/{sub}",
                                    {**hdr, "Accept": ACCEPT_MANIFEST})
                for lay in man.get("layers", [])[:layers]:
                    if time.monotonic() > deadline:
                        return
                    dg = lay["digest"]
                    blob = http_get(f"https://registry-1.docker.io/v2/{name}/blobs/{dg}",
                                    hdr, max_bytes=24 * 1024 * 1024)
                    try:
                        with gzip.GzipFile(fileobj=io.BytesIO(blob)) as gz:
                            text = _slurp_archive_text(gz.read(MAX_ITEM_TEXT + 1), "layer.tar", limit=2)
                    except OSError:
                        text = ""
                    if text:
                        yield Item(channel=self.id, uri=f"dockerhub://{name}:{tag}#{dg[:15]}",
                                   text=text, published_at=None,
                                   meta={"image": f"{name}:{tag}"})
            except Exception as e:
                print(f"[dockerhub] {name}: {e}")
                continue


# ---------------------------------------------------------------- 搜索引擎站点矩阵


SITE_TARGETS = [
    # 知识共享/社区（站内内容常含配置粘贴）
    ("csdn.net", "CSDN"), ("zhihu.com", "知乎"), ("cnblogs.com", "博客园"),
    ("juejin.cn", "掘金"), ("jianshu.com", "简书"), ("51cto.com", "51CTO"),
    ("oschina.net", "开源中国"), ("segmentfault.com", "思否 SegmentFault"),
    ("infoq.cn", "InfoQ 中国"), ("v2ex.com", "V2EX"), ("weibo.com", "微博"),
    # 问答站（Stack Exchange 家族：提问/回答里粘贴配置泄露高发）
    ("stackoverflow.com", "Stack Overflow"), ("superuser.com", "Super User"),
    ("serverfault.com", "Server Fault"), ("askubuntu.com", "Ask Ubuntu"),
    # Paste/临时粘贴站（泄露高发区）
    ("pastebin.com", "Pastebin"), ("dpaste.com", "dpaste"), ("controlc.com", "ControlC"),
    ("paste.ee", "paste.ee"), ("rentry.co", "Rentry"), ("justpaste.it", "JustPaste"),
    ("telegra.ph", "Telegraph"),
    # Wiki 站群
    ("fandom.com", "Fandom Wiki"), ("wikidot.com", "Wikidot"),
]


@register_channel
class SearxMatrixChannel(Channel):
    """SearxNG 元搜索 × 站点矩阵：一份查询词广播到 N 个公开渠道，pastebin 命中自动追 raw 全文。"""
    id = "searx_matrix"; title = f"搜索引擎矩阵（{len(SITE_TARGETS)} 个公开站点渠道）"; kind = "matrix"

    def iter_items(self, query: str = "", sites: Optional[List[str]] = None,
                   per_site: int = 5, **kw) -> Iterator[Item]:
        if not query:
            return
        base = os.environ.get("SEARX_URL", "http://127.0.0.1:8888").rstrip("/")
        targets = [(s, label) for s, label in SITE_TARGETS
                   if sites is None or s in sites or label in sites]
        for site, label in targets:
            q = f"{query} site:{site}"
            try:
                data = http_json(f"{base}/search?q={urllib.parse.quote(q)}&format=json")
            except Exception as e:
                print(f"[searx:{site}] {type(e).__name__}: {str(e)[:100]}")
                continue
            for res in data.get("results", [])[:per_site]:
                url = res.get("url", "")
                text = (res.get("title", "") + "\n" + res.get("content", ""))
                m = re.match(r"https?://pastebin\.com/(?!raw/)([A-Za-z0-9]{6,12})$", url)
                if m:  # 追取 pastebin 原文
                    try:
                        text = http_get(f"https://pastebin.com/raw/{m.group(1)}",
                                        max_bytes=MAX_FILE).decode("utf-8", "ignore")
                    except Exception:
                        pass
                yield Item(channel=f"searx:{site}", uri=url, text=text,
                           published_at=res.get("publishedDate"), meta={"site_label": label})


# ---------------------------------------------------------------- HuggingFace / Sourcegraph / 新包流（2026-10-11 W1 批次）
# 全部入口 2026-10-10/11 实测验证（见 docs/优化方案-冲刺10.11-10.21.md W1 表）。


def _strip_html(html: str) -> str:
    """HTML 粗剥离：去 script/style 后按标签断行（知识平台正文抓取用）。"""
    txt = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", html)
    txt = re.sub(r"(?s)<!--.*?-->", " ", txt)
    txt = re.sub(r"<[^>]+>", "\n", txt)
    return re.sub(r"\n{2,}", "\n", txt)


def _unix_to_iso(v) -> Optional[str]:
    try:
        n = int(v)
        if n > 10 ** 12:          # 毫秒
            n //= 1000
        if n > 10 ** 9:
            from datetime import datetime
            return datetime.fromtimestamp(n, tz=timezone.utc).isoformat(timespec="seconds")
    except (TypeError, ValueError):
        pass
    return None


@register_channel
class HuggingFeedChannel(Channel):
    """HuggingFace 公开 Spaces/Datasets 新增流（sort=createdAt 事件型轮询，分钟级可见；
    匿名 500req/5min/IP，2026-10-10 实测）。内容取仓库 README + 小文本代码/配置文件。"""
    id = "hf_feed"; title = "HuggingFace 公开 Spaces/Datasets 新增流"; kind = "network"

    def iter_items(self, kinds=("spaces", "datasets"), per_kind: int = 4,
                   files_per_repo: int = 3, max_items: int = 8,
                   budget_sec: int = 180, **kw) -> Iterator[Item]:
        deadline = time.monotonic() + budget_sec
        n = 0
        for kind in kinds:
            if n >= max_items or time.monotonic() > deadline:
                return
            try:
                lst = http_json(
                    f"https://huggingface.co/api/{kind}?sort=createdAt&direction=-1&limit={per_kind}")
            except Exception as e:
                print(f"[hf_feed] {kind} failed: {e}")
                continue
            for r in lst:
                if n >= max_items or time.monotonic() > deadline:
                    return
                repo = r.get("id")
                if not repo:
                    continue
                texts: List[str] = []
                # 1) README（repo card）
                for path in ["README.md"]:
                    try:
                        raw = http_get(
                            f"https://huggingface.co/{kind}/{repo}/resolve/main/{urllib.parse.quote(path)}",
                            max_bytes=MAX_FILE).decode("utf-8", "ignore")
                        texts.append(f"# ==== {path} ====\n{raw}")
                    except Exception:
                        pass
                # 2) tree 顶层小文本文件
                try:
                    tree = json.loads(http_get(
                        f"https://huggingface.co/api/{kind}/{repo}/tree/main",
                        max_bytes=512 * 1024).decode("utf-8", "ignore"))
                    taken = 0
                    for ent in tree:
                        if taken >= files_per_repo or time.monotonic() > deadline:
                            break
                        path = ent.get("path", "")
                        if ent.get("type") != "file" or Path(path).suffix.lower() not in TEXT_SUFFIX \
                                or (ent.get("size") or 0) > MAX_FILE:
                            continue
                        try:
                            raw = http_get(
                                f"https://huggingface.co/{kind}/{repo}/resolve/main/{urllib.parse.quote(path)}",
                                max_bytes=MAX_FILE).decode("utf-8", "ignore")
                            texts.append(f"# ==== {path} ====\n{raw}")
                            taken += 1
                        except Exception:
                            continue
                except Exception:
                    pass
                if texts:
                    n += 1
                    yield Item(channel=self.id,
                               uri=f"https://huggingface.co/{kind}/{repo}",
                               text="\n".join(texts)[:MAX_ITEM_TEXT],
                               published_at=to_iso(r.get("createdAt")),
                               meta={"kind": kind, "repo": repo})


@register_channel
class SourcegraphChannel(Channel):
    """Sourcegraph 公开流式代码搜索（/.api/search/stream 匿名 200，2026-10-10 实测）：
    全球公开仓库内容级命中，无 GitHub 搜索 10q/min 配额；自限速礼貌节流。"""
    id = "sourcegraph_search"; title = "Sourcegraph 全球代码流式搜索"; kind = "network"

    def iter_items(self, query: str = "", max_items: int = 12, budget_sec: int = 150,
                   pause_sec: float = 6.0, **kw) -> Iterator[Item]:
        # 查询词用检测器级正则（patternType=regexp URL 参数生效，内联不生效——2026-10-11 实测）
        queries = [query] if query else [
            "LTAI[A-Za-z0-9]{12,24}", "AKID[A-Za-z0-9]{32}", "AKIA[A-Z0-9]{16}",
            "bce-v3/ALTAK-[A-Za-z0-9]{8,}", "sk-ant-[A-Za-z0-9_-]{20,}",
        ]
        deadline = time.monotonic() + budget_sec
        n = 0
        for q in queries:
            if n >= max_items or time.monotonic() > deadline:
                return
            url = ("https://sourcegraph.com/.api/search/stream?v=V3&patternType=regexp&display=2&q="
                   + urllib.parse.quote(f"context:global {q} count:20"))
            try:
                # WAF 按 UA+TLS 指纹拦 urllib 默认 UA（2026-10-11 实测），Mozilla 风格 UA 放行
                raw = http_get(url, timeout=30, max_bytes=4 * 1024 * 1024,
                               headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) credscan/1.0"}
                               ).decode("utf-8", "ignore")
            except Exception as e:
                print(f"[sourcegraph] {q!r} failed: {e}")
                continue
            for repo, path, lines in self._parse_matches(raw):
                if n >= max_items:
                    return
                n += 1
                yield Item(channel=self.id,
                           uri=f"https://sourcegraph.com/{repo}/-/blob/{path}",
                           text="\n".join(lines), published_at=None,
                           meta={"repo": repo, "path": path, "query": q})
            if n < max_items:
                time.sleep(pause_sec)          # 自限速（无公布频控）

    @staticmethod
    def _parse_matches(raw: str):
        """极简 SSE 解析：event: matches 的 data JSON（对象或数组皆容忍）。"""
        lines_out = []
        block_event = None
        for line in raw.split("\n"):
            if line.startswith("event: "):
                block_event = line[7:].strip()
                lines_out = []
            elif line.startswith("data: ") and block_event == "matches":
                try:
                    obj = json.loads(line[6:])
                except Exception:
                    continue
                for m in (obj if isinstance(obj, list) else [obj]):
                    repo = (m.get("repository") or m.get("repo") or "").strip("/")
                    path = m.get("path") or ""
                    if not repo or not path:
                        continue
                    plines = [(lm.get("line") or lm.get("preview") or "")
                              for lm in (m.get("lineMatches") or [])]
                    if not plines:            # chunkMatches 兜底
                        for cm in (m.get("chunkMatches") or []):
                            plines += [(lm.get("line") or lm.get("preview") or "")
                                       for lm in (cm.get("lineMatches") or [])]
                    if plines:
                        yield repo, path, plines[:20]


@register_channel
class NuGetCatalogChannel(Channel):
    """NuGet catalog0：官方 append-only 事件流（index→page→leaf），commitTs 秒级；
    取最新页新增包，下载 .nupkg（zip）抽文本扫描。"""
    id = "nuget_catalog"; title = "NuGet catalog0 事件流"; kind = "network"

    def iter_items(self, leaves: int = 6, max_pkg_bytes: int = 3 * 1024 * 1024,
                   max_items: int = 6, budget_sec: int = 200, **kw) -> Iterator[Item]:
        deadline = time.monotonic() + budget_sec
        try:
            index = http_json("https://api.nuget.org/v3/catalog0/index.json")
            pages = index.get("items", [])[-2:]
        except Exception as e:
            print(f"[nuget_catalog] index failed: {e}")
            return
        got = 0
        for page in pages:
            if got >= max_items or time.monotonic() > deadline:
                return
            try:
                page_items = page.get("items") or http_json(page["@id"]).get("items", [])
            except Exception:
                continue
            for leaf in reversed(page_items[-40:]):        # 新包在后
                if got >= max_items or time.monotonic() > deadline:
                    return
                ce = leaf.get("catalogEntry") or {}
                if ce.get("listed") is False or leaf.get("type") == "nuget:PackageDelete":
                    continue
                try:
                    detail = http_json(leaf["@id"])          # leaf 详情（无 packageContent）
                except Exception:
                    detail = ce
                pid = (detail.get("id") or leaf.get("nuget:id") or "").lower()
                pver = (detail.get("verbatimVersion") or detail.get("version")
                        or leaf.get("nuget:version") or "").lower()
                if not pid or not pver:
                    continue
                if (detail.get("packageSize") or 0) > max_pkg_bytes:   # 大包不拉
                    continue
                content = f"https://api.nuget.org/v3-flatcontainer/{pid}/{pver}/{pid}.{pver}.nupkg"
                try:
                    blob = http_get(content, max_bytes=max_pkg_bytes)
                except Exception:
                    continue
                text = _slurp_archive_text(blob, "pkg.nupkg")
                if not text:
                    continue
                got += 1
                pkg = f"{detail.get('id') or leaf.get('nuget:id')}@{detail.get('version') or leaf.get('nuget:version')}"
                yield Item(channel=self.id,
                           uri=str(detail.get("packageContent") or leaf["@id"]),
                           text=text, published_at=to_iso(leaf.get("commitTimeStamp")),
                           meta={"package": pkg})


@register_channel
class RubyGemsActivityChannel(Channel):
    """RubyGems activity 流（官方 10req/s；.gem = tar.gz 内嵌 data.tar.gz，双层解包）。"""
    id = "rubygems_activity"; title = "RubyGems 最新发布流"; kind = "network"

    def iter_items(self, feed: str = "latest", max_items: int = 6,
                   max_gem_bytes: int = 3 * 1024 * 1024, budget_sec: int = 160, **kw) -> Iterator[Item]:
        deadline = time.monotonic() + budget_sec
        try:
            gems = http_json(f"https://rubygems.org/api/v1/activity/{feed}.json") or []
        except Exception as e:
            print(f"[rubygems] activity failed: {e}")
            return
        got = 0
        for g in gems[:30]:
            if got >= max_items or time.monotonic() > deadline:
                return
            name = g.get("name")
            if not name:
                continue
            try:
                det = http_json(f"https://rubygems.org/api/v1/gems/{urllib.parse.quote(name)}.json")
            except Exception:
                continue
            uri = det.get("gem_uri")
            if not uri:
                continue
            try:
                blob = http_get(uri, max_bytes=max_gem_bytes)
                text = self._gem_text(blob)
            except Exception:
                continue
            if not text:
                continue
            got += 1
            yield Item(channel=self.id, uri=uri, text=text,
                       published_at=to_iso(g.get("version_created_at") or det.get("created_at")),
                       meta={"gem": f"{name}@{g.get('version')}"})

    @staticmethod
    def _gem_text(blob: bytes) -> str:
        """解开 .gem（tar.gz）内嵌的 data.tar.gz 再抽文本。"""
        out: List[str] = []
        try:
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as outer:
                member = next((m for m in outer.getmembers()
                               if m.name.endswith("data.tar.gz")), None)
                if member is None:
                    return ""
                with tarfile.open(fileobj=io.BytesIO(outer.extractfile(member).read()),
                                  mode="r:*") as inner:
                    taken = 0
                    for m in inner.getmembers():
                        if taken >= 40:
                            break
                        if m.isfile() and Path(m.name).suffix.lower() in TEXT_SUFFIX and m.size <= MAX_FILE:
                            out.append(f"# ==== {m.name} ====\n"
                                       + inner.extractfile(m).read().decode("utf-8", "ignore"))
                            taken += 1
        except Exception:
            return ""
        return "\n".join(out)[:MAX_ITEM_TEXT]


@register_channel
class JuejinSearchChannel(Channel):
    """掘金社区搜索（匿名 JSON，2026-10-11 实测；search → article detail 正文）。"""
    id = "juejin_search"; title = "掘金社区搜索（标题+摘要级）"; kind = "network"

    def iter_items(self, query: str = "", limit: int = 10, max_items: int = 8,
                   budget_sec: int = 90, **kw) -> Iterator[Item]:
        """正文 detail 接口带反爬指纹参数（2026-10-11 实测 err_no=2），不硬刚：
        搜索响应自带 article_info（title/brief_content），摘要级扫描。"""
        if not query:
            return
        try:
            data = http_json("https://api.juejin.cn/search_api/v1/search?query="
                             + urllib.parse.quote(query) + f"&id_type=0&cursor=0&limit={limit}")
        except Exception as e:
            print(f"[juejin] search failed: {e}")
            return
        rows = data.get("data") if isinstance(data.get("data"), list) else []
        got = 0
        for row in rows:
            if got >= max_items:
                return
            rm = row.get("result_model") or {}
            info = rm.get("article_info") or {}
            aid = info.get("article_id") or rm.get("article_id")
            text = "\n".join(x for x in (info.get("title"), row.get("title_highlight"),
                                         info.get("brief_content")) if x)
            if not aid or len(text) < 30:
                continue
            got += 1
            yield Item(channel=self.id,
                       uri=f"https://juejin.cn/post/{aid}",
                       text=text[:MAX_ITEM_TEXT],
                       published_at=_unix_to_iso(info.get("ctime")),
                       meta={"article_id": aid})



@register_channel
class CSDNSearchChannel(Channel):
    """CSDN 博客搜索（so.csdn.net/api/v1 匿名 JSON，2026-10-11 实测；
    正文页 HTML 粗剥离，带 UA + 低频防封）。"""
    id = "csdn_search"; title = "CSDN 博客搜索"; kind = "network"

    def iter_items(self, query: str = "", max_items: int = 4, budget_sec: int = 120,
                   pause_sec: float = 3.0, **kw) -> Iterator[Item]:
        if not query:
            return
        deadline = time.monotonic() + budget_sec
        try:
            data = http_json("https://so.csdn.net/api/v1/search?q="
                             + urllib.parse.quote(query) + "&t=blog&p=1")
        except Exception as e:
            print(f"[csdn] search failed: {e}")
            return
        got = 0
        for vo in (data.get("result_vos") or [])[:10]:
            if got >= max_items or time.monotonic() > deadline:
                return
            url = vo.get("url_location") or vo.get("url") or ""
            if not url.startswith("http"):
                continue
            try:
                html = http_get(url, max_bytes=2 * 1024 * 1024).decode("utf-8", "ignore")
            except Exception:
                continue
            text = _strip_html(html)
            if len(text) < 200:
                continue
            got += 1
            yield Item(channel=self.id, uri=url,
                       text=text[:MAX_ITEM_TEXT],
                       published_at=_unix_to_iso(vo.get("created_at")),
                       meta={"title": vo.get("title", "")[:80]})
            time.sleep(pause_sec)             # 低频防封
