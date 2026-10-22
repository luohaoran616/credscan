#!/usr/bin/env python3
"""校验《技术说明书》正文中全部 `文件.py:NN` 锚点与源码实际行的一致性。

用法（在 credscan/ 目录执行）：
    python3 tools/check_anchors.py [--manual ../docs/技术说明书-从零重写版.md]

三层检查：
1. 存在性：锚点文件存在、行号不越界、不指向空行。
2. 定义行断言：锚点所在 markdown 行含反引号符号（`Symbol` 或 `Class.method`）时，
   若锚点行不是该符号的 def/class 定义行、但其 ±2 行内恰有定义行，
   则报告"装饰器/注释行错位"（锚点应指向定义行本身）。
3. 引用完整性：正文所有 §X.Y / 表 X-Y / 图 X-Y 引用必须存在对应标题/表题/图题。

另输出"符号近邻零命中"可疑清单（表格行已降噪），仅需人工判断、不改变退出码。
退出码：存在性违例、定义行错位或引用缺失 >0 时返回 2；仅可疑项时返回 0。
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PKG = HERE.parent / "credscan"
TOOLS = HERE.parent / "tools"
TESTS = HERE.parent / "tests"

STOP = {
    "python", "文件", "行号", "实现", "定义", "输出", "输入", "配置",
    "default", "return", "class", "self", "import", "def", "true", "false",
    "none", "with", "from", "time", "json", "text", "code", "说明", "其中",
    "测试", "锁定", "入口", "校验", "执行", "现场", "命令", "读取", "写入",
    "调用", "产生", "使用", "用于", "详见", "对应", "实际", "该行", "锚点",
}

# 锚点形态：文件名.py:数字；连写多锚点（.py:86、:276、:292）逐段处理
ANCHOR_RE = re.compile(r"([A-Za-z_][\w]*\.py):(\d+)")
DEF_RE = re.compile(r"^\s*(?:async\s+)?(?:def|class)\s+([A-Za-z_]\w*)")
# 反引号内符号：`Symbol` / `Class.method` / `mod.func`（取末段作为定义名候选）
SYM_RE = re.compile(r"`([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)`")

# 人工核验白名单：符号近邻零命中但经 2026-10-15 人工复核确认为合理锚点
# （区间/机制内部行或类定义行，上下文窗口无重叠 token 属预期）。
# 键为 (文件, 行号)；源码行号漂移后条目自动失效、可疑重现，提醒重新核验。
KNOWN_OK = {
    ("core.py", 259): "闸④ 仅对 weak 生效的分支行（§3.2 三条纪律）",
    ("test_core.py", 251): "TestPlaceholderClass 类定义行（§3.2 证据）",
    ("channels.py", 30): "统一 UA 常量（§2.5 退避机制）",
    ("daemon.py", 112): "单渠道 try/except 隔离起始行（§2.5）",
    ("test_core.py", 81): "test_example_secrets_whitelisted 定义行（表 8-2 TC-03）",
    ("detectors.py", 551): "GenericHighEntropySecret 类定义行（表 3-4 闸③）",
    ("channels.py", 93): "包内标记行写入（§3.5）",
    ("test_tools.py", 81): "TestHoneyGen 类定义行（§3.10）",
    ("channels.py", 84): "解包 try/except 起始行（§4.2 防御细节）",
    ("daemon.py", 75): "Daemon.due 定义行（§4.4 三条件）",
    ("daemon.py", 91): "判新旧 if self.store.save(f)（§5.7）",
    ("response.py", 276): "Registry.get 拦截行（表 3-6 红线②）",
    ("test_core.py", 230): "TestRuleOverlap 类定义行（§3.1/表 4-3）",
    ("cli.py", 100): "scan 摘要 JSON 输出行（§13 第三条命令）",
    ("honeygen.py", 10): "overall 四维加权注释行（§3.10 评分公式）",
    ("test_core.py", 70): "test_snippet_masks_sibling_secret_on_same_line 定义行（§5.6 红线③同行扩展）",
}


def parse_anchors(text: str) -> list[tuple[str, int, int]]:
    """返回 (file, line, char_pos) 列表。"""
    out = []
    for m in ANCHOR_RE.finditer(text):
        out.append((m.group(1), int(m.group(2)), m.start()))
    return out


def resolve(path: str) -> Path | None:
    for root in (PKG, TOOLS, TESTS):
        p = root / path
        if p.exists():
            return p
    # 直接相对 cwd
    p = Path(path)
    if p.exists():
        return p
    return None


def src_line(path: Path, n: int) -> str | None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return "<unreadable>"
    if n > len(lines):
        return None
    return lines[n - 1]


def def_positions(path: Path) -> dict[str, int]:
    """文件内全部 def/class 定义名 → 行号。"""
    out = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return out
    for i, line in enumerate(lines, 1):
        m = DEF_RE.match(line)
        if m:
            out.setdefault(m.group(1), i)
    return out


def check_list(list_path: str) -> int:
    r"""清单模式：核对《代码功能清单》行号列与内联 L 行号。

    规则：小节标题（## N. file.py）确定文件；表格行号列与内联 L(\d+) 全部核对；
    符号有 def/class 定义时断言行号=定义行，无定义（常量/表）时只验存在性。
    """
    text = Path(list_path).read_text(encoding="utf-8")
    # 内联行号只认括号形态（L258）/（L220/L235）；排除 L1-7、L158-160 docstring 等区间
    inline_re = re.compile(r"[（(](?:(\w+\.py)\s*)?L(\d+)(?:/L(\d+))*[)）]")
    # 一遍收集：(file, lineno, sym) 三元组；无符号的行号 sym 为空串
    items: list[tuple[str, int, str]] = []
    cur_file = ""
    for line in text.splitlines():
        m = re.match(r"^## \d+\. (\w+\.py)", line)
        if m:
            cur_file = m.group(1)
            continue
        if not cur_file:
            continue
        inline = []
        for im in inline_re.finditer(line):
            fname = im.group(1) or cur_file
            inline.append((fname, int(im.group(2)), ""))
        pairs = []
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) >= 2:
                syms = [sm.group(1).split(".")[-1] for sm in SYM_RE.finditer(cells[0])]
                nums = [int(x) for x in re.findall(r"\d+", cells[1]) if x.isdigit()]
                if syms and len(syms) == len(nums):
                    pairs = list(zip(nums, syms))
        items.extend(inline)
        items.extend([(cur_file, n, s) for n, s in pairs])

    violations = 0
    for fname, n, sym in items:
        p = resolve(fname)
        if p is None:
            print(f"[清单违例] {fname}:{n} —— 文件不存在")
            violations += 1
            continue
        line = src_line(p, n)
        if not line or is_blank_or_missing(line):
            print(f"[清单违例] {fname}:{n} —— 行号越界或空行")
            violations += 1
            continue
        if sym:
            real = def_positions(p).get(sym)
            if real is not None and real != n:
                print(f"[清单错位] {fname}:{n} 不是 `{sym}` 定义行，定义在 :{real}")
                violations += 1
    print(f"清单行号：核对 {len(items)} 处，违例 {violations}")
    return violations


def is_blank_or_missing(line: str) -> bool:
    return not line.strip()


def tokens(snippet: str) -> set[str]:
    toks = set()
    for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", snippet):
        if t.lower() not in STOP:
            toks.add(t)
    return toks


def check_panel_routes(manual: str) -> int:
    r"""第 5 层：说明书表 4-4 面板路由行号 vs panel.py 实际路由行号。

    表 4-4 的行号列是纯数字（非 file.py:NN 锚点形态），锚点层不覆盖，
    单独核对防止 panel.py 改动后漂移。
    """
    m = re.search(r"\*\*表 4-4[^\n]*\*\*\n\n((?:\|.*\n)+)", manual)
    if not m:
        # 表题被改写后按表头特征定位：panel 端点表（方法列 GET/POST + /api/ 路径）
        cand = re.search(r"((?:\|\s*(?:GET|POST)\s*\|[^\n]*\n){2,})", manual)
        m = cand if cand else m
    if not m:
        print("面板端点表未找到，跳过面板路由核对")
        return 0
    rows = {}
    for line in m.group(1).splitlines():
        cells = [c.strip().strip("`") for c in line.strip("|").split("|")]
        # 兼容两种列序：| 路径 | 行号 | 与 | 方法 | 路径 | 行号 |
        if len(cells) >= 2 and cells[0].startswith("/"):
            n = re.match(r"^:??(\d+)$", cells[1])
            if n:
                rows[cells[0]] = int(n.group(1))
        elif len(cells) >= 3 and cells[0] in ("GET", "POST") and cells[1].startswith("/"):
            n = re.match(r"^:??(\d+)$", cells[2])
            if n:
                key = ("POST " + cells[1]) if cells[0] == "POST" else cells[1]
                rows[key] = int(n.group(1))
    panel = resolve("panel.py")
    if panel is None:
        return 0
    src = panel.read_text(encoding="utf-8").splitlines()
    real = {}
    for i, line in enumerate(src, 1):
        s = line.strip()
        m2 = re.match(r'elif u == "(/[^"]+)":', s)
        if m2:
            real[m2.group(1)] = i
        elif re.match(r'if u == "/":', s):
            real["/"] = i
    # POST /api/review 行号：单独找（上面 elif 不适用）
    for i, line in enumerate(src, 1):
        if 'path != "/api/review"' in line:
            real["POST /api/review"] = i
    viol = 0
    for route, want in rows.items():
        got = real.get(route)
        if got != want:
            print(f"[路由错位] 表 4-4 {route} 写 :{want}，panel.py 实际 :{got}")
            viol += 1
    print(f"面板路由：核对 {len(rows)} 个端点，违例 {viol}")
    return viol


def check_module_lines(manual: str) -> int:
    r"""第 6 层：说明书表 2-1 模块行数列 + §4.x 标题「（N 行）」vs 源码 wc -l 实测。

    表 2-1 的行数列与 §4.1–§4.8 节标题的行数标注都是纯数字（锚点层不覆盖），
    随模块增删漂移，此处两处一起对 8 个业务模块做行数比对。
    """
    m = re.search(r"\*\*表 2-1[^\n]*\*\*\n\n((?:\|.*\n)+)", manual)
    if not m:
        # 表题被改写后按表头特征定位：模块行数表（| 模块 | 行数 | …）
        cand = re.search(r"(\| 模块 \| 行数 \|[^\n]*\n(?:\|.*\n)+)", manual)
        m = cand if cand else m
    if not m:
        print("模块行数表未找到，跳过模块行数核对")
        return 0
    rows = {}
    for line in m.group(1).splitlines():
        cells = [c.strip().strip("`") for c in line.strip("|").split("|")]
        mm = re.match(r"^(\w+)(?:\.py)?$", cells[0]) if cells else None
        if mm and len(cells) >= 2 and not cells[0].startswith("-"):
            n = re.match(r"^(\d+)$", cells[1])
            if n:
                rows[mm.group(1) + ".py"] = int(n.group(1))
    # §4.x 标题：### 4.x `file.py`（N 行）——与表 2-1 同文件时不一致即违例
    viol = 0
    for hm in re.finditer(r"^### 4\.\d+ `(\w+\.py)`（(\d+) 行）", manual, re.M):
        fname, n = hm.group(1), int(hm.group(2))
        if fname in rows and rows[fname] != n:
            print(f"[行数错位] §4.x 标题 {fname} 写 {n} 行，表 2-1 写 {rows[fname]}")
            viol += 1
        else:
            rows.setdefault(fname, n)
    for fname, want in rows.items():
        p = resolve(fname)
        if p is None:
            print(f"[行数违例] 表 2-1 {fname} —— 文件不存在")
            viol += 1
            continue
        with p.open(encoding="utf-8") as fh: got = sum(1 for _ in fh)
        if got != want:
            print(f"[行数错位] {fname} 写 {want} 行，wc -l 实测 {got}")
            viol += 1
    print(f"模块行数：核对 {len(rows)} 个文件，违例 {viol}")
    return viol


def check_line_totals(manual: str) -> int:
    r"""第 7 层：说明书行数口径合计 vs 源码/工具目录 wc -l 实测。

    正文「全部源码合计 3,744 行」（§2.2）= credscan/credscan/ 包全量（含入口）
    + tools/ 目录（**不含 check_anchors.py 自身**——文档校验工具不入口径，
    避免"改校验器必改说明书"的自指循环）。
    """
    viol = 0
    src_root = HERE.parent / "credscan"  # credscan/credscan/ 包源码（含入口）
    tools_root = HERE  # credscan/tools/
    total_want = re.search(r"全部源码合计\s*([\d,]+)\s*行", manual)
    if total_want:
        want = int(total_want.group(1).replace(",", ""))
        got = (
            sum(sum(1 for _ in p.open(encoding="utf-8")) for p in src_root.glob("*.py"))
            + sum(sum(1 for _ in p.open(encoding="utf-8")) for p in tools_root.glob("*.py")
                  if p.name != "check_anchors.py")
        )
        if got != want:
            print(f"[行数错位] 正文写全部源码合计 {want} 行，credscan/+tools/ 实测 {got}")
            viol += 1
    # §2.2 工具逐个行数（`report_numbers.py` 136 形态）——逐文件核对
    for tm in re.finditer(r"`(\w+\.py)`\s*(\d+)", manual.split("**锚点校验工具**")[0]):
        fname, want = tm.group(1), int(tm.group(2))
        p = tools_root / fname
        if fname == "check_anchors.py" or not p.exists():
            continue
        with p.open(encoding="utf-8") as fh: got = sum(1 for _ in fh)
        if got != want:
            print(f"[行数错位] §2.2 工具 {fname} 写 {want} 行，wc -l 实测 {got}")
            viol += 1
    print(f"行数口径：核对合计+工具逐个，违例 {viol}")
    return viol


def check_counts(manual: str, label: str = "说明书") -> int:
    r"""第 8 层：核心实数（检测器/族/适配器/口径/站点）vs 源码注册表实测。

    从源码 import 注册表取真值（56 检测器 / 12 族 / 15 适配器 / 38 口径 /
    24 站点矩阵），与正文「数字即真相」表述比对，防止核心实数漂移。
    """
    viol = 0
    try:
        import sys as _sys
        src_root = HERE.parent  # credscan/
        if str(src_root) not in _sys.path:
            _sys.path.insert(0, str(src_root))
        from credscan import core, channels
        n_det = len(core.DETECTORS)
        n_fam = len({getattr(d, "family", d.id) for d in core.DETECTORS.values()})
        n_ch = len(core.CHANNELS)
        n_site = len(channels.SITE_TARGETS)
        n_scope = n_ch + n_site - 1  # searx_matrix 适配器由矩阵展开，不计为独立口径
    except Exception as e:  # noqa: BLE001 —— 运行时环境缺依赖时跳过本层
        print(f"实数核对跳过（import 失败：{e}）")
        return 0
    checks = [
        (r"(\d+)\s*个?检测器", 1, n_det, "检测器"),
        (r"(\d+)\s*个凭据族|(\d+)\s*凭据族|(\d+)\s*族", 3, n_fam, "凭据族"),
        (r"(\d+)\s*个适配器|(\d+)\s*类适配器", 2, n_ch, "适配器"),
        (r"(\d+)\s*个监测口径|(\d+)\s*个口径|(\d+)\s*口径|(\d+)\s*类可扫内容源", 4, n_scope, "口径"),
        (r"(\d+)\s*条?站点(?:搜索)?矩阵", 1, n_site, "站点矩阵"),
    ]
    for pat, ngrp, real, lbl in checks:
        mm = re.search(pat, manual)
        val = next((mm.group(i) for i in range(1, ngrp + 1) if mm.group(i)), None) if mm else None
        if mm and int(val or "0") != real:
            print(f"[实数错位] {label} {mm.group(0)[:24]} 写 {val}，源码实测 {real}")
            viol += 1
    print(f"核心实数（{label}）：检测器 {n_det}/族 {n_fam}/适配器 {n_ch}/口径 {n_scope}/站点 {n_site}，违例 {viol}")
    return viol


def check_style(manual: str, label: str = "") -> int:
    """第 9 层：文体门禁（MS Style Guide 斜杠禁令 / 段落成文）。"""
    tag = f"[{label}] " if label else ""
    body = re.sub(r"```.*?```", lambda m: re.sub(r"[^\n]", " ", m.group(0)),
                  manual, flags=re.S)
    body = re.sub(r"`[^`\n]*`", lambda m: " " * len(m.group(0)), body)
    body = re.sub(r"^\|.*$", lambda m: " " * len(m.group(0)), body, flags=re.M)

    viol = 0
    for m in re.finditer(r"(?:[^\s。；：、，）（\"'/]{1,20}/){2,}[^\s。；：、，）（\"']{1,20}", body):
        segs = m.group(0).split("/")
        if any(("." in s or ":" in s or "~" in s or "\\" in s) for s in segs):
            continue  # 路径 / URL / 行号列表豁免
        if any((not s or s.isdigit() or s in {"OL", "J", "M", "D", "C"})
               for s in segs):
            continue  # 空段 / 纯数字列举 / GB/T 7714 文献类型标识豁免
        line_no = manual[:m.start()].count("\n") + 1
        print(f"  [斜杠链] {tag}L{line_no}  {m.group(0)[:60]}")
        viol += 1
    for m in re.finditer(r"[a-z_]{2,}(?:\|[a-z_]{2,}){2,}", body):
        line_no = manual[:m.start()].count("\n") + 1
        print(f"  [竖线枚举] {tag}L{line_no}  {m.group(0)[:60]}")
        viol += 1

    # 第 9 层b：词面门禁（元话语、称谓、口语词）
    LEXICON = [
        "评委", "本文将", "下面精讲", "逐条对翻", "拍脑袋", "勿混",
        "如实写明", "温区", "演示常用", "我们将", "读者可以",
        "每条按四个部分撰写", "每条记录分四段展开", "先摆问题", "供审计使用",
        "干系人",
    ]
    for w in LEXICON:
        for m in re.finditer(re.escape(w), body):
            ln = manual[:m.start()].count("\n") + 1
            print(f"  [词面] {tag}L{ln}  {w}")
            viol += 1

    paras = [p for p in body.split("\n") if len(p.strip()) > 20
             and not p.lstrip().startswith(("#", "-", "*", ">"))]
    single = [p for p in paras
              if len(re.findall(r"[。！？]", p)) <= 1]
    ratio = len(single) / len(paras) if paras else 0
    print(f"文体门禁：{tag}正文段 {len(paras)}，单句段 {len(single)}"
          f"（{ratio:.0%}，阈值 50%）")
    return viol + (1 if ratio > 0.5 else 0)


def check_figures(manual: str, base: Path) -> int:
    """第 10 层：图片引用——文件存在、图题结论句、编号唯一、正文有引用。"""
    viol = 0
    embeds = list(re.finditer(r"!\[([^\]]*)\]\(([^)]+)\)", manual))
    fig_dir = base / "docs" / "figures"
    seen_nums = {}
    for m in embeds:
        cap, rel = m.group(1).strip(), m.group(2).strip()
        ln = manual[:m.start()].count("\n") + 1
        p = base / rel if not rel.startswith("figures/") else base / "docs" / rel
        if not p.exists():
            print(f"  [图缺失] L{ln}  {rel}")
            viol += 1
            continue
        # 图题必须是结论句：≥8 字且含中文与动词性信息（以名词短语裸标题为不合格）
        if len(cap) < 8 or not re.search(r"[\u4e00-\u9fff]", cap):
            print(f"  [图题不合格] L{ln}  「{cap}」——须为含中文的结论句")
            viol += 1
        nm = re.match(r"图\s*(\d+)[-–](\d+)", cap)
        if nm:
            key = nm.group(1) + "-" + nm.group(2)
            if key in seen_nums:
                print(f"  [图号重复] L{ln}  {key}（首现 L{seen_nums[key]}）")
                viol += 1
            # 图号章号须与所在章一致：向上找最近的 ##/### 标题
            head = None
            for hm in re.finditer(r"^#{2,4}\s+(\d+)(?:[.\d　 ]|$)", manual[:m.start()], re.M):
                head = hm.group(1)
            if head and head != nm.group(1):
                print(f"  [图号章错位] L{ln}  图 {key} 出现在第 {head} 章")
                viol += 1
            seen_nums[key] = ln
        else:
            print(f"  [图号缺失] L{ln}  「{cap[:24]}」")
            viol += 1
    # 正文引用：图 N-M 至少在图片行之外被提及一次
    body_wo_paths = re.sub(r"\]\([^)]*\)", "]", manual)  # 排除链接/图片目标路径里的文件名
    for key, first_ln in seen_nums.items():
        refs = [manual[:m.start()].count("\n") + 1
                for m in re.finditer(re.escape(key), manual)]
        # 区间写法「图 A-B 至 图 C-D」视为引用了区间内每一号
        for rm in re.finditer(r"图\s*(\d+)[-–](\d+)\s*至\s*图\s*(\d+)[-–](\d+)", body_wo_paths):
            a, b = int(rm.group(2)), int(rm.group(4))
            if rm.group(1) == key.split("-")[0] and a <= b and a <= int(key.split("-")[1]) <= b:
                refs.append(-99)
        if all(abs(r - first_ln) < 2 for r in refs):
            print(f"  [图未被引用] {key}（L{first_ln}）——正文须有「如图 {key} 所示」类引用")
            viol += 1
    print(f"图引用门禁：内嵌 {len(embeds)} 张，编号 {len(seen_nums)} 个，违例 {viol}")
    return viol


def main() -> int:
    manual_path = sys.argv[1] if len(sys.argv) > 1 else (
        str(HERE.parent / "docs" / "技术说明书-从零重写版.md"))
    manual = Path(manual_path).read_text(encoding="utf-8")
    anchors = parse_anchors(manual)

    exist_viol = 0
    blank_anchors = []
    def_mismatch = []
    suspicious = []
    for fname, lineno, pos in anchors:
        path = resolve(fname)
        if path is None:
            print(f"[违例] {fname}:{lineno} —— 文件不存在")
            exist_viol += 1
            continue
        line = src_line(path, lineno)
        if line is None:
            print(f"[违例] {fname}:{lineno} —— 行号越界")
            exist_viol += 1
            continue
        if is_blank_or_missing(line):
            blank_anchors.append((fname, lineno))
            continue
        # 定义行断言：同行反引号符号的末段若不是本行定义名，
        # 但 ±2 行内恰有该定义 → 装饰器/注释行错位
        mline = manual[:pos].rsplit("\n", 1)[-1]
        in_table = mline.lstrip().startswith("|")
        for sm in SYM_RE.finditer(mline):
            sym = sm.group(1).split(".")[-1]
            if not sym[0].isalpha() or not sym[-1].isalpha():
                continue  # 跳过 file.py:NN 本身被反引号包裹的形态
            if DEF_RE.match(line) and DEF_RE.match(line).group(1) == sym:
                break
            for d in (-2, -1, 1, 2):
                sl = src_line(path, lineno + d)
                dm = DEF_RE.match(sl) if sl else None
                if dm and dm.group(1) == sym:
                    def_mismatch.append(
                        (fname, lineno, lineno + d, sym))
                    break
            else:
                continue
            break
        # 窗口 token 近邻命中（表格行除外：表格的符号列超出 ±120 窗口，
        # 符号一致性已由上一层定义行断言覆盖）
        if not in_table:
            window = manual[max(0, pos - 120): pos + 140]
            toks = tokens(window)
            hits = any(t in line for t in toks)
            if not hits:
                # 扩大检查：±2 行
                ctx = "\n".join(src_line(path, lineno + d) or "" for d in (-2, -1, 0, 1, 2))
                hits = any(t in ctx for t in toks)
            if not hits and (fname, lineno) not in KNOWN_OK:
                suspicious.append((fname, lineno, line.strip()[:80], sorted(toks)[:8]))

    print(f"锚点总数：{len(anchors)}；存在性违例：{exist_viol}；空行锚点：{len(blank_anchors)}；"
          f"定义行错位：{len(def_mismatch)}")
    for fname, lineno in blank_anchors:
        print(f"  [空行] {fname}:{lineno} —— 指向空行，若非故意（如区间起点）需补位")
    for fname, lineno, real, sym in def_mismatch:
        print(f"  [错位] {fname}:{lineno} 不是 `{sym}` 定义行，定义在 :{real}（锚点应指向定义行）")

    # 第 3 层：§X.Y / 表 X-Y / 图 X-Y 引用完整性
    heads = set(re.findall(r"^#{1,4}\s+([\d]+(?:\.[\d]+)*)", manual, re.M))
    table_titles = set(re.findall(r"\*\*表\s*([\d]+-[\d]+)", manual))
    fig_titles = (set(re.findall(r"\*\*图\s*([\d]+-[\d]+)", manual))
                  | set(re.findall(r"!\[图\s*([\d]+-[\d]+)", manual)))
    sec_refs = set(re.findall(r"§([\d]+(?:\.[\d]+)*)", manual))
    tab_refs = set(re.findall(r"表\s*([\d]+-[\d]+)", manual))
    _body_wo_paths = re.sub(r"\]\([^)]*\)", "]", manual)  # 排除链接/图片目标路径
    fig_refs = set(re.findall(r"图\s*([\d]+-[\d]+)", _body_wo_paths))
    miss_s, miss_t, miss_f = (sorted(x - y) for x, y in (
        (sec_refs, heads), (tab_refs, table_titles), (fig_refs, fig_titles)))
    print(f"引用完整性：节 {len(sec_refs)}/表 {len(tab_refs)}/图 {len(fig_refs)} 种；"
          f"缺失：节 {miss_s} 表 {miss_t} 图 {miss_f}")

    print(f"可疑锚点（符号近邻零命中，需人工确认）：{len(suspicious)}")
    for fname, lineno, line, toks in suspicious:
        print(f"  {fname}:{lineno}  源码行：{line}")
        print(f"      窗口 token：{', '.join(toks)}")

    # 清单模式（可选第二参数）
    list_viol = 0
    if len(sys.argv) > 2:
        list_viol = check_list(sys.argv[2])
    elif (HERE.parent.parent / "docs" / "说明书-代码功能清单.md").exists():
        list_viol = check_list(str(HERE.parent.parent / "docs" / "说明书-代码功能清单.md"))

    # 第 5 层：面板路由表核对
    route_viol = check_panel_routes(manual)

    # 第 6 层：模块行数表核对
    lines_viol = check_module_lines(manual)

    # 第 7 层：行数口径合计核对
    totals_viol = check_line_totals(manual)

    # 第 8 层：核心实数核对（说明书 + 作品报告 + 答辩追问库 + DEMO 脚本，四个对外交付件）
    counts_viol = check_counts(manual)
    for extra in ("docs/作品报告-从零重写版.md", "docs/答辩-代码解剖与追问库.md",
                  "docs/DEMO视频脚本.md"):
        ep = HERE.parent.parent / extra
        if ep.exists():
            counts_viol += check_counts(ep.read_text(encoding="utf-8"), label=ep.stem)

    # 第 9 层：文体门禁（斜杠链、竖线枚举、单句段占比）
    style_viol = check_style(manual)
    for extra in ("docs/作品报告-从零重写版.md",):
        ep = HERE.parent.parent / extra
        if ep.exists():
            style_viol += check_style(ep.read_text(encoding="utf-8"), label=ep.stem)

    # 第 10 层：图片引用（存在性、图题结论句、编号唯一、正文引用）
    fig_viol = check_figures(manual, HERE.parent.parent)

    return 2 if (exist_viol or def_mismatch or miss_s or miss_t or miss_f
                 or list_viol or route_viol or lines_viol or totals_viol
                 or counts_viol or style_viol or fig_viol) else 0


if __name__ == "__main__":
    sys.exit(main())
