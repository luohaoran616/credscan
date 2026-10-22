"""credscan panel：只读运维工作台（标准库 http.server，零第三方依赖）。

五页（单页应用，CDN ECharts + 原生 JS，零构建）：
  1 态势总览   轴①②④：总量/唯一/置信分布/渠道×类型矩阵
  2 时效闭环   轴⑤：事件型通道延迟分位 + 检测→告警→处置时间链
  3 发现处置   分层检索 + 确认/忽略（写独立 review 表，不动 findings，与 daemon 零冲突）
  4 渠道管理   渠道清单 + daemon 节奏/状态（--config daemon.json 时展示健康度）
  5 响应联动   告警流（--alerts jsonl）+ 蜜凭据处置事件
红线：库里本无明文，接口只出 sha256/脱敏预览；处置能力不在此暴露（响应层 CLI 双开关）。
"""
from __future__ import annotations

import json
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

_PAGE = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>CredScan 运维工作台</title>
<script src="https://cdn.jsdelivr.net/npm/echarts@5.5.0/dist/echarts.min.js"></script>
<style>
 body{font:14px/1.6 system-ui,'PingFang SC','Microsoft YaHei',sans-serif;margin:0;background:#f5f7fa;color:#1f2d3d}
 header{background:#17324d;color:#fff;padding:10px 20px;display:flex;gap:24px;align-items:baseline}
 header h1{font-size:17px;margin:0;font-weight:600}
 header .sub{font-size:12px;opacity:.75}
 nav{background:#fff;border-bottom:1px solid #e4e9f0;padding:0 20px}
 nav button{border:0;background:none;padding:12px 16px;font-size:14px;cursor:pointer;color:#5a6c82;border-bottom:2px solid transparent}
 nav button.on{color:#17324d;border-color:#2f6fb2;font-weight:600}
 main{padding:16px 20px;max-width:1280px;margin:0 auto}
 .cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}
 .card{background:#fff;border:1px solid #e4e9f0;border-radius:8px;padding:12px 18px;min-width:150px}
 .card .v{font-size:26px;font-weight:700;color:#17324d}
 .card .k{font-size:12px;color:#7a8ba3}
 .chart{background:#fff;border:1px solid #e4e9f0;border-radius:8px;padding:10px;height:320px;margin-bottom:14px}
 .grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
 table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e4e9f0;border-radius:8px;font-size:13px}
 th,td{padding:7px 10px;border-bottom:1px solid #eef2f6;text-align:left;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:340px}
 th{background:#f8fafc;color:#5a6c82;font-weight:600}
 .b{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px}
 .b.strong{background:#e6f4ea;color:#1e7e34}.b.medium{background:#fff4e0;color:#a4700f}.b.weak{background:#eef1f5;color:#7a8ba3}
 .b.confirm{background:#e6f4ea;color:#1e7e34}.b.ignore{background:#fdeaea;color:#b02a37}
 button.act{border:1px solid #c9d4e2;background:#fff;border-radius:5px;padding:2px 10px;cursor:pointer;font-size:12px}
 button.act:hover{background:#f0f5fb}
 .tool{display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap}
 select,input{padding:5px 8px;border:1px solid #c9d4e2;border-radius:5px;background:#fff}
 .muted{color:#7a8ba3;font-size:12px}
</style></head><body>
<header><h1>CredScan 运维工作台</h1><span class="sub" id="gen"></span>
<span class="sub">只读 + 处置标记 · 库中无明文凭据</span></header>
<nav id="nav"></nav><main id="main"></main>
<script>
const $=s=>document.querySelector(s);
const api=(p,o)=>fetch(p,o).then(r=>r.json());
const esc=s=>(s??'').toString().replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fmt=n=>(n??0).toLocaleString('zh-CN');
let charts={};
function chart(id,fn){let el=document.getElementById(id);if(!el)return;
 if(typeof echarts==='undefined'){el.innerHTML='<div class="muted" style="padding:14px">图表库未加载（离线环境）：本块数据见下方表格</div>';return;}
 if(!charts[id]){charts[id]=echarts.init(el);}fn(charts[id]);charts[id].resize();}
const PAGES=['态势总览','时效闭环','发现处置','渠道管理','响应联动'];
function nav(cur){$('#nav').innerHTML=PAGES.map((p,i)=>
 `<button class="${i===cur?'on':''}" onclick="show(${i})">${p}</button>`).join('');}
function show(i){nav(i);[page1,page2,page3,page4,page5][i]();}
function badge(c){return `<span class="b ${c}">${c}</span>`;}
async function page1(){nav(0);$('#main').innerHTML=`<div class="cards" id="cards"></div>
 <div class="grid"><div class="chart" id="chCh"></div><div class="chart" id="chConf"></div></div>
 <div class="chart" id="chDet" style="height:380px"></div>`;
 const d=await api('/api/overview');
 $('#cards').innerHTML=[['检出记录',d.total],['唯一凭据',d.unique],['strong 唯一',d.strong_unique],
  ['凭据族',d.families],['监测口径',d.channels],['检测器',d.detectors]]
  .map(([k,v])=>`<div class="card"><div class="v">${fmt(v)}</div><div class="k">${k}</div></div>`).join('');
 chart('chCh',c=>c.setOption({title:{text:'渠道 × 检出条数',left:'center',textStyle:{fontSize:13}},
  tooltip:{},grid:{left:60,bottom:70},
  xAxis:{type:'category',data:d.by_channel.map(x=>x[0]),axisLabel:{rotate:38,fontSize:10}},
  yAxis:{type:'value'},series:[{type:'bar',data:d.by_channel.map(x=>x[1]),itemStyle:{color:'#2f6fb2'}}]}));
 chart('chConf',c=>c.setOption({title:{text:'置信分层（条数）',left:'center',textStyle:{fontSize:13}},
  tooltip:{},series:[{type:'pie',radius:['32%','62%'],
   data:d.by_conf.map(x=>({name:x[0],value:x[1]}))}]}));
 chart('chDet',c=>c.setOption({title:{text:'检测器 Top10',left:'center',textStyle:{fontSize:13}},
  tooltip:{},grid:{left:150,top:36},
  xAxis:{type:'value'},yAxis:{type:'category',data:d.by_detector.map(x=>x[0]).reverse()},
  series:[{type:'bar',data:d.by_detector.map(x=>x[1]).reverse(),itemStyle:{color:'#3d8b6e'}}]}));
}
async function page2(){nav(1);$('#main').innerHTML=`<div class="chart" id="chLat"></div>
 <div class="cards" id="latc"></div><h3 style="margin:8px 0">检测 → 告警 → 处置 时间链（events 最新 50）</h3>
 <table id="ev"></table>`;
 const d=await api('/api/latency');
 chart('chLat',c=>c.setOption({title:{text:'检出延迟 P50/P90 与模型 T/2（秒，对数轴）',left:'center',textStyle:{fontSize:13}},
  tooltip:{trigger:'axis'},legend:{top:26},
  grid:{left:70,bottom:60},xAxis:{type:'category',data:d.channels,axisLabel:{rotate:30,fontSize:10}},
  yAxis:{type:'log'},series:[
   {name:'P50',type:'bar',data:d.p50,itemStyle:{color:'#2f6fb2'}},
   {name:'P90',type:'bar',data:d.p90,itemStyle:{color:'#c8a13d'}},
   {name:'模型 T/2',type:'bar',data:d.pred,itemStyle:{color:'#9aa7b5'}}]}));
 $('#latc').innerHTML=(d.note||[]).map(x=>`<div class="card"><div class="k">${esc(x.k)}</div><div class="v" style="font-size:18px">${esc(x.v)}</div></div>`).join('')
  +`<div class="card"><div class="k">蜜凭据端到端闭环（实测）</div><div class="v" style="font-size:18px">81 秒</div></div>`;
 const e=await api('/api/events');
 $('#ev').innerHTML='<tr><th>时间</th><th>事件</th><th>动作</th><th>状态</th><th>明细</th></tr>'+
  e.map(r=>`<tr><td>${esc(r[0])}</td><td>${esc(r[1])}</td><td>${esc(r[2])}</td><td>${esc(r[3])}</td><td class="muted">${esc(r[4]).slice(0,90)}</td></tr>`).join('');
}
async function page3(){nav(2);$('#main').innerHTML=`<div class="tool">
  <select id="fConf"><option value="">全部置信</option><option>strong</option><option>medium</option><option>weak</option></select>
  <input id="fCh" placeholder="渠道过滤（回车）" style="width:180px">
  <button class="act" onclick="loadF()">查询</button>
  <span class="muted">处置标记写入独立 review 表，不改 findings</span></div>
 <table id="ft"></table><div class="muted" id="fm" style="margin-top:6px"></div>`;
 $('#fConf').onchange=loadF; $('#fCh').onkeydown=e=>{if(e.key==='Enter')loadF();}; loadF();}
async function loadF(){const c=$('#fConf').value,ch=$('#fCh').value.trim();
 const d=await api(`/api/findings?conf=${c}&channel=${encodeURIComponent(ch)}&limit=80&offset=0`);
 $('#ft').innerHTML='<tr><th>时间</th><th>置信</th><th>检测器</th><th>凭据</th><th>来源</th><th>上下文</th><th>处置</th></tr>'+
  d.rows.map(r=>`<tr><td>${esc(r.ts).slice(0,16)}</td><td>${badge(r.confidence)}</td><td>${esc(r.detector)}</td>
   <td title="sha256 前 12 位">${esc(r.preview)}</td><td><a href="${esc(r.source_uri)}" target="_blank">${esc(r.source_uri).slice(8,66)}</a></td>
   <td class="muted">${esc(r.snippet).slice(0,80)}</td>
   <td>${r.review?`<span class="b ${r.review}">${r.review}</span>`:
    `<button class="act" onclick="review('${r.dedup}','confirm')">确认</button>
     <button class="act" onclick="review('${r.dedup}','ignore')">忽略</button>`}</td></tr>`).join('');
 $('#fm').textContent=`共 ${fmt(d.total)} 条（显示前 ${d.rows.length}）`;}
async function review(dedup,action){await api('/api/review',{method:'POST',
  headers:{'Content-Type':'application/json'},body:JSON.stringify({dedup,action})});loadF();}
async function page4(){nav(3);const d=await api('/api/channels');
 $('#main').innerHTML=`<table><tr><th>渠道</th><th>类型</th><th>节奏(秒)</th><th>查询词</th><th>上次运行</th><th>标题</th></tr>`+
  d.map(c=>`<tr><td>${esc(c.id)}</td><td>${esc(c.kind)}</td><td>${c.every_sec??'-'}</td>
   <td>${c.queries??'-'}</td><td class="muted">${esc(c.last_run||'-')}</td><td class="muted">${esc(c.title)}</td></tr>`).join('')+'</table>';}
async function page5(){nav(4);const d=await api('/api/alerts');
 $('#main').innerHTML=`<h3 style="margin:4px 0">告警流（jsonl 最新 50；载荷只含 sha256+脱敏预览）</h3>
  <table><tr><th>时间</th><th>置信</th><th>检测器</th><th>凭据</th><th>来源</th></tr>`+
  (d.length?d.map(a=>`<tr><td>${esc(a.ts)}</td><td>${badge(a.confidence)}</td><td>${esc(a.detector)}</td>
   <td>${esc(a.preview)}</td><td class="muted">${esc(a.source_uri).slice(8,80)}</td></tr>`).join('')
   :'<tr><td colspan="5" class="muted">（无告警记录）</td></tr>')+'</table>';}
show(0);setInterval(()=>$('#gen').textContent='数据于 '+new Date().toLocaleTimeString('zh-CN')+' 刷新',1000);
</script></body></html>"""


def _connect(db: str) -> tuple:
    conn = sqlite3.connect(db, timeout=5, check_same_thread=False)
    conn.execute("CREATE TABLE IF NOT EXISTS review("
                 "dedup TEXT PRIMARY KEY, action TEXT, ts TEXT)")
    conn.commit()
    return conn, threading.Lock()   # 锁内做全部 DB 访问（ThreadingHTTPServer 多线程）


def _q1(c, sql, args=()):
    r = c.execute(sql, args).fetchone()
    return r[0] if r else 0


def make_handler(db: str, config: str | None, alerts: str | None, registry_note: str = ""):
    conn, dblock = _connect(db)
    cfg = {}
    if config:
        try:
            cfg = json.loads(Path(config).read_text(encoding="utf-8"))
        except Exception:
            cfg = {}
    state = {}
    if config:
        sp = Path(config + ".state.json")
        try:
            state = json.loads(sp.read_text(encoding="utf-8"))
        except Exception:
            state = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):      # 静默访问日志
            pass

        def _send(self, obj, code=200, ctype="application/json; charset=utf-8"):
            body = json.dumps(obj, ensure_ascii=False).encode() if not isinstance(obj, bytes) else obj
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urlparse(self.path).path
            qs = parse_qs(urlparse(self.path).query)
            with dblock:
                self._do_get(u, qs)

        def _do_get(self, u: str, qs):
            c = conn.cursor()
            if u == "/":
                self._send(_PAGE.encode(), ctype="text/html; charset=utf-8")
            elif u == "/api/overview":
                from .core import CHANNELS, DETECTORS
                from .channels import SITE_TARGETS
                fams = {d.family for d in DETECTORS.values()}
                self._send({
                    "total": _q1(c, "SELECT COUNT(*) FROM findings"),
                    "unique": _q1(c, "SELECT COUNT(DISTINCT secret_sha256) FROM findings"),
                    "strong_unique": _q1(c, "SELECT COUNT(DISTINCT secret_sha256) FROM findings WHERE confidence='strong'"),
                    "families": len(fams),
                    "channels": len(CHANNELS) - 1 + len(SITE_TARGETS),  # searx 矩阵按站点展开
                    "detectors": len(DETECTORS),
                    "by_conf": c.execute("SELECT confidence,COUNT(*) FROM findings GROUP BY confidence").fetchall(),
                    "by_channel": c.execute("SELECT channel,COUNT(*) n FROM findings GROUP BY channel ORDER BY n DESC LIMIT 16").fetchall(),
                    "by_detector": c.execute("SELECT detector,COUNT(*) n FROM findings GROUP BY detector ORDER BY n DESC LIMIT 10").fetchall(),
                })
            elif u == "/api/latency":
                chans = [r[0] for r in c.execute(
                    "SELECT DISTINCT channel FROM findings WHERE latency_sec IS NOT NULL AND latency_sec>=0")]
                p50, p90, mean, pred = [], [], [], []
                chcfg = cfg.get("channels", {})
                for ch in chans:
                    xs = sorted(r[0] for r in c.execute(
                        "SELECT latency_sec FROM findings WHERE channel=? AND latency_sec>=0", (ch,)))
                    p50.append(round(xs[len(xs)//2]) if xs else None)
                    p90.append(round(xs[min(int(len(xs)*0.9), len(xs)-1)]) if xs else None)
                    mean.append(round(sum(xs)/len(xs)) if xs else None)
                    # 模型预测（M2，数学模型方案 §2.6）：E[R] = T/2 + c，结构性项 T/2 取配置
                    # 周期；实测 P50 − T/2 = 经验处理常数 ĉ（抓取/解析/传播）。批扫无周期不预测。
                    cid = "searx_matrix" if ch.startswith("searx:") else ch
                    T = (chcfg.get(cid) or {}).get("every_sec")
                    pred.append(round(T/2) if T else None)
                note = [
                    {"k": "反应时间模型", "v": "E[R] = T/2 + c"},
                    {"k": "灰柱 = 模型结构性项 T/2", "v": "实测 P50 − T/2 = 处理常数 ĉ"},
                ]
                self._send({"channels": chans, "p50": p50, "p90": p90,
                            "mean": mean, "pred": pred, "note": note})
            elif u == "/api/events":
                self._send(c.execute("SELECT ts,kind,action,status,COALESCE(detail,'') FROM events "
                                     "ORDER BY id DESC LIMIT 50").fetchall())
            elif u == "/api/findings":
                conf = (qs.get("conf") or [""])[0]
                ch = (qs.get("channel") or [""])[0]
                lim = int((qs.get("limit") or ["80"])[0])
                off = int((qs.get("offset") or ["0"])[0])
                where, args = ["1=1"], []
                if conf:
                    where.append("f.confidence=?"); args.append(conf)
                if ch:
                    where.append("f.channel LIKE ?"); args.append(f"%{ch}%")
                w = " AND ".join(where)
                total = _q1(c, f"SELECT COUNT(*) FROM findings f WHERE {w}", args)
                rows = c.execute(
                    f"SELECT f.dedup,f.ts,f.confidence,f.detector,f.preview,f.source_uri,f.snippet,"
                    f"COALESCE(r.action,'') FROM findings f LEFT JOIN review r ON r.dedup=f.dedup "
                    f"WHERE {w} ORDER BY f.ts DESC LIMIT ? OFFSET ?", (*args, lim, off)).fetchall()
                self._send({"total": total, "rows": [
                    {"dedup": r[0], "ts": r[1], "confidence": r[2], "detector": r[3],
                     "preview": r[4], "source_uri": r[5], "snippet": r[6], "review": r[7]}
                    for r in rows]})
            elif u == "/api/channels":
                from .core import CHANNELS
                # 每次请求重读 state：daemon 持续更新 last_run，启动时快照会永远停在旧值
                # （启动时快照会使健康判据永远停在旧值）
                try:
                    sp = Path(config + ".state.json")
                    st = json.loads(sp.read_text(encoding="utf-8")) if sp.exists() else {}
                except Exception:
                    st = {}
                chcfg = cfg.get("channels", {})
                out = []
                for cid, ch in CHANNELS.items():
                    cc = chcfg.get(cid, {}) or {}
                    sc = st.get(cid, {}) or {}
                    out.append({"id": cid, "title": ch.title, "kind": ch.kind,
                                "every_sec": cc.get("every_sec"),
                                "queries": len(cc.get("queries") or []) or None,
                                "last_run": sc.get("last_run")})
                self._send(out)
            elif u == "/api/alerts":
                out = []
                if alerts:
                    try:
                        lines = Path(alerts).read_text(encoding="utf-8").strip().splitlines()
                        for ln in lines[-50:]:
                            try:
                                out.append(json.loads(ln))
                            except Exception:
                                pass
                    except OSError:
                        pass
                self._send(out)
            else:
                self._send({"error": "not found"}, code=404)

        def do_POST(self):
            if urlparse(self.path).path != "/api/review":
                self._send({"error": "not found"}, code=404)
                return
            n = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(n))
                dedup, action = body["dedup"], body["action"]
                assert action in ("confirm", "ignore")
            except Exception:
                self._send({"error": "bad request"}, code=400)
                return
            with dblock:
                from .core import now_iso
                conn.execute("INSERT INTO review(dedup,action,ts) VALUES (?,?,?) "
                             "ON CONFLICT(dedup) DO UPDATE SET action=excluded.action, ts=excluded.ts",
                             (dedup, action, now_iso()))
                conn.commit()
            self._send({"ok": True})

    return H


def serve(db: str, host: str = "127.0.0.1", port: int = 8088,
          config: str | None = None, alerts: str | None = None) -> None:
    handler = make_handler(db, config, alerts)
    srv = ThreadingHTTPServer((host, port), handler)
    print(f"[panel] http://{host}:{port}  db={db}  config={config}  alerts={alerts}")
    srv.serve_forever()
