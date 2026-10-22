# 快速上手

零安装：git 检出即用，无 pip 依赖，唯一前置是 Python 3.10 及以上。

## 自检与清单

```bash
git clone https://github.com/luohaoran616/credscan.git
cd credscan
python3 -m unittest discover -s tests   # 86 例，末行 OK 为准
python3 -m credscan list               # 渠道/检测器/凭据族清单（运行时导出）
```

## 离线扫描（无网，秒级）

```bash
python3 -m credscan scan --channel local_fs --path ./demo --db out.db -v
python3 -m credscan stats --db out.db
python3 -m credscan stats --db out.db --weak-paths   # 弱层同包同路径聚合
```

## 在线渠道扫描

```bash
python3 -m credscan scan --channel github_gists --db out.db
python3 -m credscan scan --channel pypi_feed --db out.db --max-items 50
```

网络渠道可选环境变量（缺省自动降级）：`GITHUB_TOKEN`、`GITEE_TOKEN`、`SEARX_URL`（默认 `http://127.0.0.1:8888`，本机 SearxNG）。12 个网络适配器无需任何令牌即可匿名使用。

## 常驻生产形态

```bash
python3 -m credscan daemon --config daemon.json   # 每渠道独立节奏，断点续跑
python3 -m credscan panel                         # 运维面板 127.0.0.1:8088
```

## 告警与蜜凭据闭环

```bash
python3 -m credscan scan --channel github_gists --db out.db \
    --alert-jsonl alerts.jsonl --webhook https://your-ops/hook --respond

echo "<牺牲AK明文>" | python3 -m credscan honeytoken add --user demo --ak-id LTAI5tXXXX
python3 -m credscan honeytoken list
```

处置默认 dry-run；live 需 `--respond` 与环境变量 `CREDSCAN_RESPOND_LIVE=1` 双开关，且对象仅限登记在册的自有蜜凭据，详见[伦理红线](/guide/ethics)。
