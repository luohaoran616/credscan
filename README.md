# CredScan

![tests](https://img.shields.io/badge/tests-86%2F86-brightgreen) ![python](https://img.shields.io/badge/python-3.10%2B-blue) ![deps](https://img.shields.io/badge/dependencies-0-success) ![license](https://img.shields.io/badge/license-MIT-informational)

公开渠道云凭据泄露的**分钟级检测与响应**。CredScan 以 15 个渠道适配器持续监测 24 个站点、38 类内容源，56 个检测器分属 12 个凭据族，命中经置信分级与 SHA-256 指纹去重后入库告警；纯 Python 标准库实现，零第三方依赖。

连续采集生产库实测（2026-10-21 快照）：**73,006 条命中，21,353 个唯一凭据，strong 档 1,209 个**；事件型渠道检出时延中位数 **49–270 秒**，蜜凭据泄露到告警全链 **81–304 秒**（7 次实测全部落入模型预测区间）。

[官网与完整文档](https://luohaoran616.github.io/credscan/)

## 快速开始

```bash
git clone https://github.com/luohaoran616/credscan.git
cd credscan
python3 -m unittest discover -s tests   # 86 例（1 例依赖未随仓文档自动跳过），末行 OK 为准
python3 -m credscan list                # 渠道/检测器/凭据族清单（运行时导出）
python3 -m credscan scan --channel local_fs --path <目录> --db out.db -v
python3 -m credscan stats --db out.db   # 检出统计 + 时效分位
python3 -m credscan stats --db out.db --weak-paths   # 弱层同包同路径聚合
python3 -m credscan daemon --config daemon.json      # 7×24 守护进程
python3 -m credscan panel               # 运维面板（127.0.0.1:8088，8 个端点）
```

网络渠道可选环境变量（缺省自动降级）：`GITHUB_TOKEN`、`GITEE_TOKEN`、`SEARX_URL`（默认 `http://127.0.0.1:8888`）。

## 架构：四层流水线

```
采集层  15 适配器 / 38 监测口径（离线/代码托管/包仓库事件流/容器代码流/社区直连/搜索矩阵；
        每渠道 budget_sec 预算墙 + 条数上限双约束）
          ↓ Item(channel, uri, text, published_at)
检测层  56 检测器 / 12 凭据族 / 四档置信（strong·medium·weak·placeholder，只降不升）
        41 条手写规则 + 15 条数据表生成；官方示例值白名单；规则交叠 CI
          ↓ Finding（sha256 + 脱敏 preview/snippet + 包内路径；永不落完整明文）
存储层  SQLite（findings + events 响应审计链，WAL；四元组指纹去重）
响应层  告警三 sink（console/jsonl/webhook）+ 蜜凭据登记（只存哈希）
        + 可插拔处置 Provider（阿里云 RAM 纯标准库签名；默认 dry-run，live 双开关）
```

四个环节各有数学模型并经生产数据校验：采集层 AoI `E[R]=T/2+c`（拟合误差 <4%）、检测层正则并语言单调不减、增长层负二项过散与子模覆盖贪心、调度层配额最优周期平方根律。

## 精度基准

与 gitleaks 8.24.3 同语料对扫（2026-10-12）：中国生态凭据样本 19 行命中 **19/19 vs 3/19**；熵阈值治理后 strong 层零误报（熵闸 3.6→4.0，查全率 0.30→0.92）。

## 伦理红线

- 库中只存哈希与脱敏预览，绝不保存完整明文凭据（测试有断言）。
- 不做任何「有效性验证」式的凭据实际调用；置信分级用格式级校验替代在线验证。
- 检出结果仅用于计数统计与负责任披露，不利用、不传播。
- 处置只针对预登记的**自有蜜凭据**；第三方泄露凭据只告警、绝不触碰（测试强制断言）；处置默认 dry-run，live 需命令行与环境变量双开关。

## 工具箱（tools/）

`fit_entropy` 熵阈值 P-R 拟合 · `fit_dispersion` 发现流过散检验 · `suggest_intervals` 配额最优轮询周期 · `coverage` 渠道覆盖贪心 · `honeygen` 蜜凭据生成（四维可信度自评）· `honey_rerun` 蜜凭据端到端复跑 · `report_numbers` 生产库数字快照 · `cleanup_snippets` 历史 snippet 补偿清洗 · `check_anchors` 文档行号锚点校验。

## 版本线

- v0.1–0.2：引擎 + 8 类渠道 + 41 检测器，首批真实检出。
- v0.3–0.4：daemon 调度、运维面板、时效/精度/蜜凭据三份实测。
- v0.5.x：生产化（预算墙/退避/优雅退出）、检测器 56/口径 38。
- v0.6.0：placeholder 占位细分 + 蜜凭据四维可信度。
- v0.6.1：弱层同包路径级聚合，`stats --weak-paths`。
- v0.6.3：结果聚合层（唯一凭据实体 + 出现记录两表，HMAC 指纹）。

## License

[MIT](LICENSE)
