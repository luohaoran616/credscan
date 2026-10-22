# 运维面板

`python3 -m credscan panel` 启动单页运维面板（默认 `127.0.0.1:8088`）。面板定位是**只读视图 + 单一复核写接口**：8 个端点里除只读视图外只有一个写接口 `POST /api/review`，写独立 review 表、不触 findings。

## 总览

![面板总览](/figures/panel-overview.png)

命中规模、时延分位与渠道运行状态一屏可读。

## 发现列表

![发现列表](/figures/panel-findings.png)

每条命中带掩码快照与行号，可按置信与渠道过滤，可标记 confirm 或 ignore 供人工复核。

## 时延视图

![时延视图](/figures/panel-latency.png)

检出时延按渠道分位呈现，验证「事件型渠道分钟级检出」的时效主张。
