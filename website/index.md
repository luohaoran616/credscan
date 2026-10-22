---
layout: home

hero:
  name: CredScan
  text: 公开渠道凭据泄露，分钟级发现
  tagline: 纯 Python 标准库实现的凭据泄露检测与响应系统——24 个站点持续监测，56 个检测器，73,006 条实测命中。
  actions:
    - theme: brand
      text: 快速上手
      link: /guide/quickstart
    - theme: alt
      text: GitHub
      link: https://github.com/luohaoran616/credscan
    - theme: alt
      text: 看实测
      link: /guide/evidence

features:
  - icon: 🌐
    title: 24 个站点持续监测
    details: 15 个渠道适配器覆盖 38 类内容源：包管理仓、代码托管、容器镜像、技术社区、paste 与 wiki 站；预算墙与条数上限双约束。
  - icon: 🔍
    title: 56 个检测器 · 12 个凭据族
    details: 云 AK/SK、大模型 API Key、Webhook、私钥证书、数据库连接串、支付商户密钥；四档置信只降不升，官方示例值白名单。
  - icon: ⚡
    title: 分钟级时效
    details: 事件型渠道检出时延中位数 49–270 秒；蜜凭据泄露到告警全链 81–304 秒，7 次实测全部落入模型预测区间。
  - icon: 🕵️
    title: 响应闭环
    details: 新发现即时告警（console / jsonl / webhook 三路）；自有蜜凭据可执行云侧处置，默认 dry-run，双开关确认。
  - icon: 🧩
    title: 零第三方依赖
    details: 仅 Python 标准库（urllib、sqlite3、json、argparse 等），Python 3.10+，3.14 实测 86 例单元测试全绿。
  - icon: 📊
    title: 运维面板
    details: 单页只读视图 + 单一复核写接口，8 个端点呈现命中规模、时延分位、事件流与渠道状态。
---

## 实测速览

生产库连续采集（2026-10-21 快照）：**73,006 条命中 · 21,353 个唯一凭据 · strong 档 1,209 个**。

![面板总览](/figures/panel-overview.png)

检出条数按渠道分布与检出时延对照见[实测与证据](/guide/evidence)。
