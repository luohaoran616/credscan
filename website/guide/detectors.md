# 检测器

## 56 个检测器 · 12 个凭据族

![检测器族谱](/figures/families.png)

族覆盖云 AK/SK、大模型 API Key、SaaS 平台令牌、OAuth、私钥证书、代码平台、Webhook、数据库、支付、账号密码与 Web 凭据。41 条为手写规则，15 条由数据表直接生成——新增厂商只需扩充数据表，不必改动判定代码。

## 四档置信，只降不升

![置信四档](/figures/confidence.png)

strong、medium、weak 三档对应不同证据强度，placeholder 一档标记形态可疑而取值明显为占位的命中。置信只降不升：被判为弱层的命中不会因后续规则升回强层，弱层命中默认不进入告警。

## 四元组指纹去重

![指纹四元组](/figures/fingerprint.png)

去重键为 `sha256(detector | secret_sha256 | source_uri | line_no)` 四元组：同一凭据在同一位置重复出现只入库一次；库中只存哈希与脱敏预览，永不保存完整明文。

## 扩展一个新渠道

![扩展三步](/figures/extend.png)

新增渠道只需三步：写一个适配器类、注册、配置节奏——采集与判定主流程零改动。同理，新凭据类型是规则表的一行数据，站点矩阵是 `SITE_TARGETS` 的一行。
