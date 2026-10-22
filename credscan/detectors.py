"""凭据检测插件包：每个类 = 一种（族）凭据类型。命中即产出 Finding。

置信度分级：
  strong  = 有唯一前缀/结构特征，误报率极低
  medium  = 结构特征 + 上下文关键词/熵校验
  weak    = 仅上下文启发（人工复核队列）
"""
from __future__ import annotations

import re
from typing import Iterator

from .core import Detector, shannon_entropy, register_detector

# ---------------------------------------------------------------- 云厂商 AK/SK（L1：数据表驱动，加厂商 = 加一行）
# (id, kind, title, 正则, confidence, severity)。格式来源逐条见 credential-formats.md。

VENDORS: list = [
    ("aliyun_access_key_id", "aliyun_ak", "阿里云 AccessKey ID",
     r"(?<![A-Za-z0-9])LTAI[A-Za-z0-9]{12,24}(?![A-Za-z0-9])", "strong", "high"),
    ("tencent_secret_id", "tencent_sk", "腾讯云 SecretId",
     r"(?<![A-Za-z0-9])AKID[A-Za-z0-9]{32}(?![A-Za-z0-9])", "strong", "high"),
    # 百度千帆官方示例 bce-v3/ALTAK-111（cloud.baidu.com/doc/qianfan/s/wmh8l6tnf，2026-10-11 抓正文核实）
    ("baidu_qianfan_key", "qianfan_key", "百度智能云千帆 API Key（bce-v3/ALTAK-）",
     r"(?<![A-Za-z0-9_/])bce-v3/ALTAK-[A-Za-z0-9]{8,64}(?![A-Za-z0-9])", "strong", "high"),
    # 青云官方签名文档示例 QYACCESSKEYIDEXAMPLE（QY 前缀官方证实，长度为社区通则）
    ("qingcloud_ak", "qingcloud_ak", "青云 QingCloud AccessKey（QY 前缀）",
     r"(?<![A-Za-z0-9])QY[A-Za-z0-9]{10,40}(?![A-Za-z0-9])", "medium", "high"),
    ("volcengine_ak", "volc_ak", "火山引擎/金山云 AccessKey（AKLT 前缀，两家同前缀）",
     r"(?<![A-Za-z0-9])AKLT[A-Za-z0-9+/=]{12,}(?![A-Za-z0-9+/=])", "medium", "high"),
    # 阿里云 STS 临时访问凭据：AccessKeyId 以 "STS." 开头（官方 OSS 文档实锤）
    ("aliyun_sts_ak", "sts_ak", "阿里云 STS 临时访问凭据",
     r"(?<![A-Za-z0-9_.])STS\.[A-Za-z0-9]{12,40}(?![A-Za-z0-9])", "medium", "high"),
    # 京东云 AccessKey：JDC_ 前缀（社区规则，长度 32-36 待实测收紧）
    ("jdcloud_access_key", "jd_ak", "京东云 AccessKey",
     r"(?<![A-Za-z0-9_])JDC_[A-Z0-9]{20,40}(?![A-Z0-9])", "medium", "high"),
    ("aws_access_key_id", "aws_ak", "AWS Access Key ID",
     r"(?<![A-Z0-9])(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
     "strong", "high"),
    ("gcp_api_key", "gcp_key", "Google API / Gemini Key",
     r"(?<![A-Za-z0-9_\-])AIza[0-9A-Za-z_\-]{35}(?![A-Za-z0-9_\-])", "strong", "high"),
]

def _is_placeholder(v: str) -> bool:
    """占位值：去掉 4 位前缀后为 全同字符 / 全 x·0 / 前置 0-3 位后全 x 的文档示例形态
    （如 CSDN 教程值 LTAI5txxxxxxxxxxxxxxx，2026-10-11 基准实锤）。"""
    body = v[4:] if len(v) > 8 else v
    if len(body) < 6:
        return False
    low = body.lower()
    return (len(set(low)) == 1
            or set(low) <= {"x", "0"}
            or re.fullmatch(r"[a-z0-9]{0,3}x{6,}", low) is not None)


# 共享占位值判定：收敛 _VendorDetector / WePayKey / OAuthSecretPair 的散落过滤逻辑
# （纯数字 / 已知占位值 / 占位关键词 / 形态退化）。DatabaseURI 的 PLACEHOLDER_USERINFO
# 与 PasswordPair 的 STOP 属领域专属（账密对 / 弱口令），此处不合并。
_PLACEHOLDER_MARK_RX = re.compile(r"(?i)(your|placeholder|示例|密钥|example|x{4,}|\*{4,})")
_KNOWN_PLACEHOLDER_VALUES = frozenset({"your_secret_here", "xxxxxxxxxxxxxxxx", "placeholder", "key"})


def is_placeholder_value(v: str) -> bool:
    """通用占位值判定：纯数字 / 已知占位值 / 含占位关键词 / 形态退化。"""
    if v.isdigit() or v.lower() in _KNOWN_PLACEHOLDER_VALUES or _PLACEHOLDER_MARK_RX.search(v):
        return True
    return _is_placeholder(v)


class _VendorDetector(Detector):
    def match(self, text: str) -> Iterator[dict]:
        for kind, rx in self.patterns:
            for m in rx.finditer(text):
                if is_placeholder_value(m.group(0)):
                    continue
                yield {"kind": kind, "secret": m.group(0), "pos": m.start()}


for _row in VENDORS:
    _id, _kind, _title, _rx, _conf, _sev = _row
    register_detector(type("Vendor_" + _id, (_VendorDetector,), {
        "id": _id, "title": _title, "family": "云 AK/SK",
        "confidence": _conf, "severity": _sev,
        "patterns": [(_kind, re.compile(_rx))],
    }))


@register_detector
class AzureStorageConn(Detector):
    id = "azure_storage_conn"; title = "Azure 存储连接串"; family = "云 AK/SK"
    patterns = [("azure_conn", re.compile(
        r"DefaultEndpointsProtocol=[^;\s\"']+;AccountName=[^;\s\"']+;AccountKey=[A-Za-z0-9+/=]{60,}"))]


@register_detector
class AzureSAS(Detector):
    id = "azure_sas"; title = "Azure SAS 签名 URL"; family = "云 AK/SK"
    confidence = "medium"
    patterns = [("azure_sas", re.compile(
        r"(?i)sv=\d{4}-\d{2}-\d{2}[^\"'\s]{0,200}?sig=[A-Za-z0-9%+/=]{20,}"))]


# ---------------------------------------------------------------- 厂商键名成对（L2：数据表驱动）
# 华为云/七牛/天翼/UCloud 官方无格式前缀（2026-10-11 逐家抓官方文档核实，见 credential-formats.md），
# 键名成对是这些厂商的主力检测层。捕获组 2 = 秘密值。

VENDOR_PAIRS: list = [
    # 华为云 AK 为大写字母数字（官方 API 响应示例 P83EVBZJMXCYTMUII… 形态）
    ("huawei_cloud_pair", "huawei_pair", "华为云 AK/SK 键值对（HUAWEICLOUD_* 环境变量/配置）",
     r"(?is)huaweicloud[_\-]?(?:access[_\-]?key(?:[_\-]?id)?|ak)\s*[:=]\s*[\"']?([A-Z0-9]{12,40})[\"']?"
     r"[\s\S]{0,200}?huaweicloud[_\-]?(?:secret[_\-]?(?:access[_\-]?)?key|sk)\s*[:=]\s*[\"']?([A-Za-z0-9]{20,64})"),
    ("qiniu_pair", "qiniu_pair", "七牛云 AK/SK 键值对",
     r"(?is)qiniu[_\-]?(?:access[_\-]?key|ak)\s*[:=]\s*[\"']?([A-Za-z0-9]{15,45})[\"']?"
     r"[\s\S]{0,200}?qiniu[_\-]?(?:secret[_\-]?key|sk)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{20,64})"),
    ("ctyun_pair", "ctyun_pair", "天翼云 EOP AK/SK 键值对",
     r"(?is)ctyun[_\-]?eop[_\-]?(?:ak|access[_\-]?key)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{12,45})[\"']?"
     r"[\s\S]{0,200}?ctyun[_\-]?eop[_\-]?(?:sk|secret[_\-]?key)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{20,64})"),
    # UCloud 公私钥为 Base64 形态（官方 CLI 文档，docs.ucloud.cn/cli/intro）
    ("ucloud_pair", "ucloud_pair", "UCloud 公私钥键值对（Base64 形态）",
     r"(?is)ucloud[_\-]?public[_\-]?key\s*[:=]\s*[\"']?([A-Za-z0-9+/=]{24,64})[\"']?"
     r"[\s\S]{0,200}?ucloud[_\-]?private[_\-]?key\s*[:=]\s*[\"']?([A-Za-z0-9+/=]{24,64})"),
]


class _VendorPairDetector(Detector):
    def match(self, text: str) -> Iterator[dict]:
        for kind, rx in self.patterns:
            for m in rx.finditer(text):
                yield {"kind": kind, "secret": m.group(2), "pos": m.start(2)}


for _row in VENDOR_PAIRS:
    _id, _kind, _title, _rx = _row
    register_detector(type("Pair_" + _id, (_VendorPairDetector,), {
        "id": _id, "title": _title, "family": "云 AK/SK",
        "confidence": "medium", "severity": "high",
        "patterns": [(_kind, re.compile(_rx))],
    }))


@register_detector
class CloudAKSKPair(Detector):
    """上下文成对：access_key(:id)? 与 secret_(access_)key 相邻出现（无固定前缀云厂商通用兜底）。"""
    id = "cloud_aksk_pair"; title = "AK/SK 键值对（无前缀云厂商通用）"; family = "云 AK/SK"
    severity = "high"; confidence = "medium"
    patterns = [("aksk_pair", re.compile(
        r"(?is)access[_\-]?key(?:[_\-]?id)?\s*[:=]\s*[\"']?([A-Za-z0-9]{15,40})[\"']?"
        r"[\s\S]{0,200}?secret[_\-]?(?:access[_\-]?)?key\s*[:=]\s*[\"']?([A-Za-z0-9+/=_\-]{24,64})"))]

    def match(self, text: str) -> Iterator[dict]:
        for kind, rx in self.patterns:
            for m in rx.finditer(text):
                yield {"kind": kind, "secret": m.group(2), "pos": m.start(2)}


# ---------------------------------------------------------------- 私钥 / 证书

@register_detector
class PrivateKeyPEM(Detector):
    id = "private_key_pem"; title = "私钥文件（RSA/EC/DSA/OpenSSH/PGP/加密 PEM，头+base64 体）"; family = "私钥与证书"
    patterns = [("pem_header", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
        r"[ \t]*\r?\n+[ \t]*[A-Za-z0-9+/]{40,}"))]


@register_detector
class PuttyPPK(Detector):
    id = "putty_ppk"; title = "PuTTY 私钥文件（PPK）"; family = "私钥与证书"
    patterns = [("ppk", re.compile(r"PuTTY-User-Key-File-[23]:"))]


@register_detector
class GCPServiceAccount(Detector):
    id = "gcp_service_account"; title = "GCP 服务账号 JSON"; family = "私钥与证书"
    confidence = "medium"
    patterns = [("sa_json", re.compile(r"\"type\"\s*:\s*\"service_account\""))]


@register_detector
class BareB64PrivateKey(Detector):
    """无 PEM 头的单行 base64 私钥（支付宝 app_private_key 为典型形态）。泄露面：
    『app_private_key』出现于 12.3 万仓库，与 MIIE 字面量同现 ≥1,344；2026-10-13
    GitHub 实测字面量 17/17=MII 前缀、完整长度 1,590–1,626（2048 位 PKCS8）。
    带 -----BEGIN----- 头的形态由 private_key_pem 负责，此处不双计。"""
    id = "bare_b64_private_key"; title = "单行 base64 私钥（无 PEM 头，支付宝 app_private_key 典型）"
    family = "私钥与证书"
    severity = "high"; confidence = "strong"
    KEY_CTX = re.compile(r"(?i)(?:private[_\-]?key|app[_\-]?private)")
    patterns = [("bare_b64_key", re.compile(r"\bMII[A-Za-z0-9+/]{200,}"))]

    def match(self, text: str) -> Iterator[dict]:
        for kind, rx in self.patterns:
            for m in rx.finditer(text):
                head = text[max(0, m.start() - 60):m.start()]
                if "-----BEGIN" in head:      # PEM 体归 private_key_pem
                    continue
                if not self.KEY_CTX.search(head):
                    continue
                yield {"kind": kind, "secret": m.group(0), "pos": m.start()}


# ---------------------------------------------------------------- 数据库连接串


PLACEHOLDER_USERINFO = {
    "user:pass", "user:password", "username:password", "postgres:postgres",
    "root:root", "admin:admin", "test:test", "sa:sa", "foo:bar", "demo:demo",
}


@register_detector
class DatabaseURI(Detector):
    id = "db_uri"; title = "数据库连接串（MySQL/MariaDB/PostgreSQL/MongoDB/Redis/AMQP/MSSQL）"; family = "数据库凭据"
    patterns = [("db_uri", re.compile(
        r"(?i)(?<![A-Za-z0-9+.\-])(?:mysql|mariadb|mongodb(?:\+srv)?|postgres(?:ql)?|redis|rediss|amqps?|mssql)"
        r"://([^\s\"'<>@]{1,64}):([^\s\"'<>@]{3,64})@[^\s\"'<>]{3,}"))]

    def match(self, text: str) -> Iterator[dict]:
        for kind, rx in self.patterns:
            for m in rx.finditer(text):
                userinfo = f"{m.group(1).lower()}:{m.group(2).lower()}"
                if userinfo in PLACEHOLDER_USERINFO:
                    continue
                yield {"kind": kind, "secret": m.group(0), "pos": m.start()}


@register_detector
class JdbcPassword(Detector):
    id = "jdbc_password"; title = "JDBC 连接串内嵌密码"; family = "数据库凭据"
    confidence = "medium"
    patterns = [("jdbc_pw", re.compile(
        r"(?i)jdbc:[a-z0-9]+://[^\s\"']{3,}?[?&;]password=[^\s&\"';]{3,}"))]


# ---------------------------------------------------------------- SaaS / 平台令牌


@register_detector
class SlackToken(Detector):
    id = "slack_token"; title = "Slack Token"; family = "SaaS/平台令牌"
    patterns = [("slack", re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[0-9A-Za-z\-]{10,}"))]


@register_detector
class TelegramBotToken(Detector):
    id = "telegram_bot_token"; title = "Telegram Bot Token"; family = "SaaS/平台令牌"
    patterns = [("tg_bot", re.compile(r"(?<![0-9])[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}(?![A-Za-z0-9_\-])"))]


@register_detector
class DiscordToken(Detector):
    id = "discord_token"; title = "Discord Bot Token"; family = "SaaS/平台令牌"
    confidence = "medium"
    patterns = [("discord", re.compile(r"(?<![A-Za-z0-9_\-])(?:MTE|MTA|NDE|NTA)[A-Za-z0-9_\-]{20,}"))]


@register_detector
class SendGridKey(Detector):
    id = "sendgrid_key"; title = "SendGrid API Key"; family = "SaaS/平台令牌"
    patterns = [("sendgrid", re.compile(r"(?<![A-Za-z0-9_.\-])SG\.[A-Za-z0-9_\-]{16,64}\.[A-Za-z0-9_\-]{16,64}"))]


@register_detector
class TwilioKey(Detector):
    id = "twilio_key"; title = "Twilio API Key"; family = "SaaS/平台令牌"
    patterns = [("twilio", re.compile(r"(?<![A-Za-z0-9])SK[a-fA-F0-9]{32}(?![a-fA-F0-9])"))]


@register_detector
class StripeKey(Detector):
    id = "stripe_key"; title = "Stripe 密钥"; family = "支付凭据"
    patterns = [("stripe", re.compile(r"(?<![A-Za-z0-9])(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,}"))]


@register_detector
class WePayKey(Detector):
    """微信支付 v2 API key（商户 API 密钥）。v2 key 为用户自定义 32 字符、**无固定
    字符集**——形态约束不成立，只能「支付上下文+长度」约束，诚实定级 medium。
    形态依据（2026-10-13 GitHub 实测）：mchKey 命中 4,528 仓库、字面量 1/1=32 位
    字母数字；paySignKey/APIv3Key 字面量 0。排除占位/纯数字/泛化 apikey 上下文。"""
    id = "wepay_key"; title = "微信支付商户 API 密钥（v2，32 位自定义）"; family = "支付凭据"
    severity = "high"; confidence = "medium"
    rationale = "v2 key 无固定字符集，仅支付上下文+长度约束，诚实定级 medium"
    KEY_CTX = re.compile(r"(?i)(?:mch[_\-]?key|partner[_\-]?key|paysign[_\-]?key)")
    patterns = [("wepay32", re.compile(r"(?<![A-Za-z0-9])([0-9A-Za-z]{32})(?![A-Za-z0-9])"))]

    def match(self, text: str) -> Iterator[dict]:
        for kind, rx in self.patterns:
            for m in rx.finditer(text):
                head = text[max(0, m.start() - 40):m.start()]
                if not self.KEY_CTX.search(head):
                    continue
                v = m.group(1)
                if is_placeholder_value(v):
                    continue
                yield {"kind": kind, "secret": v, "pos": m.start()}


@register_detector
class GitHubToken(Detector):
    id = "github_token"; title = "GitHub Token（ghp_/gho_/ghu_/ghs_/github_pat_）"; family = "代码平台令牌"
    patterns = [("github", re.compile(
        r"(?<![A-Za-z0-9_])(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"))]


@register_detector
class GitLabPAT(Detector):
    id = "gitlab_pat"; title = "GitLab Personal Access Token"; family = "代码平台令牌"
    patterns = [("gitlab", re.compile(r"(?<![A-Za-z0-9_\-])glpat-[A-Za-z0-9_\-]{16,}"))]


@register_detector
class NpmToken(Detector):
    id = "npm_token"; title = "npm 发布令牌"; family = "代码平台令牌"
    patterns = [("npm", re.compile(r"(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])"))]


@register_detector
class MailgunKey(Detector):
    id = "mailgun_key"; title = "Mailgun API Key"; family = "SaaS/平台令牌"
    confidence = "medium"
    patterns = [("mailgun", re.compile(r"(?<![A-Za-z0-9_\-])key-[0-9a-zA-Z]{32}(?![0-9a-zA-Z])"))]


@register_detector
class FacebookToken(Detector):
    id = "facebook_token"; title = "Facebook 访问令牌"; family = "SaaS/平台令牌"
    patterns = [("facebook", re.compile(r"(?<![A-Za-z0-9])EAAC[A-Za-z0-9]{10,}"))]


# ---------------------------------------------------------------- 大模型 API Key（中国生态特色）


@register_detector
class OpenAIKey(Detector):
    id = "openai_key"; title = "OpenAI/Moonshot(Kimi) 族 API Key（sk- + 40+）"; family = "大模型 API Key"
    patterns = [("openai", re.compile(r"(?<![A-Za-z0-9_\-])sk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{40,}"))]


@register_detector
class AnthropicKey(Detector):
    id = "anthropic_key"; title = "Anthropic API Key（sk-ant-api03-）"; family = "大模型 API Key"
    patterns = [("anthropic", re.compile(r"(?<![A-Za-z0-9_\-])sk-ant-[A-Za-z0-9_\-]{20,}"))]


@register_detector
class LLMHex32Key(Detector):
    id = "llm_hex32_key"; title = "DeepSeek/DashScope 族 API Key（sk- + 32 位小写字母数字）"; family = "大模型 API Key"
    patterns = [("llm_hex32", re.compile(r"(?<![A-Za-z0-9_\-])sk-[a-z0-9]{32}(?![a-z0-9])"))]


@register_detector
class ZhipuKey(Detector):
    id = "zhipu_key"; title = "智谱 API Key（id.secret 格式：32hex.16）"; family = "大模型 API Key"
    confidence = "medium"
    patterns = [("zhipu", re.compile(
        r"(?<![0-9a-f])[0-9a-f]{32}\.[A-Za-z0-9]{16}(?![A-Za-z0-9])"))]


@register_detector
class XAIKey(Detector):
    id = "xai_key"; title = "xAI（Grok）API Key（xai- 前缀）"; family = "大模型 API Key"
    patterns = [("xai", re.compile(r"(?<![A-Za-z0-9_\-])xai-[A-Za-z0-9_\-]{20,}"))]


@register_detector
class GroqKey(Detector):
    """Groq：gsk_ + 52 位（truffleHog 与 secretlint 双源一致，同 GitHub secret scanning 模式）。"""
    id = "groq_key"; title = "Groq API Key"; family = "大模型 API Key"
    patterns = [("groq", re.compile(r"(?<![A-Za-z0-9_])gsk_[A-Za-z0-9]{52}(?![A-Za-z0-9])"))]


# 命名大模型 Key（L2 键名锚点）：MiniMax/Moonshot 官方无格式规定（2026-10-11 核实），
# 值形态已由 jwt/openai_key 覆盖，这里用键名归因 + 捕获无前缀形态。
NAMED_LLM_KEYS: list = [
    ("minimax_api_key", "minimax_key", "MiniMax API Key（新 Key 为 JWT 形态）",
     r"(?i)minimax[_\-]?api[_\-]?key\s*[:=]\s*[\"']?([A-Za-z0-9_\-.]{24,128})"),
    ("moonshot_api_key", "moonshot_key", "Moonshot/Kimi API Key（键名锚定归因）",
     r"(?i)(?:moonshot|kimi)[_\-]?api[_\-]?key\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{24,64})"),
]


class _NamedKeyDetector(Detector):
    def match(self, text: str) -> Iterator[dict]:
        for kind, rx in self.patterns:
            for m in rx.finditer(text):
                yield {"kind": kind, "secret": m.group(1), "pos": m.start(1)}


for _row in NAMED_LLM_KEYS:
    _id, _kind, _title, _rx = _row
    register_detector(type("NamedKey_" + _id, (_NamedKeyDetector,), {
        "id": _id, "title": _title, "family": "大模型 API Key",
        "confidence": "medium", "severity": "high",
        "patterns": [(_kind, re.compile(_rx))],
    }))


# ---------------------------------------------------------------- OAuth / 开放平台


@register_detector
class GoogleOAuthSecret(Detector):
    id = "google_oauth_secret"; title = "Google OAuth Client Secret"; family = "OAuth/开放平台"
    patterns = [("gocpsx", re.compile(r"(?<![A-Za-z0-9_\-])GOCSPX-[A-Za-z0-9_\-]{28}"))]


@register_detector
class GoogleClientID(Detector):
    id = "google_client_id"; title = "Google OAuth Client ID（配套密钥的定位线索）"; family = "OAuth/开放平台"
    severity = "medium"; confidence = "medium"
    patterns = [("gclient", re.compile(
        r"(?<![0-9])[0-9]{6,}-[a-z0-9]+\.apps\.googleusercontent\.com"))]


@register_detector
class WeChatAppID(Detector):
    id = "wechat_appid"; title = "微信 AppID（小程序/公众号，配套 AppSecret 泄露定位）"; family = "OAuth/开放平台"
    severity = "medium"; confidence = "medium"
    patterns = [("wx_appid", re.compile(r"(?<![a-f0-9])wx[a-f0-9]{16}(?![a-f0-9])"))]


@register_detector
class OAuthSecretPair(Detector):
    """上下文：app_secret / client_secret / appsecret 等键值对（飞书/钉钉/企业微信/支付宝等）。"""
    id = "oauth_secret_pair"; title = "OAuth/AppSecret 键值对（飞书/钉钉/企业微信/支付宝等）"; family = "OAuth/开放平台"
    confidence = "medium"
    patterns = [("oauth_secret", re.compile(
        r"(?i)(?:app[_\-]?secret|client[_\-]?secret|appsecret|api[_\-]?secret)\s*[:=]\s*[\"']?"
        r"([A-Za-z0-9_\-]{16,64})"))]

    def match(self, text: str) -> Iterator[dict]:
        for kind, rx in self.patterns:
            for m in rx.finditer(text):
                v = m.group(1)
                if is_placeholder_value(v):
                    continue
                yield {"kind": kind, "secret": v, "pos": m.start(1)}


@register_detector
class WeComCorpSecret(Detector):
    """企业微信 corpsecret：官方无格式规定（developer.work.weixin.qq.com 2026-10-11 核实），
    键名锚定 + 要求 corpid 上下文（gettoken 场景成对出现）。"""
    id = "wecom_corpsecret"; title = "企业微信 corpsecret（corpid 上下文）"; family = "OAuth/开放平台"
    severity = "high"; confidence = "medium"
    patterns = [("wecom_secret", re.compile(
        r"(?i)corp[_\-]?secret\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{16,64})"))]

    def match(self, text: str) -> Iterator[dict]:
        low = text.lower()
        for kind, rx in self.patterns:
            for m in rx.finditer(text):
                if "corpid" not in low:          # 无 corpid 上下文则不判企微
                    continue
                yield {"kind": kind, "secret": m.group(1), "pos": m.start(1)}


@register_detector
class FeishuAppID(Detector):
    """飞书 App ID：cli_ 前缀（社区多源；须含数字降低误报）。定位线索，配套 App Secret 由
    oauth_secret_pair 捕获。"""
    id = "feishu_app_id"; title = "飞书 App ID（cli_ 前缀）"; family = "OAuth/开放平台"
    severity = "medium"; confidence = "medium"
    patterns = [("feishu_app", re.compile(r"(?<![a-z0-9_])cli_[a-z0-9]{12,32}(?![a-z0-9])"))]

    def match(self, text: str) -> Iterator[dict]:
        for kind, rx in self.patterns:
            for m in rx.finditer(text):
                if not any(c.isdigit() for c in m.group(0)):
                    continue
                yield {"kind": kind, "secret": m.group(0), "pos": m.start()}


# ---------------------------------------------------------------- 协作机器人 Webhook
# 形态依据（2026-10-13）：官方文档（飞书 client-docs/bot-v3/add-custom-bot 明确警示
# 「不要公布在 Gitlab、博客等可公开查阅的网站上，避免地址泄露后被恶意调用」；企业微信
# developer.work.weixin.qq.com/document/path/91770）+ GitHub 公开代码搜索字面量实测：
# 钉钉 access_token 8/8 样本=64 位小写 hex（命中 12,160 个仓库）；飞书 hook 5/5=小写
# hex UUID（8,304 仓库）；企业微信 key 3/3=小写 hex UUID（8,512 仓库）。
# 域名+路径+精确形态三层约束 → 误报趋零，confidence=strong。


@register_detector
class FeishuWebhook(Detector):
    id = "feishu_webhook"; title = "飞书/Lark 群机器人 Webhook"; family = "协作机器人 Webhook"
    severity = "medium"; confidence = "strong"
    patterns = [("feishu_hook", re.compile(
        r"https://open\.(?:feishu\.cn|larksuite\.com)/open-apis/bot/v2/hook/"
        r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"))]


@register_detector
class DingTalkWebhook(Detector):
    id = "dingtalk_webhook"; title = "钉钉群机器人 Webhook"; family = "协作机器人 Webhook"
    severity = "medium"; confidence = "strong"
    patterns = [("dingtalk_token", re.compile(
        r"https://oapi\.dingtalk\.com/robot/send\?access_token=([0-9a-f]{64})"))]


@register_detector
class WeComWebhook(Detector):
    id = "wecom_webhook"; title = "企业微信群机器人 Webhook"; family = "协作机器人 Webhook"
    severity = "medium"; confidence = "strong"
    patterns = [("wecom_key", re.compile(
        r"https://qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key="
        r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"))]


# ---------------------------------------------------------------- 通用 Web 凭据


@register_detector
class JWT(Detector):
    id = "jwt"; title = "JWT（含已签名会话令牌）"; family = "Web 凭据"
    severity = "medium"
    patterns = [("jwt", re.compile(
        r"(?<![A-Za-z0-9_\-])eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"))]


@register_detector
class BasicAuthURL(Detector):
    id = "basic_auth_url"; title = "URL 内嵌账密（Basic Auth / git / ftp / ssh）"; family = "账号密码"
    confidence = "medium"
    patterns = [("url_cred", re.compile(
        r"(?i)(?<![A-Za-z0-9+.\-])(?:https?|ftps?|sftp|ssh|git(?:\+ssh)?|svn)://"
        r"[A-Za-z0-9._%\-]{1,32}:[^\s\"'@/]{3,64}@[A-Za-z0-9.\-]+"))]


@register_detector
class PasswordPair(Detector):
    """上下文：password/passwd/pwd/pass = <值>。带停用词过滤。"""
    id = "password_pair"; title = "配置中的账号密码键值对"; family = "账号密码"
    severity = "medium"; confidence = "weak"
    rationale = "仅上下文启发，弱口令/停用词易误报，需人工复核"
    STOP = {
        "password", "passwd", "your_password", "yourpassword", "yourpass", "changeme",
        "change_me", "example", "placeholder", "xxxxxx", "xxxx", "xxx", "test", "123456",
        "12345678", "password123", "1234567890", "null", "none", "true", "false", "secret",
        "abcdefgh", "qwerty", "letmein", "admin123", "root123", "1qaz2wsx", "iloveyou",
    }
    patterns = [("pw_pair", re.compile(
        r"(?i)\b(?:password|passwd|pwd|pass)\b\s*[:=]\s*[\"']?([^\s\"'<>{}]{6,32})"))]

    def match(self, text: str) -> Iterator[dict]:
        for kind, rx in self.patterns:
            for m in rx.finditer(text):
                v = m.group(1)
                lv = v.lower().lstrip("$").strip("${}")
                if lv in self.STOP or v.startswith(("$", "%(", "#{")):
                    continue
                if shannon_entropy(v) < 2.0:
                    continue
                yield {"kind": kind, "secret": v, "pos": m.start(1)}


@register_detector
class ShadowHash(Detector):
    id = "shadow_hash"; title = "Linux 口令哈希（/etc/shadow 格式）"; family = "账号密码"
    severity = "high"; confidence = "medium"
    patterns = [("shadow", re.compile(r"\$[0-9][a-z]?\$[A-Za-z0-9./+$]{10,}"))]


@register_detector
class GenericHighEntropySecret(Detector):
    """兜底：secret/token/api_key 上下文附近的高熵长串（覆盖未知厂商格式）。"""
    id = "generic_entropy_secret"; title = "高熵泛化凭据（secret/token/api_key 上下文）"; family = "泛化兜底"
    severity = "medium"; confidence = "weak"
    rationale = "仅上下文启发 + 熵闸 θ=4.0（正例池 14 候选过闸 13，负例 47 假拟合）"
    # 熵闸拟合（2026-10-12，tools/fit_entropy.py，正例池=合成真凭据 13 值 / 负例池=真实新发
    # 语料 47 值）：h=3.6 时 P=0.30；h=4.0 达 P=0.92/R=0.92（P≥0.9 的最小 h），被挡掉的
    # 唯一正例是无上下文孤儿示例串。池规模小，随语料增长复拟合。
    MIN_ENTROPY = 4.0
    patterns = [("generic", re.compile(
        r"(?i)(?:secret|token|api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|credential)"
        r"[^\n]{0,60}?[\"']?([A-Za-z0-9+/_\-]{24,64})\b"))]

    def match(self, text: str) -> Iterator[dict]:
        for kind, rx in self.patterns:
            for m in rx.finditer(text):
                v = m.group(1)
                # 压缩/打包产物（单行超长）里全是高熵串，全部跳过——误报治理
                line = text[text.rfind("\n", 0, m.start(1)) + 1:
                            text.find("\n", m.end(1))]
                if len(line) > 400:
                    continue
                if shannon_entropy(v) >= self.MIN_ENTROPY:
                    yield {"kind": kind, "secret": v, "pos": m.start(1)}
