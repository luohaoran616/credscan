"""credscan 响应层：告警分发 + 可插拔处置 + 蜜凭据（honeytoken）闭环。

三平面模型的执行端（docs §5.9）：检测面只"旁观"公开渠道；响应动作通过告警
打回企业侧（webhook/工单），处置只对**自有蜜凭据**执行——即为了度量泄露窗口，
由我们自己创建、植入公开渠道的牺牲凭据（同 GitGuardian honeytoken 模式）。

三条红线（答辩必问，tests 强制）：
1. 默认 dry-run：处置动作只记事件不执行；live 需 --respond 且 CREDSCAN_RESPOND_LIVE=1。
2. 只处置自有蜜凭据：secret_sha256 必须预先登记在 honeytokens.json；
   第三方泄露凭据永远只告警、绝不触碰（刑法 285 条红线，见 docs §5.6）。
3. 告警载荷永不含完整明文：Finding 本身只带 sha256+脱敏预览，这里原样转发。

全链路留痕：检测→告警→处置每步写 events 表，构成"泄露窗口"时间戳链（评分轴⑤证据）。
纯标准库，零第三方依赖；HTTP 走模块级 _http_post 便于测试注入。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from .core import Finding, Store, now_iso

UA = {"User-Agent": "credscan/1.0 (research; contest entry)", "Content-Type": "application/json"}
TIMEOUT = 15
DEFAULT_REGISTRY = "honeytokens.json"


def _http_post(url: str, body: bytes, headers: dict, timeout: int = TIMEOUT) -> tuple:
    """返回 (status_code, resp_bytes)。模块级函数，测试用 monkeypatch 替换。"""
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read()


# ---------------------------------------------------------------- 告警 sink

class AlertSink:
    """告警出口插件：emit 收到的永远是脱敏 Finding 视图。"""
    id = ""

    def emit(self, payload: dict) -> None:
        raise NotImplementedError


class ConsoleSink(AlertSink):
    id = "console"

    def emit(self, payload: dict) -> None:
        print(f"[ALERT] {payload['confidence']:<6} {payload['detector']:<24} "
              f"{payload['preview']:<10} @ {payload['source_uri']}", file=sys.stderr)


class JsonlSink(AlertSink):
    """追加写 JSONL：展示层（panel）与事后分析的告警流。"""
    id = "jsonl"

    def __init__(self, path: str):
        self.path = Path(path)

    def emit(self, payload: dict) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False) + "\n")


class WebhookSink(AlertSink):
    """POST 脱敏 JSON 到部署方 webhook（企业侧再接钉钉/Slack/工单）。"""
    id = "webhook"

    def __init__(self, url: str):
        self.url = url

    def emit(self, payload: dict) -> None:
        _http_post(self.url, json.dumps(payload, ensure_ascii=False).encode("utf-8"), UA)


def alert_payload(f: Finding) -> dict:
    """告警载荷：字段白名单，永不携带完整明文（Finding 里本来也没有）。"""
    return {
        "type": "credscan.alert",
        "ts": f.ts,
        "channel": f.channel,
        "detector": f.detector,
        "severity": f.severity,
        "confidence": f.confidence,
        "preview": f.preview,             # 脱敏预览 LTA…1D
        "secret_sha256": f.secret_sha256, # 只存哈希（红线）
        "source_uri": f.source_uri,
        "published_at": f.published_at,
        "latency_sec": f.latency_sec,
    }


# ---------------------------------------------------------------- 蜜凭据登记

class Registry:
    """honeytokens.json：自有牺牲凭据登记表（只有 sha256，无明文）。

    条目：{sha256: {provider, user_name, access_key_id, note, planted_at}}
    """

    def __init__(self, path: str = DEFAULT_REGISTRY):
        self.path = Path(path)
        self.entries: Dict[str, dict] = {}
        self._mtime: float = -1.0
        self._reload_if_changed()

    def _reload_if_changed(self) -> None:
        """热加载：CLI/人工在 daemon 常驻期间新增登记无需重启（mtime 感知）。

        文件缺失/读取失败时保留当前内存快照——登记表短暂不可用不应使
        常驻 daemon 丢失已加载的蜜凭据记忆。
        """
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            return
        if mtime == self._mtime:
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return                              # 损坏文件：保留旧快照，不中断扫描
        self.entries, self._mtime = data, mtime

    def get(self, secret_sha256: str) -> Optional[dict]:
        self._reload_if_changed()
        return self.entries.get(secret_sha256)

    @staticmethod
    def make_entry(secret: str, provider: str, user_name: str, access_key_id: str,
                   note: str = "") -> tuple:
        """返回 (sha256, entry)。secret 只在此处出现一次，绝不落盘/打日志。"""
        sha = hashlib.sha256(secret.encode("utf-8", "ignore")).hexdigest()
        return sha, {
            "provider": provider,
            "user_name": user_name,
            "access_key_id": access_key_id,
            "note": note,
            "planted_at": now_iso(),
        }

    def add(self, secret: str, provider: str, user_name: str, access_key_id: str,
            note: str = "") -> dict:
        sha, entry = self.make_entry(secret, provider, user_name, access_key_id, note)
        self.entries[sha] = entry
        self.path.write_text(json.dumps(self.entries, ensure_ascii=False, indent=2),
                             encoding="utf-8")
        self.path.chmod(0o600)          # 登记表可反推凭据归属，收紧权限
        return {"sha256": sha, **entry}


# ---------------------------------------------------------------- 处置 provider

class ResponseProvider:
    """处置插件基类。execute 只应被 Responder 在蜜凭据命中时调用。"""
    id = ""

    def execute(self, finding: Finding, meta: dict, live: bool) -> dict:
        raise NotImplementedError


def _penc(v) -> str:
    """阿里云 RPC 签名的 RFC3986 百分号编码。"""
    return urllib.parse.quote(str(v), safe="-_.~")


def _rpc_call(action: str, extra: dict, ak_id: str, ak_secret: str) -> dict:
    """阿里云 RAM RPC API（HMAC-SHA1 签名，纯标准库实现）。

    POST https://ram.aliyuncs.com/ ，签名算法：StringToSign = "POST&%2F&" + pct(canonical_qs)。
    """
    params = {
        "Action": action,
        "Format": "JSON",
        "Version": "2015-05-01",
        "AccessKeyId": ak_id,
        "SignatureMethod": "HMAC-SHA1",
        "SignatureVersion": "1.0",
        "SignatureNonce": uuid.uuid4().hex,
        "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        **extra,
    }
    canonical = "&".join(f"{_penc(k)}={_penc(v)}" for k, v in sorted(params.items()))
    string_to_sign = "POST&%2F&" + _penc(canonical)
    digest = hmac.new((ak_secret + "&").encode("utf-8"), string_to_sign.encode("utf-8"),
                      hashlib.sha1).digest()
    params["Signature"] = base64.b64encode(digest).decode("ascii")
    body = "&".join(f"{_penc(k)}={_penc(v)}" for k, v in sorted(params.items()))
    status, raw = _http_post("https://ram.aliyuncs.com/", body.encode("utf-8"),
                             {"Content-Type": "application/x-www-form-urlencoded",
                              "User-Agent": UA["User-Agent"]})
    return {"http_status": status, "resp": raw.decode("utf-8", "ignore")}


class AliyunRAMProvider(ResponseProvider):
    """自有蜜凭据处置：UpdateAccessKey → Inactive（禁用牺牲 AK）。

    凭据从环境变量读（管理员 AK，与被处置的牺牲 AK 分离）：
      CREDSCAN_DEMO_ALIYUN_AK_ID / CREDSCAN_DEMO_ALIYUN_AK_SECRET
    """

    id = "aliyun_ram"

    def execute(self, finding: Finding, meta: dict, live: bool) -> dict:
        action = "aliyun.ram.UpdateAccessKey(Inactive)"
        if not live:
            return {"action": action, "status": "dry_run",
                    "detail": f"would disable {meta.get('access_key_id')} "
                              f"(user={meta.get('user_name')})"}
        ak_id = os.environ.get("CREDSCAN_DEMO_ALIYUN_AK_ID", "")
        ak_secret = os.environ.get("CREDSCAN_DEMO_ALIYUN_AK_SECRET", "")
        if not ak_id or not ak_secret:
            return {"action": action, "status": "error",
                    "detail": "missing CREDSCAN_DEMO_ALIYUN_AK_ID/SECRET env"}
        out = _rpc_call("UpdateAccessKey",
                        {"UserAccessKeyId": meta["access_key_id"],
                         "Status": "Inactive",
                         "UserName": meta.get("user_name", "")},
                        ak_id, ak_secret)
        ok = out["http_status"] == 200
        return {"action": action, "status": "ok" if ok else "error", "detail": out["resp"][:300]}

    def describe(self, meta: dict) -> dict:
        """闭环验证：查询牺牲 AK 当前状态（ListAccessKeys）。"""
        ak_id = os.environ.get("CREDSCAN_DEMO_ALIYUN_AK_ID", "")
        ak_secret = os.environ.get("CREDSCAN_DEMO_ALIYUN_AK_SECRET", "")
        if not ak_id or not ak_secret:
            return {"action": "aliyun.ram.ListAccessKeys", "status": "error",
                    "detail": "missing env"}
        out = _rpc_call("ListAccessKeys",
                        {"UserName": meta.get("user_name", "")}, ak_id, ak_secret)
        return {"action": "aliyun.ram.ListAccessKeys",
                "status": "ok" if out["http_status"] == 200 else "error",
                "detail": out["resp"][:600]}


# ---------------------------------------------------------------- 编排

class Responder:
    """新 Finding 入库后的编排：告警（按置信过滤）→ 蜜凭据命中则处置。

    告警失败不影响扫描主流程；处置只针对 Registry 命中的自有蜜凭据。
    """

    def __init__(self, sinks: list, providers: dict, registry: Registry,
                 store: Store, live: bool = False,
                 alert_on: tuple = ("strong", "medium")):
        self.sinks = sinks
        self.providers = providers
        self.registry = registry
        self.store = store
        self.live = live
        self.alert_on = set(alert_on)

    def on_new_finding(self, f: Finding) -> None:
        dedup = self.store.dedup_key(f)
        if f.confidence in self.alert_on:
            payload = alert_payload(f)
            for sink in self.sinks:
                try:
                    sink.emit(payload)
                    self.store.log_event("alert", dedup, f"sink:{sink.id}", "ok",
                                         f"{f.detector} {f.preview}")
                except Exception as e:  # 告警出口故障不拖垮扫描
                    self.store.log_event("alert", dedup, f"sink:{sink.id}", "error", str(e)[:200])
        meta = self.registry.get(f.secret_sha256)
        if meta is None:
            return  # 第三方凭据：只告警，到此为止（红线②）
        provider = self.providers.get(meta.get("provider", ""))
        if provider is None:
            self.store.log_event("response", dedup, meta.get("provider", "?"),
                                 "error", "unknown provider")
            return
        try:
            result = provider.execute(f, meta, self.live)
            self.store.log_event("response", dedup, result["action"], result["status"],
                                 result["detail"])
        except Exception as e:
            self.store.log_event("response", dedup, provider.id, "error", str(e)[:200])


def live_enabled(flag_respond: bool) -> bool:
    """live 双开关：命令行 --respond 且环境变量 CREDSCAN_RESPOND_LIVE=1。"""
    return bool(flag_respond) and os.environ.get("CREDSCAN_RESPOND_LIVE") == "1"
