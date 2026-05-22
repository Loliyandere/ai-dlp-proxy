"""
addon.py (đã tích hợp Lớp 1 — Structured Logging)

Thay đổi so với bản gốc:
  - Import write_http_audit / write_ws_audit từ dlp.audit_logger
  - Gọi write_*_audit() SAU khi đã xử lý xong, TRƯỚC khi return
  - Không thay đổi logic DLP hiện có
"""

import json
import asyncio
import os

from urllib.parse import parse_qsl, urlencode
from typing import Any, Dict, Tuple

from mitmproxy import http, ctx

from dlp.dlp_engine import DLPEngine
from dlp.audit_logger import write_http_audit, write_ws_audit
from dlp.alerter import send_alert                              # ← Lớp 2   # ← MỚI


AI_DOMAINS = os.getenv(
    "AI_DLP_DOMAINS",
    "chatgpt.com,chat.openai.com,openai.com,"
    "gemini.google.com,bard.google.com,googleapis.com,"
    "claude.ai,"
    "copilot.microsoft.com,copilot.cloud.microsoft.com,bing.com,edgeservices.bing.com,"
    "deepseek.com,chat.deepseek.com,platform.deepseek.com,api.deepseek.com"
).split(",")

DLP_MODE = os.getenv("DLP_MODE", "redact")  # log, redact, block

engine = DLPEngine()


# ---------------------------------------------------------------------------
# Helpers (giữ nguyên từ bản gốc)
# ---------------------------------------------------------------------------

def is_ai_domain(host: str) -> bool:
    host = host.lower().strip()
    for domain in AI_DOMAINS:
        domain = domain.strip().lower()
        if host == domain or host.endswith("." + domain):
            return True
    return False


def should_skip_request(flow: http.HTTPFlow) -> bool:
    path = flow.request.path.lower()
    skip_paths = ["/ces/", "/ces/v1/", "/backend-api/sentinel/", "/public-api/"]
    return any(item in path for item in skip_paths)


def empty_stats() -> Dict:
    return {
        "static_replacements": 0,
        "ml_replacements": 0,
        "pii_types": {},
        "matches": [],
    }


def has_detection(stats: Dict) -> bool:
    if stats.get("static_replacements", 0) > 0: return True
    if stats.get("ml_replacements", 0) > 0:     return True
    if stats.get("pii_types"):                   return True
    if stats.get("matches"):                     return True
    return False


def merge_stats(total: Dict, child: Dict):
    total["static_replacements"] += child.get("static_replacements", 0)
    total["ml_replacements"]     += child.get("ml_replacements", 0)
    for pii_type, count in child.get("pii_types", {}).items():
        total["pii_types"][pii_type] = total["pii_types"].get(pii_type, 0) + count
    total["matches"].extend(child.get("matches", []))


PROMPT_KEYS = {"text", "prompt", "parts", "query", "input"}


def is_prompt_key(key: str) -> bool:
    return key.lower() in PROMPT_KEYS


def is_form_prompt_key(key: str) -> bool:
    return key.lower() in {"f.req", "text", "prompt", "query", "input"}


async def redact_prompt_fields(
    value: Any,
    parent_key: str = "",
    in_prompt_field: bool = False,
) -> Tuple[Any, Dict]:
    total_stats = empty_stats()
    if isinstance(value, dict):
        new_obj = {}
        for key, child in value.items():
            child_is_prompt = in_prompt_field or is_prompt_key(key)
            new_child, child_stats = await redact_prompt_fields(
                child, parent_key=key, in_prompt_field=child_is_prompt,
            )
            new_obj[key] = new_child
            merge_stats(total_stats, child_stats)
        return new_obj, total_stats
    if isinstance(value, list):
        new_list = []
        for item in value:
            new_item, item_stats = await redact_prompt_fields(
                item, parent_key=parent_key, in_prompt_field=in_prompt_field,
            )
            new_list.append(new_item)
            merge_stats(total_stats, item_stats)
        return new_list, total_stats
    if isinstance(value, str):
        if in_prompt_field:
            return await engine.redact(value)
        return value, total_stats
    return value, total_stats


async def redact_only_text_fields(value: Any) -> Tuple[Any, Dict]:
    total_stats = empty_stats()
    if isinstance(value, dict):
        new_obj = {}
        for key, child in value.items():
            if key.lower() == "text" and isinstance(child, str):
                new_child, child_stats = await engine.redact(child)
            else:
                new_child, child_stats = await redact_only_text_fields(child)
            new_obj[key] = new_child
            merge_stats(total_stats, child_stats)
        return new_obj, total_stats
    if isinstance(value, list):
        new_list = []
        for item in value:
            new_item, item_stats = await redact_only_text_fields(item)
            new_list.append(new_item)
            merge_stats(total_stats, item_stats)
        return new_list, total_stats
    return value, total_stats


async def redact_gemini_any(value: Any) -> Tuple[Any, Dict]:
    total_stats = empty_stats()
    if isinstance(value, dict):
        new_obj = {}
        for key, child in value.items():
            new_child, child_stats = await redact_gemini_any(child)
            new_obj[key] = new_child
            merge_stats(total_stats, child_stats)
        return new_obj, total_stats
    if isinstance(value, list):
        new_list = []
        for item in value:
            new_item, item_stats = await redact_gemini_any(item)
            new_list.append(new_item)
            merge_stats(total_stats, item_stats)
        return new_list, total_stats
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("[") or stripped.startswith("{"):
            try:
                nested = json.loads(stripped)
                redacted_nested, nested_stats = await redact_gemini_any(nested)
                new_string = json.dumps(redacted_nested, ensure_ascii=False, separators=(",", ":"))
                return new_string, nested_stats
            except Exception:
                pass
        return await engine.redact(value)
    return value, total_stats


async def redact_gemini_json_string(value: str) -> Tuple[str, Dict]:
    try:
        data = json.loads(value)
    except Exception:
        return await engine.redact(value)
    redacted_data, stats = await redact_gemini_any(data)
    redacted_value = json.dumps(redacted_data, ensure_ascii=False, separators=(",", ":"))
    return redacted_value, stats


async def redact_form_urlencoded_body(body: str) -> Tuple[str, Dict]:
    total_stats = empty_stats()
    pairs = parse_qsl(body, keep_blank_values=True)
    new_pairs = []
    for key, value in pairs:
        if key.lower() == "f.req":
            redacted_value, stats = await redact_gemini_json_string(value)
        elif is_form_prompt_key(key):
            redacted_value, stats = await engine.redact(value)
        else:
            redacted_value = value
            stats = empty_stats()
        new_pairs.append((key, redacted_value))
        merge_stats(total_stats, stats)
    return urlencode(new_pairs, doseq=True), total_stats


async def scan_body(body: str, content_type: str) -> Tuple[str, Dict]:
    if "application/json" in content_type:
        try:
            data = json.loads(body)
            redacted_data, stats = await redact_prompt_fields(data)
            redacted_body = json.dumps(redacted_data, ensure_ascii=False, separators=(",", ":"))
            return redacted_body, stats
        except json.JSONDecodeError:
            return body, empty_stats()
    if "application/x-www-form-urlencoded" in content_type:
        return await redact_form_urlencoded_body(body)
    return await engine.redact(body)


# ---------------------------------------------------------------------------
# mitmproxy hooks
# ---------------------------------------------------------------------------

async def request(flow: http.HTTPFlow):
    host = flow.request.pretty_host

    if not is_ai_domain(host):
        return
    if should_skip_request(flow):
        return
    if flow.request.method.upper() not in ["POST", "PUT", "PATCH"]:
        return

    body = flow.request.get_text(strict=False)
    if not body:
        return

    content_type = flow.request.headers.get("content-type", "").lower()
    redacted_body, stats = await scan_body(body, content_type)

    if not has_detection(stats):
        return

    # ── Lớp 1: ghi audit log ────────────────────────────────────────────
    event = write_http_audit(flow, stats, DLP_MODE)
    asyncio.create_task(send_alert(event))                             # ← Lớp 2
    ctx.log.info(f"[DLP] audit_event_id={event['event_id']} host={host} "
                 f"hits={event['total_hits']} action={DLP_MODE}")
    # ────────────────────────────────────────────────────────────────────

    if DLP_MODE == "log":
        return

    if DLP_MODE == "block":
        flow.response = http.Response.make(
            403,
            json.dumps({
                "error":    "Blocked by AI DLP Proxy",
                "event_id": event["event_id"],       # ← trả về event_id cho client
            }, ensure_ascii=False),
            {"Content-Type": "application/json"},
        )
        return

    if DLP_MODE == "redact":
        flow.request.set_text(redacted_body)
        ctx.log.info(f"[DLP] Redacted request to {host}{flow.request.path}")


async def websocket_message(flow: http.HTTPFlow):
    if not flow.websocket or not flow.websocket.messages:
        return

    host = flow.request.pretty_host
    if not is_ai_domain(host):
        return

    message = flow.websocket.messages[-1]
    if not message.from_client:
        return

    raw = message.content
    try:
        text = raw.decode("utf-8", errors="ignore")
    except Exception:
        return
    if not text:
        return

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        redacted_text, stats = await engine.redact(text)
        if not has_detection(stats):
            return

        # ── Lớp 1: ghi audit log (plain text frame) ─────────────────────
        event = write_ws_audit(flow, stats, DLP_MODE, frame_type="text")
        ctx.log.info(f"[DLP] WS audit_event_id={event['event_id']} action={DLP_MODE}")
        # ─────────────────────────────────────────────────────────────────

        if DLP_MODE == "log":   return
        if DLP_MODE == "block": message.drop(); return
        if DLP_MODE == "redact":
            message.content = redacted_text.encode("utf-8")
        return

    redacted_data, stats = await redact_only_text_fields(data)
    if not has_detection(stats):
        return

    # ── Lớp 1: ghi audit log (JSON frame) ───────────────────────────────
    event = write_ws_audit(flow, stats, DLP_MODE, frame_type="json")
    ctx.log.info(f"[DLP] WS audit_event_id={event['event_id']} action={DLP_MODE}")
    # ────────────────────────────────────────────────────────────────────

    if DLP_MODE == "log":   return
    if DLP_MODE == "block": message.drop(); return
    if DLP_MODE == "redact":
        new_payload = json.dumps(
            redacted_data, ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        message.content = new_payload