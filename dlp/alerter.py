"""
dlp/alerter.py
--------------
Lớp 2: Real-time Alerting qua Telegram Bot.

Setup:
  1. Tạo bot: nhắn @BotFather trên Telegram → /newbot → lấy BOT_TOKEN
  2. Lấy chat_id: nhắn bot 1 tin, rồi vào
     https://api.telegram.org/bot<TOKEN>/getUpdates
     → lấy "chat":{"id": ...}
  3. Set env:
       DLP_TELEGRAM_TOKEN=123456:ABC-xxx
       DLP_TELEGRAM_CHAT_ID=-100123456789

Env vars:
  DLP_TELEGRAM_TOKEN      Bot token từ @BotFather (bắt buộc)
  DLP_TELEGRAM_CHAT_ID    Chat ID nhận alert (bắt buộc)
  DLP_ALERT_THRESHOLD     Số hits tối thiểu để gửi alert (mặc định 1)
  DLP_ALERT_DEBOUNCE_SEC  Không spam cùng host trong N giây (mặc định 60)
  DLP_ALERT_MODE          all | block_only (mặc định all)
"""

import asyncio
import logging
import os
import time
from typing import Dict, Optional

import httpx

_log = logging.getLogger("ai_dlp_proxy.alerter")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

TELEGRAM_TOKEN    = os.getenv("DLP_TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID  = os.getenv("DLP_TELEGRAM_CHAT_ID", "")
ALERT_THRESHOLD   = int(os.getenv("DLP_ALERT_THRESHOLD", "1"))
DEBOUNCE_SEC      = int(os.getenv("DLP_ALERT_DEBOUNCE_SEC", "60"))
ALERT_MODE        = os.getenv("DLP_ALERT_MODE", "all")   # all | block_only

TELEGRAM_API      = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"

# ---------------------------------------------------------------------------
# Debounce state  {host: last_alert_timestamp}
# ---------------------------------------------------------------------------

_last_alert: Dict[str, float] = {}
_debounce_lock = asyncio.Lock()


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

_ACTION_EMOJI = {
    "log":    "📝",
    "redact": "✏️",
    "block":  "🚫",
}

_PII_EMOJI = {
    "EMAIL_ADDRESS": "📧",
    "PHONE_NUMBER":  "📞",
    "CREDIT_CARD":   "💳",
    "PERSON":        "👤",
    "LOCATION":      "📍",
    "ORGANIZATION":  "🏢",
    "IP_ADDRESS":    "🌐",
    "URL":           "🔗",
    "DATE_TIME":     "📅",
    "STATIC_TERM":   "🔑",
}


def _format_pii_types(pii_types: Dict[str, int]) -> str:
    """Ví dụ: 📧 EMAIL×2  💳 CREDIT_CARD×1"""
    if not pii_types:
        return "—"
    parts = []
    for pii_type, count in pii_types.items():
        emoji = _PII_EMOJI.get(pii_type, "⚠️")
        parts.append(f"{emoji} `{pii_type}`×{count}")
    return "  ".join(parts)


def _build_message(event: Dict) -> str:
    """
    Tạo message Telegram dạng Markdown (MarkdownV2).
    Telegram parse_mode=HTML dễ escape hơn nên dùng HTML.
    """
    action     = event.get("action", "unknown")
    host       = event.get("host", "unknown")
    path       = event.get("path", "")
    method     = event.get("method", "")
    total_hits = event.get("total_hits", 0)
    pii_types  = event.get("pii_types", {})
    event_id   = event.get("event_id", "")[:8]   # 8 ký tự đầu đủ dùng
    timestamp  = event.get("timestamp", "")
    static_n   = event.get("static_replacements", 0)
    ml_n       = event.get("ml_replacements", 0)
    frame_type = event.get("extra", {}).get("frame_type", "")

    emoji  = _ACTION_EMOJI.get(action, "⚠️")
    pii_str = _format_pii_types(pii_types)

    # WebSocket hay HTTP
    conn_label = f"WS ({frame_type})" if method == "WS" else f"HTTP {method}"

    lines = [
        f"{emoji} <b>DLP {action.upper()}</b>",
        f"",
        f"🌐 <b>Host:</b> <code>{host}</code>",
        f"🔀 <b>Endpoint:</b> <code>{conn_label} {path}</code>",
        f"",
        f"🔍 <b>Tổng hits:</b> {total_hits}  "
        f"(static: {static_n}, ML: {ml_n})",
        f"📋 <b>PII phát hiện:</b>",
        f"    {pii_str}",
        f"",
        f"🕐 <code>{timestamp}</code>",
        f"🆔 event: <code>{event_id}…</code>",
    ]

    if action == "block":
        lines.insert(1, "")
        lines.insert(1, "⛔️ <b>Request đã bị chặn hoàn toàn!</b>")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core send
# ---------------------------------------------------------------------------

async def _send_telegram(text: str) -> bool:
    """Gửi message tới Telegram, trả về True nếu thành công."""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        _log.warning("[Alerter] Telegram chưa cấu hình "
                     "(DLP_TELEGRAM_TOKEN / DLP_TELEGRAM_CHAT_ID)")
        return False

    payload = {
        "chat_id":    TELEGRAM_CHAT_ID,
        "text":       text,
        "parse_mode": "HTML",
    }

    try:
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.post(TELEGRAM_API, json=payload)

        if resp.status_code == 200:
            return True

        _log.error(f"[Alerter] Telegram trả về {resp.status_code}: {resp.text[:200]}")
        return False

    except httpx.TimeoutException:
        _log.error("[Alerter] Telegram request timeout")
        return False

    except Exception as e:
        _log.error(f"[Alerter] Lỗi gửi Telegram: {e}")
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def send_alert(event: Dict) -> bool:
    """
    Gửi alert Telegram nếu đủ điều kiện.

    Điều kiện:
      1. total_hits >= DLP_ALERT_THRESHOLD
      2. Không bị debounce (host chưa alert trong DEBOUNCE_SEC giây)
      3. ALERT_MODE phù hợp (all hoặc block_only)

    Trả về True nếu thực sự gửi đi.
    """

    total_hits = event.get("total_hits", 0)
    action     = event.get("action", "")
    host       = event.get("host", "unknown")

    # --- filter theo threshold ---
    if total_hits < ALERT_THRESHOLD:
        return False

    # --- filter theo mode ---
    if ALERT_MODE == "block_only" and action != "block":
        return False

    # --- debounce ---
    async with _debounce_lock:
        now      = time.monotonic()
        last     = _last_alert.get(host, 0.0)

        if now - last < DEBOUNCE_SEC:
            _log.debug(f"[Alerter] Debounce {host}, bỏ qua alert")
            return False

        _last_alert[host] = now

    # --- gửi ---
    message = _build_message(event)
    ok = await _send_telegram(message)

    if ok:
        _log.info(f"[Alerter] Đã gửi Telegram alert: host={host} action={action}")

    return ok


def send_alert_sync(event: Dict) -> None:
    """
    Wrapper đồng bộ — dùng khi không có event loop sẵn.
    Tự tạo loop tạm để gửi.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(send_alert(event))
        else:
            loop.run_until_complete(send_alert(event))
    except RuntimeError:
        asyncio.run(send_alert(event))