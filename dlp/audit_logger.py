"""
dlp/audit_logger.py
-------------------
Lớp 1: Structured Logging — Nhật ký có cấu trúc cho AI DLP Proxy.

Schema chuẩn JSON Lines (.jsonl):
- Mỗi sự kiện là 1 dòng JSON độc lập → dễ grep, stream, ingest vào ELK/Splunk.
- Không lưu giá trị gốc của PII → privacy-preserving audit.
- Thread-safe (dùng threading.Lock).
- Tự rotate log theo ngày.
"""

import json
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

# ---------------------------------------------------------------------------
# Config từ env
# ---------------------------------------------------------------------------

LOG_DIR        = Path(os.getenv("DLP_LOG_DIR", "logs"))
LOG_ROTATE     = os.getenv("DLP_LOG_ROTATE", "daily")   # daily | single
LOG_MAX_DAYS   = int(os.getenv("DLP_LOG_MAX_DAYS", "30"))  # giữ tối đa N ngày log
SERVICE_NAME   = os.getenv("DLP_SERVICE_NAME", "ai-dlp-proxy")

# ---------------------------------------------------------------------------
# Internal logger (dùng Python logging, không phải mitmproxy ctx)
# ---------------------------------------------------------------------------

_pylog = logging.getLogger("ai_dlp_proxy.audit")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    """ISO-8601 UTC timestamp, ví dụ: 2025-05-22T07:30:00Z"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today_str() -> str:
    """YYYY-MM-DD theo UTC, dùng để tạo tên file rotate."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _log_path() -> Path:
    """
    Trả về đường dẫn file log hiện tại.
    - daily  → logs/dlp_audit_2025-05-22.jsonl
    - single → logs/dlp_audit.jsonl
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    if LOG_ROTATE == "daily":
        return LOG_DIR / f"dlp_audit_{_today_str()}.jsonl"

    return LOG_DIR / "dlp_audit.jsonl"


def _sanitize_matches(matches: list) -> list:
    """
    Chỉ giữ metadata của match, BỎ giá trị gốc (value).
    Nguyên tắc: audit trail không được lưu PII lần thứ hai.
    """
    sanitized = []

    for m in matches:
        sanitized.append({
            "type":   m.get("type", "UNKNOWN"),
            "start":  m.get("start", 0),
            "end":    m.get("end", 0),
            "method": m.get("method", "unknown"),
            "score":  round(float(m.get("score", 0.0)), 4),
            # "value" bị loại bỏ có chủ đích
        })

    return sanitized


def _purge_old_logs():
    """
    Xóa log file cũ hơn DLP_LOG_MAX_DAYS ngày.
    Chỉ chạy khi LOG_ROTATE == "daily".
    """
    if LOG_ROTATE != "daily":
        return

    cutoff = time.time() - LOG_MAX_DAYS * 86400

    for f in LOG_DIR.glob("dlp_audit_*.jsonl"):
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink()
                _pylog.info(f"[AuditLogger] Purged old log: {f.name}")
        except Exception as e:
            _pylog.warning(f"[AuditLogger] Could not purge {f.name}: {e}")


# ---------------------------------------------------------------------------
# AuditLogger class
# ---------------------------------------------------------------------------

class AuditLogger:
    """
    Thread-safe, rotation-aware structured logger.

    Mỗi event được ghi dưới dạng 1 dòng JSON (JSON Lines format).
    """

    _instance: Optional["AuditLogger"] = None
    _lock     = threading.Lock()
    _file_lock = threading.Lock()

    # Singleton — toàn bộ addon dùng chung 1 instance
    def __new__(cls) -> "AuditLogger":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._initialized = True
        self._last_purge_day = ""

        _pylog.info(
            f"[AuditLogger] Started. log_dir={LOG_DIR}, "
            f"rotate={LOG_ROTATE}, max_days={LOG_MAX_DAYS}"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log_event(
        self,
        *,
        action:     str,
        host:       str,
        path:       str,
        method:     str,
        stats:      Dict[str, Any],
        user_agent: str = "",
        client_ip:  str = "",
        extra:      Optional[Dict] = None,
    ) -> Dict:
        """
        Ghi 1 audit event vào file log.

        Trả về dict event đã ghi (tiện dùng để gửi alert sau).

        Parameters
        ----------
        action      : "log" | "redact" | "block"
        host        : domain đích, ví dụ "claude.ai"
        path        : request path
        method      : HTTP method
        stats       : dict từ DLPEngine.redact()
        user_agent  : User-Agent header (optional)
        client_ip   : IP client (optional, có thể ẩn nếu cần)
        extra       : metadata tùy ý thêm vào event
        """

        event = self._build_event(
            action=action,
            host=host,
            path=path,
            method=method,
            stats=stats,
            user_agent=user_agent,
            client_ip=client_ip,
            extra=extra or {},
        )

        self._write(event)
        self._maybe_purge()

        return event

    def log_websocket_event(
        self,
        *,
        action:     str,
        host:       str,
        frame_type: str,        # "text" | "json"
        stats:      Dict[str, Any],
        extra:      Optional[Dict] = None,
    ) -> Dict:
        """
        Ghi audit event cho WebSocket message.
        """

        event = self._build_event(
            action=action,
            host=host,
            path="<websocket>",
            method="WS",
            stats=stats,
            extra={"frame_type": frame_type, **(extra or {})},
        )

        self._write(event)
        self._maybe_purge()

        return event

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_event(
        self,
        *,
        action:     str,
        host:       str,
        path:       str,
        method:     str,
        stats:      Dict[str, Any],
        user_agent: str = "",
        client_ip:  str = "",
        extra:      Optional[Dict] = None,
    ) -> Dict:
        """Xây dựng dict event chuẩn, KHÔNG chứa giá trị PII gốc."""

        total_hits = (
            stats.get("static_replacements", 0)
            + stats.get("ml_replacements", 0)
        )

        event: Dict[str, Any] = {
            # --- định danh ---
            "event_id":   str(uuid.uuid4()),
            "timestamp":  _utc_now_iso(),
            "service":    SERVICE_NAME,

            # --- request context ---
            "action":     action,           # log | redact | block
            "host":       host,
            "path":       path,
            "method":     method,

            # --- DLP summary ---
            "total_hits":          total_hits,
            "static_replacements": stats.get("static_replacements", 0),
            "ml_replacements":     stats.get("ml_replacements", 0),
            "pii_types":           stats.get("pii_types", {}),

            # --- chi tiết match, ĐÃ loại bỏ giá trị gốc ---
            "matches": _sanitize_matches(stats.get("matches", [])),

            # --- client info (có thể ẩn tuỳ policy) ---
            "user_agent": user_agent,
            "client_ip":  client_ip,
        }

        if extra:
            event["extra"] = dict(extra)   # defensive copy

        return event

    def _write(self, event: Dict):
        """Ghi 1 dòng JSON vào file log. Thread-safe."""

        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))

        with self._file_lock:
            log_file = _log_path()

            try:
                with log_file.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")

            except OSError as e:
                _pylog.error(f"[AuditLogger] Failed to write log: {e}")

    def _maybe_purge(self):
        """Xóa log cũ 1 lần/ngày."""
        today = _today_str()

        if today != self._last_purge_day:
            self._last_purge_day = today
            _purge_old_logs()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

audit_logger = AuditLogger()


# ---------------------------------------------------------------------------
# Convenience function — dùng trực tiếp trong addon.py
# ---------------------------------------------------------------------------

def write_http_audit(
    flow,
    stats:  Dict[str, Any],
    action: str,
) -> Dict:
    """
    Shortcut: gọi audit_logger.log_event() từ mitmproxy HTTPFlow.

    Trả về event dict (để gửi alert).
    """
    # Preserve infected_files from stats into the audit record so forensic
    # queries can answer "which file triggered the block" without re-scanning.
    extra: Dict[str, Any] = {}
    if stats.get("infected_files"):
        extra["infected_files"] = stats["infected_files"]

    return audit_logger.log_event(
        action     = action,
        host       = flow.request.pretty_host,
        path       = flow.request.path,
        method     = flow.request.method,
        stats      = stats,
        user_agent = flow.request.headers.get("user-agent", ""),
        client_ip  = flow.client_conn.peername[0]
                     if flow.client_conn and flow.client_conn.peername
                     else "",
        extra      = extra,
    )


def write_ws_audit(
    flow,
    stats:      Dict[str, Any],
    action:     str,
    frame_type: str = "json",
) -> Dict:
    """
    Shortcut: gọi audit_logger.log_websocket_event() từ mitmproxy HTTPFlow.

    Trả về event dict (để gửi alert).
    """
    return audit_logger.log_websocket_event(
        action     = action,
        host       = flow.request.pretty_host,
        frame_type = frame_type,
        stats      = stats,
    )