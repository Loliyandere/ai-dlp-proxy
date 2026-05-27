"""
addon.py — AI DLP Proxy
Tích hợp: audit log, Telegram alert, rule engine, file upload scanning
"""

import asyncio
import email.parser
import json
import os
import time
from urllib.parse import parse_qsl, urlencode, urlparse, parse_qs
from typing import Any, Dict, List, Optional, Tuple

from mitmproxy import http, ctx

from dlp.dlp_engine     import DLPEngine
from dlp.audit_logger   import write_http_audit, write_ws_audit
from dlp.alerter        import send_alert
from dlp.file_extractor import extract_text
from dlp.rule_engine    import rule_engine


AI_DOMAINS = os.getenv(
    "AI_DLP_DOMAINS",
    "chatgpt.com,chat.openai.com,openai.com,"
    "gemini.google.com,bard.google.com,googleapis.com,"
    "claude.ai,anthropic.com,"
    "copilot.microsoft.com,copilot.cloud.microsoft.com,bing.com,edgeservices.bing.com,"
    "deepseek.com,chat.deepseek.com,platform.deepseek.com,api.deepseek.com"
).split(",")

# Hosts dùng để lưu file (S3 / Azure Blob / GCS) — chỉ xử lý bởi LUỒNG 0.
# KHÔNG chạy LUỒNG 2 (text/JSON redact) trên các host này vì:
#   1. Body là binary (PDF/DOCX) → Presidio sẽ ra false positive
#   2. Redact làm hỏng body → Azure/GCS từ chối vì signature không khớp
FILE_STORAGE_HOSTS = os.getenv(
    "DLP_FILE_STORAGE_HOSTS",
    "oaiusercontent.com,"          # ChatGPT / OpenAI (Azure)
    "storage.googleapis.com,"     # Gemini / Google Cloud Storage
    "blob.core.windows.net,"      # Azure Blob generic
    "s3.amazonaws.com"            # AWS S3 generic
).split(",")


def is_file_storage_host(host: str) -> bool:
    host = host.lower().strip()
    for h in FILE_STORAGE_HOSTS:
        h = h.strip().lower()
        if h and (host == h or host.endswith("." + h)):
            return True
    return False

DLP_MODE = os.getenv("DLP_MODE", "redact")
engine   = DLPEngine()

# TTL (seconds) cho mỗi entry trong _pending_uploads — tự xóa nếu không dùng
_PENDING_UPLOAD_TTL = int(os.getenv("DLP_PENDING_UPLOAD_TTL", "300"))

# {url_key: (filename, registered_at_epoch)}
_pending_uploads: Dict[str, Tuple[str, float]] = {}


# ── Helpers ───────────────────────────────────────────────────────────────────

def is_ai_domain(host: str) -> bool:
    host = host.lower().strip()
    for domain in AI_DOMAINS:
        d = domain.strip().lower()
        if host == d or host.endswith("." + d):
            return True
    return False


def should_skip_request(flow: http.HTTPFlow) -> bool:
    path = flow.request.path.lower()
    skip_paths = ["/ces/", "/ces/v1/", "/backend-api/sentinel/", "/public-api/"]
    return any(item in path for item in skip_paths)


UPLOAD_PATTERNS = [
    "/backend-api/files",
    "/backend-anon/files",
    "/api/v0/file/upload_file",
    "/c/api/attachments",
]


def is_file_upload_endpoint(path: str) -> bool:
    path = path.lower()
    skip_sub = ["/process_upload", "/library", "/fetch_files", "/cancel"]
    if any(s in path for s in skip_sub):
        return False
    return any(p in path for p in UPLOAD_PATTERNS)


def get_upload_filename(flow: http.HTTPFlow) -> str:
    """
    Lấy filename của file upload.
    Thứ tự ưu tiên:
      1. Header Content-Disposition ở cấp request
      2. Custom headers X-Filename / X-File-Name / X-Original-Filename
      3. Query param filename / file_name / name
      4. Multipart body — tìm filename trong Content-Disposition của từng part
      5. Suy ra từ Content-Type
      6. Fallback: "upload.bin"
    """
    # 1. Request-level Content-Disposition
    disposition = flow.request.headers.get("content-disposition", "")
    if "filename=" in disposition:
        for part in disposition.split(";"):
            part = part.strip()
            if part.lower().startswith("filename="):
                return part[9:].strip('"\'')

    # 2. Custom headers
    for h in ("x-filename", "x-file-name", "x-original-filename"):
        val = flow.request.headers.get(h, "")
        if val:
            return val

    # 3. Query params
    params = parse_qs(urlparse(flow.request.path).query)
    for key in ("filename", "file_name", "name"):
        if key in params:
            return params[key][0]

    # 4. Parse multipart body để tìm filename trong từng part
    ct = flow.request.headers.get("content-type", "")
    if "multipart/form-data" in ct.lower():
        try:
            body = flow.request.get_content()
            raw_msg = b"Content-Type: " + ct.encode() + b"\r\n\r\n" + body
            parser = email.parser.BytesParser()
            msg = parser.parsebytes(raw_msg)
            for part in msg.walk():
                part_disposition = part.get("Content-Disposition", "")
                fn = part.get_filename()
                if fn:
                    return fn
        except Exception:
            pass

    # 5. Suy ra từ Content-Type của request
    ext_map = {
        "application/pdf":   "upload.pdf",
        "wordprocessingml":  "upload.docx",
        "spreadsheetml":     "upload.xlsx",
        "text/plain":        "upload.txt",
        "text/csv":          "upload.csv",
    }
    for mime, name in ext_map.items():
        if mime in ct:
            return name

    return "upload.bin"


def empty_stats() -> Dict:
    return {"static_replacements": 0, "ml_replacements": 0, "pii_types": {}, "matches": []}


def has_detection(stats: Dict) -> bool:
    return bool(
        stats.get("static_replacements")
        or stats.get("ml_replacements")
        or stats.get("pii_types")
        or stats.get("matches")
    )


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


# ── Prompt redaction ──────────────────────────────────────────────────────────

async def redact_prompt_fields(value: Any, parent_key: str = "", in_prompt_field: bool = False) -> Tuple[Any, Dict]:
    total_stats = empty_stats()
    if isinstance(value, dict):
        new_obj = {}
        for key, child in value.items():
            child_is_prompt = in_prompt_field or is_prompt_key(key)
            new_child, child_stats = await redact_prompt_fields(child, parent_key=key, in_prompt_field=child_is_prompt)
            new_obj[key] = new_child
            merge_stats(total_stats, child_stats)
        return new_obj, total_stats
    if isinstance(value, list):
        new_list = []
        for item in value:
            new_item, item_stats = await redact_prompt_fields(item, parent_key=parent_key, in_prompt_field=in_prompt_field)
            new_list.append(new_item)
            merge_stats(total_stats, item_stats)
        return new_list, total_stats
    if isinstance(value, str) and in_prompt_field:
        return await engine.redact(value)
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
                return json.dumps(redacted_nested, ensure_ascii=False, separators=(",", ":")), nested_stats
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
    return json.dumps(redacted_data, ensure_ascii=False, separators=(",", ":")), stats


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


# ── File upload scanning ──────────────────────────────────────────────────────

async def scan_raw_file_upload(flow: http.HTTPFlow) -> Tuple[Dict, str, List]:
    """
    Scan file upload request. Trả về (stats, filename, infected_files).

    Hai trường hợp:
    - multipart/form-data  : parse từng part, extract text từ file bytes thật sự.
                             Đây là trường hợp upload qua trình duyệt (ChatGPT, Claude, v.v.)
    - Raw binary (PUT/body): đọc thẳng bytes, extract text rồi scan.
                             Đây là trường hợp PUT lên S3 pre-signed URL.

    Bug đã sửa (Bug #1/2): trước đây cả hai trường hợp đều dùng extract_text trực tiếp
    trên toàn bộ body, dẫn đến magic byte detection thất bại vì multipart bắt đầu bằng
    "--boundary" chứ không phải %PDF hay PK\x03\x04. File PDF/DOCX với PII bên trong
    sẽ không bao giờ bị phát hiện.
    """
    body         = flow.request.get_content()
    content_type = flow.request.headers.get("content-type", "").lower()
    filename     = get_upload_filename(flow)

    # ── Trường hợp 1: multipart/form-data ────────────────────────────────────
    # Dùng scan_multipart để parse đúng từng part, lấy bytes thực của file.
    if "multipart/form-data" in content_type:
        ctx.log.info(f"[DLP] Multipart file upload at upload endpoint — parsing parts...")
        _, stats, infected_files = await scan_multipart(body, content_type)
        if has_detection(stats):
            ctx.log.warn(f"[DLP] PII in multipart upload parts: {stats['pii_types']}")
        return stats, filename, infected_files

    # ── Trường hợp 2: Raw binary body (PUT lên S3, API upload không dùng form) ─
    ctx.log.info(f"[DLP] Raw binary upload: '{filename}' ({len(body):,} bytes)")
    result = extract_text(body, filename)
    if result is None:
        ctx.log.info(f"[DLP] Skipped (unsupported or empty): '{filename}'")
        return empty_stats(), filename, []
    ctx.log.info(f"[DLP] Extracted {result.char_count:,} chars from '{filename}'")
    _, stats = await engine.redact(result.text)
    if has_detection(stats):
        ctx.log.warn(f"[DLP] PII in upload '{filename}': {stats['pii_types']}")
    return stats, filename, []


async def scan_multipart(body: bytes, content_type: str) -> Tuple[Optional[bytes], Dict, List]:
    total_stats    = empty_stats()
    infected_files = []
    raw_msg = b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + body
    parser  = email.parser.BytesParser()
    msg     = parser.parsebytes(raw_msg)
    for part in msg.walk():
        disposition = part.get("Content-Disposition", "")
        if "filename=" not in disposition:
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            field_name = ""
            for item in disposition.split(";"):
                item = item.strip()
                if item.startswith('name="'):
                    field_name = item[6:-1]
            if is_form_prompt_key(field_name):
                text = payload.decode("utf-8", errors="ignore")
                _, stats = await engine.redact(text)
                merge_stats(total_stats, stats)
            continue
        filename = part.get_filename() or "unknown_file"
        payload  = part.get_payload(decode=True)
        if not payload:
            continue
        ctx.log.info(f"[DLP] Scanning attachment: {filename} ({len(payload):,} bytes)")
        result = extract_text(payload, filename)
        if result is None:
            continue
        _, stats = await engine.redact(result.text)
        merge_stats(total_stats, stats)
        if has_detection(stats):
            infected_files.append({"filename": filename, "file_type": result.file_type, "pii_types": stats["pii_types"]})
            ctx.log.warn(f"[DLP] PII in '{filename}': {stats['pii_types']}")
    return body, total_stats, infected_files


async def scan_body(body: bytes, content_type: str) -> Tuple[Optional[bytes], Dict, List]:
    infected_files = []
    if "multipart/form-data" in content_type:
        return await scan_multipart(body, content_type)
    body_str = body.decode("utf-8", errors="ignore")
    if "application/json" in content_type:
        try:
            data = json.loads(body_str)
            redacted_data, stats = await redact_prompt_fields(data)
            redacted_body = json.dumps(redacted_data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            return redacted_body, stats, infected_files
        except json.JSONDecodeError:
            return body, empty_stats(), infected_files
    if "application/x-www-form-urlencoded" in content_type:
        redacted_str, stats = await redact_form_urlencoded_body(body_str)
        return redacted_str.encode("utf-8"), stats, infected_files
    redacted_str, stats = await engine.redact(body_str)
    return redacted_str.encode("utf-8"), stats, infected_files


def block_response(flow: http.HTTPFlow, event_id: str, reason: str, extra: dict = {}):
    flow.response = http.Response.make(
        403,
        json.dumps({"error": reason, "event_id": event_id, **extra}, ensure_ascii=False),
        {"Content-Type": "application/json"},
    )


# ── mitmproxy hooks ───────────────────────────────────────────────────────────

async def request(flow: http.HTTPFlow):
    host = flow.request.pretty_host

    # ── LUỒNG 0: Pre-signed S3/CDN upload ────────────────────────────────────
    # url_key được lưu mà không có query params (chỉ scheme+host+path).
    # request_url có thể có query string (X-Amz-Algorithm=...) → dùng startswith.
    #
    # Bug #3 đã sửa: điều kiện cũ "url_key.startswith(f'https://{host}')" là backwards —
    # nó so sánh URL đã lưu với host của request hiện tại, không phải ngược lại.
    # Điều này khiến bất kỳ request nào tới cùng CDN host đều khớp với entry đầu tiên
    # trong _pending_uploads, bất kể path là gì.
    # Điều kiện đúng: request URL hiện tại phải bắt đầu bằng url_key đã lưu.

    # Dọn dẹp các entry đã hết TTL trước khi match
    now = time.monotonic()
    expired_keys = [k for k, (_, ts) in list(_pending_uploads.items()) if now - ts > _PENDING_UPLOAD_TTL]
    for k in expired_keys:
        _pending_uploads.pop(k, None)
        ctx.log.debug(f"[DLP] Expired pending upload entry: {k}")

    request_url = f"https://{host}{flow.request.path}"
    matched_filename = None
    matched_url_key  = None
    for url_key, (filename, _ts) in list(_pending_uploads.items()):
        # Chỉ dùng prefix match theo path — KHÔNG dùng host-level fallback
        if request_url.startswith(url_key):
            matched_filename = filename
            matched_url_key  = url_key
            break

    if matched_filename:
        method = flow.request.method.upper()

        # Bug fix: OPTIONS là CORS preflight — trình duyệt gửi trước mỗi PUT thật.
        # Nếu pop entry ở đây, PUT thật sẽ không còn entry để match → rơi vào LUỒNG 2
        # → Presidio scan binary body → false positive → body bị corrupt → Azure reject.
        # Fix: chỉ pop và scan khi method là write (PUT/POST/PATCH).
        if method in ("PUT", "POST", "PATCH"):
            _pending_uploads.pop(matched_url_key, None)
            body = flow.request.get_content()
            if body and len(body) > 512:
                ctx.log.info(f"[DLP] Scanning S3/CDN upload: '{matched_filename}' ({len(body):,} bytes)")
                result = extract_text(body, matched_filename)
                if result:
                    ctx.log.info(f"[DLP] Extracted {result.char_count:,} chars from '{matched_filename}'")
                    _, stats = await engine.redact(result.text)
                    if has_detection(stats):
                        event = write_http_audit(flow, stats, "block")
                        if rule_engine.needs_alert(stats):
                            asyncio.create_task(send_alert({**event, "action": "block"}))
                        ctx.log.warn(f"[DLP] BLOCK S3 upload '{matched_filename}': {stats['pii_types']}")
                        block_response(flow, event["event_id"],
                                       f"File '{matched_filename}' bị chặn: chứa thông tin nhạy cảm",
                                       {"pii_types": stats["pii_types"], "filename": matched_filename})
                        return
                    ctx.log.info(f"[DLP] S3 upload '{matched_filename}' — clean, allow")
            else:
                ctx.log.debug(f"[DLP] S3 PUT body too small or empty for '{matched_filename}', allowing")
        else:
            ctx.log.debug(f"[DLP] FLOW 0: {method} preflight for '{matched_filename}' — keeping entry")
        return  # Luôn return sớm: không cho LUỒNG 2 xử lý file storage request

    # Safety net: nếu host là file storage (oaiusercontent.com v.v.) nhưng không có
    # entry nào trong _pending_uploads (đã hết TTL hoặc lý do khác) → KHÔNG chạy
    # LUỒNG 2. Xử lý binary body bằng text redact sẽ làm hỏng chữ ký S3/Azure.
    if is_file_storage_host(host):
        ctx.log.debug(f"[DLP] File storage host {host} with no pending entry — skip LUỒNG 2")
        return

    if not is_ai_domain(host):
        return
    if should_skip_request(flow):
        return
    if flow.request.method.upper() not in ["POST", "PUT", "PATCH"]:
        return

    body = flow.request.get_content()
    if not body:
        return

    content_type = flow.request.headers.get("content-type", "").lower()

    # ── LUỒNG 1: File upload endpoint → scan → BLOCK nếu có PII ──────────────
    if is_file_upload_endpoint(flow.request.path):
        stats, filename, infected_files = await scan_raw_file_upload(flow)
        if not has_detection(stats):
            ctx.log.info(f"[DLP] File '{filename}' — clean, allow upload")
            return
        # Dùng infected_files từ scan_multipart nếu có (giữ đủ chi tiết từng file),
        # hoặc tạo mới từ filename nếu là raw binary upload.
        if not infected_files:
            infected_files = [{"filename": filename, "pii_types": stats["pii_types"]}]
        stats["infected_files"] = infected_files
        event = write_http_audit(flow, stats, "block")
        if rule_engine.needs_alert(stats):
            asyncio.create_task(send_alert({**event, "action": "block"}))
        ctx.log.warn(f"[DLP] BLOCK file upload '{filename}': {stats['pii_types']}")
        block_response(flow, event["event_id"],
                       f"File '{filename}' bị chặn: chứa thông tin nhạy cảm",
                       {"infected_files": infected_files, "pii_types": stats["pii_types"]})
        return

    # ── LUỒNG 2: Text/JSON prompt → redact theo rule ──────────────────────────
    redacted_body, stats, infected_files = await scan_body(body, content_type)
    if not has_detection(stats):
        return
    if infected_files:
        stats["infected_files"] = infected_files
    effective_action = rule_engine.get_effective_action(stats)
    event = write_http_audit(flow, stats, effective_action)
    ctx.log.info(f"[DLP] host={host} entities={list(stats['pii_types'].keys())} action={effective_action}")
    if rule_engine.needs_alert(stats):
        asyncio.create_task(send_alert({**event, "action": effective_action}))
    if infected_files:
        block_response(flow, event["event_id"], "File đính kèm chứa thông tin nhạy cảm", {"infected_files": infected_files})
        return
    if effective_action == "log":
        return
    if effective_action == "block":
        block_response(flow, event["event_id"], "Blocked by AI DLP Proxy", {"pii_types": stats.get("pii_types", {})})
        return
    if effective_action == "redact" and redacted_body:
        flow.request.set_content(redacted_body)
        ctx.log.info(f"[DLP] Redacted prompt → {host}{flow.request.path}")


async def response(flow: http.HTTPFlow):
    """
    Intercept response từ các file upload endpoint để lấy pre-signed upload URL.

    Khi LLM trả về pre-signed S3/CDN URL (2-step upload flow), lưu URL vào
    _pending_uploads để LUỒNG 0 trong request() có thể intercept và scan file
    khi browser thực sự PUT lên S3.

    Bug #4 đã sửa: trước đây chỉ theo dõi /backend-api/files (OpenAI).
    Nay mở rộng ra tất cả upload endpoint trong UPLOAD_PATTERNS.
    Bug #5: mỗi entry có thêm timestamp để hỗ trợ TTL cleanup.
    """
    host = flow.request.pretty_host
    if not is_ai_domain(host):
        return
    path = flow.request.path.lower()

    # Theo dõi TẤT CẢ các upload endpoint, không chỉ /backend-api/files
    RESPONSE_WATCH_PATTERNS = [
        "/backend-api/files",
        "/backend-anon/files",
        "/api/v0/file",
        "/c/api/attachments",
        "/upload",
    ]
    if not any(p in path for p in RESPONSE_WATCH_PATTERNS):
        return
    if any(s in path for s in ("/process_upload", "/library", "/fetch_files", "/cancel")):
        return
    if not flow.response or flow.response.status_code not in (200, 201):
        return

    try:
        # ── Bước 1: đọc filename từ request body trước (nguồn chính xác nhất) ──
        # ChatGPT gửi: POST /backend-api/files body = {"file_name":"doc.pdf","content_type":"application/pdf"}
        filename = ""
        try:
            req_body = flow.request.get_content()
            if req_body:
                req_data = json.loads(req_body)
                filename = (
                    req_data.get("file_name") or req_data.get("filename") or
                    req_data.get("name")      or req_data.get("original_name") or ""
                )
        except Exception:
            pass

        # ── Bước 2: parse response JSON ──────────────────────────────────────
        raw_text = flow.response.text
        ctx.log.debug(f"[DLP] Upload endpoint response (first 400): {raw_text[:400]}")

        data = json.loads(raw_text)

        # Tìm upload_url trong mọi field có thể
        upload_url = ""
        for key, val in data.items():
            if not isinstance(val, str):
                continue
            if val.startswith("https://") and ("upload" in key.lower() or "url" in key.lower()):
                upload_url = val
            # Bổ sung filename từ response nếu chưa có
            if not filename and ("name" in key.lower() or "file" in key.lower()):
                if "." in val:
                    filename = val

        # Fallback tên field phổ biến
        if not upload_url:
            upload_url = (
                data.get("upload_url") or data.get("uploadUrl") or
                data.get("put_url")    or data.get("url") or ""
            )
        if not filename:
            filename = (
                data.get("file_name") or data.get("filename") or
                data.get("name")      or "unknown"
            )

        if upload_url:
            parsed  = urlparse(upload_url)
            url_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            _pending_uploads[url_key] = (filename, time.monotonic())
            ctx.log.info(f"[DLP] Registered upload URL: '{filename}' → {parsed.netloc}{parsed.path[:80]}")
        else:
            ctx.log.debug(f"[DLP] No pre-signed URL found in response from {host}{path}")

    except Exception as e:
        ctx.log.warn(f"[DLP] response hook error: {e}")


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
        effective_action = rule_engine.get_effective_action(stats)
        event = write_ws_audit(flow, stats, effective_action, frame_type="text")
        if rule_engine.needs_alert(stats):
            asyncio.create_task(send_alert({**event, "action": effective_action}))
        if effective_action == "log":    return
        if effective_action == "block":  message.drop(); return
        if effective_action == "redact": message.content = redacted_text.encode("utf-8")
        return
    redacted_data, stats = await redact_only_text_fields(data)
    if not has_detection(stats):
        return
    effective_action = rule_engine.get_effective_action(stats)
    event = write_ws_audit(flow, stats, effective_action, frame_type="json")
    if rule_engine.needs_alert(stats):
        asyncio.create_task(send_alert({**event, "action": effective_action}))
    if effective_action == "log":    return
    if effective_action == "block":  message.drop(); return
    if effective_action == "redact":
        message.content = json.dumps(
            redacted_data, ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")