"""
dlp_addon.py — AI DLP Proxy
Providers: ChatGPT (chatgpt.com / openai.com) and Claude (claude.ai / anthropic.com)

Luồng xử lý:
  LUỒNG 0 — Pre-signed CDN PUT (ChatGPT 2-step upload):
              response hook registers upload_url → request hook scans raw bytes
  LUỒNG 1 — Direct file upload endpoint (Claude multipart, ChatGPT direct):
              scan_raw_file_upload → FlashText + Presidio ML → block if sensitive
  LUỒNG 2 — Text / JSON prompt (both providers):
              scan_body → redact_prompt_fields → redact / block / log per rules
"""

import asyncio
import email.parser
import json
import mimetypes
import os
import time
from urllib.parse import urlparse, parse_qs
from typing import Any, Dict, List, Optional, Tuple

from mitmproxy import http, ctx

from dlp.dlp_engine     import DLPEngine
from dlp.audit_logger   import write_http_audit, write_ws_audit
from dlp.alerter        import send_alert
from dlp.file_extractor import extract_text
from dlp.rule_engine    import rule_engine


# ── Supported providers ───────────────────────────────────────────────────────

AI_DOMAINS = os.getenv(
    "AI_DLP_DOMAINS",
    "chatgpt.com,chat.openai.com,openai.com,"
    "claude.ai,anthropic.com",
).split(",")

# ChatGPT uses a 2-step upload: POST /backend-api/files returns a pre-signed
# Azure CDN URL (*.oaiusercontent.com); the browser then PUTs the actual bytes
# there.  We must NOT run LUỒNG 2 (text redact) on these hosts — it corrupts
# the binary body and breaks the Azure signature check.
# s3.amazonaws.com is kept as a safety net in case Claude ever issues pre-signed
# S3 URLs (Anthropic runs on AWS).
FILE_STORAGE_HOSTS = os.getenv(
    "DLP_FILE_STORAGE_HOSTS",
    "oaiusercontent.com,"   # ChatGPT / OpenAI (Azure CDN)
    "s3.amazonaws.com",     # AWS S3 (Claude potential backend)
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

# TTL (seconds) for each _pending_uploads entry — auto-expire stale entries
_PENDING_UPLOAD_TTL = int(os.getenv("DLP_PENDING_UPLOAD_TTL", "300"))

# {url_key: (filename, registered_at_monotonic)}
_pending_uploads: Dict[str, Tuple[str, float]] = {}


# ── Domain / path helpers ─────────────────────────────────────────────────────

def is_ai_domain(host: str) -> bool:
    host = host.lower().strip()
    for domain in AI_DOMAINS:
        d = domain.strip().lower()
        if host == d or host.endswith("." + d):
            return True
    return False


# Paths that are definitively NOT user prompts.  Scanning them produces
# confirmed false-positives (Cloudflare challenge tokens, CSP reports, etc.)
_SKIP_PATH_PREFIXES = (
    "/cdn-cgi/",    # Cloudflare bot-challenge / analytics (ChatGPT)
    "/cspreport",   # Browser CSP violation reports
    "/telemetry",   # Telemetry beacons
    "/analytics",   # Analytics collection
    "/beacon",      # Telemetry beacons
    "/metrics",     # Metrics / monitoring
)
_SKIP_PATH_CONTAINS = (
    "/ces/", "/ces/v1/",        # OpenAI internal event stream
    "/backend-api/sentinel/",   # ChatGPT bot detection
    "/public-api/",             # OpenAI public (non-chat) API
    "/collect",                 # Generic telemetry collect endpoints
)


def should_skip_request(flow: http.HTTPFlow) -> bool:
    path = flow.request.path.lower()
    if path.startswith(_SKIP_PATH_PREFIXES):
        return True
    return any(s in path for s in _SKIP_PATH_CONTAINS)


# ── Upload endpoint detection ─────────────────────────────────────────────────

# Paths where the request body contains (or initiates) a file upload.
UPLOAD_PATTERNS = [
    # ChatGPT / OpenAI
    "/backend-api/files",
    "/backend-anon/files",
    # Claude.ai
    "/api/convert_document",    # multipart PDF → text conversion
    "/api/organizations",       # /api/organizations/{org_id}/files or /upload
    "/api/files",               # Claude direct files API
    # Anthropic Files API (a-api.anthropic.com)
    "/v1/files",                # POST /v1/files — direct upload, returns file_id
]

# Sub-paths that superficially match UPLOAD_PATTERNS but are NOT file uploads.
UPLOAD_SKIP_SUBS = [
    "/process_upload", "/library", "/fetch_files", "/cancel",
    "/settings", "/conversations", "/messages",
    "/billing", "/members", "/invites", "/usage",
]


def is_file_upload_endpoint(path: str) -> bool:
    path = path.lower()
    if any(s in path for s in UPLOAD_SKIP_SUBS):
        return False
    # Claude org-scoped endpoints: /files, /upload, and /docs are all file operations.
    # Everything else (members, billing, invites, etc.) is already caught by UPLOAD_SKIP_SUBS.
    if "/api/organizations" in path:
        return "/files" in path or "/upload" in path or "/docs" in path
    return any(p in path for p in UPLOAD_PATTERNS)


def get_upload_filename(flow: http.HTTPFlow) -> str:
    """
    Extract filename from a file upload request.
    Priority order:
      1. Content-Disposition header on the request
      2. Custom headers X-Filename / X-File-Name / X-Original-Filename
      3. Query params: filename / file_name / name
      4. Multipart body — scan part Content-Disposition headers
      5. Infer from Content-Type
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

    # 4. Multipart body
    ct = flow.request.headers.get("content-type", "")
    if "multipart/form-data" in ct.lower():
        try:
            body   = flow.request.get_content()
            raw_msg = b"Content-Type: " + ct.encode() + b"\r\n\r\n" + body
            msg    = email.parser.BytesParser().parsebytes(raw_msg)
            for part in msg.walk():
                fn = part.get_filename()
                if fn:
                    return fn
        except Exception:
            pass

    # 5. Infer from Content-Type
    ext_map = {
        "application/pdf":  "upload.pdf",
        "wordprocessingml": "upload.docx",
        "spreadsheetml":    "upload.xlsx",
        "text/plain":       "upload.txt",
        "text/csv":         "upload.csv",
    }
    for mime, name in ext_map.items():
        if mime in ct:
            return name

    return "upload.bin"


# ── Stats helpers ─────────────────────────────────────────────────────────────

def empty_stats() -> Dict:
    return {"static_replacements": 0, "ml_replacements": 0, "pii_types": {}, "matches": []}


def has_detection(stats: Dict) -> bool:
    return bool(
        stats.get("static_replacements")
        or stats.get("ml_replacements")
        or stats.get("pii_types")
        or stats.get("matches")
    )


def merge_stats(total: Dict, child: Dict) -> None:
    total["static_replacements"] += child.get("static_replacements", 0)
    total["ml_replacements"]     += child.get("ml_replacements", 0)
    for pii_type, count in child.get("pii_types", {}).items():
        total["pii_types"][pii_type] = total["pii_types"].get(pii_type, 0) + count
    total["matches"].extend(child.get("matches", []))


# ── Prompt redaction ──────────────────────────────────────────────────────────

# Keys whose string values are user-supplied prompt text and must be scanned.
# "content" covers both:
#   - Anthropic API:      {"messages": [{"role": "user", "content": "…"}]}
#   - OpenAI-compatible:  same structure
# Note: base64 images also appear under "content" but contain no plain-text
# PII, so scanning them is harmless (FlashText finds nothing; Presidio finds
# nothing above the confidence threshold).
PROMPT_KEYS = {"text", "prompt", "parts", "query", "input", "content"}


def is_prompt_key(key: str) -> bool:
    return key.lower() in PROMPT_KEYS


async def redact_prompt_fields(
    value: Any,
    in_prompt_field: bool = False,
) -> Tuple[Any, Dict]:
    """
    Recursively walk a JSON-decoded value and redact all strings that sit
    under a prompt key (PROMPT_KEYS) or are nested inside one.
    """
    total_stats = empty_stats()

    if isinstance(value, dict):
        new_obj = {}
        for key, child in value.items():
            child_is_prompt = in_prompt_field or is_prompt_key(key)
            new_child, child_stats = await redact_prompt_fields(child, child_is_prompt)
            new_obj[key] = new_child
            merge_stats(total_stats, child_stats)
        return new_obj, total_stats

    if isinstance(value, list):
        new_list = []
        for item in value:
            new_item, item_stats = await redact_prompt_fields(item, in_prompt_field)
            new_list.append(new_item)
            merge_stats(total_stats, item_stats)
        return new_list, total_stats

    if isinstance(value, str) and in_prompt_field:
        return await engine.redact(value)

    return value, total_stats


# ── File upload scanning ──────────────────────────────────────────────────────

async def scan_raw_file_upload(flow: http.HTTPFlow) -> Tuple[Dict, str, List]:
    """
    Scan a file upload request.  Returns (stats, filename, infected_files).

    Two cases:
    - multipart/form-data: parse each part individually (browser upload to
                           Claude /api/convert_document, ChatGPT direct form).
    - Raw binary body:     direct read of bytes (PUT to ChatGPT Azure CDN).

    The multipart branch delegates to scan_multipart() which extracts the real
    file bytes from each part before passing them to extract_text().  Calling
    extract_text() on the whole multipart envelope would fail: it starts with
    "--boundary" not with a PDF/DOCX magic header.
    """
    body             = flow.request.get_content()
    # Preserve original case — multipart boundary matching is case-sensitive.
    content_type_raw = flow.request.headers.get("content-type", "")
    content_type     = content_type_raw.lower()   # comparisons only
    filename         = get_upload_filename(flow)

    # Case 1: multipart/form-data
    if "multipart/form-data" in content_type:
        ctx.log.info("[DLP] Multipart upload — parsing parts")
        _, stats, infected_files = await scan_multipart(body, content_type_raw)
        if has_detection(stats):
            ctx.log.warn(f"[DLP] Sensitive content in multipart upload: {stats['pii_types']}")
        return stats, filename, infected_files

    # Case 2: raw binary body
    ctx.log.info(f"[DLP] Raw binary upload: '{filename}' ({len(body):,} bytes)")
    result = extract_text(body, filename)
    if result is None:
        ctx.log.info(f"[DLP] Skipped (unsupported/empty): '{filename}'")
        return empty_stats(), filename, []
    ctx.log.info(f"[DLP] Extracted {result.char_count:,} chars from '{filename}'")
    # FlashText (internal terms) + Presidio ML restricted entity set.
    # PERSON/LOCATION/ORG are excluded to avoid false positives on document text.
    stats = await engine.scan_file_content(result.text)
    if has_detection(stats):
        ctx.log.warn(f"[DLP] Sensitive content in upload '{filename}': {stats['pii_types']}")
    return stats, filename, []


def _is_binary_mime(mime: str) -> bool:
    """
    Return True if a MIME type indicates a document/binary file that needs
    content scanning, even when the multipart part carries no filename.

    Claude's /conversations endpoint often sends the file bytes in a part
    whose Content-Disposition is just:
        Content-Disposition: form-data; name="file"
    (no filename=) but whose Content-Type is "application/pdf" etc.
    """
    if not mime:
        return False
    # Explicitly NOT a file: plain text fields, JSON, multipart wrapper
    non_file = ("text/plain", "application/json", "application/x-www-form-urlencoded")
    if mime in non_file or mime.startswith("multipart/"):
        return False
    # Everything else is treated as a file (PDF, DOCX, XLSX, images, …)
    return True


async def scan_multipart(
    body: bytes,
    content_type: str,
) -> Tuple[Optional[bytes], Dict, List]:
    """
    Parse a multipart/form-data body.

    - Text form fields whose name matches a prompt key are scanned with the
      full redact engine (FlashText + Presidio, all entities).
    - File attachment parts are scanned with scan_file_content (restricted
      entity set — no PERSON/ORG false positives from document text).

    A part is treated as a FILE if it has EITHER:
      a) ``filename=`` in its Content-Disposition header  (standard browser)
      b) A binary/document MIME type in its Content-Type  (Claude.ai sends
         PDFs this way: no filename, just ``Content-Type: application/pdf``)

    Returns (original_body, stats, infected_files).
    The body is never modified here; blocking happens at the caller level.
    """
    total_stats    = empty_stats()
    infected_files: List[Dict] = []

    raw_msg = b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + body
    msg     = email.parser.BytesParser().parsebytes(raw_msg)

    for part in msg.walk():
        # part.get() may return an email.header.Header object on encoded headers.
        # Cast to str so "in" / startswith checks work correctly.
        disposition  = str(part.get("Content-Disposition") or "")
        part_mime    = (part.get_content_type() or "").lower()

        has_filename = "filename=" in disposition
        is_file_part = has_filename or _is_binary_mime(part_mime)

        if not is_file_part:
            # Text form field — scan if it looks like a prompt field
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            field_name = ""
            for item in disposition.split(";"):
                item = item.strip()
                if item.startswith('name="'):
                    field_name = item[6:-1]
            if is_prompt_key(field_name):
                text = payload.decode("utf-8", errors="ignore")
                _, stats = await engine.redact(text)
                merge_stats(total_stats, stats)
            continue

        # File attachment part
        # Prefer explicit filename; fall back to inferring from MIME type.
        filename = part.get_filename() or ""
        if not filename:
            ext      = mimetypes.guess_extension(part_mime) or ".bin"
            # mimetypes sometimes returns ".jpe" for jpeg — normalise
            ext      = {"jpe": ".jpg", "jfif": ".jpg"}.get(ext.lstrip("."), ext)
            filename = f"upload{ext}"

        payload = part.get_payload(decode=True)
        if not payload:
            continue

        ctx.log.info(f"[DLP] Scanning attachment: {filename} ({len(payload):,} bytes, mime={part_mime})")
        result = extract_text(payload, filename)
        if result is None:
            ctx.log.info(f"[DLP] Attachment '{filename}' — unsupported/empty, skip")
            continue
        stats = await engine.scan_file_content(result.text)
        merge_stats(total_stats, stats)
        if has_detection(stats):
            infected_files.append({
                "filename":  filename,
                "file_type": result.file_type,
                "pii_types": stats["pii_types"],
            })
            ctx.log.warn(f"[DLP] Sensitive content in '{filename}': {stats['pii_types']}")

    return body, total_stats, infected_files


async def scan_body(
    body: bytes,
    content_type: str,
) -> Tuple[Optional[bytes], Dict, List]:
    """
    Scan / redact a request body for LUỒNG 2 (text prompt path).

    - multipart/form-data   → scan_multipart()
    - application/json      → redact_prompt_fields() on parsed JSON
    - everything else       → engine.redact() on decoded string
    """
    ct_lower = content_type.lower()

    if "multipart/form-data" in ct_lower:
        # Pass content_type as-is (original case) — boundary matching is case-sensitive.
        return await scan_multipart(body, content_type)

    body_str = body.decode("utf-8", errors="ignore")

    if "application/json" in ct_lower:
        try:
            data          = json.loads(body_str)
            redacted_data, stats = await redact_prompt_fields(data)
            redacted_body = json.dumps(
                redacted_data, ensure_ascii=False, separators=(",", ":"),
            ).encode("utf-8")
            return redacted_body, stats, []
        except json.JSONDecodeError:
            return body, empty_stats(), []

    # Fallback: plain text body
    redacted_str, stats = await engine.redact(body_str)
    return redacted_str.encode("utf-8"), stats, []


def block_response(
    flow: http.HTTPFlow,
    event_id: str,
    reason: str,
    extra: Optional[Dict] = None,
) -> None:
    payload = {"error": reason, "event_id": event_id}
    if extra:
        payload.update(extra)
    flow.response = http.Response.make(
        403,
        json.dumps(payload, ensure_ascii=False),
        {"Content-Type": "application/json"},
    )


# ── mitmproxy hooks ───────────────────────────────────────────────────────────

async def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host

    # ── LUỒNG 0: Pre-signed CDN upload (ChatGPT 2-step flow) ─────────────────
    # ChatGPT POST /backend-api/files returns an upload_url (*.oaiusercontent.com).
    # The response hook registers that URL in _pending_uploads.  When the browser
    # PUTs the actual file bytes to the CDN, we intercept here and scan them.

    # Expire stale entries before matching
    now = time.monotonic()
    for k in [k for k, (_, ts) in list(_pending_uploads.items()) if now - ts > _PENDING_UPLOAD_TTL]:
        _pending_uploads.pop(k, None)
        ctx.log.debug(f"[DLP] Expired pending upload entry: {k}")

    request_url = f"https://{host}{flow.request.path}"
    matched_filename: Optional[str] = None
    matched_url_key:  Optional[str] = None
    for url_key, (fname, _ts) in list(_pending_uploads.items()):
        if request_url.startswith(url_key):
            matched_filename = fname
            matched_url_key  = url_key
            break

    if matched_filename:
        method = flow.request.method.upper()
        # Skip CORS preflight (OPTIONS) — keep entry so the real PUT can match it
        if method in ("PUT", "POST", "PATCH"):
            _pending_uploads.pop(matched_url_key, None)
            body = flow.request.get_content()
            if body and len(body) > 512:
                ctx.log.info(f"[DLP] Scanning CDN upload: '{matched_filename}' ({len(body):,} bytes)")
                result = extract_text(body, matched_filename)
                if result:
                    ctx.log.info(f"[DLP] Extracted {result.char_count:,} chars from '{matched_filename}'")
                    stats = await engine.scan_file_content(result.text)
                    if has_detection(stats):
                        event = write_http_audit(flow, stats, "block")
                        if rule_engine.needs_alert(stats):
                            asyncio.create_task(send_alert({**event, "action": "block"}))
                        ctx.log.warn(f"[DLP] BLOCK CDN upload '{matched_filename}': {stats['pii_types']}")
                        block_response(
                            flow, event["event_id"],
                            f"File '{matched_filename}' bị chặn: chứa thông tin nhạy cảm",
                            {"pii_types": stats["pii_types"], "filename": matched_filename},
                        )
                        return
                    ctx.log.info(f"[DLP] CDN upload '{matched_filename}' — clean, allow")
            else:
                ctx.log.debug(f"[DLP] CDN PUT body too small for '{matched_filename}', allowing")
        else:
            ctx.log.debug(f"[DLP] LUỒNG 0: {method} preflight for '{matched_filename}' — keeping entry")
        # Always return early — never run LUỒNG 2 on file-storage requests
        return

    # Safety net: if host is a CDN/storage host with no registered entry (TTL
    # expired, entry never registered), skip LUỒNG 2.  Running text redact on
    # binary content corrupts it and breaks S3/Azure signature verification.
    if is_file_storage_host(host):
        return

    if not is_ai_domain(host):
        return
    if should_skip_request(flow):
        return

    method = flow.request.method.upper()
    if method not in ("POST", "PUT", "PATCH"):
        return

    body             = flow.request.get_content()
    # Keep raw content-type for parsing (multipart boundary is case-sensitive).
    # Use lowercase only for string comparisons (startswith / "in" checks).
    content_type_raw = flow.request.headers.get("content-type", "")
    content_type     = content_type_raw.lower()

    if not body:
        return

    # ── LUỒNG 1: File upload endpoint → scan → block if sensitive ────────────
    if is_file_upload_endpoint(flow.request.path):
        ctx.log.info(
            f"[DLP] Upload endpoint: {method} {host}{flow.request.path[:80]} "
            f"({len(body):,}b, {content_type[:50]})"
        )
        stats, filename, infected_files = await scan_raw_file_upload(flow)
        if not has_detection(stats):
            ctx.log.info(f"[DLP] File '{filename}' — clean, allow")
            return
        if not infected_files:
            infected_files = [{"filename": filename, "pii_types": stats["pii_types"]}]
        stats["infected_files"] = infected_files
        event = write_http_audit(flow, stats, "block")
        if rule_engine.needs_alert(stats):
            asyncio.create_task(send_alert({**event, "action": "block"}))
        ctx.log.warn(f"[DLP] BLOCK upload '{filename}': {stats['pii_types']}")
        block_response(
            flow, event["event_id"],
            f"File '{filename}' bị chặn: chứa thông tin nhạy cảm",
            {"infected_files": infected_files, "pii_types": stats["pii_types"]},
        )
        return

    # ── LUỒNG 2: Text / JSON prompt → redact per rule ─────────────────────────
    # Pass raw (non-lowercased) content-type so scan_multipart can match the
    # multipart boundary exactly — boundaries are case-sensitive per RFC 2046.
    redacted_body, stats, infected_files = await scan_body(body, content_type_raw)
    if not has_detection(stats):
        return
    if infected_files:
        stats["infected_files"] = infected_files
    effective_action = rule_engine.get_effective_action(stats)
    event            = write_http_audit(flow, stats, effective_action)
    ctx.log.info(
        f"[DLP] {host} — entities={list(stats['pii_types'].keys())} action={effective_action}"
    )
    if rule_engine.needs_alert(stats):
        asyncio.create_task(send_alert({**event, "action": effective_action}))
    if infected_files:
        block_response(flow, event["event_id"],
                       "File đính kèm chứa thông tin nhạy cảm",
                       {"infected_files": infected_files})
        return
    if effective_action == "log":
        return
    if effective_action == "block":
        block_response(flow, event["event_id"],
                       "Blocked by AI DLP Proxy",
                       {"pii_types": stats.get("pii_types", {})})
        return
    if effective_action == "redact" and redacted_body:
        flow.request.set_content(redacted_body)
        ctx.log.info(f"[DLP] Redacted prompt → {host}{flow.request.path}")


async def response(flow: http.HTTPFlow) -> None:
    """
    Intercept upload initiation responses to extract the pre-signed upload URL.

    ChatGPT 2-step flow:
      POST /backend-api/files  →  {"upload_url": "https://*.oaiusercontent.com/…"}
      The pre-signed URL is registered in _pending_uploads so LUỒNG 0 can
      scan the actual file bytes when the browser PUTs them to the CDN.

    Claude direct flow:
      POST /api/convert_document or /api/organizations/.../upload
      File bytes arrive directly in the POST body (handled in LUỒNG 1).
      No pre-signed URL is issued, so _pending_uploads stays empty for Claude.
      We still watch these paths to log the response for debugging.
    """
    host = flow.request.pretty_host
    if not is_ai_domain(host):
        return
    path = flow.request.path.lower()

    RESPONSE_WATCH_PATTERNS = (
        "/backend-api/files",    # ChatGPT — POST returns upload_url
        "/backend-anon/files",   # ChatGPT anon
        "/api/convert_document", # Claude — direct multipart (no pre-signed URL)
        "/api/organizations",    # Claude — /api/organizations/{id}/files or /upload
        "/api/files",            # Claude direct files API
        "/v1/files",             # Anthropic Files API
    )
    if not any(p in path for p in RESPONSE_WATCH_PATTERNS):
        return
    # Skip non-upload sub-paths that match the patterns above
    if any(s in path for s in (
        "/process_upload", "/library", "/fetch_files", "/cancel",
        "/settings", "/projects", "/conversations", "/members",
        "/billing", "/invites", "/usage",
    )):
        return
    if not flow.response or flow.response.status_code not in (200, 201):
        return

    try:
        # Step 1: extract filename from request body
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

        # Fallback: filename from Content-Disposition header
        if not filename:
            cd = flow.request.headers.get("content-disposition", "")
            if "filename=" in cd:
                for part in cd.split(";"):
                    part = part.strip()
                    if part.lower().startswith("filename="):
                        filename = part[9:].strip('"\'')
                        break

        # Step 2: extract pre-signed upload URL from response JSON
        # Only ChatGPT returns one; Claude does not.
        upload_url = ""
        try:
            data = json.loads(flow.response.text)

            # Explicit well-known keys first
            upload_url = (
                data.get("upload_url") or data.get("uploadUrl") or
                data.get("put_url")    or data.get("url") or ""
            )

            # Heuristic scan: any top-level https:// string in an "upload"/"url" key
            if not upload_url:
                for key, val in data.items():
                    if isinstance(val, str) and val.startswith("https://"):
                        if "upload" in key.lower() or "url" in key.lower():
                            upload_url = val
                            break

            # Filename from response if still unknown
            if not filename:
                filename = (
                    data.get("file_name") or data.get("filename") or
                    data.get("name") or ""
                )
        except Exception:
            pass

        filename = filename or "unknown"

        if upload_url:
            parsed  = urlparse(upload_url)
            url_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            _pending_uploads[url_key] = (filename, time.monotonic())
            ctx.log.info(
                f"[DLP] Registered upload URL: '{filename}' → "
                f"{parsed.netloc}{parsed.path[:80]}"
            )
        else:
            ctx.log.debug(
                f"[DLP] No upload URL in response from {host}{path[:60]} "
                f"(status={flow.response.status_code}) — direct upload or Claude"
            )

    except Exception as e:
        ctx.log.warn(f"[DLP] response hook error: {e}")


async def websocket_message(flow: http.HTTPFlow) -> None:
    """
    Scan / redact client→server WebSocket frames.

    ChatGPT sends prompts over HTTP (POST /backend-api/conversation), but
    some newer versions stream prompts over WebSocket.  Claude uses HTTP only.
    We handle both text frames and JSON frames.
    """
    if not flow.websocket or not flow.websocket.messages:
        return
    host = flow.request.pretty_host
    if not is_ai_domain(host):
        return
    message = flow.websocket.messages[-1]
    if not message.from_client:
        return

    try:
        text = message.content.decode("utf-8", errors="ignore")
    except Exception:
        return
    if not text:
        return

    # Plain text frame
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

    # JSON frame — use redact_prompt_fields to catch all prompt keys
    # (text, prompt, parts, content, query, input)
    redacted_data, stats = await redact_prompt_fields(data)
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
