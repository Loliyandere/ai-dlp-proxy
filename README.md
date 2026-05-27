# AI DLP Proxy

A man-in-the-middle proxy that enforces **Data Loss Prevention (DLP)** on traffic to **ChatGPT** and **Claude**. It inspects prompts and file uploads in real time, then **redacts**, **blocks**, or **logs** sensitive data according to configurable rules — with optional Telegram alerts.

Built on [mitmproxy](https://mitmproxy.org/) + [Microsoft Presidio](https://microsoft.github.io/presidio/), with custom Vietnamese PII recognizers and FlashText keyword matching for internal terms.

---

## What it does

- **Text prompts** — detects PII and internal keywords, then redacts / blocks / logs per rule.
- **File uploads** — extracts text from PDF / DOCX / XLSX / source files and scans the content. Blocks the upload if it contains internal terms or sensitive PII.
- **Audit trail** — every event is written to privacy-preserving JSON Lines logs (PII values are never stored).
- **Alerting** — sends a Telegram message when a configured entity is detected.

Supported providers: **ChatGPT** (`chatgpt.com`, `openai.com`) and **Claude** (`claude.ai`, `anthropic.com`). Other AI platforms are intentionally out of scope.

---

## How it works

Traffic is routed through the proxy via a PAC file. Each request is classified into one of three flows:

| Flow | Trigger | Action |
|------|---------|--------|
| **LUỒNG 0** | ChatGPT 2-step upload — pre-signed Azure CDN `PUT` (`*.oaiusercontent.com`) | The response hook registers the upload URL; the request hook scans the raw file bytes before they leave. |
| **LUỒNG 1** | Direct file-upload endpoint (Claude multipart, ChatGPT direct) | Extract text → scan (FlashText + Presidio) → block if sensitive. |
| **LUỒNG 2** | Text / JSON prompt (both providers) | Recursively scan prompt fields → redact / block / log per rule. |

### Detection layers

1. **FlashText** — exact, case-insensitive match against internal keywords in `config/terms.txt`. Any hit → `STATIC_TERM`.
2. **Presidio (ML)** — entity recognition for emails, phones, credit cards, IPs, URLs.
3. **Vietnamese recognizers** — custom patterns for CCCD/CMND, phone, tax code, passport, bank account, license plate, BHYT.

> File-content scanning uses a **restricted** entity set (no `PERSON` / `LOCATION` / `ORGANIZATION` / `DATE_TIME`) to avoid false positives on document text and Azure SAS-token timestamps.

---

## Quick start

### 1. Configure environment

Copy the example below into `.env` and fill in your Telegram credentials (see [Telegram setup](#telegram-alerts)):

```ini
# DLP core
DLP_MODE=redact                 # log | redact | block (fallback when no rule matches)
DLP_LOG_DIR=logs
DLP_LOG_ROTATE=daily
DLP_LOG_MAX_DAYS=30
DLP_SERVICE_NAME=ai-dlp-proxy

# Presidio (ML)
DLP_PRESIDIO_ENABLED=true
DLP_PRESIDIO_THRESHOLD=0.60
DLP_PRESIDIO_LANGUAGE=en
DLP_SPACY_MODEL=en_core_web_sm
DLP_PRESIDIO_ENTITIES=EMAIL_ADDRESS,PHONE_NUMBER,CREDIT_CARD,IP_ADDRESS,URL,VN_CCCD,VN_PHONE,VN_TAX_CODE,VN_PASSPORT,VN_BANK_ACCOUNT,VN_LICENSE_PLATE,VN_BHYT

# Telegram alerts
DLP_TELEGRAM_TOKEN=your-bot-token
DLP_TELEGRAM_CHAT_ID=your-chat-id
DLP_ALERT_THRESHOLD=1
DLP_ALERT_DEBOUNCE_SEC=60
DLP_ALERT_MODE=all              # all | block_only
```

> `.env` is gitignored — never commit real tokens.

### 2. Start the services

```bash
docker compose up -d --build
```

This launches two containers:

| Service | Port | Purpose |
|---------|------|---------|
| `ai-dlp-proxy` | `8080` | The mitmproxy DLP proxy |
| `ai-dlp-pac`   | `8000` | Serves the PAC file |

### 3. Point the client through the proxy

Edit `pac/proxy.pac` so the `PROXY` line matches your host's LAN IP:

```javascript
var proxy = "PROXY 192.168.x.x:8080";
```

On the client machine, set the **automatic proxy configuration URL** to:

```
http://<proxy-host-ip>:8000/proxy.pac
```

Only ChatGPT / Claude / their CDN hosts are routed through the proxy; everything else goes `DIRECT`.

### 4. Install the mitmproxy CA certificate

On the client, visit **http://mitm.it** (while the proxy is active) and install the certificate for your OS/browser so HTTPS interception is trusted.

---

## Configuration

### Internal keywords — `config/terms.txt`

One term per line. Any match blocks the request as `STATIC_TERM`. Hot-reloaded on change.

```
Project Phoenix
super_secret_token
internal_api_gateway
database_password
```

### Per-entity rules — `config/rules.yaml`

Each entity maps to an `action` (`log` / `redact` / `block`) and whether it triggers a Telegram `alert`. Hot-reloaded on change.

```yaml
rules:
  - entity: CREDIT_CARD
    enabled: true
    action: block
    alert: true
  - entity: EMAIL_ADDRESS
    enabled: true
    action: redact
    alert: false
  # ...
```

When multiple entities are detected, the **strongest** action wins: `block` > `redact` > `log`.

### Telegram alerts

1. Message [@BotFather](https://t.me/BotFather) → `/newbot` → copy the bot token.
2. Send your bot a message, then open `https://api.telegram.org/bot<TOKEN>/getUpdates` and copy `chat.id`.
3. Set `DLP_TELEGRAM_TOKEN` and `DLP_TELEGRAM_CHAT_ID` in `.env`.

Alerts are debounced per `(host, action)` for `DLP_ALERT_DEBOUNCE_SEC` seconds to prevent spam.

---

## Audit logs

Events are written to `logs/dlp_audit_YYYY-MM-DD.jsonl` (one JSON object per line), rotated daily and purged after `DLP_LOG_MAX_DAYS`. Original PII values are **never** logged — only entity type, position, method, and score.

```bash
# Tail today's events
tail -f logs/dlp_audit_$(date +%F).jsonl

# Show blocked uploads
grep '"action":"block"' logs/dlp_audit_*.jsonl
```

---

## Project structure

```
addons/dlp_addon.py        # mitmproxy addon — request/response/websocket hooks (the 3 flows)
dlp/
  dlp_engine.py            # FlashText + Presidio scanning, redaction, span merging
  rule_engine.py           # rules.yaml loader, per-entity action/alert, hot-reload
  file_extractor.py        # PDF / DOCX / XLSX / text extraction (magic-byte detection)
  audit_logger.py          # privacy-preserving JSONL audit logger
  alerter.py               # Telegram alerting with debounce
  recognizers/             # Vietnamese PII recognizers (CCCD, phone, tax, passport, …)
config/
  terms.txt                # internal keywords (FlashText)
  rules.yaml               # per-entity DLP rules
pac/proxy.pac              # proxy auto-config (routes ChatGPT/Claude only)
docker-compose.yml         # proxy + PAC server
Dockerfile
```

---

## Known limitations

- **No OCR** — sensitive data inside images / screenshots is not detected.
- **Base64-encoded file content** inside JSON prompts is not decoded before scanning.
- File text is **truncated at 50,000 characters** for scanning.
- Detection language model is English (`en_core_web_sm`); `PERSON`/`LOCATION`/`ORG` are disabled to avoid false positives on Vietnamese text.

---

## Development

```bash
# Run the engine against a sample string
python test_engine.py

# Exercise the Vietnamese recognizers
python test_vn_recognizers.py
```

Code and configuration (`terms.txt`, `rules.yaml`) hot-reload without a restart. Changes to the addon or Python modules require a rebuild:

```bash
docker compose up -d --build dlp-proxy
```
