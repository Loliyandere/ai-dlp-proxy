import asyncio
import logging
import os
from pathlib import Path
from typing import Dict, List, Tuple

from dlp.recognizers import ALL_VN_RECOGNIZERS
from flashtext import KeywordProcessor

try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
except Exception:
    AnalyzerEngine = None
    NlpEngineProvider = None


logger = logging.getLogger("ai_dlp_proxy")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TERMS_FILE = PROJECT_ROOT / "config" / "terms.txt"


class FileTermProvider:
    def __init__(self, file_path: Path = DEFAULT_TERMS_FILE):
        self.file_path = Path(file_path)

    def get_terms(self) -> List[str]:
        if not self.file_path.exists():
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            self.file_path.write_text("password\nsecret\napi_key\n", encoding="utf-8")
        terms = []
        with self.file_path.open("r", encoding="utf-8") as f:
            for line in f:
                term = line.strip()
                if not term or term.startswith("#"):
                    continue
                terms.append(term)
        return terms

    def get_mtime(self) -> float:
        if not self.file_path.exists():
            return 0.0
        return self.file_path.stat().st_mtime


class DLPEngine:
    """
    DLP Engine:
    - FlashText     : static terms từ config/terms.txt
    - Presidio      : EMAIL, PHONE, CREDIT_CARD, IP, URL
    - VN recognizers: CCCD, SĐT, MST, hộ chiếu, STK, biển số, BHYT

    ĐÃ TẮT: PERSON, LOCATION, ORGANIZATION, DATE_TIME
    Lý do  : en_core_web_sm không hiểu tiếng Việt → false positive cao
    """

    def __init__(
        self,
        terms_file: Path = DEFAULT_TERMS_FILE,
        replacement_token: str = "[REDACTED]",
        case_sensitive: bool = False,
    ):
        self.provider          = FileTermProvider(terms_file)
        self.replacement_token = replacement_token
        self.case_sensitive    = case_sensitive

        self.keyword_processor = KeywordProcessor(case_sensitive=case_sensitive)
        self.last_terms_mtime  = 0.0

        self.presidio_enabled   = os.getenv("DLP_PRESIDIO_ENABLED", "true").lower() == "true"
        self.presidio_threshold = float(os.getenv("DLP_PRESIDIO_THRESHOLD", "0.60"))
        self.presidio_language  = os.getenv("DLP_PRESIDIO_LANGUAGE", "en")
        self.presidio_model     = os.getenv("DLP_SPACY_MODEL", "en_core_web_sm")

        self.presidio_entities = [
            item.strip()
            for item in os.getenv(
                "DLP_PRESIDIO_ENTITIES",
                "EMAIL_ADDRESS,PHONE_NUMBER,CREDIT_CARD,IP_ADDRESS,URL,"
                "VN_CCCD,VN_PHONE,VN_TAX_CODE,VN_PASSPORT,"
                "VN_BANK_ACCOUNT,VN_LICENSE_PLATE,VN_BHYT",
            ).split(",")
            if item.strip()
        ]

        self.analyzer = None

        self.reload_config()
        self._load_presidio()
        self._load_vn_recognizers()

    def start_workers(self):
        return

    def shutdown(self):
        return

    def reload_config(self):
        new_processor = KeywordProcessor(case_sensitive=self.case_sensitive)
        terms = self.provider.get_terms()
        for term in terms:
            new_processor.add_keyword(term, term)
        self.keyword_processor = new_processor
        self.last_terms_mtime  = self.provider.get_mtime()
        logger.info(f"[DLP] Loaded {len(terms)} static terms from {self.provider.file_path}")
        print(f"[DLP] Loaded {len(terms)} static terms from {self.provider.file_path}")

    def reload_if_changed(self):
        current_mtime = self.provider.get_mtime()
        if current_mtime != self.last_terms_mtime:
            self.reload_config()

    def _load_presidio(self):
        if not self.presidio_enabled:
            print("[DLP] Presidio disabled by config")
            return
        if AnalyzerEngine is None or NlpEngineProvider is None:
            print("[DLP] Presidio not installed.")
            return
        try:
            nlp_configuration = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": self.presidio_language, "model_name": self.presidio_model}],
            }
            provider   = NlpEngineProvider(nlp_configuration=nlp_configuration)
            nlp_engine = provider.create_engine()
            self.analyzer = AnalyzerEngine(
                nlp_engine=nlp_engine,
                supported_languages=[self.presidio_language],
            )
            print(
                f"[DLP] Presidio loaded: language={self.presidio_language}, "
                f"model={self.presidio_model}, entities={self.presidio_entities}"
            )
        except Exception as e:
            self.analyzer = None
            print(f"[DLP] Failed to load Presidio: {e}")

    def _load_vn_recognizers(self):
        if self.analyzer is None:
            return
        loaded = []
        for RecognizerClass in ALL_VN_RECOGNIZERS:
            try:
                recognizer = RecognizerClass()
                self.analyzer.registry.add_recognizer(recognizer)
                loaded.append(recognizer.supported_entities[0])
            except Exception as e:
                print(f"[DLP] Failed to load {RecognizerClass.__name__}: {e}")
        print(f"[DLP] Loaded VN recognizers: {', '.join(loaded)}")

    def scan_terms_only(self, text: str) -> Dict:
        """
        Chỉ kiểm tra từ khoá tĩnh trong terms.txt (FlashText) — KHÔNG dùng Presidio.
        Dùng khi cần kết quả đồng bộ (sync). Với file upload hãy dùng scan_file_content.
        """
        self.reload_if_changed()
        stats: Dict = {
            "static_replacements": 0,
            "ml_replacements": 0,
            "pii_types": {},
            "matches": [],
        }
        if not text:
            return stats
        hits = self.keyword_processor.extract_keywords(text, span_info=True)
        for keyword, start, end in hits:
            stats["static_replacements"] += 1
            stats["pii_types"]["STATIC_TERM"] = stats["pii_types"].get("STATIC_TERM", 0) + 1
            stats["matches"].append({
                "type": "STATIC_TERM",
                "value": text[start:end],
                "start": start,
                "end": end,
                "method": "flashtext",
                "score": 1.0,
            })
        return stats

    # Entities used for file-content ML scanning.
    # Excludes PERSON / LOCATION / ORGANIZATION / DATE_TIME which cause massive
    # false positives on company names, document metadata, and address strings.
    _FILE_SCAN_ENTITIES: List[str] = [
        "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "IP_ADDRESS",
        "VN_CCCD", "VN_PHONE", "VN_TAX_CODE", "VN_PASSPORT",
        "VN_BANK_ACCOUNT", "VN_LICENSE_PLATE", "VN_BHYT",
    ]

    async def scan_file_content(self, text: str) -> Dict:
        """
        Scan extracted file text using TWO layers:
          1. FlashText  – exact keyword match against config/terms.txt
                          Any hit → STATIC_TERM → block (internal data marker)
          2. Presidio ML – restricted to _FILE_SCAN_ENTITIES (no PERSON/ORG/LOC)
                          Catches credit-card numbers, emails, phone numbers, etc.
                          in uploaded documents even without a matching keyword.

        Called from:
          - LUỒNG 0 : S3/CDN pre-signed PUT (ChatGPT Azure CDN)
          - LUỒNG 1 : direct multipart upload (Claude /api/convert_document,
                      Claude /api/organizations/.../upload)
        """
        self.reload_if_changed()
        stats: Dict = {
            "static_replacements": 0,
            "ml_replacements": 0,
            "pii_types": {},
            "matches": [],
        }
        if not text:
            return stats

        # ── Layer 1: FlashText keyword scan ──────────────────────────────────
        hits = self.keyword_processor.extract_keywords(text, span_info=True)
        for keyword, start, end in hits:
            stats["static_replacements"] += 1
            stats["pii_types"]["STATIC_TERM"] = stats["pii_types"].get("STATIC_TERM", 0) + 1
            stats["matches"].append({
                "type": "STATIC_TERM",
                "value": text[start:end],
                "start": start,
                "end": end,
                "method": "flashtext",
                "score": 1.0,
            })

        # ── Layer 2: Presidio ML (restricted entity set) ──────────────────────
        if self.analyzer is not None:
            try:
                results = await asyncio.to_thread(
                    self.analyzer.analyze,
                    text=text,
                    language=self.presidio_language,
                    entities=self._FILE_SCAN_ENTITIES,
                )
                for result in results:
                    if result.score < self.presidio_threshold:
                        continue
                    entity_type = result.entity_type
                    stats["ml_replacements"] += 1
                    stats["pii_types"][entity_type] = (
                        stats["pii_types"].get(entity_type, 0) + 1
                    )
                    stats["matches"].append({
                        "type":   entity_type,
                        "value":  text[result.start:result.end],
                        "start":  result.start,
                        "end":    result.end,
                        "method": "presidio",
                        "score":  result.score,
                    })
            except Exception as e:
                logger.error(f"[DLP] scan_file_content Presidio error: {e}")

        return stats

    async def redact(self, text: str) -> Tuple[str, Dict]:
        self.reload_if_changed()

        stats = {
            "static_replacements": 0,
            "ml_replacements": 0,
            "pii_types": {},
            "matches": [],
        }

        if not text:
            return text, stats

        spans = []

        # 1. FlashText static terms
        static_hits = self.keyword_processor.extract_keywords(text, span_info=True)
        for keyword, start, end in static_hits:
            entity_type = "STATIC_TERM"
            spans.append((start, end, entity_type))
            stats["static_replacements"] += 1
            stats["pii_types"][entity_type] = stats["pii_types"].get(entity_type, 0) + 1
            stats["matches"].append({
                "type": entity_type, "value": text[start:end],
                "start": start, "end": end, "method": "flashtext", "score": 1.0,
            })

        # 2. Presidio PII
        if self.analyzer is not None:
            try:
                results = await asyncio.to_thread(
                    self.analyzer.analyze,
                    text=text,
                    language=self.presidio_language,
                    entities=self.presidio_entities,
                )

                for result in results:
                    if result.score < self.presidio_threshold:
                        continue
                    entity_type = result.entity_type
                    start       = result.start
                    end         = result.end
                    spans.append((start, end, entity_type))
                    stats["ml_replacements"] += 1
                    stats["pii_types"][entity_type] = stats["pii_types"].get(entity_type, 0) + 1
                    stats["matches"].append({
                        "type": entity_type, "value": text[start:end],
                        "start": start, "end": end,
                        "method": "presidio", "score": result.score,
                    })

            except Exception as e:
                logger.error(f"[DLP] Presidio analyze error: {e}")

        if not spans:
            return text, stats

        merged_spans  = self._merge_spans(spans)
        redacted_text = self._apply_redaction(text, merged_spans)
        return redacted_text, stats

    def _entity_priority(self, entity_type: str) -> int:
        priority = {
            "STATIC_TERM":      100,
            "API_KEY":          100,
            "SECRET":           100,
            "CREDIT_CARD":       95,
            "VN_CCCD":           95,
            "VN_PASSPORT":       95,
            "EMAIL_ADDRESS":     90,
            "PHONE_NUMBER":      90,
            "VN_PHONE":          90,
            "VN_TAX_CODE":       85,
            "VN_BANK_ACCOUNT":   85,
            "VN_BHYT":           85,
            "VN_LICENSE_PLATE":  75,
            "URL":               60,
            "IP_ADDRESS":        60,
        }
        return priority.get(entity_type, 50)

    def _merge_spans(self, spans: List[Tuple[int, int, str]]) -> List[Tuple[int, int, str]]:
        spans  = sorted(spans, key=lambda x: (x[0], x[1]))
        merged = []
        for start, end, entity_type in spans:
            if not merged:
                merged.append((start, end, entity_type))
                continue
            last_start, last_end, last_type = merged[-1]
            if start < last_end:
                new_start = min(last_start, start)
                new_end   = max(last_end, end)
                if self._entity_priority(entity_type) > self._entity_priority(last_type):
                    merged[-1] = (new_start, new_end, entity_type)
                else:
                    merged[-1] = (new_start, new_end, last_type)
            else:
                merged.append((start, end, entity_type))
        return merged

    def _replacement_for_entity(self, entity_type: str) -> str:
        mapping = {
            # ── Quốc tế ─────────────────────────────
            "STATIC_TERM":      "[REDACTED]",
            "EMAIL_ADDRESS":    "[EMAIL]",
            "PHONE_NUMBER":     "[PHONE]",
            "CREDIT_CARD":      "[CREDIT_CARD]",
            "URL":              "[URL]",
            "IP_ADDRESS":       "[IP_ADDRESS]",
            # ── Việt Nam ────────────────────────────
            "VN_CCCD":          "[CCCD/CMND]",
            "VN_PHONE":         "[SĐT]",
            "VN_TAX_CODE":      "[MST]",
            "VN_PASSPORT":      "[HỘ CHIẾU]",
            "VN_BANK_ACCOUNT":  "[STK NGÂN HÀNG]",
            "VN_LICENSE_PLATE": "[BIỂN SỐ XE]",
            "VN_BHYT":          "[THẺ BHYT]",
        }
        return mapping.get(entity_type, self.replacement_token)

    def _apply_redaction(self, text: str, spans: List[Tuple[int, int, str]]) -> str:
        result = list(text)
        for start, end, entity_type in reversed(spans):
            replacement = self._replacement_for_entity(entity_type)
            result[start:end] = list(replacement)
        return "".join(result)