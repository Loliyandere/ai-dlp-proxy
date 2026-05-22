import asyncio
import logging
import os
from pathlib import Path
from typing import Dict, List, Tuple

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
    """
    Đọc static terms từ file config/terms.txt.
    Mỗi dòng là một term cần redact.
    """

    def __init__(self, file_path: Path = DEFAULT_TERMS_FILE):
        self.file_path = Path(file_path)

    def get_terms(self) -> List[str]:
        if not self.file_path.exists():
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            self.file_path.write_text(
                "password\nsecret\napi_key\n",
                encoding="utf-8",
            )

        terms = []

        with self.file_path.open("r", encoding="utf-8") as f:
            for line in f:
                term = line.strip()

                if not term:
                    continue

                if term.startswith("#"):
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
    - FlashText: phát hiện static terms từ config/terms.txt.
    - Presidio: phát hiện PII trên prompt đã extract.
    """

    def __init__(
        self,
        terms_file: Path = DEFAULT_TERMS_FILE,
        replacement_token: str = "[REDACTED]",
        case_sensitive: bool = False,
    ):
        self.provider = FileTermProvider(terms_file)
        self.replacement_token = replacement_token
        self.case_sensitive = case_sensitive

        self.keyword_processor = KeywordProcessor(case_sensitive=case_sensitive)
        self.last_terms_mtime = 0.0

        self.presidio_enabled = os.getenv("DLP_PRESIDIO_ENABLED", "true").lower() == "true"
        self.presidio_threshold = float(os.getenv("DLP_PRESIDIO_THRESHOLD", "0.60"))
        self.presidio_language = os.getenv("DLP_PRESIDIO_LANGUAGE", "en")
        self.presidio_model = os.getenv("DLP_SPACY_MODEL", "en_core_web_sm")

        self.presidio_entities = [
            item.strip()
            for item in os.getenv(
                "DLP_PRESIDIO_ENTITIES",
                "PERSON,EMAIL_ADDRESS,PHONE_NUMBER,CREDIT_CARD,LOCATION,ORGANIZATION,URL,IP_ADDRESS,DATE_TIME",
            ).split(",")
            if item.strip()
        ]

        self.analyzer = None

        self.reload_config()
        self._load_presidio()

    def start_workers(self):
        return

    def shutdown(self):
        return

    def reload_config(self):
        """
        Load lại terms từ file và rebuild FlashText KeywordProcessor.
        """
        new_processor = KeywordProcessor(case_sensitive=self.case_sensitive)
        terms = self.provider.get_terms()

        for term in terms:
            new_processor.add_keyword(term, term)

        self.keyword_processor = new_processor
        self.last_terms_mtime = self.provider.get_mtime()

        logger.info(f"[DLP] Loaded {len(terms)} static terms from {self.provider.file_path}")
        print(f"[DLP] Loaded {len(terms)} static terms from {self.provider.file_path}")

    def reload_if_changed(self):
        """
        Hot reload đơn giản:
        Nếu config/terms.txt đổi thì load lại.
        """
        current_mtime = self.provider.get_mtime()

        if current_mtime != self.last_terms_mtime:
            self.reload_config()

    def _load_presidio(self):
        if not self.presidio_enabled:
            print("[DLP] Presidio disabled by config")
            return

        if AnalyzerEngine is None or NlpEngineProvider is None:
            print("[DLP] Presidio not installed. Run: pip3 install presidio-analyzer spacy")
            return

        try:
            nlp_configuration = {
                "nlp_engine_name": "spacy",
                "models": [
                    {
                        "lang_code": self.presidio_language,
                        "model_name": self.presidio_model,
                    }
                ],
            }

            provider = NlpEngineProvider(nlp_configuration=nlp_configuration)
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
            print("[DLP] FlashText will still work.")

    async def redact(self, text: str) -> Tuple[str, Dict]:
        """
        Hàm addon gọi sau khi đã extract được prompt/user text.

        Input:
            prompt/user text

        Output:
            redacted_text, stats
        """

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
        static_hits = self.keyword_processor.extract_keywords(
            text,
            span_info=True,
        )

        for keyword, start, end in static_hits:
            entity_type = "STATIC_TERM"
            spans.append((start, end, entity_type))

            stats["static_replacements"] += 1
            stats["pii_types"][entity_type] = stats["pii_types"].get(entity_type, 0) + 1
            stats["matches"].append({
                "type": entity_type,
                "value": text[start:end],
                "start": start,
                "end": end,
                "method": "flashtext",
                "score": 1.0,
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

                cc_spans = [(r.start, r.end) for r in results if r.entity_type == "CREDIT_CARD"]
                results = [
                r for r in results
                if not (
                r.entity_type == "DATE_TIME"
                and any(r.start < e and r.end > s for s, e in cc_spans)
                )
                ]
                for result in results:
                    if result.score < self.presidio_threshold:
                        continue

                    entity_type = result.entity_type
                    start = result.start
                    end = result.end

                    spans.append((start, end, entity_type))

                    stats["ml_replacements"] += 1
                    stats["pii_types"][entity_type] = stats["pii_types"].get(entity_type, 0) + 1
                    stats["matches"].append({
                        "type": entity_type,
                        "value": text[start:end],
                        "start": start,
                        "end": end,
                        "method": "presidio",
                        "score": result.score,
                    })

            except Exception as e:
                logger.error(f"[DLP] Presidio analyze error: {e}")

        if not spans:
            return text, stats

        merged_spans = self._merge_spans(spans)
        redacted_text = self._apply_redaction(text, merged_spans)

        return redacted_text, stats

    def _entity_priority(self, entity_type: str) -> int:
        priority = {
            "STATIC_TERM": 100,
            "API_KEY": 100,
            "SECRET": 100,
            "CREDIT_CARD": 95,
            "EMAIL_ADDRESS": 90,
            "PHONE_NUMBER": 90,
            "PERSON": 80,
            "LOCATION": 70,
            "ORGANIZATION": 70,
            "URL": 60,
            "IP_ADDRESS": 60,
            "DATE_TIME": 50,
        }

        return priority.get(entity_type, 50)

    def _merge_spans(self, spans: List[Tuple[int, int, str]]) -> List[Tuple[int, int, str]]:
        """
        Gộp span bị overlap.
        Nếu overlap thì entity có priority cao hơn sẽ thắng.
        """

        spans = sorted(spans, key=lambda x: (x[0], x[1]))
        merged = []

        for start, end, entity_type in spans:
            if not merged:
                merged.append((start, end, entity_type))
                continue

            last_start, last_end, last_type = merged[-1]

            if start < last_end:
                new_start = min(last_start, start)
                new_end = max(last_end, end)

                if self._entity_priority(entity_type) > self._entity_priority(last_type):
                    merged[-1] = (new_start, new_end, entity_type)
                else:
                    merged[-1] = (new_start, new_end, last_type)
            else:
                merged.append((start, end, entity_type))

        return merged

    def _replacement_for_entity(self, entity_type: str) -> str:
        mapping = {
            "STATIC_TERM": "[REDACTED]",
            "PERSON": "[PERSON]",
            "LOCATION": "[LOCATION]",
            "ORGANIZATION": "[ORGANIZATION]",
            "EMAIL_ADDRESS": "[EMAIL]",
            "PHONE_NUMBER": "[PHONE]",
            "CREDIT_CARD": "[CREDIT_CARD]",
            "URL": "[URL]",
            "IP_ADDRESS": "[IP_ADDRESS]",
            "DATE_TIME": "[DATE_TIME]",
        }

        return mapping.get(entity_type, self.replacement_token)

    def _apply_redaction(self, text: str, spans: List[Tuple[int, int, str]]) -> str:
        """
        Redact từ cuối về đầu để không lệch index.
        """
        result = list(text)

        for start, end, entity_type in reversed(spans):
            replacement = self._replacement_for_entity(entity_type)
            result[start:end] = list(replacement)

        return "".join(result)