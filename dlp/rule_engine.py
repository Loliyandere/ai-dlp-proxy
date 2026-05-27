"""
dlp/rule_engine.py
------------------
Đọc config/rules.yaml và áp dụng rule cho từng entity.

Tính năng:
  - Load rules.yaml khi khởi động
  - Hot-reload: tự detect file thay đổi, không cần restart
  - Per-entity action: log | redact | block (ghi đè DLP_MODE global)
  - Per-entity alert: bật/tắt Telegram riêng từng loại
  - Enabled/disabled từng rule
"""

import logging
import os
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger("ai_dlp_proxy.rule_engine")

PROJECT_ROOT    = Path(__file__).resolve().parent.parent
DEFAULT_RULES   = PROJECT_ROOT / "config" / "rules.yaml"
GLOBAL_DLP_MODE = os.getenv("DLP_MODE", "redact")


class RuleEngine:
    """
    Load và áp dụng rules từ config/rules.yaml.
    Fallback về DLP_MODE env nếu entity không có rule.
    """

    def __init__(self, rules_file: Path = DEFAULT_RULES):
        self.rules_file   = rules_file
        self._rules: Dict = {}
        self._last_mtime  = 0.0
        self._load()

    # ── Public API ───────────────────────────────────────────────────────────

    def get_action(self, entity_type: str) -> str:
        """
        Trả về action cho entity.
        Nếu không có rule → fallback về DLP_MODE env.
        """
        self._reload_if_changed()
        rule = self._rules.get(entity_type)
        if rule and rule.get("enabled", True):
            return rule.get("action", GLOBAL_DLP_MODE)
        return GLOBAL_DLP_MODE

    def should_alert(self, entity_type: str) -> bool:
        """Trả về True nếu entity này cần gửi Telegram alert."""
        self._reload_if_changed()
        rule = self._rules.get(entity_type)
        if rule and rule.get("enabled", True):
            return bool(rule.get("alert", True))
        return True

    def is_enabled(self, entity_type: str) -> bool:
        """Trả về False nếu rule bị disabled."""
        self._reload_if_changed()
        rule = self._rules.get(entity_type)
        if rule:
            return bool(rule.get("enabled", True))
        return True

    def get_active_entities(self) -> List[str]:
        """Danh sách entity đang được bật."""
        self._reload_if_changed()
        return [e for e, r in self._rules.items() if r.get("enabled", True)]

    def get_effective_action(self, stats: dict) -> str:
        """
        Nhìn vào toàn bộ pii_types trong stats,
        trả về action nặng nhất.
        Ưu tiên: block > redact > log
        """
        self._reload_if_changed()
        priority = {"block": 3, "redact": 2, "log": 1}
        best = "log"
        for entity_type in stats.get("pii_types", {}):
            action = self.get_action(entity_type)
            if priority.get(action, 0) > priority.get(best, 0):
                best = action
        return best

    def needs_alert(self, stats: dict) -> bool:
        """True nếu bất kỳ entity nào trong stats cần alert."""
        self._reload_if_changed()
        return any(
            self.should_alert(entity_type)
            for entity_type in stats.get("pii_types", {})
        )

    def summary(self) -> str:
        lines = ["[RuleEngine] Loaded rules:"]
        for entity, rule in sorted(self._rules.items()):
            status = "ON " if rule.get("enabled", True) else "OFF"
            action = rule.get("action", GLOBAL_DLP_MODE)
            alert  = "alert=yes" if rule.get("alert", True) else "alert=no"
            lines.append(f"  [{status}] {entity:<22} action={action:<8} {alert}")
        return "\n".join(lines)

    # ── Internal ─────────────────────────────────────────────────────────────

    def _load(self):
        if not self.rules_file.exists():
            logger.warning(f"[RuleEngine] {self.rules_file} not found, using DLP_MODE={GLOBAL_DLP_MODE}")
            self._rules = {}
            return

        try:
            import yaml
        except ImportError:
            logger.error("[RuleEngine] PyYAML not installed. Run: pip install pyyaml")
            self._rules = {}
            return

        try:
            with self.rules_file.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            rules = {}
            for rule in data.get("rules", []):
                entity = rule.get("entity", "").strip()
                if not entity:
                    continue
                rules[entity] = {
                    "enabled": bool(rule.get("enabled", True)),
                    "action":  rule.get("action", GLOBAL_DLP_MODE),
                    "alert":   bool(rule.get("alert", True)),
                    "note":    rule.get("note", ""),
                }

            self._rules      = rules
            self._last_mtime = self.rules_file.stat().st_mtime

            print(self.summary())
            logger.info(f"[RuleEngine] Loaded {len(rules)} rules from {self.rules_file}")

        except Exception as e:
            logger.error(f"[RuleEngine] Failed to load rules: {e}")
            self._rules = {}

    def _reload_if_changed(self):
        try:
            mtime = self.rules_file.stat().st_mtime
            if mtime != self._last_mtime:
                logger.info("[RuleEngine] Detected change, reloading rules...")
                self._load()
        except FileNotFoundError:
            pass


# Module-level singleton
rule_engine = RuleEngine()