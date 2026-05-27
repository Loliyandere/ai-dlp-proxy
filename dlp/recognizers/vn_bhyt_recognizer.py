"""
dlp/recognizers/vn_bhyt_recognizer.py
Số thẻ Bảo hiểm y tế (BHYT) Việt Nam
"""
from presidio_analyzer import Pattern, PatternRecognizer


class VnBHYTRecognizer(PatternRecognizer):
    """
    Nhận diện số thẻ BHYT:
    Format: XX XXXXXXXX XXX XXXXXXXXXX
    Ví dụ:  HS 4010123456789 hay DN4010123456789

    Cấu trúc 15 ký tự:
    - 2 ký tự đầu: mã đối tượng (HS, HX, DN, ...)
    - 13 số tiếp theo
    """

    PATTERNS = [
        Pattern(
            name="bhyt_standard",
            regex=r"\b[A-Z]{2}\d{13}\b",
            score=0.80,
        ),
        Pattern(
            name="bhyt_with_space",
            # Format có dấu cách: HS 4010123456789
            regex=r"\b[A-Z]{2}\s\d{13}\b",
            score=0.80,
        ),
    ]

    CONTEXT = [
        "bảo hiểm y tế", "bhyt", "thẻ bhyt",
        "health insurance", "insurance card",
        "mã thẻ bhyt", "số bhyt",
        "bảo hiểm xã hội", "bhxh",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="VN_BHYT",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )