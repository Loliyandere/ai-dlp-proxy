"""
dlp/recognizers/vn_passport_recognizer.py
Số hộ chiếu Việt Nam
"""
from presidio_analyzer import Pattern, PatternRecognizer


class VnPassportRecognizer(PatternRecognizer):
    """
    Nhận diện hộ chiếu VN:
    - Format mới (2022+): B + 8 số    → B12345678
    - Format cũ:          1-2 chữ hoa + 7 số → A1234567 hoặc AB123456
    """

    PATTERNS = [
        Pattern(
            name="vn_passport_new",
            regex=r"\bB[0-9]{8}\b",
            score=0.90,
        ),
        Pattern(
            name="vn_passport_old",
            regex=r"\b[A-Z]{1,2}[0-9]{7}\b",
            score=0.65,
        ),
    ]

    CONTEXT = [
        "hộ chiếu", "passport", "travel document",
        "số hộ chiếu", "passport number", "passport no",
        "xuất nhập cảnh", "visa",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="VN_PASSPORT",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )