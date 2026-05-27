"""
dlp/recognizers/vn_cccd_recognizer.py
Căn cước công dân / CMND Việt Nam
"""
from presidio_analyzer import Pattern, PatternRecognizer


class VnCCCDRecognizer(PatternRecognizer):
    """
    Nhận diện:
    - CCCD 12 số (từ 2021)
    - CMND 9 số (cũ)
    """

    PATTERNS = [
        Pattern(
            name="cccd_12_digit",
            regex=r"\b0(?:0[1-9]|[1-8][0-9]|9[0-6])[12]\d{8}\b",
            score=0.85,
        ),
        Pattern(
            name="cmnd_9_digit",
            regex=r"\b0(?:0[1-9]|[1-8][0-9]|9[0-6])\d{6}\b",
            score=0.65,
        ),
    ]

    CONTEXT = [
        "căn cước", "cccd", "cmnd", "chứng minh nhân dân",
        "citizen id", "identity card", "id card", "national id",
        "số định danh", "định danh cá nhân", "mã định danh",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="VN_CCCD",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )