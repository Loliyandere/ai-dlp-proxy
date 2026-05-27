"""
dlp/recognizers/vn_phone_recognizer.py
Số điện thoại Việt Nam
"""
from presidio_analyzer import Pattern, PatternRecognizer


class VnPhoneRecognizer(PatternRecognizer):
    """
    Nhận diện số điện thoại VN:
    - Đầu số Viettel:  032-039, 086, 096, 097, 098
    - Đầu số Mobifone: 070, 076-079, 089, 090, 093
    - Đầu số Vinaphone:056, 058, 091, 094
    - Đầu số Vietnamobile: 052, 056, 058, 092
    - Đầu số Gmobile: 059, 099
    - Có thể có +84 hoặc 0 ở đầu
    - Có thể có dấu cách, gạch ngang
    """

    _PREFIX = (
        r"(?:(?:\+84|0084|84)[\s.-]?)?"   # +84 / 0084 / 84 (optional)
        r"(?:0)"                            # leading 0
    )

    PATTERNS = [
        Pattern(
            name="vn_phone_full",
            regex=(
                r"\b(?:\+84|0084|84)?[\s.-]?"
                r"(?:0[35789][0-9]|09[0-9])"   # đầu số hợp lệ
                r"[\s.-]?\d{3}"
                r"[\s.-]?\d{4}\b"
            ),
            score=0.80,
        ),
        Pattern(
            name="vn_phone_with_context",
            # Relaxed hơn, chỉ dùng khi có context
            regex=r"\b0[0-9]{9}\b",
            score=0.50,
        ),
    ]

    CONTEXT = [
        "điện thoại", "phone", "mobile", "sdt", "số dt",
        "liên hệ", "contact", "tel", "call", "zalo",
        "hotline", "số máy", "di động",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="VN_PHONE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )