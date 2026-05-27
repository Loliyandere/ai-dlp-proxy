"""
dlp/recognizers/vn_plate_recognizer.py
Biển số xe Việt Nam
"""
from presidio_analyzer import Pattern, PatternRecognizer


class VnLicensePlateRecognizer(PatternRecognizer):
    """
    Nhận diện biển số xe VN:
    - Xe ô tô:    51A-123.45  hoặc  51A-12345
    - Xe máy:     51B1-12345
    - Biển 5 số:  51-A1 23456 (format mới)
    - Biển quân sự: không nhận diện (khác format)
    """

    PATTERNS = [
        Pattern(
            name="vn_plate_car",
            # 2 số + 1-2 chữ + gạch + 3-5 số (có thể có dấu chấm)
            regex=r"\b\d{2}[A-Z]{1,2}-\d{3}[.\s]?\d{2,3}\b",
            score=0.85,
        ),
        Pattern(
            name="vn_plate_motorbike",
            # 2 số + 1 chữ + 1 số + gạch + 5 số
            regex=r"\b\d{2}[A-Z]\d-\d{5}\b",
            score=0.85,
        ),
        Pattern(
            name="vn_plate_new_format",
            # format mới: 2 số + gạch + 1 chữ + 1 số + cách + 5 số
            regex=r"\b\d{2}-[A-Z]\d\s\d{5}\b",
            score=0.80,
        ),
    ]

    CONTEXT = [
        "biển số", "biển xe", "bien so", "license plate",
        "plate number", "số xe", "đăng ký xe",
        "phương tiện", "vehicle", "ô tô", "xe máy",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="VN_LICENSE_PLATE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )