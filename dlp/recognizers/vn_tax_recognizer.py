"""
dlp/recognizers/vn_tax_recognizer.py
Mã số thuế (MST) doanh nghiệp và cá nhân Việt Nam
"""
from presidio_analyzer import Pattern, PatternRecognizer


class VnTaxRecognizer(PatternRecognizer):
    """
    Nhận diện MST:
    - Doanh nghiệp: 10 chữ số
    - Chi nhánh:    10 số + gạch ngang + 3 số  (0123456789-001)
    - Cá nhân:      10 chữ số (trùng format DN nhưng khác đầu số)
    """

    PATTERNS = [
        Pattern(
            name="mst_branch",
            regex=r"\b\d{10}-\d{3}\b",
            score=0.90,
        ),
        Pattern(
            name="mst_company",
            regex=r"\b[0-9]{10}\b",
            score=0.55,   # thấp vì 10 chữ số hay nhầm, cần context
        ),
    ]

    CONTEXT = [
        "mã số thuế", "mst", "tax code", "tax id",
        "mã thuế", "tax number", "tin",
        "mã doanh nghiệp", "business id",
        "đăng ký kinh doanh", "dkdn",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="VN_TAX_CODE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )