"""
dlp/recognizers/vn_bank_recognizer.py
Số tài khoản ngân hàng Việt Nam
"""
from presidio_analyzer import Pattern, PatternRecognizer


class VnBankAccountRecognizer(PatternRecognizer):
    """
    Nhận diện số tài khoản ngân hàng VN.
    Các ngân hàng lớn thường dùng 9-14 chữ số.

    Một số format thực tế:
    - Vietcombank:  13 số
    - BIDV:         14 số
    - Agribank:     13 số
    - Techcombank:  12 số
    - MB Bank:      10 số
    - ACB:          9-13 số
    """

    PATTERNS = [
        Pattern(
            name="bank_account_common",
            regex=r"\b\d{9,14}\b",
            score=0.45,   # cần context mạnh
        ),
        Pattern(
            name="bank_account_with_space",
            # format có dấu cách: 1234 5678 9012
            regex=r"\b\d{4}[\s]\d{4}[\s]\d{4,6}\b",
            score=0.70,
        ),
    ]

    CONTEXT = [
        "tài khoản", "stk", "số tài khoản", "account number",
        "bank account", "ngân hàng", "chuyển khoản",
        "transfer", "banking", "tk ngân hàng",
        "vietcombank", "bidv", "agribank", "techcombank",
        "mbbank", "acb", "vpbank", "tpbank", "sacombank",
        "hdbank", "ocb", "msb", "seabank", "vib",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="VN_BANK_ACCOUNT",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
        )