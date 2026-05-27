"""
dlp/recognizers/__init__.py
Export tất cả VN recognizers để load dễ dàng.
"""

from .vn_cccd_recognizer    import VnCCCDRecognizer
from .vn_phone_recognizer   import VnPhoneRecognizer
from .vn_tax_recognizer     import VnTaxRecognizer
from .vn_passport_recognizer import VnPassportRecognizer
from .vn_bank_recognizer    import VnBankAccountRecognizer
from .vn_plate_recognizer   import VnLicensePlateRecognizer
from .vn_bhyt_recognizer    import VnBHYTRecognizer

ALL_VN_RECOGNIZERS = [
    VnCCCDRecognizer,
    VnPhoneRecognizer,
    VnTaxRecognizer,
    VnPassportRecognizer,
    VnBankAccountRecognizer,
    VnLicensePlateRecognizer,
    VnBHYTRecognizer,
]

__all__ = [
    "VnCCCDRecognizer",
    "VnPhoneRecognizer",
    "VnTaxRecognizer",
    "VnPassportRecognizer",
    "VnBankAccountRecognizer",
    "VnLicensePlateRecognizer",
    "VnBHYTRecognizer",
    "ALL_VN_RECOGNIZERS",
]